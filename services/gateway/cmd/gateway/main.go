// Command gateway is the Sovereign Private Messenger delivery/control-plane
// gateway. Phase A: health + CBOR validation + KT STH retrieval when configured.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/deviceauth"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/devices"
	gwhttp "github.com/sovereign-messenger/private-messenger/services/gateway/internal/http"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/messages"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/recoveryratelimit"
)

func main() {
	addr := os.Getenv("GATEWAY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	handler := gwhttp.NewHandler()

	databaseURL := os.Getenv("GATEWAY_DATABASE_URL")
	deviceRequestAuthEnabled := os.Getenv("GATEWAY_ENABLE_DEVICE_REQUEST_AUTH") == "1"
	recoveryAPIEnabled := os.Getenv("GATEWAY_ENABLE_RECOVERY_API") == "1"
	initialBootstrapEnabled := os.Getenv("GATEWAY_ENABLE_INITIAL_ACCOUNT_BOOTSTRAP") == "1"
	if initialBootstrapEnabled && databaseURL == "" {
		log.Fatal("GATEWAY_DATABASE_URL is required when initial-account bootstrap is enabled")
	}
	if recoveryAPIEnabled && databaseURL == "" {
		log.Fatal("GATEWAY_DATABASE_URL is required when the recovery API is enabled")
	}
	var recoveryRateLimitHMACKey []byte
	if recoveryAPIEnabled {
		decoded, err := hex.DecodeString(os.Getenv("GATEWAY_RECOVERY_RATE_LIMIT_HMAC_KEY"))
		if err != nil || len(decoded) != 32 {
			log.Fatal("GATEWAY_RECOVERY_RATE_LIMIT_HMAC_KEY must be 64 hexadecimal characters (32 random bytes) when the recovery API is enabled")
		}
		recoveryRateLimitHMACKey = decoded
	}
	if deviceRequestAuthEnabled && databaseURL == "" {
		log.Fatal("GATEWAY_DATABASE_URL is required when per-device request authentication is enabled")
	}
	if deviceRequestAuthEnabled && os.Getenv("GATEWAY_ENABLE_DEMO_MESSAGE_RELAY") != "1" {
		log.Fatal("GATEWAY_ENABLE_DEMO_MESSAGE_RELAY=1 is required when per-device request authentication is enabled")
	}
	if databaseURL != "" {
		db, err := sql.Open("pgx", databaseURL)
		if err != nil {
			log.Fatalf("open gateway database: %v", err)
		}
		defer db.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = db.PingContext(ctx)
		cancel()
		if err != nil {
			log.Fatalf("ping gateway database: %v", err)
		}

		seedPath := os.Getenv("KT_LOG_PRIVATE_SEED_FILE")
		if seedPath == "" {
			log.Fatal("KT_LOG_PRIVATE_SEED_FILE is required when GATEWAY_DATABASE_URL is configured")
		}

		logPrivate, err := loadKTSigningKey(seedPath)
		if err != nil {
			log.Fatalf("load KT signing key: %v", err)
		}

		sthStore := kt.NewPostgresSTHStore(db)
		sthPublisher := kt.NewSTHPublisher(sthStore, logPublicKey(logPrivate))
		deviceDirectory := devices.NewPostgresDirectory(db)

		// Keep the demo relay disabled unless explicitly enabled.
		handler = gwhttp.NewHandlerWithSTHAndDevices(sthPublisher, deviceDirectory)

		if os.Getenv("GATEWAY_ENABLE_DEMO_MESSAGE_RELAY") == "1" {
			messageDelivery := messages.NewDeliveryService(db)
			if deviceRequestAuthEnabled {
				var authSchemaReady bool
				checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := db.QueryRowContext(checkCtx, `SELECT
					to_regclass('public.authorization_accounts') IS NOT NULL AND
					to_regclass('public.authorization_devices') IS NOT NULL AND
					to_regclass('public.device_request_nonces') IS NOT NULL`).Scan(&authSchemaReady)
				checkCancel()
				if err != nil {
					log.Fatalf("check per-device request-auth schema: %v", err)
				}
				if !authSchemaReady {
					log.Fatal("per-device request authentication requires authorization migrations 0004 and 0006")
				}
				handler = gwhttp.NewHandlerWithSTHAndDevicesAndMessagesAndDeviceAuth(
					sthPublisher,
					deviceDirectory,
					messageDelivery,
					deviceauth.NewPostgresRequestAuthenticator(db),
				)
				log.Printf("per-device request authentication enabled for demo message relay")
			} else {
				messageAuthToken := os.Getenv("GATEWAY_MESSAGE_AUTH_TOKEN")
				if len(messageAuthToken) < 32 {
					log.Fatal("GATEWAY_MESSAGE_AUTH_TOKEN must contain at least 32 bytes when shared-bearer demo messaging is enabled")
				}
				handler = gwhttp.NewHandlerWithSTHAndDevicesAndMessages(
					sthPublisher,
					deviceDirectory,
					messageDelivery,
					messageAuthToken,
				)
				log.Printf("WARNING: demo relay uses shared bearer authentication; set GATEWAY_ENABLE_DEVICE_REQUEST_AUTH=1 for per-device request authentication")
			}
		} else {
			log.Printf("demo message relay disabled")
		}

		if initialBootstrapEnabled {
			var bootstrapSchemaReady bool
			checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := db.QueryRowContext(checkCtx, `SELECT
				to_regclass('public.initial_account_bootstrap_challenges') IS NOT NULL AND
				to_regclass('public.authorization_accounts') IS NOT NULL AND
				to_regclass('public.authorization_devices') IS NOT NULL AND
				to_regclass('public.authorization_events') IS NOT NULL`).Scan(&bootstrapSchemaReady)
			checkCancel()
			if err != nil {
				log.Fatalf("check initial-account bootstrap schema: %v", err)
			}
			if !bootstrapSchemaReady {
				log.Fatal("initial-account bootstrap requires migrations 0001, 0004, and 0011")
			}
			handler = gwhttp.NewHandlerWithInitialAccountBootstrap(handler, authorization.NewPostgresAuthorizer(db))
			log.Printf("WARNING: initial-account bootstrap enabled; this candidate flow is not production-ready")
		}

		if os.Getenv("GATEWAY_ENABLE_CANDIDATE_ENROLLMENT") == "1" {
			handler = gwhttp.NewHandlerWithCandidateEnrollment(
				handler,
				authorization.NewPostgresAuthorizer(db),
			)
			log.Printf("WARNING: candidate enrollment routes enabled; candidate protocol/API is not frozen and is not production-ready")
		}

		if recoveryAPIEnabled {
			var recoverySchemaReady bool
			checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := db.QueryRowContext(checkCtx, `SELECT
				to_regclass('public.authorization_accounts') IS NOT NULL AND
				to_regclass('public.authorization_devices') IS NOT NULL AND
				to_regclass('public.authorization_events') IS NOT NULL AND
				to_regclass('public.device_enrollment_challenges') IS NOT NULL AND
				to_regclass('public.account_recovery_requests') IS NOT NULL AND
				to_regclass('public.recovery_api_rate_limits') IS NOT NULL`).Scan(&recoverySchemaReady)
			checkCancel()
			if err != nil {
				log.Fatalf("check recovery API schema: %v", err)
			}
			if !recoverySchemaReady {
				log.Fatal("recovery API requires authorization migrations including migrations 0008 and 0009")
			}
			recoveryLimiter, err := recoveryratelimit.NewPostgres(
				db, recoveryRateLimitHMACKey, 10, time.Minute,
			)
			if err != nil {
				log.Fatalf("configure PostgreSQL recovery rate limiter: %v", err)
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := recoveryLimiter.PruneExpired(cleanupCtx); err != nil {
				log.Printf("WARNING: initial recovery rate-limit cleanup failed: %v", err)
			}
			cleanupCancel()
			go func() {
				ticker := time.NewTicker(time.Hour)
				defer ticker.Stop()
				for range ticker.C {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					if err := recoveryLimiter.PruneExpired(ctx); err != nil {
						log.Printf("WARNING: recovery rate-limit cleanup failed: %v", err)
					}
					cancel()
				}
			}()
			handler = gwhttp.NewHandlerWithRecoveryAPIAndLimiter(
				handler,
				authorization.NewPostgresAuthorizer(db),
				recoveryLimiter,
			)
			log.Printf("WARNING: recovery API enabled; expose it only through a protected HTTPS deployment and keep the recovery protocol/API under security review")
		} else {
			log.Printf("recovery API disabled")
		}

		log.Printf("KT STH persistence enabled")
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	log.Printf("gateway listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func loadKTSigningKey(path string) (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read log seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("transparency log seed must be exactly 32 bytes")
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

func logPublicKey(private ed25519.PrivateKey) [32]byte {
	public := private.Public().(ed25519.PublicKey)
	var out [32]byte
	copy(out[:], public)
	return out
}
