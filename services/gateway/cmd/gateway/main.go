// Command gateway is the Sovereign Private Messenger delivery/control-plane
// gateway. Phase A: health + CBOR validation + KT STH retrieval when configured.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/devices"
	gwhttp "github.com/sovereign-messenger/private-messenger/services/gateway/internal/http"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/messages"
)

func main() {
	addr := os.Getenv("GATEWAY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	handler := gwhttp.NewHandler()

	databaseURL := os.Getenv("GATEWAY_DATABASE_URL")
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
		messageDelivery := messages.NewDeliveryService(db)
		messageAuthToken := os.Getenv("GATEWAY_MESSAGE_AUTH_TOKEN")
		handler = gwhttp.NewHandlerWithSTHAndDevicesAndMessages(
			sthPublisher,
			deviceDirectory,
			messageDelivery,
			messageAuthToken,
		)
		if os.Getenv("GATEWAY_ENABLE_CANDIDATE_ENROLLMENT") == "1" {
			handler = gwhttp.NewHandlerWithCandidateEnrollment(
				handler,
				authorization.NewPostgresAuthorizer(db),
			)
			log.Printf("WARNING: candidate enrollment routes enabled; candidate protocol/API is not frozen and is not production-ready")
		}

		log.Printf("KT STH persistence enabled")
		log.Printf("demo message relay enabled")
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
