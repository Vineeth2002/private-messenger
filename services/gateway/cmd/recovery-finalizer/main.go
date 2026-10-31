// Command recovery-finalizer runs the durable PostgreSQL recovery finalization
// worker independently of the HTTP gateway process.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Printf("recovery-finalizer stopped with error: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	databaseURL := os.Getenv("GATEWAY_DATABASE_URL")
	if databaseURL == "" {
		return errors.New("GATEWAY_DATABASE_URL is required")
	}

	config, err := workerConfigFromEnvironment()
	if err != nil {
		return err
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open gateway database: %w", err)
	}
	defer db.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = db.PingContext(pingCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("ping gateway database: %w", err)
	}

	schemaCtx, schemaCancel := context.WithTimeout(ctx, 5*time.Second)
	defer schemaCancel()
	var recoverySchemaReady bool
	if err := db.QueryRowContext(schemaCtx, `SELECT
		to_regclass('public.accounts') IS NOT NULL AND
		to_regclass('public.authorization_accounts') IS NOT NULL AND
		to_regclass('public.account_recovery_requests') IS NOT NULL`).Scan(&recoverySchemaReady); err != nil {
		return fmt.Errorf("check recovery schema: %w", err)
	}
	if !recoverySchemaReady {
		return errors.New("recovery schema is unavailable; apply gateway migrations through 0008 before starting the finalizer")
	}

	worker, err := authorization.NewRecoveryFinalizationWorker(db, config)
	if err != nil {
		return fmt.Errorf("configure recovery finalizer: %w", err)
	}

	log.Printf("recovery finalizer started (poll_interval=%s batch_size=%d request_timeout=%s)",
		config.PollInterval, config.BatchSize, config.RequestTimeout)
	if err := worker.Run(ctx); err != nil {
		return fmt.Errorf("run recovery finalizer: %w", err)
	}
	log.Printf("recovery finalizer stopped")
	return nil
}

func workerConfigFromEnvironment() (authorization.RecoveryFinalizationWorkerConfig, error) {
	config := authorization.DefaultRecoveryFinalizationWorkerConfig()

	if raw := os.Getenv("RECOVERY_FINALIZER_POLL_INTERVAL"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil {
			return config, fmt.Errorf("parse RECOVERY_FINALIZER_POLL_INTERVAL: %w", err)
		}
		config.PollInterval = value
	}
	if raw := os.Getenv("RECOVERY_FINALIZER_BATCH_SIZE"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return config, fmt.Errorf("parse RECOVERY_FINALIZER_BATCH_SIZE: %w", err)
		}
		config.BatchSize = value
	}
	if raw := os.Getenv("RECOVERY_FINALIZER_REQUEST_TIMEOUT"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil {
			return config, fmt.Errorf("parse RECOVERY_FINALIZER_REQUEST_TIMEOUT: %w", err)
		}
		config.RequestTimeout = value
	}
	return config, nil
}
