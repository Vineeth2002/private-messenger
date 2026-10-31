package authorization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

const (
	defaultRecoveryFinalizerPollInterval   = 15 * time.Second
	defaultRecoveryFinalizerBatchSize      = 100
	defaultRecoveryFinalizerRequestTimeout = 15 * time.Second
)

// DefaultRecoveryFinalizationWorkerConfig returns the conservative default
// polling, batch, and per-request timeout settings.
func DefaultRecoveryFinalizationWorkerConfig() RecoveryFinalizationWorkerConfig {
	return RecoveryFinalizationWorkerConfig{
		PollInterval:   defaultRecoveryFinalizerPollInterval,
		BatchSize:      defaultRecoveryFinalizerBatchSize,
		RequestTimeout: defaultRecoveryFinalizerRequestTimeout,
	}
}

// RecoveryFinalizationWorkerConfig controls the durable recovery finalizer.
// Zero values select conservative defaults.
type RecoveryFinalizationWorkerConfig struct {
	PollInterval   time.Duration
	BatchSize      int
	RequestTimeout time.Duration
}

// RecoveryFinalizationWorker scans PostgreSQL for due PENDING recovery requests
// and delegates every state transition to PostgresAuthorizer.FinalizeRecovery.
// PostgreSQL remains authoritative for the deadline; this process clock is used
// only to schedule polling and bound individual calls.
type RecoveryFinalizationWorker struct {
	db             *sql.DB
	authorizer     *PostgresAuthorizer
	pollInterval   time.Duration
	batchSize      int
	requestTimeout time.Duration
}

type dueRecoveryRequest struct {
	finalizeAfter time.Time
	accountID     [16]byte
	requestID     [16]byte
}

func NewRecoveryFinalizationWorker(db *sql.DB, config RecoveryFinalizationWorkerConfig) (*RecoveryFinalizationWorker, error) {
	if db == nil {
		return nil, ErrNilAuthorizer
	}
	defaults := DefaultRecoveryFinalizationWorkerConfig()
	if config.PollInterval == 0 {
		config.PollInterval = defaults.PollInterval
	}
	if config.BatchSize == 0 {
		config.BatchSize = defaults.BatchSize
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaults.RequestTimeout
	}
	if config.PollInterval < time.Second || config.PollInterval > 5*time.Minute {
		return nil, errors.New("authorization: recovery finalizer poll interval must be between 1 second and 5 minutes")
	}
	if config.BatchSize < 1 || config.BatchSize > 1000 {
		return nil, errors.New("authorization: recovery finalizer batch size must be between 1 and 1000")
	}
	if config.RequestTimeout < time.Second || config.RequestTimeout > 2*time.Minute {
		return nil, errors.New("authorization: recovery finalizer request timeout must be between 1 second and 2 minutes")
	}
	return &RecoveryFinalizationWorker{
		db:             db,
		authorizer:     NewPostgresAuthorizer(db),
		pollInterval:   config.PollInterval,
		batchSize:      config.BatchSize,
		requestTimeout: config.RequestTimeout,
	}, nil
}

// Run performs a scan immediately on startup, then polls until ctx is cancelled.
// Query failures are logged and retried on the next tick. Per-request failures do
// not prevent other due requests in the same batch from being processed.
func (w *RecoveryFinalizationWorker) Run(ctx context.Context) error {
	if w == nil || w.db == nil || w.authorizer == nil {
		return ErrNilAuthorizer
	}
	if ctx == nil {
		return errors.New("authorization: nil recovery finalizer context")
	}

	w.runAndLog(ctx)
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if ctx.Err() != nil {
				return nil
			}
			w.runAndLog(ctx)
		}
	}
}

func (w *RecoveryFinalizationWorker) runAndLog(ctx context.Context) {
	finalized, err := w.runOnce(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("recovery finalizer scan failed: %v", err)
		}
		return
	}
	if finalized > 0 {
		log.Printf("recovery finalizer completed %d due request(s)", finalized)
	}
}

// runOnce is intentionally kept package-private; integration tests exercise it
// against the dedicated disposable PostgreSQL database.
func (w *RecoveryFinalizationWorker) runOnce(ctx context.Context) (int, error) {
	var cursor *dueRecoveryRequest
	finalized := 0

	for {
		batch, err := w.loadDueBatch(ctx, cursor)
		if err != nil {
			return finalized, err
		}
		if len(batch) == 0 {
			return finalized, nil
		}

		for i := range batch {
			item := batch[i]
			if err := ctx.Err(); err != nil {
				return finalized, err
			}
			requestCtx, cancel := context.WithTimeout(ctx, w.requestTimeout)
			state, err := w.authorizer.FinalizeRecovery(requestCtx, item.accountID, item.requestID)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return finalized, ctx.Err()
				}
				// A concurrent worker may have finalized the same request after
				// this scan. FinalizeRecovery is idempotent for the exact request.
				// Other failures are logged; keyset pagination ensures one
				// problematic request does not starve later due requests.
				log.Printf("recovery finalizer could not finalize account=%s request=%s: %v",
					uuidText(item.accountID), uuidText(item.requestID), err)
				continue
			}
			if state.Status != RecoveryRequestFinalized {
				log.Printf("recovery finalizer returned non-final status account=%s request=%s status=%s",
					uuidText(item.accountID), uuidText(item.requestID), state.Status)
				continue
			}
			finalized++
		}

		last := batch[len(batch)-1]
		cursor = &last
		if len(batch) < w.batchSize {
			return finalized, nil
		}
	}
}

func (w *RecoveryFinalizationWorker) loadDueBatch(
	ctx context.Context,
	cursor *dueRecoveryRequest,
) ([]dueRecoveryRequest, error) {
	var cursorTime interface{}
	var cursorAccountID interface{}
	var cursorRequestID interface{}
	if cursor != nil {
		cursorTime = cursor.finalizeAfter
		cursorAccountID = uuidText(cursor.accountID)
		cursorRequestID = uuidText(cursor.requestID)
	}

	rows, err := w.db.QueryContext(ctx, `
SELECT finalize_after, uuid_send(account_id), uuid_send(request_id)
FROM account_recovery_requests
WHERE status = 'PENDING'
  AND finalize_after <= clock_timestamp()
  AND ($2::timestamptz IS NULL OR
       (finalize_after, account_id, request_id) >
       ($2::timestamptz, $3::uuid, $4::uuid))
ORDER BY finalize_after, account_id, request_id
LIMIT $1
`, w.batchSize, cursorTime, cursorAccountID, cursorRequestID)
	if err != nil {
		return nil, err
	}

	batch := make([]dueRecoveryRequest, 0, w.batchSize)
	for rows.Next() {
		var item dueRecoveryRequest
		var accountBytes, requestBytes []byte
		if err := rows.Scan(&item.finalizeAfter, &accountBytes, &requestBytes); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if len(accountBytes) != 16 || len(requestBytes) != 16 {
			_ = rows.Close()
			return nil, fmt.Errorf("authorization: malformed due recovery identifiers")
		}
		copy(item.accountID[:], accountBytes)
		copy(item.requestID[:], requestBytes)
		batch = append(batch, item)
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil {
		return nil, rowsErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return batch, nil
}
