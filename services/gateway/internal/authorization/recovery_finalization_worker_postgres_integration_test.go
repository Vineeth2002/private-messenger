package authorization

import (
	"context"
	"testing"
	"time"
)

func TestPostgresRecoveryFinalizationWorkerProcessesDueAndIsRestartSafeIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	forceRecoveryDueForTest(t, f.db, f.recoveryRequestID)

	worker, err := NewRecoveryFinalizationWorker(f.db, RecoveryFinalizationWorkerConfig{
		PollInterval:   5 * time.Minute,
		BatchSize:      10,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("create recovery finalizer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	finalized, err := worker.runOnce(ctx)
	if err != nil {
		t.Fatalf("worker scan: %v", err)
	}
	if finalized != 1 {
		t.Fatalf("worker finalized %d requests; want 1", finalized)
	}

	var status string
	var accountEpoch, authEpoch int64
	var authStatus int
	if err := f.db.QueryRowContext(ctx, `SELECT status FROM account_recovery_requests WHERE request_id=$1::uuid`, uuidText(f.recoveryRequestID)).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT account_epoch FROM accounts WHERE account_id=$1::uuid`, uuidText(f.base.accountID)).Scan(&accountEpoch); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT epoch,status FROM authorization_accounts WHERE account_id=$1::uuid`, uuidText(f.base.accountID)).Scan(&authEpoch, &authStatus); err != nil {
		t.Fatal(err)
	}
	if status != string(RecoveryRequestFinalized) || accountEpoch != 2 || authEpoch != 2 || authStatus != int(AccountRecoveryLocked) {
		t.Fatalf("worker did not atomically finalize: request=%s account_epoch=%d auth_epoch=%d auth_status=%d", status, accountEpoch, authEpoch, authStatus)
	}

	// A new worker instance simulates process restart. The terminal request is
	// not selected again and the account epoch is not advanced a second time.
	restarted, err := NewRecoveryFinalizationWorker(f.db, RecoveryFinalizationWorkerConfig{})
	if err != nil {
		t.Fatalf("create restarted worker: %v", err)
	}
	finalized, err = restarted.runOnce(ctx)
	if err != nil {
		t.Fatalf("restarted worker scan: %v", err)
	}
	if finalized != 0 {
		t.Fatalf("restarted worker finalized %d requests; want 0", finalized)
	}
}

func TestPostgresRecoveryFinalizationWorkerLeavesNotDueRequestPendingIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}

	worker, err := NewRecoveryFinalizationWorker(f.db, RecoveryFinalizationWorkerConfig{})
	if err != nil {
		t.Fatalf("create recovery finalizer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	finalized, err := worker.runOnce(ctx)
	if err != nil {
		t.Fatalf("worker scan: %v", err)
	}
	if finalized != 0 {
		t.Fatalf("worker finalized %d not-due requests; want 0", finalized)
	}

	var status string
	if err := f.db.QueryRowContext(ctx, `SELECT status FROM account_recovery_requests WHERE request_id=$1::uuid`, uuidText(f.recoveryRequestID)).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(RecoveryRequestPending) {
		t.Fatalf("not-due request status=%s; want PENDING", status)
	}
}

func TestPostgresRecoveryFinalizationWorkerContinuesAfterOneRequestFailsIntegration(t *testing.T) {
	bad := newRecoveryLifecycleFixture(t)
	if _, err := bad.begin(); err != nil {
		t.Fatalf("begin first recovery: %v", err)
	}
	forceRecoveryDueForTest(t, bad.db, bad.recoveryRequestID)

	good := newRecoveryLifecycleFixture(t)
	if _, err := good.begin(); err != nil {
		t.Fatalf("begin second recovery: %v", err)
	}
	forceRecoveryDueForTest(t, good.db, good.recoveryRequestID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Introduce an account/auth epoch inconsistency in one isolated fixture.
	// That request must fail closed, but it must not prevent another due account
	// in the same batch from being finalized.
	if _, err := bad.db.ExecContext(ctx, `UPDATE accounts SET account_epoch=2 WHERE account_id=$1::uuid`, uuidText(bad.base.accountID)); err != nil {
		t.Fatalf("corrupt isolated fixture epoch: %v", err)
	}

	worker, err := NewRecoveryFinalizationWorker(bad.db, RecoveryFinalizationWorkerConfig{
		PollInterval:   5 * time.Minute,
		BatchSize:      10,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("create recovery finalizer: %v", err)
	}

	finalized, err := worker.runOnce(ctx)
	if err != nil {
		t.Fatalf("worker scan: %v", err)
	}
	if finalized != 1 {
		t.Fatalf("worker finalized %d healthy requests; want 1", finalized)
	}

	var badStatus, goodStatus string
	if err := bad.db.QueryRowContext(ctx, `SELECT status FROM account_recovery_requests WHERE request_id=$1::uuid`, uuidText(bad.recoveryRequestID)).Scan(&badStatus); err != nil {
		t.Fatal(err)
	}
	if err := good.db.QueryRowContext(ctx, `SELECT status FROM account_recovery_requests WHERE request_id=$1::uuid`, uuidText(good.recoveryRequestID)).Scan(&goodStatus); err != nil {
		t.Fatal(err)
	}
	if badStatus != string(RecoveryRequestPending) || goodStatus != string(RecoveryRequestFinalized) {
		t.Fatalf("worker failure isolation mismatch: bad=%s good=%s", badStatus, goodStatus)
	}
}

func TestPostgresRecoveryFinalizationWorkerConcurrentSameRequestIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)

	state, err := f.begin()
	if err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	forceRecoveryDueForTest(t, f.db, f.recoveryRequestID)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// The worker scans every due PENDING request in this database, not only
	// this fixture's request. Keep the integration database deterministic.
	var dueRequestCount int
	if err := f.db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM account_recovery_requests
		WHERE status = 'PENDING'
		  AND finalize_after <= clock_timestamp()
	`).Scan(&dueRequestCount); err != nil {
		t.Fatalf("count due recovery requests: %v", err)
	}
	if dueRequestCount != 1 {
		t.Fatalf(
			"expected exactly one due PENDING recovery request in integration database; found %d",
			dueRequestCount,
		)
	}

	// Hold the account row so both workers must wait at the same
	// account-level serialization point before either can finalize.
	lockTx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin account lock transaction: %v", err)
	}
	defer lockTx.Rollback()

	var blockerPID int
	if err := lockTx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatalf("read lock-holder backend PID: %v", err)
	}

	var lockedAccountID string
	if err := lockTx.QueryRowContext(ctx, `
		SELECT account_id::text
		FROM accounts
		WHERE account_id = $1::uuid
		FOR UPDATE
	`, uuidText(f.base.accountID)).Scan(&lockedAccountID); err != nil {
		t.Fatalf("lock recovery account: %v", err)
	}
	if lockedAccountID != uuidText(f.base.accountID) {
		t.Fatalf("locked unexpected account: %s", lockedAccountID)
	}

	config := RecoveryFinalizationWorkerConfig{
		PollInterval:   5 * time.Minute,
		BatchSize:      10,
		RequestTimeout: 15 * time.Second,
	}

	workerA, err := NewRecoveryFinalizationWorker(f.db, config)
	if err != nil {
		t.Fatalf("create worker A: %v", err)
	}
	workerB, err := NewRecoveryFinalizationWorker(f.db, config)
	if err != nil {
		t.Fatalf("create worker B: %v", err)
	}

	type workerResult struct {
		finalized int
		err       error
	}

	results := make(chan workerResult, 2)
	start := make(chan struct{})

	runWorker := func(worker *RecoveryFinalizationWorker) {
		<-start
		finalized, runErr := worker.runOnce(ctx)
		results <- workerResult{
			finalized: finalized,
			err:       runErr,
		}
	}

	go runWorker(workerA)
	go runWorker(workerB)
	close(start)

	// Wait for PostgreSQL to confirm that both distinct worker sessions
	// are waiting on a lock chain rooted at the transaction holding the
	// account row. One worker may queue behind the other, so checking only
	// direct blockers would miss that second session.
	deadline := time.Now().Add(10 * time.Second)
	var blockedSessions int64

	for time.Now().Before(deadline) {
		err := f.db.QueryRowContext(ctx, `
			WITH RECURSIVE wait_chain(waiter_pid, blocker_pid, path) AS (
				SELECT
					a.pid,
					p.blocker_pid,
					ARRAY[a.pid, p.blocker_pid]
				FROM pg_stat_activity a
				CROSS JOIN LATERAL
					unnest(pg_blocking_pids(a.pid)) AS p(blocker_pid)
				WHERE a.datname = current_database()
				  AND a.pid <> $1
				  AND a.wait_event_type = 'Lock'

				UNION ALL

				SELECT
					wc.waiter_pid,
					p.blocker_pid,
					wc.path || p.blocker_pid
				FROM wait_chain wc
				CROSS JOIN LATERAL
					unnest(pg_blocking_pids(wc.blocker_pid)) AS p(blocker_pid)
				WHERE NOT p.blocker_pid = ANY(wc.path)
			)
			SELECT count(DISTINCT a.pid)
			FROM pg_stat_activity a
			WHERE a.datname = current_database()
			  AND a.pid <> $1
			  AND a.wait_event_type = 'Lock'
			  AND a.query ILIKE '%FROM accounts%'
			  AND a.query ILIKE '%FOR UPDATE%'
			  AND EXISTS (
				  SELECT 1
				  FROM wait_chain wc
				  WHERE wc.waiter_pid = a.pid
				    AND wc.blocker_pid = $1
			  )
		`, blockerPID).Scan(&blockedSessions)
		if err != nil {
			t.Fatalf("inspect blocked worker sessions: %v", err)
		}

		if blockedSessions >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if blockedSessions < 2 {
		t.Fatalf(
			"expected two worker sessions blocked by backend %d; observed %d",
			blockerPID,
			blockedSessions,
		)
	}

	// Release the account lock. One worker should finalize; the other
	// should observe FINALIZED and take the idempotent retry path.
	if err := lockTx.Commit(); err != nil {
		t.Fatalf("release account lock: %v", err)
	}

	var workerResults [2]workerResult
	for i := range workerResults {
		select {
		case workerResults[i] = <-results:
		case <-ctx.Done():
			t.Fatalf("workers did not finish: %v", ctx.Err())
		}
	}

	for i, result := range workerResults {
		if result.err != nil {
			t.Errorf("worker %d returned error: %v", i+1, result.err)
		}
		if result.finalized != 1 {
			t.Errorf(
				"worker %d reported %d finalized requests; want 1",
				i+1,
				result.finalized,
			)
		}
	}

	var requestStatus string
	if err := f.db.QueryRowContext(ctx, `
		SELECT status
		FROM account_recovery_requests
		WHERE request_id = $1::uuid
	`, uuidText(f.recoveryRequestID)).Scan(&requestStatus); err != nil {
		t.Fatal(err)
	}

	var accountEpoch, authEpoch int64
	var authStatus int

	if err := f.db.QueryRowContext(ctx, `
		SELECT account_epoch
		FROM accounts
		WHERE account_id = $1::uuid
	`, uuidText(f.base.accountID)).Scan(&accountEpoch); err != nil {
		t.Fatal(err)
	}

	if err := f.db.QueryRowContext(ctx, `
		SELECT epoch, status
		FROM authorization_accounts
		WHERE account_id = $1::uuid
	`, uuidText(f.base.accountID)).Scan(&authEpoch, &authStatus); err != nil {
		t.Fatal(err)
	}

	if requestStatus != string(RecoveryRequestFinalized) ||
		accountEpoch != 2 ||
		authEpoch != 2 ||
		authStatus != int(AccountRecoveryLocked) {
		t.Fatalf(
			"concurrent finalization state mismatch: request=%s account_epoch=%d auth_epoch=%d auth_status=%d",
			requestStatus,
			accountEpoch,
			authEpoch,
			authStatus,
		)
	}

	// Both workers processed the same request, but the database must
	// contain exactly one matching RECOVERY_FINALIZED event.
	var eventCount int64
	if err := f.db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM authorization_events
		WHERE auth_digest = $1
		  AND kind = 'RECOVERY_FINALIZED'
		  AND account_id = $2::uuid
		  AND old_epoch = 1
		  AND new_epoch = 2
		  AND target_device_id = $3::uuid
	`,
		state.RequestDigest[:],
		uuidText(f.base.accountID),
		uuidText(f.base.deviceID),
	).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}

	if eventCount != 1 {
		t.Fatalf(
			"concurrent finalization created %d matching lifecycle events; want exactly 1",
			eventCount,
		)
	}
}
