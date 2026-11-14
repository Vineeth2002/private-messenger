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
