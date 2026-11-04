package authorization

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

type recoveryChallengeAbortRaceResult struct {
	operation string
	challenge EnrollmentChallenge
	state     RecoveryRequestState
	err       error
}

func runRecoveryChallengeAbortRace(
	t *testing.T,
	issuanceFirst bool,
) {
	t.Helper()

	f := newRecoveryLifecycleFixture(t)

	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}

	// Use a separate active device to authorize the abort.
	abortingDeviceID, abortingDevicePrivate := f.addActiveDevice()
	abortRaw := f.signedAbort(abortingDeviceID, abortingDevicePrivate)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	blockerConn, err := f.db.Conn(ctx)
	if err != nil {
		t.Fatalf("obtain account-lock blocker connection: %v", err)
	}
	defer blockerConn.Close()

	blockerTx, err := blockerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin account-lock blocker transaction: %v", err)
	}
	defer blockerTx.Rollback()

	var blockerPID int
	if err := blockerConn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatalf("read account-lock blocker PID: %v", err)
	}

	var lockedAccount string
	if err := blockerTx.QueryRowContext(
		ctx,
		`SELECT account_id::text
         FROM accounts
         WHERE account_id = $1::uuid
         FOR UPDATE`,
		uuidText(f.base.accountID),
	).Scan(&lockedAccount); err != nil {
		t.Fatalf("lock fixture account row: %v", err)
	}

	results := make(chan recoveryChallengeAbortRaceResult, 2)

	startIssuance := func() {
		go func() {
			challenge, err := f.authorizer.IssueRecoveryEnrollmentChallenge(
				ctx,
				f.recoveryRequestID,
				f.enrollmentRaw,
				f.base.recoveryPublic,
			)
			results <- recoveryChallengeAbortRaceResult{
				operation: "issue_challenge",
				challenge: challenge,
				err:       err,
			}
		}()
	}

	startAbort := func() {
		go func() {
			state, err := f.authorizer.AbortRecovery(ctx, abortRaw)
			results <- recoveryChallengeAbortRaceResult{
				operation: "abort_recovery",
				state:     state,
				err:       err,
			}
		}()
	}

	// Queue the intended first operation behind the account-row lock.
	if issuanceFirst {
		startIssuance()
	} else {
		startAbort()
	}

	if err := waitForAccountRowLockWaiters(ctx, f.db, blockerPID, 1); err != nil {
		t.Fatalf("first operation did not reach account-row lock: %v", err)
	}

	// Queue the competing operation behind it.
	if issuanceFirst {
		startAbort()
	} else {
		startIssuance()
	}

	if err := waitForAccountRowLockWaiters(ctx, f.db, blockerPID, 2); err != nil {
		t.Fatalf("both operations did not reach account-row lock: %v", err)
	}

	if err := blockerTx.Commit(); err != nil {
		t.Fatalf("release account-row lock: %v", err)
	}

	var issueResult, abortResult recoveryChallengeAbortRaceResult

	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			switch result.operation {
			case "issue_challenge":
				issueResult = result
			case "abort_recovery":
				abortResult = result
			default:
				t.Fatalf("unexpected race operation: %q", result.operation)
			}
		case <-ctx.Done():
			t.Fatalf("timed out collecting race results: %v", ctx.Err())
		}
	}

	if issueResult.operation == "" || abortResult.operation == "" {
		t.Fatalf(
			"missing race results: issue=%q abort=%q",
			issueResult.operation,
			abortResult.operation,
		)
	}

	if abortResult.err != nil {
		t.Fatalf("AbortRecovery failed: %v", abortResult.err)
	}

	if abortResult.state.Status != RecoveryRequestAborted {
		t.Fatalf(
			"abort returned status=%s; want %s",
			abortResult.state.Status,
			RecoveryRequestAborted,
		)
	}

	if abortResult.state.AbortedAt == nil ||
		!abortResult.state.AbortedAt.Before(abortResult.state.FinalizeAfter) ||
		abortResult.state.AbortingDeviceID != abortingDeviceID {
		t.Fatalf("unexpected aborted recovery state: %+v", abortResult.state)
	}

	if issuanceFirst {
		if !errors.Is(issueResult.err, ErrRecoveryNotReady) {
			t.Fatalf(
				"issuance queued before abort on pending request: got %v, want ErrRecoveryNotReady",
				issueResult.err,
			)
		}
	} else {
		if !errors.Is(issueResult.err, ErrRecoveryAborted) {
			t.Fatalf(
				"issuance queued after abort: got %v, want ErrRecoveryAborted",
				issueResult.err,
			)
		}
	}

	if issueResult.challenge.ID != ([16]byte{}) {
		t.Fatalf(
			"rejected challenge issuance returned nonzero challenge ID: %s",
			uuidText(issueResult.challenge.ID),
		)
	}

	// Verify the exact aborted request and its persisted abort evidence.
	var persistedStatus string
	var persistedAbortingDevice string
	var persistedAbortedAt sql.NullTime
	var persistedAbortCBOR []byte

	err = f.db.QueryRowContext(ctx, `
SELECT status,
       aborting_device_id::text,
       aborted_at,
       abort_cbor
FROM account_recovery_requests
WHERE account_id = $1::uuid
  AND request_id = $2::uuid
`, uuidText(f.base.accountID), uuidText(f.recoveryRequestID)).Scan(
		&persistedStatus,
		&persistedAbortingDevice,
		&persistedAbortedAt,
		&persistedAbortCBOR,
	)
	if err != nil {
		t.Fatalf("inspect persisted aborted recovery request: %v", err)
	}

	if persistedStatus != string(RecoveryRequestAborted) ||
		persistedAbortingDevice != uuidText(abortingDeviceID) ||
		!persistedAbortedAt.Valid ||
		!bytes.Equal(persistedAbortCBOR, abortRaw) {
		t.Fatalf(
			"persisted abort evidence mismatch: status=%q aborting_device=%q aborted_at_valid=%v abort_cbor_matches=%v",
			persistedStatus,
			persistedAbortingDevice,
			persistedAbortedAt.Valid,
			bytes.Equal(persistedAbortCBOR, abortRaw),
		)
	}

	// No recovery challenge may be created while the request is pending
	// or after it becomes aborted.
	var recoveryChallenges int64

	if err := f.db.QueryRowContext(ctx, `
SELECT count(*)
FROM device_enrollment_challenges
WHERE account_id = $1::uuid
  AND device_id = $2::uuid
  AND recovery_request_id = $3::uuid
`, uuidText(f.base.accountID),
		uuidText(f.base.deviceID),
		uuidText(f.recoveryRequestID),
	).Scan(&recoveryChallenges); err != nil {
		t.Fatalf("count recovery-bound challenges: %v", err)
	}

	if recoveryChallenges != 0 {
		t.Fatalf(
			"aborted recovery has %d recovery-bound challenge rows; want zero",
			recoveryChallenges,
		)
	}

	// Abort must not advance or lock the account.
	var accountEpoch, authEpoch int64
	var accountStatus int

	err = f.db.QueryRowContext(ctx, `
SELECT a.account_epoch, aa.epoch, aa.status
FROM accounts a
JOIN authorization_accounts aa ON aa.account_id = a.account_id
WHERE a.account_id = $1::uuid
`, uuidText(f.base.accountID)).Scan(
		&accountEpoch,
		&authEpoch,
		&accountStatus,
	)
	if err != nil {
		t.Fatalf("inspect account after abort: %v", err)
	}

	if accountEpoch != 1 ||
		authEpoch != 1 ||
		accountStatus != int(AccountActive) {
		t.Fatalf(
			"abort unexpectedly changed account state: account_epoch=%d auth_epoch=%d status=%d",
			accountEpoch,
			authEpoch,
			accountStatus,
		)
	}

	// The device authorizing abort must remain active at the old epoch.
	var abortingDeviceStatus, abortingDeviceEpoch int64
	var abortingAuthorizedEpoch, abortingRevokedEpoch int64

	err = f.db.QueryRowContext(ctx, `
SELECT d.account_epoch,
       ad.status,
       ad.authorized_epoch,
       ad.revoked_epoch
FROM devices d
JOIN authorization_devices ad
  ON ad.device_id = d.device_id
 AND ad.account_id = d.account_id
WHERE d.account_id = $1::uuid
  AND d.device_id = $2::uuid
`, uuidText(f.base.accountID), uuidText(abortingDeviceID)).Scan(
		&abortingDeviceEpoch,
		&abortingDeviceStatus,
		&abortingAuthorizedEpoch,
		&abortingRevokedEpoch,
	)
	if err != nil {
		t.Fatalf("inspect aborting device after abort: %v", err)
	}

	if abortingDeviceEpoch != 1 ||
		abortingDeviceStatus != 1 ||
		abortingAuthorizedEpoch != 1 ||
		abortingRevokedEpoch != 0 {
		t.Fatalf(
			"abort unexpectedly changed authorizing device: device_epoch=%d status=%d authorized_epoch=%d revoked_epoch=%d",
			abortingDeviceEpoch,
			abortingDeviceStatus,
			abortingAuthorizedEpoch,
			abortingRevokedEpoch,
		)
	}

	if issuanceFirst {
		t.Log("valid serialization: challenge issuance observed PENDING and returned ErrRecoveryNotReady; abort then committed ABORTED")
		return
	}

	t.Log("valid serialization: abort committed ABORTED first; queued challenge issuance returned ErrRecoveryAborted")
}

func TestPostgresRecoveryChallengeAbortIssuanceQueuedFirstRaceIntegration(t *testing.T) {
	runRecoveryChallengeAbortRace(t, true)
}

func TestPostgresRecoveryChallengeAbortAbortQueuedFirstRaceIntegration(t *testing.T) {
	runRecoveryChallengeAbortRace(t, false)
}
