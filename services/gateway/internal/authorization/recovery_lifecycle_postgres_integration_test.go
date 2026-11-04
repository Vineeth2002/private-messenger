package authorization

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

type recoveryLifecycleFixture struct {
	t                 *testing.T
	db                *sql.DB
	base              *candidateEnrollmentPGFixture
	authorizer        *PostgresAuthorizer
	enrollmentRaw     []byte
	recoveryRequest   []byte
	recoveryRequestID [16]byte
}

func newRecoveryLifecycleFixture(t *testing.T) *recoveryLifecycleFixture {
	t.Helper()
	db := openCandidateEnrollmentIntegrationDB(t)
	var ready bool
	if err := db.QueryRow(`SELECT to_regclass('public.account_recovery_requests') IS NOT NULL`).Scan(&ready); err != nil {
		t.Fatalf("inspect recovery schema: %v", err)
	}
	if !ready {
		t.Fatal("migration 0008 is not installed in the dedicated integration database")
	}

	base := newCandidateEnrollmentPGFixture(t, db)
	f := &recoveryLifecycleFixture{t: t, db: db, base: base, authorizer: base.authorizer}
	// Register after newCandidateEnrollmentPGFixture: cleanup runs first and
	// removes the immutable recovery row using test-database owner privileges.
	t.Cleanup(f.cleanupRecoveryRows)

	f.enrollmentRaw = f.targetEnrollmentCertificate(2)
	f.recoveryRequestID = randomCandidateEnrollmentID(t)
	f.recoveryRequest = signTestRecoveryRequestV1(
		t, base.recoveryPriv, base.accountID, 1, 2,
		f.recoveryRequestID, base.deviceID, f.enrollmentRaw,
	)
	return f
}

func (f *recoveryLifecycleFixture) targetEnrollmentCertificate(epoch uint64) []byte {
	f.t.Helper()
	cert := testEnrollmentCert(
		f.t, f.base.recoveryPriv, f.base.accountID, f.base.deviceID,
		epoch, f.base.certificate.DSKPub, f.base.certificate.DDHKPub,
	)
	return cert.Raw
}

func (f *recoveryLifecycleFixture) begin() (RecoveryRequestState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return f.authorizer.BeginRecovery(ctx, f.recoveryRequest, f.enrollmentRaw, f.base.recoveryPublic)
}

func (f *recoveryLifecycleFixture) cleanupRecoveryRows() {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		f.t.Errorf("begin recovery-fixture cleanup: %v", err)
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `ALTER TABLE account_recovery_requests DISABLE TRIGGER account_recovery_requests_block_delete_trg`); err != nil {
		f.t.Errorf("disable recovery delete guard for test cleanup: %v", err)
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM device_enrollment_challenges WHERE account_id = $1::uuid`, uuidText(f.base.accountID)); err != nil {
		f.t.Errorf("delete recovery-fixture challenges: %v", err)
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_recovery_requests WHERE account_id = $1::uuid`, uuidText(f.base.accountID)); err != nil {
		f.t.Errorf("delete recovery-fixture requests: %v", err)
		return
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE account_recovery_requests ENABLE TRIGGER account_recovery_requests_block_delete_trg`); err != nil {
		f.t.Errorf("re-enable recovery delete guard after test cleanup: %v", err)
		return
	}
	if err := tx.Commit(); err != nil {
		f.t.Errorf("commit recovery-fixture cleanup: %v", err)
	}
}

func (f *recoveryLifecycleFixture) addActiveDevice() ([16]byte, ed25519.PrivateKey) {
	f.t.Helper()
	deviceID := randomCandidateEnrollmentID(f.t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatalf("generate aborting DSK: %v", err)
	}
	ddhkPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatalf("generate aborting DDHK: %v", err)
	}
	var dsk, ddhk [32]byte
	copy(dsk[:], publicKey)
	copy(ddhk[:], ddhkPrivate.PublicKey().Bytes())
	digest := sha256.Sum256(append(append([]byte(nil), deviceID[:]...), dsk[:]...))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := f.db.ExecContext(ctx, `
INSERT INTO devices (device_id, account_id, account_epoch, dsk_pub, ddhk_pub, push_pub, revoked_at)
VALUES ($1::uuid, $2::uuid, 1, $3, $4, NULL, NULL)
`, uuidText(deviceID), uuidText(f.base.accountID), dsk[:], ddhk[:]); err != nil {
		f.t.Fatalf("insert active device row: %v", err)
	}
	if _, err := f.db.ExecContext(ctx, `
INSERT INTO authorization_devices (
    device_id, account_id, dsk_pub, ddhk_pub, status,
    authorized_epoch, enrollment_auth_digest, revoked_epoch
) VALUES ($1::uuid, $2::uuid, $3, $4, 1, 1, $5, 0)
`, uuidText(deviceID), uuidText(f.base.accountID), dsk[:], ddhk[:], digest[:]); err != nil {
		f.t.Fatalf("insert active authorization device row: %v", err)
	}
	return deviceID, privateKey
}

func (f *recoveryLifecycleFixture) signedAbort(deviceID [16]byte, private ed25519.PrivateKey) []byte {
	f.t.Helper()
	request, err := ParseRecoveryRequestV1(f.recoveryRequest)
	if err != nil {
		f.t.Fatal(err)
	}
	abort := RecoveryAbortV1{
		AccountID:             request.AccountID,
		DeviceID:              deviceID,
		OldEpoch:              request.OldEpoch,
		NewEpoch:              request.NewEpoch,
		RequestID:             request.RequestID,
		RecoveryRequestDigest: request.Digest(),
	}
	core, err := abort.canonicalCore()
	if err != nil {
		f.t.Fatal(err)
	}
	abort.Signature = [64]byte{}
	copy(abort.Signature[:], ed25519.Sign(private, append([]byte(RecoveryAbortDomain), core...)))
	raw, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: []cbor.Pair{
		uintPair(1, AuthorizationProtocolVersion),
		bytesPair(2, abort.AccountID[:]),
		bytesPair(3, abort.DeviceID[:]),
		uintPair(4, abort.OldEpoch),
		uintPair(5, abort.NewEpoch),
		bytesPair(6, abort.RequestID[:]),
		bytesPair(7, abort.RecoveryRequestDigest[:]),
		bytesPair(8, abort.Signature[:]),
	}})
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func forceRecoveryDueForTest(t *testing.T, db *sql.DB, requestID [16]byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `ALTER TABLE account_recovery_requests DISABLE TRIGGER account_recovery_requests_guard_update_trg`); err != nil {
		t.Fatalf("disable update guard to age disposable test fixture: %v", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE account_recovery_requests
SET finalize_after = accepted_at + INTERVAL '1 microsecond'
WHERE request_id = $1::uuid AND status = 'PENDING'
`, uuidText(requestID))
	if err != nil {
		t.Fatalf("age disposable recovery fixture: %v", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		t.Fatalf("aged recovery rows=%d err=%v; want one", changed, err)
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE account_recovery_requests ENABLE TRIGGER account_recovery_requests_guard_update_trg`); err != nil {
		t.Fatalf("re-enable recovery update guard: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit aged recovery fixture: %v", err)
	}
}

func TestPostgresBeginRecoveryPersistsReplaysAndBlocksEnrollmentIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	challenge, err := f.base.issueChallenge()
	if err != nil {
		t.Fatalf("issue ordinary enrollment challenge: %v", err)
	}

	first, err := f.begin()
	if err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	if first.Status != RecoveryRequestPending || first.FinalizeAfter.Sub(first.AcceptedAt) != 48*time.Hour {
		t.Fatalf("unexpected persisted recovery state: %+v", first)
	}
	// A fresh authorizer instance proves the pending request is read from PostgreSQL,
	// not retained in process-local state.
	restartedAuthorizer := NewPostgresAuthorizer(f.db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	second, err := restartedAuthorizer.BeginRecovery(ctx, f.recoveryRequest, f.enrollmentRaw, f.base.recoveryPublic)
	if err != nil {
		t.Fatalf("exact begin retry: %v", err)
	}
	if second.RequestDigest != first.RequestDigest || !second.AcceptedAt.Equal(first.AcceptedAt) || !second.FinalizeAfter.Equal(first.FinalizeAfter) {
		t.Fatalf("exact retry returned different recovery state: first=%+v second=%+v", first, second)
	}

	conflictingTarget := randomCandidateEnrollmentID(t)
	conflictingEnrollment := testEnrollmentCert(
		t, f.base.recoveryPriv, f.base.accountID, conflictingTarget, 2,
		f.base.certificate.DSKPub, f.base.certificate.DDHKPub,
	)
	conflictingRequest := signTestRecoveryRequestV1(
		t, f.base.recoveryPriv, f.base.accountID, 1, 2,
		f.recoveryRequestID, conflictingTarget, conflictingEnrollment.Raw,
	)
	if _, err := restartedAuthorizer.BeginRecovery(ctx, conflictingRequest, conflictingEnrollment.Raw, f.base.recoveryPublic); !errors.Is(err, ErrAuthorizationConflict) {
		t.Fatalf("same request ID with different signed bytes: got %v, want ErrAuthorizationConflict", err)
	}

	var challengeConsumed bool
	if err := f.db.QueryRow(`SELECT consumed_at IS NOT NULL FROM device_enrollment_challenges WHERE challenge_id = $1::uuid`, uuidText(challenge.ID)).Scan(&challengeConsumed); err != nil {
		t.Fatal(err)
	}
	if !challengeConsumed {
		t.Fatal("begin recovery did not invalidate the outstanding ordinary enrollment challenge")
	}

	otherID := randomCandidateEnrollmentID(t)
	otherRequest := signTestRecoveryRequestV1(t, f.base.recoveryPriv, f.base.accountID, 1, 2, otherID, f.base.deviceID, f.enrollmentRaw)
	if _, err := f.authorizer.BeginRecovery(ctx, otherRequest, f.enrollmentRaw, f.base.recoveryPublic); !errors.Is(err, ErrRecoveryPending) {
		t.Fatalf("second pending recovery: got %v, want ErrRecoveryPending", err)
	}
	if _, err := f.base.issueChallenge(); !errors.Is(err, ErrRecoveryPending) {
		t.Fatalf("ordinary challenge during pending recovery: got %v, want ErrRecoveryPending", err)
	}
	if err := f.base.activate(f.base.proofFor(challenge)); !errors.Is(err, ErrRecoveryPending) {
		t.Fatalf("ordinary activation during pending recovery: got %v, want ErrRecoveryPending", err)
	}
	activeDeviceID, _ := f.addActiveDevice()
	revoke := testTransitionCert(t, f.base.recoveryPriv, f.base.accountID, activeDeviceID, 1, 2, RevokeDeviceAction)
	if err := f.authorizer.Transition(ctx, revoke, f.base.recoveryPublic); !errors.Is(err, ErrRecoveryPending) {
		t.Fatalf("device revoke during pending recovery: got %v, want ErrRecoveryPending", err)
	}

	var accountEpoch, authEpoch int64
	var authStatus int
	if err := f.db.QueryRow(`SELECT account_epoch FROM accounts WHERE account_id=$1::uuid`, uuidText(f.base.accountID)).Scan(&accountEpoch); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT epoch,status FROM authorization_accounts WHERE account_id=$1::uuid`, uuidText(f.base.accountID)).Scan(&authEpoch, &authStatus); err != nil {
		t.Fatal(err)
	}
	if accountEpoch != 1 || authEpoch != 1 || authStatus != int(AccountActive) {
		t.Fatalf("begin recovery changed account authorization early: account epoch=%d auth epoch=%d status=%d", accountEpoch, authEpoch, authStatus)
	}
}

func TestPostgresAbortRecoveryRequiresActiveDeviceAndPersistsExactRetryIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	deviceID, privateKey := f.addActiveDevice()
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongAbort := f.signedAbort(deviceID, wrongPrivate)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := f.authorizer.AbortRecovery(ctx, wrongAbort); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("abort signed by wrong DSK: got %v, want ErrInvalidAuthorization", err)
	}
	abortRaw := f.signedAbort(deviceID, privateKey)

	state, err := f.authorizer.AbortRecovery(ctx, abortRaw)
	if err != nil {
		t.Fatalf("valid active-device abort: %v", err)
	}
	if state.Status != RecoveryRequestAborted || state.AbortedAt == nil || !state.AbortedAt.Before(state.FinalizeAfter) || state.AbortingDeviceID != deviceID {
		t.Fatalf("unexpected aborted recovery state: %+v", state)
	}
	restartedAuthorizer := NewPostgresAuthorizer(f.db)
	retry, err := restartedAuthorizer.AbortRecovery(ctx, abortRaw)
	if err != nil {
		t.Fatalf("exact abort retry: %v", err)
	}
	if retry.Status != RecoveryRequestAborted || retry.AbortingDeviceID != deviceID || retry.AbortedAt == nil || !retry.AbortedAt.Equal(*state.AbortedAt) {
		t.Fatalf("exact abort retry returned changed state: %+v", retry)
	}
	if _, err := f.authorizer.FinalizeRecovery(ctx, f.base.accountID, f.recoveryRequestID); !errors.Is(err, ErrRecoveryAborted) {
		t.Fatalf("finalize aborted recovery: got %v, want ErrRecoveryAborted", err)
	}
}

func TestPostgresAbortRecoveryRejectsRevokedDeviceIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	deviceID, privateKey := f.addActiveDevice()
	abortRaw := f.signedAbort(deviceID, privateKey)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := f.db.ExecContext(ctx, `UPDATE authorization_devices SET status=2, revoked_epoch=1 WHERE device_id=$1::uuid`, uuidText(deviceID)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(ctx, `UPDATE devices SET revoked_at=clock_timestamp() WHERE device_id=$1::uuid`, uuidText(deviceID)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.authorizer.AbortRecovery(ctx, abortRaw); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("abort from revoked device: got %v, want ErrDeviceRevoked", err)
	}
}

func TestPostgresFinalizeRecoveryRequiresDeadlineAndRevokesAllDevicesIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	device1, _ := f.addActiveDevice()
	device2, _ := f.addActiveDevice()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := f.authorizer.FinalizeRecovery(ctx, f.base.accountID, f.recoveryRequestID); !errors.Is(err, ErrRecoveryNotReady) {
		t.Fatalf("premature finalization: got %v, want ErrRecoveryNotReady", err)
	}

	forceRecoveryDueForTest(t, f.db, f.recoveryRequestID)
	state, err := f.authorizer.FinalizeRecovery(ctx, f.base.accountID, f.recoveryRequestID)
	if err != nil {
		t.Fatalf("due recovery finalization: %v", err)
	}
	if state.Status != RecoveryRequestFinalized || state.FinalizedAt == nil || state.FinalizedAt.Before(state.FinalizeAfter) {
		t.Fatalf("unexpected finalized state: %+v", state)
	}

	var accountEpoch, authEpoch int64
	var authStatus int
	if err := f.db.QueryRowContext(ctx, `SELECT account_epoch FROM accounts WHERE account_id=$1::uuid`, uuidText(f.base.accountID)).Scan(&accountEpoch); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT epoch,status FROM authorization_accounts WHERE account_id=$1::uuid`, uuidText(f.base.accountID)).Scan(&authEpoch, &authStatus); err != nil {
		t.Fatal(err)
	}
	if accountEpoch != 2 || authEpoch != 2 || authStatus != int(AccountRecoveryLocked) {
		t.Fatalf("finalization account state mismatch: account epoch=%d auth epoch=%d status=%d", accountEpoch, authEpoch, authStatus)
	}
	var activeCount, revokedCount, eventCount int64
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM authorization_devices WHERE account_id=$1::uuid AND status=1`, uuidText(f.base.accountID)).Scan(&activeCount); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM authorization_devices WHERE account_id=$1::uuid AND status=2 AND revoked_epoch=2`, uuidText(f.base.accountID)).Scan(&revokedCount); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM authorization_events WHERE auth_digest=$1 AND kind='RECOVERY_FINALIZED' AND account_id=$2::uuid AND old_epoch=1 AND new_epoch=2 AND target_device_id=$3::uuid`, state.RequestDigest[:], uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if activeCount != 0 || revokedCount != 2 || eventCount != 1 {
		t.Fatalf("finalization side effects mismatch: active=%d revoked_at_epoch2=%d event=%d (device ids %s %s)", activeCount, revokedCount, eventCount, uuidText(device1), uuidText(device2))
	}

	// The append-only trigger must reject UPDATE, DELETE, and TRUNCATE attempts.
	mutationAttempts := []struct {
		name string
		stmt string
	}{
		{
			name: "update",
			stmt: `UPDATE authorization_events SET payload_cbor = payload_cbor WHERE auth_digest = $1`,
		},
		{
			name: "delete",
			stmt: `DELETE FROM authorization_events WHERE auth_digest = $1`,
		},
		{
			name: "truncate",
			stmt: `TRUNCATE authorization_events`,
		},
	}
	for _, attempt := range mutationAttempts {
		var err error
		if attempt.name == "truncate" {
			_, err = f.db.ExecContext(ctx, attempt.stmt)
		} else {
			_, err = f.db.ExecContext(ctx, attempt.stmt, state.RequestDigest[:])
		}
		if err == nil {
			t.Fatalf("authorization_events unexpectedly allowed %s", attempt.name)
		}
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM authorization_events WHERE auth_digest=$1`, state.RequestDigest[:]).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("append-only check changed or removed finalization event: count=%d", eventCount)
	}

	restartedAuthorizer := NewPostgresAuthorizer(f.db)
	retry, err := restartedAuthorizer.FinalizeRecovery(ctx, f.base.accountID, f.recoveryRequestID)
	if err != nil {
		t.Fatalf("exact finalize retry: %v", err)
	}
	if retry.Status != RecoveryRequestFinalized || retry.FinalizedAt == nil || !retry.FinalizedAt.Equal(*state.FinalizedAt) {
		t.Fatalf("finalize retry returned different state: %+v", retry)
	}
}

func TestPostgresFinalizeRecoveryCancellationRollsBackPartialWorkIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}

	deviceID, _ := f.addActiveDevice()
	forceRecoveryDueForTest(t, f.db, f.recoveryRequestID)

	// Hold the active authorization-device row so finalization blocks
	// specifically at its first device-revocation UPDATE.
	blocker, err := f.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin blocker transaction: %v", err)
	}
	defer blocker.Rollback()

	var lockedDeviceID string
	if err := blocker.QueryRowContext(context.Background(), `
SELECT device_id::text
FROM authorization_devices
WHERE device_id = $1::uuid AND account_id = $2::uuid AND status = 1
FOR UPDATE
`, uuidText(deviceID), uuidText(f.base.accountID)).Scan(&lockedDeviceID); err != nil {
		t.Fatalf("lock active authorization device: %v", err)
	}

	finalizeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type finalizeResult struct {
		err error
	}
	done := make(chan finalizeResult, 1)

	go func() {
		_, err := f.authorizer.FinalizeRecovery(
			finalizeCtx,
			f.base.accountID,
			f.recoveryRequestID,
		)
		done <- finalizeResult{err: err}
	}()

	// Do not treat a timeout alone as proof that the intended UPDATE
	// was blocked. Confirm the PostgreSQL backend is waiting on a lock
	// while executing the authorization_devices UPDATE.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	observeDeadline := time.NewTimer(2 * time.Second)
	defer observeDeadline.Stop()

	lockObserved := false
	for !lockObserved {
		select {
		case result := <-done:
			t.Fatalf("finalization returned before the expected device-row lock: %v", result.err)

		case <-observeDeadline.C:
			t.Fatal("finalization never appeared as a lock-waiting authorization_devices UPDATE")

		case <-ticker.C:
			queryCtx, queryCancel := context.WithTimeout(context.Background(), time.Second)
			err := f.db.QueryRowContext(queryCtx, `
SELECT EXISTS (
    SELECT 1
    FROM pg_stat_activity
    WHERE datname = current_database()
      AND state = 'active'
      AND wait_event_type = 'Lock'
      AND position('UPDATE authorization_devices' IN query) > 0
)
`).Scan(&lockObserved)
			queryCancel()
			if err != nil {
				t.Fatalf("inspect PostgreSQL lock wait: %v", err)
			}
		}
	}

	// The finalizer must now be canceled while it is blocked.
	result := <-done
	if result.err == nil {
		t.Fatal("finalization unexpectedly succeeded while its device update was blocked")
	}
	if !errors.Is(result.err, context.DeadlineExceeded) &&
		!errors.Is(result.err, context.Canceled) {
		t.Fatalf("finalization returned unexpected error after cancellation: %v", result.err)
	}

	// Release the row lock before inspecting persisted state.
	if err := blocker.Rollback(); err != nil {
		t.Fatalf("release blocker transaction: %v", err)
	}

	var recoveryStatus string
	if err := f.db.QueryRowContext(context.Background(), `
SELECT status
FROM account_recovery_requests
WHERE request_id = $1::uuid
`, uuidText(f.recoveryRequestID)).Scan(&recoveryStatus); err != nil {
		t.Fatalf("read recovery request status: %v", err)
	}
	if recoveryStatus != string(RecoveryRequestPending) {
		t.Fatalf("recovery request status=%s; want PENDING after rollback", recoveryStatus)
	}

	var accountEpoch, authorizationEpoch int64
	var authorizationStatus int
	if err := f.db.QueryRowContext(context.Background(), `
SELECT a.account_epoch, aa.epoch, aa.status
FROM accounts a
JOIN authorization_accounts aa ON aa.account_id = a.account_id
WHERE a.account_id = $1::uuid
`, uuidText(f.base.accountID)).Scan(
		&accountEpoch,
		&authorizationEpoch,
		&authorizationStatus,
	); err != nil {
		t.Fatalf("read account authorization state: %v", err)
	}
	if accountEpoch != 1 ||
		authorizationEpoch != 1 ||
		authorizationStatus != int(AccountActive) {
		t.Fatalf(
			"account state changed despite rollback: account_epoch=%d authorization_epoch=%d status=%d",
			accountEpoch, authorizationEpoch, authorizationStatus,
		)
	}

	var deviceStatus int
	var revokedEpoch int64
	if err := f.db.QueryRowContext(context.Background(), `
SELECT status, revoked_epoch
FROM authorization_devices
WHERE device_id = $1::uuid
`, uuidText(deviceID)).Scan(&deviceStatus, &revokedEpoch); err != nil {
		t.Fatalf("read authorization device state: %v", err)
	}
	if deviceStatus != 1 || revokedEpoch != 0 {
		t.Fatalf("authorization device changed despite rollback: status=%d revoked_epoch=%d", deviceStatus, revokedEpoch)
	}

	var deviceEpoch int64
	var revokedAt sql.NullTime
	if err := f.db.QueryRowContext(context.Background(), `
SELECT account_epoch, revoked_at
FROM devices
WHERE device_id = $1::uuid
`, uuidText(deviceID)).Scan(&deviceEpoch, &revokedAt); err != nil {
		t.Fatalf("read device directory state: %v", err)
	}
	if deviceEpoch != 1 || revokedAt.Valid {
		t.Fatalf("device directory state changed despite rollback: epoch=%d revoked_at=%v", deviceEpoch, revokedAt)
	}

	var finalizedEventCount int64
	if err := f.db.QueryRowContext(context.Background(), `
SELECT count(*)
FROM authorization_events
WHERE account_id = $1::uuid
  AND kind = 'RECOVERY_FINALIZED'
`, uuidText(f.base.accountID)).Scan(&finalizedEventCount); err != nil {
		t.Fatalf("count recovery finalization events: %v", err)
	}
	if finalizedEventCount != 0 {
		t.Fatalf("found %d RECOVERY_FINALIZED events after canceled transaction; want 0", finalizedEventCount)
	}
}

func TestPostgresAbortFinalizeRaceHasOneTerminalOutcomeIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	deviceID, privateKey := f.addActiveDevice()
	abortRaw := f.signedAbort(deviceID, privateKey)
	forceRecoveryDueForTest(t, f.db, f.recoveryRequestID)

	start := make(chan struct{})
	results := make(chan error, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() {
		<-start
		_, err := f.authorizer.AbortRecovery(ctx, abortRaw)
		results <- err
	}()
	go func() {
		<-start
		_, err := f.authorizer.FinalizeRecovery(ctx, f.base.accountID, f.recoveryRequestID)
		results <- err
	}()
	close(start)
	first, second := <-results, <-results
	if !((first == nil && (errors.Is(second, ErrRecoveryFinalized) || errors.Is(second, ErrRecoveryAbortWindowClosed))) ||
		(first != nil && (errors.Is(first, ErrRecoveryFinalized) || errors.Is(first, ErrRecoveryAbortWindowClosed)) && second == nil)) {
		t.Fatalf("abort/finalize race did not produce one finalization and one rejected abort: first=%v second=%v", first, second)
	}
	var status string
	if err := f.db.QueryRowContext(ctx, `SELECT status FROM account_recovery_requests WHERE request_id=$1::uuid`, uuidText(f.recoveryRequestID)).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(RecoveryRequestFinalized) {
		t.Fatalf("race terminal status=%s; want FINALIZED", status)
	}
}

func TestPostgresAbortFinalizeRaceBeforeDeadlineEndsAbortedIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	deviceID, privateKey := f.addActiveDevice()
	abortRaw := f.signedAbort(deviceID, privateKey)

	start := make(chan struct{})
	results := make(chan error, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() {
		<-start
		_, err := f.authorizer.AbortRecovery(ctx, abortRaw)
		results <- err
	}()
	go func() {
		<-start
		_, err := f.authorizer.FinalizeRecovery(ctx, f.base.accountID, f.recoveryRequestID)
		results <- err
	}()
	close(start)
	first, second := <-results, <-results
	var abortSucceeded bool
	if first == nil && (errors.Is(second, ErrRecoveryNotReady) || errors.Is(second, ErrRecoveryAborted)) {
		abortSucceeded = true
	} else if second == nil && (errors.Is(first, ErrRecoveryNotReady) || errors.Is(first, ErrRecoveryAborted)) {
		abortSucceeded = true
	}
	if !abortSucceeded {
		t.Fatalf("pre-deadline abort/finalize race did not resolve to ABORTED: first=%v second=%v", first, second)
	}
	var status string
	if err := f.db.QueryRowContext(ctx, `SELECT status FROM account_recovery_requests WHERE request_id=$1::uuid`, uuidText(f.recoveryRequestID)).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(RecoveryRequestAborted) {
		t.Fatalf("race terminal status=%s; want ABORTED", status)
	}
}
