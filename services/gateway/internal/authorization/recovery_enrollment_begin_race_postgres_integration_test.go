package authorization

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
)

type recoveryEnrollmentRaceMaterial struct {
	ordinaryCertificate DeviceEnrollmentAuthorizationV1
	ordinaryDSKPrivate  ed25519.PrivateKey
	challenge           EnrollmentChallenge
	ordinaryProof       []byte
	recoveryCertificate DeviceEnrollmentAuthorizationV1
	recoveryRequestID   [16]byte
	recoveryRequest     []byte
}

type recoveryEnrollmentRaceResult struct {
	operation string
	state     RecoveryRequestState
	err       error
}

func recoveryEnrollmentRaceCertificate(
	t *testing.T,
	f *recoveryLifecycleFixture,
	epoch uint64,
) (DeviceEnrollmentAuthorizationV1, ed25519.PrivateKey) {
	t.Helper()

	deviceID := randomCandidateEnrollmentID(t)

	for deviceID == f.base.deviceID {
		deviceID = randomCandidateEnrollmentID(t)
	}

	dskPublicKey, dskPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate race-test DSK: %v", err)
	}

	var dskPublic [32]byte
	copy(dskPublic[:], dskPublicKey)

	ddhkPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate race-test DDHK: %v", err)
	}

	var ddhkPublic [32]byte
	copy(ddhkPublic[:], ddhkPrivateKey.PublicKey().Bytes())

	cert := testEnrollmentCert(
		t,
		f.base.recoveryPriv,
		f.base.accountID,
		deviceID,
		epoch,
		dskPublic,
		ddhkPublic,
	)

	return cert, dskPrivateKey
}

func recoveryEnrollmentRaceProof(
	t *testing.T,
	cert DeviceEnrollmentAuthorizationV1,
	challenge EnrollmentChallenge,
	dskPrivate ed25519.PrivateKey,
) []byte {
	t.Helper()

	digest := sha256.Sum256(cert.Raw)

	proof := DeviceEnrollmentPoPV1{
		AccountID:                   cert.AccountID,
		DeviceID:                    cert.DeviceID,
		Epoch:                       cert.Epoch,
		EnrollmentCertificateDigest: digest,
		ChallengeID:                 challenge.ID,
		ChallengeNonce:              challenge.Nonce,
	}

	core, err := proof.canonicalCore()
	if err != nil {
		t.Fatalf("encode enrollment proof core: %v", err)
	}

	message := append([]byte(DeviceEnrollmentPoPDomain), core...)
	copy(proof.Signature[:], ed25519.Sign(dskPrivate, message))

	return deviceEnrollmentPoPWireForTest(
		t,
		proof.AccountID,
		proof.DeviceID,
		proof.Epoch,
		proof.EnrollmentCertificateDigest,
		proof.ChallengeID,
		proof.ChallengeNonce,
		proof.Signature,
	)
}

func newRecoveryEnrollmentRaceMaterial(
	t *testing.T,
	f *recoveryLifecycleFixture,
	ctx context.Context,
) recoveryEnrollmentRaceMaterial {
	t.Helper()

	ordinaryCert, ordinaryPrivate :=
		recoveryEnrollmentRaceCertificate(t, f, 1)

	recoveryCert, _ :=
		recoveryEnrollmentRaceCertificate(t, f, 2)

	if ordinaryCert.DeviceID == recoveryCert.DeviceID {
		t.Fatal("ordinary enrollment and recovery target DeviceIDs must differ")
	}

	requestID := randomCandidateEnrollmentID(t)

	requestRaw := signTestRecoveryRequestV1(
		t,
		f.base.recoveryPriv,
		f.base.accountID,
		1,
		2,
		requestID,
		recoveryCert.DeviceID,
		recoveryCert.Raw,
	)

	challenge, err := f.authorizer.IssueCandidateEnrollmentChallenge(
		ctx,
		ordinaryCert.Raw,
		f.base.recoveryPublic,
	)
	if err != nil {
		t.Fatalf("issue ordinary enrollment challenge: %v", err)
	}

	proof := recoveryEnrollmentRaceProof(
		t,
		ordinaryCert,
		challenge,
		ordinaryPrivate,
	)

	return recoveryEnrollmentRaceMaterial{
		ordinaryCertificate: ordinaryCert,
		ordinaryDSKPrivate:  ordinaryPrivate,
		challenge:           challenge,
		ordinaryProof:       proof,
		recoveryCertificate: recoveryCert,
		recoveryRequestID:   requestID,
		recoveryRequest:     requestRaw,
	}
}

func waitForAccountRowLockWaiters(
	ctx context.Context,
	db *sql.DB,
	blockerPID int,
	minimum int,
) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		var waiters int

		err := db.QueryRowContext(ctx, `
WITH RECURSIVE wait_chain(waiter_pid, blocker_pid, path) AS (
    SELECT
        a.pid,
        p.blocker_pid,
        ARRAY[a.pid, p.blocker_pid]
    FROM pg_stat_activity AS a
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
    FROM wait_chain AS wc
    CROSS JOIN LATERAL
        unnest(pg_blocking_pids(wc.blocker_pid)) AS p(blocker_pid)
    WHERE NOT p.blocker_pid = ANY(wc.path)
)
SELECT count(DISTINCT waiter.pid)
FROM pg_stat_activity AS waiter
WHERE waiter.datname = current_database()
  AND waiter.pid <> $1
  AND waiter.wait_event_type = 'Lock'
  AND waiter.query ILIKE '%FROM accounts%'
  AND waiter.query ILIKE '%FOR UPDATE%'
  AND EXISTS (
      SELECT 1
      FROM wait_chain AS wc
      WHERE wc.waiter_pid = waiter.pid
        AND wc.blocker_pid = $1
  )
`, blockerPID).Scan(&waiters)

		if err != nil {
			return fmt.Errorf("inspect account-row lock waiters: %w", err)
		}

		if waiters >= minimum {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"timed out waiting for %d account-row lock waiter(s) blocked by backend %d: %w",
				minimum,
				blockerPID,
				ctx.Err(),
			)
		case <-ticker.C:
		}
	}
}
func runCandidateEnrollmentBeginRecoveryRace(
	t *testing.T,
	activationFirst bool,
) {
	t.Helper()

	f := newRecoveryLifecycleFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	material := newRecoveryEnrollmentRaceMaterial(t, f, ctx)

	// Hold the account row that both production operations must lock first.
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
		`SELECT account_id::text FROM accounts WHERE account_id=$1::uuid FOR UPDATE`,
		uuidText(f.base.accountID),
	).Scan(&lockedAccount); err != nil {
		t.Fatalf("lock fixture account row: %v", err)
	}

	results := make(chan recoveryEnrollmentRaceResult, 2)

	startActivation := func() {
		go func() {
			err := f.authorizer.ActivateCandidateEnrollment(
				ctx,
				material.ordinaryCertificate.Raw,
				material.ordinaryProof,
				f.base.recoveryPublic,
			)
			results <- recoveryEnrollmentRaceResult{
				operation: "activate",
				err:       err,
			}
		}()
	}

	startRecovery := func() {
		go func() {
			state, err := f.authorizer.BeginRecovery(
				ctx,
				material.recoveryRequest,
				material.recoveryCertificate.Raw,
				f.base.recoveryPublic,
			)
			results <- recoveryEnrollmentRaceResult{
				operation: "begin_recovery",
				state:     state,
				err:       err,
			}
		}()
	}

	// Queue the intended winner first and confirm that it is actually waiting.
	if activationFirst {
		startActivation()
	} else {
		startRecovery()
	}

	if err := waitForAccountRowLockWaiters(ctx, f.db, blockerPID, 1); err != nil {
		t.Fatalf("first operation did not reach account-row lock: %v", err)
	}

	// Queue the competing operation behind the first.
	if activationFirst {
		startRecovery()
	} else {
		startActivation()
	}

	if err := waitForAccountRowLockWaiters(ctx, f.db, blockerPID, 2); err != nil {
		t.Fatalf("both operations did not reach account-row lock: %v", err)
	}

	if err := blockerTx.Commit(); err != nil {
		t.Fatalf("release account-row lock: %v", err)
	}

	var activationResult, recoveryResult recoveryEnrollmentRaceResult

	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			switch result.operation {
			case "activate":
				activationResult = result
			case "begin_recovery":
				recoveryResult = result
			default:
				t.Fatalf("unexpected operation result: %q", result.operation)
			}
		case <-ctx.Done():
			t.Fatalf("timed out collecting race results: %v", ctx.Err())
		}
	}

	if activationResult.operation == "" || recoveryResult.operation == "" {
		t.Fatalf(
			"missing race results: activation=%q recovery=%q",
			activationResult.operation,
			recoveryResult.operation,
		)
	}

	if recoveryResult.err != nil {
		t.Fatalf("BeginRecovery failed: %v", recoveryResult.err)
	}

	if recoveryResult.state.Status != RecoveryRequestPending {
		t.Fatalf(
			"recovery status=%s; want %s",
			recoveryResult.state.Status,
			RecoveryRequestPending,
		)
	}

	if recoveryResult.state.FinalizeAfter.Sub(recoveryResult.state.AcceptedAt) != 48*time.Hour {
		t.Fatalf("unexpected recovery deadline: %+v", recoveryResult.state)
	}

	// Inspect account epoch and status after both operations have committed.
	var accountEpoch, authEpoch int64
	var authStatus int

	err = f.db.QueryRowContext(ctx, `
SELECT a.account_epoch, aa.epoch, aa.status
FROM accounts a
JOIN authorization_accounts aa ON aa.account_id = a.account_id
WHERE a.account_id = $1::uuid
`, uuidText(f.base.accountID)).Scan(
		&accountEpoch,
		&authEpoch,
		&authStatus,
	)
	if err != nil {
		t.Fatalf("inspect account authorization state: %v", err)
	}

	if accountEpoch != 1 ||
		authEpoch != 1 ||
		authStatus != int(AccountActive) {
		t.Fatalf(
			"BeginRecovery must not advance or lock the account early: account_epoch=%d auth_epoch=%d auth_status=%d",
			accountEpoch,
			authEpoch,
			authStatus,
		)
	}

	// Verify the request is durably pending.
	var persistedStatus string
	if err := f.db.QueryRowContext(ctx, `
SELECT status
FROM account_recovery_requests
WHERE request_id = $1::uuid
`, uuidText(material.recoveryRequestID)).Scan(&persistedStatus); err != nil {
		t.Fatalf("read persisted recovery request: %v", err)
	}

	if persistedStatus != string(RecoveryRequestPending) {
		t.Fatalf("persisted recovery status=%q; want PENDING", persistedStatus)
	}

	// BeginRecovery must invalidate the ordinary challenge in either ordering.
	var challengeConsumed bool
	if err := f.db.QueryRowContext(ctx, `
SELECT consumed_at IS NOT NULL
FROM device_enrollment_challenges
WHERE challenge_id = $1::uuid
`, uuidText(material.challenge.ID)).Scan(&challengeConsumed); err != nil {
		t.Fatalf("read ordinary challenge state: %v", err)
	}

	if !challengeConsumed {
		t.Fatal("ordinary enrollment challenge remained live after BeginRecovery")
	}

	// Count all rows belonging to the ordinary enrollment target.
	var devices, certificates, authDevices, enrollmentEvents int64

	err = f.db.QueryRowContext(ctx, `
SELECT
    (SELECT count(*) FROM devices
      WHERE account_id=$1::uuid AND device_id=$2::uuid),
    (SELECT count(*) FROM device_certificates
      WHERE device_id=$2::uuid),
    (SELECT count(*) FROM authorization_devices
      WHERE account_id=$1::uuid AND device_id=$2::uuid),
    (SELECT count(*) FROM authorization_events
      WHERE account_id=$1::uuid
        AND target_device_id=$2::uuid
        AND kind='ENROLL')
`, uuidText(f.base.accountID), uuidText(material.ordinaryCertificate.DeviceID)).Scan(
		&devices,
		&certificates,
		&authDevices,
		&enrollmentEvents,
	)
	if err != nil {
		t.Fatalf("inspect ordinary enrollment rows: %v", err)
	}

	if activationFirst {
		if activationResult.err != nil {
			t.Fatalf("activation queued first should commit: %v", activationResult.err)
		}

		if devices != 1 ||
			certificates != 1 ||
			authDevices != 1 ||
			enrollmentEvents != 1 {
			t.Fatalf(
				"activation-first state incomplete: devices=%d certificates=%d authDevices=%d events=%d",
				devices,
				certificates,
				authDevices,
				enrollmentEvents,
			)
		}

		t.Log("valid serialization: candidate enrollment committed first; BeginRecovery then persisted pending recovery")
		return
	}

	if !errors.Is(activationResult.err, ErrRecoveryPending) {
		t.Fatalf(
			"activation queued after BeginRecovery: got %v, want ErrRecoveryPending",
			activationResult.err,
		)
	}

	if devices != 0 ||
		certificates != 0 ||
		authDevices != 0 ||
		enrollmentEvents != 0 {
		t.Fatalf(
			"recovery-first outcome partially enrolled device: devices=%d certificates=%d authDevices=%d events=%d",
			devices,
			certificates,
			authDevices,
			enrollmentEvents,
		)
	}

	t.Log("valid serialization: BeginRecovery committed first; candidate activation rejected with ErrRecoveryPending")
}

func TestPostgresCandidateEnrollmentBeginRecoveryEnrollmentWinsRaceIntegration(t *testing.T) {
	runCandidateEnrollmentBeginRecoveryRace(t, true)
}

func TestPostgresCandidateEnrollmentBeginRecoveryRecoveryWinsRaceIntegration(t *testing.T) {
	runCandidateEnrollmentBeginRecoveryRace(t, false)
}
