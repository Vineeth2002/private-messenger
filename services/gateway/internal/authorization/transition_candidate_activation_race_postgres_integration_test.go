package authorization

import (
	"context"
	"errors"
	"testing"
	"time"
)

type transitionCandidateRaceResult struct {
	operation string
	err       error
}

func runTransitionCandidateEnrollmentRace(
	t *testing.T,
	activationFirst bool,
) {
	t.Helper()

	f := newRecoveryLifecycleFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Prepare a valid epoch-1 candidate certificate, challenge and PoP.
	material := newRecoveryEnrollmentRaceMaterial(t, f, ctx)

	// Transition revokes a separate, already-active device.
	targetDeviceID, _ := f.addActiveDevice()

	transition := testTransitionCert(
		t,
		f.base.recoveryPriv,
		f.base.accountID,
		targetDeviceID,
		1,
		2,
		RevokeDeviceAction,
	)

	// Hold the account row so both operations queue in a deterministic order.
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

	results := make(chan transitionCandidateRaceResult, 2)

	startActivation := func() {
		go func() {
			err := f.authorizer.ActivateCandidateEnrollment(
				ctx,
				material.ordinaryCertificate.Raw,
				material.ordinaryProof,
				f.base.recoveryPublic,
			)
			results <- transitionCandidateRaceResult{
				operation: "activate",
				err:       err,
			}
		}()
	}

	startTransition := func() {
		go func() {
			err := f.authorizer.Transition(
				ctx,
				transition,
				f.base.recoveryPublic,
			)
			results <- transitionCandidateRaceResult{
				operation: "transition",
				err:       err,
			}
		}()
	}

	// Queue the intended first operation.
	if activationFirst {
		startActivation()
	} else {
		startTransition()
	}

	if err := waitForAccountRowLockWaiters(ctx, f.db, blockerPID, 1); err != nil {
		t.Fatalf("first operation did not reach account-row lock: %v", err)
	}

	// Queue the competing operation behind it.
	if activationFirst {
		startTransition()
	} else {
		startActivation()
	}

	if err := waitForAccountRowLockWaiters(ctx, f.db, blockerPID, 2); err != nil {
		t.Fatalf("both operations did not reach account-row lock: %v", err)
	}

	if err := blockerTx.Commit(); err != nil {
		t.Fatalf("release account-row lock: %v", err)
	}

	var activationResult, transitionResult transitionCandidateRaceResult

	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			switch result.operation {
			case "activate":
				activationResult = result
			case "transition":
				transitionResult = result
			default:
				t.Fatalf("unexpected race operation: %q", result.operation)
			}
		case <-ctx.Done():
			t.Fatalf("timed out collecting transition race results: %v", ctx.Err())
		}
	}

	if activationResult.operation == "" || transitionResult.operation == "" {
		t.Fatalf(
			"missing race results: activation=%q transition=%q",
			activationResult.operation,
			transitionResult.operation,
		)
	}

	if transitionResult.err != nil {
		t.Fatalf("authorization transition failed: %v", transitionResult.err)
	}

	if activationFirst {
		if activationResult.err != nil {
			t.Fatalf("candidate activation queued first should succeed: %v", activationResult.err)
		}
	} else {
		if !errors.Is(activationResult.err, ErrInvalidEpoch) {
			t.Fatalf(
				"candidate activation queued after transition: got %v, want ErrInvalidEpoch",
				activationResult.err,
			)
		}
	}

	// Both serializations must finish at account epoch 2, active status.
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

	if accountEpoch != 2 || authEpoch != 2 || authStatus != int(AccountActive) {
		t.Fatalf(
			"transition did not advance account consistently: account_epoch=%d auth_epoch=%d status=%d",
			accountEpoch,
			authEpoch,
			authStatus,
		)
	}

	// The transition target must be revoked at epoch 2.
	var targetAccountEpoch, targetStatus int64
	var targetAuthorizedEpoch, targetRevokedEpoch int64
	var targetRevoked bool

	err = f.db.QueryRowContext(ctx, `
SELECT d.account_epoch,
       (d.revoked_at IS NOT NULL),
       ad.status,
       ad.authorized_epoch,
       ad.revoked_epoch
FROM devices d
JOIN authorization_devices ad
  ON ad.device_id = d.device_id
 AND ad.account_id = d.account_id
WHERE d.account_id = $1::uuid
  AND d.device_id = $2::uuid
`, uuidText(f.base.accountID), uuidText(targetDeviceID)).Scan(
		&targetAccountEpoch,
		&targetRevoked,
		&targetStatus,
		&targetAuthorizedEpoch,
		&targetRevokedEpoch,
	)
	if err != nil {
		t.Fatalf("inspect revoked transition target: %v", err)
	}

	if targetAccountEpoch != 2 ||
		!targetRevoked ||
		targetStatus != 2 ||
		targetAuthorizedEpoch != 1 ||
		targetRevokedEpoch != 2 {
		t.Fatalf(
			"revoked target state mismatch: account_epoch=%d revoked=%v status=%d authorized_epoch=%d revoked_epoch=%d",
			targetAccountEpoch,
			targetRevoked,
			targetStatus,
			targetAuthorizedEpoch,
			targetRevokedEpoch,
		)
	}

	// Verify challenge consumption and candidate enrollment side effects.
	var challengeConsumed bool
	if err := f.db.QueryRowContext(ctx, `
SELECT consumed_at IS NOT NULL
FROM device_enrollment_challenges
WHERE challenge_id = $1::uuid
`, uuidText(material.challenge.ID)).Scan(&challengeConsumed); err != nil {
		t.Fatalf("inspect candidate challenge: %v", err)
	}

	var candidateDevices, certificates, candidateAuthDevices, enrollmentEvents int64

	err = f.db.QueryRowContext(ctx, `
SELECT
    (SELECT count(*) FROM devices
      WHERE account_id = $1::uuid AND device_id = $2::uuid),
    (SELECT count(*) FROM device_certificates
      WHERE device_id = $2::uuid),
    (SELECT count(*) FROM authorization_devices
      WHERE account_id = $1::uuid AND device_id = $2::uuid),
    (SELECT count(*) FROM authorization_events
      WHERE account_id = $1::uuid
        AND target_device_id = $2::uuid
        AND kind = 'ENROLL')
`, uuidText(f.base.accountID), uuidText(material.ordinaryCertificate.DeviceID)).Scan(
		&candidateDevices,
		&certificates,
		&candidateAuthDevices,
		&enrollmentEvents,
	)
	if err != nil {
		t.Fatalf("inspect candidate enrollment side effects: %v", err)
	}

	var transitionEvents int64
	if err := f.db.QueryRowContext(ctx, `
SELECT count(*)
FROM authorization_events
WHERE account_id = $1::uuid
  AND kind = 'TRANSITION'
  AND old_epoch = 1
  AND new_epoch = 2
  AND target_device_id = $2::uuid
`, uuidText(f.base.accountID), uuidText(targetDeviceID)).Scan(&transitionEvents); err != nil {
		t.Fatalf("inspect transition event: %v", err)
	}

	if transitionEvents != 1 {
		t.Fatalf("transition event count=%d; want exactly one", transitionEvents)
	}

	if activationFirst {
		if !challengeConsumed {
			t.Fatal("successful candidate activation challenge was not consumed")
		}

		if candidateDevices != 1 ||
			certificates != 1 ||
			candidateAuthDevices != 1 ||
			enrollmentEvents != 1 {
			t.Fatalf(
				"enrollment-first state incomplete: devices=%d certificates=%d authDevices=%d enrollmentEvents=%d",
				candidateDevices,
				certificates,
				candidateAuthDevices,
				enrollmentEvents,
			)
		}

		// The transition must advance the newly enrolled active device too.
		var candidateAccountEpoch, candidateAuthorizedEpoch int64
		var candidateStatus, candidateRevokedEpoch int64
		var candidateRevoked bool

		err = f.db.QueryRowContext(ctx, `
SELECT d.account_epoch,
       (d.revoked_at IS NOT NULL),
       ad.status,
       ad.authorized_epoch,
       ad.revoked_epoch
FROM devices d
JOIN authorization_devices ad
  ON ad.device_id = d.device_id
 AND ad.account_id = d.account_id
WHERE d.account_id = $1::uuid
  AND d.device_id = $2::uuid
`, uuidText(f.base.accountID), uuidText(material.ordinaryCertificate.DeviceID)).Scan(
			&candidateAccountEpoch,
			&candidateRevoked,
			&candidateStatus,
			&candidateAuthorizedEpoch,
			&candidateRevokedEpoch,
		)
		if err != nil {
			t.Fatalf("inspect newly enrolled device after transition: %v", err)
		}

		if candidateAccountEpoch != 2 ||
			candidateRevoked ||
			candidateStatus != 1 ||
			candidateAuthorizedEpoch != 2 ||
			candidateRevokedEpoch != 0 {
			t.Fatalf(
				"newly enrolled active device was not advanced: account_epoch=%d revoked=%v status=%d authorized_epoch=%d revoked_epoch=%d",
				candidateAccountEpoch,
				candidateRevoked,
				candidateStatus,
				candidateAuthorizedEpoch,
				candidateRevokedEpoch,
			)
		}

		t.Log("valid serialization: candidate enrollment committed first; transition revoked its target and advanced the new active device to epoch 2")
		return
	}

	if challengeConsumed {
		t.Fatal("epoch-rejected candidate activation unexpectedly consumed its challenge")
	}

	if candidateDevices != 0 ||
		certificates != 0 ||
		candidateAuthDevices != 0 ||
		enrollmentEvents != 0 {
		t.Fatalf(
			"transition-first outcome partially enrolled candidate: devices=%d certificates=%d authDevices=%d enrollmentEvents=%d",
			candidateDevices,
			certificates,
			candidateAuthDevices,
			enrollmentEvents,
		)
	}

	t.Log("valid serialization: transition committed first; epoch-1 candidate activation rejected with ErrInvalidEpoch and no enrollment side effects")
}

func TestPostgresTransitionCandidateEnrollmentActivationWinsRaceIntegration(t *testing.T) {
	runTransitionCandidateEnrollmentRace(t, true)
}

func TestPostgresTransitionCandidateEnrollmentTransitionWinsRaceIntegration(t *testing.T) {
	runTransitionCandidateEnrollmentRace(t, false)
}
