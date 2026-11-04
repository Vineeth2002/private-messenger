package authorization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

type recoveryChallengeFinalizeRaceResult struct {
	operation string
	challenge EnrollmentChallenge
	state     RecoveryRequestState
	err       error
}

func runRecoveryChallengeFinalizeRace(
	t *testing.T,
	issuanceFirst bool,
) {
	t.Helper()

	f := newRecoveryLifecycleFixture(t)

	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}

	// Finalization must be eligible before both operations are queued.
	forceRecoveryDueForTest(t, f.db, f.recoveryRequestID)

	// Confirm finalization revokes an active device as part of the same
	// transaction that advances the account and finalizes the request.
	activeDeviceID, _ := f.addActiveDevice()

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

	results := make(chan recoveryChallengeFinalizeRaceResult, 2)

	startIssuance := func() {
		go func() {
			challenge, err := f.authorizer.IssueRecoveryEnrollmentChallenge(
				ctx,
				f.recoveryRequestID,
				f.enrollmentRaw,
				f.base.recoveryPublic,
			)
			results <- recoveryChallengeFinalizeRaceResult{
				operation: "issue_challenge",
				challenge: challenge,
				err:       err,
			}
		}()
	}

	startFinalization := func() {
		go func() {
			state, err := f.authorizer.FinalizeRecovery(
				ctx,
				f.base.accountID,
				f.recoveryRequestID,
			)
			results <- recoveryChallengeFinalizeRaceResult{
				operation: "finalize_recovery",
				state:     state,
				err:       err,
			}
		}()
	}

	// Queue the intended first operation behind the account-row lock.
	if issuanceFirst {
		startIssuance()
	} else {
		startFinalization()
	}

	if err := waitForAccountRowLockWaiters(ctx, f.db, blockerPID, 1); err != nil {
		t.Fatalf("first operation did not reach account-row lock: %v", err)
	}

	// Queue the competing operation behind the first.
	if issuanceFirst {
		startFinalization()
	} else {
		startIssuance()
	}

	if err := waitForAccountRowLockWaiters(ctx, f.db, blockerPID, 2); err != nil {
		t.Fatalf("both operations did not reach account-row lock: %v", err)
	}

	if err := blockerTx.Commit(); err != nil {
		t.Fatalf("release account-row lock: %v", err)
	}

	var issueResult, finalizeResult recoveryChallengeFinalizeRaceResult

	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			switch result.operation {
			case "issue_challenge":
				issueResult = result
			case "finalize_recovery":
				finalizeResult = result
			default:
				t.Fatalf("unexpected race operation: %q", result.operation)
			}
		case <-ctx.Done():
			t.Fatalf("timed out collecting race results: %v", ctx.Err())
		}
	}

	if issueResult.operation == "" || finalizeResult.operation == "" {
		t.Fatalf(
			"missing race results: issuance=%q finalization=%q",
			issueResult.operation,
			finalizeResult.operation,
		)
	}

	if finalizeResult.err != nil {
		t.Fatalf("FinalizeRecovery failed: %v", finalizeResult.err)
	}

	if finalizeResult.state.Status != RecoveryRequestFinalized ||
		finalizeResult.state.FinalizedAt == nil ||
		finalizeResult.state.FinalizedAt.Before(finalizeResult.state.FinalizeAfter) {
		t.Fatalf("unexpected finalized recovery state: %+v", finalizeResult.state)
	}

	if issuanceFirst {
		if !errors.Is(issueResult.err, ErrRecoveryNotReady) {
			t.Fatalf(
				"issuance queued before finalization: got %v, want ErrRecoveryNotReady",
				issueResult.err,
			)
		}

		if issueResult.challenge.ID != ([16]byte{}) {
			t.Fatalf("rejected issuance returned nonzero challenge ID")
		}
	} else {
		if issueResult.err != nil {
			t.Fatalf("issuance queued after finalization should succeed: %v", issueResult.err)
		}

		if issueResult.challenge.ID == ([16]byte{}) {
			t.Fatal("successful issuance returned zero challenge ID")
		}
	}

	// Verify terminal request state in PostgreSQL.
	var persistedStatus string
	var finalizedAtPresent bool

	err = f.db.QueryRowContext(ctx, `
SELECT status, finalized_at IS NOT NULL
FROM account_recovery_requests
WHERE account_id = $1::uuid
  AND request_id = $2::uuid
`, uuidText(f.base.accountID), uuidText(f.recoveryRequestID)).Scan(
		&persistedStatus,
		&finalizedAtPresent,
	)
	if err != nil {
		t.Fatalf("inspect persisted recovery request: %v", err)
	}

	if persistedStatus != string(RecoveryRequestFinalized) || !finalizedAtPresent {
		t.Fatalf(
			"recovery request not durably finalized: status=%q finalized_at_present=%v",
			persistedStatus,
			finalizedAtPresent,
		)
	}

	// Finalization advances the account to epoch 2 and locks it for recovery
	// until the replacement device is activated.
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
		t.Fatalf("inspect finalized account state: %v", err)
	}

	if accountEpoch != 2 ||
		authEpoch != 2 ||
		accountStatus != int(AccountRecoveryLocked) {
		t.Fatalf(
			"finalized account state mismatch: account_epoch=%d auth_epoch=%d status=%d",
			accountEpoch,
			authEpoch,
			accountStatus,
		)
	}

	// Verify that finalization revoked the pre-existing active device.
	var deviceEpoch, authorizedEpoch, revokedEpoch int64
	var deviceStatus int
	var deviceRevoked bool

	err = f.db.QueryRowContext(ctx, `
SELECT d.account_epoch,
       d.revoked_at IS NOT NULL,
       ad.status,
       ad.authorized_epoch,
       ad.revoked_epoch
FROM devices d
JOIN authorization_devices ad
  ON ad.device_id = d.device_id
 AND ad.account_id = d.account_id
WHERE d.account_id = $1::uuid
  AND d.device_id = $2::uuid
`, uuidText(f.base.accountID), uuidText(activeDeviceID)).Scan(
		&deviceEpoch,
		&deviceRevoked,
		&deviceStatus,
		&authorizedEpoch,
		&revokedEpoch,
	)
	if err != nil {
		t.Fatalf("inspect revoked device after finalization: %v", err)
	}

	if deviceEpoch != 2 ||
		!deviceRevoked ||
		deviceStatus != 2 ||
		authorizedEpoch != 1 ||
		revokedEpoch != 2 {
		t.Fatalf(
			"finalized device state mismatch: device_epoch=%d revoked=%v status=%d authorized_epoch=%d revoked_epoch=%d",
			deviceEpoch,
			deviceRevoked,
			deviceStatus,
			authorizedEpoch,
			revokedEpoch,
		)
	}

	// Exactly one immutable RECOVERY_FINALIZED event must exist.
	var finalizationEvents int64

	if err := f.db.QueryRowContext(ctx, `
SELECT count(*)
FROM authorization_events
WHERE auth_digest = $1
  AND kind = 'RECOVERY_FINALIZED'
  AND account_id = $2::uuid
  AND old_epoch = 1
  AND new_epoch = 2
  AND target_device_id = $3::uuid
`, finalizeResult.state.RequestDigest[:],
		uuidText(f.base.accountID),
		uuidText(f.base.deviceID),
	).Scan(&finalizationEvents); err != nil {
		t.Fatalf("inspect recovery finalization event: %v", err)
	}

	if finalizationEvents != 1 {
		t.Fatalf("RECOVERY_FINALIZED event count=%d; want exactly one", finalizationEvents)
	}

	// Verify recovery-bound challenge count and binding.
	var challengeCount int64

	if err := f.db.QueryRowContext(ctx, `
SELECT count(*)
FROM device_enrollment_challenges
WHERE account_id = $1::uuid
  AND device_id = $2::uuid
  AND recovery_request_id = $3::uuid
`, uuidText(f.base.accountID),
		uuidText(f.base.deviceID),
		uuidText(f.recoveryRequestID),
	).Scan(&challengeCount); err != nil {
		t.Fatalf("count recovery-bound challenges: %v", err)
	}

	if issuanceFirst {
		if challengeCount != 0 {
			t.Fatalf("issuance-first case created %d recovery challenges; want zero", challengeCount)
		}
	} else {
		if challengeCount != 1 {
			t.Fatalf("finalization-first case created %d recovery challenges; want exactly one", challengeCount)
		}

		var boundRequestID string
		var boundRequestDigest, boundCertificateDigest []byte
		var boundEpoch int64
		var consumed bool

		err = f.db.QueryRowContext(ctx, `
SELECT recovery_request_id::text,
       recovery_request_digest,
       enrollment_certificate_digest,
       account_epoch,
       consumed_at IS NOT NULL
FROM device_enrollment_challenges
WHERE challenge_id = $1::uuid
`, uuidText(issueResult.challenge.ID)).Scan(
			&boundRequestID,
			&boundRequestDigest,
			&boundCertificateDigest,
			&boundEpoch,
			&consumed,
		)
		if err != nil {
			t.Fatalf("inspect issued recovery challenge binding: %v", err)
		}

		expectedRequestDigest := sha256.Sum256(f.recoveryRequest)
		expectedCertificateDigest := sha256.Sum256(f.enrollmentRaw)

		if boundRequestID != uuidText(f.recoveryRequestID) ||
			!bytes.Equal(boundRequestDigest, expectedRequestDigest[:]) ||
			!bytes.Equal(boundCertificateDigest, expectedCertificateDigest[:]) ||
			boundEpoch != 2 ||
			consumed {
			t.Fatalf(
				"recovery challenge binding mismatch: request=%q epoch=%d consumed=%v request_digest_match=%v certificate_digest_match=%v",
				boundRequestID,
				boundEpoch,
				consumed,
				bytes.Equal(boundRequestDigest, expectedRequestDigest[:]),
				bytes.Equal(boundCertificateDigest, expectedCertificateDigest[:]),
			)
		}
	}

	// Issuing a challenge must never enroll the replacement device.
	var devices, certificates, authDevices, enrollmentEvents int64

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
`, uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(
		&devices,
		&certificates,
		&authDevices,
		&enrollmentEvents,
	)
	if err != nil {
		t.Fatalf("inspect replacement-device enrollment side effects: %v", err)
	}

	if devices != 0 || certificates != 0 || authDevices != 0 || enrollmentEvents != 0 {
		t.Fatalf(
			"challenge issuance unexpectedly enrolled replacement device: devices=%d certificates=%d authDevices=%d enrollmentEvents=%d",
			devices,
			certificates,
			authDevices,
			enrollmentEvents,
		)
	}

	if issuanceFirst {
		t.Log("valid serialization: issuance observed PENDING and returned ErrRecoveryNotReady; finalization then committed with no challenge")
		return
	}

	t.Log("valid serialization: finalization committed first; recovery challenge issuance succeeded with exact request and certificate binding")
}

func TestPostgresRecoveryChallengeFinalizeIssuanceQueuedFirstRaceIntegration(t *testing.T) {
	runRecoveryChallengeFinalizeRace(t, true)
}

func TestPostgresRecoveryChallengeFinalizeFinalizationQueuedFirstRaceIntegration(t *testing.T) {
	runRecoveryChallengeFinalizeRace(t, false)
}
