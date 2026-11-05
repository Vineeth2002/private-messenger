package authorization

import (
	"context"
	"errors"
	"testing"
	"time"
)

type ordinaryChallengeIssueRaceResult struct {
	challenge EnrollmentChallenge
	err       error
}

type ordinaryChallengeBeginRecoveryRaceResult struct {
	state RecoveryRequestState
	err   error
}

func runOrdinaryChallengeIssueBeginRecoveryRace(
	t *testing.T,
	issuanceFirst bool,
) {
	t.Helper()

	f := newRecoveryLifecycleFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// This creates the ordinary certificate, recovery request, and one
	// already-persisted ordinary challenge for the ordinary target device.
	material := newRecoveryEnrollmentRaceMaterial(t, f, ctx)

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

	issueResults := make(chan ordinaryChallengeIssueRaceResult, 1)
	recoveryResults := make(chan ordinaryChallengeBeginRecoveryRaceResult, 1)

	startIssuance := func() {
		go func() {
			challenge, err := f.authorizer.IssueCandidateEnrollmentChallenge(
				ctx,
				material.ordinaryCertificate.Raw,
				f.base.recoveryPublic,
			)
			issueResults <- ordinaryChallengeIssueRaceResult{
				challenge: challenge,
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
			recoveryResults <- ordinaryChallengeBeginRecoveryRaceResult{
				state: state,
				err:   err,
			}
		}()
	}

	// Queue the intended first operation behind the held account-row lock.
	if issuanceFirst {
		startIssuance()
	} else {
		startRecovery()
	}

	if err := waitForAccountRowLockWaiters(ctx, f.db, blockerPID, 1); err != nil {
		t.Fatalf("first operation did not reach account-row lock: %v", err)
	}

	// Queue the competing operation behind the first.
	if issuanceFirst {
		startRecovery()
	} else {
		startIssuance()
	}

	if err := waitForAccountRowLockWaiters(ctx, f.db, blockerPID, 2); err != nil {
		t.Fatalf("both operations did not reach account-row lock: %v", err)
	}

	if err := blockerTx.Commit(); err != nil {
		t.Fatalf("release account-row lock: %v", err)
	}

	var issueResult ordinaryChallengeIssueRaceResult
	select {
	case issueResult = <-issueResults:
	case <-ctx.Done():
		t.Fatalf("timed out collecting challenge issuance result: %v", ctx.Err())
	}

	var recoveryResult ordinaryChallengeBeginRecoveryRaceResult
	select {
	case recoveryResult = <-recoveryResults:
	case <-ctx.Done():
		t.Fatalf("timed out collecting BeginRecovery result: %v", ctx.Err())
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

	if issuanceFirst {
		if issueResult.err != nil {
			t.Fatalf("challenge issuance queued first should succeed: %v", issueResult.err)
		}

		if issueResult.challenge.ID == ([16]byte{}) {
			t.Fatal("successful challenge issuance returned a zero challenge ID")
		}

		if issueResult.challenge.ID == material.challenge.ID {
			t.Fatal("replacement issuance returned the original challenge ID")
		}
	} else {
		if !errors.Is(issueResult.err, ErrRecoveryPending) {
			t.Fatalf(
				"challenge issuance queued after BeginRecovery: got %v, want ErrRecoveryPending",
				issueResult.err,
			)
		}
	}

	// Recovery initiation must persist without advancing or locking the
	// account epoch early.
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

	if accountEpoch != 1 || authEpoch != 1 || authStatus != int(AccountActive) {
		t.Fatalf(
			"BeginRecovery changed account authorization early: account_epoch=%d auth_epoch=%d auth_status=%d",
			accountEpoch,
			authEpoch,
			authStatus,
		)
	}

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

	// Count all challenge rows for the ordinary enrollment target.
	var totalChallenges, consumedChallenges, liveChallenges int64

	err = f.db.QueryRowContext(ctx, `
SELECT
    count(*),
    count(*) FILTER (WHERE consumed_at IS NOT NULL),
    count(*) FILTER (WHERE consumed_at IS NULL)
FROM device_enrollment_challenges
WHERE account_id = $1::uuid
  AND device_id = $2::uuid
`, uuidText(f.base.accountID), uuidText(material.ordinaryCertificate.DeviceID)).Scan(
		&totalChallenges,
		&consumedChallenges,
		&liveChallenges,
	)
	if err != nil {
		t.Fatalf("inspect ordinary challenge rows: %v", err)
	}

	expectedTotal := int64(1)
	if issuanceFirst {
		expectedTotal = 2
	}

	if totalChallenges != expectedTotal ||
		consumedChallenges != expectedTotal ||
		liveChallenges != 0 {
		t.Fatalf(
			"challenge state mismatch: total=%d consumed=%d live=%d; want total=%d consumed=%d live=0",
			totalChallenges,
			consumedChallenges,
			liveChallenges,
			expectedTotal,
			expectedTotal,
		)
	}

	// Verify the original challenge and, when issuance won, its replacement
	// are both consumed after BeginRecovery commits.
	challengeIDs := [][16]byte{material.challenge.ID}
	if issuanceFirst {
		challengeIDs = append(challengeIDs, issueResult.challenge.ID)
	}

	for _, challengeID := range challengeIDs {
		var consumed bool
		if err := f.db.QueryRowContext(ctx, `
SELECT consumed_at IS NOT NULL
FROM device_enrollment_challenges
WHERE challenge_id = $1::uuid
`, uuidText(challengeID)).Scan(&consumed); err != nil {
			t.Fatalf("inspect challenge %s: %v", uuidText(challengeID), err)
		}

		if !consumed {
			t.Fatalf("challenge %s remained live after BeginRecovery", uuidText(challengeID))
		}
	}

	// Challenge issuance must never partially enroll the target device.
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
`, uuidText(f.base.accountID), uuidText(material.ordinaryCertificate.DeviceID)).Scan(
		&devices,
		&certificates,
		&authDevices,
		&enrollmentEvents,
	)
	if err != nil {
		t.Fatalf("inspect ordinary enrollment side effects: %v", err)
	}

	if devices != 0 || certificates != 0 || authDevices != 0 || enrollmentEvents != 0 {
		t.Fatalf(
			"challenge issuance unexpectedly enrolled device: devices=%d certificates=%d authDevices=%d events=%d",
			devices,
			certificates,
			authDevices,
			enrollmentEvents,
		)
	}

	if issuanceFirst {
		t.Log("valid serialization: ordinary challenge issuance committed first; BeginRecovery then consumed original and replacement challenges")
		return
	}

	t.Log("valid serialization: BeginRecovery committed first; ordinary challenge issuance rejected with ErrRecoveryPending and inserted no challenge")
}

func TestPostgresOrdinaryChallengeIssueBeginRecoveryIssuanceWinsRaceIntegration(t *testing.T) {
	runOrdinaryChallengeIssueBeginRecoveryRace(t, true)
}

func TestPostgresOrdinaryChallengeIssueBeginRecoveryRecoveryWinsRaceIntegration(t *testing.T) {
	runOrdinaryChallengeIssueBeginRecoveryRace(t, false)
}
