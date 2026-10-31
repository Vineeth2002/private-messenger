package authorization

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func assertRecoveryEnrollmentNotApplied(
	t *testing.T,
	f *recoveryLifecycleFixture,
	challenge EnrollmentChallenge,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var devices, certificates, authDevices, enrollmentEvents int64
	if err := f.db.QueryRowContext(ctx, `
SELECT count(*) FROM devices WHERE account_id=$1::uuid AND device_id=$2::uuid
`, uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `
SELECT count(*) FROM device_certificates WHERE device_id=$1::uuid
`, uuidText(f.base.deviceID)).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `
SELECT count(*) FROM authorization_devices WHERE account_id=$1::uuid AND device_id=$2::uuid
`, uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(&authDevices); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `
SELECT count(*) FROM authorization_events
WHERE account_id=$1::uuid AND target_device_id=$2::uuid AND kind='ENROLL'
`, uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(&enrollmentEvents); err != nil {
		t.Fatal(err)
	}
	var accountStatus int
	if err := f.db.QueryRowContext(ctx, `
SELECT status FROM authorization_accounts WHERE account_id=$1::uuid
`, uuidText(f.base.accountID)).Scan(&accountStatus); err != nil {
		t.Fatal(err)
	}
	var consumed bool
	if err := f.db.QueryRowContext(ctx, `
SELECT consumed_at IS NOT NULL FROM device_enrollment_challenges WHERE challenge_id=$1::uuid
`, uuidText(challenge.ID)).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if devices != 0 || certificates != 0 || authDevices != 0 || enrollmentEvents != 0 ||
		accountStatus != int(AccountRecoveryLocked) || consumed {
		t.Fatalf("rejected recovery activation changed state: devices=%d certs=%d authDevices=%d enrollEvents=%d accountStatus=%d challengeConsumed=%v",
			devices, certificates, authDevices, enrollmentEvents, accountStatus, consumed)
	}
}

func TestPostgresRecoveryEnrollmentExpiredChallengeDoesNotUnlockIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	finalizeRecoveryForEnrollmentTest(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	challenge, err := insertExpiredRecoveryEnrollmentChallenge(t, f)
	if err != nil {
		t.Fatalf("insert already-expired recovery challenge: %v", err)
	}
	proof := recoveryEnrollmentProofForTest(t, f.enrollmentRaw, challenge, f.base.dskPrivate)
	if err := f.authorizer.ActivateRecoveryEnrollment(
		ctx, f.recoveryRequestID, f.enrollmentRaw, proof, f.base.recoveryPublic,
	); !errors.Is(err, ErrEnrollmentChallengeExpired) {
		t.Fatalf("activate using expired challenge: got %v, want ErrEnrollmentChallengeExpired", err)
	}
	assertRecoveryEnrollmentNotApplied(t, f, challenge)
}

func TestPostgresRecoveryEnrollmentRejectsWrongRequestCertificateAndChallengeIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	finalizeRecoveryForEnrollmentTest(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	challenge, err := f.authorizer.IssueRecoveryEnrollmentChallenge(
		ctx, f.recoveryRequestID, f.enrollmentRaw, f.base.recoveryPublic,
	)
	if err != nil {
		t.Fatalf("issue recovery challenge: %v", err)
	}
	validProof := recoveryEnrollmentProofForTest(t, f.enrollmentRaw, challenge, f.base.dskPrivate)

	wrongRequestID := randomCandidateEnrollmentID(t)
	if err := f.authorizer.ActivateRecoveryEnrollment(
		ctx, wrongRequestID, f.enrollmentRaw, validProof, f.base.recoveryPublic,
	); !errors.Is(err, ErrRecoveryRequestNotFound) {
		t.Fatalf("activate against wrong request ID: got %v, want ErrRecoveryRequestNotFound", err)
	}

	wrongTarget := randomCandidateEnrollmentID(t)
	wrongCertificate := testEnrollmentCert(
		t, f.base.recoveryPriv, f.base.accountID, wrongTarget, 2,
		f.base.certificate.DSKPub, f.base.certificate.DDHKPub,
	)
	wrongTargetProof := recoveryEnrollmentProofForTest(t, wrongCertificate.Raw, challenge, f.base.dskPrivate)
	if err := f.authorizer.ActivateRecoveryEnrollment(
		ctx, f.recoveryRequestID, wrongCertificate.Raw, wrongTargetProof, f.base.recoveryPublic,
	); !errors.Is(err, ErrAuthorizationConflict) {
		t.Fatalf("activate with different target certificate: got %v, want ErrAuthorizationConflict", err)
	}

	wrongChallenge := challenge
	wrongChallenge.ID = randomCandidateEnrollmentID(t)
	wrongChallengeProof := recoveryEnrollmentProofForTest(t, f.enrollmentRaw, wrongChallenge, f.base.dskPrivate)
	if err := f.authorizer.ActivateRecoveryEnrollment(
		ctx, f.recoveryRequestID, f.enrollmentRaw, wrongChallengeProof, f.base.recoveryPublic,
	); !errors.Is(err, ErrEnrollmentChallengeNotFound) {
		t.Fatalf("activate with unknown challenge ID: got %v, want ErrEnrollmentChallengeNotFound", err)
	}
	assertRecoveryEnrollmentNotApplied(t, f, challenge)
}

func TestPostgresRecoveryEnrollmentRollsBackAllWritesOnEventDigestConflictIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	finalizeRecoveryForEnrollmentTest(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	challenge, err := f.authorizer.IssueRecoveryEnrollmentChallenge(
		ctx, f.recoveryRequestID, f.enrollmentRaw, f.base.recoveryPublic,
	)
	if err != nil {
		t.Fatalf("issue recovery challenge: %v", err)
	}

	// Reserve the certificate digest for a conflicting event. Activation will
	// insert the device and certificate rows first, then fail at the event insert.
	certificateDigest := sha256.Sum256(f.enrollmentRaw)
	conflictTarget := randomCandidateEnrollmentID(t)
	if _, err := f.db.ExecContext(ctx, `
INSERT INTO authorization_events (
    auth_digest, kind, account_id, old_epoch, new_epoch, target_device_id, cert_cbor
) VALUES ($1, 'TRANSITION', $2::uuid, 2, 2, $3::uuid, $4)
`, certificateDigest[:], uuidText(f.base.accountID), uuidText(conflictTarget), f.enrollmentRaw); err != nil {
		t.Fatalf("insert intentional event-digest conflict: %v", err)
	}

	proof := recoveryEnrollmentProofForTest(t, f.enrollmentRaw, challenge, f.base.dskPrivate)
	if err := f.authorizer.ActivateRecoveryEnrollment(
		ctx, f.recoveryRequestID, f.enrollmentRaw, proof, f.base.recoveryPublic,
	); err == nil {
		t.Fatal("activation unexpectedly succeeded despite authorization-event digest conflict")
	}
	assertRecoveryEnrollmentNotApplied(t, f, challenge)
}

func TestPostgresRecoveryEnrollmentConcurrentExactRetryIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	finalizeRecoveryForEnrollmentTest(t, f)
	challengeCtx, challengeCancel := context.WithTimeout(context.Background(), 15*time.Second)
	challenge, err := f.authorizer.IssueRecoveryEnrollmentChallenge(
		challengeCtx, f.recoveryRequestID, f.enrollmentRaw, f.base.recoveryPublic,
	)
	challengeCancel()
	if err != nil {
		t.Fatalf("issue recovery challenge: %v", err)
	}
	proof := recoveryEnrollmentProofForTest(t, f.enrollmentRaw, challenge, f.base.dskPrivate)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			results <- f.authorizer.ActivateRecoveryEnrollment(
				ctx, f.recoveryRequestID, f.enrollmentRaw, proof, f.base.recoveryPublic,
			)
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first != nil || second != nil {
		t.Fatalf("concurrent exact activation retries failed: first=%v second=%v", first, second)
	}

	var devices, certificates, authDevices, enrollmentEvents int64
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM devices WHERE account_id=$1::uuid AND device_id=$2::uuid`, uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM device_certificates WHERE device_id=$1::uuid`, uuidText(f.base.deviceID)).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM authorization_devices WHERE account_id=$1::uuid AND device_id=$2::uuid`, uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(&authDevices); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM authorization_events WHERE account_id=$1::uuid AND target_device_id=$2::uuid AND kind='ENROLL'`, uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(&enrollmentEvents); err != nil {
		t.Fatal(err)
	}
	if devices != 1 || certificates != 1 || authDevices != 1 || enrollmentEvents != 1 {
		t.Fatalf("concurrent activation created duplicate or incomplete state: devices=%d certificates=%d authDevices=%d enrollmentEvents=%d", devices, certificates, authDevices, enrollmentEvents)
	}
}
