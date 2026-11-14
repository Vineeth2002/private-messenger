package authorization

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func recoveryEnrollmentProofForTest(
	t *testing.T,
	certificateRaw []byte,
	challenge EnrollmentChallenge,
	dskPrivate ed25519.PrivateKey,
) []byte {
	t.Helper()
	cert, err := ParseDeviceEnrollmentAuthorizationV1(certificateRaw)
	if err != nil {
		t.Fatalf("parse recovery enrollment certificate for proof: %v", err)
	}
	proof := DeviceEnrollmentPoPV1{
		AccountID:                   cert.AccountID,
		DeviceID:                    cert.DeviceID,
		Epoch:                       cert.Epoch,
		EnrollmentCertificateDigest: sha256.Sum256(certificateRaw),
		ChallengeID:                 challenge.ID,
		ChallengeNonce:              challenge.Nonce,
	}
	core, err := proof.canonicalCore()
	if err != nil {
		t.Fatalf("encode recovery enrollment proof core: %v", err)
	}
	message := append([]byte(DeviceEnrollmentPoPDomain), core...)
	copy(proof.Signature[:], ed25519.Sign(dskPrivate, message))
	return deviceEnrollmentPoPWireForTest(
		t, proof.AccountID, proof.DeviceID, proof.Epoch,
		proof.EnrollmentCertificateDigest, proof.ChallengeID,
		proof.ChallengeNonce, proof.Signature,
	)
}

func finalizeRecoveryForEnrollmentTest(t *testing.T, f *recoveryLifecycleFixture) {
	t.Helper()
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	forceRecoveryDueForTest(t, f.db, f.recoveryRequestID)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	state, err := f.authorizer.FinalizeRecovery(ctx, f.base.accountID, f.recoveryRequestID)
	if err != nil {
		t.Fatalf("finalize recovery for enrollment test: %v", err)
	}
	if state.Status != RecoveryRequestFinalized {
		t.Fatalf("recovery status=%s; want FINALIZED", state.Status)
	}
}

func insertExpiredRecoveryEnrollmentChallenge(t *testing.T, f *recoveryLifecycleFixture) (EnrollmentChallenge, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	challenge := EnrollmentChallenge{ID: randomCandidateEnrollmentID(t)}
	if _, err := rand.Read(challenge.Nonce[:]); err != nil {
		return EnrollmentChallenge{}, err
	}
	certificateDigest := sha256.Sum256(f.enrollmentRaw)
	var requestDigest []byte
	if err := f.db.QueryRowContext(ctx, `
SELECT request_digest
FROM account_recovery_requests
WHERE account_id = $1::uuid AND request_id = $2::uuid
`, uuidText(f.base.accountID), uuidText(f.recoveryRequestID)).Scan(&requestDigest); err != nil {
		return EnrollmentChallenge{}, err
	}
	if len(requestDigest) != 32 {
		return EnrollmentChallenge{}, errors.New("stored recovery request digest has invalid length")
	}
	err := f.db.QueryRowContext(ctx, `
INSERT INTO device_enrollment_challenges (
    challenge_id, account_id, device_id, account_epoch,
    enrollment_certificate_digest, recovery_request_id,
    recovery_request_digest, challenge_nonce, created_at, expires_at
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, 2, $4, $5::uuid,
    $6, $7, clock_timestamp() - INTERVAL '10 minutes',
    clock_timestamp() - INTERVAL '1 second'
)
RETURNING expires_at
`, uuidText(challenge.ID), uuidText(f.base.accountID),
		uuidText(f.base.deviceID), certificateDigest[:],
		uuidText(f.recoveryRequestID), requestDigest, challenge.Nonce[:]).Scan(&challenge.ExpiresAt)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	return challenge, nil
}

func TestPostgresRecoveryEnrollmentRequiresFinalizedRequestAndExactCertificateIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := f.authorizer.IssueRecoveryEnrollmentChallenge(
		ctx, f.recoveryRequestID, f.enrollmentRaw, f.base.recoveryPublic,
	); !errors.Is(err, ErrRecoveryNotReady) {
		t.Fatalf("issue challenge before finalization: got %v, want ErrRecoveryNotReady", err)
	}

	forceRecoveryDueForTest(t, f.db, f.recoveryRequestID)
	if _, err := f.authorizer.FinalizeRecovery(ctx, f.base.accountID, f.recoveryRequestID); err != nil {
		t.Fatalf("finalize recovery: %v", err)
	}

	wrongTarget := randomCandidateEnrollmentID(t)
	wrongCertificate := testEnrollmentCert(
		t, f.base.recoveryPriv, f.base.accountID, wrongTarget, 2,
		f.base.certificate.DSKPub, f.base.certificate.DDHKPub,
	)
	if _, err := f.authorizer.IssueRecoveryEnrollmentChallenge(
		ctx, f.recoveryRequestID, wrongCertificate.Raw, f.base.recoveryPublic,
	); !errors.Is(err, ErrAuthorizationConflict) {
		t.Fatalf("issue challenge for a different target certificate: got %v, want ErrAuthorizationConflict", err)
	}
}

func TestPostgresRecoveryEnrollmentActivatesOnlyBoundDeviceAndUnlocksAtomicallyIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	finalizeRecoveryForEnrollmentTest(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	challenge, err := f.authorizer.IssueRecoveryEnrollmentChallenge(
		ctx, f.recoveryRequestID, f.enrollmentRaw, f.base.recoveryPublic,
	)
	if err != nil {
		t.Fatalf("issue recovery enrollment challenge: %v", err)
	}

	var boundRequestID string
	var boundRequestDigest, boundCertificateDigest []byte
	var boundEpoch int64
	if err := f.db.QueryRowContext(ctx, `
SELECT recovery_request_id::text, recovery_request_digest,
       enrollment_certificate_digest, account_epoch
FROM device_enrollment_challenges WHERE challenge_id = $1::uuid
`, uuidText(challenge.ID)).Scan(
		&boundRequestID, &boundRequestDigest, &boundCertificateDigest, &boundEpoch,
	); err != nil {
		t.Fatalf("read recovery challenge binding: %v", err)
	}
	certificateDigest := sha256.Sum256(f.enrollmentRaw)
	requestDigest := sha256.Sum256(f.recoveryRequest)
	if boundRequestID != uuidText(f.recoveryRequestID) ||
		!bytesEqual32(boundRequestDigest, requestDigest) ||
		!bytesEqual32(boundCertificateDigest, certificateDigest) || boundEpoch != 2 {
		t.Fatalf("recovery challenge binding mismatch: request=%s epoch=%d", boundRequestID, boundEpoch)
	}

	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong DSK: %v", err)
	}
	wrongProof := recoveryEnrollmentProofForTest(t, f.enrollmentRaw, challenge, wrongPrivate)
	if err := f.authorizer.ActivateRecoveryEnrollment(
		ctx, f.recoveryRequestID, f.enrollmentRaw, wrongProof, f.base.recoveryPublic,
	); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("activate with wrong DSK proof: got %v, want ErrInvalidAuthorization", err)
	}

	var statusBefore int
	if err := f.db.QueryRowContext(ctx, `SELECT status FROM authorization_accounts WHERE account_id=$1::uuid`, uuidText(f.base.accountID)).Scan(&statusBefore); err != nil {
		t.Fatal(err)
	}
	if statusBefore != int(AccountRecoveryLocked) {
		t.Fatalf("invalid proof changed account status to %d; want RecoveryLocked", statusBefore)
	}

	proof := recoveryEnrollmentProofForTest(t, f.enrollmentRaw, challenge, f.base.dskPrivate)
	if err := f.authorizer.ActivateRecoveryEnrollment(
		ctx, f.recoveryRequestID, f.enrollmentRaw, proof, f.base.recoveryPublic,
	); err != nil {
		t.Fatalf("activate recovery replacement device: %v", err)
	}

	var accountEpoch, authEpoch int64
	var accountStatus, deviceStatus int
	var devices, certificates, authDevices, enrollmentEvents int64
	if err := f.db.QueryRowContext(ctx, `SELECT account_epoch FROM accounts WHERE account_id=$1::uuid`, uuidText(f.base.accountID)).Scan(&accountEpoch); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT epoch,status FROM authorization_accounts WHERE account_id=$1::uuid`, uuidText(f.base.accountID)).Scan(&authEpoch, &accountStatus); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT status FROM authorization_devices WHERE account_id=$1::uuid AND device_id=$2::uuid`, uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(&deviceStatus); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM devices WHERE account_id=$1::uuid AND device_id=$2::uuid AND account_epoch=2 AND revoked_at IS NULL`, uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM device_certificates WHERE device_id=$1::uuid AND cert_cbor=$2`, uuidText(f.base.deviceID), f.enrollmentRaw).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM authorization_devices WHERE account_id=$1::uuid AND device_id=$2::uuid AND status=1 AND authorized_epoch=2 AND revoked_epoch=0`, uuidText(f.base.accountID), uuidText(f.base.deviceID)).Scan(&authDevices); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM authorization_events WHERE account_id=$1::uuid AND target_device_id=$2::uuid AND kind='ENROLL' AND cert_cbor=$3`, uuidText(f.base.accountID), uuidText(f.base.deviceID), f.enrollmentRaw).Scan(&enrollmentEvents); err != nil {
		t.Fatal(err)
	}
	var challengeConsumed bool
	if err := f.db.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL FROM device_enrollment_challenges WHERE challenge_id=$1::uuid`, uuidText(challenge.ID)).Scan(&challengeConsumed); err != nil {
		t.Fatal(err)
	}
	if accountEpoch != 2 || authEpoch != 2 || accountStatus != int(AccountActive) || deviceStatus != int(DeviceActive) ||
		devices != 1 || certificates != 1 || authDevices != 1 || enrollmentEvents != 1 || !challengeConsumed {
		t.Fatalf("recovery activation was not atomic: accountEpoch=%d authEpoch=%d accountStatus=%d deviceStatus=%d devices=%d certificates=%d authDevices=%d events=%d challengeConsumed=%v",
			accountEpoch, authEpoch, accountStatus, deviceStatus, devices, certificates, authDevices, enrollmentEvents, challengeConsumed)
	}

	// Exact retry is allowed, but ordinary enrollment must not consume this
	// recovery-bound challenge even after the account has been unlocked.
	if err := f.authorizer.ActivateRecoveryEnrollment(
		ctx, f.recoveryRequestID, f.enrollmentRaw, proof, f.base.recoveryPublic,
	); err != nil {
		t.Fatalf("exact recovery activation retry: %v", err)
	}
	if err := f.authorizer.ActivateCandidateEnrollment(
		ctx, f.enrollmentRaw, proof, f.base.recoveryPublic,
	); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("ordinary enrollment accepted recovery-bound challenge: got %v, want ErrInvalidAuthorization", err)
	}
}

func TestPostgresRecoveryEnrollmentRejectsAbortedRequestIntegration(t *testing.T) {
	f := newRecoveryLifecycleFixture(t)
	if _, err := f.begin(); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	deviceID, privateKey := f.addActiveDevice()
	abortRaw := f.signedAbort(deviceID, privateKey)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := f.authorizer.AbortRecovery(ctx, abortRaw); err != nil {
		t.Fatalf("abort recovery: %v", err)
	}
	if _, err := f.authorizer.IssueRecoveryEnrollmentChallenge(
		ctx, f.recoveryRequestID, f.enrollmentRaw, f.base.recoveryPublic,
	); !errors.Is(err, ErrRecoveryAborted) {
		t.Fatalf("issue challenge for aborted request: got %v, want ErrRecoveryAborted", err)
	}
}

func bytesEqual32(raw []byte, expected [32]byte) bool {
	return len(raw) == len(expected) && string(raw) == string(expected[:])
}
