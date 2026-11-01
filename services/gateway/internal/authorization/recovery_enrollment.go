package authorization

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"
)

// IssueRecoveryEnrollmentChallenge issues a short-lived proof-of-possession
// challenge for the exact replacement certificate bound to a FINALIZED
// recovery request. Ordinary enrollment remains a separate, active-account
// only flow.
func (a *PostgresAuthorizer) IssueRecoveryEnrollmentChallenge(
	ctx context.Context,
	requestID [16]byte,
	certificateRaw []byte,
	recoveryPublicKey [32]byte,
) (EnrollmentChallenge, error) {
	if err := a.valid(); err != nil {
		return EnrollmentChallenge{}, err
	}
	if requestID == [16]byte{} {
		return EnrollmentChallenge{}, ErrInvalidAuthorization
	}
	cert, err := parseCandidateEnrollmentCertificate(certificateRaw, recoveryPublicKey)
	if err != nil {
		return EnrollmentChallenge{}, err
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	defer tx.Rollback()

	// Preserve the lifecycle lock order: account, authorization account,
	// recovery request, then (for activation) enrollment challenge.
	account, err := a.lockRecoveryAccountTx(ctx, tx, cert.AccountID)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	if account.RecoveryPub != recoveryPublicKey {
		return EnrollmentChallenge{}, ErrAuthorizationConflict
	}
	row, found, err := loadRecoveryRequestTx(ctx, tx, requestID)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	if !found || row.accountID != cert.AccountID {
		return EnrollmentChallenge{}, ErrRecoveryRequestNotFound
	}
	request, err := verifyStoredRecoveryRequest(row, cert.AccountID, account.RecoveryPub)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	switch row.state.Status {
	case RecoveryRequestPending:
		return EnrollmentChallenge{}, ErrRecoveryNotReady
	case RecoveryRequestAborted:
		return EnrollmentChallenge{}, ErrRecoveryAborted
	case RecoveryRequestFinalized:
		// Continue below.
	default:
		return EnrollmentChallenge{}, ErrAuthorizationConflict
	}
	if account.Status != AccountRecoveryLocked || account.Epoch != request.NewEpoch {
		return EnrollmentChallenge{}, ErrAuthorizationConflict
	}

	certificateDigest := sha256.Sum256(certificateRaw)
	if cert.AccountID != request.AccountID || cert.DeviceID != request.TargetDeviceID ||
		cert.Epoch != request.NewEpoch || certificateDigest != request.EnrollmentCertDigest ||
		certificateDigest != row.enrollmentCertificateSHA {
		return EnrollmentChallenge{}, ErrAuthorizationConflict
	}

	var targetExists bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM devices WHERE device_id = $1::uuid)
    OR EXISTS (SELECT 1 FROM authorization_devices WHERE device_id = $1::uuid)
`, uuidText(cert.DeviceID)).Scan(&targetExists); err != nil {
		return EnrollmentChallenge{}, err
	}
	if targetExists {
		return EnrollmentChallenge{}, ErrDeviceExists
	}

	var challenge EnrollmentChallenge
	if _, err := rand.Read(challenge.ID[:]); err != nil {
		return EnrollmentChallenge{}, err
	}
	challenge.ID[6] = (challenge.ID[6] & 0x0f) | 0x40
	challenge.ID[8] = (challenge.ID[8] & 0x3f) | 0x80
	if _, err := rand.Read(challenge.Nonce[:]); err != nil {
		return EnrollmentChallenge{}, err
	}

	// Only the most recently issued challenge for this account/device remains
	// usable. Challenge binding columns are immutable under migration 0008.
	if _, err := tx.ExecContext(ctx, `
UPDATE device_enrollment_challenges
SET consumed_at = COALESCE(consumed_at, clock_timestamp())
WHERE account_id = $1::uuid AND device_id = $2::uuid AND consumed_at IS NULL
`, uuidText(cert.AccountID), uuidText(cert.DeviceID)); err != nil {
		return EnrollmentChallenge{}, err
	}

	err = tx.QueryRowContext(ctx, `
INSERT INTO device_enrollment_challenges (
    challenge_id, account_id, device_id, account_epoch,
    enrollment_certificate_digest, recovery_request_id,
    recovery_request_digest, challenge_nonce, expires_at
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4, $5, $6::uuid, $7, $8,
    clock_timestamp() + INTERVAL '5 minutes'
)
RETURNING expires_at
`, uuidText(challenge.ID), uuidText(cert.AccountID), uuidText(cert.DeviceID),
		int64(cert.Epoch), certificateDigest[:], uuidText(requestID), row.state.RequestDigest[:],
		challenge.Nonce[:]).Scan(&challenge.ExpiresAt)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	if err := tx.Commit(); err != nil {
		return EnrollmentChallenge{}, err
	}
	return challenge, nil
}

// ActivateRecoveryEnrollment activates only the replacement device named by a
// FINALIZED recovery request. It atomically installs the device, consumes the
// exact recovery-bound challenge, records the ENROLL event, and unlocks the
// account. Exact retries are accepted only when PostgreSQL confirms that the
// same certificate is already installed and active.
func (a *PostgresAuthorizer) ActivateRecoveryEnrollment(
	ctx context.Context,
	requestID [16]byte,
	certificateRaw []byte,
	proofRaw []byte,
	recoveryPublicKey [32]byte,
) error {
	if err := a.valid(); err != nil {
		return err
	}
	if requestID == [16]byte{} {
		return ErrInvalidAuthorization
	}
	cert, err := parseCandidateEnrollmentCertificate(certificateRaw, recoveryPublicKey)
	if err != nil {
		return err
	}
	proof, err := ParseDeviceEnrollmentPoPV1(proofRaw)
	if err != nil {
		return ErrInvalidAuthorization
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	account, err := a.lockRecoveryAccountTx(ctx, tx, cert.AccountID)
	if err != nil {
		return err
	}
	if account.RecoveryPub != recoveryPublicKey {
		return ErrAuthorizationConflict
	}
	row, found, err := loadRecoveryRequestTx(ctx, tx, requestID)
	if err != nil {
		return err
	}
	if !found || row.accountID != cert.AccountID {
		return ErrRecoveryRequestNotFound
	}
	request, err := verifyStoredRecoveryRequest(row, cert.AccountID, account.RecoveryPub)
	if err != nil {
		return err
	}
	switch row.state.Status {
	case RecoveryRequestPending:
		return ErrRecoveryNotReady
	case RecoveryRequestAborted:
		return ErrRecoveryAborted
	case RecoveryRequestFinalized:
		// Continue below.
	default:
		return ErrAuthorizationConflict
	}

	certificateDigest := sha256.Sum256(certificateRaw)
	if cert.AccountID != request.AccountID || cert.DeviceID != request.TargetDeviceID ||
		cert.Epoch != request.NewEpoch || certificateDigest != request.EnrollmentCertDigest ||
		certificateDigest != row.enrollmentCertificateSHA || account.Epoch != request.NewEpoch {
		return ErrAuthorizationConflict
	}

	var challengeAccountID, challengeDeviceID []byte
	var challengeEpoch int64
	var storedCertificateDigest, storedNonce, storedRecoveryRequestDigest []byte
	var storedRecoveryRequestID sql.NullString
	var expiresAt time.Time
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT uuid_send(account_id), uuid_send(device_id), account_epoch,
       enrollment_certificate_digest, recovery_request_id::text,
       recovery_request_digest, challenge_nonce, expires_at, consumed_at
FROM device_enrollment_challenges
WHERE challenge_id = $1::uuid
FOR UPDATE
`, uuidText(proof.ChallengeID)).Scan(
		&challengeAccountID, &challengeDeviceID, &challengeEpoch,
		&storedCertificateDigest, &storedRecoveryRequestID,
		&storedRecoveryRequestDigest, &storedNonce, &expiresAt, &consumedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollmentChallengeNotFound
	}
	if err != nil {
		return err
	}
	if len(challengeAccountID) != 16 || len(challengeDeviceID) != 16 ||
		!bytes.Equal(challengeAccountID, cert.AccountID[:]) ||
		!bytes.Equal(challengeDeviceID, cert.DeviceID[:]) ||
		challengeEpoch < 1 || uint64(challengeEpoch) != cert.Epoch ||
		len(storedCertificateDigest) != 32 || !bytes.Equal(storedCertificateDigest, certificateDigest[:]) ||
		!storedRecoveryRequestID.Valid || storedRecoveryRequestID.String != uuidText(requestID) ||
		len(storedRecoveryRequestDigest) != 32 || !bytes.Equal(storedRecoveryRequestDigest, row.state.RequestDigest[:]) ||
		len(storedNonce) != 32 {
		return ErrInvalidAuthorization
	}

	var expectedNonce [32]byte
	copy(expectedNonce[:], storedNonce)
	if err := proof.VerifyForEnrollmentAndChallenge(
		recoveryPublicKey, certificateRaw, proof.ChallengeID, expectedNonce,
	); err != nil {
		return ErrInvalidAuthorization
	}

	if consumedAt.Valid {
		installed, err := candidateEnrollmentAlreadyCommittedTx(ctx, tx, certificateDigest, cert)
		if err != nil {
			return err
		}
		if account.Status == AccountActive && installed {
			return tx.Commit()
		}
		return ErrEnrollmentChallengeConsumed
	}
	if account.Status != AccountRecoveryLocked {
		return ErrAccountLocked
	}

	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
		return err
	}
	if !databaseNow.Before(expiresAt) {
		return ErrEnrollmentChallengeExpired
	}

	var deviceExists bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM devices WHERE device_id = $1::uuid)
    OR EXISTS (SELECT 1 FROM authorization_devices WHERE device_id = $1::uuid)
`, uuidText(cert.DeviceID)).Scan(&deviceExists); err != nil {
		return err
	}
	if deviceExists {
		return ErrDeviceExists
	}

	// Installation, challenge consumption and account unlock are one transaction.
	if _, err := tx.ExecContext(ctx, `
INSERT INTO devices (
    device_id, account_id, account_epoch, dsk_pub, ddhk_pub, push_pub, revoked_at
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, NULL, NULL)
`, uuidText(cert.DeviceID), uuidText(cert.AccountID), int64(cert.Epoch),
		cert.DSKPub[:], cert.DDHKPub[:]); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO device_certificates (device_id, cert_cbor)
VALUES ($1::uuid, $2)
`, uuidText(cert.DeviceID), certificateRaw); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO authorization_devices (
    device_id, account_id, dsk_pub, ddhk_pub, status,
    authorized_epoch, enrollment_auth_digest, revoked_epoch
) VALUES ($1::uuid, $2::uuid, $3, $4, 1, $5, $6, 0)
`, uuidText(cert.DeviceID), uuidText(cert.AccountID), cert.DSKPub[:],
		cert.DDHKPub[:], int64(cert.Epoch), certificateDigest[:]); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO authorization_events (
    auth_digest, kind, account_id, old_epoch, new_epoch, target_device_id, payload_cbor
) VALUES ($1, 'ENROLL', $2::uuid, $3, $3, $4::uuid, $5)
`, certificateDigest[:], uuidText(cert.AccountID), int64(cert.Epoch),
		uuidText(cert.DeviceID), certificateRaw); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE device_enrollment_challenges
SET consumed_at = clock_timestamp()
WHERE challenge_id = $1::uuid AND consumed_at IS NULL
`, uuidText(proof.ChallengeID))
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return ErrEnrollmentChallengeConsumed
	}
	result, err = tx.ExecContext(ctx, `
UPDATE authorization_accounts
SET status = $3, updated_at = clock_timestamp()
WHERE account_id = $1::uuid AND epoch = $2 AND status = $4
`, uuidText(cert.AccountID), int64(cert.Epoch), int(AccountActive), int(AccountRecoveryLocked))
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return ErrAuthorizationConflict
	}
	return tx.Commit()
}
