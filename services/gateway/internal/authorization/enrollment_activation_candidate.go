package authorization

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"
)

// EnrollmentChallenge contains public one-time challenge data. It is a candidate
// API contract, not a frozen product wire format.
type EnrollmentChallenge struct {
	ID        [16]byte
	Nonce     [32]byte
	ExpiresAt time.Time
}

// IssueCandidateEnrollmentChallenge verifies a recovery-signed certificate
// against the account's committed recovery key, locks the authoritative account
// state, and persists a short-lived challenge bound to the exact certificate.
//
// This implementation supports ordinary enrollment for an active account only.
// Recovery-locked activation and the 48-hour recovery protocol are deliberately
// not enabled by this method.
func (a *PostgresAuthorizer) IssueCandidateEnrollmentChallenge(
	ctx context.Context,
	certificateRaw []byte,
	recoveryPublicKey [32]byte,
) (EnrollmentChallenge, error) {
	if err := a.valid(); err != nil {
		return EnrollmentChallenge{}, err
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

	// ensureAccountTx locks the account row and its authorization row. It may
	// initialize the authorization row only when the recovery key matches IRC.
	account, err := a.ensureAccountTx(ctx, tx, cert.AccountID, recoveryPublicKey)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	pending, err := hasPendingRecoveryTx(ctx, tx, cert.AccountID)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	if pending {
		return EnrollmentChallenge{}, ErrRecoveryPending
	}
	if account.Status != AccountActive {
		return EnrollmentChallenge{}, ErrAccountLocked
	}
	if account.Epoch != cert.Epoch || account.Epoch > LifecycleWireV1MaxEpoch {
		return EnrollmentChallenge{}, ErrInvalidEpoch
	}

	var deviceExists bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM devices WHERE device_id = $1::uuid)
    OR EXISTS (SELECT 1 FROM authorization_devices WHERE device_id = $1::uuid)
`, uuidText(cert.DeviceID)).Scan(&deviceExists); err != nil {
		return EnrollmentChallenge{}, err
	}
	if deviceExists {
		return EnrollmentChallenge{}, ErrDeviceExists
	}

	var challenge EnrollmentChallenge
	if _, err := rand.Read(challenge.ID[:]); err != nil {
		return EnrollmentChallenge{}, err
	}
	// UUIDv4 shape; nonzero by construction.
	challenge.ID[6] = (challenge.ID[6] & 0x0f) | 0x40
	challenge.ID[8] = (challenge.ID[8] & 0x3f) | 0x80
	if _, err := rand.Read(challenge.Nonce[:]); err != nil {
		return EnrollmentChallenge{}, err
	}

	// Reissuing a challenge invalidates older outstanding challenges for this
	// account/device. This happens in the same transaction as the new insert.
	if _, err := tx.ExecContext(ctx, `
UPDATE device_enrollment_challenges
SET consumed_at = clock_timestamp()
WHERE account_id = $1::uuid AND device_id = $2::uuid AND consumed_at IS NULL
`, uuidText(cert.AccountID), uuidText(cert.DeviceID)); err != nil {
		return EnrollmentChallenge{}, err
	}

	digest := sha256.Sum256(certificateRaw)
	err = tx.QueryRowContext(ctx, `
INSERT INTO device_enrollment_challenges (
    challenge_id, account_id, device_id, account_epoch,
    enrollment_certificate_digest, challenge_nonce, expires_at
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4, $5, $6,
    clock_timestamp() + INTERVAL '5 minutes'
)
RETURNING expires_at
`, uuidText(challenge.ID), uuidText(cert.AccountID), uuidText(cert.DeviceID),
		int64(cert.Epoch), digest[:], challenge.Nonce[:]).Scan(&challenge.ExpiresAt)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	if err := tx.Commit(); err != nil {
		return EnrollmentChallenge{}, err
	}
	return challenge, nil
}

// ActivateCandidateEnrollment validates the native device's DSK proof against
// the exact certificate and database-issued challenge, then atomically commits
// the challenge consumption, device row, certificate, authorization row, and
// immutable authorization event.
//
// A consumed challenge is idempotent only if the exact certificate is already
// installed and active. A stale epoch, locked account, missing challenge, or
// partial/inconsistent prior installation fails closed.
func (a *PostgresAuthorizer) ActivateCandidateEnrollment(
	ctx context.Context,
	certificateRaw []byte,
	proofRaw []byte,
	recoveryPublicKey [32]byte,
) error {
	if err := a.valid(); err != nil {
		return err
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

	// Unlike challenge issuance, activation must not recreate missing auth state.
	// A missing row here is corruption/ambiguity and is rejected.
	account, err := a.lockExistingCandidateEnrollmentAccountTx(ctx, tx, cert.AccountID, recoveryPublicKey)
	if err != nil {
		return err
	}
	pending, err := hasPendingRecoveryTx(ctx, tx, cert.AccountID)
	if err != nil {
		return err
	}
	if pending {
		return ErrRecoveryPending
	}
	if account.Status != AccountActive {
		return ErrAccountLocked
	}
	if account.Epoch != cert.Epoch || account.Epoch > LifecycleWireV1MaxEpoch {
		return ErrInvalidEpoch
	}

	var challengeAccountID, challengeDeviceID []byte
	var challengeEpoch int64
	var storedDigest, storedNonce []byte
	var expiresAt time.Time
	var consumedAt sql.NullTime
	var recoveryRequestID sql.NullString
	var recoveryRequestDigest []byte
	err = tx.QueryRowContext(ctx, `
SELECT uuid_send(account_id), uuid_send(device_id), account_epoch,
       enrollment_certificate_digest, challenge_nonce, expires_at,
       consumed_at, recovery_request_id::text, recovery_request_digest
FROM device_enrollment_challenges
WHERE challenge_id = $1::uuid
FOR UPDATE
`, uuidText(proof.ChallengeID)).Scan(
		&challengeAccountID, &challengeDeviceID, &challengeEpoch,
		&storedDigest, &storedNonce, &expiresAt, &consumedAt,
		&recoveryRequestID, &recoveryRequestDigest,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollmentChallengeNotFound
	}
	if err != nil {
		return err
	}

	digest := sha256.Sum256(certificateRaw)
	if len(challengeAccountID) != 16 || len(challengeDeviceID) != 16 ||
		!bytes.Equal(challengeAccountID, cert.AccountID[:]) ||
		!bytes.Equal(challengeDeviceID, cert.DeviceID[:]) ||
		challengeEpoch < 1 || uint64(challengeEpoch) > LifecycleWireV1MaxEpoch ||
		uint64(challengeEpoch) != cert.Epoch ||
		len(storedDigest) != 32 || !bytes.Equal(storedDigest, digest[:]) ||
		len(storedNonce) != 32 ||
		recoveryRequestID.Valid || len(recoveryRequestDigest) != 0 {
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
		installed, err := candidateEnrollmentAlreadyCommittedTx(
			ctx, tx, digest, cert,
		)
		if err != nil {
			return err
		}
		if installed {
			return tx.Commit()
		}
		return ErrEnrollmentChallengeConsumed
	}

	// Evaluate expiry using database time only after the account and challenge
	// rows have been locked; application clocks do not decide challenge validity.
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

	// These writes intentionally share one transaction with challenge consumption.
	// No active device is created by a certificate-only or proof-only path.
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
		cert.DDHKPub[:], int64(cert.Epoch), digest[:]); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO authorization_events (
    auth_digest, kind, account_id, old_epoch, new_epoch, target_device_id, cert_cbor
) VALUES ($1, 'ENROLL', $2::uuid, $3, $3, $4::uuid, $5)
`, digest[:], uuidText(cert.AccountID), int64(cert.Epoch),
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
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrEnrollmentChallengeConsumed
	}
	return tx.Commit()
}

func parseCandidateEnrollmentCertificate(
	raw []byte,
	recoveryPublicKey [32]byte,
) (DeviceEnrollmentAuthorizationV1, error) {
	cert, err := ParseDeviceEnrollmentAuthorizationV1(raw)
	if err != nil {
		return DeviceEnrollmentAuthorizationV1{}, ErrInvalidAuthorization
	}
	if cert.Epoch == 0 || cert.Epoch > LifecycleWireV1MaxEpoch {
		return DeviceEnrollmentAuthorizationV1{}, ErrInvalidEpoch
	}
	if err := cert.Verify(recoveryPublicKey); err != nil {
		return DeviceEnrollmentAuthorizationV1{}, ErrInvalidAuthorization
	}
	if !candidateX25519PublicKeyUsable(cert.DDHKPub) {
		return DeviceEnrollmentAuthorizationV1{}, ErrInvalidAuthorization
	}
	return cert, nil
}

func candidateX25519PublicKeyUsable(raw [32]byte) bool {
	curve := ecdh.X25519()
	publicKey, err := curve.NewPublicKey(raw[:])
	if err != nil {
		return false
	}
	// A fixed nonzero test scalar is enough to reject low-order public points;
	// ECDH returns an error for the all-zero shared secret in Go's X25519 API.
	privateKey, err := curve.NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		return false
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return false
	}
	var aggregate byte
	for _, value := range shared {
		aggregate |= value
	}
	return aggregate != 0
}

func (a *PostgresAuthorizer) lockExistingCandidateEnrollmentAccountTx(
	ctx context.Context,
	tx *sql.Tx,
	accountID [16]byte,
	recoveryPublicKey [32]byte,
) (persistedAccount, error) {
	var epoch int64
	var irc []byte
	err := tx.QueryRowContext(ctx, `
SELECT account_epoch, irc
FROM accounts
WHERE account_id = $1::uuid
FOR UPDATE
`, uuidText(accountID)).Scan(&epoch, &irc)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedAccount{}, ErrAccountNotFound
	}
	if err != nil {
		return persistedAccount{}, err
	}
	if epoch < 1 || uint64(epoch) > LifecycleWireV1MaxEpoch || len(irc) != 32 {
		return persistedAccount{}, ErrAuthorizationConflict
	}

	var authEpoch int64
	var storedCommitment, storedPublic []byte
	var status int
	err = tx.QueryRowContext(ctx, `
SELECT epoch, recovery_commitment, recovery_pub, status
FROM authorization_accounts
WHERE account_id = $1::uuid
FOR UPDATE
`, uuidText(accountID)).Scan(&authEpoch, &storedCommitment, &storedPublic, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	if err != nil {
		return persistedAccount{}, err
	}
	if authEpoch != epoch || authEpoch < 1 || uint64(authEpoch) > LifecycleWireV1MaxEpoch ||
		len(storedCommitment) != 32 || len(storedPublic) != 32 ||
		!bytes.Equal(storedCommitment, irc) ||
		!bytes.Equal(storedPublic, recoveryPublicKey[:]) {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	var commitment [32]byte
	copy(commitment[:], storedCommitment)
	if !VerifyRecoveryCommitment(commitment, recoveryPublicKey) {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	if status != int(AccountActive) && status != int(AccountRecoveryLocked) {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	var storedPub [32]byte
	copy(storedPub[:], storedPublic)
	return persistedAccount{
		Epoch:              uint64(authEpoch),
		RecoveryCommitment: commitment,
		RecoveryPub:        storedPub,
		Status:             AccountStatus(status),
	}, nil
}

func candidateEnrollmentAlreadyCommittedTx(
	ctx context.Context,
	tx *sql.Tx,
	digest [32]byte,
	cert DeviceEnrollmentAuthorizationV1,
) (bool, error) {
	var installed bool
	err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM authorization_events e
    JOIN authorization_devices ad
      ON ad.account_id = e.account_id AND ad.device_id = e.target_device_id
    JOIN devices d
      ON d.account_id = ad.account_id AND d.device_id = ad.device_id
    WHERE e.auth_digest = $1
      AND e.kind = 'ENROLL'
      AND e.account_id = $2::uuid
      AND e.target_device_id = $3::uuid
      AND e.cert_cbor = $4
      AND e.old_epoch = $6
      AND e.new_epoch = $6
      AND ad.enrollment_auth_digest = $1
      AND ad.status = $5
      AND ad.authorized_epoch = $6
      AND ad.dsk_pub = $7
      AND ad.ddhk_pub = $8
      AND ad.revoked_epoch = 0
      AND d.account_epoch = $6
      AND d.revoked_at IS NULL
      AND d.dsk_pub = $7
      AND d.ddhk_pub = $8
      AND EXISTS (
          SELECT 1 FROM device_certificates dc
          WHERE dc.device_id = d.device_id AND dc.cert_cbor = $4
      )
)
`, digest[:], uuidText(cert.AccountID), uuidText(cert.DeviceID), cert.Raw,
		int(DeviceActive), int64(cert.Epoch), cert.DSKPub[:], cert.DDHKPub[:]).Scan(&installed)
	return installed, err
}
