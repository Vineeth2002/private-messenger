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

// IssueInitialAccountBootstrapChallenge creates a short-lived challenge for the
// first device of an account. Unlike additional-device enrollment, no account
// row exists yet; the challenge is therefore stored in its own unbound table.
func (a *PostgresAuthorizer) IssueInitialAccountBootstrapChallenge(
	ctx context.Context, certificateRaw []byte, recoveryPublicKey [32]byte,
) (EnrollmentChallenge, error) {
	if err := a.valid(); err != nil {
		return EnrollmentChallenge{}, err
	}
	cert, err := parseCandidateEnrollmentCertificate(certificateRaw, recoveryPublicKey)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	if cert.Epoch != 1 {
		return EnrollmentChallenge{}, ErrInvalidEpoch
	}
	commitment := RecoveryCommitment(recoveryPublicKey)

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	defer tx.Rollback()
	if err = lockInitialBootstrapAccount(ctx, tx, uuidText(cert.AccountID)); err != nil {
		return EnrollmentChallenge{}, err
	}

	var accountExists, deviceExists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM accounts WHERE account_id=$1::uuid)`, uuidText(cert.AccountID)).Scan(&accountExists); err != nil {
		return EnrollmentChallenge{}, err
	}
	if accountExists {
		return EnrollmentChallenge{}, ErrAccountExists
	}
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE device_id=$1::uuid) OR EXISTS(SELECT 1 FROM authorization_devices WHERE device_id=$1::uuid)`, uuidText(cert.DeviceID)).Scan(&deviceExists); err != nil {
		return EnrollmentChallenge{}, err
	}
	if deviceExists {
		return EnrollmentChallenge{}, ErrDeviceExists
	}

	var challenge EnrollmentChallenge
	if _, err = rand.Read(challenge.ID[:]); err != nil {
		return EnrollmentChallenge{}, err
	}
	challenge.ID[6] = (challenge.ID[6] & 0x0f) | 0x40
	challenge.ID[8] = (challenge.ID[8] & 0x3f) | 0x80
	if _, err = rand.Read(challenge.Nonce[:]); err != nil {
		return EnrollmentChallenge{}, err
	}
	digest := sha256.Sum256(certificateRaw)
	// A newly issued challenge supersedes every still-live challenge for this
	// account. Consumed challenges remain immutable audit records.
	if _, err = tx.ExecContext(ctx, `UPDATE initial_account_bootstrap_challenges SET consumed_at=clock_timestamp() WHERE account_id=$1::uuid AND consumed_at IS NULL`, uuidText(cert.AccountID)); err != nil {
		return EnrollmentChallenge{}, err
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO initial_account_bootstrap_challenges
      (challenge_id,account_id,device_id,account_epoch,enrollment_certificate_digest,recovery_commitment,recovery_pub,challenge_nonce,expires_at)
      VALUES ($1::uuid,$2::uuid,$3::uuid,1,$4,$5,$6,$7,clock_timestamp()+INTERVAL '5 minutes') RETURNING expires_at`,
		uuidText(challenge.ID), uuidText(cert.AccountID), uuidText(cert.DeviceID), digest[:], commitment[:], recoveryPublicKey[:], challenge.Nonce[:]).Scan(&challenge.ExpiresAt)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	if err = tx.Commit(); err != nil {
		return EnrollmentChallenge{}, err
	}
	return challenge, nil
}

// ActivateInitialAccountBootstrap proves possession of the first device key and
// atomically creates the account, authorization state, device, certificate,
// event, and challenge consumption. Exact retries are accepted only if the
// complete installed state matches the original certificate.
func (a *PostgresAuthorizer) ActivateInitialAccountBootstrap(
	ctx context.Context, certificateRaw, proofRaw []byte, recoveryPublicKey [32]byte,
) error {
	if err := a.valid(); err != nil {
		return err
	}
	cert, err := parseCandidateEnrollmentCertificate(certificateRaw, recoveryPublicKey)
	if err != nil {
		return err
	}
	if cert.Epoch != 1 {
		return ErrInvalidEpoch
	}
	proof, err := ParseDeviceEnrollmentPoPV1(proofRaw)
	if err != nil {
		return ErrInvalidAuthorization
	}

	// Read only the account lock key first. The row is re-read and locked after
	// acquiring the same advisory lock used by challenge issuance.
	var accountIDText string
	err = a.db.QueryRowContext(ctx, `SELECT account_id::text FROM initial_account_bootstrap_challenges WHERE challenge_id=$1::uuid`, uuidText(proof.ChallengeID)).Scan(&accountIDText)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollmentChallengeNotFound
	}
	if err != nil {
		return err
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockInitialBootstrapAccount(ctx, tx, accountIDText); err != nil {
		return err
	}

	var challengeAccount, challengeDevice, storedDigest, storedCommitment, storedRecoveryPub, nonce []byte
	var epoch int64
	var expires time.Time
	var consumed sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT uuid_send(account_id),uuid_send(device_id),account_epoch,enrollment_certificate_digest,recovery_commitment,recovery_pub,challenge_nonce,expires_at,consumed_at FROM initial_account_bootstrap_challenges WHERE challenge_id=$1::uuid FOR UPDATE`, uuidText(proof.ChallengeID)).Scan(
		&challengeAccount, &challengeDevice, &epoch, &storedDigest, &storedCommitment, &storedRecoveryPub, &nonce, &expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollmentChallengeNotFound
	}
	if err != nil {
		return err
	}
	digest := sha256.Sum256(certificateRaw)
	commitment := RecoveryCommitment(recoveryPublicKey)
	if len(challengeAccount) != 16 || !bytes.Equal(challengeAccount, cert.AccountID[:]) || len(challengeDevice) != 16 || !bytes.Equal(challengeDevice, cert.DeviceID[:]) || epoch != 1 || cert.Epoch != 1 || len(storedDigest) != 32 || !bytes.Equal(storedDigest, digest[:]) || len(storedCommitment) != 32 || !bytes.Equal(storedCommitment, commitment[:]) || len(storedRecoveryPub) != 32 || !bytes.Equal(storedRecoveryPub, recoveryPublicKey[:]) || len(nonce) != 32 {
		return ErrInvalidAuthorization
	}
	var expectedNonce [32]byte
	copy(expectedNonce[:], nonce)
	if err = proof.VerifyForEnrollmentAndChallenge(recoveryPublicKey, certificateRaw, proof.ChallengeID, expectedNonce); err != nil {
		return ErrInvalidAuthorization
	}

	if consumed.Valid {
		installed, checkErr := initialAccountBootstrapAlreadyCommittedTx(ctx, tx, digest, cert, commitment, recoveryPublicKey)
		if checkErr != nil {
			return checkErr
		}
		if installed {
			return tx.Commit()
		}
		return ErrEnrollmentChallengeConsumed
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if !now.Before(expires) {
		return ErrEnrollmentChallengeExpired
	}

	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM accounts WHERE account_id=$1::uuid) OR EXISTS(SELECT 1 FROM devices WHERE device_id=$2::uuid)`, uuidText(cert.AccountID), uuidText(cert.DeviceID)).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrAccountExists
	}

	// username is an internal schema-required identifier, not a user-selected
	// handle. Deriving it from the UUID makes it deterministic and collision-free.
	username := "pm-" + uuidText(cert.AccountID)
	if _, err = tx.ExecContext(ctx, `INSERT INTO accounts(account_id,username,account_epoch,irc) VALUES($1::uuid,$2,1,$3)`, uuidText(cert.AccountID), username, commitment[:]); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO authorization_accounts(account_id,epoch,recovery_commitment,recovery_pub,status) VALUES($1::uuid,1,$2,$3,1)`, uuidText(cert.AccountID), commitment[:], recoveryPublicKey[:]); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO devices(device_id,account_id,account_epoch,dsk_pub,ddhk_pub,push_pub,revoked_at) VALUES($1::uuid,$2::uuid,1,$3,$4,NULL,NULL)`, uuidText(cert.DeviceID), uuidText(cert.AccountID), cert.DSKPub[:], cert.DDHKPub[:]); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_certificates(device_id,cert_cbor) VALUES($1::uuid,$2)`, uuidText(cert.DeviceID), certificateRaw); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO authorization_devices(device_id,account_id,dsk_pub,ddhk_pub,status,authorized_epoch,enrollment_auth_digest,revoked_epoch) VALUES($1::uuid,$2::uuid,$3,$4,1,1,$5,0)`, uuidText(cert.DeviceID), uuidText(cert.AccountID), cert.DSKPub[:], cert.DDHKPub[:], digest[:]); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO authorization_events(auth_digest,kind,account_id,old_epoch,new_epoch,target_device_id,payload_cbor) VALUES($1,'ENROLL',$2::uuid,1,1,$3::uuid,$4)`, digest[:], uuidText(cert.AccountID), uuidText(cert.DeviceID), certificateRaw); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE initial_account_bootstrap_challenges SET consumed_at=clock_timestamp() WHERE challenge_id=$1::uuid AND consumed_at IS NULL`, uuidText(proof.ChallengeID))
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

func initialAccountBootstrapAlreadyCommittedTx(ctx context.Context, tx *sql.Tx, digest [32]byte, cert DeviceEnrollmentAuthorizationV1, commitment, recoveryPub [32]byte) (bool, error) {
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(
      SELECT 1 FROM accounts a JOIN authorization_accounts aa ON aa.account_id=a.account_id
      JOIN devices d ON d.account_id=a.account_id JOIN authorization_devices ad ON ad.account_id=a.account_id AND ad.device_id=d.device_id
      JOIN authorization_events e ON e.account_id=a.account_id AND e.target_device_id=d.device_id
      WHERE a.account_id=$1::uuid AND a.username=$2 AND a.account_epoch=1 AND a.irc=$3
      AND aa.epoch=1 AND aa.recovery_commitment=$3 AND aa.recovery_pub=$4 AND aa.status=1
      AND d.device_id=$5::uuid AND d.account_epoch=1 AND d.dsk_pub=$6 AND d.ddhk_pub=$7 AND d.revoked_at IS NULL
      AND ad.status=1 AND ad.authorized_epoch=1 AND ad.enrollment_auth_digest=$8 AND ad.dsk_pub=$6 AND ad.ddhk_pub=$7 AND ad.revoked_epoch=0
      AND e.auth_digest=$8 AND e.kind='ENROLL' AND e.old_epoch=1 AND e.new_epoch=1 AND e.payload_cbor=$9
      AND EXISTS(SELECT 1 FROM device_certificates dc WHERE dc.device_id=d.device_id AND dc.cert_cbor=$9)
    )`, uuidText(cert.AccountID), "pm-"+uuidText(cert.AccountID), commitment[:], recoveryPub[:], uuidText(cert.DeviceID), cert.DSKPub[:], cert.DDHKPub[:], digest[:], cert.Raw).Scan(&ok)
	return ok, err
}

// lockInitialBootstrapAccount serializes challenge replacement and first-account
// activation for the same account without requiring an accounts row to exist.
func lockInitialBootstrapAccount(ctx context.Context, tx *sql.Tx, accountID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, accountID)
	if err != nil {
		return err
	}
	if !rows.Next() {
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return err
		}
		return errors.New("initial bootstrap advisory lock returned no row")
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	return closeErr
}
