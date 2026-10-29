package authorization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

type PostgresAuthorizer struct{ db *sql.DB }

func NewPostgresAuthorizer(db *sql.DB) *PostgresAuthorizer { return &PostgresAuthorizer{db: db} }
func (a *PostgresAuthorizer) valid() error {
	if a == nil || a.db == nil {
		return ErrNilAuthorizer
	}
	return nil
}

func (a *PostgresAuthorizer) Enroll(ctx context.Context, cert DeviceEnrollmentAuthorizationV1, recoveryPub [32]byte) error {
	if err := a.valid(); err != nil {
		return err
	}
	// A recovery-signed public-key certificate alone does not prove possession
	// of the DSK. All activation must use ActivateCandidateEnrollment, which
	// checks a live database challenge and commits its consumption atomically.
	return ErrEnrollmentProofRequired
}
func (a *PostgresAuthorizer) Transition(ctx context.Context, cert EpochTransitionAuthorizationV1, recoveryPub [32]byte) error {
	if err := a.valid(); err != nil {
		return err
	}
	if err := cert.Verify(recoveryPub); err != nil {
		return err
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	account, err := a.ensureAccountTx(ctx, tx, cert.AccountID, recoveryPub)
	if err != nil {
		return err
	}
	digest := cert.Digest()
	if prior, ok, err := a.eventByDigestTx(ctx, tx, digest); err != nil {
		return err
	} else if ok {
		_ = prior
		return nil
	}
	if account.Epoch != cert.OldEpoch {
		return ErrInvalidEpoch
	}
	if ev, ok, err := a.logicalEventTx(ctx, tx, "TRANSITION", cert.AccountID, cert.OldEpoch, cert.NewEpoch, cert.DeviceID); err != nil {
		return err
	} else if ok {
		if bytes.Equal(ev.Digest, digest[:]) {
			return nil
		}
		return ErrAuthorizationConflict
	}
	now := time.Now().UTC()
	switch cert.Action {
	case RevokeDeviceAction:
		var status int
		var dsk, ddhk []byte
		err = tx.QueryRowContext(ctx, `SELECT status,dsk_pub,ddhk_pub FROM authorization_devices WHERE device_id=$1::uuid AND account_id=$2::uuid FOR UPDATE`, uuidText(cert.DeviceID), uuidText(cert.AccountID)).Scan(&status, &dsk, &ddhk)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceNotFound
		}
		if err != nil {
			return err
		}
		if status != int(DeviceActive) {
			return ErrDeviceRevoked
		}
		if _, err = tx.ExecContext(ctx, `UPDATE authorization_devices SET status=2,revoked_epoch=$3,updated_at=now() WHERE device_id=$1::uuid AND account_id=$2::uuid`, uuidText(cert.DeviceID), uuidText(cert.AccountID), int64(cert.NewEpoch)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE authorization_devices SET authorized_epoch=$2,updated_at=now() WHERE account_id=$1::uuid AND status=1`, uuidText(cert.AccountID), int64(cert.NewEpoch)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE devices d SET account_epoch=$2,revoked_at=CASE WHEN d.device_id=$3::uuid THEN COALESCE(d.revoked_at,$4) ELSE d.revoked_at END FROM authorization_devices ad WHERE ad.device_id=d.device_id AND ad.account_id=$1::uuid`, uuidText(cert.AccountID), int64(cert.NewEpoch), uuidText(cert.DeviceID), now); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE accounts SET account_epoch=$2 WHERE account_id=$1::uuid`, uuidText(cert.AccountID), int64(cert.NewEpoch)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE authorization_accounts SET epoch=$2,status=1,updated_at=now() WHERE account_id=$1::uuid`, uuidText(cert.AccountID), int64(cert.NewEpoch)); err != nil {
			return err
		}
	case RecoveryResetAction:
		if _, err = tx.ExecContext(ctx, `UPDATE authorization_devices SET status=2,revoked_epoch=$2,updated_at=now() WHERE account_id=$1::uuid AND status=1`, uuidText(cert.AccountID), int64(cert.NewEpoch)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE devices d SET account_epoch=$2,revoked_at=COALESCE(d.revoked_at,$3) FROM authorization_devices ad WHERE ad.device_id=d.device_id AND ad.account_id=$1::uuid AND ad.status=2`, uuidText(cert.AccountID), int64(cert.NewEpoch), now); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE accounts SET account_epoch=$2 WHERE account_id=$1::uuid`, uuidText(cert.AccountID), int64(cert.NewEpoch)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE authorization_accounts SET epoch=$2,status=2,updated_at=now() WHERE account_id=$1::uuid`, uuidText(cert.AccountID), int64(cert.NewEpoch)); err != nil {
			return err
		}
	default:
		return ErrInvalidAuthorization
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO authorization_events (auth_digest,kind,account_id,old_epoch,new_epoch,target_device_id,cert_cbor) VALUES ($1,'TRANSITION',$2,$3,$4,$5::uuid,$6)`, digest[:], uuidText(cert.AccountID), int64(cert.OldEpoch), int64(cert.NewEpoch), uuidText(cert.DeviceID), cert.Raw); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *PostgresAuthorizer) ValidateLeaf(ctx context.Context, leaf kt.TransparencyLeafV1) error {
	if err := a.valid(); err != nil {
		return err
	}
	var accountStatus, deviceStatus int
	var accountEpoch, deviceEpoch int64
	var dsk, ddhk []byte
	err := a.db.QueryRowContext(ctx, `SELECT aa.status,aa.epoch,ad.status,ad.authorized_epoch,ad.dsk_pub,ad.ddhk_pub FROM authorization_accounts aa JOIN authorization_devices ad ON ad.account_id=aa.account_id WHERE aa.account_id=$1::uuid AND ad.device_id=$2::uuid`, uuidText(leaf.AccountID), uuidText(leaf.DeviceID)).Scan(&accountStatus, &accountEpoch, &deviceStatus, &deviceEpoch, &dsk, &ddhk)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDeviceNotFound
	}
	if err != nil {
		return err
	}
	if accountStatus != int(AccountActive) {
		return ErrAccountLocked
	}
	if deviceStatus != int(DeviceActive) {
		return ErrDeviceRevoked
	}
	if accountEpoch < 1 || uint64(accountEpoch) != leaf.Epoch || deviceEpoch < 1 || uint64(deviceEpoch) != leaf.Epoch {
		return ErrInvalidEpoch
	}
	if len(dsk) != 32 || len(ddhk) != 32 || !bytes.Equal(dsk, leaf.DSKPub[:]) || !bytes.Equal(ddhk, leaf.DDHKPub[:]) {
		return ErrAuthorizationConflict
	}
	return nil
}

type persistedAccount struct {
	Epoch              uint64
	RecoveryCommitment [32]byte
	RecoveryPub        [32]byte
	Status             AccountStatus
}
type persistedEvent struct{ Digest []byte }

func (a *PostgresAuthorizer) ensureAccountTx(ctx context.Context, tx *sql.Tx, accountID [16]byte, recoveryPub [32]byte) (persistedAccount, error) {
	var epoch int64
	var irc []byte
	err := tx.QueryRowContext(ctx, `SELECT account_epoch,irc FROM accounts WHERE account_id=$1::uuid FOR UPDATE`, uuidText(accountID)).Scan(&epoch, &irc)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedAccount{}, ErrAccountNotFound
	}
	if err != nil {
		return persistedAccount{}, err
	}
	if epoch < 1 || len(irc) != 32 {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	var commitment [32]byte
	copy(commitment[:], irc)
	if !VerifyRecoveryCommitment(commitment, recoveryPub) {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	var rowEpoch int64
	var storedCommitment, storedPub []byte
	var status int
	err = tx.QueryRowContext(ctx, `SELECT epoch,recovery_commitment,recovery_pub,status FROM authorization_accounts WHERE account_id=$1::uuid FOR UPDATE`, uuidText(accountID)).Scan(&rowEpoch, &storedCommitment, &storedPub, &status)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err = tx.ExecContext(ctx, `INSERT INTO authorization_accounts(account_id,epoch,recovery_commitment,recovery_pub,status) VALUES($1::uuid,$2,$3,$4,1)`, uuidText(accountID), epoch, irc, recoveryPub[:]); err != nil {
			return persistedAccount{}, err
		}
		return persistedAccount{Epoch: uint64(epoch), RecoveryCommitment: commitment, RecoveryPub: recoveryPub, Status: AccountActive}, nil
	}
	if err != nil {
		return persistedAccount{}, err
	}
	if rowEpoch != epoch || len(storedCommitment) != 32 || len(storedPub) != 32 || !bytes.Equal(storedCommitment, irc) || !bytes.Equal(storedPub, recoveryPub[:]) {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	if status < 1 || status > 2 {
		return persistedAccount{}, ErrAuthorizationConflict
	}
	var outCommit, outPub [32]byte
	copy(outCommit[:], storedCommitment)
	copy(outPub[:], storedPub)
	return persistedAccount{Epoch: uint64(rowEpoch), RecoveryCommitment: outCommit, RecoveryPub: outPub, Status: AccountStatus(status)}, nil
}
func (a *PostgresAuthorizer) eventByDigestTx(ctx context.Context, tx *sql.Tx, digest [32]byte) (persistedEvent, bool, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT auth_digest FROM authorization_events WHERE auth_digest=$1 FOR UPDATE`, digest[:]).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedEvent{}, false, nil
	}
	if err != nil {
		return persistedEvent{}, false, err
	}
	return persistedEvent{Digest: append([]byte(nil), raw...)}, true, nil
}
func (a *PostgresAuthorizer) logicalEventTx(ctx context.Context, tx *sql.Tx, kind string, accountID [16]byte, oldEpoch, newEpoch uint64, deviceID [16]byte) (persistedEvent, bool, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT auth_digest FROM authorization_events WHERE kind=$1 AND account_id=$2::uuid AND old_epoch=$3 AND new_epoch=$4 AND target_device_id=$5::uuid FOR UPDATE`, kind, uuidText(accountID), int64(oldEpoch), int64(newEpoch), uuidText(deviceID)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedEvent{}, false, nil
	}
	if err != nil {
		return persistedEvent{}, false, err
	}
	return persistedEvent{Digest: append([]byte(nil), raw...)}, true, nil
}
func uuidText(id [16]byte) string {
	var out [36]byte
	hex.Encode(out[0:8], id[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], id[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], id[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], id[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], id[10:16])
	return string(out[:])
}
func CanonicalAuthorizationDigest(raw []byte) [32]byte { return sha256.Sum256(raw) }
