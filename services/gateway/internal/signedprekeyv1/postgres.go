package signedprekeyv1

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/deviceauth"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

var (
	ErrStoreUnavailable     = errors.New("signed prekey v1: PostgreSQL store unavailable")
	ErrPrincipalMismatch    = errors.New("signed prekey v1: request principal does not match candidate")
	ErrAccountInactive      = errors.New("signed prekey v1: account is inactive")
	ErrDeviceInactive       = errors.New("signed prekey v1: device is inactive or revoked")
	ErrEpochMismatch        = errors.New("signed prekey v1: epoch mismatch")
	ErrDeviceStateMismatch  = errors.New("signed prekey v1: persisted device identity mismatch")
	ErrPendingRecovery      = errors.New("signed prekey v1: account recovery is pending")
	ErrTransparencyMissing  = errors.New("signed prekey v1: current transparency leaf is missing")
	ErrTransparencyMismatch = errors.New("signed prekey v1: candidate does not match current transparency leaf")
	ErrSPKConflict          = errors.New("signed prekey v1: SPK ID already exists with different content")
	ErrSPKNotPublished      = errors.New("signed prekey v1: current transparency SPK has no persisted signed-prekey record")
	ErrInvalidCandidate     = errors.New("signed prekey v1: invalid candidate object")
)

// PostgresStore persists immutable candidate SPK records. It is deliberately
// candidate-only: there is no expiry/rotation policy in this API yet. Reads
// return only the record whose SPK public key matches the current KT leaf.
type PostgresStore struct{ db *sql.DB }

func NewPostgresStore(db *sql.DB) *PostgresStore { return &PostgresStore{db: db} }

func (s *PostgresStore) Publish(ctx context.Context, principal deviceauth.Principal, raw []byte) error {
	if s == nil || s.db == nil {
		return ErrStoreUnavailable
	}
	object, err := Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCandidate, err)
	}
	if object.AccountID != principal.AccountID || object.DeviceID != principal.DeviceID {
		return ErrPrincipalMismatch
	}
	if principal.Epoch == 0 || principal.Epoch > MaxEpoch || uint64(object.AccountEpoch) != principal.Epoch {
		return ErrEpochMismatch
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin signed-prekey publication: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Lock order matches deviceauth and authorization lifecycle operations:
	// accounts -> authorization_accounts -> authorization_devices -> devices.
	var accountEpoch int64
	if err := tx.QueryRowContext(ctx, `
SELECT account_epoch FROM accounts WHERE account_id = $1::uuid FOR SHARE
`, uuidText(principal.AccountID)).Scan(&accountEpoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAccountInactive
		}
		return err
	}

	var accountStatus int
	var authorizationEpoch int64
	if err := tx.QueryRowContext(ctx, `
SELECT status, epoch FROM authorization_accounts WHERE account_id = $1::uuid FOR SHARE
`, uuidText(principal.AccountID)).Scan(&accountStatus, &authorizationEpoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAccountInactive
		}
		return err
	}
	if accountStatus != int(authorization.AccountActive) {
		return ErrAccountInactive
	}
	if accountEpoch < 1 || accountEpoch > int64(MaxEpoch) || authorizationEpoch != accountEpoch || uint64(accountEpoch) != principal.Epoch {
		return ErrEpochMismatch
	}

	var deviceStatus int
	var authorizedEpoch int64
	var authorizationDSK, authorizationDDHK []byte
	if err := tx.QueryRowContext(ctx, `
SELECT status, authorized_epoch, dsk_pub, ddhk_pub
FROM authorization_devices
WHERE account_id = $1::uuid AND device_id = $2::uuid
FOR SHARE
`, uuidText(principal.AccountID), uuidText(principal.DeviceID)).Scan(
		&deviceStatus, &authorizedEpoch, &authorizationDSK, &authorizationDDHK,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceInactive
		}
		return err
	}
	if deviceStatus != int(authorization.DeviceActive) {
		return ErrDeviceInactive
	}
	if authorizedEpoch != accountEpoch || authorizedEpoch < 1 || authorizedEpoch > int64(MaxEpoch) {
		return ErrEpochMismatch
	}

	var deviceEpoch int64
	var deviceDSK, deviceDDHK []byte
	var revoked bool
	if err := tx.QueryRowContext(ctx, `
SELECT account_epoch, dsk_pub, ddhk_pub, revoked_at IS NOT NULL
FROM devices
WHERE account_id = $1::uuid AND device_id = $2::uuid
FOR UPDATE
`, uuidText(principal.AccountID), uuidText(principal.DeviceID)).Scan(
		&deviceEpoch, &deviceDSK, &deviceDDHK, &revoked,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceInactive
		}
		return err
	}
	if revoked {
		return ErrDeviceInactive
	}
	if deviceEpoch != accountEpoch || len(deviceDSK) != 32 || len(deviceDDHK) != 32 ||
		len(authorizationDSK) != 32 || len(authorizationDDHK) != 32 ||
		!bytes.Equal(deviceDSK, authorizationDSK) || !bytes.Equal(deviceDDHK, authorizationDDHK) {
		return ErrDeviceStateMismatch
	}
	if err := VerifyRecordFields(object.AccountID, uint64(object.AccountEpoch), object.DeviceID, int64(object.SPKID), object.SPKPub[:], object.Signature[:], deviceDSK); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCandidate, err)
	}

	var pending bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM account_recovery_requests
    WHERE account_id = $1::uuid AND status = 'PENDING'
)
`, uuidText(principal.AccountID)).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrPendingRecovery
	}

	// The current KT leaf commits to the device's SPK. Publication is accepted
	// only for the exact SPK currently represented by that DSK-signed leaf.
	smtKey := kt.SMTKey(principal.AccountID, principal.DeviceID)
	var leafRaw []byte
	if err := tx.QueryRowContext(ctx, `
SELECT leaf_cbor FROM transparency_current_state WHERE smt_key = $1 FOR SHARE
`, smtKey[:]).Scan(&leafRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTransparencyMissing
		}
		return err
	}
	leaf, _, err := kt.VerifyTransparencyLeafV1(leafRaw)
	if err != nil {
		return fmt.Errorf("verify current transparency leaf: %w", err)
	}
	if leaf.AccountID != principal.AccountID || leaf.DeviceID != principal.DeviceID ||
		leaf.Epoch != principal.Epoch || !bytes.Equal(leaf.DSKPub[:], deviceDSK) ||
		!bytes.Equal(leaf.DDHKPub[:], deviceDDHK) || leaf.SPKPub != object.SPKPub {
		return ErrTransparencyMismatch
	}

	// One SPK public key has one stable ID for a device. Reusing the same key
	// under another ID adds ambiguity without adding any security value.
	var existingID int64
	err = tx.QueryRowContext(ctx, `
SELECT spk_id FROM signed_prekeys
WHERE device_id = $1::uuid AND spk_pub = $2
LIMIT 1 FOR SHARE
`, uuidText(principal.DeviceID), object.SPKPub[:]).Scan(&existingID)
	if err == nil && existingID != int64(object.SPKID) {
		return ErrSPKConflict
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	result, err := tx.ExecContext(ctx, `
INSERT INTO signed_prekeys (device_id, spk_id, spk_pub, signature)
VALUES ($1::uuid, $2, $3, $4)
ON CONFLICT (device_id, spk_id) DO NOTHING
`, uuidText(principal.DeviceID), int64(object.SPKID), object.SPKPub[:], object.Signature[:])
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		var storedPub, storedSignature []byte
		if err := tx.QueryRowContext(ctx, `
SELECT spk_pub, signature FROM signed_prekeys
WHERE device_id = $1::uuid AND spk_id = $2 FOR SHARE
`, uuidText(principal.DeviceID), int64(object.SPKID)).Scan(&storedPub, &storedSignature); err != nil {
			return err
		}
		if !bytes.Equal(storedPub, object.SPKPub[:]) || !bytes.Equal(storedSignature, object.Signature[:]) {
			return ErrSPKConflict
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// List returns only the signed prekey bound by the current DSK-signed KT leaf.
// It deliberately filters out historical rows before validating the persisted
// record. A repeatable-read transaction keeps device authorization, the KT
// leaf, and the matching signed-prekey row on one consistent database snapshot.
// Inactive or unpublished devices return no keys; a KT leaf with no matching
// persisted signed-prekey row is treated as a consistency failure.
func (s *PostgresStore) List(ctx context.Context, accountID, deviceID [16]byte) ([][]byte, error) {
	if s == nil || s.db == nil {
		return nil, ErrStoreUnavailable
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	smtKey := kt.SMTKey(accountID, deviceID)
	var epoch int64
	var dsk, ddhk, leafRaw []byte
	err = tx.QueryRowContext(ctx, `
SELECT a.account_epoch, d.dsk_pub, d.ddhk_pub, t.leaf_cbor
FROM accounts AS a
JOIN devices AS d ON d.account_id = a.account_id
JOIN authorization_accounts AS aa ON aa.account_id = a.account_id
JOIN authorization_devices AS ad ON ad.account_id = d.account_id AND ad.device_id = d.device_id
JOIN transparency_current_state AS t ON t.smt_key = $3
WHERE a.account_id = $1::uuid AND d.device_id = $2::uuid
  AND d.revoked_at IS NULL AND d.account_epoch = a.account_epoch
  AND aa.status = $4 AND aa.epoch = a.account_epoch
  AND ad.status = $5 AND ad.authorized_epoch = a.account_epoch
  AND ad.dsk_pub = d.dsk_pub AND ad.ddhk_pub = d.ddhk_pub
  AND NOT EXISTS (
      SELECT 1 FROM account_recovery_requests ar
      WHERE ar.account_id = a.account_id AND ar.status = 'PENDING'
  )
`, uuidText(accountID), uuidText(deviceID), smtKey[:], int(authorization.AccountActive), int(authorization.DeviceActive)).Scan(
		&epoch, &dsk, &ddhk, &leafRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return [][]byte{}, nil
	}
	if err != nil {
		return nil, err
	}
	if epoch < 1 || epoch > int64(MaxEpoch) || len(dsk) != 32 || len(ddhk) != 32 {
		return nil, errors.New("invalid persisted device state for signed-prekey response")
	}
	leaf, _, err := kt.VerifyTransparencyLeafV1(leafRaw)
	if err != nil {
		return nil, fmt.Errorf("verify current transparency leaf: %w", err)
	}
	if leaf.AccountID != accountID || leaf.DeviceID != deviceID || leaf.Epoch != uint64(epoch) ||
		!bytes.Equal(leaf.DSKPub[:], dsk) || !bytes.Equal(leaf.DDHKPub[:], ddhk) {
		return nil, ErrTransparencyMismatch
	}

	// Old SPKs remain in the legacy table after rotation. Select only the
	// public key committed by the current KT leaf; otherwise a historical row
	// would make every lookup fail even when the new key had been published.
	rows, err := tx.QueryContext(ctx, `
SELECT spk_id, spk_pub, signature
FROM signed_prekeys
WHERE device_id = $1::uuid AND spk_pub = $2
ORDER BY spk_id ASC
`, uuidText(deviceID), leaf.SPKPub[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out [][]byte
	for rows.Next() {
		var spkID int64
		var spkPub, signature []byte
		if err := rows.Scan(&spkID, &spkPub, &signature); err != nil {
			return nil, err
		}
		if err := VerifyRecordFields(accountID, uint64(epoch), deviceID, spkID, spkPub, signature, dsk); err != nil {
			return nil, fmt.Errorf("verify persisted signed-prekey record: %w", err)
		}
		raw, err := EncodeRecord(accountID, uint64(epoch), deviceID, uint64(spkID), spkPub, signature)
		if err != nil {
			return nil, err
		}
		if len(out) != 0 {
			return nil, ErrSPKConflict
		}
		out = append(out, raw)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrSPKNotPublished
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func uuidText(id [16]byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7],
		id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15])
}
