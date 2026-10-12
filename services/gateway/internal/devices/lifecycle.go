package devices

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrAccountNotFound = errors.New("device directory: account not found")
	ErrDeviceExists    = errors.New("device directory: device already exists")
)

// DeviceProvisioner persists an already-authorized device state into the
// existing devices, device_certificates, and signed_prekeys tables. It does
// not decide who is authorized to request enrollment or revocation.
type DeviceProvisioner struct {
	db interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	}
}

func NewPostgresDeviceProvisioner(db interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}) *DeviceProvisioner {
	return &DeviceProvisioner{db: db}
}

// Enroll persists one complete public device state. The supplied account epoch
// must equal the current account epoch. Authorization is deliberately outside
// this persistence boundary.
func (p *DeviceProvisioner) Enroll(ctx context.Context, device Device, certificate []byte, prekeys []SignedPrekey) error {
	if p == nil || p.db == nil {
		return errors.New("nil device provisioner")
	}
	if device.AccountEpoch < 1 {
		return errors.New("device epoch must be >= 1")
	}
	if device.AccountID == [16]byte{} || device.DeviceID == [16]byte{} {
		return errors.New("device account and device IDs are required")
	}
	if device.Revoked {
		return errors.New("cannot enroll a revoked device")
	}
	if len(certificate) == 0 {
		return errors.New("device certificate is required")
	}
	for _, prekey := range prekeys {
		if prekey.DeviceID != device.DeviceID {
			return errors.New("signed prekey device ID mismatch")
		}
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var accountEpoch int64
	if err := tx.QueryRowContext(ctx, `
SELECT account_epoch FROM accounts WHERE account_id = $1::uuid FOR UPDATE
`, uuidText(device.AccountID)).Scan(&accountEpoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAccountNotFound
		}
		return err
	}
	if accountEpoch < 1 {
		return errors.New("persisted account epoch must be >= 1")
	}
	if uint64(accountEpoch) != device.AccountEpoch {
		return fmt.Errorf("device epoch %d does not match account epoch %d", device.AccountEpoch, accountEpoch)
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO devices (
    device_id, account_id, account_epoch, dsk_pub, ddhk_pub, push_pub, revoked_at
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, NULL)
`,
		uuidText(device.DeviceID),
		uuidText(device.AccountID),
		int64(device.AccountEpoch),
		device.DSKPub[:],
		device.DDHKPub[:],
		optionalBytes(device.PushPub),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDeviceExists
		}
		return err
	}

	if _, err = tx.ExecContext(ctx, `
INSERT INTO device_certificates (device_id, cert_cbor)
VALUES ($1::uuid, $2)
`, uuidText(device.DeviceID), certificate); err != nil {
		return err
	}

	for _, prekey := range prekeys {
		if _, err = tx.ExecContext(ctx, `
INSERT INTO signed_prekeys (device_id, spk_id, spk_pub, signature)
VALUES ($1::uuid, $2, $3, $4)
`, uuidText(device.DeviceID), prekey.SPKID, prekey.SPKPub[:], prekey.Signature[:]); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// Revoke marks an existing device revoked. It does not perform account epoch
// authorization; that policy must be supplied by the caller before invoking
// this persistence operation.
func (p *DeviceProvisioner) Revoke(ctx context.Context, accountID, deviceID [16]byte, revokedAt time.Time) error {
	if p == nil || p.db == nil {
		return errors.New("nil device provisioner")
	}
	if accountID == [16]byte{} || deviceID == [16]byte{} {
		return errors.New("account and device IDs are required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var exists bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM devices WHERE account_id = $1::uuid AND device_id = $2::uuid
)
`, uuidText(accountID), uuidText(deviceID)).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE devices
SET revoked_at = COALESCE(revoked_at, $3)
WHERE account_id = $1::uuid AND device_id = $2::uuid
`, uuidText(accountID), uuidText(deviceID), revokedAt.UTC()); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func optionalBytes(v []byte) any {
	if len(v) == 0 {
		return nil
	}
	return v
}

// PostgreSQL reports uniqueness conflicts through SQLSTATE 23505. Keep this
// helper dependency-free; callers receive the generic database error otherwise.
func isUniqueViolation(err error) bool {
	type sqlStater interface{ SQLState() string }
	var state sqlStater
	if errors.As(err, &state) {
		return state.SQLState() == "23505"
	}
	return false
}
