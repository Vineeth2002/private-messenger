package devices

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrNotFound = errors.New("device directory: device not found")
)

type Device struct {
	AccountID    [16]byte
	DeviceID     [16]byte
	AccountEpoch uint64
	DSKPub       [32]byte
	DDHKPub      [32]byte
	PushPub      []byte
	Revoked      bool
	CreatedAt    time.Time
}

type DeviceCertificate struct {
	DeviceID  [16]byte
	CertCBOR  []byte
	CreatedAt time.Time
}

type SignedPrekey struct {
	DeviceID  [16]byte
	SPKID     int64
	SPKPub    [32]byte
	Signature [64]byte
}

// Directory exposes only persistence-backed device-directory data. It does not
// define enrollment, revocation, recovery, or HTTP authorization semantics.
type Directory interface {
	Get(ctx context.Context, accountID, deviceID [16]byte) (Device, error)
	ListActive(ctx context.Context, accountID [16]byte) ([]Device, error)
	ListCertificates(ctx context.Context, deviceID [16]byte) ([]DeviceCertificate, error)
	ListSignedPrekeys(ctx context.Context, deviceID [16]byte) ([]SignedPrekey, error)
}

type PostgresDirectory struct {
	db interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	}
}

func NewPostgresDirectory(db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) *PostgresDirectory {
	return &PostgresDirectory{db: db}
}

const selectDeviceSQL = `
SELECT account_id::text,
       device_id::text,
       account_epoch,
       dsk_pub,
       ddhk_pub,
       push_pub,
       revoked_at IS NOT NULL,
       created_at
FROM devices
WHERE account_id = $1::uuid
  AND device_id = $2::uuid`

const selectActiveDevicesSQL = `
SELECT account_id::text,
       device_id::text,
       account_epoch,
       dsk_pub,
       ddhk_pub,
       push_pub,
       revoked_at IS NOT NULL,
       created_at
FROM devices
WHERE account_id = $1::uuid
  AND revoked_at IS NULL
ORDER BY device_id ASC`

const selectDeviceCertificatesSQL = `
SELECT device_id::text,
       cert_cbor,
       created_at
FROM device_certificates
WHERE device_id = $1::uuid
ORDER BY created_at ASC`

const selectSignedPrekeysSQL = `
SELECT device_id::text,
       spk_id,
       spk_pub,
       signature
FROM signed_prekeys
WHERE device_id = $1::uuid
ORDER BY spk_id ASC`

func (d *PostgresDirectory) Get(ctx context.Context, accountID, deviceID [16]byte) (Device, error) {
	if d == nil || d.db == nil {
		return Device{}, errors.New("nil device directory")
	}
	var accountText, deviceText string
	var epoch int64
	var dsk, ddhk, push []byte
	var revoked bool
	var createdAt time.Time
	err := d.db.QueryRowContext(ctx, selectDeviceSQL, uuidText(accountID), uuidText(deviceID)).Scan(
		&accountText, &deviceText, &epoch, &dsk, &ddhk, &push, &revoked, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	return decodeDevice(accountText, deviceText, epoch, dsk, ddhk, push, revoked, createdAt)
}

func (d *PostgresDirectory) ListActive(ctx context.Context, accountID [16]byte) ([]Device, error) {
	if d == nil || d.db == nil {
		return nil, errors.New("nil device directory")
	}
	rows, err := d.db.QueryContext(ctx, selectActiveDevicesSQL, uuidText(accountID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var accountText, deviceText string
		var epoch int64
		var dsk, ddhk, push []byte
		var revoked bool
		var createdAt time.Time
		if err := rows.Scan(&accountText, &deviceText, &epoch, &dsk, &ddhk, &push, &revoked, &createdAt); err != nil {
			return nil, err
		}
		device, err := decodeDevice(accountText, deviceText, epoch, dsk, ddhk, push, revoked, createdAt)
		if err != nil {
			return nil, err
		}
		if device.Revoked {
			return nil, errors.New("active device query returned revoked device")
		}
		out = append(out, device)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *PostgresDirectory) ListCertificates(ctx context.Context, deviceID [16]byte) ([]DeviceCertificate, error) {
	if d == nil || d.db == nil {
		return nil, errors.New("nil device directory")
	}
	rows, err := d.db.QueryContext(ctx, selectDeviceCertificatesSQL, uuidText(deviceID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DeviceCertificate
	for rows.Next() {
		var deviceText string
		var cert []byte
		var createdAt time.Time
		if err := rows.Scan(&deviceText, &cert, &createdAt); err != nil {
			return nil, err
		}
		certificate, err := decodeCertificate(deviceText, cert, createdAt, deviceID)
		if err != nil {
			return nil, err
		}
		out = append(out, certificate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *PostgresDirectory) ListSignedPrekeys(ctx context.Context, deviceID [16]byte) ([]SignedPrekey, error) {
	if d == nil || d.db == nil {
		return nil, errors.New("nil device directory")
	}
	rows, err := d.db.QueryContext(ctx, selectSignedPrekeysSQL, uuidText(deviceID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SignedPrekey
	for rows.Next() {
		var deviceText string
		var spkID int64
		var spkPub, signature []byte
		if err := rows.Scan(&deviceText, &spkID, &spkPub, &signature); err != nil {
			return nil, err
		}
		prekey, err := decodeSignedPrekey(deviceText, spkID, spkPub, signature, deviceID)
		if err != nil {
			return nil, err
		}
		out = append(out, prekey)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeDevice(accountText, deviceText string, epoch int64, dsk, ddhk, push []byte, revoked bool, createdAt time.Time) (Device, error) {
	if epoch < 1 {
		return Device{}, errors.New("persisted device epoch must be >= 1")
	}
	if len(dsk) != 32 || len(ddhk) != 32 {
		return Device{}, errors.New("invalid persisted device public key length")
	}
	accountID, err := parseUUIDText(accountText)
	if err != nil {
		return Device{}, fmt.Errorf("invalid persisted account id: %w", err)
	}
	deviceID, err := parseUUIDText(deviceText)
	if err != nil {
		return Device{}, fmt.Errorf("invalid persisted device id: %w", err)
	}
	pushCopy := append([]byte(nil), push...)
	var out Device
	out.AccountID = accountID
	out.DeviceID = deviceID
	out.AccountEpoch = uint64(epoch)
	copy(out.DSKPub[:], dsk)
	copy(out.DDHKPub[:], ddhk)
	out.PushPub = pushCopy
	out.Revoked = revoked
	out.CreatedAt = createdAt
	return out, nil
}

func decodeCertificate(deviceText string, cert []byte, createdAt time.Time, expectedDeviceID [16]byte) (DeviceCertificate, error) {
	deviceID, err := parseUUIDText(deviceText)
	if err != nil {
		return DeviceCertificate{}, fmt.Errorf("invalid persisted device id: %w", err)
	}
	if deviceID != expectedDeviceID {
		return DeviceCertificate{}, errors.New("persisted certificate device id mismatch")
	}
	if len(cert) == 0 {
		return DeviceCertificate{}, errors.New("empty persisted device certificate")
	}
	return DeviceCertificate{
		DeviceID:  deviceID,
		CertCBOR:  append([]byte(nil), cert...),
		CreatedAt: createdAt,
	}, nil
}

func decodeSignedPrekey(deviceText string, spkID int64, spkPub, signature []byte, expectedDeviceID [16]byte) (SignedPrekey, error) {
	deviceID, err := parseUUIDText(deviceText)
	if err != nil {
		return SignedPrekey{}, fmt.Errorf("invalid persisted device id: %w", err)
	}
	if deviceID != expectedDeviceID {
		return SignedPrekey{}, errors.New("persisted signed-prekey device id mismatch")
	}
	if len(spkPub) != 32 || len(signature) != 64 {
		return SignedPrekey{}, errors.New("invalid persisted signed-prekey lengths")
	}
	var out SignedPrekey
	out.DeviceID = deviceID
	out.SPKID = spkID
	copy(out.SPKPub[:], spkPub)
	copy(out.Signature[:], signature)
	return out, nil
}

func uuidText(id [16]byte) string {
	return fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		id[0], id[1], id[2], id[3],
		id[4], id[5],
		id[6], id[7],
		id[8], id[9],
		id[10], id[11], id[12], id[13], id[14], id[15],
	)
}

func parseUUIDText(s string) ([16]byte, error) {
	var out [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return out, errors.New("invalid UUID text")
	}
	hexDigit := func(b byte) (byte, bool) {
		switch {
		case b >= '0' && b <= '9':
			return b - '0', true
		case b >= 'a' && b <= 'f':
			return b - 'a' + 10, true
		case b >= 'A' && b <= 'F':
			return b - 'A' + 10, true
		default:
			return 0, false
		}
	}
	src := 0
	for i := 0; i < len(out); i++ {
		for src < len(s) && s[src] == '-' {
			src++
		}
		if src+1 >= len(s) {
			return out, errors.New("invalid UUID hex")
		}
		hi, ok := hexDigit(s[src])
		if !ok {
			return out, errors.New("invalid UUID hex")
		}
		src++
		lo, ok := hexDigit(s[src])
		if !ok {
			return out, errors.New("invalid UUID hex")
		}
		src++
		out[i] = hi<<4 | lo
	}
	return out, nil
}
