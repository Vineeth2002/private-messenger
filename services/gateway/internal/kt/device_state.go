package kt

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var (
	ErrDeviceStateNotFound = errors.New("kt: device state not found")
	ErrDeviceRevoked       = errors.New("kt: device is revoked")
	ErrDeviceStateMismatch = errors.New("kt: transparency leaf does not match device state")
)

// DeviceState is the persisted public device state needed to bind a
// TransparencyLeafV1 to the existing devices table.
//
// This type intentionally contains no authorization semantics: it only
// represents the already-persisted device record.
type DeviceState struct {
	AccountID    [16]byte
	DeviceID     [16]byte
	AccountEpoch uint64
	DSKPub       [32]byte
	DDHKPub      [32]byte
	Revoked      bool
}

const selectDeviceStateByIDSQL = `
SELECT account_id::text,
       device_id::text,
       account_epoch,
       dsk_pub,
       ddhk_pub,
       revoked_at IS NOT NULL
FROM devices
WHERE account_id = $1::uuid
  AND device_id = $2::uuid`

type DeviceStateReader interface {
	DeviceState(ctx context.Context, accountID, deviceID [16]byte) (DeviceState, error)
}

// PostgresDeviceStateReader reads the existing devices table. It does not
// create or alter device lifecycle state.
type PostgresDeviceStateReader struct {
	db interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}
}

func NewPostgresDeviceStateReader(db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) *PostgresDeviceStateReader {
	return &PostgresDeviceStateReader{db: db}
}

func (s *PostgresDeviceStateReader) DeviceState(ctx context.Context, accountID, deviceID [16]byte) (DeviceState, error) {
	if s == nil || s.db == nil {
		return DeviceState{}, errors.New("nil device state reader")
	}

	var accountText, deviceText string
	var epoch int64
	var dsk, ddhk []byte
	var revoked bool

	if err := s.db.QueryRowContext(
		ctx,
		selectDeviceStateByIDSQL,
		uuidText(accountID),
		uuidText(deviceID),
	).Scan(&accountText, &deviceText, &epoch, &dsk, &ddhk, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeviceState{}, ErrDeviceStateNotFound
		}
		return DeviceState{}, err
	}

	if epoch < 1 || epoch > int64(^uint32(0)) {
		return DeviceState{}, errors.New("persisted device epoch is outside the V1 range")
	}
	if len(dsk) != 32 || len(ddhk) != 32 {
		return DeviceState{}, errors.New("invalid persisted device public key length")
	}

	storedAccount, err := parseUUIDText(accountText)
	if err != nil {
		return DeviceState{}, fmt.Errorf("invalid persisted account id: %w", err)
	}
	storedDevice, err := parseUUIDText(deviceText)
	if err != nil {
		return DeviceState{}, fmt.Errorf("invalid persisted device id: %w", err)
	}

	var out DeviceState
	out.AccountID = storedAccount
	out.DeviceID = storedDevice
	out.AccountEpoch = uint64(epoch)
	copy(out.DSKPub[:], dsk)
	copy(out.DDHKPub[:], ddhk)
	out.Revoked = revoked
	return out, nil
}

// ValidateTransparencyLeafAgainstDevice checks that the KT leaf exactly
// reflects the existing persisted device public state. It does not decide
// whether the device was authorized to enter that state.
func ValidateTransparencyLeafAgainstDevice(ctx context.Context, reader DeviceStateReader, leaf TransparencyLeafV1) error {
	if reader == nil {
		return errors.New("nil device state reader")
	}

	device, err := reader.DeviceState(ctx, leaf.AccountID, leaf.DeviceID)
	if err != nil {
		return err
	}
	if device.Revoked {
		return ErrDeviceRevoked
	}
	if leaf.Epoch == 0 || leaf.Epoch > uint64(^uint32(0)) ||
		device.AccountEpoch == 0 || device.AccountEpoch > uint64(^uint32(0)) ||
		device.AccountID != leaf.AccountID ||
		device.DeviceID != leaf.DeviceID ||
		device.AccountEpoch != leaf.Epoch ||
		device.DSKPub != leaf.DSKPub ||
		device.DDHKPub != leaf.DDHKPub {
		return ErrDeviceStateMismatch
	}
	return nil
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
	const canonicalLen = 36
	if len(s) != canonicalLen ||
		s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
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
		for src < canonicalLen && s[src] == '-' {
			src++
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
