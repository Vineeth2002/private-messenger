package messages

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

var (
	ErrRecipientNotFound            = errors.New("recipient device not found")
	ErrRecipientRevoked             = errors.New("recipient device revoked")
	ErrRecipientEpochMismatch       = errors.New("recipient account epoch mismatch")
	ErrSenderNotFound               = errors.New("sender device not found")
	ErrSenderRevoked                = errors.New("sender device revoked")
	ErrSenderIdentityMismatch       = errors.New("authenticated device does not match envelope sender")
	ErrAuthenticatedAccountInactive = errors.New("authenticated account is inactive")
	ErrAuthenticatedDeviceInactive  = errors.New("authenticated device is inactive or revoked")
	ErrAuthenticatedDeviceNotFound  = errors.New("authenticated device is not registered")
	ErrAuthenticatedEpochMismatch   = errors.New("authenticated device epoch is stale")
	ErrAuthenticatedDeviceState     = errors.New("authenticated device state is inconsistent")
	ErrEnvelopeNotFound             = errors.New("message envelope not found")
)

// AuthenticatedDevice is the identity established by the request-auth layer.
// Delivery methods re-check this state inside the same DB transaction as the
// message operation, closing the gap between middleware authentication and use.
type AuthenticatedDevice struct {
	AccountID [16]byte
	DeviceID  [16]byte
	Epoch     uint64
}

type sqlDB interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type deliveryQueryer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type DeliveryService struct {
	db sqlDB
}

type StoredEnvelope struct {
	EnvelopeID [16]byte
	Raw        []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

func NewDeliveryService(db sqlDB) *DeliveryService {
	return &DeliveryService{db: db}
}

// Enqueue is the legacy relay operation. It verifies sender existence and
// revocation, but does not authenticate the sender's HTTP request. New
// per-device-authenticated routes must call EnqueueAuthenticated instead.
func (s *DeliveryService) Enqueue(
	ctx context.Context,
	rawEnvelope []byte,
	expiresAt time.Time,
) (MessageEnvelopeV1, error) {
	return s.enqueue(ctx, rawEnvelope, expiresAt, nil)
}

// EnqueueAuthenticated binds the envelope sender to the authenticated device
// and revalidates the account/device lifecycle state under DB row locks in the
// same transaction that persists the envelope.
func (s *DeliveryService) EnqueueAuthenticated(
	ctx context.Context,
	rawEnvelope []byte,
	expiresAt time.Time,
	principal AuthenticatedDevice,
) (MessageEnvelopeV1, error) {
	return s.enqueue(ctx, rawEnvelope, expiresAt, &principal)
}

func (s *DeliveryService) enqueue(
	ctx context.Context,
	rawEnvelope []byte,
	expiresAt time.Time,
	principal *AuthenticatedDevice,
) (MessageEnvelopeV1, error) {
	if s == nil || s.db == nil {
		return MessageEnvelopeV1{}, errors.New("message delivery service is not initialized")
	}

	envelope, err := DecodeMessageEnvelopeV1(rawEnvelope)
	if err != nil {
		return MessageEnvelopeV1{}, err
	}
	if principal != nil && envelope.SenderDeviceID != principal.DeviceID {
		return MessageEnvelopeV1{}, ErrSenderIdentityMismatch
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return MessageEnvelopeV1{}, fmt.Errorf("begin message delivery transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if principal != nil {
		if err := lockAuthenticatedDeviceTx(ctx, tx, *principal); err != nil {
			return MessageEnvelopeV1{}, err
		}
	}

	var senderRevoked sql.NullTime
	if err := tx.QueryRowContext(ctx, `
SELECT revoked_at
FROM devices
WHERE device_id=$1::uuid
FOR SHARE
`, uuidText(envelope.SenderDeviceID)).Scan(&senderRevoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MessageEnvelopeV1{}, ErrSenderNotFound
		}
		return MessageEnvelopeV1{}, fmt.Errorf("load sender device: %w", err)
	}
	if senderRevoked.Valid {
		return MessageEnvelopeV1{}, ErrSenderRevoked
	}

	var accountEpoch int64
	var recipientRevoked sql.NullTime
	if err := tx.QueryRowContext(ctx, `
SELECT account_epoch, revoked_at
FROM devices
WHERE device_id=$1::uuid
FOR SHARE
`, uuidText(envelope.RecipientDeviceID)).Scan(&accountEpoch, &recipientRevoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MessageEnvelopeV1{}, ErrRecipientNotFound
		}
		return MessageEnvelopeV1{}, fmt.Errorf("load recipient device: %w", err)
	}
	if recipientRevoked.Valid {
		return MessageEnvelopeV1{}, ErrRecipientRevoked
	}
	if accountEpoch < 1 || accountEpoch > int64(^uint32(0)) || uint32(accountEpoch) != envelope.AccountEpoch {
		return MessageEnvelopeV1{}, ErrRecipientEpochMismatch
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO message_envelopes (
	envelope_id,
	recipient_device,
	envelope_cbor,
	expires_at
)
VALUES ($1::uuid, $2::uuid, $3, $4)
`,
		uuidText(envelope.EnvelopeID),
		uuidText(envelope.RecipientDeviceID),
		envelope.Raw,
		expiresAt,
	)
	if err != nil {
		return MessageEnvelopeV1{}, fmt.Errorf("persist message envelope: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return MessageEnvelopeV1{}, fmt.Errorf("commit message envelope: %w", err)
	}

	return envelope, nil
}

// Fetch returns unacknowledged, unexpired opaque envelopes for a recipient.
// Expired envelopes for that recipient are deleted as opportunistic cleanup.
func (s *DeliveryService) Fetch(ctx context.Context, recipientDeviceID [16]byte, limit int) ([]StoredEnvelope, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("message delivery service is not initialized")
	}
	return fetchEnvelopes(ctx, s.db, recipientDeviceID, limit)
}

// FetchAuthenticated holds the device/account lifecycle rows while it cleans
// and reads the recipient queue. A concurrent revocation or epoch transition
// cannot race the authenticated fetch.
func (s *DeliveryService) FetchAuthenticated(
	ctx context.Context,
	principal AuthenticatedDevice,
	limit int,
) ([]StoredEnvelope, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("message delivery service is not initialized")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin authenticated message fetch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockAuthenticatedDeviceTx(ctx, tx, principal); err != nil {
		return nil, err
	}
	out, err := fetchEnvelopes(ctx, tx, principal.DeviceID, limit)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit authenticated message fetch: %w", err)
	}
	return out, nil
}

func fetchEnvelopes(ctx context.Context, q deliveryQueryer, recipientDeviceID [16]byte, limit int) ([]StoredEnvelope, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if _, err := q.ExecContext(ctx, `
DELETE FROM message_envelopes
WHERE recipient_device=$1::uuid AND expires_at <= now()
`, uuidText(recipientDeviceID)); err != nil {
		return nil, fmt.Errorf("cleanup expired message envelopes: %w", err)
	}

	rows, err := q.QueryContext(ctx, `
SELECT uuid_send(me.envelope_id), me.envelope_cbor, me.created_at, me.expires_at
FROM message_envelopes me
LEFT JOIN delivery_acks da ON da.envelope_id = me.envelope_id
WHERE me.recipient_device=$1::uuid
  AND me.expires_at > now()
  AND da.envelope_id IS NULL
ORDER BY me.created_at, me.envelope_id
LIMIT $2
`, uuidText(recipientDeviceID), limit)
	if err != nil {
		return nil, fmt.Errorf("fetch message envelopes: %w", err)
	}
	defer rows.Close()

	out := make([]StoredEnvelope, 0, limit)
	for rows.Next() {
		var id []byte
		var raw []byte
		var createdAt, expiresAt time.Time
		if err := rows.Scan(&id, &raw, &createdAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("scan message envelope: %w", err)
		}
		if len(id) != 16 {
			return nil, fmt.Errorf("stored envelope_id length=%d", len(id))
		}
		var envelopeID [16]byte
		copy(envelopeID[:], id)
		out = append(out, StoredEnvelope{
			EnvelopeID: envelopeID,
			Raw:        append([]byte(nil), raw...),
			CreatedAt:  createdAt,
			ExpiresAt:  expiresAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate message envelopes: %w", err)
	}
	return out, nil
}

// Ack records delivery for an envelope belonging to the recipient. It is
// idempotent when the same envelope has already been acknowledged.
func (s *DeliveryService) Ack(ctx context.Context, recipientDeviceID [16]byte, envelopeID [16]byte) error {
	if s == nil || s.db == nil {
		return errors.New("message delivery service is not initialized")
	}
	return ackEnvelope(ctx, s.db, recipientDeviceID, envelopeID)
}

// AckAuthenticated revalidates and locks the authenticated recipient identity
// in the same transaction that records the acknowledgement.
func (s *DeliveryService) AckAuthenticated(
	ctx context.Context,
	principal AuthenticatedDevice,
	envelopeID [16]byte,
) error {
	if s == nil || s.db == nil {
		return errors.New("message delivery service is not initialized")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin authenticated message ack: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockAuthenticatedDeviceTx(ctx, tx, principal); err != nil {
		return err
	}
	if err := ackEnvelope(ctx, tx, principal.DeviceID, envelopeID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit authenticated message ack: %w", err)
	}
	return nil
}

func ackEnvelope(ctx context.Context, q deliveryQueryer, recipientDeviceID, envelopeID [16]byte) error {
	var exists bool
	if err := q.QueryRowContext(ctx, `
SELECT EXISTS (
	SELECT 1
	FROM message_envelopes
	WHERE envelope_id=$1::uuid
	  AND recipient_device=$2::uuid
	  AND expires_at > now()
)
`, uuidText(envelopeID), uuidText(recipientDeviceID)).Scan(&exists); err != nil {
		return fmt.Errorf("check message envelope for ack: %w", err)
	}
	if !exists {
		return ErrEnvelopeNotFound
	}
	if _, err := q.ExecContext(ctx, `
INSERT INTO delivery_acks (envelope_id)
VALUES ($1::uuid)
ON CONFLICT (envelope_id) DO NOTHING
`, uuidText(envelopeID)); err != nil {
		return fmt.Errorf("ack message envelope: %w", err)
	}
	return nil
}

// lockAuthenticatedDeviceTx uses the same explicit lock order as
// PostgresAuthorizer.Transition: accounts -> authorization_accounts ->
// authorization_devices -> devices. Separate SELECTs make the acquisition
// order independent of PostgreSQL's join plan.
func lockAuthenticatedDeviceTx(ctx context.Context, tx *sql.Tx, principal AuthenticatedDevice) error {
	if principal.AccountID == [16]byte{} || principal.DeviceID == [16]byte{} || principal.Epoch == 0 || principal.Epoch > uint64(^uint32(0)) {
		return ErrAuthenticatedEpochMismatch
	}

	var accountEpoch int64
	err := tx.QueryRowContext(ctx, `
SELECT account_epoch
FROM accounts
WHERE account_id = $1::uuid
FOR SHARE
`, uuidText(principal.AccountID)).Scan(&accountEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthenticatedDeviceNotFound
	}
	if err != nil {
		return fmt.Errorf("lock authenticated account row: %w", err)
	}

	var accountStatus int
	var authorizationEpoch int64
	err = tx.QueryRowContext(ctx, `
SELECT status, epoch
FROM authorization_accounts
WHERE account_id = $1::uuid
FOR SHARE
`, uuidText(principal.AccountID)).Scan(&accountStatus, &authorizationEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthenticatedDeviceNotFound
	}
	if err != nil {
		return fmt.Errorf("lock authenticated authorization account row: %w", err)
	}

	var deviceStatus int
	var authorizedEpoch int64
	var authorizationDSK, authorizationDDHK []byte
	err = tx.QueryRowContext(ctx, `
SELECT status, authorized_epoch, dsk_pub, ddhk_pub
FROM authorization_devices
WHERE account_id = $1::uuid AND device_id = $2::uuid
FOR SHARE
`, uuidText(principal.AccountID), uuidText(principal.DeviceID)).Scan(
		&deviceStatus, &authorizedEpoch, &authorizationDSK, &authorizationDDHK,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthenticatedDeviceNotFound
	}
	if err != nil {
		return fmt.Errorf("lock authenticated authorization device row: %w", err)
	}

	var deviceEpoch int64
	var deviceDSK, deviceDDHK []byte
	var revoked bool
	err = tx.QueryRowContext(ctx, `
SELECT account_epoch, dsk_pub, ddhk_pub, revoked_at IS NOT NULL
FROM devices
WHERE account_id = $1::uuid AND device_id = $2::uuid
FOR SHARE
`, uuidText(principal.AccountID), uuidText(principal.DeviceID)).Scan(
		&deviceEpoch, &deviceDSK, &deviceDDHK, &revoked,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthenticatedDeviceNotFound
	}
	if err != nil {
		return fmt.Errorf("lock authenticated device row: %w", err)
	}

	if accountStatus != int(authorization.AccountActive) {
		return ErrAuthenticatedAccountInactive
	}
	if deviceStatus != int(authorization.DeviceActive) || revoked {
		return ErrAuthenticatedDeviceInactive
	}
	if accountEpoch < 1 || accountEpoch > int64(^uint32(0)) ||
		authorizationEpoch < 1 || authorizationEpoch > int64(^uint32(0)) ||
		authorizedEpoch < 1 || authorizedEpoch > int64(^uint32(0)) ||
		deviceEpoch < 1 || deviceEpoch > int64(^uint32(0)) ||
		uint64(accountEpoch) != principal.Epoch || uint64(authorizationEpoch) != principal.Epoch ||
		uint64(authorizedEpoch) != principal.Epoch || uint64(deviceEpoch) != principal.Epoch {
		return ErrAuthenticatedEpochMismatch
	}
	if len(authorizationDSK) != 32 || len(deviceDSK) != 32 ||
		len(authorizationDDHK) != 32 || len(deviceDDHK) != 32 ||
		!equalBytes(authorizationDSK, deviceDSK) || !equalBytes(authorizationDDHK, deviceDDHK) {
		return ErrAuthenticatedDeviceState
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
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

func UUIDText(id [16]byte) string {
	return uuidText(id)
}
