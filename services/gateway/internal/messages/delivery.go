package messages

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	ErrRecipientNotFound      = errors.New("recipient device not found")
	ErrRecipientRevoked       = errors.New("recipient device revoked")
	ErrRecipientEpochMismatch = errors.New("recipient account epoch mismatch")
	ErrSenderNotFound         = errors.New("sender device not found")
	ErrSenderRevoked          = errors.New("sender device revoked")
	ErrEnvelopeNotFound       = errors.New("message envelope not found")
)

type sqlDB interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
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

// Enqueue validates the opaque envelope and persists it for the recipient.
// The gateway never decrypts the envelope.
//
// The current repository contract does not define a sender-session protocol,
// so this method only verifies that the sender device exists and is not
// revoked. It does not claim cryptographic sender authentication.
func (s *DeliveryService) Enqueue(
	ctx context.Context,
	rawEnvelope []byte,
	expiresAt time.Time,
) (MessageEnvelopeV1, error) {
	if s == nil || s.db == nil {
		return MessageEnvelopeV1{}, errors.New("message delivery service is not initialized")
	}

	envelope, err := DecodeMessageEnvelopeV1(rawEnvelope)
	if err != nil {
		return MessageEnvelopeV1{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return MessageEnvelopeV1{}, fmt.Errorf("begin message delivery transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

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
	if accountEpoch < 0 || accountEpoch > int64(^uint32(0)) || uint32(accountEpoch) != envelope.AccountEpoch {
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
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	if _, err := s.db.ExecContext(ctx, `
DELETE FROM message_envelopes
WHERE recipient_device=$1::uuid AND expires_at <= now()
`, uuidText(recipientDeviceID)); err != nil {
		return nil, fmt.Errorf("cleanup expired message envelopes: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
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

	var exists bool
	if err := s.db.QueryRowContext(ctx, `
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

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO delivery_acks (envelope_id)
VALUES ($1::uuid)
ON CONFLICT (envelope_id) DO NOTHING
`, uuidText(envelopeID)); err != nil {
		return fmt.Errorf("ack message envelope: %w", err)
	}
	return nil
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
