package deviceauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
)

var (
	ErrRequestReplay       = errors.New("device auth: request nonce already consumed")
	ErrAccountInactive     = errors.New("device auth: account is inactive")
	ErrDeviceInactive      = errors.New("device auth: device is inactive or revoked")
	ErrDeviceNotFound      = errors.New("device auth: registered device not found")
	ErrEpochMismatch       = errors.New("device auth: account or device epoch mismatch")
	ErrDeviceStateInvalid  = errors.New("device auth: inconsistent persisted device state")
	ErrAuthenticatorClosed = errors.New("device auth: postgres authenticator is not initialized")
)

// RequestAuthenticator authenticates a device-bound HTTP request and consumes
// its nonce before returning. Implementations must fail closed on persistence
// errors and must make nonce consumption atomic across gateway instances.
type RequestAuthenticator interface {
	Authenticate(ctx context.Context, authorizationHeader, method, requestTarget string, body []byte, now time.Time) (Principal, error)
}

type PostgresRequestAuthenticator struct {
	db *sql.DB
}

func NewPostgresRequestAuthenticator(db *sql.DB) *PostgresRequestAuthenticator {
	return &PostgresRequestAuthenticator{db: db}
}

// Authenticate locks the authoritative account/device rows, verifies their
// lifecycle state and DSK, verifies the exact HTTP transcript, and consumes the
// nonce in the same transaction. The row locks serialize acceptance against
// concurrent device revocation and account-epoch transitions.
func (a *PostgresRequestAuthenticator) Authenticate(
	ctx context.Context,
	authorizationHeader, method, requestTarget string,
	body []byte,
	now time.Time,
) (Principal, error) {
	if a == nil || a.db == nil {
		return Principal{}, ErrAuthenticatorClosed
	}
	proof, err := ParseAuthorizationHeader(authorizationHeader)
	if err != nil {
		return Principal{}, err
	}
	// Reject malformed method/target/body before opening a transaction or
	// taking locks on account and device rows.
	if err := validateRequest(method, requestTarget, body); err != nil {
		return Principal{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Principal{}, fmt.Errorf("begin device request authentication: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock in the same order as PostgresAuthorizer.Transition: accounts,
	// authorization_accounts, authorization_devices, then devices. This avoids
	// introducing a reverse lock order during concurrent revocation.
	var rowAccountEpoch int64
	err = tx.QueryRowContext(ctx, `
SELECT account_epoch
FROM accounts
WHERE account_id = $1::uuid
FOR SHARE
`, uuidText(proof.AccountID)).Scan(&rowAccountEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrDeviceNotFound
	}
	if err != nil {
		return Principal{}, fmt.Errorf("lock account row for device request: %w", err)
	}

	var accountStatus int
	var accountEpoch int64
	err = tx.QueryRowContext(ctx, `
SELECT status, epoch
FROM authorization_accounts
WHERE account_id = $1::uuid
FOR SHARE
`, uuidText(proof.AccountID)).Scan(&accountStatus, &accountEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrDeviceNotFound
	}
	if err != nil {
		return Principal{}, fmt.Errorf("lock authorization account row for device request: %w", err)
	}

	var deviceStatus int
	var authorizedEpoch int64
	var authorizationDSK, authorizationDDHK []byte
	err = tx.QueryRowContext(ctx, `
SELECT status, authorized_epoch, dsk_pub, ddhk_pub
FROM authorization_devices
WHERE account_id = $1::uuid AND device_id = $2::uuid
FOR SHARE
`, uuidText(proof.AccountID), uuidText(proof.DeviceID)).Scan(
		&deviceStatus, &authorizedEpoch, &authorizationDSK, &authorizationDDHK,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrDeviceNotFound
	}
	if err != nil {
		return Principal{}, fmt.Errorf("lock authorization device row for request: %w", err)
	}

	var rowDeviceEpoch int64
	var deviceDSK, deviceDDHK []byte
	var revoked bool
	err = tx.QueryRowContext(ctx, `
SELECT account_epoch, dsk_pub, ddhk_pub, revoked_at IS NOT NULL
FROM devices
WHERE account_id = $1::uuid AND device_id = $2::uuid
FOR SHARE
`, uuidText(proof.AccountID), uuidText(proof.DeviceID)).Scan(
		&rowDeviceEpoch, &deviceDSK, &deviceDDHK, &revoked,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrDeviceNotFound
	}
	if err != nil {
		return Principal{}, fmt.Errorf("lock device row for request: %w", err)
	}
	if accountStatus != int(authorization.AccountActive) {
		return Principal{}, ErrAccountInactive
	}
	if deviceStatus != int(authorization.DeviceActive) || revoked {
		return Principal{}, ErrDeviceInactive
	}
	if accountEpoch < 1 || accountEpoch > int64(MaxEpoch) ||
		authorizedEpoch < 1 || authorizedEpoch > int64(MaxEpoch) ||
		rowAccountEpoch < 1 || rowAccountEpoch > int64(MaxEpoch) ||
		rowDeviceEpoch < 1 || rowDeviceEpoch > int64(MaxEpoch) ||
		uint64(accountEpoch) != proof.Epoch || uint64(authorizedEpoch) != proof.Epoch ||
		uint64(rowAccountEpoch) != proof.Epoch || uint64(rowDeviceEpoch) != proof.Epoch {
		return Principal{}, ErrEpochMismatch
	}
	if len(authorizationDSK) != ed25519.PublicKeySize || len(deviceDSK) != ed25519.PublicKeySize ||
		len(authorizationDDHK) != 32 || len(deviceDDHK) != 32 ||
		!bytes.Equal(authorizationDSK, deviceDSK) || !bytes.Equal(authorizationDDHK, deviceDDHK) {
		return Principal{}, ErrDeviceStateInvalid
	}
	if err := proof.Verify(ed25519.PublicKey(authorizationDSK), method, requestTarget, body, now); err != nil {
		return Principal{}, err
	}

	// Expire only a bounded batch on each authenticated request. The index in
	// migration 0006 makes this cleanup bounded and avoids unbounded table growth.
	_, err = tx.ExecContext(ctx, `
WITH expired AS (
    SELECT ctid
    FROM device_request_nonces
    WHERE expires_at <= $1
    ORDER BY expires_at
    LIMIT 128
    FOR UPDATE SKIP LOCKED
)
DELETE FROM device_request_nonces n
USING expired e
WHERE n.ctid = e.ctid
`, now.UTC())
	if err != nil {
		return Principal{}, fmt.Errorf("prune expired device request nonces: %w", err)
	}

	// The extra second preserves the inclusive timestamp-skew boundary. Once
	// the row expires, the signed proof is no longer acceptable to Verify.
	nonceExpiresAt := time.Unix(int64(proof.Timestamp), 0).Add(MaxClockSkew + time.Second).UTC()
	result, err := tx.ExecContext(ctx, `
INSERT INTO device_request_nonces (account_id, device_id, nonce, expires_at)
VALUES ($1::uuid, $2::uuid, $3, $4)
ON CONFLICT (account_id, device_id, nonce) DO NOTHING
`, uuidText(proof.AccountID), uuidText(proof.DeviceID), proof.Nonce[:], nonceExpiresAt)
	if err != nil {
		return Principal{}, fmt.Errorf("consume device request nonce: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return Principal{}, fmt.Errorf("inspect device request nonce result: %w", err)
	}
	if rowsAffected != 1 {
		return Principal{}, ErrRequestReplay
	}
	if err := tx.Commit(); err != nil {
		return Principal{}, fmt.Errorf("commit device request authentication: %w", err)
	}
	return proof.Principal, nil
}

// uuidText formats the protocol's 16-byte identifiers as PostgreSQL UUID text.
// The deviceauth package intentionally owns this helper instead of depending on
// unexported helpers in authorization, devices, or messages.
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
