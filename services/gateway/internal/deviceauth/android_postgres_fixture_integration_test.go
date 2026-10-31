package deviceauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAndroidGeneratedRequestProofUsesAuthoritativePostgresKeyAndRejectsReplayIntegration(t *testing.T) {
	fixturePath := strings.TrimSpace(os.Getenv("PM_ANDROID_PROOF_FIXTURE"))
	if fixturePath == "" {
		t.Skip("PM_ANDROID_PROOF_FIXTURE is not set; Android/PostgreSQL fixture not supplied")
	}

	db := openRequestAuthIntegrationDB(t)

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read Android proof fixture: %v", err)
	}

	var fixture struct {
		AuthorizationHeader string `json:"authorization_header"`
		PublicKeyHex        string `json:"public_key_hex"`
		Method              string `json:"method"`
		RequestTarget       string `json:"request_target"`
		BodyBase64          string `json:"body_base64"`
	}

	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode Android proof fixture: %v", err)
	}

	publicKeyBytes, err := hex.DecodeString(fixture.PublicKeyHex)
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize {
		t.Fatalf("invalid Android DSK public key: len=%d err=%v", len(publicKeyBytes), err)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)

	body, err := base64.StdEncoding.DecodeString(fixture.BodyBase64)
	if err != nil {
		t.Fatalf("decode Android request body: %v", err)
	}

	proof, err := ParseAuthorizationHeader(fixture.AuthorizationHeader)
	if err != nil {
		t.Fatalf("parse Android authorization proof: %v", err)
	}

	if proof.Epoch == 0 {
		t.Fatal("Android proof contains epoch zero")
	}

	var ddhk, commitment, recoveryPub, authDigest [32]byte
	for _, value := range []*[32]byte{&ddhk, &commitment, &recoveryPub, &authDigest} {
		if _, err := rand.Read(value[:]); err != nil {
			t.Fatalf("generate disposable database fixture material: %v", err)
		}
	}

	wrongPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate deliberately incorrect database DSK: %v", err)
	}

	accountText := uuidText(proof.AccountID)
	deviceText := uuidText(proof.DeviceID)
	username := "pm-android-auth-" + strings.ReplaceAll(accountText, "-", "")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register precisely the identity and public key produced by Android.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin Android PostgreSQL fixture transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO accounts (account_id, username, account_epoch, irc)
VALUES ($1::uuid, $2, $3, $4)
`, accountText, username, int64(proof.Epoch), commitment[:]); err != nil {
		t.Fatalf("insert Android account: %v", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO authorization_accounts (account_id, epoch, recovery_commitment, recovery_pub, status)
VALUES ($1::uuid, $2, $3, $4, 1)
`, accountText, int64(proof.Epoch), commitment[:], recoveryPub[:]); err != nil {
		t.Fatalf("insert Android authorization account: %v", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO devices (device_id, account_id, account_epoch, dsk_pub, ddhk_pub, push_pub, revoked_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, NULL, NULL)
`, deviceText, accountText, int64(proof.Epoch), publicKey, ddhk[:]); err != nil {
		t.Fatalf("insert Android device: %v", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO authorization_devices (
    device_id, account_id, dsk_pub, ddhk_pub, status, authorized_epoch,
    enrollment_auth_digest, revoked_epoch
) VALUES ($1::uuid, $2::uuid, $3, $4, 1, $5, $6, 0)
`, deviceText, accountText, publicKey, ddhk[:], int64(proof.Epoch), authDigest[:]); err != nil {
		t.Fatalf("insert Android authorization device: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit Android PostgreSQL fixture: %v", err)
	}

	// Clean only this test's disposable identity and nonce.
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()

		statements := []struct {
			query string
			args  []any
		}{
			{`DELETE FROM device_request_nonces WHERE account_id=$1::uuid AND device_id=$2::uuid`, []any{accountText, deviceText}},
			{`DELETE FROM authorization_events WHERE account_id=$1::uuid AND target_device_id=$2::uuid`, []any{accountText, deviceText}},
			{`DELETE FROM device_enrollment_challenges WHERE account_id=$1::uuid AND device_id=$2::uuid`, []any{accountText, deviceText}},
			{`DELETE FROM authorization_devices WHERE account_id=$1::uuid AND device_id=$2::uuid`, []any{accountText, deviceText}},
			{`DELETE FROM device_certificates WHERE device_id=$1::uuid`, []any{deviceText}},
			{`DELETE FROM signed_prekeys WHERE device_id=$1::uuid`, []any{deviceText}},
			{`DELETE FROM one_time_prekeys WHERE device_id=$1::uuid`, []any{deviceText}},
			{`DELETE FROM notification_state WHERE device_id=$1::uuid`, []any{deviceText}},
			{`DELETE FROM media_upload_sessions WHERE owner_device=$1::uuid`, []any{deviceText}},
			{`DELETE FROM devices WHERE account_id=$1::uuid AND device_id=$2::uuid`, []any{accountText, deviceText}},
			{`DELETE FROM authorization_accounts WHERE account_id=$1::uuid`, []any{accountText}},
			{`DELETE FROM accounts WHERE account_id=$1::uuid`, []any{accountText}},
		}

		for _, statement := range statements {
			if _, err := db.ExecContext(cleanupCtx, statement.query, statement.args...); err != nil {
				t.Errorf("cleanup Android PostgreSQL fixture: %v", err)
				return
			}
		}
	})

	authenticator := NewPostgresRequestAuthenticator(db)
	now := time.Now().UTC()

	// A different key in BOTH authoritative records must not authenticate
	// a proof signed by Android's original private key.
	if _, err := db.ExecContext(ctx, `
UPDATE authorization_devices
SET dsk_pub = $3
WHERE account_id = $1::uuid AND device_id = $2::uuid
`, accountText, deviceText, wrongPublicKey); err != nil {
		t.Fatalf("replace authorization DSK for negative test: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
UPDATE devices
SET dsk_pub = $3
WHERE account_id = $1::uuid AND device_id = $2::uuid
`, accountText, deviceText, wrongPublicKey); err != nil {
		t.Fatalf("replace device DSK for negative test: %v", err)
	}

	if _, err := authenticator.Authenticate(
		ctx, fixture.AuthorizationHeader, fixture.Method,
		fixture.RequestTarget, body, now,
	); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("proof with wrong authoritative database DSK returned %v; want ErrInvalidProof", err)
	}

	// Restore the DSK that Android actually used.
	if _, err := db.ExecContext(ctx, `
UPDATE authorization_devices
SET dsk_pub = $3
WHERE account_id = $1::uuid AND device_id = $2::uuid
`, accountText, deviceText, publicKey); err != nil {
		t.Fatalf("restore authorization DSK: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
UPDATE devices
SET dsk_pub = $3
WHERE account_id = $1::uuid AND device_id = $2::uuid
`, accountText, deviceText, publicKey); err != nil {
		t.Fatalf("restore device DSK: %v", err)
	}

	// The exact body is part of the signed transcript.
	alteredBody := append([]byte(nil), body...)
	if len(alteredBody) == 0 {
		t.Fatal("Android fixture body unexpectedly empty")
	}
	alteredBody[0] ^= 0x01

	if _, err := authenticator.Authenticate(
		ctx, fixture.AuthorizationHeader, fixture.Method,
		fixture.RequestTarget, alteredBody, now,
	); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("altered request body returned %v; want ErrInvalidProof", err)
	}

	// The original Android proof must now authenticate against PostgreSQL.
	principal, err := authenticator.Authenticate(
		ctx, fixture.AuthorizationHeader, fixture.Method,
		fixture.RequestTarget, body, now,
	)
	if err != nil {
		t.Fatalf("authenticate Android proof against PostgreSQL: %v", err)
	}

	if principal.AccountID != proof.AccountID ||
		principal.DeviceID != proof.DeviceID ||
		principal.Epoch != proof.Epoch {
		t.Fatalf("PostgreSQL authenticator returned unexpected principal: %+v", principal)
	}

	// A second authenticator instance must observe the persisted nonce.
	anotherAuthenticator := NewPostgresRequestAuthenticator(db)

	if _, err := anotherAuthenticator.Authenticate(
		ctx, fixture.AuthorizationHeader, fixture.Method,
		fixture.RequestTarget, body, time.Now().UTC(),
	); !errors.Is(err, ErrRequestReplay) {
		t.Fatalf("replayed Android proof returned %v; want ErrRequestReplay", err)
	}

	t.Logf(
		"verified Android proof against PostgreSQL authoritative DSK and lifecycle state: account=%x device=%x epoch=%d; wrong DB key rejected; altered body rejected; replay rejected",
		principal.AccountID, principal.DeviceID, principal.Epoch,
	)
}
