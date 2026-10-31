package gwhttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/deviceauth"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/messages"
)

const (
	messageHTTPAuthTestDatabaseEnv  = "PM_ENROLLMENT_TEST_DATABASE_URL"
	messageHTTPAuthTestDatabaseName = "pm_enrollment_test_20261030"
)

type messageHTTPAuthPostgresFixture struct {
	account [16]byte
	device  [16]byte
	private ed25519.PrivateKey
}

func openMessageHTTPAuthIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv(messageHTTPAuthTestDatabaseEnv))
	if dsn == "" {
		t.Skip("set PM_ENROLLMENT_TEST_DATABASE_URL to run HTTP/PostgreSQL device-auth integration")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open HTTP device-auth integration database: %v", err)
	}

	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping HTTP device-auth integration database: %v", err)
	}

	var databaseName string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
		t.Fatalf("read integration database name: %v", err)
	}
	if databaseName != messageHTTPAuthTestDatabaseName {
		t.Fatalf(
			"safety stop: HTTP device-auth integration is restricted to %q, connected to %q",
			messageHTTPAuthTestDatabaseName,
			databaseName,
		)
	}

	var schemaReady bool
	if err := db.QueryRowContext(ctx, `
        SELECT
            to_regclass('public.accounts') IS NOT NULL AND
            to_regclass('public.devices') IS NOT NULL AND
            to_regclass('public.authorization_accounts') IS NOT NULL AND
            to_regclass('public.authorization_devices') IS NOT NULL AND
            to_regclass('public.authorization_events') IS NOT NULL AND
            to_regclass('public.device_enrollment_challenges') IS NOT NULL AND
            to_regclass('public.device_request_nonces') IS NOT NULL AND
            to_regclass('public.message_envelopes') IS NOT NULL
    `).Scan(&schemaReady); err != nil {
		t.Fatalf("inspect HTTP device-auth integration schema: %v", err)
	}

	if !schemaReady {
		t.Fatal("integration schema is incomplete; apply the required gateway migrations to the dedicated test database")
	}

	return db
}

func newMessageHTTPAuthPostgresFixture(t *testing.T, db *sql.DB) *messageHTTPAuthPostgresFixture {
	t.Helper()

	fixture := &messageHTTPAuthPostgresFixture{}

	if _, err := rand.Read(fixture.account[:]); err != nil {
		t.Fatalf("generate fixture account ID: %v", err)
	}
	if _, err := rand.Read(fixture.device[:]); err != nil {
		t.Fatalf("generate fixture device ID: %v", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate fixture DSK: %v", err)
	}
	fixture.private = privateKey

	var ddhk, commitment, recoveryPub, authDigest [32]byte
	for _, value := range []*[32]byte{&ddhk, &commitment, &recoveryPub, &authDigest} {
		if _, err := rand.Read(value[:]); err != nil {
			t.Fatalf("generate fixture key material: %v", err)
		}
	}

	accountText := messages.UUIDText(fixture.account)
	deviceText := messages.UUIDText(fixture.device)
	username := "pm-http-auth-" + strings.ReplaceAll(accountText, "-", "")

	// Register cleanup before inserting anything, so partial fixture setup
	// is also cleaned up if a later INSERT fails.
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
				t.Errorf("cleanup HTTP device-auth fixture: %v", err)
				return
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := db.ExecContext(ctx, `
        INSERT INTO accounts (account_id, username, account_epoch, irc)
        VALUES ($1::uuid, $2, 1, $3)
    `, accountText, username, commitment[:]); err != nil {
		t.Fatalf("insert HTTP fixture account: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
        INSERT INTO authorization_accounts (account_id, epoch, recovery_commitment, recovery_pub, status)
        VALUES ($1::uuid, 1, $2, $3, 1)
    `, accountText, commitment[:], recoveryPub[:]); err != nil {
		t.Fatalf("insert HTTP fixture authorization account: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
        INSERT INTO devices (device_id, account_id, account_epoch, dsk_pub, ddhk_pub, push_pub, revoked_at)
        VALUES ($1::uuid, $2::uuid, 1, $3, $4, NULL, NULL)
    `, deviceText, accountText, publicKey, ddhk[:]); err != nil {
		t.Fatalf("insert HTTP fixture device: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
        INSERT INTO authorization_devices (
            device_id, account_id, dsk_pub, ddhk_pub, status, authorized_epoch,
            enrollment_auth_digest, revoked_epoch
        ) VALUES ($1::uuid, $2::uuid, $3, $4, 1, 1, $5, 0)
    `, deviceText, accountText, publicKey, ddhk[:], authDigest[:]); err != nil {
		t.Fatalf("insert HTTP fixture authorization device: %v", err)
	}

	return fixture
}

// This test-only signer mirrors the PM-V1 request transcript. Android-to-Go
// interoperability is independently checked by the Android fixture tests.
func signMessageHTTPAuthRequest(
	privateKey ed25519.PrivateKey,
	accountID, deviceID [16]byte,
	epoch uint64,
	method, requestTarget string,
	body []byte,
	now time.Time,
) (string, error) {
	var principal deviceauth.Principal
	principal.AccountID = accountID
	principal.DeviceID = deviceID
	principal.Epoch = epoch
	principal.Timestamp = uint64(now.Unix())

	if _, err := rand.Read(principal.Nonce[:]); err != nil {
		return "", err
	}

	bodyDigest := sha256.Sum256(body)

	transcript := make([]byte, 0, 128+len(method)+len(requestTarget))
	transcript = append(transcript, []byte("PM-V1-DEVICE-HTTP-REQUEST-AUTH-v1\x00")...)
	transcript = append(transcript, deviceauth.Version)
	transcript = append(transcript, principal.AccountID[:]...)
	transcript = append(transcript, principal.DeviceID[:]...)

	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], principal.Epoch)
	transcript = append(transcript, u64[:]...)

	binary.BigEndian.PutUint64(u64[:], principal.Timestamp)
	transcript = append(transcript, u64[:]...)
	transcript = append(transcript, principal.Nonce[:]...)

	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(method)))
	transcript = append(transcript, u16[:]...)
	transcript = append(transcript, method...)

	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(requestTarget)))
	transcript = append(transcript, u32[:]...)
	transcript = append(transcript, requestTarget...)
	transcript = append(transcript, bodyDigest[:]...)

	signature := ed25519.Sign(privateKey, transcript)

	raw := make([]byte, deviceauth.ProofSize)
	raw[0] = deviceauth.Version
	copy(raw[1:17], principal.AccountID[:])
	copy(raw[17:33], principal.DeviceID[:])
	binary.BigEndian.PutUint64(raw[33:41], principal.Epoch)
	binary.BigEndian.PutUint64(raw[41:49], principal.Timestamp)
	copy(raw[49:81], principal.Nonce[:])
	copy(raw[81:145], signature)

	return deviceauth.Scheme + " " + base64.RawURLEncoding.EncodeToString(raw), nil
}

func TestPostgresDeviceAuthenticationProtectsMessageFetchHTTPIntegration(t *testing.T) {
	db := openMessageHTTPAuthIntegrationDB(t)
	fixture := newMessageHTTPAuthPostgresFixture(t, db)

	delivery := messages.NewDeliveryService(db)
	authenticator := deviceauth.NewPostgresRequestAuthenticator(db)

	handler := NewHandlerWithSTHAndDevicesAndMessagesAndDeviceAuth(
		nil,
		nil,
		delivery,
		authenticator,
	)

	requestTarget := "/v1/demo/messages/" + messages.UUIDText(fixture.device) + "?limit=17"
	now := time.Now().UTC().Truncate(time.Second)

	authorization, err := signMessageHTTPAuthRequest(
		fixture.private,
		fixture.account,
		fixture.device,
		1,
		http.MethodGet,
		requestTarget,
		nil,
		now,
	)
	if err != nil {
		t.Fatalf("sign HTTP integration request: %v", err)
	}

	// The same signature must not authorize a different query string.
	alteredTarget := strings.Replace(requestTarget, "limit=17", "limit=18", 1)
	alteredRequest := httptest.NewRequest(http.MethodGet, alteredTarget, nil)
	alteredRequest.Header.Set("Authorization", authorization)
	alteredResponse := httptest.NewRecorder()
	handler.ServeHTTP(alteredResponse, alteredRequest)

	if alteredResponse.Code != http.StatusUnauthorized {
		t.Fatalf(
			"altered request target status=%d body=%s; want 401",
			alteredResponse.Code,
			alteredResponse.Body.String(),
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accountText := messages.UUIDText(fixture.account)
	deviceText := messages.UUIDText(fixture.device)

	assertNonceCount := func(want int64) {
		t.Helper()

		var count int64
		if err := db.QueryRowContext(ctx, `
            SELECT count(*)
            FROM device_request_nonces
            WHERE account_id=$1::uuid AND device_id=$2::uuid
        `, accountText, deviceText).Scan(&count); err != nil {
			t.Fatalf("count persisted request nonces: %v", err)
		}

		if count != want {
			t.Fatalf("persisted nonce count=%d; want %d", count, want)
		}
	}

	// Failed transcript verification must not consume the nonce.
	assertNonceCount(0)

	validRequest := httptest.NewRequest(http.MethodGet, requestTarget, nil)
	validRequest.Header.Set("Authorization", authorization)
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, validRequest)

	if validResponse.Code != http.StatusOK {
		t.Fatalf(
			"valid authenticated fetch status=%d body=%s",
			validResponse.Code,
			validResponse.Body.String(),
		)
	}
	if validResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("authenticated response Cache-Control=%q; want no-store", validResponse.Header().Get("Cache-Control"))
	}

	var response struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(validResponse.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode authenticated fetch response: %v; body=%s", err, validResponse.Body.String())
	}
	if response.Messages == nil || len(response.Messages) != 0 {
		t.Fatalf("expected an empty authenticated message queue, got %d messages", len(response.Messages))
	}

	// The real PostgreSQL authenticator must have persisted the request nonce.
	assertNonceCount(1)

	// Replaying the exact HTTP request must be rejected by middleware before
	// the authenticated fetch handler can run again.
	replayRequest := httptest.NewRequest(http.MethodGet, requestTarget, nil)
	replayRequest.Header.Set("Authorization", authorization)
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, replayRequest)

	if replayResponse.Code != http.StatusUnauthorized {
		t.Fatalf(
			"replayed HTTP request status=%d body=%s; want 401",
			replayResponse.Code,
			replayResponse.Body.String(),
		)
	}

	assertNonceCount(1)

	t.Log("verified PostgreSQL-backed device authentication through the HTTP message-fetch route: altered target rejected; valid fetch accepted; nonce persisted; replay rejected")
}
