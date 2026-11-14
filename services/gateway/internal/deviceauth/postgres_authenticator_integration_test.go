package deviceauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/messages"
)

const (
	requestAuthIntegrationDSNEnv = "PM_ENROLLMENT_TEST_DATABASE_URL"
	requestAuthIntegrationDBName = "pm_enrollment_test_20261030"
)

// PostgreSQL auth integration tests are opt-in and restricted to the same
// explicitly named disposable database used by the existing enrollment tests.
// These tests never create a database or apply migrations automatically.
func openRequestAuthIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(requestAuthIntegrationDSNEnv))
	if dsn == "" {
		t.Skip("set PM_ENROLLMENT_TEST_DATABASE_URL to run PostgreSQL request-auth integration tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open request-auth integration database: %v", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping request-auth integration database: %v", err)
	}
	var databaseName string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
		t.Fatalf("read integration database name: %v", err)
	}
	if databaseName != requestAuthIntegrationDBName {
		t.Fatalf("safety stop: request-auth integration tests are restricted to %q, connected to %q", requestAuthIntegrationDBName, databaseName)
	}
	var schemaReady bool
	if err := db.QueryRowContext(ctx, `SELECT
		to_regclass('public.accounts') IS NOT NULL AND
		to_regclass('public.devices') IS NOT NULL AND
		to_regclass('public.authorization_accounts') IS NOT NULL AND
		to_regclass('public.authorization_devices') IS NOT NULL AND
		to_regclass('public.device_enrollment_challenges') IS NOT NULL AND
		to_regclass('public.device_request_nonces') IS NOT NULL`).Scan(&schemaReady); err != nil {
		t.Fatalf("inspect request-auth integration schema: %v", err)
	}
	if !schemaReady {
		t.Fatal("integration schema is incomplete; apply migrations 0001 through 0006 to the dedicated test database first")
	}
	return db
}

type requestAuthPGFixture struct {
	db      *sql.DB
	account [16]byte
	device  [16]byte
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newRequestAuthPGFixture(t *testing.T, db *sql.DB) *requestAuthPGFixture {
	t.Helper()
	f := &requestAuthPGFixture{db: db}
	if _, err := rand.Read(f.account[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(f.device[:]); err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.public, f.private = pub, private
	var ddhk, commitment, recoveryPub, authDigest [32]byte
	for _, value := range []*[32]byte{&ddhk, &commitment, &recoveryPub, &authDigest} {
		if _, err := rand.Read(value[:]); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accountText := uuidText(f.account)
	deviceText := uuidText(f.device)
	username := "pm-request-auth-" + strings.ReplaceAll(accountText, "-", "")
	if _, err := db.ExecContext(ctx, `
INSERT INTO accounts (account_id, username, account_epoch, irc)
VALUES ($1::uuid, $2, 1, $3)
`, accountText, username, commitment[:]); err != nil {
		t.Fatalf("insert integration account: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO authorization_accounts (account_id, epoch, recovery_commitment, recovery_pub, status)
VALUES ($1::uuid, 1, $2, $3, 1)
`, accountText, commitment[:], recoveryPub[:]); err != nil {
		t.Fatalf("insert authorization account: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO devices (device_id, account_id, account_epoch, dsk_pub, ddhk_pub, push_pub, revoked_at)
VALUES ($1::uuid, $2::uuid, 1, $3, $4, NULL, NULL)
`, deviceText, accountText, f.public, ddhk[:]); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO authorization_devices (
    device_id, account_id, dsk_pub, ddhk_pub, status, authorized_epoch,
    enrollment_auth_digest, revoked_epoch
) VALUES ($1::uuid, $2::uuid, $3, $4, 1, 1, $5, 0)
`, deviceText, accountText, f.public, ddhk[:], authDigest[:]); err != nil {
		t.Fatalf("insert authorization device: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
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
				t.Errorf("cleanup request-auth fixture: %v", err)
				return
			}
		}
	})
	return f
}

func (f *requestAuthPGFixture) signedHeader(t *testing.T, epoch uint64, method, target string, body []byte, now time.Time) string {
	t.Helper()
	var principal Principal
	principal.AccountID = f.account
	principal.DeviceID = f.device
	principal.Epoch = epoch
	principal.Timestamp = uint64(now.Unix())
	if _, err := rand.Read(principal.Nonce[:]); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, ProofSize)
	raw[0] = Version
	copy(raw[1:17], principal.AccountID[:])
	copy(raw[17:33], principal.DeviceID[:])
	binary.BigEndian.PutUint64(raw[33:41], principal.Epoch)
	binary.BigEndian.PutUint64(raw[41:49], principal.Timestamp)
	copy(raw[49:81], principal.Nonce[:])
	signature := ed25519.Sign(f.private, requestTranscript(principal, method, target, body))
	copy(raw[81:], signature)
	return Scheme + " " + base64.RawURLEncoding.EncodeToString(raw)
}

func TestPostgresRequestAuthenticatorConsumesNonceAndRejectsReplayIntegration(t *testing.T) {
	db := openRequestAuthIntegrationDB(t)
	fixture := newRequestAuthPGFixture(t, db)
	authenticator := NewPostgresRequestAuthenticator(db)
	now := time.Now().UTC().Truncate(time.Second)
	body := []byte(`{"ciphertext":"integration"}`)
	header := fixture.signedHeader(t, 1, "POST", "/v1/demo/messages", body, now)

	principal, err := authenticator.Authenticate(context.Background(), header, "POST", "/v1/demo/messages", body, now)
	if err != nil {
		t.Fatalf("authenticate valid request: %v", err)
	}
	if principal.AccountID != fixture.account || principal.DeviceID != fixture.device || principal.Epoch != 1 {
		t.Fatalf("unexpected authenticated principal: %+v", principal)
	}
	if _, err := authenticator.Authenticate(context.Background(), header, "POST", "/v1/demo/messages", body, now); !errors.Is(err, ErrRequestReplay) {
		t.Fatalf("replayed request error=%v, want ErrRequestReplay", err)
	}
}

func TestPostgresRequestAuthenticatorAllowsOnlyOneConcurrentReplayWinnerIntegration(t *testing.T) {
	db := openRequestAuthIntegrationDB(t)
	fixture := newRequestAuthPGFixture(t, db)
	authenticator := NewPostgresRequestAuthenticator(db)
	now := time.Now().UTC().Truncate(time.Second)
	body := []byte(`{"ciphertext":"concurrent"}`)
	header := fixture.signedHeader(t, 1, "POST", "/v1/demo/messages", body, now)

	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := authenticator.Authenticate(context.Background(), header, "POST", "/v1/demo/messages", body, now)
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	accepted, replayed := 0, 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrRequestReplay):
			replayed++
		default:
			t.Fatalf("unexpected concurrent authentication error: %v", err)
		}
	}
	if accepted != 1 || replayed != 1 {
		t.Fatalf("concurrent outcomes accepted=%d replayed=%d; want exactly one of each", accepted, replayed)
	}
}

func TestAuthenticatedDeliveryRechecksEpochAfterMiddlewareAuthenticationIntegration(t *testing.T) {
	db := openRequestAuthIntegrationDB(t)
	fixture := newRequestAuthPGFixture(t, db)
	authenticator := NewPostgresRequestAuthenticator(db)
	now := time.Now().UTC().Truncate(time.Second)
	body := []byte(nil)
	header := fixture.signedHeader(t, 1, "GET", "/v1/demo/messages/00000000-0000-0000-0000-000000000001", body, now)
	principal, err := authenticator.Authenticate(context.Background(), header, "GET", "/v1/demo/messages/00000000-0000-0000-0000-000000000001", body, now)
	if err != nil {
		t.Fatalf("authenticate initial request: %v", err)
	}

	// Simulate a completed account epoch transition in between middleware auth
	// and the protected delivery operation. The latter must re-check state.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accountText, deviceText := uuidText(fixture.account), uuidText(fixture.device)
	updates := []struct {
		query string
		args  []any
	}{
		{`UPDATE accounts SET account_epoch=2 WHERE account_id=$1::uuid`, []any{accountText}},
		{`UPDATE authorization_accounts SET epoch=2 WHERE account_id=$1::uuid`, []any{accountText}},
		{`UPDATE authorization_devices SET authorized_epoch=2 WHERE account_id=$1::uuid AND device_id=$2::uuid`, []any{accountText, deviceText}},
		{`UPDATE devices SET account_epoch=2 WHERE account_id=$1::uuid AND device_id=$2::uuid`, []any{accountText, deviceText}},
	}
	for _, update := range updates {
		if _, err := db.ExecContext(ctx, update.query, update.args...); err != nil {
			t.Fatalf("advance fixture epoch: %v", err)
		}
	}

	delivery := messages.NewDeliveryService(db)
	_, err = delivery.FetchAuthenticated(ctx, messages.AuthenticatedDevice{
		AccountID: principal.AccountID,
		DeviceID:  principal.DeviceID,
		Epoch:     principal.Epoch,
	}, 10)
	if !errors.Is(err, messages.ErrAuthenticatedEpochMismatch) {
		t.Fatalf("stale authenticated fetch error=%v, want ErrAuthenticatedEpochMismatch", err)
	}
}

func TestPostgresRequestAuthenticatorRejectsRevokedAndInactiveStateIntegration(t *testing.T) {
	db := openRequestAuthIntegrationDB(t)
	fixture := newRequestAuthPGFixture(t, db)
	authenticator := NewPostgresRequestAuthenticator(db)
	now := time.Now().UTC().Truncate(time.Second)
	body := []byte(`{}`)
	accountText, deviceText := uuidText(fixture.account), uuidText(fixture.device)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := db.ExecContext(ctx, `UPDATE authorization_devices SET status=2 WHERE account_id=$1::uuid AND device_id=$2::uuid`, accountText, deviceText); err != nil {
		t.Fatalf("revoke fixture device: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE devices SET revoked_at=now() WHERE account_id=$1::uuid AND device_id=$2::uuid`, accountText, deviceText); err != nil {
		t.Fatalf("mark fixture device revoked: %v", err)
	}
	header := fixture.signedHeader(t, 1, "POST", "/v1/demo/messages", body, now)
	if _, err := authenticator.Authenticate(ctx, header, "POST", "/v1/demo/messages", body, now); !errors.Is(err, ErrDeviceInactive) {
		t.Fatalf("revoked device error=%v, want ErrDeviceInactive", err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE authorization_devices SET status=1 WHERE account_id=$1::uuid AND device_id=$2::uuid`, accountText, deviceText); err != nil {
		t.Fatalf("restore auth device for account-lock case: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE devices SET revoked_at=NULL WHERE account_id=$1::uuid AND device_id=$2::uuid`, accountText, deviceText); err != nil {
		t.Fatalf("restore device for account-lock case: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE authorization_accounts SET status=2 WHERE account_id=$1::uuid`, accountText); err != nil {
		t.Fatalf("lock fixture account: %v", err)
	}
	header = fixture.signedHeader(t, 1, "POST", "/v1/demo/messages", body, now)
	if _, err := authenticator.Authenticate(ctx, header, "POST", "/v1/demo/messages", body, now); !errors.Is(err, ErrAccountInactive) {
		t.Fatalf("inactive account error=%v, want ErrAccountInactive", err)
	}
}
