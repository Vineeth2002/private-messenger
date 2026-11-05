package gwhttp

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/authorization"
	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/cbor"
)

const (
	recoveryHTTPIntegrationDSNEnv = "PM_ENROLLMENT_TEST_DATABASE_URL"
	recoveryHTTPIntegrationDBName = "pm_enrollment_test_20261030"
)

// These tests use only the explicitly named local disposable PostgreSQL database.
// They never create, migrate, truncate, or reset a database.
func openRecoveryHTTPIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(recoveryHTTPIntegrationDSNEnv))
	if dsn == "" {
		t.Skip("set PM_ENROLLMENT_TEST_DATABASE_URL to run recovery HTTP/PostgreSQL integration tests")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open recovery HTTP integration database: %v", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping recovery HTTP integration database: %v", err)
	}

	var databaseName, serverAddress, schemaName string
	var serverPort int
	var inRecovery bool
	if err := db.QueryRowContext(ctx, `
SELECT current_database(), COALESCE(host(inet_server_addr()), ''),
       COALESCE(inet_server_port(), 0), current_schema(), pg_is_in_recovery()
`).Scan(&databaseName, &serverAddress, &serverPort, &schemaName, &inRecovery); err != nil {
		t.Fatalf("inspect recovery HTTP integration connection: %v", err)
	}
	if databaseName != recoveryHTTPIntegrationDBName {
		t.Fatalf("safety stop: tests are restricted to database %q, connected to %q", recoveryHTTPIntegrationDBName, databaseName)
	}
	if serverAddress != "127.0.0.1" || serverPort != 5432 || schemaName != "public" || inRecovery {
		t.Fatalf("safety stop: expected local primary PostgreSQL at 127.0.0.1:5432/public; got address=%q port=%d schema=%q in_recovery=%v", serverAddress, serverPort, schemaName, inRecovery)
	}

	var schemaReady bool
	if err := db.QueryRowContext(ctx, `SELECT
		to_regclass('public.accounts') IS NOT NULL AND
		to_regclass('public.devices') IS NOT NULL AND
		to_regclass('public.device_certificates') IS NOT NULL AND
		to_regclass('public.authorization_accounts') IS NOT NULL AND
		to_regclass('public.authorization_devices') IS NOT NULL AND
		to_regclass('public.authorization_events') IS NOT NULL AND
		to_regclass('public.device_enrollment_challenges') IS NOT NULL AND
		to_regclass('public.account_recovery_requests') IS NOT NULL`).Scan(&schemaReady); err != nil {
		t.Fatalf("inspect recovery HTTP integration schema: %v", err)
	}
	if !schemaReady {
		t.Fatal("recovery HTTP integration schema is incomplete; apply the gateway migrations through 0008 to the dedicated test database")
	}
	return db
}

type recoveryHTTPIntegrationFixture struct {
	t              *testing.T
	db             *sql.DB
	authorizer     *authorization.PostgresAuthorizer
	handler        http.Handler
	accountID      [16]byte
	oldDeviceID    [16]byte
	targetDeviceID [16]byte
	recoveryPub    [32]byte
	recoveryPriv   ed25519.PrivateKey
	oldDSKPriv     ed25519.PrivateKey
	targetDSKPriv  ed25519.PrivateKey
	targetCert     []byte
	requestID      [16]byte
	requestRaw     []byte
}

func newRecoveryHTTPIntegrationFixture(t *testing.T, db *sql.DB) *recoveryHTTPIntegrationFixture {
	t.Helper()
	f := &recoveryHTTPIntegrationFixture{
		t: t, db: db, authorizer: authorization.NewPostgresAuthorizer(db),
		accountID: recoveryHTTPRandomID(t), oldDeviceID: recoveryHTTPRandomID(t),
		targetDeviceID: recoveryHTTPRandomID(t), requestID: recoveryHTTPRandomID(t),
	}
	t.Cleanup(f.cleanup)

	recoveryPublic, recoveryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate recovery key: %v", err)
	}
	copy(f.recoveryPub[:], recoveryPublic)
	f.recoveryPriv = recoveryPrivate

	oldDSKPublic, oldDSKPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate original-device DSK: %v", err)
	}
	f.oldDSKPriv = oldDSKPrivate
	targetDSKPublic, targetDSKPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate replacement-device DSK: %v", err)
	}
	f.targetDSKPriv = targetDSKPrivate

	oldDDHKPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate original-device DDHK: %v", err)
	}
	targetDDHKPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate replacement-device DDHK: %v", err)
	}
	var oldDDHKPublic, targetDDHKPublic [32]byte
	copy(oldDDHKPublic[:], oldDDHKPrivate.PublicKey().Bytes())
	copy(targetDDHKPublic[:], targetDDHKPrivate.PublicKey().Bytes())
	var oldDSKPub, targetDSKPub [32]byte
	copy(oldDSKPub[:], oldDSKPublic)
	copy(targetDSKPub[:], targetDSKPublic)

	oldCertificate := recoveryHTTPSignEnrollment(t, f.recoveryPriv, f.accountID, 1, f.oldDeviceID, oldDSKPub, oldDDHKPublic)
	f.targetCert = recoveryHTTPSignEnrollment(t, f.recoveryPriv, f.accountID, 2, f.targetDeviceID, targetDSKPub, targetDDHKPublic)
	f.requestRaw = recoveryHTTPSignRequest(t, f.recoveryPriv, f.accountID, 1, 2, f.requestID, f.targetDeviceID, sha256.Sum256(f.targetCert))

	commitment := authorization.RecoveryCommitment(f.recoveryPub)
	username := "pm-recovery-http-it-" + hex.EncodeToString(f.accountID[:])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `INSERT INTO accounts (account_id, username, account_epoch, irc)
VALUES ($1::uuid, $2, 1, $3)`, recoveryHTTPUUID(f.accountID), username, commitment[:]); err != nil {
		t.Fatalf("insert recovery HTTP test account: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO authorization_accounts
(account_id, epoch, recovery_commitment, recovery_pub, status)
VALUES ($1::uuid, 1, $2, $3, $4)`, recoveryHTTPUUID(f.accountID), commitment[:], f.recoveryPub[:], int(authorization.AccountActive)); err != nil {
		t.Fatalf("insert recovery HTTP authorization account: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO devices
(device_id, account_id, account_epoch, dsk_pub, ddhk_pub, push_pub, revoked_at)
VALUES ($1::uuid, $2::uuid, 1, $3, $4, NULL, NULL)`, recoveryHTTPUUID(f.oldDeviceID), recoveryHTTPUUID(f.accountID), oldDSKPub[:], oldDDHKPublic[:]); err != nil {
		t.Fatalf("insert original device: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO device_certificates (device_id, cert_cbor)
VALUES ($1::uuid, $2)`, recoveryHTTPUUID(f.oldDeviceID), oldCertificate); err != nil {
		t.Fatalf("insert original device certificate: %v", err)
	}
	oldCertDigest := sha256.Sum256(oldCertificate)
	if _, err := db.ExecContext(ctx, `INSERT INTO authorization_devices
(device_id, account_id, dsk_pub, ddhk_pub, status, authorized_epoch, enrollment_auth_digest, revoked_epoch)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, 1, $6, 0)`, recoveryHTTPUUID(f.oldDeviceID), recoveryHTTPUUID(f.accountID), oldDSKPub[:], oldDDHKPublic[:], int(authorization.DeviceActive), oldCertDigest[:]); err != nil {
		t.Fatalf("insert original authorization device: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO authorization_events
(auth_digest, kind, account_id, old_epoch, new_epoch, target_device_id, cert_cbor)
VALUES ($1, 'ENROLL', $2::uuid, 1, 1, $3::uuid, $4)`, oldCertDigest[:], recoveryHTTPUUID(f.accountID), recoveryHTTPUUID(f.oldDeviceID), oldCertificate); err != nil {
		t.Fatalf("insert original enrollment event: %v", err)
	}

	f.handler = NewHandlerWithRecoveryAPI(http.NotFoundHandler(), f.authorizer)
	return f
}

func (f *recoveryHTTPIntegrationFixture) cleanup() {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		f.t.Errorf("begin recovery HTTP fixture cleanup: %v", err)
		return
	}
	defer tx.Rollback()
	account := recoveryHTTPUUID(f.accountID)
	for _, statement := range []string{
		`DELETE FROM device_enrollment_challenges WHERE account_id = $1::uuid`,
	} {
		if _, err := tx.ExecContext(ctx, statement, account); err != nil {
			f.t.Errorf("clean recovery HTTP fixture: %v", err)
			return
		}
	}
	// Migration 0008 deliberately installs DELETE/TRUNCATE blockers. Disable only
	// user triggers, inside this test-only cleanup transaction, to remove this
	// fixture's rows from the explicitly verified disposable database. The triggers
	// are restored before commit; rollback also restores them if cleanup fails.
	if _, err := tx.ExecContext(ctx, `ALTER TABLE account_recovery_requests DISABLE TRIGGER account_recovery_requests_block_delete_trg`); err != nil {
		f.t.Errorf("disable recovery-request delete guard in disposable test DB: %v", err)
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_recovery_requests WHERE account_id = $1::uuid`, account); err != nil {
		f.t.Errorf("delete recovery HTTP fixture requests: %v", err)
		return
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE account_recovery_requests ENABLE TRIGGER account_recovery_requests_block_delete_trg`); err != nil {
		f.t.Errorf("restore recovery-request delete guard: %v", err)
		return
	}
	for _, statement := range []string{
		`DELETE FROM authorization_events WHERE account_id = $1::uuid`,
		`DELETE FROM authorization_devices WHERE account_id = $1::uuid`,
		`DELETE FROM device_certificates WHERE device_id IN (SELECT device_id FROM devices WHERE account_id = $1::uuid)`,
		`DELETE FROM devices WHERE account_id = $1::uuid`,
		`DELETE FROM authorization_accounts WHERE account_id = $1::uuid`,
		`DELETE FROM accounts WHERE account_id = $1::uuid`,
	} {
		if _, err := tx.ExecContext(ctx, statement, account); err != nil {
			f.t.Errorf("clean recovery HTTP fixture (%s): %v", statement, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		f.t.Errorf("commit recovery HTTP fixture cleanup: %v", err)
	}
}

func (f *recoveryHTTPIntegrationFixture) beginPayload() map[string]string {
	return map[string]string{
		"recovery_request_cbor_hex":  hex.EncodeToString(f.requestRaw),
		"enrollment_certificate_hex": hex.EncodeToString(f.targetCert),
		"recovery_public_key_hex":    hex.EncodeToString(f.recoveryPub[:]),
	}
}

func (f *recoveryHTTPIntegrationFixture) post(path string, payload any) *httptest.ResponseRecorder {
	f.t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatalf("marshal recovery HTTP request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.RemoteAddr = "127.0.0.1:43210"
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	return rr
}

func (f *recoveryHTTPIntegrationFixture) signAbort() []byte {
	f.t.Helper()
	return recoveryHTTPSignAbort(f.t, f.oldDSKPriv, f.accountID, f.oldDeviceID, 1, 2, f.requestID, sha256.Sum256(f.requestRaw))
}

func recoveryHTTPRandomID(t *testing.T) [16]byte {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("generate UUID: %v", err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

func recoveryHTTPUUID(id [16]byte) string {
	raw := hex.EncodeToString(id[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", raw[:8], raw[8:12], raw[12:16], raw[16:20], raw[20:])
}

func recoveryHTTPUintPair(key, value uint64) cbor.Pair {
	return cbor.Pair{
		Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: key}},
		Val: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: value}},
	}
}

func recoveryHTTPBytesPair(key uint64, value []byte) cbor.Pair {
	return cbor.Pair{
		Key: cbor.Value{Kind: cbor.KindInt, Int: cbor.Int{Arg: key}},
		Val: cbor.Value{Kind: cbor.KindBytes, Bytes: append([]byte(nil), value...)},
	}
}

func recoveryHTTPEncodeMap(t *testing.T, pairs []cbor.Pair) []byte {
	t.Helper()
	raw, err := cbor.EncodeCanonical(cbor.Value{Kind: cbor.KindMap, Map: pairs})
	if err != nil {
		t.Fatalf("encode canonical recovery HTTP test CBOR: %v", err)
	}
	return raw
}

func recoveryHTTPSignEnrollment(t *testing.T, private ed25519.PrivateKey, accountID [16]byte, epoch uint64, deviceID [16]byte, dskPub, ddhkPub [32]byte) []byte {
	t.Helper()
	corePairs := []cbor.Pair{
		recoveryHTTPUintPair(1, authorization.AuthorizationProtocolVersion),
		recoveryHTTPBytesPair(2, accountID[:]),
		recoveryHTTPUintPair(3, epoch),
		recoveryHTTPBytesPair(4, deviceID[:]),
		recoveryHTTPBytesPair(5, dskPub[:]),
		recoveryHTTPBytesPair(6, ddhkPub[:]),
	}
	core := recoveryHTTPEncodeMap(t, corePairs)
	signedMessage := append([]byte(authorization.DeviceEnrollmentDomain), core...)
	signature := ed25519.Sign(private, signedMessage)
	wirePairs := append(corePairs, recoveryHTTPBytesPair(7, signature))
	return recoveryHTTPEncodeMap(t, wirePairs)
}

func recoveryHTTPSignRequest(t *testing.T, private ed25519.PrivateKey, accountID [16]byte, oldEpoch, newEpoch uint64, requestID, targetDeviceID [16]byte, certificateDigest [32]byte) []byte {
	t.Helper()
	corePairs := []cbor.Pair{
		recoveryHTTPUintPair(1, authorization.AuthorizationProtocolVersion),
		recoveryHTTPBytesPair(2, accountID[:]),
		recoveryHTTPUintPair(3, oldEpoch),
		recoveryHTTPUintPair(4, newEpoch),
		recoveryHTTPBytesPair(5, requestID[:]),
		recoveryHTTPBytesPair(6, targetDeviceID[:]),
		recoveryHTTPBytesPair(7, certificateDigest[:]),
	}
	core := recoveryHTTPEncodeMap(t, corePairs)
	signedMessage := append([]byte(authorization.RecoveryRequestDomain), core...)
	signature := ed25519.Sign(private, signedMessage)
	wirePairs := append(corePairs, recoveryHTTPBytesPair(8, signature))
	return recoveryHTTPEncodeMap(t, wirePairs)
}

func recoveryHTTPSignAbort(t *testing.T, private ed25519.PrivateKey, accountID, deviceID [16]byte, oldEpoch, newEpoch uint64, requestID [16]byte, requestDigest [32]byte) []byte {
	t.Helper()
	corePairs := []cbor.Pair{
		recoveryHTTPUintPair(1, authorization.AuthorizationProtocolVersion),
		recoveryHTTPBytesPair(2, accountID[:]),
		recoveryHTTPBytesPair(3, deviceID[:]),
		recoveryHTTPUintPair(4, oldEpoch),
		recoveryHTTPUintPair(5, newEpoch),
		recoveryHTTPBytesPair(6, requestID[:]),
		recoveryHTTPBytesPair(7, requestDigest[:]),
	}
	core := recoveryHTTPEncodeMap(t, corePairs)
	signedMessage := append([]byte(authorization.RecoveryAbortDomain), core...)
	signature := ed25519.Sign(private, signedMessage)
	wirePairs := append(corePairs, recoveryHTTPBytesPair(8, signature))
	return recoveryHTTPEncodeMap(t, wirePairs)
}

func recoveryHTTPSignEnrollmentProof(t *testing.T, private ed25519.PrivateKey, accountID, deviceID [16]byte, epoch uint64, certificate []byte, challengeID [16]byte, challengeNonce [32]byte) []byte {
	t.Helper()
	certificateDigest := sha256.Sum256(certificate)
	corePairs := []cbor.Pair{
		recoveryHTTPUintPair(1, authorization.AuthorizationProtocolVersion),
		recoveryHTTPBytesPair(2, accountID[:]),
		recoveryHTTPBytesPair(3, deviceID[:]),
		recoveryHTTPUintPair(4, epoch),
		recoveryHTTPBytesPair(5, certificateDigest[:]),
		recoveryHTTPBytesPair(6, challengeID[:]),
		recoveryHTTPBytesPair(7, challengeNonce[:]),
	}
	core := recoveryHTTPEncodeMap(t, corePairs)
	signedMessage := append([]byte(authorization.DeviceEnrollmentPoPDomain), core...)
	signature := ed25519.Sign(private, signedMessage)
	wirePairs := append(corePairs, recoveryHTTPBytesPair(8, signature))
	return recoveryHTTPEncodeMap(t, wirePairs)
}

func recoveryHTTPAssertError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("HTTP status = %d, want %d; body=%s", response.Code, status, response.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode HTTP error body: %v; body=%s", err, response.Body.String())
	}
	if got["error"] != code {
		t.Fatalf("HTTP error = %q, want %q", got["error"], code)
	}
}

func recoveryHTTPDecodeState(t *testing.T, response *httptest.ResponseRecorder) recoveryRequestStateHTTPResponse {
	t.Helper()
	var state recoveryRequestStateHTTPResponse
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode recovery state response: %v; body=%s", err, response.Body.String())
	}
	return state
}

func TestRecoveryHTTPPostgresBeginAbortReplayAndAbortedChallengeIntegration(t *testing.T) {
	db := openRecoveryHTTPIntegrationDB(t)
	f := newRecoveryHTTPIntegrationFixture(t, db)

	invalidRequest := append([]byte(nil), f.requestRaw...)
	invalidRequest[len(invalidRequest)-1] ^= 0x01
	invalidPayload := f.beginPayload()
	invalidPayload["recovery_request_cbor_hex"] = hex.EncodeToString(invalidRequest)
	invalidBegin := f.post(recoveryBeginURL, invalidPayload)
	recoveryHTTPAssertError(t, invalidBegin, http.StatusBadRequest, "ERR_RECOVERY_REJECTED")
	var persistedBeforeValidRequest int64
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM account_recovery_requests WHERE account_id = $1::uuid`, recoveryHTTPUUID(f.accountID)).Scan(&persistedBeforeValidRequest); err != nil {
		cancel()
		t.Fatalf("check that invalid signed request was not persisted: %v", err)
	}
	cancel()
	if persistedBeforeValidRequest != 0 {
		t.Fatalf("invalid signed recovery request persisted %d rows", persistedBeforeValidRequest)
	}

	begin := f.post(recoveryBeginURL, f.beginPayload())
	if begin.Code != http.StatusOK {
		t.Fatalf("begin recovery: status=%d body=%s", begin.Code, begin.Body.String())
	}
	pending := recoveryHTTPDecodeState(t, begin)
	if pending.Status != string(authorization.RecoveryRequestPending) || pending.RequestIDHex != hex.EncodeToString(f.requestID[:]) {
		t.Fatalf("unexpected begin state: %+v", pending)
	}
	requestDigest := sha256.Sum256(f.requestRaw)
	if pending.RequestDigestHex != hex.EncodeToString(requestDigest[:]) {
		t.Fatalf("begin response returned wrong request digest: %s", pending.RequestDigestHex)
	}
	acceptedAt, err := time.Parse(time.RFC3339Nano, pending.AcceptedAt)
	if err != nil {
		t.Fatalf("parse accepted_at: %v", err)
	}
	finalizeAfter, err := time.Parse(time.RFC3339Nano, pending.FinalizeAfter)
	if err != nil {
		t.Fatalf("parse finalize_after: %v", err)
	}
	if finalizeAfter.Sub(acceptedAt) < 47*time.Hour || finalizeAfter.Sub(acceptedAt) > 49*time.Hour {
		t.Fatalf("recovery deadline delta = %s, expected approximately 48 hours", finalizeAfter.Sub(acceptedAt))
	}

	replay := f.post(recoveryBeginURL, f.beginPayload())
	if replay.Code != http.StatusOK {
		t.Fatalf("exact begin replay: status=%d body=%s", replay.Code, replay.Body.String())
	}
	replayed := recoveryHTTPDecodeState(t, replay)
	if replayed.RequestDigestHex != pending.RequestDigestHex || replayed.Status != pending.Status {
		t.Fatalf("exact begin replay changed state: first=%+v replay=%+v", pending, replayed)
	}

	abortRaw := f.signAbort()
	abort := f.post(recoveryAbortURL, map[string]string{"recovery_abort_cbor_hex": hex.EncodeToString(abortRaw)})
	if abort.Code != http.StatusOK {
		t.Fatalf("abort recovery: status=%d body=%s", abort.Code, abort.Body.String())
	}
	aborted := recoveryHTTPDecodeState(t, abort)
	if aborted.Status != string(authorization.RecoveryRequestAborted) || aborted.AbortingDeviceIDHex != hex.EncodeToString(f.oldDeviceID[:]) || aborted.AbortedAt == "" {
		t.Fatalf("unexpected abort state: %+v", aborted)
	}

	abortReplay := f.post(recoveryAbortURL, map[string]string{"recovery_abort_cbor_hex": hex.EncodeToString(abortRaw)})
	if abortReplay.Code != http.StatusOK || recoveryHTTPDecodeState(t, abortReplay).Status != string(authorization.RecoveryRequestAborted) {
		t.Fatalf("exact abort replay failed: status=%d body=%s", abortReplay.Code, abortReplay.Body.String())
	}

	badAbort := append([]byte(nil), abortRaw...)
	badAbort[len(badAbort)-1] ^= 0x01
	badAbortResponse := f.post(recoveryAbortURL, map[string]string{"recovery_abort_cbor_hex": hex.EncodeToString(badAbort)})
	recoveryHTTPAssertError(t, badAbortResponse, http.StatusBadRequest, "ERR_RECOVERY_REJECTED")

	challengeResponse := f.post(recoveryEnrollmentChallengeURL, map[string]string{
		"request_id_hex":             hex.EncodeToString(f.requestID[:]),
		"enrollment_certificate_hex": hex.EncodeToString(f.targetCert),
		"recovery_public_key_hex":    hex.EncodeToString(f.recoveryPub[:]),
	})
	recoveryHTTPAssertError(t, challengeResponse, http.StatusConflict, "ERR_RECOVERY_CONFLICT")
}

func TestRecoveryHTTPPostgresFinalizeReplacementChallengeAndActivationIntegration(t *testing.T) {
	db := openRecoveryHTTPIntegrationDB(t)
	f := newRecoveryHTTPIntegrationFixture(t, db)

	begin := f.post(recoveryBeginURL, f.beginPayload())
	if begin.Code != http.StatusOK {
		t.Fatalf("begin recovery: status=%d body=%s", begin.Code, begin.Body.String())
	}

	// Exercise the real finalization transaction without waiting 48 hours. This
	// mirrors the recovery lifecycle integration-test seam: disable only the
	// update guard within a transaction, move the deadline just beyond accepted_at,
	// restore the guard, then commit in the explicitly verified disposable DB.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		cancel()
		t.Fatalf("begin disposable recovery-deadline test transaction: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE account_recovery_requests DISABLE TRIGGER account_recovery_requests_guard_update_trg`); err != nil {
		_ = tx.Rollback()
		cancel()
		t.Fatalf("disable recovery update guard in test transaction: %v", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE account_recovery_requests
SET finalize_after = accepted_at + INTERVAL '1 microsecond'
WHERE request_id = $1::uuid AND status = 'PENDING'`, recoveryHTTPUUID(f.requestID))
	if err != nil {
		_ = tx.Rollback()
		cancel()
		t.Fatalf("age recovery request in disposable integration DB: %v", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		_ = tx.Rollback()
		cancel()
		t.Fatalf("aged recovery rows=%d err=%v; want one pending request", changed, err)
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE account_recovery_requests ENABLE TRIGGER account_recovery_requests_guard_update_trg`); err != nil {
		_ = tx.Rollback()
		cancel()
		t.Fatalf("restore recovery update guard: %v", err)
	}
	if err := tx.Commit(); err != nil {
		cancel()
		t.Fatalf("commit aged recovery fixture: %v", err)
	}
	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	finalized, err := f.authorizer.FinalizeRecovery(ctx, f.accountID, f.requestID)
	cancel()
	if err != nil {
		t.Fatalf("finalize recovery via lifecycle service: %v", err)
	}
	if finalized.Status != authorization.RecoveryRequestFinalized || finalized.FinalizedAt == nil {
		t.Fatalf("unexpected finalized state: %+v", finalized)
	}

	challengeResponse := f.post(recoveryEnrollmentChallengeURL, map[string]string{
		"request_id_hex":             hex.EncodeToString(f.requestID[:]),
		"enrollment_certificate_hex": hex.EncodeToString(f.targetCert),
		"recovery_public_key_hex":    hex.EncodeToString(f.recoveryPub[:]),
	})
	if challengeResponse.Code != http.StatusOK {
		t.Fatalf("issue recovery enrollment challenge: status=%d body=%s", challengeResponse.Code, challengeResponse.Body.String())
	}
	var challenge recoveryEnrollmentChallengeHTTPResponse
	if err := json.Unmarshal(challengeResponse.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("decode recovery enrollment challenge: %v", err)
	}
	challengeIDBytes, err := hex.DecodeString(challenge.ChallengeIDHex)
	if err != nil || len(challengeIDBytes) != 16 {
		t.Fatalf("invalid challenge ID response %q: %v", challenge.ChallengeIDHex, err)
	}
	nonceBytes, err := hex.DecodeString(challenge.ChallengeNonceHex)
	if err != nil || len(nonceBytes) != 32 {
		t.Fatalf("invalid challenge nonce response: %v", err)
	}
	var challengeID [16]byte
	var challengeNonce [32]byte
	copy(challengeID[:], challengeIDBytes)
	copy(challengeNonce[:], nonceBytes)
	proof := recoveryHTTPSignEnrollmentProof(t, f.targetDSKPriv, f.accountID, f.targetDeviceID, 2, f.targetCert, challengeID, challengeNonce)

	activatePayload := map[string]string{
		"request_id_hex":             hex.EncodeToString(f.requestID[:]),
		"enrollment_certificate_hex": hex.EncodeToString(f.targetCert),
		"proof_hex":                  hex.EncodeToString(proof),
		"recovery_public_key_hex":    hex.EncodeToString(f.recoveryPub[:]),
	}
	activation := f.post(recoveryEnrollmentActivateURL, activatePayload)
	if activation.Code != http.StatusNoContent {
		t.Fatalf("activate replacement device: status=%d body=%s", activation.Code, activation.Body.String())
	}
	activationReplay := f.post(recoveryEnrollmentActivateURL, activatePayload)
	if activationReplay.Code != http.StatusNoContent {
		t.Fatalf("exact activation replay: status=%d body=%s", activationReplay.Code, activationReplay.Body.String())
	}

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var accountEpoch, authorizationEpoch, accountStatus int64
	if err := db.QueryRowContext(ctx, `SELECT a.account_epoch, aa.epoch, aa.status
FROM accounts a JOIN authorization_accounts aa USING (account_id)
WHERE a.account_id = $1::uuid`, recoveryHTTPUUID(f.accountID)).Scan(&accountEpoch, &authorizationEpoch, &accountStatus); err != nil {
		t.Fatalf("read recovered account state: %v", err)
	}
	if accountEpoch != 2 || authorizationEpoch != 2 || accountStatus != int64(authorization.AccountActive) {
		t.Fatalf("recovered account state epoch=%d auth_epoch=%d status=%d; want 2/2/ACTIVE", accountEpoch, authorizationEpoch, accountStatus)
	}
	var oldDeviceStatus, targetDeviceStatus int64
	var oldRevoked, targetRevoked bool
	if err := db.QueryRowContext(ctx, `SELECT ad.status, (d.revoked_at IS NOT NULL)
FROM authorization_devices ad JOIN devices d USING (device_id)
WHERE ad.account_id = $1::uuid AND ad.device_id = $2::uuid`, recoveryHTTPUUID(f.accountID), recoveryHTTPUUID(f.oldDeviceID)).Scan(&oldDeviceStatus, &oldRevoked); err != nil {
		t.Fatalf("read original device state: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT ad.status, (d.revoked_at IS NOT NULL)
FROM authorization_devices ad JOIN devices d USING (device_id)
WHERE ad.account_id = $1::uuid AND ad.device_id = $2::uuid`, recoveryHTTPUUID(f.accountID), recoveryHTTPUUID(f.targetDeviceID)).Scan(&targetDeviceStatus, &targetRevoked); err != nil {
		t.Fatalf("read replacement device state: %v", err)
	}
	if oldDeviceStatus != int64(authorization.DeviceRevoked) || !oldRevoked || targetDeviceStatus != int64(authorization.DeviceActive) || targetRevoked {
		t.Fatalf("device states old=(status %d revoked %v) target=(status %d revoked %v)", oldDeviceStatus, oldRevoked, targetDeviceStatus, targetRevoked)
	}
	var challengeConsumed bool
	if err := db.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL FROM device_enrollment_challenges WHERE challenge_id = $1::uuid`, recoveryHTTPUUID(challengeID)).Scan(&challengeConsumed); err != nil {
		t.Fatalf("read recovery challenge consumption: %v", err)
	}
	if !challengeConsumed {
		t.Fatal("replacement enrollment challenge was not consumed")
	}

	finalizeRoute := f.post("/v1/recovery/finalize", map[string]string{})
	recoveryHTTPAssertError(t, finalizeRoute, http.StatusNotFound, "ERR_NOT_FOUND")
}
