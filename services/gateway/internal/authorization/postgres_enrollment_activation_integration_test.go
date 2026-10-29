package authorization

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const candidateEnrollmentIntegrationDSNEnv = "PM_ENROLLMENT_TEST_DATABASE_URL"
const candidateEnrollmentIntegrationDatabase = "pm_enrollment_test_20261030"

// These integration tests are intentionally opt-in and are restricted to the
// explicitly named disposable database above. They never create or migrate a DB.
func openCandidateEnrollmentIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(candidateEnrollmentIntegrationDSNEnv))
	if dsn == "" {
		t.Skip("set PM_ENROLLMENT_TEST_DATABASE_URL to run PostgreSQL enrollment integration tests")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL integration database: %v", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping PostgreSQL integration database: %v", err)
	}
       var databaseName, serverAddress, schemaName string
       var serverPort int
       var inRecovery bool
       if err := db.QueryRowContext(ctx, `
               SELECT current_database(),
                      COALESCE(host(inet_server_addr()), ''),
                      COALESCE(inet_server_port(), 0),
                      current_schema(),
                      pg_is_in_recovery()
       `).Scan(&databaseName, &serverAddress, &serverPort, &schemaName, &inRecovery); err != nil {
               t.Fatalf("inspect PostgreSQL integration connection: %v", err)
       }
       if databaseName != candidateEnrollmentIntegrationDatabase {
               t.Fatalf("safety stop: integration tests are restricted to database %q, connected to %q", candidateEnrollmentIntegrationDatabase, databaseName)
       }
       if serverAddress != "127.0.0.1" || serverPort != 5432 || schemaName != "public" || inRecovery {
               t.Fatalf("safety stop: expected local primary PostgreSQL at 127.0.0.1:5432 with public schema; got address=%q port=%d schema=%q in_recovery=%v", serverAddress, serverPort, schemaName, inRecovery)
       }

	var schemaReady bool
	if err := db.QueryRowContext(ctx, `SELECT
		to_regclass('public.accounts') IS NOT NULL AND
		to_regclass('public.devices') IS NOT NULL AND
		to_regclass('public.device_certificates') IS NOT NULL AND
		to_regclass('public.authorization_accounts') IS NOT NULL AND
		to_regclass('public.authorization_devices') IS NOT NULL AND
		to_regclass('public.authorization_events') IS NOT NULL AND
		to_regclass('public.device_enrollment_challenges') IS NOT NULL`).Scan(&schemaReady); err != nil {
		t.Fatalf("inspect PostgreSQL integration schema: %v", err)
	}
	if !schemaReady {
		t.Fatal("integration schema is incomplete; apply migrations 0001 through 0005 to the dedicated test database first")
	}
	return db
}

type candidateEnrollmentPGFixture struct {
	t              *testing.T
	db             *sql.DB
	authorizer     *PostgresAuthorizer
	accountID      [16]byte
	deviceID       [16]byte
	recoveryPublic [32]byte
	recoveryPriv   ed25519.PrivateKey
	dskPrivate     ed25519.PrivateKey
	certificate    DeviceEnrollmentAuthorizationV1
}

func newCandidateEnrollmentPGFixture(t *testing.T, db *sql.DB) *candidateEnrollmentPGFixture {
	t.Helper()

	accountID := randomCandidateEnrollmentID(t)
	deviceID := randomCandidateEnrollmentID(t)

	recoveryPublicKey, recoveryPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate recovery key: %v", err)
	}
	var recoveryPublic [32]byte
	copy(recoveryPublic[:], recoveryPublicKey)

	dskPublicKey, dskPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate DSK: %v", err)
	}
	var dskPublic [32]byte
	copy(dskPublic[:], dskPublicKey)

	ddhkPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate DDHK: %v", err)
	}
	var ddhkPublic [32]byte
	copy(ddhkPublic[:], ddhkPrivateKey.PublicKey().Bytes())

	commitment := RecoveryCommitment(recoveryPublic)
	username := "pm-enroll-it-" + hex.EncodeToString(accountID[:])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `INSERT INTO accounts (account_id, username, account_epoch, irc)
VALUES ($1::uuid, $2, 1, $3)`, uuidText(accountID), username, commitment[:]); err != nil {
		t.Fatalf("insert test account: %v", err)
	}

	f := &candidateEnrollmentPGFixture{
		t: t, db: db, authorizer: NewPostgresAuthorizer(db),
		accountID: accountID, deviceID: deviceID,
		recoveryPublic: recoveryPublic, recoveryPriv: recoveryPrivateKey,
		dskPrivate: dskPrivateKey,
	}
	t.Cleanup(func() { f.cleanup() })

	if _, err := db.ExecContext(ctx, `INSERT INTO authorization_accounts
(account_id, epoch, recovery_commitment, recovery_pub, status)
VALUES ($1::uuid, 1, $2, $3, $4)`, uuidText(accountID), commitment[:], recoveryPublic[:], int(AccountActive)); err != nil {
		t.Fatalf("insert test authorization account: %v", err)
	}
	f.certificate = testEnrollmentCert(t, recoveryPrivateKey, accountID, deviceID, 1, dskPublic, ddhkPublic)
	return f
}

func randomCandidateEnrollmentID(t *testing.T) [16]byte {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("generate UUID bytes: %v", err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

func (f *candidateEnrollmentPGFixture) cleanup() {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	account := uuidText(f.accountID)
	statements := []string{
		`DELETE FROM authorization_events WHERE account_id = $1::uuid`,
		`DELETE FROM device_enrollment_challenges WHERE account_id = $1::uuid`,
		`DELETE FROM authorization_devices WHERE account_id = $1::uuid`,
		`DELETE FROM delivery_acks WHERE envelope_id IN (SELECT envelope_id FROM message_envelopes WHERE recipient_device IN (SELECT device_id FROM devices WHERE account_id = $1::uuid))`,
		`DELETE FROM message_envelopes WHERE recipient_device IN (SELECT device_id FROM devices WHERE account_id = $1::uuid)`,
		`DELETE FROM media_upload_sessions WHERE owner_device IN (SELECT device_id FROM devices WHERE account_id = $1::uuid)`,
		`DELETE FROM notification_state WHERE device_id IN (SELECT device_id FROM devices WHERE account_id = $1::uuid)`,
		`DELETE FROM signed_prekeys WHERE device_id IN (SELECT device_id FROM devices WHERE account_id = $1::uuid)`,
		`DELETE FROM one_time_prekeys WHERE device_id IN (SELECT device_id FROM devices WHERE account_id = $1::uuid)`,
		`DELETE FROM device_certificates WHERE device_id IN (SELECT device_id FROM devices WHERE account_id = $1::uuid)`,
		`DELETE FROM devices WHERE account_id = $1::uuid`,
		`DELETE FROM authorization_accounts WHERE account_id = $1::uuid`,
		`DELETE FROM accounts WHERE account_id = $1::uuid`,
	}
	for _, statement := range statements {
		if _, err := f.db.ExecContext(ctx, statement, account); err != nil {
			f.t.Errorf("clean up PostgreSQL integration fixture (%s): %v", statement, err)
		}
	}
}

func (f *candidateEnrollmentPGFixture) issueChallenge() (EnrollmentChallenge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return f.authorizer.IssueCandidateEnrollmentChallenge(ctx, f.certificate.Raw, f.recoveryPublic)
}

func (f *candidateEnrollmentPGFixture) proofFor(challenge EnrollmentChallenge) []byte {
	f.t.Helper()
	digest := sha256.Sum256(f.certificate.Raw)
	proof := DeviceEnrollmentPoPV1{
		AccountID:                   f.certificate.AccountID,
		DeviceID:                    f.certificate.DeviceID,
		Epoch:                       f.certificate.Epoch,
		EnrollmentCertificateDigest: digest,
		ChallengeID:                 challenge.ID,
		ChallengeNonce:              challenge.Nonce,
	}
	core, err := proof.canonicalCore()
	if err != nil {
		f.t.Fatalf("encode device proof core: %v", err)
	}
	message := append([]byte(DeviceEnrollmentPoPDomain), core...)
	copy(proof.Signature[:], ed25519.Sign(f.dskPrivate, message))
	return deviceEnrollmentPoPWireForTest(f.t, proof.AccountID, proof.DeviceID, proof.Epoch,
		proof.EnrollmentCertificateDigest, proof.ChallengeID, proof.ChallengeNonce, proof.Signature)
}

func (f *candidateEnrollmentPGFixture) activate(proof []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return f.authorizer.ActivateCandidateEnrollment(ctx, f.certificate.Raw, proof, f.recoveryPublic)
}

func assertCandidateEnrollmentPGState(t *testing.T, f *candidateEnrollmentPGFixture, challenge EnrollmentChallenge, activated, consumed bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var devices, certificates, authDevices, enrollmentEvents int64
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM devices WHERE device_id = $1::uuid`, uuidText(f.deviceID)).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM device_certificates WHERE device_id = $1::uuid`, uuidText(f.deviceID)).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM authorization_devices WHERE device_id = $1::uuid`, uuidText(f.deviceID)).Scan(&authDevices); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM authorization_events WHERE account_id = $1::uuid AND target_device_id = $2::uuid AND kind = 'ENROLL'`, uuidText(f.accountID), uuidText(f.deviceID)).Scan(&enrollmentEvents); err != nil {
		t.Fatal(err)
	}
	var isConsumed bool
	if err := f.db.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL FROM device_enrollment_challenges WHERE challenge_id = $1::uuid`, uuidText(challenge.ID)).Scan(&isConsumed); err != nil {
		t.Fatal(err)
	}

	want := int64(0)
	if activated {
		want = 1
	}
	if devices != want || certificates != want || authDevices != want || enrollmentEvents != want {
		t.Fatalf("unexpected activation rows: devices=%d certificates=%d authorization_devices=%d enrollment_events=%d; want each %d", devices, certificates, authDevices, enrollmentEvents, want)
	}
	if isConsumed != consumed {
		t.Fatalf("challenge consumed=%v, want %v", isConsumed, consumed)
	}
}

func TestPostgresCandidateEnrollmentSuccessAndIdempotentRetryIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)
	f := newCandidateEnrollmentPGFixture(t, db)
	challenge, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	proof := f.proofFor(challenge)
	if err := f.activate(proof); err != nil {
		t.Fatalf("valid activation failed: %v", err)
	}
	assertCandidateEnrollmentPGState(t, f, challenge, true, true)

	if err := f.activate(proof); err != nil {
		t.Fatalf("exact successful retry should be idempotent: %v", err)
	}
	assertCandidateEnrollmentPGState(t, f, challenge, true, true)
	if _, err := f.issueChallenge(); !errors.Is(err, ErrDeviceExists) {
		t.Fatalf("second challenge for already enrolled device: got %v, want ErrDeviceExists", err)
	}
}

func TestPostgresCandidateEnrollmentRetryRejectsInconsistentEventEpochIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)
	f := newCandidateEnrollmentPGFixture(t, db)
	challenge, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	proof := f.proofFor(challenge)
	if err := f.activate(proof); err != nil {
		t.Fatalf("valid activation failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	digest := sha256.Sum256(f.certificate.Raw)
	_, err = db.ExecContext(ctx, `UPDATE authorization_events SET new_epoch = new_epoch + 1 WHERE auth_digest = $1`, digest[:])
	cancel()
	if err != nil {
		t.Fatalf("corrupt event epoch for regression test: %v", err)
	}
	if err := f.activate(proof); !errors.Is(err, ErrEnrollmentChallengeConsumed) {
		t.Fatalf("retry with inconsistent event epoch: got %v, want ErrEnrollmentChallengeConsumed", err)
	}
}

func TestPostgresCandidateEnrollmentRetryRejectsRevokedDeviceIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)
	f := newCandidateEnrollmentPGFixture(t, db)
	challenge, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	proof := f.proofFor(challenge)
	if err := f.activate(proof); err != nil {
		t.Fatalf("valid activation failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = db.ExecContext(ctx, `UPDATE authorization_devices SET revoked_epoch = 1 WHERE device_id = $1::uuid AND account_id = $2::uuid`, uuidText(f.deviceID), uuidText(f.accountID))
	cancel()
	if err != nil {
		t.Fatalf("mark device revoked for regression test: %v", err)
	}
	if err := f.activate(proof); !errors.Is(err, ErrEnrollmentChallengeConsumed) {
		t.Fatalf("retry for revoked device: got %v, want ErrEnrollmentChallengeConsumed", err)
	}
}
func TestPostgresCandidateEnrollmentRetryRejectsInconsistentAuthorizationDeviceKeysIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)
	f := newCandidateEnrollmentPGFixture(t, db)
	challenge, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	proof := f.proofFor(challenge)
	if err := f.activate(proof); err != nil {
		t.Fatalf("valid activation failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	badDSK := append([]byte(nil), f.certificate.DSKPub[:]...)
	badDSK[0] ^= 0xff
	result, err := db.ExecContext(ctx, `UPDATE authorization_devices
SET dsk_pub = $1
WHERE account_id = $2::uuid AND device_id = $3::uuid`,
		badDSK, uuidText(f.accountID), uuidText(f.deviceID))
	if err != nil {
		t.Fatalf("corrupt authorization-device DSK for regression test: %v", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		t.Fatalf("authorization-device DSK update rows=%d err=%v; want one row", changed, err)
	}
	if err := f.activate(proof); !errors.Is(err, ErrEnrollmentChallengeConsumed) {
		t.Fatalf("retry with inconsistent authorization-device DSK: got %v, want ErrEnrollmentChallengeConsumed", err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE authorization_devices
SET dsk_pub = $1
WHERE account_id = $2::uuid AND device_id = $3::uuid`,
		f.certificate.DSKPub[:], uuidText(f.accountID), uuidText(f.deviceID)); err != nil {
		t.Fatalf("restore authorization-device DSK: %v", err)
	}

	badDDHK := append([]byte(nil), f.certificate.DDHKPub[:]...)
	badDDHK[0] ^= 0xff
	result, err = db.ExecContext(ctx, `UPDATE authorization_devices
SET ddhk_pub = $1
WHERE account_id = $2::uuid AND device_id = $3::uuid`,
		badDDHK, uuidText(f.accountID), uuidText(f.deviceID))
	if err != nil {
		t.Fatalf("corrupt authorization-device DDHK for regression test: %v", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		t.Fatalf("authorization-device DDHK update rows=%d err=%v; want one row", changed, err)
	}
	if err := f.activate(proof); !errors.Is(err, ErrEnrollmentChallengeConsumed) {
		t.Fatalf("retry with inconsistent authorization-device DDHK: got %v, want ErrEnrollmentChallengeConsumed", err)
	}
}
func TestPostgresCandidateEnrollmentInvalidProofDoesNotActivateIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)
	f := newCandidateEnrollmentPGFixture(t, db)
	challenge, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	proof := f.proofFor(challenge)
	proof[len(proof)-1] ^= 0x01
	if err := f.activate(proof); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("invalid proof activation: got %v, want ErrInvalidAuthorization", err)
	}
	assertCandidateEnrollmentPGState(t, f, challenge, false, false)
}

func TestPostgresCandidateEnrollmentExpiredChallengeDoesNotActivateIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)
	f := newCandidateEnrollmentPGFixture(t, db)
	challenge, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	proof := f.proofFor(challenge)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = db.ExecContext(ctx, `UPDATE device_enrollment_challenges
SET created_at = clock_timestamp() - INTERVAL '10 minutes',
    expires_at = clock_timestamp() - INTERVAL '1 second'
WHERE challenge_id = $1::uuid`, uuidText(challenge.ID))
	cancel()
	if err != nil {
		t.Fatalf("expire challenge in test database: %v", err)
	}
	if err := f.activate(proof); !errors.Is(err, ErrEnrollmentChallengeExpired) {
		t.Fatalf("expired challenge activation: got %v, want ErrEnrollmentChallengeExpired", err)
	}
	assertCandidateEnrollmentPGState(t, f, challenge, false, false)
}

func TestPostgresCandidateEnrollmentInsertFailureRollsBackIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)
	f := newCandidateEnrollmentPGFixture(t, db)
	challenge, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	proof := f.proofFor(challenge)
	digest := sha256.Sum256(f.certificate.Raw)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = db.ExecContext(ctx, `INSERT INTO authorization_events
(auth_digest, kind, account_id, old_epoch, new_epoch, target_device_id, cert_cbor)
VALUES ($1, 'TRANSITION', $2::uuid, 1, 1, $3::uuid, $4)`,
		digest[:], uuidText(f.accountID), uuidText(f.deviceID), []byte("deliberate conflicting digest for rollback test"))
	cancel()
	if err != nil {
		t.Fatalf("seed deliberate digest conflict: %v", err)
	}
	if err := f.activate(proof); err == nil {
		t.Fatal("activation succeeded despite deliberate authorization_events primary-key conflict")
	}
	assertCandidateEnrollmentPGState(t, f, challenge, false, false)
}

func TestPostgresCandidateEnrollmentStaleEpochDoesNotActivateIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)
	f := newCandidateEnrollmentPGFixture(t, db)
	challenge, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	proof := f.proofFor(challenge)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = db.ExecContext(ctx, `UPDATE accounts SET account_epoch = 2 WHERE account_id = $1::uuid`, uuidText(f.accountID))
	if err == nil {
		_, err = db.ExecContext(ctx, `UPDATE authorization_accounts SET epoch = 2 WHERE account_id = $1::uuid`, uuidText(f.accountID))
	}
	cancel()
	if err != nil {
		t.Fatalf("advance test account epoch: %v", err)
	}
	if err := f.activate(proof); !errors.Is(err, ErrInvalidEpoch) {
		t.Fatalf("stale epoch activation: got %v, want ErrInvalidEpoch", err)
	}
	assertCandidateEnrollmentPGState(t, f, challenge, false, false)
}

func TestPostgresCandidateEnrollmentConcurrentExactRetryIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)
	f := newCandidateEnrollmentPGFixture(t, db)
	challenge, err := f.issueChallenge()
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	proof := f.proofFor(challenge)

	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer workers.Done()
			<-start
			results <- f.activate(proof)
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent exact activation/retry failed: %v", err)
		}
	}
	assertCandidateEnrollmentPGState(t, f, challenge, true, true)
}
