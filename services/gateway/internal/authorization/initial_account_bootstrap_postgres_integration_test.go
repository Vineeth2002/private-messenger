package authorization

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
)

type initialBootstrapRaceResult struct {
	operation string
	challenge EnrollmentChallenge
	err       error
}

func initialBootstrapRaceMaterial(
	t *testing.T,
) (DeviceEnrollmentAuthorizationV1, [32]byte, ed25519.PrivateKey) {
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

	cert := testEnrollmentCert(
		t,
		recoveryPrivateKey,
		accountID,
		deviceID,
		1,
		dskPublic,
		ddhkPublic,
	)

	return cert, recoveryPublic, dskPrivateKey
}

func initialBootstrapProofForTest(
	t *testing.T,
	cert DeviceEnrollmentAuthorizationV1,
	challenge EnrollmentChallenge,
	dskPrivate ed25519.PrivateKey,
) []byte {
	t.Helper()

	digest := sha256.Sum256(cert.Raw)

	proof := DeviceEnrollmentPoPV1{
		AccountID:                   cert.AccountID,
		DeviceID:                    cert.DeviceID,
		Epoch:                       cert.Epoch,
		EnrollmentCertificateDigest: digest,
		ChallengeID:                 challenge.ID,
		ChallengeNonce:              challenge.Nonce,
	}

	core, err := proof.canonicalCore()
	if err != nil {
		t.Fatalf("encode bootstrap proof core: %v", err)
	}

	message := append([]byte(DeviceEnrollmentPoPDomain), core...)
	signature := ed25519.Sign(dskPrivate, message)
	copy(proof.Signature[:], signature)

	return deviceEnrollmentPoPWireForTest(
		t,
		proof.AccountID,
		proof.DeviceID,
		proof.Epoch,
		proof.EnrollmentCertificateDigest,
		proof.ChallengeID,
		proof.ChallengeNonce,
		proof.Signature,
	)
}

func waitForBootstrapAdvisoryWaiters(
	ctx context.Context,
	db *sql.DB,
	blockerPID int,
	minimum int,
) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		var waiters int

		err := db.QueryRowContext(ctx, `
SELECT count(*)
FROM pg_stat_activity AS waiter
WHERE waiter.wait_event_type = 'Lock'
  AND waiter.wait_event = 'advisory'
  AND $1 = ANY(pg_blocking_pids(waiter.pid))
  AND waiter.query LIKE '%pg_advisory_xact_lock%'
`, blockerPID).Scan(&waiters)
		if err != nil {
			return fmt.Errorf("inspect advisory-lock waiters: %w", err)
		}

		if waiters >= minimum {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"timed out waiting for at least %d advisory-lock waiter(s): %w",
				minimum,
				ctx.Err(),
			)
		case <-ticker.C:
		}
	}
}

func TestPostgresInitialBootstrapConcurrentIssueAndActivateIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	var schemaReady bool
	err := db.QueryRowContext(ctx, `
SELECT
    to_regclass('public.initial_account_bootstrap_challenges') IS NOT NULL
    AND EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = to_regclass('public.initial_account_bootstrap_challenges')
          AND tgname = 'initial_account_bootstrap_guard_lifecycle_trg'
          AND NOT tgisinternal
          AND tgenabled = 'O'
    )
`).Scan(&schemaReady)
	if err != nil {
		t.Fatalf("inspect bootstrap integration schema: %v", err)
	}
	if !schemaReady {
		t.Fatal("initial-account-bootstrap table or enabled lifecycle trigger is missing")
	}

	cert, recoveryPublic, dskPrivate := initialBootstrapRaceMaterial(t)
	accountID := uuidText(cert.AccountID)
	authorizer := NewPostgresAuthorizer(db)

	var accountOrDeviceExists bool
	err = db.QueryRowContext(ctx, `
SELECT
    EXISTS (SELECT 1 FROM accounts WHERE account_id = $1::uuid)
    OR EXISTS (SELECT 1 FROM authorization_accounts WHERE account_id = $1::uuid)
    OR EXISTS (SELECT 1 FROM devices WHERE device_id = $2::uuid)
    OR EXISTS (SELECT 1 FROM authorization_devices WHERE device_id = $2::uuid)
`, accountID, uuidText(cert.DeviceID)).Scan(&accountOrDeviceExists)
	if err != nil {
		t.Fatalf("check generated bootstrap fixture identifiers: %v", err)
	}
	if accountOrDeviceExists {
		t.Fatal("random bootstrap fixture identifiers unexpectedly already exist")
	}

	// This integration test intentionally uses the guarded disposable database.
	// If activation wins, migration 0012 makes its authorization event append-only.
	// Do not attempt to erase that event or disable its protection during cleanup.

	challengeA, err := authorizer.IssueInitialAccountBootstrapChallenge(
		ctx,
		cert.Raw,
		recoveryPublic,
	)
	if err != nil {
		t.Fatalf("issue original bootstrap challenge: %v", err)
	}

	proofA := initialBootstrapProofForTest(t, cert, challengeA, dskPrivate)

	// Hold the exact advisory lock used by both production operations.
	blockerConn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("obtain advisory-lock blocker connection: %v", err)
	}
	defer blockerConn.Close()

	blockerTx, err := blockerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin advisory-lock blocker transaction: %v", err)
	}
	defer blockerTx.Rollback()

	var blockerPID int
	if err := blockerConn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatalf("read advisory-lock blocker PID: %v", err)
	}

	if _, err := blockerTx.ExecContext(
		ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		accountID,
	); err != nil {
		t.Fatalf("acquire bootstrap advisory lock: %v", err)
	}

	results := make(chan initialBootstrapRaceResult, 2)

	// Start challenge replacement first and wait until PostgreSQL confirms
	// that it is blocked by our transaction.
	go func() {
		challenge, issueErr := authorizer.IssueInitialAccountBootstrapChallenge(
			ctx,
			cert.Raw,
			recoveryPublic,
		)
		results <- initialBootstrapRaceResult{
			operation: "issue",
			challenge: challenge,
			err:       issueErr,
		}
	}()

	if err := waitForBootstrapAdvisoryWaiters(ctx, db, blockerPID, 1); err != nil {
		t.Fatalf("replacement issuance did not reach the advisory lock: %v", err)
	}

	// Start activation of the original challenge while replacement issuance
	// is already queued on the same account lock.
	go func() {
		activationErr := authorizer.ActivateInitialAccountBootstrap(
			ctx,
			cert.Raw,
			proofA,
			recoveryPublic,
		)
		results <- initialBootstrapRaceResult{
			operation: "activate",
			err:       activationErr,
		}
	}()

	if err := waitForBootstrapAdvisoryWaiters(ctx, db, blockerPID, 2); err != nil {
		t.Fatalf("both operations did not reach the advisory lock: %v", err)
	}

	// Release both operations only after PostgreSQL confirms both are waiting.
	if err := blockerTx.Commit(); err != nil {
		t.Fatalf("release bootstrap advisory lock: %v", err)
	}

	var issueResult initialBootstrapRaceResult
	var activationResult initialBootstrapRaceResult

	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			switch result.operation {
			case "issue":
				issueResult = result
			case "activate":
				activationResult = result
			default:
				t.Fatalf("unexpected operation result: %q", result.operation)
			}
		case <-ctx.Done():
			t.Fatalf("timed out collecting concurrent operation results: %v", ctx.Err())
		}
	}

	if issueResult.operation == "" || activationResult.operation == "" {
		t.Fatalf("missing operation results: issue=%q activation=%q",
			issueResult.operation, activationResult.operation)
	}

	// Read the complete persisted outcome. Exactly one of the two serial
	// orders is valid:
	//
	//  1. Replacement issuance wins:
	//     A is consumed, B remains live, activation of A is rejected.
	//
	//  2. Bootstrap activation wins:
	//     A is consumed, the account/device/event are committed, and the
	//     replacement issuance is rejected because the account now exists.
	var accounts, authorizationAccounts int64
	var devices, certificates, authorizationDevices, events int64

	err = db.QueryRowContext(ctx, `
SELECT
    (SELECT count(*) FROM accounts WHERE account_id = $1::uuid),
    (SELECT count(*) FROM authorization_accounts WHERE account_id = $1::uuid),
    (SELECT count(*) FROM devices WHERE account_id = $1::uuid),
    (SELECT count(*) FROM device_certificates WHERE device_id = $2::uuid),
    (SELECT count(*) FROM authorization_devices WHERE account_id = $1::uuid),
    (SELECT count(*) FROM authorization_events WHERE account_id = $1::uuid)
`, accountID, uuidText(cert.DeviceID)).Scan(
		&accounts,
		&authorizationAccounts,
		&devices,
		&certificates,
		&authorizationDevices,
		&events,
	)
	if err != nil {
		t.Fatalf("inspect bootstrap activation state: %v", err)
	}

	var challengeRows, liveChallenges int64
	var originalConsumed, replacementLive int64

	err = db.QueryRowContext(ctx, `
SELECT
    count(*),
    count(*) FILTER (WHERE consumed_at IS NULL),
    count(*) FILTER (
        WHERE challenge_id = $2::uuid AND consumed_at IS NOT NULL
    ),
    count(*) FILTER (
        WHERE challenge_id = $3::uuid AND consumed_at IS NULL
    )
FROM initial_account_bootstrap_challenges
WHERE account_id = $1::uuid
`, accountID, uuidText(challengeA.ID), uuidText(issueResult.challenge.ID)).Scan(
		&challengeRows,
		&liveChallenges,
		&originalConsumed,
		&replacementLive,
	)
	if err != nil {
		t.Fatalf("inspect bootstrap challenge states: %v", err)
	}

	if originalConsumed != 1 {
		t.Fatalf("original challenge consumed rows=%d; want exactly 1", originalConsumed)
	}

	switch {
	case issueResult.err == nil &&
		errors.Is(activationResult.err, ErrEnrollmentChallengeConsumed):

		if issueResult.challenge.ID == ([16]byte{}) {
			t.Fatal("replacement issuance returned an empty challenge ID")
		}

		if accounts != 0 ||
			authorizationAccounts != 0 ||
			devices != 0 ||
			certificates != 0 ||
			authorizationDevices != 0 ||
			events != 0 {
			t.Fatalf(
				"replacement-first outcome created partial bootstrap state: accounts=%d authorization_accounts=%d devices=%d certificates=%d authorization_devices=%d events=%d",
				accounts,
				authorizationAccounts,
				devices,
				certificates,
				authorizationDevices,
				events,
			)
		}

		if challengeRows != 2 ||
			liveChallenges != 1 ||
			replacementLive != 1 {
			t.Fatalf(
				"replacement-first challenge state: rows=%d live=%d replacement_live=%d; want 2, 1, 1",
				challengeRows,
				liveChallenges,
				replacementLive,
			)
		}

		t.Log("valid serialization: replacement challenge issued first; original activation rejected")

	case errors.Is(issueResult.err, ErrAccountExists) &&
		activationResult.err == nil:

		if accounts != 1 ||
			authorizationAccounts != 1 ||
			devices != 1 ||
			certificates != 1 ||
			authorizationDevices != 1 ||
			events != 1 {
			t.Fatalf(
				"activation-first outcome has incomplete state: accounts=%d authorization_accounts=%d devices=%d certificates=%d authorization_devices=%d events=%d",
				accounts,
				authorizationAccounts,
				devices,
				certificates,
				authorizationDevices,
				events,
			)
		}

		if challengeRows != 1 ||
			liveChallenges != 0 ||
			replacementLive != 0 {
			t.Fatalf(
				"activation-first challenge state: rows=%d live=%d replacement_live=%d; want 1, 0, 0",
				challengeRows,
				liveChallenges,
				replacementLive,
			)
		}

		t.Log("valid serialization: bootstrap activation committed first; replacement issuance rejected")

	default:
		t.Fatalf(
			"invalid concurrent outcome: issue_err=%v activation_err=%v",
			issueResult.err,
			activationResult.err,
		)
	}
}

// Test the opposite advisory-lock queue order: activation is waiting first,
// then challenge replacement joins the same account lock queue.
func TestPostgresInitialBootstrapConcurrentActivateAndIssueIntegration(t *testing.T) {
	db := openCandidateEnrollmentIntegrationDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	var schemaReady bool
	if err := db.QueryRowContext(ctx, `
SELECT
    to_regclass('public.initial_account_bootstrap_challenges') IS NOT NULL
    AND EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = to_regclass('public.initial_account_bootstrap_challenges')
          AND tgname = 'initial_account_bootstrap_guard_lifecycle_trg'
          AND NOT tgisinternal
          AND tgenabled = 'O'
    )
`).Scan(&schemaReady); err != nil {
		t.Fatalf("inspect bootstrap integration schema: %v", err)
	}
	if !schemaReady {
		t.Fatal("bootstrap challenge table or enabled lifecycle trigger is missing")
	}

	cert, recoveryPublic, dskPrivate := initialBootstrapRaceMaterial(t)
	accountID := uuidText(cert.AccountID)
	authorizer := NewPostgresAuthorizer(db)

	challengeA, err := authorizer.IssueInitialAccountBootstrapChallenge(
		ctx, cert.Raw, recoveryPublic,
	)
	if err != nil {
		t.Fatalf("issue original bootstrap challenge: %v", err)
	}
	proofA := initialBootstrapProofForTest(t, cert, challengeA, dskPrivate)

	blockerConn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("obtain advisory-lock blocker connection: %v", err)
	}
	defer blockerConn.Close()

	blockerTx, err := blockerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin advisory-lock blocker transaction: %v", err)
	}
	defer blockerTx.Rollback()

	var blockerPID int
	if err := blockerConn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatalf("read advisory-lock blocker PID: %v", err)
	}

	if _, err := blockerTx.ExecContext(
		ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		accountID,
	); err != nil {
		t.Fatalf("acquire bootstrap advisory lock: %v", err)
	}

	activationResult := make(chan error, 1)
	issueResult := make(chan initialBootstrapRaceResult, 1)

	// Queue activation first.
	go func() {
		activationResult <- authorizer.ActivateInitialAccountBootstrap(
			ctx, cert.Raw, proofA, recoveryPublic,
		)
	}()

	if err := waitForBootstrapAdvisoryWaiters(ctx, db, blockerPID, 1); err != nil {
		t.Fatalf("activation did not reach advisory lock: %v", err)
	}

	// Queue replacement issuance second, behind activation.
	go func() {
		challenge, issueErr := authorizer.IssueInitialAccountBootstrapChallenge(
			ctx, cert.Raw, recoveryPublic,
		)
		issueResult <- initialBootstrapRaceResult{
			operation: "issue",
			challenge: challenge,
			err:       issueErr,
		}
	}()

	if err := waitForBootstrapAdvisoryWaiters(ctx, db, blockerPID, 2); err != nil {
		t.Fatalf("both operations did not reach advisory lock: %v", err)
	}

	if err := blockerTx.Commit(); err != nil {
		t.Fatalf("release bootstrap advisory lock: %v", err)
	}

	var activationErr error
	select {
	case activationErr = <-activationResult:
	case <-ctx.Done():
		t.Fatalf("timed out collecting activation result: %v", ctx.Err())
	}

	var issue initialBootstrapRaceResult
	select {
	case issue = <-issueResult:
	case <-ctx.Done():
		t.Fatalf("timed out collecting replacement issuance result: %v", ctx.Err())
	}

	if activationErr != nil {
		t.Fatalf("activation was queued first but failed: %v", activationErr)
	}
	if !errors.Is(issue.err, ErrAccountExists) {
		t.Fatalf("replacement issuance after activation: got %v, want ErrAccountExists", issue.err)
	}

	var accounts, authorizationAccounts int64
	var devices, certificates, authorizationDevices, events int64
	err = db.QueryRowContext(ctx, `
SELECT
    (SELECT count(*) FROM accounts WHERE account_id = $1::uuid),
    (SELECT count(*) FROM authorization_accounts WHERE account_id = $1::uuid),
    (SELECT count(*) FROM devices WHERE account_id = $1::uuid),
    (SELECT count(*) FROM device_certificates WHERE device_id = $2::uuid),
    (SELECT count(*) FROM authorization_devices WHERE account_id = $1::uuid),
    (SELECT count(*) FROM authorization_events WHERE account_id = $1::uuid)
`, accountID, uuidText(cert.DeviceID)).Scan(
		&accounts,
		&authorizationAccounts,
		&devices,
		&certificates,
		&authorizationDevices,
		&events,
	)
	if err != nil {
		t.Fatalf("inspect activation-first database state: %v", err)
	}

	if accounts != 1 ||
		authorizationAccounts != 1 ||
		devices != 1 ||
		certificates != 1 ||
		authorizationDevices != 1 ||
		events != 1 {
		t.Fatalf(
			"activation-first state is incomplete: accounts=%d authorization_accounts=%d devices=%d certificates=%d authorization_devices=%d events=%d",
			accounts,
			authorizationAccounts,
			devices,
			certificates,
			authorizationDevices,
			events,
		)
	}

	var challengeRows, liveChallenges, originalConsumed int64
	err = db.QueryRowContext(ctx, `
SELECT
    count(*),
    count(*) FILTER (WHERE consumed_at IS NULL),
    count(*) FILTER (
        WHERE challenge_id = $2::uuid AND consumed_at IS NOT NULL
    )
FROM initial_account_bootstrap_challenges
WHERE account_id = $1::uuid
`, accountID, uuidText(challengeA.ID)).Scan(
		&challengeRows,
		&liveChallenges,
		&originalConsumed,
	)
	if err != nil {
		t.Fatalf("inspect activation-first challenge state: %v", err)
	}

	if challengeRows != 1 || liveChallenges != 0 || originalConsumed != 1 {
		t.Fatalf(
			"activation-first challenge state: rows=%d live=%d original_consumed=%d; want 1, 0, 1",
			challengeRows,
			liveChallenges,
			originalConsumed,
		)
	}

	t.Log("valid serialization: activation committed first; replacement issuance rejected with ErrAccountExists")
}
