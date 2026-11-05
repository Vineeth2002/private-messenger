# P2 Enrollment and Recovery Contract Review Addendum

**Document status:** Review addendum — NOT FROZEN
**Target branch:** `feature/p2-enrollment-recovery-contract`
**Review base:** `01b3651cff3cfa56b4c84e1e84852b26e0a72624`
**Scope:** Android additional-device enrollment, Gateway candidate enrollment endpoints, native signing boundary, PostgreSQL activation, and the relationship to delayed account recovery.

## 1. Executive decision

The current candidate ordinary-enrollment implementation has a coherent cryptographic and database activation path:

1. A recovery-key-signed `DeviceEnrollmentAuthorizationV1` certificate binds AccountID, DeviceID, epoch, DSK public key, and DDHK public key.
2. The Gateway verifies the certificate against the recovery public key and authoritative account state.
3. The Gateway issues a short-lived, one-use challenge bound to the account, device, epoch, and exact certificate digest.
4. The new device proves possession of its DSK by signing the challenge-bound `DeviceEnrollmentPoPV1` structure.
5. The Gateway verifies the proof against the certificate and server-stored challenge, then atomically installs device and authorization records, records the authorization event, and consumes the challenge.

Rust and Go implement matching candidate PoP wire semantics, and both sides test a shared lifecycle candidate vector. PostgreSQL integration-test source covers successful activation, exact retry, concurrent exact retry, stale/expired challenges, invalid proof, and rollback cases.

This is **not** a frozen product contract and is **not** a complete enrollment/recovery implementation. The current Gateway candidate path supports ordinary enrollment for an active account only. It rejects pending recovery and does not implement the 48-hour delayed recovery enrollment flow. The candidate endpoints must remain disabled.

A narrowly scoped candidate HTTP error-mapping correction for `ErrRecoveryPending` was applied on this review branch after the initial source review. That correction is not authorization to enable candidate routes, freeze the protocol, or claim production readiness.

## 2. Verified implementation facts

### 2.1 Candidate HTTP contract

The Android client and Gateway currently agree on:

- `POST /v1/candidate/enrollment/challenges`
- `POST /v1/candidate/enrollment/activate`
- JSON field names `enrollment_certificate_hex`, `recovery_public_key_hex`, and `proof_hex`
- Challenge response fields `challenge_id_hex`, `challenge_nonce_hex`, and `expires_at`
- Hexadecimal representation of binary protocol objects
- Certificate, proof, request-body, and response-body size bounds in the current implementations

The Gateway rejects unknown JSON fields, multiple JSON values, non-JSON content types, unsupported methods, and malformed hex fields. The route is explicitly opt-in through `GATEWAY_ENABLE_CANDIDATE_ENROLLMENT=1` and logs that it is not production-ready.

### 2.2 Native certificate and PoP binding

The native `AccountContext` keeps a transient `EnrollmentBinding` containing the exact certificate bytes and recovery public key. `RecoveryContext.sign_device_enrollment_for_device()` creates the certificate from the target device context's own IDs and public keys and refuses conflicting rebinding. `AccountContext.sign_device_enrollment_pop_for_challenge()` requires the exact previously bound certificate before delegating to the PoP signer.

The lower-level Rust signer independently checks certificate AccountID, DeviceID, DSK, and DDHK against values derived from the native context and verifies that the held DSK signing key corresponds to the certificate's DSK public key. DSK and DDHK private material remains in Rust.

The Rust and Go candidate PoP structures use the same domain string, canonical eight-field CBOR proof map, seven-field canonical signed core, certificate digest, challenge ID, challenge nonce, and Ed25519 signature semantics. Shared fixture tests exercise parsing and verification on both sides.

### 2.3 Gateway challenge and activation behavior

Challenge issuance locks and verifies the existing authorized account state, rejects a pending recovery request, requires an active account, checks the certificate epoch against the authoritative stored epoch, rejects an already-existing device, invalidates earlier outstanding challenges for the same account/device, and inserts a new database-timed challenge with a five-minute lifetime.

Activation re-checks account authorization, recovery state, account status, and epoch. It loads and locks the challenge from PostgreSQL, checks account/device/epoch/certificate-digest binding, verifies the DSK proof against the stored challenge nonce and ID, and evaluates expiry using database time. Successful activation writes device, certificate, authorization-device, and authorization-event records and consumes the challenge in one database transaction.

A consumed challenge is treated as an idempotent retry only when the exact certificate is already installed and all checked records still describe the same active, non-revoked device. Changed or inconsistent state fails closed.

### 2.4 Test evidence present in source

The reviewed source contains:

- Rust native-context binding tests.
- Rust lifecycle candidate vector verification.
- Go verification of the shared Rust-generated candidate vector.
- Go negative tests for wrong keys, altered certificates, mismatched challenges, malformed proof encodings, and digest mismatch.
- PostgreSQL integration-test source for successful activation and exact sequential retry.
- PostgreSQL integration-test source for concurrent exact activation/retry.
- PostgreSQL integration-test source for stale/expired challenge rejection, invalid-proof rejection, transaction rollback, and inconsistent installed-state rejection.
- PostgreSQL integration-test source for the challenge timestamp and one-way-consumption trigger.

These are source-level observations. Validation actually executed on 2026-11-05 in this review branch is recorded in Section 10. The PostgreSQL tests are opt-in and restrict execution to the named disposable database `pm_enrollment_bootstrap_it_20261104`; any execution must preserve that safety check. A test process reporting `PASS` when these tests are skipped is not evidence that PostgreSQL behavior executed.

## 3. Explicit non-goals and unsupported claims

The current candidate ordinary-enrollment path does not establish:

- An approval signature from an already-authorized device.
- A complete delayed 48-hour recovery enrollment flow.
- A signed or rollback-resistant Gateway device-directory statement.
- A trusted epoch merely because an Android caller supplied a `ULong`.
- Challenge issuance authenticity inside the new device's native context.
- Durable Android recovery of an in-progress activation after process death.
- Production-grade, globally shared candidate-enrollment rate limiting across Gateway instances.
- Production deployment readiness, an independent security audit, or complete P2 acceptance.

A successful build, passing unit tests, or a shared protocol vector does not prove any of these properties.

## 4. Decisions required before contract freeze

### DEC-01 — Enrollment authorization authority

**Observed candidate behavior:** the recovery key signs the enrollment certificate; the new device's DSK proves possession. The candidate HTTP request has no separate existing-device approval signature.

**Decision required:** explicitly select the product rule:

- **Option A:** possession of the account recovery credential is sufficient to authorize ordinary additional-device enrollment; or
- **Option B:** an already-authorized device must approve ordinary additional-device enrollment, with recovery credential use reserved for the separate recovery workflow; or
- **Option C:** define distinct, rigorously separated authorization modes.

Do not silently describe the current implementation as existing-device-approved enrollment. The selected rule must define compromise assumptions, user confirmation, audit evidence, and how recovery-key rotation/revocation affects enrollment.

**Status:** OPEN — product/security policy decision.

### DEC-02 — Epoch authority

**Observed candidate behavior:** Kotlin passes an epoch to native certificate signing. Rust enforces the numeric lifecycle bound but does not independently know the authoritative current account epoch. Gateway challenge issuance and activation compare the certificate epoch with locked PostgreSQL account state.

**Required contract:** the Gateway's committed account state is authoritative for candidate ordinary activation. A directory response that is not independently signed and rollback-resistant must not be accepted as epoch authority. Any existing-device handoff or stronger native verified-account context must be specified separately; its authenticity and freshness must be established, not asserted by a caller-provided boolean or integer.

**Status:** OPEN — authority and client UX contract.

### DEC-03 — Challenge authenticity boundary

**Observed candidate behavior:** Rust validates challenge ID/nonce shape and binds the resulting proof to those values. The Gateway verifies that they match the server-stored challenge and enforces expiry and single use.

**Required contract:** explicitly state that challenge issuance authenticity, freshness, and single-use are server-authoritative properties. If the design instead requires the native context to authenticate a Gateway-issued challenge before signing, specify the signed challenge transcript, pinned Gateway/service key, key rotation, and native verification API. Do not claim the native code currently proves server issuance.

**Status:** OPEN — trust-boundary decision.

### DEC-04 — Process-death and ambiguous activation recovery

**Observed candidate behavior:** `PendingCandidateEnrollment` retains exact certificate/proof bytes only in memory. The native certificate binding is also transient. The Gateway has an exact consumed-challenge retry path when installed state remains active and consistent.

**Required contract:** define a durable client operation record containing the exact target AccountID/DeviceID, certificate bytes or digest, challenge identity, exact proof bytes, attempt state, and enough integrity protection to detect substitution. Do not persist the recovery mnemonic or private keys in this record. After restart, the client must resolve an uncertain outcome by replaying only the exact same activation request or by using a separately specified authenticated status endpoint. It must not generate a different certificate/proof or a new challenge merely because the HTTP response was lost. Define expiry behavior, account-state changes, cancellation, retention, and secure deletion.

The restored native identity must re-establish its transient certificate binding using the exact certificate and compare bytes before proof signing. The recovery mnemonic must not be silently persisted to make this possible.

**Status:** OPEN — Android durability and recovery design.

### DEC-05 — Ordinary enrollment versus delayed recovery

**Observed candidate behavior:** challenge issuance and activation reject accounts with pending recovery. The current candidate activation code requires ordinary challenge rows with no recovery request ID/digest. It is not the finalized 48-hour recovery path.

**Required contract:** keep ordinary enrollment and delayed recovery enrollment as distinct state machines. The recovery path must bind the finalized recovery request ID/digest, target DeviceID, target certificate digest, and new authoritative epoch. It must not activate or advance epoch during the pending timelock. A post-finalization challenge may be issued under the frozen recovery contract; a five-minute challenge must not be expected to survive a 48-hour timelock.

**Status:** OPEN — recovery design and implementation.

### DEC-06 — HTTP error semantics

**Observed defect:** `ErrRecoveryPending` can be returned by challenge issuance and activation, but the candidate HTTP error mapper does not explicitly map it; it falls through to `500 ERR_ENROLLMENT_INTERNAL`.

**Required change before freeze:** choose a stable public status and code for this state conflict (a conflict response such as HTTP 409 is the likely mapping), add handler tests for both routes, and ensure internal error details remain undisclosed. Also freeze whether expired challenge, consumed challenge, missing challenge, locked account, stale epoch, account adoption required, rate limit, and internal failures map to distinct stable public codes.

**Status:** NARROW HTTP MAPPING CORRECTION APPLIED ON THIS REVIEW BRANCH; protocol semantics remain candidate/unfrozen. `ErrRecoveryPending` now maps to HTTP 409 `ERR_RECOVERY_PENDING`. A new handler regression test covers both challenge issuance and activation. The focused regression and complete HTTP package tests passed on 2026-11-05. The mapping still requires inclusion in the eventual contract and compatibility review.

### DEC-07 — Shared rate limiting and ingress trust

**Observed candidate behavior:** candidate enrollment uses an in-memory limiter in the HTTP handler. That is not a shared quota across multiple Gateway instances. The separate recovery API deployment document describes PostgreSQL-backed rate limiting, but that does not prove candidate enrollment uses it.

**Required contract:** choose a shared limiter or a correctly configured ingress-wide control for candidate enrollment. Specify trusted-proxy behavior; do not trust arbitrary `Forwarded` or `X-Forwarded-For` headers. Define quota keys, IPv4/IPv6 normalization, storage outage behavior, retry response, and abuse monitoring.

**Status:** OPEN — deployment/security requirement.

### DEC-08 — Challenge-row integrity

**Observed candidate behavior:** the lifecycle trigger protects `created_at`, `expires_at`, and one-way `consumed_at`. It does not itself make account ID, device ID, account epoch, certificate digest, challenge nonce, or recovery binding columns immutable.

**Required review:** inspect database roles, grants, and all update paths. If the runtime database role can update challenge-binding columns, add database enforcement that prevents mutation of those fields after insertion, while preserving only the intended consumption transition. Add PostgreSQL tests for identity, digest, nonce, epoch, and recovery-binding mutation. Do not label this an exploitable vulnerability until the privileges and reachable write paths are assessed.

**Status:** OPEN — database integrity/privilege review.

## 5. Proposed normative behavior to specify

The frozen contract should define, at minimum:

1. Exact route paths, methods, content types, field names, hex casing rules, canonical binary encodings, and body/response limits.
2. Certificate and PoP schemas, versioning, domain separation, field validation, and exact digest inputs.
3. Challenge generation, replacement/invalidation, server-side expiry clock, one-time consumption, and account/device binding.
4. The authoritative state checks and lock order used at challenge issuance and activation.
5. The atomic database commit boundary and the exact conditions for idempotent replay.
6. Stable HTTP status/error-code mapping and whether each error is retryable.
7. Client retry behavior after timeout, lost acknowledgement, process death, account epoch change, device revocation, or pending recovery.
8. Enrollment authorization authority and the distinction between ordinary enrollment and recovery enrollment.
9. Rate limiting, ingress/TLS termination, proxy trust, database permissions, operational logging, and endpoint enablement controls.
10. Compatibility/version negotiation and deprecation rules before any wire-format change.

## 6. Required validation before freeze

The following evidence is required. Existing tests should be reused; do not duplicate tests merely to inflate counts.

### Cross-language and native

- Run the Rust lifecycle vector test and Go candidate PoP vector test from the same branch/base.
- Retain negative cases for wrong recovery key, wrong DSK, altered certificate, mismatched digest, challenge ID/nonce mismatch, zero identifiers, invalid epoch, non-canonical/trailing CBOR, and cross-session certificate use.
- Add or confirm tests for a certificate whose DSK matches but DDHK differs from the native context.
- Clearly distinguish native structural/cryptographic validation from server authority over challenge issuance and account epoch.

### Gateway and PostgreSQL

- Run focused PostgreSQL enrollment integration tests against only `pm_enrollment_bootstrap_it_20261104`, with `PM_ENROLLMENT_TEST_DATABASE_URL` set to that disposable local database.
- Verify sequential and concurrent exact activation retries.
- Verify retries after account epoch/status changes and after device revocation return the documented result.
- Verify challenge replacement invalidates the prior challenge and concurrent issuance/activation serializes correctly.
- Add handler tests for `ErrRecoveryPending` mapping.
- Review and test DB runtime privileges and immutability of challenge-binding columns.
- Verify candidate enrollment rate limiting across multiple Gateway instances or the selected shared ingress boundary.

### Android end-to-end

- Implement no UI integration until DEC-01 through DEC-05 have approved outcomes.
- Then test an actual Android native-generated certificate and PoP against a real Gateway/PostgreSQL disposable test deployment.
- Test successful activation, lost HTTP response after commit, process death before and after commit, app restart, retry of the exact persisted request, challenge replacement, stale epoch, revoked device, and recovery-pending state.
- Verify no recovery mnemonic or private DSK/DDHK material is persisted in the pending operation record.
- Verify Android does not treat the unsigned/non-rollback-resistant directory response as epoch authority.

## 7. Implementation order after decisions

1. Record decisions DEC-01 through DEC-05 in the lifecycle specification and obtain protocol/security review.
2. **Completed on this review branch:** correct the candidate HTTP error map and add focused handler tests. Still required: review challenge-row database privileges and required integrity controls.
3. Select and implement shared candidate rate limiting and deployment controls, while keeping the route disabled by default.
4. Freeze the exact HTTP, binary, retry, idempotency, and error contract with Rust/Go vectors and negative cases.
5. Design and implement durable Android pending-operation recovery without persisting recovery secrets or native private keys.
6. Integrate the Android additional-device flow behind an explicit development/test gate.
7. Implement the separate delayed recovery enrollment path only after its 48-hour lifecycle and finalization semantics are frozen.
8. Run complete Android-to-Gateway-to-PostgreSQL end-to-end tests and update P2 evidence.

## 8. Freeze and release gates

The candidate API may be frozen only when:

- All policy/trust decisions above have written answers.
- Rust and Go parity tests and negative cases pass.
- Gateway/PostgreSQL transaction, concurrency, replay, expiry, and idempotency tests pass in the dedicated disposable database.
- Android process-death behavior is specified and tested.
- HTTP errors, shared rate limiting, database privileges, and deployment controls are reviewed.
- The lifecycle contract receives independent protocol/security review.

Even after candidate API freeze, that does not make the messenger production-ready. Production release still requires the full P0–P9 roadmap exit criteria, complete two-device messaging, ratchet persistence and anti-rollback implementation, operational readiness, and independent security review.

## 9. Current disposition

- **Candidate enrollment wire parity:** demonstrated by shared Rust/Go candidate vectors.
- **Candidate ordinary activation:** implemented in Gateway source; PostgreSQL integration-test coverage exists in source. The PostgreSQL integration tests were not executed in this review run because `PM_ENROLLMENT_TEST_DATABASE_URL` was unset; see Section 10.
- **Native exact certificate binding:** implemented in the native FFI source.
- **Recovery-pending HTTP mapping:** corrected on this review branch to HTTP 409 `ERR_RECOVERY_PENDING`; focused regression and full HTTP package tests passed.
- **Delayed recovery enrollment:** not implemented by the candidate ordinary-enrollment path.
- **Android enrollment end-to-end:** not integrated into `MainActivity` and not proven against a live Gateway.
- **Contract status:** NOT FROZEN.
- **Candidate routes:** KEEP DISABLED.
- **Production status:** NOT PRODUCTION-READY.
- **Source code changes in this addendum:** none.


## 10. Review-branch change and validation record (2026-11-05)

The following narrow change was applied in `feature/p2-enrollment-recovery-contract` at review base `01b3651cff3cfa56b4c84e1e84852b26e0a72624`:

- `services/gateway/internal/http/enrollment_candidate_http.go`: explicitly map `authorization.ErrRecoveryPending` to HTTP 409 with public code `ERR_RECOVERY_PENDING`.
- `services/gateway/internal/http/enrollment_candidate_recovery_pending_test.go`: add handler regression coverage for both challenge issuance and activation. The test checks status, `Cache-Control: no-store`, the exact one-field JSON error body, and that the intended service method was called.

Validation actually executed:

| Command | Result |
|---|---|
| `go test ./internal/http -run '^TestCandidateEnrollmentHandlerMapsRecoveryPending$' -count=1` | Passed |
| `go test ./internal/http -count=1` | Passed |
| `go test ./... -count=1` | Passed across all Gateway packages shown in the run |
| `git diff --check` | Passed |
| `go test ./internal/authorization -run '^TestPostgres(CandidateEnrollment|EnrollmentChallengeLifecycleGuard)' -count=1 -v` | Test process returned PASS, but all 13 matching PostgreSQL integration tests were SKIPPED |

The PostgreSQL skip was confirmed explicitly: `PM_ENROLLMENT_TEST_DATABASE_URL` was not configured. Therefore this review has **not** newly verified database-backed challenge lifecycle, activation, concurrency, or retry behavior. Existing PostgreSQL test source remains useful coverage, but execution evidence must not be claimed for this run. Do not set the variable to an arbitrary database; any later run must use only the test suite's guarded disposable database `pm_enrollment_bootstrap_it_20261104` at the required local endpoint and preserve all safety checks.

The review branch remained uncommitted at the time of this record. No route enablement, production deployment, schema migration, database operation, commit, or push was performed by the patch script.

**Current conclusion:** the candidate HTTP error classification defect is corrected and covered by passing Go handler/package tests on this branch. Contract freeze remains blocked by DEC-01 through DEC-05 and the remaining rate-limit, DB privilege/integrity, deployment, and Android end-to-end gates. Candidate routes remain disabled; the application is not production-ready.
