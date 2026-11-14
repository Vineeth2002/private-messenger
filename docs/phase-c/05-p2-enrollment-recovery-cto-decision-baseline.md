# P2 Enrollment and Recovery — CTO Decision Baseline

**Status:** Decision proposal for protocol/security review — NOT FROZEN
**Target branch:** `phase-c/ratchet-persistence-design`
**Review point:** 2026-11-05
**Purpose:** Resolve the policy direction for DEC-01 through DEC-08 before changing enrollment wire formats or enabling candidate routes.

## Executive decision

Adopt **two deliberately separate device-authorization modes**:

1. **Ordinary additional-device enrollment:** an already-authorized, active device explicitly approves the exact new-device identity; the new device independently proves possession of its DSK. The recovery credential is not used for ordinary device addition.
2. **Catastrophic account recovery:** the recovery credential signs a distinct recovery request; the existing 48-hour delay and active-device abort window apply; finalization advances the epoch and revokes old devices; the intended replacement device must then complete its own DSK proof-of-possession enrollment before the account is unlocked.

This is the recommended policy equivalent of DEC-01 Option C, with a concrete separation between normal enrollment and recovery. Do not retrofit the current recovery-signed `DeviceEnrollmentAuthorizationV1` as an ordinary device-approval object. Preserve its existing bytes and semantics for compatibility while designing a separately versioned ordinary-enrollment authorization object.

This policy is a design baseline, not a claim that the current code implements it. It does not authorize route enablement, migration execution, ratchet persistence, or production deployment.

## Source facts verified on the Phase C branch

- Ordinary candidate endpoints are `/v1/candidate/enrollment/challenges` and `/v1/candidate/enrollment/activate`. The current candidate certificate is recovery-key signed; the new device proves DSK possession. No existing-device approval signature is part of that HTTP request.
- Ordinary candidate activation is active-account-only. It rejects pending recovery and checks the account epoch against locked PostgreSQL state.
- A separate recovery API exists: `POST /v1/recovery/requests`, `/v1/recovery/abort`, `/v1/recovery/enrollment/challenges`, and `/v1/recovery/enrollment/activate`.
- The Gateway source contains `BeginRecovery`, `AbortRecovery`, `FinalizeRecovery`, `IssueRecoveryEnrollmentChallenge`, and `ActivateRecoveryEnrollment`; a separate `cmd/recovery-finalizer` process runs the due-request worker. These are candidate implementation paths, not a frozen production contract.
- The Android `NativeDeviceEnrollmentSession` says its certificate binding is transient and currently instructs a restored session to re-sign using the recovery mnemonic and epoch before PoP signing. The pending operation is not yet a durable restart-safe activation protocol.
- The candidate HTTP handler constructs an in-memory `newDemoMessageLimiter(10, time.Minute)` for each handler instance. The PostgreSQL-backed HMAC limiter is wired to the separate recovery API, not candidate enrollment.
- Migration `0010_enrollment_challenge_lifecycle_guard.sql` protects `created_at`, `expires_at`, and one-way `consumed_at`. It does not compare the challenge's account/device/epoch/certificate-digest/nonce/recovery-binding columns on update.
- The repository's existing `RECOVERY_API_DEPLOYMENT.md` says the Gateway listener is plain HTTP and requires a trusted HTTPS ingress or another protected transport boundary. It also warns not to trust forwarded headers without explicit trusted-proxy configuration.

## DEC-01 — Enrollment authorization authority

**Decision:** Use distinct authorization modes (Option C).

### Ordinary additional-device enrollment

- Require explicit approval by at least one currently active, non-revoked device in the current account epoch.
- The approval must be signed by that approving device's DSK and bind the exact target account, target DeviceID, target DSK, target DDHK, account epoch, and exact canonical target-descriptor digest.
- The new device must separately prove possession of its own DSK using a fresh one-time challenge.
- No recovery mnemonic, recovery private key, or recovery signature is required for this normal operation.
- The Gateway re-checks the approving device's status and epoch under the same account serialization/transaction boundary as activation.

### Catastrophic recovery

- Recovery-key possession authorizes only initiation of the separate recovery process, not immediate active-account device addition.
- Preserve the signed `RecoveryRequestV1` / `RecoveryAbortV1` design direction and 48-hour timelock.
- After finalization, the target device must complete the recovery-bound challenge and DSK proof-of-possession flow before the account becomes active.

### Compatibility requirement

Do not change the existing seven-field `DeviceEnrollmentAuthorizationV1` or its signature transcript in place. Define a new, explicitly versioned ordinary-enrollment descriptor/approval contract. Preserve the existing recovery-signed certificate format only where the recovery flow requires it. Rust and Go must share byte-level vectors before implementation.

**Rationale:** a stolen recovery credential must not silently add a device immediately to an otherwise active account. Conversely, ordinary device addition should not require users to expose/use their catastrophic recovery secret. Separate paths make the security and UX guarantees understandable and testable.

## DEC-02 — Epoch authority

**Decision:** PostgreSQL-backed Gateway authorization state is authoritative for server-side activation. A client-supplied epoch is only a proposed value, never authority.

- The approving existing device signs an approval bound to the epoch it believes current.
- At challenge issuance and activation, the Gateway locks and re-checks the account and approving-device state, including active status, revocation, and exact current epoch.
- The target device must not treat an unsigned or rollback-unprotected directory record, Kotlin `ULong`, or caller-provided `verified=true` flag as authoritative.
- Recovery finalization uses the persisted signed recovery request and the database's committed epoch transition; no new epoch is authoritative before finalization commits.

## DEC-03 — Challenge authenticity boundary

**Decision:** the Gateway database is authoritative for challenge existence, binding, expiry, replacement, and one-time consumption.

- Challenge bytes are delivered only through the explicitly configured HTTPS Gateway origin; redirects remain disabled and the client must validate the expected origin and TLS certificate chain.
- The native PoP signer validates structure and binds the signature to the exact account/device/epoch/certificate digest/challenge ID/nonce. It does not independently prove that the Gateway issued the challenge.
- The Gateway verifies the supplied challenge against its locked PostgreSQL row and consumes it in the same transaction as activation.
- Do not add a second Gateway-signed challenge protocol unless a threat-model review demonstrates that TLS-authenticated delivery and server-side challenge verification are insufficient.

## DEC-04 — Process death and ambiguous activation

**Decision:** implement an encrypted, durable client operation journal and exact-request retry. Never persist recovery mnemonics or private keys in it.

Persist only the public/protocol operation material and state needed to resolve one exact activation attempt:

- AccountID and target DeviceID;
- exact canonical target descriptor/certificate bytes and digest;
- challenge ID, nonce, and expiry;
- exact existing-device approval bytes (for ordinary enrollment), where applicable;
- exact target-device PoP bytes;
- configured Gateway origin identity/version;
- operation status (`PREPARED`, `CHALLENGE_ISSUED`, `PROOF_READY`, `ACTIVATION_SENT`, `OUTCOME_UNKNOWN`, `CONFIRMED`, or a reviewed terminal state);
- integrity-protected timestamps and a bounded retention/deletion policy.

Encrypt/authenticate this record with a key protected by Android Keystore. It must not contain the recovery mnemonic, recovery private key, DSK private key, or DDHK private key.

After restart:

- Re-read and authenticate the operation record before network activity.
- Re-establish native binding to the exact stored certificate/descriptor using a native verification/bind API that checks AccountID, DeviceID, DSK, DDHK, recovery signature where relevant, and exact bytes. Do not require persisting the mnemonic merely to restore a transient binding.
- On an uncertain activation outcome, replay only the byte-identical activation request. Do not create a new certificate, proof, or challenge merely because the HTTP response was lost.
- If durable server outcome cannot be established through exact idempotent replay, fail closed and require a separately specified authenticated status/reconciliation path. Never guess that activation failed.

## DEC-05 — Ordinary enrollment versus delayed recovery

**Decision:** maintain two independent state machines and separate HTTP namespaces.

- Ordinary enrollment requires an active existing-device approval and target-device DSK proof. It is rejected while any recovery request is pending.
- Recovery initiation binds the signed request ID/digest, account, old/new epochs, target DeviceID, and exact target-certificate digest. The old epoch remains authoritative through the full 48-hour interval.
- During the pending interval, keep old active devices authorized; block competing enrollment and epoch transitions; notify active devices using a separately specified durable notification/outbox mechanism.
- An active old-epoch device may abort only the exact pending request before the deadline.
- At/after the deadline, the finalizer serializes with abort, advances the epoch exactly once, revokes old devices, records immutable finalization evidence, and leaves the account recovery-locked.
- Only the exact target device/certificate bound to that finalized request may complete recovery enrollment. The account unlocks only after its PoP and all recovery-binding checks succeed.
- The immediate `RecoveryResetAction` transition must not be presented or exposed as the compliant 48-hour recovery API.

The current separate Gateway recovery API is a starting implementation. It still requires contract freeze, deployment validation, fault/race testing, operational monitoring, and independent review. Its existence does not make the ordinary candidate endpoints a recovery implementation.

## DEC-06 — HTTP error semantics

**Decision:** keep public errors stable, coarse enough not to disclose sensitive account/device state, and fully documented before freeze.

Current correction retained: `ErrRecoveryPending` maps to HTTP 409 `ERR_RECOVERY_PENDING` for both ordinary candidate routes.

Initial public mapping baseline for review:

| Condition | Public response baseline |
|---|---|
| Malformed request or cryptographically invalid authorization | 400, generic enrollment-rejected code |
| Expired challenge | 410 `ERR_CHALLENGE_EXPIRED` |
| Pending recovery or other state conflict | 409, stable conflict code |
| Account locked | 423 `ERR_ACCOUNT_LOCKED` |
| Rate limit reached | 429 `ERR_RATE_LIMITED` with `Retry-After` |
| Shared limiter unavailable | 503, fail closed |
| Unexpected internal failure | 500 generic code; never expose database/internal details |

Before freeze, decide whether account-not-found and device-not-found should share a generic rejection response to reduce enumeration. Keep exact retry semantics separate from generic conflict semantics.

## DEC-07 — Shared rate limiting and ingress trust

**Decision:** candidate enrollment must use a shared quota across Gateway instances or an explicitly documented ingress-wide control. The current process-local demo limiter is not sufficient.

Preferred initial implementation: reuse/generalize the existing PostgreSQL HMAC rate-limiter design, with:

- database-time fixed windows;
- HMAC-hashed normalized peer identity (no raw IP storage);
- IPv4 `/32` and IPv6 `/64` normalization;
- identical secret management across instances;
- fail-closed behavior on limiter/database failure;
- separate endpoint/operation buckets and abuse telemetry;
- an explicit trusted-proxy CIDR/forwarding-chain policy if deployed behind a reverse proxy.

Do not blindly trust `Forwarded` or `X-Forwarded-For`. Direct `RemoteAddr` is the only trustworthy peer value unless the immediate proxy and forwarding chain are validated. Candidate enrollment currently does not use the PostgreSQL limiter wired to the recovery API.

## DEC-08 — Challenge-row integrity and database privileges

**Decision:** add defense-in-depth immutability for all challenge binding fields and audit runtime database privileges before route enablement.

The following challenge fields are immutable after insertion: `challenge_id`, `account_id`, `device_id`, `account_epoch`, `enrollment_certificate_digest`, `recovery_request_id`, `recovery_request_digest`, `challenge_nonce`, `created_at`, and `expires_at`.

The only permitted update is the one-way transition `consumed_at: NULL -> database-generated timestamp`; a consumed value cannot be cleared or changed. Add PostgreSQL tests that attempt to mutate every binding field, including recovery fields, and prove rejection.

Separately verify that the runtime Gateway DB role is not table owner/superuser and lacks DDL/trigger-control privileges. Grant only the required column-level update permission for consumption where feasible. Do not call this a proven exploit until role grants and reachable update paths are inspected.

## Implementation order

1. Add this decision baseline to Phase C as a review proposal; reconcile terminology and status in the existing P2 addendum and lifecycle document.
2. Define the new ordinary-enrollment object schemas and exact signature transcripts; preserve existing V1/recovery object bytes. Produce canonical CBOR vectors and Rust/Go parity tests.
3. Design Gateway API request/response shape for existing-device approval plus target DSK PoP; prove account/device lock order and atomic activation.
4. Add challenge-binding immutability migration and database-role/grant review, with PostgreSQL mutation tests.
5. Replace the candidate process-local limiter with the shared design and add trusted-proxy deployment configuration.
6. Add native exact-certificate rebind/verification so process restart does not require storing recovery secrets.
7. Add the Android durable operation journal and byte-identical retry/reconciliation flow.
8. Add real Android-to-Gateway-to-PostgreSQL end-to-end tests for ordinary enrollment and separately for finalized recovery enrollment.
9. Verify the independently deployed recovery-finalizer process, monitoring, alerting, restart behavior, and backup/restore fencing.
10. Obtain independent protocol/security review. Only then freeze the contract and consider enabling candidate routes in a controlled test deployment.

## Explicit stop conditions

- Keep `GATEWAY_ENABLE_CANDIDATE_ENROLLMENT` unset.
- Keep recovery API disabled outside explicitly controlled test environments.
- Do not expose the immediate recovery-reset transition as the 48-hour recovery flow.
- Do not implement ratchet persistence or Android chat integration on the assumption that this proposal freezes lifecycle authority.
- Do not claim P2 complete, production-ready, or independently audited based on CI success or the existence of these code paths.

## Source references

- [Existing P2 enrollment/recovery review addendum](https://github.com/Vineeth2002/private-messenger/blob/phase-c/ratchet-persistence-design/docs/phase-c/04-enrollment-recovery-contract-review-addendum.md)
- [Device Lifecycle and Account Authorization V1 proposal](https://github.com/Vineeth2002/private-messenger/blob/phase-c/ratchet-persistence-design/docs/phase0/13-device-lifecycle-v1.md)
- [Candidate enrollment HTTP handler](https://github.com/Vineeth2002/private-messenger/blob/phase-c/ratchet-persistence-design/services/gateway/internal/http/enrollment_candidate_http.go)
- [Candidate enrollment PostgreSQL activation](https://github.com/Vineeth2002/private-messenger/blob/phase-c/ratchet-persistence-design/services/gateway/internal/authorization/enrollment_activation_candidate.go)
- [Challenge schema migration 0005](https://github.com/Vineeth2002/private-messenger/blob/phase-c/ratchet-persistence-design/services/gateway/migrations/0005_device_enrollment_challenges.sql)
- [Challenge lifecycle guard migration 0010](https://github.com/Vineeth2002/private-messenger/blob/phase-c/ratchet-persistence-design/services/gateway/migrations/0010_enrollment_challenge_lifecycle_guard.sql)
- [Recovery API implementation](https://github.com/Vineeth2002/private-messenger/blob/phase-c/ratchet-persistence-design/services/gateway/internal/http/recovery_http.go)
- [Recovery finalizer command](https://github.com/Vineeth2002/private-messenger/blob/phase-c/ratchet-persistence-design/services/gateway/cmd/recovery-finalizer/main.go)
- [Android native enrollment session](https://github.com/Vineeth2002/private-messenger/blob/phase-c/ratchet-persistence-design/apps/android/app/src/main/java/org/sovereign/pm/crypto/NativeDeviceEnrollmentSession.kt)
- [Recovery API deployment requirements](https://github.com/Vineeth2002/private-messenger/blob/phase-c/ratchet-persistence-design/services/gateway/RECOVERY_API_DEPLOYMENT.md)
