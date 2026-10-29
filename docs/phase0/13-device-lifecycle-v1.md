# Device Lifecycle and Account Authorization V1 — Design Proposal

**Status: DESIGN PROPOSAL — NOT FROZEN.** This document records the current implementation boundary and the decisions required before device-lifecycle V1 can be frozen. It is not approval to treat current code as production-ready.

## 1. Purpose and authority

This specification is the next lifecycle boundary after Key Transparency V1. Key Transparency proves published current state and history; it does not independently prove that an account authorized a device. Account-level authorization, device revocation, epoch transitions, and recovery therefore remain explicit lifecycle decisions.

The existing `docs/phase0/08-device-lifecycle.md` is the architectural source for the 48-hour catastrophic-recovery timelock and active-device abort requirement. The current Go implementation does not yet implement those recovery semantics. This document deliberately does not describe that implementation as compliant.

## 2. Existing candidate certificate formats (not yet frozen)

All objects use strict, canonical PM-CBOR-2026. Reject duplicate, missing, unknown, wrongly typed, non-canonical, or unsupported fields. Verify signatures over the exact canonical core specified here, not a re-encoded interpretation of untrusted input. Identifiers and fixed-length public keys must have the specified length; AccountID and DeviceID must not be all zeroes.

### 2.1 Recovery commitment

The existing commitment candidate is:

`SHA-256(ASCII("PM-V1-RECOVERY-COMMITMENT") || recovery_public_key_32)`

`recovery_public_key_32` is an Ed25519 public key. Its private key must not leave the native recovery-key boundary. The server may store the public key and commitment, never the recovery private key or mnemonic.

### 2.2 Device enrollment authorization candidate

The current Rust and Go implementations use a map with exactly these fields:

| Key | Type | Meaning |
|---:|---|---|
| 1 | unsigned integer, value 1 | protocol version |
| 2 | `bstr(16)` | AccountID |
| 3 | unsigned integer | account epoch |
| 4 | `bstr(16)` | DeviceID |
| 5 | `bstr(32)` | device signing public key (Ed25519 DSK) |
| 6 | `bstr(32)` | device DH public key (X25519 DDHK) |
| 7 | `bstr(64)` | recovery-key Ed25519 signature |

The signature transcript candidate is:

`ASCII("PM-V1-DEVICE-ENROLL-v1") || canonical_map(fields_1_to_6)`

Enrollment requires a valid recovery signature, a recovery public key matching the account's committed recovery key, and an epoch matching the currently authoritative account epoch. Exact replay may be idempotent; a conflicting certificate for the same logical enrollment must fail closed. Device identity/key conflicts and re-enrollment of a revoked DeviceID must not silently reactivate that device.

### 2.3 Epoch-transition authorization candidate

The current Rust and Go implementations use a map with exactly these fields:

| Key | Type | Meaning |
|---:|---|---|
| 1 | unsigned integer, value 1 | protocol version |
| 2 | `bstr(16)` | AccountID |
| 3 | unsigned integer | old epoch |
| 4 | unsigned integer | new epoch, exactly old epoch + 1 |
| 5 | unsigned integer | action: 1 = revoke device; 2 = recovery reset |
| 6 | `bstr(16)` for action 1; empty `bstr` for action 2 | target device or empty recovery target |
| 7 | `bstr(64)` | recovery-key Ed25519 signature |

The signature transcript candidate is:

`ASCII("PM-V1-EPOCH-TRANSITION-v1") || canonical_map(fields_1_to_6)`

For action 1, the target device must be nonzero and belong to the account. A successful revocation advances the account epoch, revokes the target device, and updates surviving active devices to the newly authorized epoch. Replay of the exact committed certificate is idempotent; a conflicting transition for the same logical epoch transition is rejected.

**Important schema gap:** this current transition certificate has no unique, signed recovery-request identifier. If a pending recovery is aborted without changing the account epoch, replaying the same signed bytes cannot be distinguished from a deliberate new recovery request. Do not freeze action 2 as the delayed-recovery protocol until a versioned, signed request identifier or a separate recovery-initiation certificate is designed. A server-generated request ID alone is insufficient because the recovery owner must sign the intent that is being timed and canceled.

## 3. Epoch range and integer conversions — open freeze gate

Rust currently accepts `u64` epochs in these signing functions, while PostgreSQL stores epoch values in signed `bigint`, and message/session boundaries use narrower integer fields. Silent casts are prohibited. Before freeze, choose and document one V1 epoch domain shared by Rust, Go, PostgreSQL, message envelopes, Key Transparency, and session binding.

**Proposal for review:** constrain V1 account epochs to `1..=2^32-1`, encode them as unsigned CBOR integers, reject out-of-range values at parsers and signers, and use checked conversions at every boundary. This avoids accepting an authorization epoch that the existing message/session boundary cannot represent. If the architects choose a different maximum, the message/session format and all stored types must be reconciled before implementation. Never truncate `u64` to `u32` or cast an unsigned value to PostgreSQL `bigint` without a prior range check.

## 4. Required account/device state semantics

The state machine must be transactional and authoritative. Valid signatures do not override current account status, device status, epoch checks, logical-event uniqueness, or revocation state.

### 4.1 Enrollment

1. Strictly parse the exact certificate and verify the recovery signature.
2. Verify that the recovery public key matches the account's stored recovery commitment and key.
3. Require the account to exist and the certificate epoch to equal the currently authoritative epoch.
4. Reject conflicting DeviceID/key bindings and reactivation of revoked devices.
5. Commit device authorization and the corresponding immutable authorization event atomically.
6. Publish a Key Transparency leaf only when the lifecycle authorizer says that exact account/device/key/epoch state is authorized.

Enrollment during a pending recovery must not activate the future epoch early. A newly recovered device can be enrolled only after the recovery epoch is finalized and the account is in the defined recovery-locked state.

### 4.2 Device revocation

A valid revocation is an immediate, atomic epoch transition under the existing recovery-key authorization model. It revokes the selected device, advances the account epoch once, updates the remaining eligible devices to the new authorized epoch, and records the immutable authorization event in the same database transaction. A revoked device is never restored by replaying an enrollment certificate. Recovery and revocation must serialize on the account row so they cannot independently commit transitions from the same old epoch.

### 4.3 Catastrophic recovery — required 48-hour flow; implementation not yet compliant

The frozen architecture requires a 48-hour timelock, alerts to active devices, and the ability for an active device to abort. The following is the proposed target state machine; its certificate/API details remain unfrozen until the request-identifier gap above is resolved.

1. **Request:** accept a valid recovery-signed intent for exactly `old_epoch -> new_epoch`, with a fresh signed request identifier. Persist the exact intent, digest, accepted timestamp, deadline, status, and account linkage in a durable transaction. The deadline is the database acceptance time plus 48 hours.
2. **Pending interval:** keep the old epoch authoritative and the existing active devices authorized. A pending request must not advance the account epoch, revoke devices, or publish the new epoch as current. Prevent conflicting enrollments or transitions while recovery is pending. Record an event that the client/device-notification system can deliver to all active devices; notification delivery and retry semantics need their own operational specification.
3. **Abort:** an active device in the old epoch may cancel the specific pending request by signing a canonical abort statement with its DSK. The statement must bind AccountID, DeviceID, old/new epochs, the exact signed recovery-request digest/ID, protocol version, and the domain `PM-V1-RECOVERY-ABORT-v1`. Verify the DSK against the authorized device record; require that device to remain active in the old epoch and require the request to match the currently pending request. An abort after the deadline is invalid. Duplicate exact aborts are idempotent; an abort for a different request is rejected.
4. **Finalization:** after the deadline, a durable worker or equivalent server-side operation finalizes the still-pending request. In one transaction, re-check the pending request and database time after locking the account/request rows; advance the epoch exactly once; revoke all devices from the previous epoch; record finalization; and mark the account recovery-locked until a new device is validly enrolled in the new epoch. The pending request cannot be finalized twice.
5. **Cancellation/finalization race:** abort and finalization must serialize on the same account and pending-request records. Exactly one transition may win. Use database time after acquiring the required locks; do not rely on a worker's local clock. A second worker, retry, lost acknowledgement, or exact replay must resolve to the same durable outcome without another epoch advancement.
6. **After abort:** the old epoch remains authoritative and old active devices remain valid. Retain an immutable audit record of the aborted request. A later recovery attempt must use a fresh signed request ID; the previous certificate must not be replayable to silently restart a new timelock.
7. **After finalization:** all old devices are revoked and old-epoch messaging is rejected. Only a separately authorized new-epoch device may complete enrollment. The account must not become active merely because any arbitrary enrollment request arrives.

This state machine is a target for implementation, not a claim about present behavior. The current Go `Transition` recovery-reset path applies the epoch change and device revocations immediately; it must not be exposed as the compliant 48-hour recovery path until the state machine and migration are implemented and tested.

## 5. Persistence and event requirements

The PostgreSQL implementation must persist pending recovery separately from the current account/device authorization state, or define an equivalent schema with the same atomicity. It must durably retain at least the request ID, exact signed request bytes/digest, AccountID, old/new epochs, accepted/deadline timestamps, pending/aborted/applied status, and exact abort/finalization evidence. Enforce one live pending recovery per account and uniqueness for transition/request identities in the database. Do not store private keys.

All state change operations must:

- lock the account and the relevant device/pending-request rows in a consistent order;
- re-check epoch, state, request identity, and deadline after locking;
- commit the account, device, pending-request, and immutable event changes atomically;
- preserve exact replay idempotency without accepting conflicting reuse;
- fail closed on epoch overflow, unsupported state, a missing/ambiguous pending request, or an inconsistent database row;
- ensure a transaction whose acknowledgement is lost can be resolved by reading its durable event/request state instead of applying the same transition twice.

A pending-recovery expiry worker requires observable health, retry, and reconciliation behavior. If the worker is down, the request remains pending; it must not be finalized early or silently discarded. After restart, overdue requests must be reconciled idempotently.

## 6. Key Transparency integration

Before publishing or accepting a leaf, the gateway must validate that the current device's account authorization, device status, DSK/DDHK binding, and epoch match the lifecycle authorizer's authoritative current state. Key Transparency still verifies leaf signatures, proof validity, history consistency, STH and witness rules, and client high-water state. A valid leaf signature or valid KT proof alone is not proof that the account authorized the device.

No new epoch may be treated as current during the recovery pending interval. After revocation or recovery finalization, leaves for revoked devices or superseded epochs must fail lifecycle validation. An old but cryptographically valid leaf must not be accepted as current merely because it exists in history.

## 7. Anti-rollback boundary

Local ratchet catalog MACs, per-session generations, and PostgreSQL record generations are not a defense against restoring a mutually consistent older full snapshot. The lifecycle and ratchet-storage designs must not claim full-snapshot anti-rollback from those mechanisms.

The separate anti-rollback requirement needs an independently trusted freshness authority and a defined online/offline policy. The existing demo message relay is not that authority: its API uses a demo bearer guard (if configured) and caller-provided device IDs, and it does not provide a ratchet-session freshness protocol. Do not add freshness counters to the demo route and label the result secure. The authoritative protocol must define monotonic per-session operation generations, durable idempotency/receipts, crash recovery, server/witness rollback assumptions, and fail-closed behavior before ratchet persistence is enabled.

## 8. Required tests before freeze

### Certificate and parser tests

- Rust/Go byte parity for all accepted canonical objects and recovery commitments.
- Wrong keys, bad signatures, altered account/device/epoch/action, wrong lengths, all-zero IDs, unknown or duplicate fields, non-canonical CBOR, trailing bytes, and unsupported versions fail closed.
- Epoch boundaries and every integer conversion are range-checked; overflow never wraps.
- Exact certificate replay is idempotent; conflicting reuse of a logical transition/request is rejected.

### State-machine and persistence tests

- Revocation advances the epoch exactly once, revokes only the named target, and updates surviving eligible devices atomically.
- A recovery request leaves the old epoch authoritative during the full 48-hour interval.
- An active device can abort only its matching pending request before its deadline; inactive/revoked/wrong-epoch devices and stale/mismatched aborts fail.
- No recovery request finalizes early. A request becomes eligible at/after the deadline using database time.
- Abort-vs-finalize races have exactly one outcome under concurrent transactions.
- Exact request replay after abort does not restart recovery; a fresh signed request ID can start a new pending request.
- Restart, duplicate worker execution, transaction rollback, lost commit acknowledgement, and worker downtime do not produce duplicate epoch changes.
- A device cannot enroll into the future epoch before finalization; revoked devices cannot be resurrected.
- KT publication and validation reject unauthorized devices and superseded epochs.
- Integration tests use PostgreSQL, including migration/rollback behavior; in-memory tests alone are insufficient for transaction and uniqueness guarantees.

## 9. Freeze gate and implementation order

Do not mark this document frozen until the owners resolve and review the recovery request identifier/certificate shape, abort certificate, epoch range, notification contract, transaction/event schema, worker recovery semantics, and online/offline freshness policy.

Recommended order:

1. Ratify the certificate and epoch-range boundary with shared Rust/Go vectors.
2. Implement the persisted pending-recovery/abort/finalization state machine and PostgreSQL migration with race/fault-injection tests.
3. Wire only authenticated lifecycle operations into a versioned API; do not reuse the demo message endpoints.
4. Integrate authorization checks with KT publication/current-state verification.
5. Design and implement the separate anti-rollback freshness authority.
6. Continue ratchet-state persistence only after the required trusted lifecycle/freshness context is available.

This proposal makes current gaps explicit; it does not certify production readiness. Independent protocol/security review remains a release requirement.

## 10. Additional source-audit gates (open; 2026-10-25)

The following requirements were identified by comparing this proposal with the current Rust and Go source. They remain review gates and do not freeze any wire format.

### 10.1 Native lifecycle trust boundary

The current Rust `authorization_v1.rs` implements recovery commitment and certificate-signing functions. The Go authorization package parses and verifies the candidate certificates and checks them against persisted current account/device state. Signature verification performed in a Rust unit test does not constitute a production Rust API for verifying a received certificate or proving that a certificate is still current. Before a native ratchet session can rely on lifecycle authorization, define a native-owned verified account/device context or narrow authenticated result, bound to the account, device, epoch, status, and applicable lifecycle/KT evidence. Do not treat a caller-supplied epoch or boolean such as `verified=true` as authority. The API and cross-language tests remain open.

### 10.2 Enrollment proof of possession and recovery unlock

Before making a newly enrolled device active, require a replay-resistant proof that the device controls the DSK private key corresponding to the public key in the recovery-signed enrollment certificate. The proof must be bound to the account, device, epoch, enrollment certificate digest, and a one-time challenge or equivalent non-replayable context. Define its canonical wire format and shared Rust/Go vectors before freeze. A recovery signature over a public key alone does not demonstrate that the enrolling device possesses the matching private key.

A recovery-locked account must not become active merely because an enrollment certificate was parsed or its public-key fields were inserted. Unlock only after the complete new-device enrollment path succeeds, including proof of possession and all current-epoch checks. The current Go `PostgresAuthorizer.Enroll` changes the account status from recovery-locked to active in the enrollment transaction; review and revise that path when the proof-of-possession contract is implemented.

### 10.3 Pending-recovery serialization

During a pending recovery, reject all new device enrollments and all competing epoch transitions, except the exact matching abort or finalization operation. Keep the active-device set and old authoritative epoch stable throughout the timelock. The recovery request, abort, finalization, and any conflicting enrollment/revocation attempt must serialize through a consistent account-row/pending-request lock order. A failed or retried transaction must resolve from durable request/event state and must not create a second effective transition.

### 10.4 PostgreSQL deadline semantics

Make abort/finalization deadline decisions using database wall-clock time after acquiring the account and pending-request locks, for example `clock_timestamp()`. PostgreSQL `now()` and `CURRENT_TIMESTAMP` represent transaction-start time and can be stale after a lock wait. Apply one documented boundary rule consistently: an abort is accepted only if the post-lock database time is strictly before the deadline; finalization is eligible at or after the deadline. Test lock-wait, concurrent abort/finalizer, retry, restart, and lost-acknowledgement cases against PostgreSQL rather than relying only on in-memory tests.

### 10.5 Request identity and durable event retention

A signed recovery request ID must be unique per account across pending, aborted, and applied requests, and must never become reusable after audit-record cleanup. Persist exact signed request bytes or an unambiguous cryptographic digest, the immutable request ID, request status, abort/finalization evidence, and the durable outcome. A server-generated ID alone is not proof that the recovery owner signed the intent. The current `authorization_events` migration models only `ENROLL` and `TRANSITION` and requires `target_device_id`; the lifecycle migration must explicitly model request/abort/finalization semantics rather than overloading a generic transition row or using a dummy target device. Exact replay must return the same durable outcome; conflicting use of an ID must fail closed.

### 10.6 Key Transparency after epoch changes

The current authorization `ValidateLeaf` logic requires a leaf epoch to equal the authoritative account and device epochs. Therefore, advancing the epoch during device revocation also makes surviving devices' old-epoch leaves fail that current-state validation until their authorized state is republished. Define how surviving devices obtain/authenticate the transition and publish a fresh leaf at the new epoch, including offline-device behavior, retry semantics, and temporary peer reachability. Do not silently accept a superseded old-epoch leaf as current; also do not describe revocation as fully integrated until publication and client validation behavior have been tested.

### 10.7 Public-key input validation

A fixed 32-byte length check alone is not sufficient to establish that public-key material is usable. Define where device enrollment rejects unacceptable Ed25519 public-key encodings and low-order/unusable X25519 public keys. Apply compatible validation in the relevant native and gateway trust boundaries and add shared negative vectors. Reuse existing cryptographic validation where appropriate, but verify that the certificate-to-authorization path actually enforces it before the device is activated or its leaf is published.

### 10.8 Additional freeze tests

Before freeze, add tests proving that: a copied recovery-signed enrollment certificate without DSK proof of possession cannot activate a device or clear recovery lock; a pending recovery blocks enrollment and competing epoch transitions; an aborted request ID cannot be reused; abort and finalization have exactly one PostgreSQL outcome at the deadline boundary; losing a commit acknowledgement does not advance the epoch twice; the new epoch is not authoritative before finalization; and surviving devices' new-epoch KT publication works without accepting stale old-epoch leaves. Include migration, restart, worker downtime, and recovery reconciliation coverage.

These are source-audit requirements, not evidence that the current Go or Rust implementation already satisfies them. The immediate `RecoveryReset` transition remains non-compliant with the required 48-hour delayed-recovery flow until the new state machine and migration are implemented and tested.

## 11. Candidate wire contracts for recovery and enrollment proof of possession (OPEN; NOT FROZEN)

This section proposes distinct, versioned wire objects for the delayed recovery flow. It does not change the existing `DeviceEnrollmentAuthorizationV1` or `EpochTransitionAuthorizationV1` schemas, their vectors, or their signature transcripts. These candidates require review and Rust/Go vectors before any production route is implemented.

### 11.1 Compatibility boundary and epoch domain

- Preserve the existing seven-field enrollment and seven-field epoch-transition objects byte-for-byte for compatibility tests. Do not append request IDs or other fields to either existing map.
- The existing `EpochTransitionAuthorizationV1` with action `2` (`RecoveryResetAction`) represents an immediate epoch transition in the present Go implementation. It is **not** the 48-hour recovery-request object and must not be exposed as the compliant delayed-recovery API.
- Candidate V1 lifecycle objects use the reviewed epoch range `1..=2^32-1`. For a transition, `old_epoch` must be at most `2^32-2`, and `new_epoch` must equal `old_epoch + 1`. Parsers, signers, persistence boundaries, and APIs must enforce the range before conversion. This remains a proposal until reviewed against all message, KT, persistence, and database fields.
- Every map is strict canonical PM-CBOR-2026: exact field set, no duplicate/unknown fields, minimal encodings, correct types and lengths, no trailing bytes, and exact signed core bytes. Domain separation is direct concatenation of the domain bytes and canonical core bytes, without a delimiter.

### 11.2 RecoveryRequestV1 candidate

The recovery request is a separate object--not `EpochTransitionAuthorizationV1` action 2--with exactly these fields:

| Key | Type | Meaning |
|---:|---|---|
| 1 | unsigned integer, value 1 | object protocol version |
| 2 | `bstr(16)` nonzero | AccountID |
| 3 | unsigned integer in the candidate epoch range | old authoritative epoch |
| 4 | unsigned integer in the candidate epoch range | new epoch, exactly old epoch + 1 |
| 5 | `bstr(16)` nonzero | randomly generated request ID, signed by the recovery key |
| 6 | `bstr(16)` nonzero | intended new DeviceID |
| 7 | `bstr(32)` | SHA-256 of the exact complete canonical `DeviceEnrollmentAuthorizationV1` bytes for the intended new device |
| 8 | `bstr(64)` | recovery-key Ed25519 signature |

Signature transcript candidate:

`ASCII("PM-V1-RECOVERY-REQUEST-v1") || canonical_map(fields_1_to_7)`

The referenced enrollment certificate must parse and verify independently, and its AccountID must match field 2, DeviceID must match field 6, and epoch must match field 4. The digest is over the exact complete signed certificate bytes, including its signature--not a reconstructed core or a re-encoded interpretation. Deliver the signed request together with the referenced certificate so active devices can inspect the intended device key and validate the digest.

The request ID must be generated with a cryptographically secure random source, scoped for uniqueness to the account, and never reused after pending, abort, finalization, or audit cleanup. The database must retain a non-reusable identifier/tombstone even if large evidence is later archived. A unique request ID is not a substitute for verifying the recovery signature.

### 11.3 RecoveryAbortV1 candidate

An active device aborts one exact pending request by signing an abort statement with that device's DSK. The canonical map has exactly:

| Key | Type | Meaning |
|---:|---|---|
| 1 | unsigned integer, value 1 | object protocol version |
| 2 | `bstr(16)` nonzero | AccountID |
| 3 | `bstr(16)` nonzero | aborting DeviceID |
| 4 | unsigned integer in the candidate epoch range | old epoch |
| 5 | unsigned integer in the candidate epoch range | requested new epoch, old epoch + 1 |
| 6 | `bstr(16)` nonzero | signed recovery request ID |
| 7 | `bstr(32)` | SHA-256 of the exact complete signed `RecoveryRequestV1` bytes |
| 8 | `bstr(64)` | aborting device's DSK Ed25519 signature |

Signature transcript candidate:

`ASCII("PM-V1-RECOVERY-ABORT-v1") || canonical_map(fields_1_to_7)`

The server must verify the DSK against the account's currently active device record and verify that the aborter remains authorized in the old epoch. It must match the request ID, request digest, account, old/new epochs, and current pending request. Using database wall-clock time after acquiring the required locks, accept abort only strictly before the deadline; at or after the deadline, finalization is eligible. Exact retry resolves to the same durable outcome; a request ID or digest mismatch is rejected.

### 11.4 Enrollment proof-of-possession challenge and response candidates

A recovery-signed public-key certificate does not prove that the target device holds the corresponding private DSK. Every device activation therefore requires a one-time DSK proof of possession bound to the exact enrollment certificate.

The gateway issues a fresh, unpredictable challenge only after strictly parsing and verifying the enrollment certificate and checking that the current lifecycle state permits challenge issuance. The stored challenge binds the AccountID, DeviceID, epoch, exact enrollment-certificate digest, random challenge ID, random nonce, expiry, and unused/consumed state. It is an ephemeral server challenge, not account authorization by itself. Suggested candidate sizes are a nonzero 16-byte challenge ID and a 32-byte CSPRNG nonce; proposed maximum lifetime is five minutes, subject to operational review. The database--not caller-provided challenge fields--is authoritative for existence, binding, expiry, and consumption.

`DeviceEnrollmentPoPV1` response map candidate, exactly:

| Key | Type | Meaning |
|---:|---|---|
| 1 | unsigned integer, value 1 | object protocol version |
| 2 | `bstr(16)` nonzero | AccountID |
| 3 | `bstr(16)` nonzero | DeviceID |
| 4 | unsigned integer in the candidate epoch range | enrollment epoch |
| 5 | `bstr(32)` | SHA-256 of the exact complete signed enrollment certificate bytes |
| 6 | `bstr(16)` nonzero | issued challenge ID |
| 7 | `bstr(32)` | exact issued challenge nonce |
| 8 | `bstr(64)` | device DSK Ed25519 signature |

Signature transcript candidate:

`ASCII("PM-V1-DEVICE-POP-v1") || canonical_map(fields_1_to_7)`

Verification and activation must occur in one durable database transaction: match the exact certificate digest and challenge binding; verify the DSK signature against the certificate's DSK public key; re-check account status and authoritative epoch; enforce normal-enrollment versus finalized-recovery rules; consume the challenge exactly once; insert the active device and immutable authorization evidence; and only then clear recovery lock if every recovery-enrollment condition is met. A parsed certificate alone must never activate a device or unlock an account. Exact duplicate submission may return its same durable result; reuse of a consumed challenge with different content must fail closed.

For recovery enrollment, require the verified enrollment certificate digest and DeviceID to match the finalized recovery request. During the pending 48-hour interval, proof/challenge activity must not activate the future-epoch device, advance the account epoch, or alter the active-device set. The target proof can be completed after finalization so it does not depend on a challenge remaining valid for 48 hours.

### 11.5 Native device-key creation and signing boundary

The audited FFI `identity_initialize()` creates a new AccountID and DeviceID, while the current recovery API signs caller-supplied public keys. The audited surface does not show a native method that creates a new device identity bound to an existing AccountID or a narrow DSK proof signer. Before implementation, define an opaque native device context that generates the new DeviceID, DSK and DDHK keys inside Rust for the existing AccountID. It may return public identifiers/keys and the signed certificate/proof objects, but raw DSK/DDHK private keys must never cross UniFFI.

The proof-signing API must only sign the precise canonical `DeviceEnrollmentPoPV1` fields for the matching native device context. It must reject a mismatched AccountID, DeviceID, epoch/certificate digest context, or challenge shape rather than acting as a general signing oracle. Do not ask Kotlin to supply a DSK private key or accept a public-key claim as proof that the native context owns that key. The exact opaque-handle and trusted current-epoch API remains open.

### 11.6 Durable state, atomicity, and audit evidence

Persist request identity and the exact signed request bytes or unambiguous digest with status `PENDING`, `ABORTED`, or `APPLIED`, accepted time, deadline, target device, target enrollment-certificate digest, and exact abort/finalization outcome. Enforce at most one pending request per account and unique `(AccountID, requestID)` across all outcomes. Do not depend on a generic `authorization_events.target_device_id` sentinel to express request lifecycle.

Use a consistent lock order for account, pending request, challenge and device records. Use database wall-clock time after locks are obtained; `now()`/`CURRENT_TIMESTAMP` is transaction-start time and can be stale after lock waits. Abort and finalization must serialize so exactly one wins. Persist the durable event and outcome atomically with state changes. Worker retries, restart, worker downtime, and lost commit acknowledgements must resolve from stored request/event state without a second epoch advance. Keep enough permanent request-ID evidence to prevent re-use even if older full event payloads are archived.

### 11.7 Shared test-vector plan and freeze gates

Do not modify existing `test-vectors/v1/authorization_v1.json` or its expected bytes as part of this candidate. Define a separate proposed `test-vectors/v1/lifecycle_wire_v1.json` covering:

- RecoveryRequestV1, RecoveryAbortV1, challenge binding, and DeviceEnrollmentPoPV1 canonical bytes, domains, signatures, and exact digests.
- Rust-generated vectors independently parsed/verified by Go and Go-generated negative cases verified by Rust where both sides implement the relevant object.
- Wrong keys, invalid signatures, zero identifiers, out-of-range epochs, wrong certificate digest/device/epoch, altered request ID, stale or consumed challenge, expired challenge, abort by revoked/wrong-epoch device, and non-canonical/duplicate/unknown/trailing-byte CBOR.
- Enrollment without proof of possession, proof for a different certificate, recovery enrollment before finalization, pending-request conflicts, request-ID reuse after abort, and exact retries after lost acknowledgements.
- PostgreSQL integration tests for unique constraints, migration, lock waits, abort/finalization race, worker restart/downtime, and idempotent reconciliation. In-memory state tests do not replace these tests.

The test-vector keys must be real test keys with known private material held only in test fixtures. Do not reuse repeated-byte placeholder public keys such as `0x33` or `0x44` in positive proof-of-possession vectors.

Before implementation, review the exact schemas, domain strings, request-ID lifecycle, target-enrollment binding, challenge lifetime, native key-generation/handle design, epoch bounds, HTTP bodies and status/error behavior. Until those are reviewed and parity tests exist, all objects in this section remain **candidate formats--NOT FROZEN**. The current immediate recovery-reset endpoint/path must remain unavailable as a compliant delayed-recovery flow.
## 12. Wire-contract review clarifications (OPEN; NOT FROZEN)

These clarifications close ambiguities found in the review of Section 11. They are design constraints for the next review, not a freeze or permission to implement production routes.

### 12.1 Recovery signer consistency

The signature on `RecoveryRequestV1` and the recovery signature on its referenced `DeviceEnrollmentAuthorizationV1` MUST both verify under the same recovery public key currently committed to that AccountID. The server MUST compare that key and its commitment with authoritative account state before accepting the request. A certificate signed by a different recovery key is invalid for the request even if its public fields and digest match. The request and certificate remain separate signed objects; do not alter the existing certificate schema.

### 12.2 Recovery proof challenge timing

For ordinary enrollment, issue a proof-of-possession challenge only when ordinary enrollment is currently permitted. For the device targeted by a pending recovery request, do not issue a challenge intended for final activation during the 48-hour pending interval. Issue it only after the exact request is durably finalized, then bind the challenge to the finalized request ID, request digest, target DeviceID, target enrollment-certificate digest, and new authoritative epoch. This avoids a five-minute challenge expiring during the timelock and prevents proof/challenge activity from implying early activation. Challenge issuance itself never authorizes the device.

### 12.3 Native device-context key binding

Before a native device context signs `DeviceEnrollmentPoPV1`, it MUST validate the exact enrollment certificate bytes and compare all of the following with its own internally generated device context: AccountID, DeviceID, enrollment epoch, DSK public key derived from the held DSK private key, and DDHK public key derived from the held DDHK private key. It must also check the exact certificate digest and issued challenge context. A matching digest supplied by the caller is not, by itself, proof that the native context owns or matches the private keys committed by the certificate. No private key may cross UniFFI, and the method must not become a general-purpose DSK signing oracle.

### 12.4 Required negative tests

Add explicit tests that reject: a recovery request and enrollment certificate verified by different recovery keys; a recovery PoP challenge requested before request finalization; a native context whose DSK matches but DDHK does not match the referenced certificate; mismatched AccountID/DeviceID/epoch; and a caller-supplied digest that does not equal the SHA-256 digest of the exact canonical signed certificate bytes. Include Rust/Go parity where both sides implement the relevant validation.

The new requirements remain review gates. Sections 11 and 12 are candidate design only; the protocol remains NOT FROZEN.
