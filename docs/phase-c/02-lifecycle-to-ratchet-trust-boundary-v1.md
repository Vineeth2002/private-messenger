# Lifecycle-to-Ratchet Trust Boundary V1

**Document ID:** PM-PHASE-C-02
**Status:** DESIGN PROPOSAL — NOT FROZEN
**Review base:** `d10afb4bd9bc914295d4d0b349482673b434adfb`
**Target repository path:** `docs/phase-c/02-lifecycle-to-ratchet-trust-boundary-v1.md`
**Depends on:** `docs/phase0/13-device-lifecycle-v1.md`, `docs/phase0/14-ratchet-state-persistence-v1.md`, `docs/phase0/15-ratchet-checkpoint-antirollback-v1-proposal.md`, `docs/phase-c/00-ratchet-design-review.md`, and `docs/phase-c/01-operation-state-machine-reconciliation.md`.

> This document defines the missing trust boundary between account/device lifecycle authorization and native Double Ratchet operations. It is a concrete implementation contract proposal, not evidence that the contract is already implemented. It does not authorize production deployment or ratchet-state persistence before the freeze gates in Section 12 pass.

---

## 1. Decision

A ratchet session must not be created, restored, advanced, or used to publish/acknowledge a message merely because Android supplies an `AccountID`, `DeviceID`, account epoch, or `verified = true` flag.

A session may operate only when Rust holds a native-owned, cryptographically verified, current `AuthorizedDeviceContext` derived from:

1. the account's trust-anchored recovery-key commitment;
2. a complete, correctly ordered, signed lifecycle-event chain up to a fresh account lifecycle head;
3. the current device's enrollment and proof-of-possession evidence;
4. the current account epoch and account status;
5. the current device status and device signing-key binding; and
6. matching, fresh responses from **all three** independent ratchet checkpoint witnesses.

The three ratchet witnesses must each independently maintain both an account lifecycle projection and their ratchet anti-rollback journal. They must refuse to authorize a ratchet operation when their lifecycle projection is stale, forked, unavailable, inconsistent with the fresh lifecycle head, or does not authorize the calling device.

**The selected rollback policy remains 3-of-3.** No 2-of-3 quorum, local-only fallback, Android-Keystore-only counter, or offline ratchet transition is introduced by this document.

## 2. Existing source facts at the review base

The following are facts from the reviewed source snapshot. They are not claims that the lifecycle design is frozen.

### 2.1 Existing lifecycle authorization objects

- `DeviceEnrollmentAuthorizationV1` is signed under the recovery public key using the `PM-V1-DEVICE-ENROLL-v1` domain. It binds account ID, account epoch, device ID, DSK public key, and DDHK public key.
- `EpochTransitionAuthorizationV1` is signed under the recovery public key using `PM-V1-EPOCH-TRANSITION-v1`. A normal revocation advances `old_epoch` to `old_epoch + 1` and identifies the target device. The legacy recovery-reset action remains parseable but the state-mutating Gateway API rejects it; the delayed `RecoveryRequestV1` flow is separate.
- `RecoveryRequestV1` is signed under the recovery public key. It binds account ID, old/new epoch, request ID, target device ID, and the SHA-256 digest of the exact enrollment-certificate bytes. The request and target enrollment certificate are verified under the same recovery public key.
- `RecoveryAbortV1` is signed by the DSK of an already active device. It binds the account, device, epochs, request ID, and digest of the exact recovery-request bytes. The Gateway checks that the aborting device is active at the old epoch and that database time is strictly before `finalize_after`.
- The recovery request's 48-hour deadline is set by PostgreSQL from `accepted_at`; callers cannot choose the deadline. Finalization uses database time and is guarded again by a database trigger.
- Recovery finalization advances the account epoch, revokes all currently active devices, places the authorization account into `RecoveryLocked`, and records the finalized request in one database transaction. A later recovery enrollment challenge is tied to the exact finalized request, target device, epoch, and enrollment-certificate digest. Successful recovery enrollment installs the new device and returns the account to active state.
- Ordinary candidate enrollment uses a one-time challenge and DSK proof-of-possession. A recovery-signed public-key certificate by itself is not sufficient to activate a device.
- On ordinary device revocation, the target device is revoked, the account epoch advances, and the still-active devices' `authorized_epoch` values advance. The `devices.account_epoch` column is currently updated as an account-epoch mirror for known devices; it must not be misinterpreted as historical per-device enrollment epoch. The per-device authorization record retains `authorized_epoch` and `revoked_epoch` semantics.

### 2.2 Current evidence gaps

- `authorization_events` currently permits only generic `ENROLL` and `TRANSITION` kinds. Recovery finalization is represented as a `TRANSITION` row whose `cert_cbor` contains the `RecoveryRequestV1` bytes. That is not an adequate typed lifecycle-event contract for independent witness consumption.
- The durable recovery-request row stores the abort bytes/digest and terminal status, but there is no single signed, append-only lifecycle event stream that witnesses can consume for request, abort, finalization, and recovery enrollment outcomes.
- A database row or a Gateway API response is not independently verifiable lifecycle evidence for a remote witness.
- The current Gateway KT witness verifier has three configured witnesses and a 2-of-3 threshold. It is not the ratchet checkpoint protocol and must not be reused as the required 3-of-3 ratchet anti-rollback service.
- The reviewed source snapshot did not demonstrate a production ratchet checkpoint service with three independent durable journals, a ratchet `MARKED_USED` barrier, or a native verified lifecycle context.
- The current UniFFI `AccountContext` does not itself establish an authoritative current account epoch, lifecycle status, or current device authorization.

## 3. Trust domains and security responsibilities

| Domain | Owns | Must not be trusted to do |
|---|---|---|
| Account recovery authority | Recovery public key and its account commitment; signs enrollment and epoch-transition authorization objects | Prove that a Gateway database transaction committed or that a 48-hour deadline elapsed |
| Active device DSK | Signs recovery aborts and device proof-of-possession challenges | Change account epoch, enroll another device by itself, or override revocation |
| Gateway lifecycle authority | Serializes lifecycle database transactions; records accepted/aborted/finalized outcomes and database timestamps; emits signed committed lifecycle evidence | Replace or forge the recovery-key/DSK authorization signatures; act as the ratchet rollback anchor |
| Ratchet witnesses W1/W2/W3 | Independently verify lifecycle evidence; maintain append-only lifecycle projections and per-device anti-rollback journals; sign status/reservation/mark-used/commit receipts | Accept caller-supplied epoch or infer authorization from a KT inclusion proof alone |
| Rust crypto core | Verifies the evidence bundle; owns the verified authorization context and all ratchet secrets/candidate state | Trust a Kotlin boolean, mutable caller epoch, or unverified serialized binding |
| Android/Kotlin | Network transport, app UI, encrypted persistence, Keystore wrapping, and delivery orchestration | Hold raw ratchet secrets, declare lifecycle authority, or bypass witness receipts |

### 3.1 Trust assumptions

This design adds a dedicated Gateway Lifecycle Attestation key (GLA key) whose public key is pinned by the ratchet witness registry. The GLA signature means: **the exact lifecycle event payload was read from an immutable outbox record that was already committed and visible in the Gateway's authoritative database before the GLA signer signed it.** The signature timestamp is the GLA attestation time, not a claim about the database's physical commit instant. Business timestamps such as `accepted_at`, `aborted_at`, and `finalized_at` remain database-generated facts inside the event payload and retain their own semantics.

The GLA key does not replace the recovery key or the DSK. Witnesses must still parse and verify the underlying signed lifecycle objects and check all bindings. The GLA key attests the database fact and its commit ordering, not the account owner's authorization.

The Gateway lifecycle database and GLA signing service are therefore part of the trusted computing base for lifecycle ordering and database-time facts. This design does not protect against a fully compromised GLA signing authority that can forge committed lifecycle outcomes. Reducing that trust would require a separate, reviewed distributed lifecycle-commit protocol; it must not be claimed as solved by the ratchet witnesses alone.

The three ratchet witnesses are independent only if their operators, signing keys, durable journals, credentials, infrastructure failure domains, and backup/restore procedures are independent. Three processes backed by one database or one shared signing key do not satisfy this requirement.

## 4. Authoritative lifecycle state

Each witness maintains the same deterministic projection for every account. The projection is derived only by applying a gap-free, signature-valid lifecycle event chain.

Minimum state:

```text
AccountLifecycleState {
    account_id: [u8; 16]
    recovery_commitment: [u8; 32]
    account_epoch: u32
    account_status: ACTIVE | RECOVERY_LOCKED
    lifecycle_sequence: u64
    lifecycle_head_digest: [u8; 32]
    lifecycle_state_digest: [u8; 32]
    devices: Map<DeviceID, DeviceLifecycleState>
    pending_recovery: Option<PendingRecoveryState>
}

DeviceLifecycleState {
    device_id: [u8; 16]
    dsk_public: [u8; 32]
    ddhk_public: [u8; 32]
    enrollment_certificate_digest: [u8; 32]
    authorized_epoch: u32
    status: ACTIVE | REVOKED
    revoked_epoch: Option<u32>
    enrollment_proof_digest: [u8; 32]
}

PendingRecoveryState {
    request_id: [u8; 16]
    request_digest: [u8; 32]
    target_device_id: [u8; 16]
    old_epoch: u32
    new_epoch: u32
    enrollment_certificate_digest: [u8; 32]
    accepted_at_unix_ms: u64
    finalize_after_unix_ms: u64
}
```

The account state digest is a deterministic hash of the canonical encoding of the complete projection, including every device status and every pending-recovery field. The exact state-digest encoding and vectors must be frozen before implementation. A digest of only `(account_id, epoch, status)` is insufficient because it would not bind the device-key set or pending recovery state.

`lifecycle_sequence` is monotonically increasing per account and never resets when the account epoch advances. `account_epoch` is the authorization epoch. They are not interchangeable.

## 5. Signed lifecycle event contract

### 5.1 Event envelope

Introduce an append-only `LifecycleEventV1` envelope. The following is the proposed canonical-CBOR field contract; numeric keys and exact integer widths must be fixed in the cross-language vectors before code is frozen.

| Key | Field | Required meaning |
|---:|---|---|
| 1 | `version` | Integer `1` |
| 2 | `event_id` | Fresh nonzero 16-byte identifier; stable across exact retries |
| 3 | `account_id` | 16-byte account identifier |
| 4 | `lifecycle_sequence` | Next account event sequence, exactly predecessor + 1 |
| 5 | `previous_event_digest` | SHA-256 digest of the previous complete event; all-zero only for the account genesis event |
| 6 | `event_type` | Explicit typed event discriminator from Section 5.3 |
| 7 | `old_epoch` | Account epoch before the event; zero only for account genesis |
| 8 | `new_epoch` | Account epoch after the event |
| 9 | `gla_attested_at_unix_ms` | GLA signer time after it has read the already-committed immutable outbox record; it is not a database commit timestamp |
| 10 | `payload` | Exact canonical bytes of the underlying authorization object(s), database-generated lifecycle timestamps, and required outcome evidence |
| 11 | `resulting_state_digest` | Digest of the complete post-event lifecycle projection |
| 12 | `gla_key_id` | Identifier of the pinned Gateway Lifecycle Attestation key |
| 13 | `signature` | Ed25519 signature over the domain-separated canonical fields 1–12 |

Signature input:

```text
"PM-V1-LIFECYCLE-EVENT-v1" || canonical_cbor(map(fields 1..12))
```

The event digest is SHA-256 over the exact canonical full event bytes, including the GLA signature. The event chain is account-scoped. Because the next event links to the digest of the fully signed predecessor, the Gateway must enforce a per-account attestation fence: at most one committed event may be `PENDING_ATTESTATION`, and no later lifecycle mutation for that account may commit until that event is GLA-attested. This deliberately makes lifecycle mutation unavailable during a prolonged GLA outage rather than allowing an ambiguous predecessor. A duplicate event is idempotent only when event ID, sequence, digest, and exact bytes all match. A different digest at an already-used sequence is a fork and must fail closed.

Do not place raw private keys, recovery secrets, DSK private keys, message keys, or ratchet state in an event payload.

### 5.2 Gateway current-head statement

A witness must be able to tell whether its lifecycle projection is current, not merely internally consistent. Add a signed `LifecycleHeadV1` response from the Gateway lifecycle authority.

Minimum fields:

- account ID;
- latest lifecycle sequence;
- latest lifecycle event digest;
- complete lifecycle state digest;
- account epoch and account status;
- issue time and short expiry;
- caller-supplied fresh 32-byte challenge;
- GLA key ID and GLA signature.

The challenge is generated by the client for that status round and is included in the signed head. Each witness also signs its own response to a fresh witness challenge. A replayed old Gateway head cannot satisfy a new random challenge.

The proposed head signature input is `"PM-V1-LIFECYCLE-HEAD-v1" || canonical_cbor(map(all head fields except signature))`. The challenge is exactly 32 fresh random bytes; the head expiry must be no more than 60 seconds after issue time. The exact map keys, timestamp units, key ID format, and vectors remain freeze items.

A witness must compare the signed head to its local projection:

- same sequence and same event/state digests: it may continue to the remaining device/checkpoint checks;
- Gateway head ahead: fetch and verify every missing event in order, apply them, and then compare the final state digest;
- witness ahead of Gateway head: fail closed as rollback/equivocation;
- same sequence but different digest/state: fail closed as fork/equivocation;
- cannot fetch or validate the complete gap: fail closed.

The Gateway head must be generated from the authoritative committed lifecycle state, not from caller parameters or a cache that can lag a committed transition. If any newer lifecycle event is committed but still `PENDING_ATTESTATION`, the Gateway must not issue an `ACTIVE` head for the prior event; it must return a non-authorizing pending/unavailable result, and witnesses must refuse ratchet authorization. Otherwise a revocation could commit while the prior head remained usable. Its signing key must be isolated, rotated through a threshold-authorized registry procedure, and audited.

### 5.3 Required event types and state transitions

No generic `TRANSITION` event is permitted in the new witness-facing stream. The event type must identify the lifecycle operation unambiguously.

| Event type | Required payload and verification | Resulting state |
|---|---|---|
| `ACCOUNT_CREATED` | Account bootstrap evidence; account ID; initial epoch; recovery commitment. The GLA key attests the committed bootstrap row. Witness verifies the bootstrap evidence and recovery-commitment binding. | Account becomes `ACTIVE`; lifecycle sequence starts at 1; no devices unless bootstrap explicitly includes an independently proven initial device enrollment. |
| `DEVICE_ENROLLED` | Exact `DeviceEnrollmentAuthorizationV1` bytes and exact successful DSK proof-of-possession evidence. Verify recovery-key signature, account ID, current epoch, device ID, DSK/DDHK keys, challenge binding, and one-time challenge consumption outcome. | Add one active device with `authorized_epoch = account_epoch`; reject duplicates and reactivation of a revoked device ID. |
| `DEVICE_REVOKED` | Exact `EpochTransitionAuthorizationV1` bytes. Require `RevokeDeviceAction`, recovery-key signature, current old epoch, `new_epoch = old_epoch + 1`, and an existing active target. | Advance account epoch; revoke only the target; set its `revoked_epoch = new_epoch`; advance `authorized_epoch` for every surviving active device to the new epoch. The `devices.account_epoch` mirror must follow the existing database meaning and must not be treated as per-device enrollment provenance. |
| `RECOVERY_REQUESTED` | Exact `RecoveryRequestV1` bytes and exact target enrollment-certificate bytes. Verify both under the same recovery key; verify certificate digest and account/device/new-epoch binding. Include database-generated `accepted_at` and `finalize_after`; require `finalize_after` to equal the persisted database rule `accepted_at + 48 hours`. This event records acceptance of the request; it does not claim that the 48-hour delay has elapsed. | Create one pending recovery request. The old epoch remains authoritative while pending. Existing active devices remain authorized at the old epoch. New enrollment and conflicting lifecycle transitions remain blocked as required by the current Gateway rules. |
| `RECOVERY_ABORTED` | Exact `RecoveryAbortV1` bytes, exact original request bytes, authoritative DSK key from the current witness projection, and database terminal-outcome evidence. Verify DSK signature, request digest, active-device status at old epoch, matching account/epochs/request ID, and `aborted_at < finalize_after`. | Clear pending recovery; account remains `ACTIVE` at the old epoch; no device is reactivated and no epoch is advanced. |
| `RECOVERY_FINALIZED` | Exact `RecoveryRequestV1` bytes, matching pending request, and database terminal-outcome evidence. Require `finalized_at >= finalize_after`; verify request and enrollment-certificate binding. | Advance account epoch to the request's new epoch; revoke all devices active in the old epoch; set account status `RECOVERY_LOCKED`; no old device may perform a ratchet operation. |
| `RECOVERY_DEVICE_ENROLLED` | Exact recovery enrollment certificate, exact finalized request reference/digest, exact recovery challenge binding, and successful DSK proof-of-possession evidence. Require target device and new epoch to match the finalized request. | Install the new device at the new epoch and set account status to `ACTIVE`. No old device is restored. |

The legacy `EpochTransitionAuthorizationV1` recovery-reset action must remain rejected by state-mutating APIs and by witnesses. It must never bypass the delayed recovery flow.

### 5.4 Lifecycle-specific rules

1. A pending recovery request does **not** itself advance the account epoch or revoke the current devices. The old epoch remains authoritative until the request is aborted or finalized.
2. Recovery abort is not a new enrollment and not an epoch transition. It clears only the exact pending request that it names.
3. Recovery finalization revokes all old devices and locks the account. The new recovery device becomes active only after the exact finalized-request-bound enrollment and DSK proof-of-possession succeed.
4. Revocation advances the epoch for the account. Surviving devices must refresh their trusted lifecycle context before further ratchet operations; prior-epoch session contexts cannot silently continue under the new epoch.
5. A revoked device ID cannot be reactivated by replaying an old enrollment certificate. New device identity and fresh key material are required.
6. A recovery commitment is not the recovery public key. Every witness must verify that the supplied recovery public key hashes to the account's trust-anchored commitment before accepting recovery-key signatures.

## 6. Witness lifecycle projection and ratchet checkpoint coupling

### 6.1 Independent state held by each witness

Each witness maintains two related but separate logs:

- **Account lifecycle log:** account-scoped `lifecycle_sequence`, event-chain digest, full state digest, epoch/status, and device authorization projection.
- **Device checkpoint log:** device-scoped monotonic `checkpoint_sequence`, committed checkpoint digest, pending operation journal, reservations, irreversible `MARKED_USED` records, staged checkpoint commitments, and terminal/commit receipts.

The sequence scopes must not be conflated:

| Value | Scope | Meaning |
|---|---|---|
| `lifecycle_sequence` | Account | Ordered account/device authorization changes |
| `checkpoint_sequence` | `(AccountID, DeviceID)` | Monotonic anti-rollback transitions shared by all ratchet sessions on that device |
| `record_generation` | One ratchet session | Active persisted RatchetState generation |
| `account_index_generation` | Local account/device catalog | Authenticated local catalog generation |
| `operation_id` | One logical operation | Unique ID bound to one exact intent/outcome |

The checkpoint digest must bind the lifecycle sequence, lifecycle event digest, account epoch, device authorization state, complete authenticated session catalog, session record generations/digests, inbox/outbox/deduplication commitments, and the operation completion evidence. A local database generation is not an anti-rollback anchor.

### 6.2 Required witness status response

Each witness status response must be freshly challenged and signed. It must include at least:

- witness ID and witness signing-key ID;
- account ID and device ID;
- client challenge;
- lifecycle sequence, head digest, state digest, account epoch, and account/device active status;
- device checkpoint sequence and committed checkpoint digest;
- pending operation ID and state, if any;
- witness issue time and short expiry;
- signature over the exact canonical status fields.

Rust (or a native verification component) must verify all three witness signatures and require byte-identical agreement on the account/device lifecycle state and device checkpoint predecessor. Two matching witnesses are not enough.

### 6.3 Witness authorization predicate

A witness may sign a reservation or operation transition only when all conditions are true:

```text
account.lifecycle_status == ACTIVE
AND device.status == ACTIVE
AND device.authorized_epoch == account.account_epoch
AND presented.lifecycle_sequence == witness.lifecycle_sequence
AND presented.lifecycle_head_digest == witness.lifecycle_head_digest
AND presented.lifecycle_state_digest == witness.lifecycle_state_digest
AND presented.account_epoch == witness.account_epoch
AND checkpoint_predecessor matches the witness journal
AND no conflicting or unresolved operation blocks this device
AND request is fresh, correctly signed, and correctly bound
```

A non-null `pending_recovery` with `account_status == ACTIVE` follows the exact policy in Section 5.4: existing active devices can remain authorized at the old epoch, but no conflicting lifecycle mutation may be accepted. `account_status == RECOVERY_LOCKED` always denies ratchet operations.

### 6.4 Lifecycle changes and in-flight ratchet operations

Lifecycle transitions and ratchet operations must share an account/device-wide serialization mechanism at each witness. A per-session mutex is insufficient because the checkpoint sequence and local account index are shared by all sessions on a device.

The order must be total and externally consistent:

1. A ratchet operation that obtains a valid 3-of-3 reservation is ordered before a later lifecycle event for that device/account.
2. The lifecycle event cannot be applied to the witness projection while a prior marked-used operation remains unresolved.
3. The prior operation must reach the exact committed or reviewed terminal outcome before the lifecycle event advances the witness lifecycle projection.
4. After the lifecycle event is committed at all three witnesses, no new operation may use the prior lifecycle sequence or epoch.
5. If a witness is unavailable, the transition cannot be treated as committed by the ratchet system. No cached or two-witness fallback is permitted.

This rule creates a deliberate availability trade-off: an ambiguous marked-used operation can delay lifecycle propagation. Do not silently override it by deleting a pending journal entry or restoring a database snapshot. Emergency retirement/terminalization semantics require a separate explicit protocol and review; they are not defined by a timeout.

### 6.5 3-of-3 operation protocol remains mandatory

Every ratchet state transition continues to use the unified operation flow in `01-operation-state-machine-reconciliation.md`:

1. Fresh lifecycle and checkpoint status from all three witnesses.
2. Exact local ARMED intent persisted before message AEAD.
3. Exact reservation at all three witnesses.
4. Irreversible `MARKED_USED` acknowledged by all three witnesses before message AEAD.
5. Exactly one native candidate operation; active state is not mutated.
6. Exact encrypted staged result persisted locally.
7. Matching commit receipt from all three witnesses.
8. Atomic local activation and native candidate promotion.
9. Only then send, display, or acknowledge.

The `MARKED_USED` and commit messages must bind `lifecycle_sequence`, lifecycle head/state digests, account epoch, device ID, checkpoint predecessor, operation ID, and staged result digest. A lifecycle transition must not be spliced into the middle of a ratchet operation by changing the epoch field supplied by Kotlin.

## 7. Native Rust and UniFFI boundary

### 7.1 Native-owned verified authorization context

Introduce an opaque native type, conceptually:

```rust
pub struct VerifiedDeviceAuthorization {
    account_id: AccountId,
    device_id: DeviceId,
    account_epoch: u32,
    lifecycle_sequence: u64,
    lifecycle_head_digest: [u8; 32],
    lifecycle_state_digest: [u8; 32],
    dsk_public: [u8; 32],
    ddhk_public: [u8; 32],
    // native verification provenance and freshness binding
}
```

The fields above are illustrative internal fields, not a public constructor contract. The type must have no Kotlin-callable constructor that accepts them as authoritative values. Only the native verification path may create it after validating the account bootstrap anchor, full lifecycle chain/current head, device authorization, DSK proof, witness registry, and 3-of-3 signed witness status.

### 7.2 Required native operations

Proposed API capabilities (method names and UDL syntax are not frozen):

- verify and construct the current `VerifiedDeviceAuthorization` from exact lifecycle evidence and three witness status responses;
- reject expired evidence, wrong account/device bindings, stale lifecycle sequence, forked event chains, revoked devices, recovery-locked accounts, and witness disagreement;
- create or restore a ratchet session only when bound to a current verified authorization context;
- invalidate/close sessions when lifecycle sequence or account epoch changes;
- prepare isolated candidate ratchet states without mutating active session state;
- expose only opaque operation handles and ciphertext/public metadata to Kotlin;
- promote a candidate only after the exact matching durable checkpoint commit succeeds;
- seal/restore ratchet state through the narrowly scoped, reviewed secret-protection API described in Document 14.

### 7.3 Forbidden native/API behavior

- No method such as `create_session(account_id, device_id, epoch, verified=true)`.
- No trust in an epoch or device-status value supplied solely by Kotlin.
- No raw root key, sending/receiving chain key, message key, DH private key, plaintext serialized ratchet state, or secret-bearing candidate state crossing UniFFI.
- No integer/pointer handle persisted and later treated as a valid session.
- No generic “encrypt arbitrary bytes with this DEK” API exposed to Kotlin as a substitute for a narrowly scoped native state-sealing operation.
- No session restore if lifecycle freshness or 3-of-3 witness agreement cannot be re-established.

The current `AccountContext` must not be relabeled as verified without implementing and testing this evidence path.

## 8. Gateway implementation changes required

These are the concrete Gateway changes implied by this contract. None is claimed complete in the reviewed snapshot.

### 8.1 Add an append-only lifecycle event journal

Add the next migration after Patch 03, tentatively `0013_lifecycle_event_log.sql`, that introduces:

- an account-scoped, unique `(account_id, lifecycle_sequence)` event/outbox-intent row;
- previous-event digest and resulting-state digest fields;
- exact event type and exact canonical payload bytes;
- database-generated business timestamps (`accepted_at`, `aborted_at`, `finalized_at`, and challenge-consumption facts where applicable);
- a one-way publication state such as `PENDING_ATTESTATION` then `ATTESTED`;
- a separate append-only GLA attestation record containing the GLA key ID, `gla_attested_at_unix_ms`, exact event digest, and signature;
- durable publication/outbox retry metadata for the three witnesses;
- immutability guards against update/delete/truncate of the committed event payload and attestation;
- transactional linkage so the lifecycle state mutation and unsigned event/outbox-intent row commit atomically.

**Required signing order:** the lifecycle transaction commits the state mutation and immutable unsigned event/outbox-intent row together. Only after that commit is visible may the isolated GLA signer read the exact row, verify its account sequence/predecessor and canonical digest, and sign it. The signer records the signature in a separate append-only attestation record. Witnesses must reject `PENDING_ATTESTATION` events and may consume only the exact GLA-attested bytes. A crash after the lifecycle commit but before signing leaves a committed-but-unpublished event; retry the signer from the immutable row. It must not roll back or fabricate a different event.

The migration must preserve old compatibility rows where necessary. Do not rewrite historical `authorization_events` rows into a fictional typed history. New events must use the explicit type values in Section 5.3.

### 8.2 Add typed evidence for missing outcomes

For every operation below, append the immutable unsigned typed event/outbox intent in the same transaction as the corresponding lifecycle mutation. The post-commit GLA signer then attests that exact intent; do not attempt to sign from inside the state transaction.

- Normal revocation: append `DEVICE_REVOKED` with the exact signed transition bytes and resulting device/account projection.
- Ordinary enrollment: append `DEVICE_ENROLLED` only in the same transaction that installs the device, consumes the DSK proof challenge, and records the enrollment authorization.
- Recovery request: append `RECOVERY_REQUESTED` only with the durable pending request row, exact signed request/certificate bytes, `accepted_at`, and `finalize_after`.
- Recovery abort: append `RECOVERY_ABORTED` in the same transaction that marks the request ABORTED and stores the exact abort bytes/digest and database `aborted_at`. The current durable request row is not a substitute for the witness-facing event.
- Recovery finalization: append `RECOVERY_FINALIZED` in the same transaction that advances the epoch, revokes old devices, locks the account, marks the request FINALIZED, and records `finalized_at`. Do not represent this as an untyped `TRANSITION` in the new event stream.
- Recovery enrollment: append `RECOVERY_DEVICE_ENROLLED` in the transaction that installs the exact target device, consumes the recovery-bound DSK proof challenge, records the enrollment, and unlocks the account.

### 8.3 Add signed lifecycle head and event retrieval

Expose authenticated endpoints or an equivalent transport for:

- fresh `LifecycleHeadV1` generation;
- retrieval of a contiguous event range by account and sequence;
- retrieval of the exact current event by digest;
- publication/retry status for each witness;
- operator-visible health of the lifecycle event publisher and GLA signing path.

A success response from an ordinary lifecycle API must distinguish (a) lifecycle transaction committed and event awaiting GLA attestation, (b) GLA attestation published, and (c) all three ratchet witnesses applied the event. A client must not infer either GLA attestation or witness propagation from the original lifecycle HTTP success alone. If post-commit GLA signing is temporarily unavailable, the durable event remains pending and the ratchet boundary remains fail-closed until signing and 3-of-3 propagation complete.

### 8.4 Recovery finalizer operations

The recovery finalization worker must publish the exact signed finalization event only after the transaction has committed. It needs health/metrics for scan success, due queue depth, oldest overdue request, per-account failure count, last successful finalization, and witness propagation lag. Logging and retrying every 15 seconds is not a substitute for supervision, health reporting, and alerting.

## 9. Witness operational requirements

Before counting a service as one of the three witnesses, prove all of the following:

- independent operator and administrative credentials;
- independent signing key protected in its own HSM or equivalent hardware-backed boundary;
- independent database and append-only journal;
- monotonic/anti-rollback recovery of its own journal, or a fail-closed restore procedure that requires external reconciliation before it can sign again;
- independent backup storage and tested restore fencing;
- authenticated mutually independent communication paths;
- signed key-registry bootstrap and threshold-authorized witness-key rotation;
- monitoring for unavailable, stale, divergent, restored, or equivocating witnesses;
- no automatic replacement of a missing witness with a second signature from one operator or one backend;
- auditable incident procedure for key compromise and witness replacement.

A witness whose durable journal was restored from a backup that may be older than its last signed response must enter a non-signing recovery state. It must not silently resume from the backup and issue valid-looking status or checkpoint signatures.

The KT witness verifier remains a separate subsystem. Its current 2-of-3 threshold does not satisfy this ratchet design.

## 10. Required acceptance tests

### 10.1 Lifecycle evidence tests

1. Canonical cross-language vectors for account creation, enrollment, revocation, recovery request, abort, finalization, and recovery enrollment.
2. Wrong recovery commitment, wrong account ID, wrong device ID, wrong epoch, wrong enrollment-certificate digest, wrong request digest, invalid signature, invalid DSK proof, and legacy immediate recovery-reset attempts are rejected.
3. Event replay with exact bytes is idempotent; same event ID with changed bytes is rejected; same sequence with a different digest is a fork and fails closed.
4. Missing sequence, wrong previous-event digest, wrong resulting-state digest, out-of-order delivery, and conflicting current-head statement are rejected.
5. Gateway head challenge replay, expired head, GLA key rotation mismatch, unknown key ID, and malformed canonical encoding are rejected.
6. Recovery request/abort/finalization tests at `finalize_after - 1 ms`, exactly `finalize_after`, and `finalize_after + 1 ms`, using the authoritative database timestamp and exact persisted terminal state.
7. Recovery request remains at old epoch while pending; abort keeps old epoch; finalization advances epoch and revokes old devices; recovery enrollment activates only the exact requested new device.
8. Revoking one device advances the account epoch and active survivors' authorized epoch; target is revoked; no prior-epoch native context remains usable.

### 10.2 Witness tests

1. Three independent processes, operators, keys, and databases produce matching signed lifecycle and checkpoint evidence.
2. Any one unavailable witness blocks new ratchet operations and blocks a 3-of-3 lifecycle propagation claim.
3. A stale witness must catch up the exact signed event chain before signing; it cannot sign using stale cached account state.
4. Same-sequence equivocation, witness database rollback, stale backup restore, key compromise, key rotation, lost acknowledgement, and partial witness application all fail closed.
5. A witness cannot authorize a device absent from the lifecycle projection or already revoked.
6. A recovery-locked account is rejected even if the device has a valid old DSK and a previously valid enrollment certificate.
7. Concurrent lifecycle and ratchet operations serialize account/device-wide; no operation can commit against a lifecycle predecessor that has already been superseded.

### 10.3 Native boundary tests

1. No FFI method can create a verified account context from caller-supplied IDs/epoch/boolean alone.
2. Wrong-device, wrong-account, stale-epoch, stale-lifecycle-sequence, expired-head, missing-witness, and witness-disagreement inputs fail before any ratchet function runs.
3. Lifecycle update invalidates the old native authorization context and all sessions bound to the old epoch/authorization state.
4. Kotlin cannot inspect or export ratchet secrets or candidate state.
5. Process restart restores only sealed state whose binding matches the revalidated current lifecycle context and committed witness checkpoint.

### 10.4 End-to-end tests

Run two real Android devices through Alice-to-Bob and Bob-to-Alice encrypted messaging, then test app restart, network interruption, duplicate delivery, replay, out-of-order messages, witness outage, device revocation, recovery pending, recovery abort, recovery finalization, and recovery enrollment. Verify that the revoked device cannot send, receive new messages, decrypt newly delivered content, publish stale outbox entries, or acknowledge messages after the lifecycle transition is committed.

## 11. Implementation order

Do not start by serializing `RatchetState`. Implement in this order:

1. **Freeze lifecycle event semantics:** agree on event fields, event types, GLA trust assumptions, account bootstrap anchor, event ordering, and exact state-digest vectors.
2. **Gateway durable event journal:** add the append-only typed event table/outbox and write events atomically from every lifecycle transaction, including abort and finalization.
3. **Gateway GLA and current-head API:** implement key isolation, key registry/rotation, signed head, contiguous event retrieval, and observability.
4. **Independent witness lifecycle projection:** implement event-chain verification, head comparison, device authorization projection, anti-rollback journal, and all-three status receipts. Keep this separate from KT witnesses.
5. **Ratchet witness operation protocol:** implement account/device-wide serialization, reservation, irreversible mark-used, staging commit receipts, terminal outcomes, and recovery behavior against the lifecycle projection.
6. **Native verified authorization context:** implement the Rust/UniFFI evidence-verification boundary and tests. No ratchet session restore or operation is enabled before this gate passes.
7. **Secret-safe ratchet candidate and persistence path:** address the generic CBOR secret-buffer issue, ratchet temporary copies, candidate state isolation, and Document 14's DEK sealing boundary.
8. **Android durable integration:** connect Gateway transport, witness receipts, encrypted local persistence, and only then the chat UI.
9. **Independent protocol/security review and release gates:** complete the tests in Section 10 and the broader acceptance suite in Documents 00/01/14/15.

## 12. Freeze blockers and explicit non-claims

This document is not frozen. The following decisions still require review before implementing the protocol as a production security boundary:

1. **Genesis trust anchor:** specify the exact signed account-bootstrap object and how witnesses pin/verify the initial recovery commitment. Do not trust an arbitrary `accounts` row or a self-asserted recovery public key.
2. **GLA authority model:** define key custody, signing service isolation, transaction-to-signature binding, key rotation, compromise response, and what guarantees remain if the Gateway/GLA authority is compromised.
3. **Exact canonical encoding:** publish canonical CBOR vectors for every event, head, witness status, and lifecycle state digest; specify integer bounds and maximum lengths.
4. **Database/event atomicity:** prove every lifecycle state mutation and typed event are committed atomically, including all recovery terminal outcomes and challenge consumption.
5. **Witness lifecycle catch-up:** specify retry, pagination, retention, snapshot, and database-restore reconciliation without accepting a fork or rollback.
6. **Lifecycle/ratchet concurrency:** independently review the serialization rule and the behavior when a marked-used operation is unresolved during a revocation or recovery finalization. A timeout is never permission to release or erase it.
7. **Witness independence and disaster recovery:** demonstrate three actual independent operators, keys, journals, and anti-rollback restore procedures.
8. **Revocation and prior session policy:** freeze whether every session bound to an old account epoch is retired and re-established after an epoch change. This proposal requires old-epoch contexts to stop; it does not yet define every wire-level session-rekey message.
9. **Operational availability:** measure three-region request latency, outage behavior, event propagation lag, and the effect of strict 3-of-3 on message availability.
10. **Independent security review:** have reviewers who did not author the protocol inspect lifecycle signatures, timestamp authority, witness journals, checkpoint binding, crash recovery, and native secret ownership.

### Release gate

Until all blockers are closed, the lifecycle-to-ratchet boundary is **NOT FROZEN**. No production ratchet persistence, production witness deployment, or Android chat integration may be described as secure or complete based on this proposal. The existing source audit and this document are design work only.

---

## Appendix A — Current-to-required gap table

| Area | Reviewed state | Required next state |
|---|---|---|
| Lifecycle wire objects | Enrollment, revoke, recovery request, and recovery abort candidate formats exist | Freeze full event/head/state-digest encodings and vectors |
| Gateway lifecycle transactions | PostgreSQL-backed enrollment, revocation, recovery begin/abort/finalize flows exist | Atomically append typed lifecycle event and witness publication record for every transition |
| Recovery event semantics | Finalization currently appears as generic `TRANSITION`; abort is stored in recovery request row | Explicit `RECOVERY_REQUESTED`, `RECOVERY_ABORTED`, `RECOVERY_FINALIZED`, and `RECOVERY_DEVICE_ENROLLED` evidence |
| Current lifecycle head | No demonstrated signed, challenge-bound head for independent ratchet witnesses | GLA-signed fresh head and contiguous signed event feed |
| Witness integration | KT witness verifier exists with 2-of-3 threshold; no ratchet integration demonstrated | Three independent ratchet witnesses, all required, each maintaining lifecycle and checkpoint journals |
| Native authorization | `AccountContext` lacks verified current lifecycle status/epoch | Opaque Rust-owned `VerifiedDeviceAuthorization` |
| Ratchet state persistence | Design proposal only; generic CBOR path is not secret-safe | Secret-safe candidate/persistence implementation after lifecycle and witness gates |
| Android messaging | HTTP envelope transport exists; complete native ratchet-backed chat path not demonstrated | Real two-device E2EE path gated by native authorization and 3-of-3 checkpoint commits |

## Appendix B — Non-negotiable rejection cases

A witness and the native core must reject, not warn-and-continue, when any of the following occurs:

- account recovery commitment does not match the recovery public key;
- lifecycle event is unsigned, malformed, noncanonical, out of sequence, forked, or has an invalid previous digest;
- same sequence has different event bytes/digest;
- signed Gateway head is stale, expired, challenge-mismatched, or inconsistent with local witness state;
- a lifecycle event is missing and cannot be fetched/verified;
- device is revoked, absent, not yet enrolled, or not authorized at the current account epoch;
- account is `RECOVERY_LOCKED`;
- recovery abort does not bind the exact pending request or is not backed by the durable pre-deadline outcome;
- recovery finalization timestamp/status does not prove the deadline elapsed;
- only one or two ratchet witnesses respond;
- witnesses disagree on lifecycle head, epoch, device status, checkpoint sequence, predecessor digest, pending operation, or operation state;
- local database is ahead of or behind the 3-of-3 committed checkpoint;
- Kotlin supplies an epoch/status that conflicts with native-verified evidence;
- witness backup restoration or key rotation cannot prove continuity of its signed journal.

**Default response to an unresolved trust condition: fail closed, preserve evidence, and require authenticated recovery. Never silently downgrade the quorum or resume from a stale local snapshot.**
