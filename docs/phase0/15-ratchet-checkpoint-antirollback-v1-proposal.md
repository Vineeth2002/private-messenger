# Private Messenger — Independent Ratchet Checkpoint Quorum V1

**Status:** Engineering proposal; NOT FROZEN; requires independent security review<br>
**Revision:** 2 — corrects the original 2-of-3 Byzantine quorum error. This revision supersedes the original installed copy.<br>
**Purpose:** Close the full-device-snapshot rollback gap before ratchet-state persistence is frozen or implemented.<br>
**Compatibility:** Separate protocol from frozen KT V1. This proposal does not modify KT V1 wire objects or signatures.

## 1. Decision

The project policy already recorded in `docs/phase0/14-ratchet-state-persistence-v1.md` is **REQUIRE ANTI-ROLLBACK PROTECTION**. Keep that requirement.

Use three independently operated checkpoint witnesses. Each witness keeps durable, monotonic state for each `(AccountID, DeviceID)` outside the phone. **All 3 of 3 witnesses must durably accept every reservation, mark-used barrier, and checkpoint commit.** The certificate must contain signatures from all three configured witnesses. The quorum stores a digest of the complete ratchet-persistence state, not merely the KT tree size. This is intentionally stricter than frozen KT V1's 2-of-3 threshold; do not reuse KT's threshold for this protocol.

The device must not perform a ratchet AEAD operation until all three witnesses have durably recorded the irreversible `MARKED_USED` transition for that exact operation. It must not publish an outbound envelope, display/acknowledge an inbound message, or promote candidate state until a quorum has committed the digest of the exact staged result.

This is deliberately online-only for ratchet operations. **If any one of the three witnesses cannot be reached, or all three cannot establish the same checkpoint and compatible operation state,** sending, receiving, decryption, and ratchet advancement stop. Previously committed local chat history may remain readable. Offline send/receive cannot be retained under this policy unless a separately proven platform-backed monotonic anchor is added for every supported device.

## 2. Why the current mechanisms are insufficient

The current local catalog HMAC detects local tampering and selective record substitution while its latest index remains available. It cannot detect restoration of an older, internally consistent snapshot containing the old index, old entries, old wrapped DEKs, and old sealed ratchet states. A local generation counter has the same weakness if it is inside the restored snapshot.

Frozen KT V1 witnesses sign a statement binding a witness ID, log ID, tree size, and STH digest. The statement has no client challenge nonce and does not bind a ratchet-state digest or per-device ratchet generation. KT's tree-size high-water detects transparency-log rollback; it is not a per-message ratchet freshness anchor.

The current `services/gateway/internal/kt/witness_service.go` is a verifier for supplied KT witness statements. `services/gateway/internal/kt/store.go` and `state_store.go` store gateway transparency state. They are not three independently operated witness services maintaining per-device ratchet checkpoints. Do not mistake the existing verifier or one gateway's PostgreSQL state for the required external anchor.

## 3. Trust and deployment model

1. Deploy three checkpoint witnesses, each with its own signing key, durable database, operator, credentials, and failure/security domain. Separate processes on one host or three schemas in one database do not count as independent witnesses.
2. The app has a pinned, versioned registry of the three witness IDs, public keys, and authenticated service endpoints. Registry/key rotation must itself be threshold-authorized and versioned; do not accept keys supplied by an unauthenticated gateway response.
3. The gateway may relay requests, but it is not the checkpoint authority. The client must verify witness signatures itself. Prefer direct witness connections or independent relay paths so one gateway cannot silently suppress all witness traffic.
4. Each witness stores its checkpoint and operation journal durably and atomically. It must never sign two different values for the same device and checkpoint sequence. A witness must retain enough history/evidence to prove and repair a lagging replica from a valid quorum certificate.
5. All three witness signatures are mandatory. Safety depends on at least one witness remaining correct: its signing key must remain protected, its durable journal must not be rolled back, and it must never sign conflicting transitions from the same predecessor. Since every certificate requires the same three witnesses, that correct witness vetoes a conflicting certificate. A malicious or unavailable witness can deny service; **any single unavailable or withholding witness stops ratchet operations**. If all three witness signing keys/state-integrity boundaries are compromised or rolled back, the guarantee is lost. This assumption must be explicit in the threat model and operating agreements.
6. Witnesses must maintain the currently authorized device signing key, account epoch, and revocation status. A DSK signature proves possession of that device key; it does not by itself prove the device remains authorized. Witnesses must consume independently verifiable lifecycle authorization/epoch transitions and reject revoked devices or stale epochs. KT V1 alone is not this authorization proof.
7. The witness's own durable journal is part of the trusted computing base. Restore from backup must not silently roll a witness behind an already signed checkpoint. A restored witness must be fenced from signing until its highest accepted checkpoint and operation journal are reconciled from independently retained, tamper-evident records. A design that protects phones but permits all witness journals to be restored from old snapshots merely moves the rollback vulnerability to the servers.

## 4. Checkpoint scope and digest

Use one monotonic checkpoint sequence per `(AccountID, DeviceID)`, shared across all ratchet sessions on that device. This serializes updates across concurrent sessions and avoids each session having a separately rollbackable high-water value.

Define a canonical `RatchetCheckpointPayloadV1` containing at least:

- protocol version, AccountID, DeviceID, authoritative account epoch, and checkpoint sequence;
- previous checkpoint digest;
- deterministically sorted session entries, each binding session-store ID, local/peer identities and epochs, the exact authenticated catalog-entry commitment, sealed ratchet-record digest, and wrapped-DEK-record digest;
- all pending ARMED/STAGED operation identifiers and commitments;
- outbox/inbox/deduplication/receipt commitments that determine whether a message key or received envelope has already been consumed, published, or acknowledged;
- a mutation/operation identifier and mutation class for the checkpoint being committed.

Compute the checkpoint digest over the exact canonical payload bytes with a domain-separated hash, for example:

`SHA-256(ASCII("PM-RATCHET-CHECKPOINT-DIGEST-V1") || uint32_be(payload_length) || canonical_payload_bytes)`

This string and framing are candidates, not frozen cryptographic constants. The final design must define canonical CBOR encoding, field numbers, integer bounds, maximum sizes, hash algorithm, and test vectors. The payload must cover every durable fact whose rollback could cause outbound message-key reuse, inbound skipped-key replay, duplicate display, duplicate acknowledgement, or lost deduplication. It must not include plaintext message bodies merely to create a checkpoint; commit hashes of the already encrypted/protected durable records.

The checkpoint digest is a commitment to local state, not a backup. A witness cannot reconstruct missing ratchet secrets from the digest.

## 5. Protocol objects (candidate, not frozen)

Define new versioned objects under a separate `PM-RATCHET-CHECKPOINT-V1` namespace. Do not extend or reinterpret `WitnessStatementV1`.

### 5.1 Freshness query and response

The client generates a fresh 32-byte CSPRNG nonce for each query. It requests the current checkpoint for one AccountID/DeviceID. Each response is independently signed by the responding witness and binds:

- protocol version and witness ID;
- AccountID, DeviceID, authoritative account epoch, and device authorization/revocation state;
- checkpoint sequence, checkpoint digest, and latest committed operation ID;
- the exact client challenge nonce;
- the witness registry/key version;
- per-witness pending-operation status (`NONE`, `RESERVED`, `MARKED_USED`, or `COMMIT_RECEIPT_ISSUED`), including operation ID, reservation digest, and any stored candidate checkpoint/receipt. A witness with a commit receipt remains locked until it verifies the complete three-receipt certificate.

The pending-operation fields are essential: a device snapshot may have been restored to a point before a remote reservation or `MARKED_USED` barrier. A client must not infer that no operation is pending merely because its local database has no ARMED marker.

The nonce prevents replay of an old signed response. A wall-clock timestamp is not a substitute for the nonce or monotonic sequence. The client must query all three witnesses; a response set with mismatched committed predecessors, unrelated pending operation IDs, or conflicting candidate digests is a security failure. A compatible partial state for one identical operation may only be resumed, never bypassed.

### 5.2 Reserve operation

Before a ratchet AEAD key is used, the client asks for a reservation binding:

- AccountID, DeviceID, and authoritative account epoch;
- expected current checkpoint sequence and digest;
- a fresh, random operation ID;
- operation class (outbound, inbound, session/lifecycle mutation);
- a digest of the exact operation intent and relevant input/envelope identifier;
- device DSK signature over the exact canonical request transcript.

All three witnesses must durably accept the same reservation. Each uses compare-and-swap against the expected checkpoint and retains a durable lock for that operation. No different operation may reserve the same next transition. A retry with the same operation ID and byte-identical request is idempotent; reusing the ID with different content is a security failure. A partial reservation is not permission to proceed; the exact same reservation must be resumed at all three witnesses.

### 5.3 Mark-used barrier

After reservation, the client obtains an all-3-of-3 signed transition for an irreversible `MARKED_USED` state for that operation ID. The client must not call ratchet AEAD before it has verified all three signatures. A partial mark-used transition remains locked to the same operation and must be resumed; it cannot be abandoned by timeout.

The barrier exists because an operation may crash after invoking AEAD but before persisting its staged result. After `MARKED_USED`, the old ratchet state must never be used for a different encryption or decryption operation. If the app restarts and cannot find a valid staged result for that operation, the session/device is fail-stopped; it must not guess whether AEAD ran or re-run it.

There are no automatic time-based reservation expirations. A timeout cannot prove that the original process did not use the key. Releasing a `MARKED_USED` reservation requires a separate, reviewed recovery/reset flow that invalidates the affected session/epoch; it must never simply make the old ratchet state usable again.

### 5.4 Commit checkpoint

After one AEAD invocation and successful durable staging of the exact candidate state and corresponding outbox/inbox/deduplication mutation, the client asks the witnesses to commit:

- the operation ID and its reservation digest;
- previous checkpoint sequence/digest;
- next checkpoint sequence (exactly previous + 1);
- new complete checkpoint digest;
- device identity and authoritative account epoch;
- device DSK signature over the exact canonical request.

Each witness verifies the matching pending reservation and `MARKED_USED` state, then durably stores the candidate checkpoint digest and signs a receipt. The client requires receipts from **all three distinct configured witnesses** over the exact same tuple. A witness that has issued a receipt must retain the operation lock and must not accept a different successor until it has verified the complete three-receipt certificate. The client persists the certificate locally with the transaction result. If only one or two receipts are available, the candidate is not publishable and no later operation may start; retry only the identical commit. Before a subsequent operation, the client presents the complete prior certificate to all three witnesses; each verifies the signatures and predecessor chain, durably finalizes that checkpoint, and acknowledges. A new reservation is allowed only after all three witnesses report the same finalized checkpoint.

The witnesses must reject sequence skips, stale predecessor digests, unauthorized epochs, revoked devices, conflicting operation IDs, and any attempt to commit a different digest for an already committed sequence.

### 5.5 Quorum certificate

The certificate contains exactly three distinct configured witness receipts for exactly the same AccountID, DeviceID, epoch, sequence, operation ID, previous digest, and new digest. Every configured witness must appear exactly once. A missing or duplicate witness receipt is not a certificate. A conflicting valid receipt for the same sequence is security evidence and causes fail-closed handling; it is not resolved by choosing whichever response arrived last.

## 6. Required message transaction order

The exact Android/Rust method names remain open. The security ordering does not.

1. **Freshness check:** obtain fresh, nonce-bound responses from all three witnesses and compare their committed checkpoint and operation status with the local authenticated catalog/checkpoint. Any unavailable witness blocks a new operation. If the remote checkpoint is ahead, the local state is stale and must not be used. If the same sequence has a different digest, fail as a security failure. If the local state is ahead of the witnesses, fail closed; do not rewrite the witnesses from local data. A partial in-flight operation may only be resumed with its exact operation ID and bytes.
2. **Local operation intent:** create and durably persist a unique operation ID and ARMED intent bound to the expected prior checkpoint and exact operation input. This must be included in the authenticated local catalog/checkpoint manifest.
3. **Remote reservation:** obtain durable acceptance from all three witnesses for that exact operation ID and prior checkpoint. No other ratchet operation on the device may race past this reservation.
4. **Mark-used barrier:** obtain and verify all three signatures on the irreversible `MARKED_USED` transition. No ratchet AEAD is permitted before this step.
5. **Single AEAD use:** Rust executes the operation exactly once using a candidate state. Raw ratchet keys never cross UniFFI.
6. **Durable staging:** persist the exact ciphertext/plaintext-protected inbox result, candidate state, operation metadata, and all related deduplication/outbox/inbox changes as a recoverable staged transaction. Do not promote state, deliver, display, send, or acknowledge yet.
7. **Remote checkpoint commit:** compute the digest of the staged complete ratchet-persistence bundle and obtain the three-of-three commit certificate for sequence `n+1`. A one- or two-receipt partial commit stays locked and must be retried exactly; it does not authorize local activation or another operation.
8. **Local atomic activation:** atomically activate the candidate state, catalog/index, operation receipt, and corresponding outbox/inbox/deduplication changes. Persist the quorum certificate. Promote the in-memory native state only after this transaction succeeds.
9. **Publication:** only after local activation may the network sender publish an outbound envelope, or the receiver acknowledge/display an inbound message.

If an account has several sessions, every operation updates the same device checkpoint sequence and digest. Serialize operations at the account/device level or use an equivalent distributed reservation discipline. A per-session mutex alone is insufficient.

## 7. Crash and restore recovery rules

| Observed state after restart | Required behavior |
|---|---|
| No local ARMED intent; witness has no pending operation; local checkpoint exactly matches fresh quorum | Normal operation may resume. |
| No local ARMED intent; any witness quorum reports a pending/reserved/marked-used operation | Fail closed. Treat as rollback or local data loss; do not create a new operation. |
| ARMED intent exists; no witness reservation exists | Retry only the same byte-identical reservation. No AEAD could have run before `MARKED_USED`. |
| Witness reservation exists but is not `MARKED_USED` | Resume the same operation ID; do not create a competing operation. |
| Witness reports `MARKED_USED`, but no valid local staged result exists | Fail-stop. Never rerun AEAD or clear the marker. Require reviewed session/device recovery. |
| Valid local staged result exists; all three witness responses identify the same pending operation and predecessor, with some witnesses possibly holding its commit receipt | Recompute/verify the staged digest and retry the exact same commit at all three witnesses; never rerun AEAD or create a new operation. If a witness is unreachable, do not begin another operation. |
| All three witness receipts exist for sequence `n+1`; matching local stage exists | Verify the complete certificate and digest, then finish local atomic activation. Before any next operation, present the certificate to all three witnesses and obtain finalization acknowledgements. |
| One or two witnesses have stored a receipt for candidate sequence `n+1`, while the others retain the same operation | Do not activate locally. Retry the byte-identical commit until all three receipts exist; do not start another operation. |
| Witness quorum is ahead, but the matching local stage is absent or does not match | Treat as rollback/data loss. Block the affected device/session and require recovery; do not initialize a replacement ratchet automatically. |
| Local checkpoint is ahead of a fresh witness quorum | SECURITY FAILURE. Do not advance witnesses based on local state. |
| Same sequence has different valid quorum/receipt digests | SECURITY FAILURE; preserve evidence and block. |
| Fewer than all three witnesses can establish a consistent current checkpoint | Block all new ratchet operations. Only an exact already-pending operation may be resumed after the three witness states are reconciled; read-only access to previously committed local history may remain available. |

A full-snapshot restore to a point before a witness-committed checkpoint is detected before any subsequent ratchet AEAD operation. The local client cannot recover missing candidate state from a digest. The safe recovery is a newly authenticated session/device lifecycle transition that prevents the superseded ratchet keys from being used again.

## 8. Offline behavior and platform alternative

Under this selected design, no ratchet state transition occurs offline or while any one of the three checkpoint witnesses is unavailable.  This includes outbound encryption, inbound decryption, skipped-key consumption, session state advancement, and message acknowledgement. The UI may queue a draft as ordinary application data, but it must not encrypt it with a ratchet message key until a fresh quorum is available.

Do not claim Android Keystore, StrongBox, AtomicFile, SQLCipher, app no-backup flags, or an HMAC key provides a portable monotonic counter. A hardware-only alternative may be considered only after proving, on every supported device/API tier, a non-resettable monotonic counter or equivalent secure state that survives the stated attacker-controlled snapshot restore. Android devices do not expose one universal app-level monotonic counter contract that can be assumed without device-specific evidence. If such proof is achieved, it may reduce online dependencies, but it is a separate platform-specific design and cannot be the V1 baseline by assumption.

## 9. Lifecycle, KT, and account-epoch integration

The checkpoint request includes the account epoch, but a caller-supplied epoch is not authority. Each witness must know the currently authorized epoch and device status from verifiable lifecycle events. Before any checkpoint operation, the witness checks that the DSK is the registered key for that active device and that the epoch is current.

On revocation or recovery epoch transition, the lifecycle system must propagate an authenticated transition to the witness quorum. Witnesses must reject operations from superseded epochs and revoked devices. Existing sessions bound to old epochs become unusable according to the lifecycle policy. Recovery of an account does not permit a stale device snapshot to re-register the old device key as current.

KT V1 remains a separate check: use its current-state leaf, proofs, consistency evidence, witness quorum, and client high-water as specified. KT evidence does not substitute for lifecycle authorization; the ratchet checkpoint quorum does not substitute for KT identity-publication verification. The two systems bind different facts.

### 9.1 Source audit: epoch ceiling is not enforced consistently

The source defines `LIFECYCLE_EPOCH_MAX = u32::MAX` in Rust and `LifecycleWireV1MaxEpoch` in Go. However, the current low-level enrollment and epoch-transition sign/parse/verify paths do not all enforce that ceiling: Rust `sign_device_enrollment`, `DeviceEnrollmentAuthorizationV1::parse`, `sign_epoch_transition`, and `EpochTransitionAuthorizationV1::parse`, plus Go `ParseDeviceEnrollmentAuthorizationV1` / `Verify` and `ParseEpochTransitionAuthorizationV1` / `Verify`, currently accept the wider `uint64` domain in the inspected source. Some higher-level enrollment, recovery-request, and proof-of-possession paths do enforce the ceiling. The PostgreSQL authorizer converts certificate epochs to signed `int64`; do not rely on a later database comparison as the protocol range check. Before witnesses consume lifecycle state, enforce the same `1..=u32::MAX` range in every Rust and Go signing, parsing, verification, database-boundary, and test path. This is a source-inspection finding; the uploaded environment lacks the Rust/Go dependency toolchains needed to run the project's tests here.

The lifecycle spec `docs/phase0/13-device-lifecycle-v1.md` is present in the current source package and must be reviewed with this proposal. Its candidate certificate/recovery objects are not automatically frozen simply because the file exists. Reconcile the exact lifecycle authorization and witness-update contract before implementing the checkpoint service.

## 10. Availability, scale, and operational costs

- Each message-state mutation requires a quorum protocol. Expect extra network round trips and per-device serialization. Benchmark actual latency and throughput before choosing timeouts or deployment capacity.
- **No witness outage is tolerated for ratchet progress.** One unavailable, stale, or withholding witness blocks every new ratchet operation; there is no 2-of-3 fallback.
- An unresolved reservation or `MARKED_USED` operation blocks later operations. Do not add lease expiry to improve availability without a cryptographic proof that no key use occurred.
- Witnesses are high-integrity security infrastructure. Define backups, disaster recovery, append-only audit, key rotation, compromise response, operator access controls, independent monitoring, and regional failure domains.
- Prevent the gateway from silently changing witness endpoints or registry keys. Prevent two witness endpoints from resolving to the same operator-controlled service without an explicit deployment exception and risk acceptance.
- Define witness catch-up from a valid three-of-three certificate. A lagging witness may adopt a checkpoint only after verifying all three receipts and a contiguous predecessor chain from a trusted checkpoint; it must preserve any conflicting receipt as evidence. Never repair a witness by trusting only the other two witnesses if its own durable history is uncertain.

## 11. Required tests and acceptance gates

### Cryptographic and protocol tests

- Cross-language Rust/Go vectors for every canonical request, response, receipt, and quorum certificate.
- Wrong nonce, replayed response, invalid witness signature, unknown witness, duplicate witness ID, wrong account/device/epoch, malformed lengths, non-canonical CBOR, trailing bytes, integer overflow, and unsupported versions.
- Same operation ID/same bytes is idempotent; same operation ID/different bytes is rejected.
- A witness never signs two different reservations or checkpoint digests for the same device/sequence.
- Two conflicting three-of-three certificates cannot be formed for one predecessor if at least one witness correctly enforces durable compare-and-swap and never equivocates. The certificate always includes the same three witnesses; do not use the flawed 2-of-3 intersection argument for this protocol.
- A witness cannot advance without the expected predecessor or skip a sequence.
- A lagging witness can catch up only with a valid quorum certificate and contiguous chain; conflicting signed evidence is retained.

### Crash and rollback tests

- Crash before local ARMED; after ARMED; after partial reservation; after all-three reservation; after partial `MARKED_USED`; after all-three `MARKED_USED`; after AEAD but before local staging; after staging; after one or two commit receipts; after all-three receipts; after local activation but before network send/ack.
- Restore a mutually consistent old full-device snapshot after a newer outbound checkpoint and prove no AEAD, send, inbound decrypt, display, or ack can proceed.
- Restore an old snapshot after a consumed skipped key and prove replay cannot be decrypted/displayed again.
- Restore local state with a missing Keystore catalog MAC key, missing witness registry, or mismatched account epoch; fail closed.
- Simulate each witness offline or stale in turn, two witnesses offline, witness equivocation, split network, delayed/reordered responses, and lost acknowledgements. Verify that even one unavailable witness blocks new ratchet operations without a local-only fallback.
- Race two processes/restored copies attempting different operations from the same prior checkpoint; at most one may obtain the reservation quorum and only its staged result may be committed/published.
- Prove no ciphertext or plaintext is published before both remote quorum commit and local durable activation.
- Run tests against three independently running witness instances and independent databases, not only an in-memory verifier or one shared database.

### Performance and platform tests

- Measure p50/p95/p99 reserve, mark-used, and commit latency on supported Android devices and target network conditions.
- Prove request/response timeouts and cancellation cannot cause a fallback to local-only operation.
- Test process death, device reboot, app restore, Android backup/restore, OS upgrade, witness-key rotation, and witness database recovery.
- Document supported platform/device tiers and the consequence that offline ratchet operations are unavailable.

## 12. Implementation sequence

1. **Design review:** threat-model review by an independent protocol/security reviewer. Reconcile this protocol with `13-device-lifecycle-v1.md`, frozen KT V1, PM-CBOR-2026, the existing ARMED/STAGED ratchet transaction proposal, and the release gate. Freeze the precise witness threat model and offline behavior.
2. **Protocol specification:** finalize canonical field layouts, domain separators, request/response transcripts, witness state machine, quorum certificate, error states, key rotation, and test vectors. Do not write production source before this is frozen.
3. **Witness service:** implement one reusable witness binary/service with its own signing key and durable transactional per-device checkpoint/operation journal; deploy three independent instances and require all three signatures. Test partial operation recovery and fail-closed behaviour when any witness is unavailable.
4. **Client native boundary:** implement Rust-owned checkpoint protocol signing/verification and opaque operation state. Do not expose raw ratchet keys or accept Kotlin-supplied `verified=true`/epoch flags.
5. **Persistence integration:** connect the account/device checkpoint digest to the exact catalog and atomic outbox/inbox transaction. Complete all crash/rollback tests before exposing session persistence through UniFFI.
6. **Android integration:** connect network witness clients, secure endpoint/registry configuration, read-only offline behavior, recovery UX, and telemetry that never logs secrets.
7. **Two-device validation:** test first-time establishment, normal send/receive, offline queue behavior, restart, backup restore, concurrent clone, witness outage, replay, epoch transition, and revocation.

## 13. Explicit non-goals and release status

- This proposal does not alter KT V1 or its frozen `WitnessStatementV1` format.
- It does not claim the existing gateway witness verifier provides independent checkpoint services.
- It does not make local backups recoverable after the checkpointed ratchet state is lost.
- It does not permit offline ratchet operations.
- It does not authorize a revoked device or replace account lifecycle verification.
- It does not freeze exact wire bytes, APIs, schemas, or error mappings.

**Acceptance condition:** the full-device rollback test must fail closed before any ratchet key use, message delivery, or acknowledgement. Until the protocol is independently reviewed, implemented, deployed across independent witness domains, and tested, ratchet persistence remains NOT FROZEN and the production release gate remains BLOCKED.
