# Phase C - Ratchet Operation State-Machine Reconciliation

**Status: REVIEW WORKING NOTE - NOT FROZEN**
**Review base:** `d10afb4bd9bc914295d4d0b349482673b434adfb`
**Scope:** Reconcile `docs/phase0/14-ratchet-state-persistence-v1.md`, `docs/phase0/15-ratchet-checkpoint-antirollback-v1-proposal.md`, `docs/phase0/13-device-lifecycle-v1.md`, the existing Rust ratchet state machine, and the Android/native boundary.

This note does not authorize production implementation. Its purpose is to identify a single operation lifecycle and the unresolved protocol decisions that must be closed before the persistence boundary can be frozen.

## 1. Confirmed repository facts at the review base

1. `RatchetState` is a Rust-owned in-memory state. Its protocol secrets include `rk`, `dhs_priv`, optional sending/receiving chain keys, and skipped-message keys. The state is not exposed as an opaque ratchet session through the current UniFFI interface.
2. `encrypt_message_0` and normal `encrypt_message` mutate the supplied state after successful AEAD encryption. `decrypt_message` and new-ratchet receive paths mutate it after successful authentication. These APIs accept `&mut RatchetState`; there is no persistence transaction or durable promotion protocol around them.
3. The message AEAD nonce is the fixed all-zero nonce. The state machine advances the chain for successful message processing. Crash recovery therefore must never restore a source state and encrypt a different message from the same message key after an uncertain encryption attempt.
4. `receive_first_dh_ratchet` already has the Alice pre-first-reply guard and associated tests. Persistence validation must preserve the existing reachable state shapes.
5. The generic PM-CBOR `Value::Bytes(Vec<u8>)` codec is not a secret-safe persistence codec. Its map encoder creates ordinary intermediate byte buffers, and decoded byte strings are ordinary vectors. A secret-aware codec or dedicated ratchet-state codec is required.
6. `AccountContext` currently binds identity keys and identifiers but does not contain an authoritative, validated lifecycle epoch/revocation context. Current FFI functions sign lifecycle objects; they do not make a signed object equivalent to a current trusted account state.
7. The lifecycle document and checkpoint-witness design are proposals, not frozen specifications. A lifecycle document's presence and parser/signature tests do not prove current authorization state.
8. The selected rollback policy remains REQUIRE ANTI-ROLLBACK PROTECTION. The current checkpoint proposal requires all three independently operated witnesses, and therefore blocks ratchet progress when any one witness is unavailable.

## 2. Required distinction between counters and generations

Do not overload these values:

- `record_generation`: generation of one active local session state record. It advances exactly once when a candidate RatchetState becomes the committed active state. A metadata-only transition does not advance it.
- `account_index_generation`: generation of the authenticated local account/device catalog index. It advances exactly once for every committed index mutation, including ARMED/STAGED state, receipt retention/GC, session changes, and ratchet-state updates.
- `checkpoint_sequence`: device-wide, witness-anchored monotonic sequence shared by all ratchet sessions belonging to `(AccountID, DeviceID)`. It advances exactly once for each successfully committed device checkpoint transition. It is independent of the local catalog generation and per-session record generation.
- `operation_id`: fresh random identifier for one logical attempt. It is never reused for different intent bytes or a different operation outcome.

A local generation stored only in the rollbackable device snapshot is not an anti-rollback anchor. The witness journal and checkpoint sequence are the external freshness authority.

### Required checkpoint binding

A committed checkpoint must bind the complete durable facts whose rollback could permit message-key reuse, skipped-key replay, duplicate display, lost deduplication, duplicate acknowledgement, or an incorrect outbox resend. This includes the exact authenticated catalog/index state, session record digests and generations, inbox/outbox/deduplication commitments, and a durable operation completion receipt.

The protocol must explicitly distinguish a **committed checkpoint digest** from a **pending operation journal record**. Reservation and MARKED_USED statuses are durable witness journal state; they must not be ambiguously described as a new committed checkpoint if the ratchet state has not yet advanced.

## 3. Proposed logical operation lifecycle

The following is a reconciliation model, not frozen wire syntax.

### 3.1 Begin

1. Obtain a fresh, challenge-bound status from all three configured witnesses.
2. Verify that all witnesses agree on the same finalized predecessor `(checkpoint_sequence, checkpoint_digest)`, active device authorization, current account epoch, and compatible pending-operation journal state.
3. Confirm that local authenticated catalog/index and all referenced session records match that predecessor.
4. Construct a fixed operation intent: operation class, operation ID, relevant session/device binding, expected source generations, envelope ID, finalized public header/context, and a commitment to the exact input.
5. Persist local ARMED intent and authenticated catalog/index updates atomically. Do not advance the active `record_generation` or committed `checkpoint_sequence` yet.

No message-key derivation or message AEAD call is allowed during this stage.

### 3.2 Reserve and mark-used

6. Obtain the same byte-identical reservation at all three witnesses, compare-and-swapping against the predecessor checkpoint.
7. Obtain all three signatures on the irreversible MARKED_USED barrier for the same operation ID and intent digest.
8. Until all three MARKED_USED signatures are verified, do not invoke message AEAD. Partial reservation/barrier states can only be resumed with the same operation ID and exact intent; a timeout is not permission to release them.

### 3.3 Prepare exactly once

9. Rust creates a secret-safe candidate state from the active state under a native account/device and per-session serialization discipline. No raw ratchet state or protocol key crosses UniFFI.
10. Invoke the relevant AEAD operation once, using only the candidate state. Do not publish the output or promote candidate state.
11. Persist an authenticated encrypted staging record containing the exact operation result, exact candidate sealed state, operation/session binding, source generations, and output/input commitments. Update the local catalog/index and stage commitment atomically.

If AEAD execution or staging has an ambiguous outcome, never invoke AEAD again from the same source state. Resolve only by reading and authenticating the exact durable operation records. If the result cannot be proven, fail-stop/quarantine.

### 3.4 Witness commit and local activation

12. Compute the next device checkpoint digest over the complete staged post-operation bundle.
13. Obtain the matching commit receipt from all three witnesses for exactly the same predecessor, operation ID, checkpoint sequence + 1, and candidate digest.
14. Do not activate, send, display, acknowledge, or deliver after only one or two receipts.
15. In one local durable transaction, activate the exact staged candidate record, update per-session record generation exactly once, update the account index generation exactly once, write authenticated completion evidence, commit inbox/outbox/deduplication mutations, clear ARMED/STAGED markers, and persist the exact three-witness certificate.
16. Promote the in-memory native candidate only after the local transaction succeeds. If local commit succeeded but native promotion failed, fail-stop and restore from the committed record before publication.
17. Publish/send outbound data or display/acknowledge inbound data only after local activation and native promotion succeed.
18. Before the next operation, all three witnesses must have finalized/acknowledged the previous complete certificate and report the same predecessor.

## 4. Recovery rules that must be identical in both proposals

| Durable evidence after restart | Required action |
|---|---|
| No local intent; all witnesses report no pending operation and exactly match the local committed checkpoint | Normal processing may resume. |
| Local ARMED exists; witnesses report no reservation | Retry only the identical reservation. No AEAD has been permitted. |
| One or two witnesses have reservation or MARKED_USED state | Resume the exact same operation at all witnesses. No AEAD until three MARKED_USED signatures exist. |
| All three witnesses report MARKED_USED; no authenticated local staged result exists | Fail-stop/quarantine. Do not infer whether AEAD ran; do not rerun it. |
| Valid staged result exists; witness states identify the same operation and predecessor | Verify exact staged bytes and retry only the identical checkpoint commit. |
| One or two witnesses have committed candidate receipts | Keep locked; retry the identical commit. Do not activate locally. |
| All three receipts exist and match exact stage | Atomically activate the exact staged bytes locally; do not rerun AEAD or reseal a different envelope. |
| Local state is ahead of witnesses, witnesses are ahead of local, or digests conflict | Security failure/quarantine. Never repair witnesses from an old local snapshot. |
| A witness is unavailable or cannot prove consistent journal state | No new ratchet operation. Read-only committed history may remain available. |

The implementation must treat a database error or lost acknowledgement as an ambiguous outcome, not proof that a transaction rolled back. Before retry, reread and authenticate the current index, entry, generations, staged bytes, completion receipt, and outbox/inbox records.

## 5. Unresolved protocol decisions - freeze blockers

### 5.1 Inbound authentication failure semantics

Document 15 requires MARKED_USED before AEAD. The existing Rust receive implementation commits ratchet receive state only after successful authentication; a failed authentication leaves the mutable state unchanged.

The proposals do not yet define what happens when the witness barrier has been irreversibly marked-used but inbound AEAD authentication fails. The design must decide whether:

- the exact failed ciphertext is terminally recorded and the witness operation is closed without advancing ratchet state; or
- the operation is quarantined and requires a new authenticated session; or
- another explicitly reviewed terminal outcome exists.

It must also define whether another ciphertext for the same receive sequence may be attempted, whether that uses a fresh operation ID, and how replay/DoS behavior is bounded. Do not assume the outbound single-use AEAD rule automatically specifies receive-side failed-auth behavior. This requires cryptographic review before freeze.

### 5.2 Outbound intent commitment and privacy

The witness reservation must bind the exact intended operation, but should not expose plaintext to witnesses. A plain hash of low-entropy plaintext enables offline guessing. Specify a salted/committing construction with CSPRNG salt, domain separation, exact encoding, and vectors. The operation intent must bind all envelope context that affects AEAD AAD (envelope ID, sender/recipient device IDs, epoch, prekey flag, canonical header bytes), and exact source generations. It must not permit the caller to change plaintext or AAD after reservation.

### 5.3 Local ARMED state versus committed checkpoint

The local ARMED write changes the authenticated catalog/index before the remote checkpoint advances. Define exactly which bytes belong to the predecessor committed checkpoint, which bytes belong to the pending-operation intent journal, and which bytes are covered by the eventual next checkpoint digest. Do not create a circular dependency where the witness must already commit a digest containing a staged result before the result exists.

### 5.4 Failed operation terminal receipts

Define terminal evidence for operations that cannot produce a valid staged candidate, including AEAD error, inbound authentication failure, process crash, native panic, cancellation, and local storage failure. A MARKED_USED operation cannot be released by timeout. A valid release/terminal outcome must not permit an old sender key to encrypt different content or allow a consumed inbound key to be replayed. The receipt lifecycle, checkpoint sequence advancement, and audit retention must be specified.

### 5.5 Account/device-wide serialization

A per-session mutex is insufficient because all sessions on one device share the witness checkpoint sequence and local account index. Define one account/device operation coordinator or an equivalent distributed compare-and-swap so two sessions cannot reserve conflicting successors or commit stale indexes.

### 5.6 Lifecycle authority and witness updates

Witnesses must validate device authorization, account epoch, revocation, recovery pending/finalized state, and lifecycle transitions from verifiable signed evidence. A gateway's database row, a Kotlin-supplied epoch, a device signature by itself, and KT inclusion proof alone are not sufficient authority. Specify:

- the root/key used to verify lifecycle authority at each witness;
- exact signed lifecycle event schemas and replay/uniqueness rules;
- how the 48-hour recovery request/abort/finalization flow updates all three witnesses;
- how revocation and account epoch changes invalidate old sessions;
- how surviving devices establish fresh authorized state;
- how witness restart/catch-up handles missing or conflicting lifecycle events.

The native client must derive a trusted local account/device authorization context from authenticated evidence, not accept arbitrary binding fields or a boolean `verified` flag from Kotlin.

### 5.7 Witness trust and disaster recovery

Three services count as independent only when operator, signing key, durable journal, credentials, and failure/security domain are independent. Define witness registry bootstrap and threshold-authorized rotation, durable journal anti-rollback, backups and restore fencing, key compromise response, operator access control, monitoring, and regional failure domains. The current Gateway KT witness verifier is not the ratchet checkpoint quorum.

### 5.8 Size and performance proofs

Prove exact maximum sizes using legal encoded RatchetState, actual valid message headers/envelopes, staging framing, catalog entries, completion receipts, and device checkpoint payload. Reject over-limit inputs before proportional allocation. Benchmark reserve, mark-used, commit, and finalize latency on target Android devices and realistic networks. The strict 3-of-3 policy has a direct availability and latency cost.

## 6. Native/API implementation boundary

The eventual native owner should be one opaque process-local `RatchetSession` handle owning immutable validated binding, active RatchetState, operation generation, pending candidate, and per-session lock. Account/device coordination must be above that per-session lock.

Proposed capabilities (method names not frozen):

- create/restore only from authenticated session-establishment and account-state context;
- prepare outbound/inbound candidate without mutating active state;
- seal a candidate using a narrowly scoped ratchet-state DEK operation;
- promote exactly the matching pending operation after durable transaction success;
- abort only when code can prove AEAD was never invoked;
- restore sealed state with trusted native binding, secret-aware decoding, and semantic validation;
- close/expire process-local handles; never restore handles from persisted integer/pointer values.

Kotlin may persist sealed state, wrapped DEK, authenticated catalog records, operation stage bytes, and public metadata. Raw root/chain/message keys, DH private keys, plaintext serialized state, or generic arbitrary plaintext+DEK operations must never cross UniFFI.

## 7. Minimum acceptance tests before freeze/implementation

1. Rust state-shape round trips for Alice initial, Bob initial, post-Message-0, Alice pre-first-reply after multiple sends, established send/receive, new DH ratchet, and skipped-key states.
2. Secret-buffer fault tests proving zeroization ownership for success, decode failure, encode failure, unwind/panic, and candidate abort paths, with documented limitations.
3. Concurrent operations across two sessions on one device; only one successor reservation/commit may win.
4. Every crash point in Begin, Reserve, MARKED_USED, AEAD, Stage, partial witness commit, full witness commit, local activation, native promotion, send/display/ack, and witness finalization.
5. Lost-ack tests where local and witness commits both may or may not have succeeded; retries must resolve from durable evidence without duplicate state advancement or AEAD calls.
6. Inbound invalid-auth behavior, including operation terminal receipt, attacker replay, legitimate retry, and availability/DoS behavior.
7. Full consistent old-device-snapshot restore after an outbound send and after consuming a skipped message key; no send, decrypt, display, or acknowledgement may occur from rolled-back state.
8. Witness outage, stale witness, equivocation, partial reservation, partial MARKED_USED, partial commit, lost response, witness database restore, key rotation, and lifecycle transition tests with three genuinely independent services/databases.
9. Exact maximum-size and cap-plus-one tests for all records and checkpoint payloads.
10. Real two-device Android Alice-to-Bob-to-Alice exchange, app restart, network interruption, replay, duplicate delivery, out-of-order receive, witness outage, and epoch revocation tests.

## 8. Gate decision

The source audit corrections in Documents 14 and 15 are documentation corrections, not a security approval. The design remains **NOT FROZEN** until the unresolved decisions in Section 5 are resolved, independent protocol/security review is completed, exact cross-language protocol vectors exist, and the acceptance gates above are assigned and testable.

No ratchet persistence implementation, witness production service, or Android chat integration should begin on the assumption that this working note itself is a frozen protocol.
