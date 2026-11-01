# Phase C — Ratchet Persistence and Anti-Rollback Design Review

**Review base:** `d10afb4bd9bc914295d4d0b349482673b434adfb`
**Intended branch:** `phase-c/ratchet-persistence-design`
**Review status:** SOURCE REVIEW COMPLETE; DESIGN NOT FROZEN; NO PRODUCTION IMPLEMENTATION AUTHORIZED
**Scope:** reconcile `docs/phase0/13-device-lifecycle-v1.md`, `docs/phase0/14-ratchet-state-persistence-v1.md`, `docs/phase0/15-ratchet-checkpoint-antirollback-v1-proposal.md`, the Rust Double Ratchet implementation, and the current UniFFI boundary.

## 1. Executive decision

Do not implement ratchet-state serialization or connect Android chat UI yet. The current source does not provide an end-to-end messaging path, and the persistence and checkpoint protocols remain proposals. Implementing either before reconciling the lifecycle trust boundary, exact transaction state machine, and witness recovery rules would create throwaway code or, worse, a path that can reuse a message key after a crash or device rollback.

Keep the recorded policy **REQUIRE ANTI-ROLLBACK PROTECTION**. The current proposal's 3-of-3 independent checkpoint witnesses is the selected candidate policy. Do not silently replace it with a 2-of-3 quorum, local HMAC, Android Keystore-only counter, or offline fallback.

The 3-of-3 policy has a hard availability consequence: one unavailable, stale, or inconsistent witness blocks all new ratchet state transitions, including send, receive, decrypt, skipped-key consumption, and acknowledgements. Previously committed local history may remain readable. This is not an offline-capable messaging design.

## 2. Source facts verified at the review base

### 2.1 Existing RatchetState shape

`native/crypto-core/src/double_ratchet.rs` defines `RatchetState` with zeroizing wrappers for `rk`, `dhs_priv`, `ck_s`, and `ck_r`; `dhs_pub`; optional `dhr_pub`; counters `ns`, `nr`, `pn`; and a `BTreeMap` of skipped-message keys whose values are `Zeroizing<RatchetKey>`.

The relevant reachable lifecycle shapes include:

| Lifecycle shape | `dhr_pub` | `ck_s` | `ck_r` | Counters | Skipped keys |
|---|---|---|---|---|---|
| Alice initialized, before Message 0 | present | present | absent | `ns=nr=pn=0` | empty |
| Alice after Message 0, before peer reply | present | present | absent | `ns>=1`, `nr=pn=0` | empty |
| Bob initialized, before Message 0 | absent | absent | absent | `ns=nr=pn=0` | empty |
| Bob after authenticated Message 0 | present | present | present | `ns=0`, `nr=1`, `pn=0` | initially empty |
| Established normal state | present | present | present | transition-dependent, bounded `u32` | zero or more unique retained keys, maximum 1,000 |

The table is a starting point, not a complete validator. The final validator must be derived by tracing every state transition and checking that serialization cannot accept impossible combinations.

### 2.2 First-DH-ratchet preconditions are already implemented

`receive_first_dh_ratchet()` already requires the Alice-side pre-first-reply shape: existing `dhr_pub`, a different new peer ratchet key, `ck_s` present, `ck_r` absent, `ns >= 1`, `nr = pn = 0`, and no skipped keys. The source tests already reject Alice's pre-Message-0 state, Bob's initial state, repeated peer keys, and inconsistent field shapes without mutating state. Tests also cover Alice sending multiple messages before the peer's first reply.

Therefore, the older recommendation in document 14 to add this guard is stale. Persistence must preserve the existing behavior; do not duplicate or weaken it.

### 2.3 Existing ratchet functions mutate live state

The current `encrypt_message`, `encrypt_message_0`, and receive paths take `&mut RatchetState`. Some receive operations carefully defer state mutation until authentication succeeds, but this is not the same as a durable candidate-state transaction. There is no native API that prepares a candidate, waits for the database and witness commits, then promotes that candidate.

`RatchetState` has no safe persistence/candidate clone API. A regular derived `Clone` is not acceptable for secret state. A future candidate-copy mechanism must deep-copy secret material into zeroizing owners and be reviewed for temporary copies and panic/error paths.

### 2.4 The generic CBOR codec is not safe for ratchet-secret serialization

`native/crypto-core/src/cbor.rs` represents byte strings as ordinary `Vec<u8>` in `Value::Bytes`. Its encoder builds intermediate key/value vectors while encoding maps. Decoding creates ordinary byte vectors. Those intermediates are not zeroized on drop.

Wrapping only the final serialized output in `Zeroizing` would not resolve the intermediate-copy problem. Ratchet secrets must not pass through the generic `Value::Bytes` path until a dedicated secret-aware serializer/deserializer and all intermediate ownership paths are audited.

The ratchet code also needs a wider secret-copy audit. In particular, skipped-key derivation currently returns temporary message keys as ordinary `RatchetKey` values before inserting zeroizing copies into the state map. `kdf_ck` uses temporary HMAC output buffers before copying into zeroizing arrays. Review all `K_msg`, skipped-key, root-key, chain-key, DH-secret, and state-copy paths, not only the persistence encoder.

### 2.5 UniFFI currently has no ratchet-session API

`native/crypto-core/src/pm_crypto_core.udl` exposes identity/recovery contexts and canonical CBOR helpers. It does not expose a `RatchetSession`, prepare/commit/abort operations, ratchet encryption/decryption, or ratchet-state seal/restore. The Android bridge therefore cannot yet own an integrated native messaging session.

`AccountContext` contains AccountID and DeviceID but not an authenticated current account epoch or a verified lifecycle/revocation state. A Kotlin-supplied epoch or `verified=true` parameter cannot become authority. A native-owned verified account-state context or equivalently trusted lifecycle result is required before sessions can be created/restored.

### 2.6 Lifecycle status is still proposal-level

`docs/phase0/13-device-lifecycle-v1.md` exists at this review base, but its status is **DESIGN PROPOSAL — NOT FROZEN**. The existence of the file does not make candidate recovery/enrollment schemas authoritative. The witness protocol cannot consume caller-provided account epochs as authority. It needs an exact, independently verifiable lifecycle transition and revocation contract.

### 2.7 Two audit statements are stale at this base

- Document 14 contains an old note saying `13-device-lifecycle-v1.md` was absent. It is present at `d10afb4`.
- Document 15's section 9.1 says Rust low-level enrollment and epoch-transition sign/parse/verify paths do not enforce the `u32` epoch ceiling. The inspected Rust `authorization_v1.rs` now checks the `1..=u32::MAX` range in the relevant base certificate signing/parsing/verification paths. Re-audit Go and PostgreSQL boundaries separately; do not copy the stale Rust finding forward.

These are documentation corrections, not evidence that lifecycle V1 is frozen or fully compliant.

## 3. Required unified operation state machine

Documents 14 and 15 must describe one single operation protocol. The intended order is:

1. **Freshness check:** obtain fresh, nonce-bound, signed status from all three configured witnesses. Compare device identity, authoritative epoch, committed checkpoint, and pending operation state. No fresh consistent 3-of-3 response means no new ratchet operation.
2. **Intent creation:** generate a fresh operation ID and exact operation context in Rust. Bind it to the local device checkpoint, prior sequence/digest, session binding, operation class, and exact message/envelope identity. Persist the local authenticated `ARMED` intent before remote reservation.
3. **Reservation:** all three witnesses durably accept the exact same reservation under compare-and-swap from the same predecessor. Partial reservation remains locked to the same operation ID and exact request bytes.
4. **Irreversible MARKED_USED:** all three witnesses durably record the irreversible mark-used barrier. No ratchet AEAD may execute before the client verifies all three signatures.
5. **Single native operation:** Rust executes exactly one encrypt/decrypt invocation against an isolated candidate state. The active state remains unchanged. No second invocation is permitted for the same source state/key after an uncertain AEAD boundary.
6. **Durable local staging:** persist the exact candidate-state record and exact outbound envelope or protected inbound result, plus deduplication/operation metadata, as an authenticated staged object. Do not send, display as committed, or acknowledge yet.
7. **Witness commit:** submit the digest of the complete staged checkpoint bundle. All three witnesses must issue receipts for the same exact operation, predecessor, sequence, and checkpoint digest. One or two receipts do not authorize local activation.
8. **Local atomic activation:** in one durable database transaction, activate the candidate state, update catalog/index/generations and authenticated completion evidence, persist the 3-of-3 certificate, and commit the matching outbox/inbox/deduplication change.
9. **Native promotion:** promote the candidate only after local durable commit. If promotion fails, fail-stop and restore from the committed record; do not continue from stale in-memory state.
10. **Publication:** outbound network send or inbound acknowledgement/display occurs only after local activation and native promotion.

The exact failure rules must be explicit for every edge. An error or lost acknowledgement is not proof that a transaction failed to commit. Re-read and authenticate durable state to resolve ambiguity. If the outcome cannot be established, quarantine/fail-stop; never rerun AEAD from the old state.

## 4. Counter and commitment model to freeze

The documents currently refer to several counters with different scopes. The frozen spec must define them separately and state which durable objects each one authenticates:

- `record_generation`: per-session generation; advances exactly once when a candidate RatchetState becomes the committed active state. A metadata-only ARMED/STAGED change does not advance it.
- `account_index_generation`: per-account/device local catalog generation; advances exactly once for every transaction that changes authenticated catalog/index content, including ARMED/STAGED metadata, completion receipts, retention/GC, and every session state commit.
- `checkpoint_sequence`: monotonic device-wide sequence held by the external 3-witness system; serializes changes across every ratchet session on the device.
- `operation_id`: unique identifier for one irreversible operation attempt; idempotent only for byte-identical request/result retries.
- `source_record_generation` and `source_checkpoint_sequence/digest`: bind the operation to its exact predecessor.

The final protocol must specify atomic relationships between these values, their digests, and their exact canonical bytes. It must not allow a local index update to be mistaken for a new remote checkpoint, or a remote checkpoint update to be committed without the corresponding local stage and completion evidence.

## 5. Witness trust requirements

The three witnesses must be independent in operator, credentials, signing key, durable database, and failure/security domain. A gateway verifier or three schemas in one database do not satisfy independence.

The registry of witness identities, public keys, and service endpoints needs a pinned bootstrap and a threshold-authorized, versioned rotation protocol. Gateway responses must not be able to replace the registry. All three distinct configured witness IDs must appear exactly once in every accepted 3-of-3 certificate.

The witness trust model must address rollback of the witnesses themselves. A durable database and ordinary backup are not automatically a monotonic anchor. A restored witness must be fenced from signing until its highest accepted sequence and complete operation journal are reconciled from independently retained, tamper-evident evidence. The design must specify the evidence source, reconciliation algorithm, and behavior if that evidence is unavailable or conflicts. This is a freeze blocker.

Witnesses must also verify current device authorization, revocation, and account epoch from the frozen lifecycle protocol. Device-key possession signatures alone are not lifecycle authority. Key Transparency V1 and the ratchet checkpoint protocol prove different facts and must remain separate checks.

## 6. Privacy and operation-intent commitment

The witness request must bind an operation to one exact intent and must be immutable across retries. Do not send plaintext message bodies to witnesses. Do not publish a bare, unsalted hash of low-entropy plaintext as an operation commitment; it can enable dictionary testing. The wire design should bind a fresh operation ID, envelope/message identity, operation class, session and predecessor commitments, and a privacy-preserving commitment to the exact native operation input. Define the commitment construction, secret ownership, and retry rules before vectors are generated.

For inbound messages, bind the exact received envelope bytes/digest. For outbound messages, do not permit a retry to substitute different plaintext/header/AAD under the same operation ID or source message key. The exact native intent must be durably bound before the irreversible mark-used barrier.

## 7. Persistence and FFI boundaries

The target is one opaque Rust-owned session object. Kotlin must not receive `RatchetState`, serialized plaintext state, `RK`, `DHS_priv`, `CK_s`, `CK_r`, skipped keys, or message keys. The only proposed narrow exception is the per-session random 32-byte ratchet-state DEK crossing UniFFI directly into dedicated native seal/restore operations. The identity Storage DEK must remain separate.

The session binding must be produced by a validated native session-establishment result and anchored to a native verified local account/device lifecycle context. Database rows and Kotlin arguments are untrusted inputs, not identity or epoch authority.

The database boundary must atomically cover:

- sealed active-state record and wrapped per-session DEK record;
- authenticated session entry and account/device index;
- per-session and account-index generations;
- ARMED/STAGED markers and encrypted staging record;
- authenticated completion receipt or retained deduplication evidence;
- outbound envelope/outbox or protected inbound item/inbox;
- inbound deduplication and delivery-ack state;
- device-wide checkpoint digest/certificate linkage.

A separate `AtomicFile` for ratchet state is insufficient for this transaction. Choose and test a local storage engine/transaction boundary that can atomically commit the complete bundle.

## 8. Open freeze gates

The following are hard blockers, not optional polish:

1. Freeze lifecycle V1 authority, epoch/revocation propagation to witnesses, local verified account-state context, and peer-session binding.
2. Freeze exact witness registry bootstrap/rotation and witness-journal rollback/reconciliation threat model.
3. Freeze canonical wire schemas, domain separators, request/response transcripts, error categories, retry/idempotency, and 3-of-3 certificate encoding, with Rust/Go vectors.
4. Freeze one combined local-plus-witness operation state machine and exact generation relationships.
5. Freeze privacy-safe intent commitment and operation ID lifecycle.
6. Audit all secret-bearing temporary allocations, panic/unwind paths, and zeroization limits; implement a dedicated secret-aware serializer/deserializer rather than using generic `Value::Bytes`.
7. Define secure candidate-state cloning/promotion and pending-operation handles; no ordinary `Clone` of secret state.
8. Prove maximum legal state, envelope, staging, catalog, and checkpoint sizes by constructing actual maximum-valid objects through production validators. Reject cap-plus-one before proportional allocation.
9. Define exact local storage transactions and crash recovery for committed, uncommitted, and ambiguous commit outcomes.
10. Independent protocol/security review before design freeze.

## 9. Implementation sequence after design freeze

1. Correct stale audit notes and freeze lifecycle/witness trust contracts.
2. Generate and cross-check canonical Rust/Go protocol vectors and negative cases.
3. Implement witness service with independent durable journals; test 3 separate instances/databases and witness recovery/fencing.
4. Implement Rust witness protocol client and verified lifecycle/session binding context.
5. Implement dedicated zeroizing ratchet state codec and semantic validator; add reachable-state round trips and tamper/size tests.
6. Implement Rust opaque session, candidate operation, seal/restore, commit/promotion, and fail-stop API.
7. Implement Android Keystore DEK wrapping/catalog authentication and atomic local database transaction.
8. Integrate Android message send/receive only after all state, witness, and storage gates pass.
9. Run two-device send/reply tests, restart tests, network interruption, crash injection at every transaction boundary, replay/out-of-order tests, full-snapshot rollback tests, and witness outage tests.

Do not call the application production-ready until the separate release gate and independent security review pass.

## 10. Current outcome

At `d10afb4`, the in-memory cryptographic ratchet logic and its unit tests exist, and Android identity/Keystore integration exists. The app is still not a complete end-to-end messenger. There is no ratchet persistence codec, no opaque ratchet session FFI, no candidate-state durable transaction, and no deployed three-witness anti-rollback system. A successful build or existing CI run cannot prove any of those properties.
