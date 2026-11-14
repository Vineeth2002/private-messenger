# Private Messenger — P0–P2 Baseline Audit

**Review date:** 2026-11-15 (Asia/Kolkata)
**Repository:** `Vineeth2002/private-messenger`
**Reviewed branch:** `main`
**Reviewed commit:** `0a332a5b08ca0eb74c83b730e20751bdee38a64b`
**Review mode:** read-only source and workflow inspection; no source files changed by this audit.

## 1. Executive assessment

The repository is materially further along than its README currently reports. `MainActivity` wires in `AlphaMessagingPanel`, and the app contains a controlled Android 1:1 messaging alpha: manual peer fingerprint pairing, native signed-prekey/X3DH setup, Double Ratchet message processing, encrypted local message storage, an outbox, an inbox receipt ledger, HTTP send/fetch/ACK, and foreground synchronization.

That is meaningful implementation, but it is not yet a production-ready messenger. The alpha explicitly uses manually pinned fingerprints instead of the production Key Transparency witness trust model; its message API is still `/v1/demo/messages`; polling runs only while the panel is in the foreground; and no Android end-to-end test was found that drives two app instances through the full Android → Gateway → PostgreSQL → Android path.

The latest merged work also restored dedicated Gateway/PostgreSQL CI. The Gateway Go tests, `go vet`, and PostgreSQL integration suite passed on the merged `main` commit. This proves the configured Gateway checks, not end-to-end app behavior or production security.

**Overall disposition: continue controlled alpha development. Production release remains blocked.**

## 2. Roadmap status — authoritative labels currently available

The current canonical baseline uses fixed stages P0–P9. The phase definitions available in the current baseline context and confirmed by the recent project record are:

| Stage | Authoritative focus | Weight / status |
|---|---|---|
| P0 | Scope and evidence baseline | In progress; no product-completion weight |
| P1 | Gateway platform foundation | 12%; in progress |
| P2 | Identity, enrollment, authorization and recovery | 12%; in progress |
| P3–P9 | Later stages in the fixed roadmap | Do not assign names, weights or completion percentages from this repository snapshot: the current tracked `main` documentation does not contain the full P3–P9 stage register |

Do not substitute the older six-stage product strategy (Core MVP, hardening, groups, language AI, mesh/interoperability) for the canonical P0–P9 baseline. Those are different roadmap views.

## 3. P0 — Scope and evidence baseline

**Status: in progress.**

### Confirmed

- `main` contains the Phase-C persistence/transparency integration merge and the dedicated Gateway PostgreSQL validation workflow.
- The actual Android entry point imports and renders `AlphaMessagingPanel`; the UI is no longer only an identity/diagnostics screen.
- The app calls the current alpha a “Controlled two-device messaging alpha” and explicitly labels manual fingerprint pinning as alpha trust, not production Key Transparency.

### Documentation drift to correct

- `README.md` still carries a 2026-10-24 status snapshot and says Android is a diagnostics/identity screen whose client does not complete session establishment, ratchet send/receive and delivery. That statement is now stale: the current `MainActivity` renders the alpha messaging panel and the engine contains those candidate flows.
- The README should not be changed to claim a production chat app. Accurate replacement wording is: a controlled Android 1:1 alpha exists; peer trust is manual; the message API is a demo relay; sync is foreground polling; production enrollment, witness-backed trust, robust recovery, anti-rollback, physical-device acceptance and independent audit remain open.
- `docs/PRIVATE_MESSENGER_RELEASE_GATE.md` still refers to an older `main` SHA and older CI evidence. It needs a dated reconciliation that adds the current Gateway/PostgreSQL CI and Android alpha evidence without checking off any unproven release gates.
- A complete authoritative P3–P9 stage register needs to be located or restored before calculating an overall P0–P9 completion percentage.

### P0 exit criteria

1. README and release-gate documents accurately describe the current alpha and explicitly distinguish alpha from production.
2. One canonical P0–P9 register exists in the repository, including names, weights, owners, dependencies and objective exit criteria.
3. Every completion claim links to source, test output, CI run or external evidence.

## 4. P1 — Gateway platform foundation (12%)

**Status: in progress.**

### Confirmed implementation and evidence

- The Gateway has PostgreSQL-backed authorization, recovery, device and message-delivery components.
- The message HTTP implementation exposes send, fetch and ACK operations. The current Android alpha client uses `/v1/demo/messages` routes.
- Gateway capabilities are deliberately feature-gated through environment variables. The demo relay, device request authentication, initial bootstrap, candidate enrollment, candidate signed-prekeys and candidate KT routes are not all enabled by default.
- `.github/workflows/gateway-go-validation.yml` now installs PostgreSQL 16, creates the test-only `pm_enrollment_test_20261030` database, applies migrations `0001`–`0011`, validates the schema, verifies Go modules, runs `go vet ./...`, and runs `go test -p 1 -count=1 ./...` with PostgreSQL integration enabled.
- The Gateway/PostgreSQL CI job passed on the merged `main` commit `0a332a5b08ca0eb74c83b730e20751bdee38a64b`.

### Remaining P1 work

1. Separate the production authenticated messaging API contract from `/v1/demo/messages`; do not treat the demo route name or a passing test as production API readiness.
2. Specify and test deployment configuration, ingress TLS, trusted-proxy behavior, secrets, DB roles/privileges, health/readiness, logging, metrics, backups and restore.
3. Add an automated Android-to-Gateway messaging integration test rather than relying only on Gateway package tests and Android identity smoke tests.
4. Preserve operator-controlled migrations; do not add automatic startup migration as an incidental feature.

## 5. P2 — Identity, enrollment, authorization and recovery (12%)

**Status: in progress; candidate protocol remains not frozen.**

### Confirmed implementation

- Android supports initial account bootstrap and first-device registration using the existing locally stored identity.
- The Gateway contains candidate ordinary-enrollment and separate recovery lifecycle code, including PostgreSQL-backed operations and recovery-finalizer components.
- Candidate capabilities are protected by explicit `GATEWAY_ENABLE_*` flags. Source logs and design documents identify candidate enrollment, candidate signed-prekeys and KT routes as non-production.
- P2 documents 05–10 establish proposed policy and V2 wire/pairing details but explicitly remain proposals / not frozen.

### Open P2 gates documented in the repository

- Ratify the ordinary additional-device authorization authority and keep it distinct from catastrophic recovery.
- Freeze the V2 wire objects, exact signatures/transcripts, retry/idempotency semantics, error mapping and origin binding.
- Resolve approver trust and state exactly what protection exists if the configured Gateway is malicious or compromised.
- Complete the signed-prekey private-key lifecycle: generation, encrypted persistence, retrieval, rotation, retirement, grace period and restore behavior.
- Replace process-local candidate rate limiting with shared PostgreSQL-backed enforcement and explicit trusted-proxy policy.
- Enforce immutability of all challenge binding columns and review the runtime database role/privileges.
- Prove lock ordering, races, expiry, replay, process death, ambiguous HTTP outcomes and restart-safe Android enrollment operations.
- Implement and test the separate delayed recovery flow, including the 48-hour abort window and finalization semantics.
- Obtain independent protocol/security review before freezing or enabling candidate routes.

**Do not enable candidate enrollment or recovery routes as a shortcut.** Their current non-production status is intentional.

## 6. Current Android 1:1 alpha — actual source behavior

### What exists

- `MainActivity.kt` renders `AlphaMessagingPanel` when debug screen mirroring is not enabled.
- `AlphaPairing.kt` creates a local signed-prekey, exports a public pairing code, validates an imported code, displays a fingerprint, and requires the user to confirm an out-of-band fingerprint comparison before pinning the peer.
- `createAlphaMessagingRuntime` fetches the local device directory, checks that the account/device/DSK/DDHK match the local identity and that the device is not marked revoked, then constructs `PersistentMessagingEngine` and `DeviceMessageHttpClient`.
- `PersistentMessagingEngine` supports initiator session creation, signed-prekey restoration, outgoing encryption, outbox submission, inbound processing, duplicate detection, durable ACK receipts and local message opening.
- `LocalMessagingDatabase` stores sessions, signed-prekeys, messages, outbox rows and inbox ACK receipts in SQLite. Ratchet snapshots, private signed-prekey records and message bodies are stored as encrypted records; routing and operational metadata remain visible.
- Outbound processing stages a native ratchet transition, persists the encrypted message/envelope/outbox entry and new encrypted snapshot in a SQLite transaction, then promotes the native state. An uncertain send is marked `DELIVERY_UNKNOWN`; it is not blindly retried.
- Inbound processing checks duplicate gateway envelope IDs, stages decryption, stores the encrypted body/message/inbox receipt and next ratchet snapshot transactionally, then ACKs only after durable local commit.
- The alpha UI offers manual foreground polling at a three-second interval. Polling stops when the panel is closed or the user stops it.

### Explicit alpha limitations

- Manual fingerprint pinning replaces the KT witness quorum only for this alpha. It is not production identity trust.
- HTTP message transport is the `/v1/demo/messages` API.
- Foreground polling is not background delivery, push delivery or a WebSocket-based real-time service.
- The directory response is not a Gateway-signed, rollback-resistant authorization statement; the UI explicitly warns about this.
- The local SQLite database uses application-level encrypted records; it is not a fully encrypted database. Some routing and operational metadata remain visible.
- No Android end-to-end test was found that instantiates two messaging engines/app clients and proves the full send → Gateway → receive → reply → restart path. The existing Android CI covers build/lint/unit tests/emulator smoke and identity instrumentation, not this chat acceptance path.

## 7. Ratchet persistence and anti-rollback — current evidence

### Implemented components

- `ratchet_snapshot.rs` contains a dedicated strict snapshot codec that writes secret-bearing state to `Zeroizing<Vec<u8>>` and parses borrowed input rather than creating a generic CBOR value tree with unzeroized secret copies.
- `storage_record.rs` uses ChaCha20-Poly1305 and authenticates record type, account ID, device ID, session ID and generation as associated data. Plaintext opened records use zeroizing memory.
- `ratchet_persistence.rs` stages state transitions against an isolated candidate and does not replace the active state until the caller commits the associated durable transaction.
- Native tests cover snapshot roundtrip, generation/tamper rejection, staged-state isolation and failed-transition non-mutation.
- Android code wires native staging into local SQLite transactions for message, outbox/inbox and snapshot persistence.

### Still open

- `docs/phase0/14-ratchet-state-persistence-v1.md` remains marked **DESIGN PROPOSAL — NOT FROZEN**. The remaining contract includes authenticated session catalog/index, receipt retention, ambiguous final-commit recovery, outbox cleanup ordering, exact API semantics, size proofs and complete crash/failure-injection evidence.
- `docs/phase0/15-ratchet-checkpoint-antirollback-v1-proposal.md` remains an engineering proposal, not frozen. The current Gateway KT witness verifier is not the independent, per-device ratchet checkpoint authority described by that proposal.
- A mutually consistent old device snapshot still needs to be detected or blocked by an independently trusted freshness mechanism before ratchet key use. An encrypted snapshot and a generation stored inside the same rollbackable local database do not by themselves prove freshness.
- Required evidence still includes crash injection around every outbound/inbound commit boundary, lost acknowledgements, restore of stale snapshots, receipt tampering/deletion/GC, concurrency and target-device performance.

## 8. Test and evidence matrix

| Area | Evidence found | What it does not prove |
|---|---|---|
| Gateway Go | `go vet`, full Go tests and PostgreSQL-backed integration CI on `main` | End-to-end Android app behavior or production deployment readiness |
| Rust ratchet | X3DH + bidirectional Double Ratchet interop test; snapshot and staged-transition tests | Android persistence crash recovery, Gateway transport, two physical devices or anti-rollback |
| Android build/identity | Gradle build/unit tests, emulator startup smoke, native rebuild and Keystore/UniFFI instrumentation | Actual two-device encrypted chat, restart/restore acceptance, production background delivery |
| Android message storage/client | Unit tests for local DB and message/directory HTTP clients | Full `PersistentMessagingEngine` and `AlphaMessagingPanel` integration against a live Gateway |
| P2 PostgreSQL | Candidate enrollment/recovery integration test source and CI database | Protocol freeze, real Android enrollment, production route enablement or independent review |

## 9. Recommended next implementation order

1. **Finish P0 reconciliation:** update README and release-gate claims to reflect the controlled alpha, latest CI and still-open production gates; add the complete authoritative P0–P9 register.
2. **Close P1 alpha integration evidence:** create an automated two-client test harness against a disposable Gateway/PostgreSQL instance. Test session establishment, first message, reply, duplicate/replay, offline queue, ACK, restart and outbox ambiguity.
3. **Close P2 design gates:** ratify and independently review enrollment/recovery decisions and V2 transcript; implement only after freeze; keep candidate routes disabled until their acceptance gates pass.
4. **Freeze ratchet persistence and anti-rollback contracts:** incorporate what is already implemented in the snapshot/StorageRecord code, close remaining receipt/catalog/transaction/freshness requirements, and review before claiming completion.
5. **Then expand client behavior:** background delivery, production KT trust, user-facing conversation lifecycle and supported-device acceptance.
6. **Production gate:** fuzzing, formal analysis, external cryptographic audit, operational staging, backup/restore and incident/rollback evidence.

## 10. Source references

- [Main commit reviewed](https://github.com/Vineeth2002/private-messenger/commit/0a332a5b08ca0eb74c83b730e20751bdee38a64b)
- [MainActivity](https://github.com/Vineeth2002/private-messenger/blob/main/apps/android/app/src/main/java/org/sovereign/pm/MainActivity.kt)
- [Alpha pairing and messaging panel](https://github.com/Vineeth2002/private-messenger/blob/main/apps/android/app/src/main/java/org/sovereign/pm/messaging/AlphaPairing.kt)
- [Persistent messaging engine](https://github.com/Vineeth2002/private-messenger/blob/main/apps/android/app/src/main/java/org/sovereign/pm/messaging/PersistentMessagingEngine.kt)
- [Local messaging database](https://github.com/Vineeth2002/private-messenger/blob/main/apps/android/app/src/main/java/org/sovereign/pm/messaging/LocalMessagingDatabase.kt)
- [Device message HTTP client](https://github.com/Vineeth2002/private-messenger/blob/main/apps/android/app/src/main/java/org/sovereign/pm/messaging/DeviceMessageHttpClient.kt)
- [Rust ratchet snapshot codec](https://github.com/Vineeth2002/private-messenger/blob/main/native/crypto-core/src/ratchet_snapshot.rs)
- [Rust record encryption](https://github.com/Vineeth2002/private-messenger/blob/main/native/crypto-core/src/storage_record.rs)
- [Rust staged ratchet persistence](https://github.com/Vineeth2002/private-messenger/blob/main/native/crypto-core/src/ratchet_persistence.rs)
- [P2 policy reconciliation](https://github.com/Vineeth2002/private-messenger/blob/main/docs/phase-c/08-p2-enrollment-v2-policy-reconciliation.md)
- [P2 adversarial review](https://github.com/Vineeth2002/private-messenger/blob/main/docs/phase-c/09-p2-enrollment-v2-adversarial-security-review.md)
- [P2 two-sided pairing proposal](https://github.com/Vineeth2002/private-messenger/blob/main/docs/phase-c/10-p2-enrollment-v2-two-sided-commit-reveal-protocol.md)
- [Ratchet persistence proposal](https://github.com/Vineeth2002/private-messenger/blob/main/docs/phase0/14-ratchet-state-persistence-v1.md)
- [Anti-rollback proposal](https://github.com/Vineeth2002/private-messenger/blob/main/docs/phase0/15-ratchet-checkpoint-antirollback-v1-proposal.md)
- [Production release gate](https://github.com/Vineeth2002/private-messenger/blob/main/docs/PRIVATE_MESSENGER_RELEASE_GATE.md)

---

**Audit conclusion:** the correct next target is not “build a chat UI from scratch.” It is to make the existing controlled Android messaging alpha reproducible end-to-end, while closing P0 documentation drift and preserving the P2 and ratchet-persistence security freeze gates. This audit does not authorize candidate route enablement or production use.
