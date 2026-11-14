# Private Messenger - Production Release Gate

**Current decision: BLOCKED for production use.**

This is a release-control document, not a claim that incomplete gates have passed. The latest reviewed main baseline is [09dfe4faa61fa810a2994f1560a0b9894fdb115a](https://github.com/Vineeth2002/private-messenger/commit/09dfe4faa61fa810a2994f1560a0b9894fdb115a), inspected on 2026-11-15 (Asia/Kolkata). The P0-P2 source audit was reviewed against main commit [0a332a5b08ca0eb74c83b730e20751bdee38a64b](https://github.com/Vineeth2002/private-messenger/commit/0a332a5b08ca0eb74c83b730e20751bdee38a64b) and merged in [PR #18](https://github.com/Vineeth2002/private-messenger/pull/18).

## Current implementation snapshot - 2026-11-15

The repository now contains a **controlled Android 1:1 messaging alpha**. MainActivity mounts AlphaMessagingPanel. The alpha includes manual out-of-band peer fingerprint pinning, signed-prekey/X3DH setup, Double Ratchet message processing, encrypted local message/ratchet records, SQLite-backed sessions/messages/outbox/inbox receipts, and send/fetch/ACK through the demo message API. Synchronization is foreground polling while the panel is active.

These capabilities supersede the older README statement that Android is only a diagnostics/identity screen. They do **not** satisfy the production release gate:

- Manual fingerprint comparison is alpha-only and does not replace witness-backed production Key Transparency.
- The Android alpha uses the `/v1/demo/messages` API, not a complete production authenticated messaging API.
- Foreground polling is not production background delivery or a completed notification lifecycle.
- No automated Android acceptance test has been established for the complete two-client Android-to-Gateway-to-PostgreSQL-to-Android path, including reply and restart/restore.
- Local encrypted records and a generation counter do not, by themselves, establish rollback-resistant freshness against restoration of an old local database snapshot.
- Candidate enrollment and recovery routes remain feature-gated; the P2 protocol and activation policy are not frozen.
- There is no completed iOS application or checked-in Xcode project.

The evidence-based implementation detail is recorded in [the P0-P2 baseline audit](ROADMAP_P0_P2_CURRENT_BASELINE_2026-11-15.md). That audit deliberately does not assign P3-P9 names, weights or completion values because the complete authoritative register is not in the tracked documentation.

## Verified baseline

- [x] The vector-manifest fix and Android CI fixes were merged in historical commit [10c6772](https://github.com/Vineeth2002/private-messenger/commit/10c6772e8095d5c3db9a22e557aac92a64ff1a45).
- [x] Android build, lint, unit tests, APK assembly and emulator startup smoke passed in the historical [run #14](https://github.com/Vineeth2002/private-messenger/actions/runs/40108208245). This is historical CI evidence, not two-device chat acceptance.
- [x] Native Rust Android libraries were rebuilt from source and Android Keystore + UniFFI identity-storage instrumentation passed in historical [run #12](https://github.com/Vineeth2002/private-messenger/actions/runs/40108208230).
- [x] Rust, Go, independent Python reference/vector checks and shared-vector parity passed in historical [run #52](https://github.com/Vineeth2002/private-messenger/actions/runs/40108208237).
- [x] The dedicated Gateway validation workflow was restored in [PR #17](https://github.com/Vineeth2002/private-messenger/pull/17). Its Gateway Go tests, `go vet` and PostgreSQL integration job passed on the merged main baseline [0a332a5](https://github.com/Vineeth2002/private-messenger/commit/0a332a5b08ca0eb74c83b730e20751bdee38a64b).
- [x] The P0-P2 implementation baseline audit was added to main in [PR #18](https://github.com/Vineeth2002/private-messenger/pull/18).
- [x] README and this release gate distinguish the current controlled Android alpha from production readiness.
- [x] The README and threat model state that the project is not for production use and has not had an independent cryptographic audit.

**CI boundary:** a passing workflow verifies only the checks configured in that workflow. It does not verify complete mobile product behavior, physical-device acceptance, deployment configuration, or cryptographic security through independent review.

## Roadmap status - do not infer missing stages

The canonical roadmap baseline uses fixed stages P0-P9. Current evidence supports:

| Stage | Focus | Status |
|---|---|---|
| P0 | Scope and evidence baseline | In progress; no product-completion weight |
| P1 | Gateway platform foundation | In progress; 12% weight |
| P2 | Identity, enrollment, authorization and recovery | In progress; 12% weight |
| P3-P9 | Remaining stages | Authoritative names, weights and exit criteria are not present in the current tracked register. Do not invent them or calculate total completion. |

The complete P0-P9 register must be reconciled from an authoritative owner-approved source before an overall roadmap percentage or P3-P9 status can be published.

## Release-blocking gates

### 1. Scope, protocol and documentation

- [ ] Confirm the canonical owner-approved P0-P9 stage register, including names, weights, dependencies and objective exit criteria.
- [ ] Declare the first release's exact supported platforms and feature scope. Do not imply iOS support unless an Xcode build and device validation pass.
- [ ] Choose the project license and confirm the canonical Go module path before external distribution.
- [ ] Keep README, threat model, implementation notes, release gate and user-facing security claims synchronized with source and test evidence.
- [ ] Freeze the first production API contract and the ordinary device-enrollment/recovery protocol only after owner decisions and independent review.

### 2. Client build and device validation

- [ ] Confirm reproducible Android builds with pinned toolchains and dependencies for the declared release scope.
- [x] Android build/lint/unit-test/emulator-startup CI and native-library rebuild + identity-storage instrumentation CI exist. These checks do not replace physical-device acceptance testing.
- [ ] Test on supported physical Android devices: first install, authorized registration, peer verification, message send/receive, background/foreground, process kill/restart, app upgrade, and local-state failure/recovery.
- [ ] Decide and document whether iOS is out of scope for the first release. If included, establish an Xcode project, reproducible build/tests, platform key protection and supported-device validation.

### 3. End-to-end messaging and service integration

- [ ] Demonstrate the complete two-device path: device setup, authenticated key establishment, first message, reply, offline recipient delivery, restart and recovery.
- [ ] Replace the alpha `/v1/demo/messages` surface with the reviewed production authenticated messaging API and integrate it end to end.
- [ ] Complete production client/API contracts, durable ratchet-state persistence, Key Transparency publication/proof/witness endpoints, and authenticated device enrollment/revocation/recovery routes.
- [ ] Verify that authentication/decryption failures, malformed input and replays leave ratchet and durable application state unchanged.
- [ ] Test tampered ciphertext, invalid identity/key binding, stale keys, skipped/out-of-order messages, duplicated delivery and replay attempts.
- [ ] Test concurrent message processing, process termination during state changes, database restart, backup/restore and rollback behavior; verify that keys/counters cannot be silently reused or rolled back.
- [ ] Demonstrate the media and push flows included in the declared release scope. Treat APNs/FCM as external, untrusted wake-up transports, not sources of message authorization.
- [ ] Implement and validate production background delivery; foreground polling in the current alpha does not satisfy this gate.

### 4. Ratchet persistence, freshness and recovery

- [ ] Freeze the ratchet persistence contract after reconciling the implemented snapshot/record code with the open design requirements.
- [ ] Establish an independently trusted anti-rollback/freshness mechanism; encryption and a generation value stored in the same rollbackable local database are insufficient by themselves.
- [ ] Add crash/fault injection around every outbound and inbound persistence/ACK boundary, including ambiguous network outcomes and process death.
- [ ] Prove restart/restore behavior, stale-snapshot rejection, receipt retention/cleanup, concurrency safety and recovery semantics on supported devices.
- [ ] Complete the distinct delayed recovery flow, including the 48-hour abort window and finalization semantics, and verify it on Android and Gateway.

### 5. Security verification

- [ ] Run and record parser and cryptographic fuzzing campaigns.
- [ ] Run and record concurrency and crash-recovery testing.
- [ ] Verify memory-handling/zeroization claims to the extent possible in each runtime, and document managed-runtime limitations.
- [ ] Complete the planned formal/symbolic protocol analysis (project notes identify ProVerif/Tamarin).
- [ ] Obtain an independent third-party cryptographic audit. Track findings and attach remediation/retest evidence before release.

### 6. Production operations and privacy

- [ ] Decide and verify infrastructure, India data-residency requirements, service boundaries, TLS configuration, least-privilege access and secret/key management.
- [ ] Configure logs, metrics, crash reports and tracing so they do not expose plaintext, cryptographic secrets, recovery material or unauthorized message content.
- [ ] Document metadata and external-provider boundaries, including APNs/FCM, IP routing, packet sizes and timing.
- [ ] Exercise backup/restore, incident response, credential rotation, monitoring/alerting, rollback and service recovery in staging.
- [ ] Complete privacy disclosures, data-retention/deletion rules, operational ownership and user-facing security claims.
- [ ] Keep production secrets out of the repository, test logs, issues and build artifacts.

## Evidence required before changing the decision to READY

Attach or link all of the following, with commit IDs and dates:

1. Passing required CI jobs and reproducible Android/iOS build results for the declared support scope.
2. An end-to-end test report for the supported messaging/media/push flows and negative security cases.
3. A persistence, concurrency, crash-recovery and backup/restore report.
4. Fuzzing and formal-analysis reports, with outstanding issues explicitly assessed.
5. Independent cryptographic audit summary plus proof that release-blocking findings were resolved and retested.
6. A staging deployment review covering secrets, infrastructure, data residency, monitoring, recovery and rollback.
7. Final review of the README, threat model, supported-feature claims, license and privacy disclosures.

## Release rule

Do not mark the project production-ready or deploy it for real users until the applicable gates above are complete and their evidence has been reviewed. A development/demo deployment, if separately chosen, must be explicitly labelled non-production and must not be presented as audited or safe for sensitive conversations.

## Source files checked

- [README.md](../README.md)
- [P0-P2 implementation baseline audit](ROADMAP_P0_P2_CURRENT_BASELINE_2026-11-15.md)
- [MainActivity](../apps/android/app/src/main/java/org/sovereign/pm/MainActivity.kt)
- [Alpha pairing and messaging panel](../apps/android/app/src/main/java/org/sovereign/pm/messaging/AlphaPairing.kt)
- [Persistent messaging engine](../apps/android/app/src/main/java/org/sovereign/pm/messaging/PersistentMessagingEngine.kt)
- [Local messaging database](../apps/android/app/src/main/java/org/sovereign/pm/messaging/LocalMessagingDatabase.kt)
- [Device message HTTP client](../apps/android/app/src/main/java/org/sovereign/pm/messaging/DeviceMessageHttpClient.kt)
- [Rust ratchet snapshot codec](../native/crypto-core/src/ratchet_snapshot.rs)
- [Rust record encryption](../native/crypto-core/src/storage_record.rs)
- [Rust staged ratchet persistence](../native/crypto-core/src/ratchet_persistence.rs)
- [Gateway validation workflow](../.github/workflows/gateway-go-validation.yml)
- [Phase B gate](PHASE_B_GATE.md)
- [Implementation notes](IMPLEMENTATION_NOTES.md)
- [Windows setup](LOCAL_SETUP_WINDOWS.md)
- [Threat model](phase0/02-threat-model.md)

## P2 enrollment activation candidate - historical status (2026-10-30)

**Release decision: BLOCKED for production use.**

- The legacy PostgreSQL `Enroll` method fails closed with `ErrEnrollmentProofRequired`; repository searches at the time found no production call site for `PostgresAuthorizer.Enroll`. The authorizer lives under Go's `internal` package boundary, so external Go modules cannot import it through normal Go package rules. Forks or copied implementations are outside this repository audit.
- Candidate challenge and activation endpoints are opt-in and must remain disabled. The protocol/API is not frozen.
- Candidate backend Go tests and PostgreSQL integration tests passed against the dedicated disposable database, but this does not substitute for end-to-end Android enrollment testing.
- Android-to-Gateway enrollment integration, the recovery-locked/48-hour recovery flow, and the broader release-gate items remained incomplete.

The P2 baseline remains in progress as of 2026-11-15. Do not enable candidate enrollment or recovery routes until the protocol, client/server integration, operational controls and required independent review are complete. Do not describe this candidate as production-ready or use it for sensitive conversations.
