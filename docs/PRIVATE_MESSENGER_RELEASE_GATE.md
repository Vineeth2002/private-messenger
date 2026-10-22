# Private Messenger — Production Release Gate

**Current decision: BLOCKED for production use.**

This checklist is based on the repository state inspected on 2026-10-20. It is a release control document, not a claim that the listed tests or reviews have already been completed.

## Verified baseline

- [x] The vector-manifest fix is merged into `main` at merge commit [`a27362ac79cc405aab4a7dc6b947eddf03ae71a2`](https://github.com/Vineeth2002/private-messenger/commit/a27362ac79cc405aab4a7dc6b947eddf03ae71a2).
- [x] GitHub Actions run [#22](https://github.com/Vineeth2002/private-messenger/actions/runs/39433309911) passed on that merge commit.
- [x] The passing workflow covers deterministic shared-vector generation and checks, Rust tests, Go module verification/vetting/tests, and Rust–Go vector parity.
- [x] The repository README states “Not for production use. Not audited.”
- [x] The README identifies gateway/API, persistence, witness-service integration, and device-authorization boundaries as remaining work.
- [x] The threat model says an independent third-party cryptographic audit is required.

**Important:** Passing the existing CI verifies the checks configured in that workflow. It does not verify mobile builds, complete product behavior, deployment configuration, or cryptographic security through independent review.

## Release-blocking gates

### 1. Reconcile the project status documentation

- [ ] Update `docs/PHASE_B_GATE.md` so its status matches the current implementation; it contains older statements saying Double Ratchet, media, push, and transparency work was not started.
- [ ] Update `docs/IMPLEMENTATION_NOTES.md` to distinguish completed, in-progress, unimplemented, and independently verified components. Resolve stale statements such as “Android/iOS projects are skeletons that have never been built” with actual build evidence.
- [ ] Declare the first release's supported platforms and features. Do not imply iOS support unless an iOS build and device validation actually pass.
- [ ] Replace placeholder license and Go module metadata before public distribution.

### 2. Client build and device validation

- [ ] Establish a reproducible Android build using pinned toolchain/dependency versions.
- [ ] Add Android build and automated test jobs to CI where practical; record which device-level tests require physical hardware.
- [ ] Test on supported Android devices: first install, registration/device authorization, message send/receive, app background/foreground, process kill/restart, app upgrade, and local-state failure/recovery.
- [ ] If iOS is in release scope, establish reproducible Xcode build/tests and validate on supported iOS devices. Otherwise mark iOS out of scope for the release.

### 3. End-to-end messaging and service integration

- [ ] Demonstrate the complete two-device path: device setup, authenticated key establishment, first message, reply, offline recipient delivery, restart, and recovery.
- [ ] Finish and test the gateway/API, durable persistence, witness/transparency integration, and device authorization boundaries identified in the README.
- [ ] Verify that authentication/decryption failures, malformed input, and replays leave ratchet and durable application state unchanged.
- [ ] Test tampered ciphertext, invalid identity/key binding, stale keys, skipped/out-of-order messages, duplicated delivery, and replay attempts.
- [ ] Test concurrent message processing, process termination during state changes, database restart, backup/restore, and rollback behavior; verify that keys/counters cannot be silently reused or rolled back.
- [ ] Demonstrate the media and push flows that are in the claimed release scope. Treat APNs/FCM as external, untrusted wake-up transports, not sources of message authorization.

### 4. Security verification

- [ ] Run and record parser and cryptographic fuzzing campaigns.
- [ ] Run and record concurrency and crash-recovery testing.
- [ ] Verify memory-handling/zeroization claims to the extent possible in each runtime, and document managed-runtime limitations.
- [ ] Complete the planned formal/symbolic protocol analysis (the project notes call out ProVerif/Tamarin).
- [ ] Obtain an independent third-party cryptographic audit. Track findings and attach remediation/retest evidence before release.

### 5. Production operations and privacy

- [ ] Decide and verify infrastructure, India data-residency requirements, service boundaries, TLS configuration, least-privilege access, and secret/key management.
- [ ] Configure logs, metrics, crash reports, and tracing so they do not expose plaintext, cryptographic secrets, recovery material, or unauthorized message content.
- [ ] Document the metadata and external-provider boundaries, including APNs/FCM, IP routing, packet sizes, and timing.
- [ ] Exercise backup/restore, incident response, credential rotation, monitoring/alerting, rollback, and service recovery in staging.
- [ ] Complete privacy disclosures, data-retention/deletion rules, operational ownership, and user-facing security claims.
- [ ] Keep production secrets out of the repository, test logs, issues, and build artifacts.

## Evidence required before changing the decision to READY

Attach or link all of the following, with commit IDs and dates:

1. Passing required CI jobs and reproducible Android/iOS build results for the declared support scope.
2. An end-to-end test report for the supported message/media/push flows and negative security cases.
3. A persistence, concurrency, and crash-recovery report, including backup/restore results.
4. Fuzzing and formal-analysis reports, with outstanding issues explicitly assessed.
5. Independent cryptographic audit summary plus proof that release-blocking findings were resolved and retested.
6. A staging deployment review covering secrets, infrastructure, data residency, monitoring, recovery, and rollback.
7. Final review of the README, threat model, supported-feature claims, license, and privacy disclosures.

## Release rule

Do not mark the project production-ready or deploy it for real users until the applicable gates above are complete and their evidence has been reviewed. A development/demo deployment, if separately chosen, must be explicitly labelled non-production and must not be presented as audited or safe for sensitive conversations.

## Source files checked

- [`README.md`](https://github.com/Vineeth2002/private-messenger/blob/main/README.md)
- [`docs/PHASE_B_GATE.md`](https://github.com/Vineeth2002/private-messenger/blob/main/docs/PHASE_B_GATE.md)
- [`docs/IMPLEMENTATION_NOTES.md`](https://github.com/Vineeth2002/private-messenger/blob/main/docs/IMPLEMENTATION_NOTES.md)
- [`docs/LOCAL_SETUP_WINDOWS.md`](https://github.com/Vineeth2002/private-messenger/blob/main/docs/LOCAL_SETUP_WINDOWS.md)
- [`docs/phase0/02-threat-model.md`](https://github.com/Vineeth2002/private-messenger/blob/main/docs/phase0/02-threat-model.md)
- [CI workflow](https://github.com/Vineeth2002/private-messenger/blob/main/.github/workflows/test-vectors-parity.yml)
