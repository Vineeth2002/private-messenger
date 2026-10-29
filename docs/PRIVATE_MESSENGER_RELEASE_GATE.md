# Private Messenger — Production Release Gate

**Current decision: BLOCKED for production use.**

This checklist reflects the repository at `main` commit [`10c6772e8095d5c3db9a22e557aac92a64ff1a45`](https://github.com/Vineeth2002/private-messenger/commit/10c6772e8095d5c3db9a22e557aac92a64ff1a45), inspected on 2026-10-24. It is a release control document, not a claim that the uncompleted gates have passed.

## Verified baseline

- [x] The vector-manifest fix and Android CI fixes are merged into `main` at commit [`10c6772e8095d5c3db9a22e557aac92a64ff1a45`](https://github.com/Vineeth2002/private-messenger/commit/10c6772e8095d5c3db9a22e557aac92a64ff1a45).
- [x] Android build, lint, unit tests, APK assembly and emulator startup smoke passed on this commit in [run #14](https://github.com/Vineeth2002/private-messenger/actions/runs/40108208245).
- [x] Native Rust Android libraries were rebuilt from source and Android Keystore + UniFFI identity-storage instrumentation passed in [run #12](https://github.com/Vineeth2002/private-messenger/actions/runs/40108208230).
- [x] Rust, Go, independent Python reference/vector checks and shared-vector parity passed in [run #52](https://github.com/Vineeth2002/private-messenger/actions/runs/40108208237).
- [x] The README and threat model state that the project is not for production use and has not had an independent cryptographic audit.
- [x] Current code includes a PostgreSQL-backed demo message relay, device-directory reads, Key Transparency storage/proof components, and authorization components; end-to-end integration remains incomplete.
**Important:** Passing the existing CI verifies the checks configured in that workflow. It does not verify mobile builds, complete product behavior, deployment configuration, or cryptographic security through independent review.

## Release-blocking gates

### 1. Reconcile the project status documentation

- [x] Update `docs/PHASE_B_GATE.md` to preserve the 2026-10-05 unlock as historical evidence and show the current Phase B status without implying production readiness.
- [x] Update `docs/IMPLEMENTATION_NOTES.md` to distinguish implemented cryptographic modules, passing Android CI, existing backend storage/proof/authorization code, and missing end-to-end integration.
- [ ] Declare the first release's exact supported platforms and features. Do not imply iOS support unless Xcode build and device validation pass.
- [ ] Choose the project license and confirm the canonical Go module path before external distribution.
### 2. Client build and device validation

- [ ] Confirm fully reproducible Android builds with pinned toolchains and dependencies for the declared release scope.
- [x] Add Android build/lint/unit-test/emulator-startup CI and native-library rebuild + identity-storage instrumentation CI. These checks do not replace physical-device acceptance testing.
- [ ] Test on supported physical Android devices: first install, authorized registration, message send/receive, background/foreground, process kill/restart, app upgrade, and local-state failure/recovery.
- [ ] Decide and document whether iOS is out of scope for the first release. If included, establish an Xcode project, reproducible build/tests, and supported-device validation.
### 3. End-to-end messaging and service integration

- [ ] Demonstrate the complete two-device path: device setup, authenticated key establishment, first message, reply, offline recipient delivery, restart, and recovery.
- [ ] Complete and integrate production client/API contracts, durable ratchet-state persistence, Key Transparency publication/proof/witness endpoints, and authenticated device enrollment/revocation/recovery routes. Existing PostgreSQL demo delivery, transparency stores/proof services, and authorization packages do not by themselves satisfy this gate.
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
