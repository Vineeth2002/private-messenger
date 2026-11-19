# Sovereign Private Messenger

A global private messenger engineered in India: persistent application data hosted in India, end-to-end encryption (E2EE) with client-owned cryptographic state, and the server acting as a delivery/control plane.

**Status snapshot: 2026-11-19 (Asia/Kolkata). Controlled Android 1:1 messaging alpha; not production-ready and not independently audited.** The latest reviewed main baseline is [1137b9b](https://github.com/Vineeth2002/private-messenger/commit/1137b9b6e6c195ca46df65800cf008bce29ad47c).

## Current product state

The earlier README statement that Android only presents a diagnostics/identity screen is stale. MainActivity now mounts AlphaMessagingPanel. The repository contains a controlled Android 1:1 messaging alpha with:

- Manual out-of-band peer fingerprint comparison and pinning. This is an alpha trust mechanism, not production Key Transparency.
- Signed-prekey/X3DH session setup and Double Ratchet message processing through the native crypto core.
- Encrypted local message-body and ratchet-snapshot records, with SQLite persistence for sessions, messages, outbox entries and inbox receipts.
- Gateway message submission, fetch and ACK through the current demo message API.
- Foreground synchronization by polling while the messaging panel is active.

This is meaningful alpha functionality, but it is not a fully validated end-to-end product. The current client uses the `/v1/demo/messages` surface, manual fingerprint trust instead of witness-backed production trust, and foreground polling rather than production background delivery. The repository does not yet contain an Android acceptance test that proves the complete two-client Android-to-Gateway-to-PostgreSQL-to-Android path, including reply and restart/restore.

## Canonical P0â€“P9 roadmap

The canonical project roadmap is now recorded in [ROADMAP_P0_P9_CANONICAL_2026-11-19.md](docs/ROADMAP_P0_P9_CANONICAL_2026-11-19.md). P0â€“P2 retain the existing baseline; P3â€“P9 formalize the remaining product scope into explicit implementation and release gates.

| Stage | Focus | Status |
|---|---|---|
| P0 | Scope and evidence baseline | In progress |
| P1 | Gateway platform foundation | In progress; 12% existing weight |
| P2 | Identity, enrollment, authorization and recovery | In progress; 12% existing weight |
| P3 | End-to-end cryptographic protocol and durable cryptographic state | In progress; freeze and assurance remain open |
| P4 | Android 1:1 messaging client | Controlled alpha exists; acceptance incomplete |
| P5 | Reliable delivery, offline operation, background sync and notifications | Foreground polling only; production behavior incomplete |
| P6 | Encrypted media and content lifecycle | Crypto foundation exists; end-to-end flow incomplete |
| P7 | Voice/video calling and cross-platform client readiness | Not started as a complete product capability |
| P8 | Groups and multi-device conversations | Not started as a complete product capability |
| P9 | Production assurance, operations and release | Blocked |

Do not calculate an overall completion percentage until the remaining phase weights are approved. Language Lens and on-device AI remain future/post-V1 work, not blockers for the narrow Android 1:1 alpha.

## What is not complete

- Production peer identity trust using the approved Key Transparency witness model. Manual fingerprint pinning is alpha-only.
- A production authenticated messaging API replacing the demo message routes.
- Background delivery and a production notification lifecycle. Current alpha synchronization is foreground polling.
- The complete two-client Android-to-Gateway-to-PostgreSQL send/reply/restart acceptance path.
- Frozen and independently reviewed ordinary device-enrollment and recovery protocols. Candidate routes remain feature-gated and must stay disabled until their gates pass.
- Frozen ratchet-persistence and independent anti-rollback/freshness contracts, plus crash/fault-injection evidence.
- Physical-device acceptance, operational hardening, formal/symbolic analysis, fuzzing, and an independent cryptographic audit.
- iOS support. There is no checked-in Xcode project or completed iOS platform key-protection implementation.

**Not for production use. Do not use this alpha for sensitive conversations. Not independently audited.**

## Gateway and CI evidence

The dedicated Gateway validation workflow runs Go tests, `go vet`, and PostgreSQL-backed integration validation. The workflow was restored and merged in [PR #17](https://github.com/Vineeth2002/private-messenger/pull/17); its successful checks establish the configured Gateway test coverage, not full Android product behavior or production security.

A passing CI workflow is evidence only for the jobs and test paths it actually runs. A plain local Go test command does not prove PostgreSQL integration ran unless the required test database configuration is present. See the [Gateway validation workflow](.github/workflows/gateway-go-validation.yml) for the database-backed CI setup.

## Security and non-claims

Hosted-in-India does not mean all packets stay in India. APNs/FCM are external boundaries. Ed25519/X25519 hardware execution is not universally available. Push is not authenticated message content. Unit tests are not certification. Zeroization is limited by managed runtimes. PM-BI-X3DH-1 is proprietary and not Signal-interoperable. An independent cryptographic audit is required. See the [threat model](docs/phase0/02-threat-model.md) and [production release gate](docs/PRIVATE_MESSENGER_RELEASE_GATE.md).

## Validation

Use the [Windows setup guide](docs/LOCAL_SETUP_WINDOWS.md) for the supported local toolchain and prerequisites.

Windows + VS Code (Command Prompt):
```powershell
py -m pip install cryptography
py tools\gen_vectors.py
py tools\check_vectors.py
py tools\build_normal_linear_vectors.py
py tools\build_reorder_vectors.py
py tools\build_hpke_push_vectors.py
py tools\check_normal_vectors.py
py tools\check_reorder_vectors.py
py tools\check_hpke_push_vectors.py
cd native\crypto-core
cargo test --locked
cd ..\..\services\gateway
go test ./...
```

Linux / macOS (bash):
```bash
python3 -m pip install cryptography
python3 tools/gen_vectors.py && git diff --exit-code test-vectors
python3 tools/check_vectors.py
cargo test --locked --manifest-path native/crypto-core/Cargo.toml
(cd services/gateway && go mod download && go mod verify && go test ./...)
bash tools/run_all.sh
```

The standard local `go test ./...` invocation does not, by itself, prove that PostgreSQL integration tests ran. For PostgreSQL-backed Gateway validation, use the dedicated [Gateway CI workflow](.github/workflows/gateway-go-validation.yml), which provisions a disposable PostgreSQL database, applies migrations and runs the database-enabled Go test suite.

The native Rust test suite, Gateway Go tests, shared-vector parity checks, Android build/test jobs and identity-storage instrumentation cover separate components. They do not collectively prove the complete app-to-app messaging path.

## Project records

- [P0-P2 implementation baseline audit](docs/ROADMAP_P0_P2_CURRENT_BASELINE_2026-11-15.md)
- [Production release gate](docs/PRIVATE_MESSENGER_RELEASE_GATE.md)
- [Phase B gate record](docs/PHASE_B_GATE.md)
- [Implementation notes](docs/IMPLEMENTATION_NOTES.md)
- [Local Windows setup](docs/LOCAL_SETUP_WINDOWS.md)
