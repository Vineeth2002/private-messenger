# Sovereign Private Messenger

A global private messenger engineered in India: persistent application data hosted in India, end-to-end encryption (E2EE) with client-owned cryptographic state, and the server acting as a delivery/control plane.

**Status snapshot: 2026-11-15 (Asia/Kolkata). Controlled Android 1:1 messaging alpha; not production-ready and not independently audited.** The latest reviewed main baseline is [09dfe4f](https://github.com/Vineeth2002/private-messenger/commit/09dfe4faa61fa810a2994f1560a0b9894fdb115a).

## Current product state

The earlier README statement that Android only presents a diagnostics/identity screen is stale. MainActivity now mounts AlphaMessagingPanel. The repository contains a controlled Android 1:1 messaging alpha with:

- Manual out-of-band peer fingerprint comparison and pinning. This is an alpha trust mechanism, not production Key Transparency.
- Signed-prekey/X3DH session setup and Double Ratchet message processing through the native crypto core.
- Encrypted local message-body and ratchet-snapshot records, with SQLite persistence for sessions, messages, outbox entries and inbox receipts.
- Gateway message submission, fetch and ACK through the current demo message API.
- Foreground synchronization by polling while the messaging panel is active.

This is meaningful alpha functionality, but it is not a fully validated end-to-end product. The current client uses the /v1/demo/messages surface, manual fingerprint trust instead of witness-backed production trust, and foreground polling rather than production background delivery. The repository does not yet contain an Android acceptance test that proves the complete two-client Android â†’ Gateway â†’ PostgreSQL â†’ Android path, including reply and restart/restore.

## Roadmap status

The canonical roadmap uses fixed stages P0â€“P9. The current tracked baseline supports only these status statements:

| Stage | Focus | Current status |
|---|---|---|
| P0 | Scope and evidence baseline | In progress; no product-completion weight |
| P1 | Gateway platform foundation | In progress; 12% weight |
| P2 | Identity, enrollment, authorization and recovery | In progress; 12% weight |
| P3â€“P9 | Remaining canonical stages | Names, weights and exit criteria are not yet present in the tracked baseline register. Do not infer them or calculate an overall completion percentage. |

The detailed evidence-based review is [the P0â€“P2 baseline audit](docs/ROADMAP_P0_P2_CURRENT_BASELINE_2026-11-15.md). The older Phase A/Phase B gate records remain historical project evidence; they are not a replacement for the canonical P0â€“P9 roadmap.

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

The dedicated Gateway validation workflow runs Go tests, go vet, and PostgreSQL-backed integration validation. The workflow was restored and merged in [PR #17](https://github.com/Vineeth2002/private-messenger/pull/17); its successful checks establish the configured Gateway test coverage, not full Android product behavior or production security.

A passing CI workflow is evidence only for the jobs and test paths it actually runs. A plain local Go test command does not prove PostgreSQL integration ran unless the required test database configuration is present. See the [Gateway validation workflow](.github/workflows/gateway-go-validation.yml) for the database-backed CI setup.

## Security and non-claims

Hosted-in-India does not mean all packets stay in India. APNs/FCM are external boundaries. Ed25519/X25519 hardware execution is not universally available. Push is not authenticated message content. Unit tests are not certification. Zeroization is limited by managed runtimes. PM-BI-X3DH-1 is proprietary and not Signal-interoperable. An independent cryptographic audit is required. See the [threat model](docs/phase0/02-threat-model.md) and [production release gate](docs/PRIVATE_MESSENGER_RELEASE_GATE.md).

## Validation

Use the [Windows setup guide](docs/LOCAL_SETUP_WINDOWS.md) for the supported local toolchain and commands. The native Rust test suite, Gateway Go tests, shared-vector parity checks, Android build/test jobs and identity-storage instrumentation cover separate components. They do not collectively prove the complete app-to-app messaging path.

For PostgreSQL-backed Gateway validation, follow the dedicated [Gateway CI workflow](.github/workflows/gateway-go-validation.yml), which provisions a disposable PostgreSQL database, applies migrations and runs the database-enabled Go test suite.

## Project records

- [P0â€“P2 implementation baseline audit](docs/ROADMAP_P0_P2_CURRENT_BASELINE_2026-11-15.md)
- [Production release gate](docs/PRIVATE_MESSENGER_RELEASE_GATE.md)
- [Phase B gate record](docs/PHASE_B_GATE.md)
- [Implementation notes](docs/IMPLEMENTATION_NOTES.md)
- [Local Windows setup](docs/LOCAL_SETUP_WINDOWS.md)