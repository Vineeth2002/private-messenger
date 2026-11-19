# Private Messenger — Canonical P0–P9 Roadmap and Android Submission Plan

**Baseline date:** 2026-11-19 (Asia/Kolkata)
**Repository baseline:** `main` at `1137b9b6e6c195ca46df65800cf008bce29ad47c`
**Decision:** Android-only controlled 1:1 alpha is the first release target. Production release remains blocked.

## 1. Why this document exists

The current tracked repository defines P0, P1 and P2, but does not contain an authoritative P0–P9 register. The frozen product specification still describes the larger product sequence: Android 1:1, iOS/calling/notifications, groups/multi-device, then future Language Lens and on-device AI.

This document normalizes that product sequence into the fixed P0–P9 project roadmap. P0–P2 retain the names and weights already recorded in the current baseline. P3–P9 are a newly formalized planning decomposition based on the frozen product specification, threat model, backend contract, and implementation found on `main`; they must not be represented as historical owner-approved phase names from a missing document.

The urgent submission target is deliberately smaller than the eventual product: **Android 1:1 text messaging in a controlled testing track**. iOS, groups, calls, media and AI are not launch blockers for that narrow alpha, but they remain later roadmap work. The alpha must be described honestly and must not be marketed as independently audited or suitable for sensitive conversations.

## 2. Canonical phase register

| Phase | Name | Status on 2026-11-19 | Dependency |
|---|---|---|---|
| P0 | Scope and evidence baseline | In progress | None |
| P1 | Gateway platform foundation | In progress; existing weight 12% | P0 |
| P2 | Identity, enrollment, authorization and recovery | In progress; existing weight 12% | P0, P1 |
| P3 | End-to-end cryptographic protocol and durable cryptographic state | In progress; substantial primitives exist, freeze/assurance remains open | P1, P2 |
| P4 | Android 1:1 messaging client | Controlled alpha exists; acceptance is incomplete | P1, P2, P3 |
| P5 | Reliable delivery, offline operation, background sync and notifications | In progress at foreground-only level; production behavior incomplete | P1, P2, P3, P4 |
| P6 | Encrypted media and content lifecycle | Cryptographic foundation exists; end-to-end product flow incomplete | P1, P3, P5 |
| P7 | Voice/video calling and cross-platform client readiness | Not started as a complete product capability | P1–P5; P3 security gates |
| P8 | Groups and multi-device conversations | Not started as a complete product capability | P2–P5, then P6/P7 as applicable |
| P9 | Production assurance, operations and release | Blocked | Applicable P1–P8 scope and all security/operations gates |

**Weights:** P1 and P2 retain their existing 12% weights. Do not calculate an overall completion percentage until the remaining weights are explicitly approved. P0 remains an evidence/governance phase with no product-completion weight.

### P0 — Scope and evidence baseline

**Purpose:** Ensure every product and security claim is tied to a defined scope and evidence.

Deliverables:
- Frozen V1 product scope and explicit first-release scope.
- Threat model, adversary assumptions, security invariants and non-claims.
- Canonical P0–P9 register, owners, dependencies, exit criteria and evidence links.
- Consistent README, roadmap, release gate, privacy disclosures and user-facing claims.
- Release evidence ledger distinguishing source existence, automated test evidence, physical-device evidence and independent assurance.

Exit criteria:
- The canonical register is in the repository and referenced by README and release gate.
- Stale documentation is corrected without upgrading partial implementation into a completion claim.
- First release is explicitly Android-only, 1:1, and alpha/beta-scoped.

**Current evidence:** frozen product specification and threat model exist; P0–P2 baseline exists; documentation still needs a current post-PR-#21 reconciliation and a full P0–P9 register.

### P1 — Gateway platform foundation

**Purpose:** Provide a reliable, authenticated, observable server-side delivery/control plane that never receives plaintext or client cryptographic secrets.

Deliverables:
- Production API contract replacing the alpha `/v1/demo/messages` surface.
- PostgreSQL schema/migrations, least-privilege roles and operational migration process.
- Authentication, device directory, encrypted-envelope routing, ACKs, rate limits and retention/expiration policy.
- Health/readiness, structured privacy-safe logs, metrics, alerts, backup/restore and deployment/rollback procedures.
- Hosting plan that meets the availability needed by the selected release track.

Exit criteria:
- API contract and authorization are reviewed and covered by integration tests.
- Retention and offline delivery policy are explicit and tested.
- Staging deployment survives restart, migration, backup restore and routine failures.

**Current evidence:** Go Gateway and PostgreSQL integration CI exist; PR #21 fixed canonical message timestamps and is merged; development Gateway is deployed on Render. The development deployment and current demo routes are not a production service.

### P2 — Identity, enrollment, authorization and recovery

**Purpose:** Ensure users can verify peers and authorize, revoke and recover devices under a frozen protocol.

Deliverables:
- Production identity and device-directory trust model, including client verification of Key Transparency and witness state.
- Frozen ordinary additional-device enrollment and separate catastrophic recovery protocol.
- Device authorization, revocation, epoch transition, signed-prekey lifecycle and replay/idempotency policy.
- Android integration and failure/restart/race/expiry testing.
- Rate limiting and trusted-proxy controls backed by shared state.

Exit criteria:
- Protocol and wire contract frozen after adversarial and independent review.
- Client and server integration proves correct state transitions and fail-closed behavior.
- Candidate enrollment/recovery routes are enabled only after the relevant gates pass.

**Current evidence:** candidate server-side enrollment/recovery components and extensive design reviews exist. Candidate routes are feature-gated and the design is not frozen for production. The current alpha uses manual fingerprint comparison, not the production witness trust model.

### P3 — End-to-end cryptographic protocol and durable cryptographic state

**Purpose:** Preserve the end-to-end security invariants across setup, messages, persistence, crashes and restoration.

Deliverables:
- Frozen PM-BI-X3DH-1 and Double Ratchet integration contracts, with precise identity/key binding.
- Durable session catalog, ratchet snapshots, message/outbox/inbox receipt semantics and authenticated storage records.
- Independent rollback/freshness protection; a generation value inside the same rollbackable local database is not sufficient.
- Crash/fault injection around every outbound/inbound persistence and ACK boundary.
- Fuzzing, parser-negative tests, key lifecycle verification and cross-language vector parity.

Exit criteria:
- Ratchet persistence and anti-rollback designs are frozen and independently reviewed.
- Crash, replay, stale snapshot, tamper, concurrency and ambiguous-network cases prove no unsafe key/state reuse.
- Android persistence implementation passes device-level restart/restore acceptance.

**Current evidence:** Rust X3DH, Double Ratchet, media AEAD, HPKE push primitives, strict snapshot/storage components and tests exist. Ratchet persistence and anti-rollback proposals remain open; the full lifecycle evidence is incomplete.

### P4 — Android 1:1 messaging client

**Purpose:** Ship the first usable Android client for verified 1:1 text messaging.

First-release scope:
- Android only.
- 1:1 text messaging only.
- Clear peer-verification and experimental-status disclosure.
- Durable local message/session/outbox/inbox state.
- Explicit send, submitted, delivered, failed and delivery-unknown states.
- No claims of support for iOS, groups, voice/video calls or encrypted media unless those features are separately implemented and tested.

Exit criteria for controlled testing:
- Signed release build/AAB builds reproducibly.
- Two physical Android devices complete first pairing, send, reply, ACK and app restart.
- Tests prove duplicate/replay handling, process death, network loss/recovery and no message/ratchet corruption.
- No known critical crash, data-loss or security defect remains in the declared alpha scope.
- Reviewers/testers receive documented setup instructions and clear warnings about unsupported behavior.

**Current evidence:** Android controlled messaging alpha exists; manual S23 FE/emulator exchanges succeeded in both directions. This is manual evidence only. Automated full two-client acceptance is missing.

### P5 — Reliable delivery, offline operation, background sync and notifications

**Purpose:** Make messages arrive reliably when a recipient is backgrounded or temporarily offline.

Deliverables:
- Stable message retention/expiry policy materially longer than the current observed 15-minute TTL, with explicit product decision.
- Idempotent submission and safe outbox reconciliation for ambiguous outcomes.
- Retry/backoff policy that never regenerates an envelope or advances the ratchet a second time for the same logical send.
- Android WorkManager/background synchronization and FCM wake-up integration.
- Push payloads contain no plaintext; push is only an untrusted wake-up hint.
- Notification privacy controls and delivery/read-state lifecycle.

Exit criteria:
- Offline recipients retrieve still-valid messages after reconnect.
- Repeated retries do not create duplicate messages or unsafe ratchet transitions.
- App backgrounding, process death, device reboot and notification loss do not break durable delivery.

**Current evidence:** foreground polling exists; message send/fetch/ACK is implemented. The current alpha is not production background or push delivery. The app Gradle file explicitly notes FCM has not yet been added.

### P6 — Encrypted media and content lifecycle

**Purpose:** Support encrypted photos, videos, documents and voice notes without giving the server plaintext or media keys.

Deliverables:
- Media upload/download control-plane contract and encrypted object storage.
- Chunk framing, key/nonce derivation, integrity verification and bounded parsing.
- Authenticated media-to-message binding, progress, retry/resume and deletion/retention behavior.
- Size limits, abuse controls and storage cost controls.

Exit criteria:
- Physical-device media send/receive, interrupted transfer, corruption, replay, deletion and storage-expiry tests pass.
- No server-side plaintext or media-key exposure is possible through the declared flow.

**Current evidence:** media AEAD and shared vectors exist in the native crypto foundation. This does not prove app-level media transfer or storage is complete.

### P7 — Voice/video calling and cross-platform client readiness

**Purpose:** Deliver secure calling and expand beyond the first Android text release.

Deliverables:
- Call signaling, connection establishment, media transport and end-to-end media protection.
- Call lifecycle, call history, missed-call handling and consent-visible local-only recording if included.
- iOS project, platform key protection, build/test pipeline and device validation.
- Push/call notification integration with privacy-safe payloads.

Exit criteria:
- Android physical-device call acceptance, network-change handling, permission and interruption tests pass.
- iOS builds and passes equivalent identity, storage and messaging security acceptance before claiming iOS support.

**Current evidence:** no completed call product was identified in the current Android alpha; no checked-in Xcode project is present.

### P8 — Groups and multi-device conversations

**Purpose:** Extend the 1:1 model to multiple user devices and group conversations without weakening identity, membership or forward-secrecy guarantees.

Deliverables:
- Multi-device key and authorization lifecycle integrated with P2.
- Group membership, invitation, removal, epoch/key rotation and state synchronization protocol.
- Group message fan-out, delivery state and replay/rollback protection.
- User-facing multi-device and group management flows.

Exit criteria:
- Membership changes, compromised/lost device removal, offline device catch-up and concurrent sends pass adversarial testing.
- Independent review covers group and multi-device protocol changes.

**Current evidence:** foundations and device lifecycle design work exist, but no complete group or multi-device messaging product was identified in the audited main baseline.

### P9 — Production assurance, operations and release

**Purpose:** Permit a production release only after the declared product scope is secure, supportable and operationally recoverable.

Deliverables:
- Independent cryptographic/protocol audit and remediation/retest evidence.
- Formal/symbolic protocol analysis, fuzzing and crash/concurrency campaigns.
- Supported-device matrix and release-signed, reproducible Android artifacts.
- Privacy policy, accurate Data safety declarations, account/data deletion flows where applicable, terms/contact/support and incident response.
- Production hosting, India data-residency analysis, secret rotation, least privilege, backups, restore drills, monitoring, alerts and rollback.
- Play Console policy declarations, store listing and reviewer access instructions.

Exit criteria:
- No unresolved critical/high security finding accepted without documented risk decision.
- All applicable release-gate evidence is linked and reviewed.
- Operational restore/rollback and incident exercises are demonstrated.
- Store declarations match actual app and SDK behavior.

**Current evidence:** production release gate remains BLOCKED. No independent cryptographic audit is complete.

## 3. Explicitly post-V1 / not a submission blocker

Language Lens, translation, Learning Mode, summaries, on-device AI and advanced AI features remain future work under `docs/phase0/05-ai-privacy.md`. They must not delay the narrow Android 1:1 closed-alpha submission, and must not be moved into V1 by implication.

## 4. Fastest honest submission path

### Track A — Internal testing

Use this first to distribute to a small, trusted group. It is not a public launch. The app must be labelled experimental, limited to the supported Android 1:1 text flow, and not recommended for sensitive conversations. Google Play's internal testing track has no 12-testers/14-day production-access prerequisite, but Play upload and policy requirements still apply where relevant.

Minimum technical gates:
1. Upgrade the Android toolchain and target API to meet current Play submission rules.
2. Produce a signed Android App Bundle (`.aab`) with a controlled upload key and monotonically increasing `versionCode`.
3. Validate installation/update and core flows on supported physical Android devices.
4. Verify the actual app-to-Gateway HTTPS/API path from Android, not only Windows or emulator ping.
5. Resolve or clearly bound message retention, offline behavior and delivery ambiguity for the testers.
6. Provide a working privacy-policy URL and in-app access to it; complete truthful Play declarations for the chosen track.

### Track B — Closed testing

Use a controlled tester cohort after internal testing is stable. If the Play developer account is a personal account created after 2023-11-13, Google currently requires at least 12 testers to remain opted in continuously for at least 14 days before applying for production access. Account type/creation date must be checked in Play Console; do not assume this requirement applies to every account type.

### Track C — Production

Do not request production access or make public security claims until the applicable P9 gates are complete. The current alpha is not independently audited and is not approved for sensitive conversations.

## 5. Immediate Google Play blockers found in the repository

The current `apps/android/app/build.gradle.kts` on `main` declares:

```kotlin
compileSdk = 34
minSdk = 26
targetSdk = 34
versionCode = 1
versionName = "0.0.1"
```

The root Android build pins Android Gradle Plugin `8.5.2` and Gradle wrapper `8.7`. As of 2026-11-19, Google Play requires **new mobile apps and app updates to target Android 16 / API 36 or higher** (the August 31, 2026 deadline has passed). The present targetSdk 34 is therefore a hard Play submission blocker.

The Android build must be migrated and tested against API 36. Android's published compatibility table lists AGP 8.9.1 as the minimum for API 36; AGP 8.9 requires Gradle 8.11.1. Keep JDK 17, but upgrade AGP/Gradle and install the API 36 SDK platform/build tools. Do not simply change `targetSdk` to 36 while leaving the old build toolchain in place.

Other repository observations:
- Current application ID: `org.sovereign.pm`.
- Current release version is `0.0.1` / code `1`.
- The app manifest currently declares `INTERNET` only; actual runtime/network data collection still needs a complete source and SDK inventory for Play declarations.
- The app Gradle file comments that FCM is not yet added.
- The audited app Gradle file has no explicit release signing configuration. Configure and protect an upload key / Play App Signing workflow before publishing an AAB.
- No completed public privacy-policy package or Play Data safety declaration was identified in the tracked documentation inspected for this plan. A threat model is not a substitute for a user-facing privacy policy.
- If users can create accounts, check and implement the required in-app and web account-deletion request path and delete the associated data as required by Play policy.

## 6. Order of execution from 2026-11-19

1. Put this P0–P9 register into the repository and reconcile README + `docs/PRIVATE_MESSENGER_RELEASE_GATE.md` to reference it.
2. Create a clean branch/worktree from current `origin/main`; keep all existing working-tree changes untouched.
3. Upgrade Android build tooling to support API 36; build and test the API 36 release candidate.
4. Complete automated and physical two-device acceptance for Android 1:1 text: pairing, send, reply, ACK, duplicate/replay, offline/reconnect, app kill/restart and outbox reconciliation.
5. Fix alpha reliability defects that invalidate testing: ambiguous send handling, idempotent retries, message retention/expiry policy and delivery state accuracy.
6. Prepare release signing, privacy policy, account/data deletion (if applicable), Data safety inventory, content rating, target audience, ads declaration and reviewer instructions.
7. Upload to Play internal testing first; fix tester findings; then move to closed testing if the developer account requires it.
8. Keep P5 background delivery and P9 production assurance as separate gates. Do not call the app production-ready because it passed an internal/closed test.

## 7. Authority and source references

Repository sources:
- `docs/phase0/01-product-spec.md` — frozen V1 and future product scope.
- `docs/phase0/02-threat-model.md` — assets, adversaries, invariants and non-claims.
- `docs/phase0/03-crypto-architecture.md` — cryptographic architecture.
- `docs/phase0/06-backend-contract.md` — backend control-plane responsibilities.
- `docs/phase0/05-ai-privacy.md` — AI explicitly future/not in V1.
- `docs/ROADMAP_P0_P2_CURRENT_BASELINE_2026-11-15.md` — current P0–P2 baseline.
- `docs/PRIVATE_MESSENGER_RELEASE_GATE.md` — production remains blocked.
- `apps/android/app/build.gradle.kts` — current Android build/SDK/version configuration.
- `apps/android/build.gradle.kts` — current AGP pin.
- `apps/android/gradle/wrapper/gradle-wrapper.properties` — current Gradle wrapper.
- `apps/android/app/src/main/AndroidManifest.xml` — current manifest permissions/app declaration.

Official Play/Android references (checked 2026-11-19):
- Target API requirements: https://support.google.com/googleplay/android-developer/answer/11926878
- New personal developer account testing requirements: https://support.google.com/googleplay/android-developer/answer/14151465
- Prepare app for review: https://support.google.com/googleplay/android-developer/answer/9859455
- Data safety form: https://support.google.com/googleplay/android-developer/answer/10787469
- Android Gradle Plugin compatibility: https://developer.android.com/build/releases/about-agp
- AGP 8.13 release notes / API 36.1 compatibility: https://developer.android.com/build/releases/agp-8-13-0-release-notes

---

**Release rule:** internal/closed testing is a controlled learning stage, not a waiver of security responsibilities. The current project may pursue a narrowly scoped Android 1:1 alpha track once its build, device acceptance and policy disclosures are ready. Production remains blocked until P9 evidence is complete.
