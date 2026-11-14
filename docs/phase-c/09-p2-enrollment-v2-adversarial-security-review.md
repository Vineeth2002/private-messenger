# P2 Enrollment V2 — Adversarial Architecture Review

**Status:** Internal adversarial review — NOT AN INDEPENDENT AUDIT; NOT FROZEN
**Review baseline:** Phase C merge `c741c4e5718ce018517a72e8137b2d22058b685b`; P2 reconciliation commit `2e45fcb1e9390536fc639844417800e917e201be`
**Applies to:** `docs/phase-c/05-p2-enrollment-recovery-cto-decision-baseline.md`, `06-ordinary-device-enrollment-v2-wire-contract-proposal.md`, `07-ordinary-device-enrollment-v2-review-refinements.md`, and `08-p2-enrollment-v2-policy-reconciliation.md`
**Purpose:** Adversarially assess the proposed enrollment design against the current source tree, identify contradictions and missing trust bindings, and set a rational freeze gate.

> This is an internal design review produced by an AI assistant, not an independent third-party security audit, cryptographic proof, or deployment assessment. It is a review artifact only. It changes no application code, database schema, protocol implementation, or route configuration.

## 1. Executive disposition

**Disposition: REVISE BEFORE FREEZE. Do not implement V2 yet.**

The P2 policy direction is sound as a minimum baseline: ordinary device addition should require approval by an already-active device and independent target-device DSK proof; catastrophic recovery must remain a separate delayed flow; PostgreSQL remains the Gateway's current-state authority; and the client must retry exact protocol bytes after ambiguous outcomes.

The reconciliation document usefully closes several omissions, but four material design conditions remain:

1. The proposed 40-bit SAS is derived from the target descriptor only. It confirms that both screens refer to the same target descriptor; it does not bind the expected approving device identity or the complete two-device pairing context.
2. The V2 threat model explicitly trusts the Gateway and its database. Existing Key Transparency V1 work is relevant, but its 2-of-3 STH witness check is not account-level lifecycle authorization and must not be presented as solving malicious-Gateway enrollment attacks.
3. The current native identity record has no SPK private key, SPK metadata, or rotation state. The existing `SignedPrekeyV1` module signs/parses public objects; it is not a complete private-key lifecycle.
4. The proposed V2 transaction/lock sequence is plausible but remains unimplemented and unproven under concurrent approval, revocation, recovery, retries, and lost acknowledgements.

The one-active-device approval rule can remain the minimum ordinary-enrollment policy only with an explicit endpoint-compromise limitation. The current Android user-authentication prompt is an application-side intent gate, not hardware-enforced per-use DSK authorization.

No item below is evidence that an exploitable vulnerability exists in production. V2 has not been implemented or exposed. These are protocol-design gaps and threat-model decisions.

## 2. Source facts verified

Review was performed against the Phase C commit listed above. Relevant source facts:

- `native/crypto-core/src/signed_prekey_v1.rs` defines a candidate seven-field `SignedPrekeyV1` public object, a DSK signature transcript, parser, verifier, and signer. It validates the public X25519 key and bounds `SPK_ID` to `u32`, but the parser currently accepts `SPK_ID = 0`. It does not generate, retain, rotate, or retrieve an SPK private key.
- `native/crypto-core/src/ffi.rs` defines `AccountContext` with DSK and DDHK seeds and a transient enrollment binding. Its sealed identity plaintext is fixed at 96 bytes: AccountID (16), DeviceID (16), DSK seed (32), and DDHK seed (32). No SPK private key or SPK counter is in that record. The same file has a `sign_transparency_leaf` operation, but that is not an SPK key lifecycle.
- `apps/android/.../PlatformKeyProtection.kt` wraps the local Storage DEK with Android Keystore AES-GCM. It does not set `setUserAuthenticationRequired`; it does not make each native DSK signature require a hardware-enforced authentication event.
- `services/gateway/internal/devices/directory.go` reads `spk_id`, `spk_pub`, and `signature`. Its current `decodeSignedPrekey` checks device ID and field lengths but does not enforce the candidate V1 `u32` SPK_ID range, perform the SignedPrekeyV1 signature verification, or prove that the returned SPK is the current transparency-leaf SPK.
- `services/gateway/internal/http/device_http.go` exposes signed-prekey directory data as a four-field CBOR record: DeviceID, SPK_ID, SPK public key, and signature. AccountID and epoch are obtained from a separate device-directory record and must be bound by the client during verification.
- `services/gateway/migrations/0001_init.sql` defines `signed_prekeys.spk_id` as PostgreSQL `bigint`, with a `(device_id, spk_id)` primary key and length checks on SPK public key/signature. It does not itself constrain SPK_ID to the protocol's `u32` range. The inspected migrations through `0012` do not add the missing SPK_ID range check.
- `services/gateway/internal/deviceauth/postgres_authenticator.go` uses account-first row locking: `accounts`, `authorization_accounts`, `authorization_devices`, then `devices`. The current authorization and recovery lifecycle code also begins by locking the account and authorization-account rows.
- Key Transparency V1 is not a blank slate. The repository contains `docs/phase0/10-key-transparency-v1-frozen.md`, Rust `transparency_v1.rs`, Go KT verification/publication services, and a device-bound publication service. The frozen KT spec explicitly says KT does **not** prove account-level authorization. Its witness policy is 2-of-3. It is distinct from the 3-of-3 ratchet lifecycle/checkpoint witness proposal.

These facts do not establish production readiness or a complete client-side transparency integration.

## 3. Finding A — Pairwise authentication and SAS

**Severity: High design gap. Disposition: Revise.**

### What is currently proposed

Document 08 derives a 40-bit string from:

`SHA-256(ASCII("PM-V2-ENROLLMENT-SAS-v1") || descriptor_digest)`

The descriptor includes the target identity and, after the field-8 refinement, the digest of the exact initial SignedPrekeyV1 bytes. Both the target and the existing device can therefore calculate the same string for the exact target descriptor.

### What this does and does not authenticate

It authenticates that the two screens are displaying the same target descriptor. It does **not**, by itself, authenticate which existing device is approving that descriptor. The approval object has an ApprovingDeviceID, but the proposed SAS input contains no approver DeviceID, approver DSK, or two-party pairing nonce. The target still obtains the approver DSK metadata from the Gateway response and must compare it with an independently expected approver identity. That expectation needs a precise pairing protocol; it cannot be left as an informal “pairing context”.

The current 40-bit value is not automatically broken. For one fixed target SAS, a substitution attacker needs a matching preimage for that specific value; do not incorrectly apply the generic birthday bound of approximately 2^20 to that one-to-one case. But the current flow has not specified a commitment/reveal handshake that constrains the attacker to a single precommitted attempt, nor does the short string cover both endpoint identities. The 40-bit choice should not be frozen on the basis of ZRTP's shorter SAS examples: RFC 6189 explains that its short SAS is viable because a DH hash-commitment step forces the attacker to commit before learning the peer's public value. That commitment property is part of the protocol, not a property of base32 itself. See [RFC 6189, Section 4.4.1.1](https://www.rfc-editor.org/rfc/rfc6189.html#section-4.4.1.1) and [Section 7](https://www.rfc-editor.org/rfc/rfc6189.html#section-7).

### Required correction

Define a canonical, two-party `PairingContextV2` before the approval signature is created. At minimum it should bind:

- protocol/version and purpose domain;
- AccountID and proposed account epoch;
- exact target descriptor digest, including the initial SPK digest;
- target DeviceID and target DSK/DDHK fingerprints;
- expected approving DeviceID and approving DSK fingerprint;
- fresh independent target and approver nonces;
- the pairing transport/session identifier and the explicit expected Gateway origin (displayed separately if not included cryptographically).

Both endpoints must obtain the counterpart's identity through the explicit handoff, compute the same canonical context, and display a SAS derived from that context. The approval must bind the pairing-context digest as well as the descriptor digest. The target must reject a returned approval whose DeviceID/DSK does not match the expected approver identity in that context.

**Recommended display candidate:** 60 bits, encoded as 12 Crockford Base32 symbols grouped `XXXX-XXXX-XXXX`. This is a review recommendation, not a frozen constant. Generate cross-language test vectors for the exact transcript and encoding. If a shorter value is desired for UX, first define and analyze the commitment/reveal ordering and online retry budget; do not choose length by intuition.

A mismatch, absent confirmation, stale pairing context, changed descriptor, or expired approval attempt must abort. QR scanning alone is not user confirmation. The app must not treat the short code as a secret or as a substitute for DSK signatures.

## 4. Finding B — Gateway trust and Key Transparency integration

**Severity: Critical threat-model decision. Disposition: Explicitly choose the trust model before freeze.**

### Current V2 trust assumption

The V2 design relies on the configured HTTPS Gateway and its PostgreSQL state as the authority for approver status, accepted approval bytes, account epoch, challenge state, and activation. The target verifies the approval signature using approver DSK metadata returned by that same Gateway response. This is coherent only if the Gateway/database/key-publication authority is inside the trusted computing base.

A fully compromised Gateway can potentially substitute authorization metadata or fabricate database state and return an approval object under a key it controls. The current proposal explicitly does not claim resistance to a malicious/compromised Gateway. That exclusion must remain prominent in product/security claims.

### Existing transparency work — relevant but not sufficient

The repository already contains a frozen Key Transparency V1 specification and partial Rust/Go components:

- `TransparencyLeafV1` commits AccountID, epoch, DeviceID, DSK, DDHK, `Cert_dh`, current SPK public key, PushPK, and a DSK signature.
- The frozen KT V1 witness policy is 2-of-3 for the same signed tree head.
- `DeviceBoundTransparencyPublicationService` checks a leaf against persisted device state and delegates to the authorization validator; `PostgresAuthorizer.ValidateLeaf` checks current account/device authorization rows.

However, the frozen KT specification explicitly states that KT does **not** prove account-level device authorization. KT witnesses attest agreement on the STH; that is not equivalent to independent verification of the complete P2 enrollment/approval lifecycle. The separate lifecycle-to-ratchet trust-boundary proposal uses typed lifecycle evidence and three independent ratchet witnesses, but it remains a proposal and is not a deployed V2 authority path.

Therefore:

- Do not invent a second transparency tree for V2.
- Do not claim that the existing 2-of-3 KT witness verifier alone prevents a malicious Gateway from adding a device.
- Do not confuse KT's 2-of-3 current-state/history quorum with the distinct 3-of-3 ratchet checkpoint/lifecycle witness requirement.
- If V2 assumes a trusted Gateway, state that clearly and keep server compromise out of the protected threat model.
- If protection against a malicious Gateway is required, define an explicit bridge from V2 approval/PoP and immutable lifecycle events to the existing KT V1 identity state and a separately reviewed lifecycle-witness authorization projection. This is a larger freeze gate; it is not solved by adding a public-key lookup to the current directory.

**CTO recommendation:** allow a trusted-Gateway-only V2 proposal to remain the minimum P2 design, but do not advertise device-enrollment protection against a malicious Gateway. Before any high-assurance/production claim, integrate account-level lifecycle authorization evidence with the existing transparency architecture and complete client-side proof/high-water verification. An independent security reviewer must ratify whether the Gateway remains an acceptable trust anchor.

## 5. Finding C — Signed-prekey lifecycle is not yet implementable from current storage

**Severity: Critical implementation blocker. Disposition: Revise the lifecycle contract before code.**

Document 07 and Document 08 correctly require one initial SignedPrekeyV1 object and its atomic persistence during activation. The design still needs a complete private-key and publication lifecycle.

### Current code mismatch

- The sealed identity record is fixed at 96 bytes and stores only AccountID, DeviceID, DSK seed, and DDHK seed. Its header is `PMIDSTOR\x01`. It has no SPK private key, SPK ID counter, rotation set, or retirement metadata.
- `AccountContext` has no SPK key collection. `sign_signed_prekey_v1` accepts a caller-provided SPK public key and signs it with the DSK; it does not generate or store the matching X25519 private key.
- The Gateway directory's current decoder does not validate SPK_ID against `u32`, verify the signed-prekey signature, or ensure that the bundle matches the current transparency-leaf SPK.
- The SQL column is `bigint`; a database constraint is needed to enforce the selected protocol range. The Rust parser currently accepts SPK_ID zero, so the contract must explicitly decide whether zero remains valid or is reserved. Do not quietly use a nonzero counter in the design while leaving a parser that accepts zero and a database column with no range constraint.

### Required lifecycle decisions

1. **Versioned native store:** define a new authenticated identity-store record version. Preserve the current v1 96-byte record restore path; do not reinterpret old bytes as a larger record. Define atomic migration/rollback behavior and zeroization.
2. **Generation:** generate the X25519 SPK keypair inside Rust/native code using the OS CSPRNG. Bind private key, public key, AccountID, DeviceID, epoch, and SPK_ID in the native-owned store. The DSK signs the exact candidate SignedPrekeyV1 object.
3. **Counter:** ratify the exact SPK_ID domain, including whether zero is legal. Store the monotonic counter durably and atomically; prohibit reuse after retirement and define overflow behavior.
4. **X3DH use:** only native code may look up and use an SPK private key. No private scalar may cross UniFFI/Kotlin, enter the Gateway DB, or enter an enrollment journal/QR/backup export.
5. **Rotation and retention:** define rotation cadence, public-key expiry, overlap/grace, local private-key retention for clients with cached bundles, deletion, app restore and secure erasure. Do not delete the old private key merely because a new public SPK was published.
6. **Gateway verifier:** implement Go SignedPrekeyV1 parser/verifier and cross-language vectors before V2 activation accepts it. Add PostgreSQL `CHECK` constraints for the chosen ID range and tests against the actual runtime role.
7. **Directory binding:** the returned SPK object must be verified against AccountID/epoch/DeviceID and target DSK from the authoritative device record. Its SPK public key must match the current committed KT V1 leaf SPK public key when the client claims transparency-verified state. The signed object binds SPK_ID to SPK_pub; KT V1's leaf commits the SPK public key but not SPK_ID.
8. **Readiness:** define an explicit `ACTIVATED_NOT_MESSAGING_READY` or equivalent state. The device must not be advertised as messaging-ready until the initial SPK is committed, verified, published consistently, and an actual X3DH initiation/response test succeeds. If KT verification is part of the product path, require the specified KT client state/quorum before claiming `VERIFIED`.

No OPK support is implied. Keep OPKs out until registration, publication, atomic single-use consumption, replenishment and replay behavior are separately designed and tested.

## 6. Finding D — Transaction locking and retry semantics

**Severity: High correctness gate. Disposition: Conditionally accept the proposed lock-order shape; require proof.**

### Lock-order assessment

The existing request authenticator locks `accounts` → `authorization_accounts` → `authorization_devices` → `devices`. Current revocation and recovery operations also begin by locking the account and authorization-account rows. Extending this prefix with the approver/target device context, enrollment-intent row, and challenge rows is a reasonable candidate order.

This is not yet proof of deadlock freedom. V2 does not exist in code, and its transaction graph must be tested against request authentication, revocation, recovery begin/abort/finalize, and concurrent activation. Every path that changes account/device authorization must take the account serialization lock first. Do not allow a V2 path to lock an intent or challenge first and then acquire account/device locks.

### Retry detail missing from the written contract

PM-Device-V1 consumes its HTTP request nonce in the authentication transaction. That authentication transaction commits before the application approval handler begins its separate authorization/intent transaction. Consequently, after a lost response or downstream failure, a retried HTTP request must carry a **fresh outer PM-Device-V1 timestamp/nonce/signature**, while preserving the exact inner `DeviceEnrollmentApprovalV2` bytes and challenge binding. The inner approval should not be regenerated merely to refresh HTTP authentication.

Specify this explicitly, and test:

- exact inner approval bytes retried with a fresh PM-Device-V1 request proof return the same accepted intent;
- changed inner approval/descriptor/SPK bytes for the same EnrollmentID fail with conflict;
- approval challenge replacement invalidates old challenges atomically;
- target challenge replacement is idempotent/recoverable after lost response and cannot create unbounded replacement traffic;
- exact activation retry after a committed/lost response returns success only from mutually consistent durable evidence;
- no active device or messaging-ready state is visible after a partial transaction;
- concurrent revoke/recovery/activation tests use the real PostgreSQL implementation and confirm the chosen global lock order.

The candidate order should be treated as unapproved until those tests and a lock-graph review pass.

## 7. Finding E — One approver and user-presence claims

**Severity: High threat-model limitation. Disposition: Accept one approver only as the minimum policy, with explicit scope.**

One active device DSK approval is a simple, testable baseline. It also means compromise of any one currently active device, or compromise of the app process capable of invoking that device's DSK, can authorize an attacker-controlled additional device. The current design does not prevent that case.

The existing device must show the proposed target identity and require deliberate user action plus a fresh Android system-authentication prompt. However, the current DSK is a Rust-owned seed in the sealed identity record; the Android Keystore currently wraps the Storage DEK only. This is not hardware-enforced per-use authorization of the DSK.

Android Keystore supports key-use authorizations and can require user authentication for a key operation, including per-operation authorization. Those capabilities must be configured on the key when it is generated/imported; they are not provided just by showing a `BiometricPrompt`. See [Android Keystore key-use authorizations](https://developer.android.com/privacy-and-security/keystore#key-use-authorizations) and [user authentication for key use](https://developer.android.com/privacy-and-security/keystore#require-user-authentication-for-key-use).

Decision:

- Keep one active-device approver as the **minimum** ordinary-enrollment rule only if the product explicitly excludes compromise of an already-authorized endpoint from this protection claim.
- Do not describe a DSK signature plus application-side prompt as hardware-enforced user presence.
- A multi-approver policy (for example 2-of-N where enough active devices exist) is a separate account policy and UX design. Do not imply it exists in the V2 wire contract unless the account policy, approval collection state, timeout, cancellation, partial approval, and recovery interactions are all specified.
- If per-use hardware-enforced authorization is required, design a dedicated approval-key/custody mechanism and its binding to the device DSK. Do not retrofit a generic DSK signing FFI or claim that the current Storage DEK wrapper solves it.

## 8. DEC disposition

| Item | Review disposition | Conditions |
|---|---|---|
| DEC-01 — ordinary approval vs recovery | **Accept with limitation** | One active device is the minimum rule; endpoint compromise remains a threat-model exclusion. |
| DEC-02 — PostgreSQL epoch authority | **Accept** | Continue to treat client epoch and unsigned directory fields as proposals, never authority. |
| DEC-03 — challenge/Gateway trust | **Revise** | Explicitly choose trusted-Gateway-only V2 or add a separately reviewed lifecycle/transparency authorization bridge. |
| DEC-04 — durable operation journal | **Accept with clarification** | Specify fresh outer PM-Device-V1 proof on retries while preserving exact inner approval bytes. |
| DEC-05 — 48-hour recovery separation | **Accept** | Keep recovery state machine, target binding and account unlock separate from ordinary V2. |
| DEC-06 — public errors | **Open** | Finalize exact status/code, expiry disclosure, enumeration and retry semantics before API freeze. |
| DEC-07 — shared rate limiting/ingress | **Accept** | Prove cross-instance quotas and fail-closed outage behavior. |
| DEC-08 — intent/challenge immutability | **Accept with tests** | Enforce immutable fields and runtime-role privileges in PostgreSQL, not only in application code. |
| 40-bit descriptor-only SAS | **Revise** | Use a pairwise context binding both endpoint identities and fresh nonces; candidate 60-bit value. |
| Initial SPK object field 8 | **Accept in principle** | Require exact raw-byte transport, Go verification, database range checks and native private-key lifecycle. |
| SPK private-key lifecycle | **Open blocker** | Versioned native-store format, generation, lookup, rotation/retention and restore semantics. |
| Candidate transaction lock order | **Conditionally accept** | Prove same-account serialization and run real PostgreSQL races/deadlock tests. |
| One approver | **Accept as minimum only** | Document single-endpoint compromise risk; multi-approver is a separate policy. |

## 9. Freeze-gate order

Do not begin implementation by creating endpoints or migrations. Close the design decisions in this order:

1. **Threat model:** ratify whether the Gateway/database is trusted for V2 enrollment or whether V2 must be integrated with lifecycle authorization evidence and the existing Key Transparency V1 architecture.
2. **Pairwise handoff/SAS:** specify the canonical two-party context, both device identities, nonces, signature binding, 60-bit candidate encoding, human comparison and abort behavior.
3. **SPK wire/storage:** decide SPK_ID zero/range policy; define Go verifier/vectors; specify a versioned native identity-store record, durable counter and private-key retention/rotation.
4. **KT/readiness binding:** define how initial SPK object, current SPK public key in the KT leaf, device authorization and messaging-ready status are reconciled. Do not confuse KT 2-of-3 with lifecycle 3-of-3 witnesses.
5. **Transaction/retry:** finalize per-endpoint locks, fresh transport nonce rules, intent/challenge idempotency, cancellation, expiry, and exact retry behavior.
6. **Approver assurance:** ratify one-approver threat scope; decide whether an optional multi-approver profile or hardware-authenticated approval key is required.
7. **Independent review:** submit the reconciled final wire maps, transcript vectors, threat model, transaction graph, native key custody and failure/recovery model to a security reviewer who did not author the design. Record each finding and disposition.

Only after these gates close may the object maps/transcripts be frozen. A documentation merge or green CI run is not a security review.

## 10. Required adversarial tests

### Pairing and SAS

- Substitute target descriptor, SPK object, target DeviceID, DSK, DDHK, epoch, approver DeviceID and approver DSK independently; both endpoints must not accept mismatching context.
- Swap the QR/local handoff between two concurrent enrollment attempts; context and SAS must fail to match.
- Replay old pairing context or nonces; approval must be rejected.
- Validate exact SAS bits, Base32 extraction, endianness, grouping and vectors identically in Rust, Go and an independent reference.
- Verify a display mismatch always aborts and no notification/QR scan can invoke approval signing automatically.

### Gateway and transparency

- Return a fake approver DSK/approval, stale device leaf, stale STH, mismatching SPK leaf, and conflicting STH/witness statements; clients must follow the declared trust model and fail closed where required.
- Prove that the selected lifecycle/KT path authenticates account-level device authorization, not merely key possession or an STH digest.
- Verify the client high-water state cannot move backwards; validate witness registry bootstrap and witness independence before making quorum claims.

### SPK custody and X3DH

- Restore legacy v1 identity records and v2 records; corrupted, incomplete or downgraded records fail closed.
- Crash between SPK generation, native persistence, signed-object creation, intent creation, Gateway insert and KT publication; no private/public mismatch becomes usable.
- Exercise SPK_ID lower/upper bounds, reuse, overflow, negative DB row, values above `u32`, malformed CBOR, invalid signature, low-order SPK key and substituted account/device/epoch.
- Verify native X3DH initiation/response uses the corresponding SPK private key, including a cached old SPK during the approved overlap window.
- Demonstrate that deleting an old SPK private key cannot break a still-valid cached bundle; define and test the retention cutoff.
- Verify directory SPK object matches the active device record and current KT leaf SPK public key.

### Transactions and recovery

- Concurrent V2 approval, challenge replacement, activation, revocation, recovery begin, recovery abort and recovery finalization for one account.
- Lost HTTP response after PM-Device-V1 nonce consumption, accepted approval, target challenge issuance and activation commit.
- Fresh outer request proof with byte-identical inner approval; reused outer nonce rejected; changed inner approval fails conflict.
- Database transaction rollback leaves no partial device, authorization row, SPK row, challenge consumption, or messaging-ready publication.
- Runtime Gateway DB role cannot mutate intent/approval/SPK evidence or challenge binding fields outside the permitted lifecycle transitions.

## 11. Sources inspected

### Repository sources at Phase C commit `c741c4e5718ce018517a72e8137b2d22058b685b`

- `native/crypto-core/src/signed_prekey_v1.rs`
- `native/crypto-core/src/ffi.rs`
- `apps/android/app/src/main/java/org/sovereign/pm/security/PlatformKeyProtection.kt`
- `apps/android/app/src/main/java/org/sovereign/pm/crypto/NativeDeviceEnrollmentSession.kt`
- `services/gateway/internal/devices/directory.go`
- `services/gateway/internal/http/device_http.go`
- `services/gateway/internal/authorization/enrollment_activation_candidate.go`
- `services/gateway/internal/authorization/postgres.go`
- `services/gateway/internal/authorization/recovery_lifecycle.go`
- `services/gateway/internal/deviceauth/postgres_authenticator.go`
- `services/gateway/internal/kt/device_publication.go`
- `services/gateway/internal/kt/device_state.go`
- `services/gateway/internal/kt/witness_service.go`
- `services/gateway/migrations/0001_init.sql` through `0012_typed_recovery_finalization_event.sql`
- `docs/phase0/10-key-transparency-v1-frozen.md`
- `docs/phase-c/02-lifecycle-to-ratchet-trust-boundary-v1.md`

### External references

- IETF RFC 6189, ZRTP, Sections 4.4.1.1 and 7: [https://www.rfc-editor.org/rfc/rfc6189.html](https://www.rfc-editor.org/rfc/rfc6189.html). Its shorter SAS examples rely on a specific DH hash-commitment ordering; they are not a generic argument that a descriptor-hash SAS of any length is sufficient.
- Android Developers, Android Keystore system — key-use authorization and user-authentication requirements: [https://developer.android.com/privacy-and-security/keystore](https://developer.android.com/privacy-and-security/keystore).

**Final disposition:** Internal adversarial review complete for the current design snapshot. V2 remains NOT FROZEN. No source code, migrations, candidate routes, production configuration, or ratchet persistence are authorized by this review. Independent third-party security review remains required.
