# Ordinary Device Enrollment V2 — Wire Contract Proposal

**Status:** Candidate protocol proposal — NOT FROZEN
**Target branch:** `phase-c/ratchet-persistence-design`
**Review point:** 2026-11-05
**Scope:** Ordinary additional-device enrollment for an already-active account.
**Non-goals:** Catastrophic account recovery, epoch transition, ratchet persistence, production route enablement, or a claim of production readiness.

## 1. Executive proposal

Define a new, separately versioned ordinary-enrollment protocol. An already-authorized, active device explicitly approves the exact public identity of a new device. The new device separately proves possession of its own Device Signing Key (DSK). The Gateway checks both proofs against authoritative PostgreSQL account/device state and atomically activates the target device.

The protocol has two independent signatures:

1. **Approver authorization:** the existing device's DSK signs an approval bound to the exact canonical target descriptor and a fresh Gateway-issued approval challenge.
2. **Target proof of possession (PoP):** the target device's DSK signs a second fresh Gateway-issued challenge bound to the same descriptor and the accepted approval.

An outer `PM-Device-V1` authenticated HTTP request is also required when an existing device requests or submits an approval. That transport/request-auth proof is not a substitute for the explicit approval object: it authenticates the HTTP caller and consumes a request nonce; the approval object is durable, auditable consent to one exact enrollment.

The current recovery-key-signed `DeviceEnrollmentAuthorizationV1` remains unchanged for compatibility and for the separate catastrophic-recovery flow. It must not be silently repurposed as ordinary existing-device approval.

This document proposes wire structures and state transitions. It does not authorize implementation or route enablement. All objects and endpoint details remain candidates until the review gates in Section 13 close.

## 2. Repository facts used as design constraints

The Phase C branch at review point `6677df50051d1a89f2260060bc4758b64629392c` contains:

- `deviceauth` PM-Device-V1 request authentication. The signed request binds account ID, device ID, epoch, timestamp, nonce, HTTP method, request target, and SHA-256 of the exact raw body. PostgreSQL authentication checks active account/device state, key equality, current epoch and nonce uniqueness in one transaction.
- `deviceRequestAuthMiddleware`, which verifies the exact body bytes before passing those same bytes to the downstream handler.
- The authenticator's lock order: `accounts`, `authorization_accounts`, `authorization_devices`, then `devices`.
- A read-only device directory. Enrollment/revocation writes are intentionally not exposed through those routes. The directory's returned records are not a signed, rollback-resistant authorization statement.
- `DeviceEnrollmentAuthorizationV1`, currently a recovery-key-signed seven-field canonical CBOR object, and `DeviceEnrollmentPoPV1`, currently a separate eight-field canonical CBOR proof.
- Ordinary candidate enrollment endpoints that currently rely on a recovery-key-signed certificate and target DSK PoP. They do not contain an existing-device approval signature and must remain disabled.
- Candidate activation code that inserts `devices`, `device_certificates`, `authorization_devices`, and an `ENROLL` authorization event in one transaction. It does not currently persist initial signed prekeys.
- A candidate challenge lifecycle guard that protects timestamps and one-way consumption, but does not independently compare all challenge identity/binding columns against their old values on update.
- A per-process in-memory limiter on candidate enrollment routes. The PostgreSQL HMAC rate limiter is currently wired to the separate recovery API, not candidate enrollment.

These source facts constrain the design. They do not prove end-to-end enrollment is integrated or production-ready.

## 3. Threat model and authorization rule

### 3.1 Security objective

Prevent a party who only possesses the account recovery credential, an unauthenticated caller, or a copied device-directory response from immediately adding a device to an active account.

### 3.2 Ordinary-enrollment rule

- The account must be `ACTIVE` with one current authoritative epoch and no pending catastrophic-recovery request.
- One currently active, non-revoked device in that exact epoch must explicitly approve the exact target descriptor. This is a proposed minimum policy; a multi-approver threshold is not part of this V2 baseline.
- The approving device must authenticate its HTTP request using PM-Device-V1 and produce the separate V2 approval signature with the same DSK.
- The target device must prove possession of the DSK named in the descriptor using a fresh one-use challenge.
- The Gateway must re-check account and approver status/epoch at approval acceptance and again in the final activation transaction. Approval does not survive a conflicting epoch transition or approver revocation.
- A recovery mnemonic or recovery private key is not used for ordinary additional-device enrollment.

### 3.3 Compromise assumptions and limitations

This policy resists recovery-credential-only compromise. It does not protect an account if an attacker controls an already-authorized active device and can obtain user approval or invoke the device's signing capability. Android user-presence/biometric gating, trusted display, device malware resistance, and approval UX require separate review. The protocol must not claim that a DSK signature alone proves informed human consent.

If every existing device is lost or unavailable, the user must use the separately specified 48-hour catastrophic recovery process. Do not add a recovery-key bypass to ordinary enrollment.

## 4. Canonical encoding and primitive rules

All signed objects below use PM-CBOR-2026, following the repository's deterministic encoding rules:

- Deterministic encoding based on RFC 8949 Core Deterministic Encoding; map keys sorted by bytewise lexicographic comparison of their deterministic encodings (not length-first ordering).
- Minimal integer and length encodings only; definite-length strings/maps; no floats; no duplicate keys; no trailing bytes.
- Exact schema field set for signed objects. Unknown or duplicate fields are rejected.
- Exact original canonical bytes are validated; parsers must not decode and re-encode untrusted input to repair it.
- Identifiers are fixed-length byte strings. `AccountID`, `DeviceID`, `EnrollmentID`, and challenge IDs must be nonzero.
- Epoch is unsigned and constrained to `1..=2^32-1`; every signed/DB boundary performs checked conversion.
- Ed25519 signatures are 64 bytes. DSK public keys are 32 bytes. X25519 DDHK public keys are 32 bytes and must pass the same unusable/low-order-key validation in Rust and Go.
- All transcript constructions use direct concatenation of the ASCII domain bytes and exact canonical core bytes, with no implicit separator. The domain text below is itself versioned and exact.

Every object below is a **proposal**. Do not add these constants to implementation until the document has been reviewed and shared vectors are agreed.

## 5. Proposed V2 wire objects

### 5.1 `DeviceEnrollmentDescriptorV2`

The descriptor is the target device's unsigned, canonical public identity proposal. It is not authorization by itself.

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Object version |
| 2 | `bstr(16)` nonzero | AccountID |
| 3 | uint in `1..=2^32-1` | Proposed current account epoch |
| 4 | `bstr(16)` nonzero | Target DeviceID |
| 5 | `bstr(32)` | Target Ed25519 DSK public key |
| 6 | `bstr(32)` | Target X25519 DDHK public key |
| 7 | `bstr(16)` nonzero | Random EnrollmentID, generated once by the target using a CSPRNG |

`descriptor_digest = SHA-256(exact complete canonical DeviceEnrollmentDescriptorV2 bytes)`.

Rules:

- The descriptor bytes are immutable for the lifetime of an EnrollmentID.
- A reused EnrollmentID with different descriptor bytes is a hard conflict.
- The epoch is a client proposal, not authority. Gateway PostgreSQL state decides whether it is current.
- DSK/DDHK keys are validated before an approval challenge is issued and again at activation.
- Do not include push tokens or mutable profile metadata in this descriptor.
- Initial signed-prekey material is not defined in this object yet. See DEC-09; the device must not be called messaging-ready until a separately reviewed signed-prekey bootstrap is complete.

### 5.2 `DeviceEnrollmentApprovalV2`

The existing device signs this object only after the user-facing approval UI has displayed and confirmed the target descriptor. The object binds the approver, account, epoch, enrollment ID, descriptor digest, and a fresh Gateway approval challenge.

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Object version |
| 2 | `bstr(16)` nonzero | AccountID |
| 3 | `bstr(16)` nonzero | Approving DeviceID |
| 4 | uint in `1..=2^32-1` | Account epoch approved by the existing device |
| 5 | `bstr(16)` nonzero | EnrollmentID from the exact descriptor |
| 6 | `bstr(32)` | Descriptor digest |
| 7 | `bstr(16)` nonzero | Gateway-issued approval challenge ID |
| 8 | `bstr(32)` | Exact Gateway-issued approval nonce |
| 9 | `bstr(64)` | Approving device's Ed25519 DSK signature |

Candidate signature domain:

`ASCII("PM-V2-DEVICE-ENROLL-APPROVAL-v2")`

Candidate signature transcript:

`ASCII("PM-V2-DEVICE-ENROLL-APPROVAL-v2") || canonical_map(fields_1_to_8)`

The Gateway must verify the signature using the approving device's DSK from authoritative PostgreSQL state. Never accept a public key supplied in the approval request as the verification key.

### 5.3 `DeviceEnrollmentChallengeRequestV2` (proposed anti-abuse gate)

The target is not yet registered, so it cannot authenticate this request with PM-Device-V1. Do not treat EnrollmentID as a bearer secret: it is part of the descriptor shared with the approving device. To prevent a party who merely learns an EnrollmentID from repeatedly replacing the target challenge, require a preliminary DSK signature over a fresh client nonce before issuing a server PoP challenge.

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Object version |
| 2 | `bstr(16)` nonzero | AccountID |
| 3 | `bstr(16)` nonzero | Target DeviceID |
| 4 | uint in `1..=2^32-1` | Proposed account epoch |
| 5 | `bstr(16)` nonzero | EnrollmentID |
| 6 | `bstr(32)` | Descriptor digest |
| 7 | `bstr(32)` nonzero | Fresh target-generated request nonce |
| 8 | `bstr(64)` | Target DSK signature |

Candidate signature domain:

`ASCII("PM-V2-DEVICE-ENROLL-CHALLENGE-REQUEST-v2")`

Candidate signature transcript:

`ASCII("PM-V2-DEVICE-ENROLL-CHALLENGE-REQUEST-v2") || canonical_map(fields_1_to_7)`

The Gateway verifies this signature against the target DSK in the stored descriptor and consumes `(EnrollmentID, requestNonce)` exactly once in PostgreSQL before issuing/replacing a target PoP challenge. This proves control of the target DSK for challenge issuance but does **not** replace the final server-challenge-bound PoP in Section 5.4.

### 5.4 `DeviceEnrollmentPoPV2`

The target device signs this object only after receiving the target PoP challenge. It binds the proof to the exact descriptor and the exact accepted approval.

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Object version |
| 2 | `bstr(16)` nonzero | AccountID |
| 3 | `bstr(16)` nonzero | Target DeviceID |
| 4 | uint in `1..=2^32-1` | Account epoch |
| 5 | `bstr(16)` nonzero | EnrollmentID |
| 6 | `bstr(32)` | Descriptor digest |
| 7 | `bstr(32)` | SHA-256 of exact complete signed DeviceEnrollmentApprovalV2 bytes |
| 8 | `bstr(16)` nonzero | Gateway-issued target PoP challenge ID |
| 9 | `bstr(32)` | Exact Gateway-issued target PoP nonce |
| 10 | `bstr(64)` | Target device's Ed25519 DSK signature |

Candidate signature domain:

`ASCII("PM-V2-DEVICE-ENROLL-POP-v2")`

Candidate signature transcript:

`ASCII("PM-V2-DEVICE-ENROLL-POP-v2") || canonical_map(fields_1_to_9)`

Gateway verification must compare every signed field against the persisted descriptor, persisted accepted approval, and locked challenge row. A structurally valid proof alone is not authorization or freshness.

## 6. Proposed protocol sequence

### Step 1 — Target prepares descriptor

The new device creates its own AccountID binding, DeviceID, DSK and DDHK inside the native context, then creates one EnrollmentID and the exact canonical descriptor bytes. The target shares the descriptor with an already-authorized device through an authenticated out-of-band handoff (for example a QR code or locally authenticated pairing channel). The handoff medium is not itself trusted authorization.

The existing device must display a human-readable account/target identity and a short fingerprint derived from the descriptor digest. The user must compare/confirm the target device before approval signing. Exact display and anti-substitution UX remain a review gate.

### Step 2 — Existing device requests approval challenge

Proposed endpoint:

`POST /v2/device-enrollments/approval-challenges`

Requirements:

- Require `Authorization: PM-Device-V1 ...` using the existing request-authentication scheme.
- The exact raw HTTP body is authenticated by PM-Device-V1; the authenticated principal must identify the approving account/device/epoch.
- Body contains the canonical descriptor bytes (lowercase hex in the JSON envelope, pending final transport ratification).
- Gateway checks account active, no pending recovery, descriptor epoch equals the current PostgreSQL epoch, target DeviceID is unused, and the authenticated approver is active/non-revoked in the same epoch.
- Gateway stores a challenge bound to AccountID, approver DeviceID, epoch, EnrollmentID, and descriptor digest. The challenge ID and nonce are CSPRNG-generated; expiry is database-time based. Proposed approval challenge lifetime: five minutes.
- Challenge replacement and exact retry semantics must be specified so an earlier challenge cannot remain usable after a replacement.

### Step 3 — Existing device signs and submits approval

Proposed endpoint:

`POST /v2/device-enrollments/approvals`

Requirements:

- Require PM-Device-V1 request authentication again. The middleware principal must exactly match the approval's AccountID, ApprovingDeviceID and epoch.
- Verify the V2 approval signature using the authoritative stored DSK; compare its EnrollmentID, descriptor digest, challenge ID and nonce to the persisted challenge.
- Under the account/device/challenge transaction lock order, re-check account active, no pending recovery, current epoch, approver active/not revoked and exact public-key consistency.
- Consume the approval challenge exactly once and persist the exact descriptor bytes/digest, approval bytes/digest, approver identity, accepted time, and intent status.
- Exact retry with the same EnrollmentID, descriptor and approval returns the same accepted outcome. Any changed bytes or conflicting reuse fail closed.
- Proposed accepted-intent lifetime: ten minutes from DB acceptance. The actual value is an operational parameter to ratify.

### Step 4 — Target requests PoP challenge

Proposed endpoint:

`POST /v2/device-enrollments/challenges`

Requirements:

- Target device is not yet authorized and cannot use PM-Device-V1. EnrollmentID is an identifier, not an authorization secret.
- Request includes EnrollmentID and `DeviceEnrollmentChallengeRequestV2`. The Gateway retrieves the accepted descriptor, verifies the preliminary target DSK signature and exact enrollment/descriptor/epoch binding, then consumes the target request nonce exactly once.
- Gateway confirms the approved intent is still pending/unexpired and account state still matches the approved epoch; it issues a fresh one-use challenge bound to EnrollmentID, descriptor digest, approval digest, account, target device and epoch.
- Proposed target PoP challenge lifetime: five minutes, measured using PostgreSQL time.
- Reissuing the target challenge invalidates/consumes any previous outstanding target challenge for that enrollment intent. Apply per-EnrollmentID, per-target and per-peer rate limits; the preliminary target signature prevents unrelated callers from forcing challenge replacement.

### Step 5 — Target proves DSK possession and activates

Proposed endpoint:

`POST /v2/device-enrollments/activate`

Requirements:

- Request includes EnrollmentID and exact DeviceEnrollmentPoPV2 bytes.
- Gateway retrieves descriptor and approval evidence from the persisted intent; do not accept a replacement descriptor or approval at activation.
- Verify the target DSK signature and every field against exact persisted bytes and the locked challenge row.
- In one transaction: re-check account active/current epoch/no pending recovery; re-check approving device remains active/non-revoked in the same epoch with the same DSK/DDHK; lock the intent and challenge; check DB expiry and one-time state; insert target device and authorization rows; store immutable enrollment evidence/event; consume the challenge; mark the intent activated.
- Do not activate the target if the approver was revoked or the account epoch changed after approval.
- The exact same activation retry after a lost response returns success only if the identical EnrollmentID, descriptor digest, approval digest and PoP digest are already committed and all installed state remains active and consistent. A different proof or altered request is rejected.
- Device activation and the evidence of approval/PoP must commit atomically. No partially installed device is visible as active.

## 7. Candidate HTTP contract

The following paths are proposed, not frozen:

| Method | Path | Caller | Result |
|---|---|---|---|
| POST | `/v2/device-enrollments/approval-challenges` | Existing device, PM-Device-V1 authenticated | Approval challenge |
| POST | `/v2/device-enrollments/approvals` | Existing device, PM-Device-V1 authenticated | Accepted approval intent |
| POST | `/v2/device-enrollments/challenges` | Target device, unregistered; DSK-signed challenge request | Target PoP challenge for accepted EnrollmentID |
| POST | `/v2/device-enrollments/activate` | Target device, unregistered | Atomic activation |

Transport proposal:

- `Content-Type: application/json` and `Accept: application/json` for consistency with the current candidate HTTP client; binary canonical objects are represented as lowercase hexadecimal strings.
- Reject unknown JSON fields, duplicate JSON keys if the selected decoder can enforce them, multiple JSON values, non-JSON content types, malformed or uppercase hex if lowercase is ratified, and over-limit bodies.
- Challenge responses contain `challenge_id_hex`, `challenge_nonce_hex`, and `expires_at` in RFC3339Nano UTC form. Database time, not the client's wall clock, decides acceptance.
- Activation returns `204 No Content` only after durable commit. Error bodies contain exactly one public `error` code, no internal database details, and `Cache-Control: no-store`.
- PM-Device-V1 request authentication signs the exact HTTP method, request target and raw body. Preserve exact bytes between middleware verification and handler processing.

Candidate stable error baseline:

| Condition | Proposed response |
|---|---|
| Malformed/non-canonical object or invalid signature | 400 generic `ERR_ENROLLMENT_REJECTED` |
| Missing/expired approval or target challenge | 410 `ERR_CHALLENGE_EXPIRED` or generic non-disclosing rejection after review |
| EnrollmentID reused with changed bytes | 409 `ERR_ENROLLMENT_CONFLICT` |
| Pending recovery, stale epoch, approver revoked | 409 `ERR_ENROLLMENT_CONFLICT` |
| Target or approving device not authorized | 401/403 generic response; do not leak unnecessary account state |
| Shared rate limit reached | 429 `ERR_RATE_LIMITED` with `Retry-After` |
| Shared limiter unavailable | 503 fail closed |
| Unexpected internal failure | 500 generic code |

Final enumeration and retry semantics need a dedicated HTTP compatibility review.

## 8. PostgreSQL state and transaction proposal

### 8.1 Durable enrollment intent

A new table or equivalently constrained schema should persist:

- EnrollmentID (unique, never reusable);
- AccountID and proposed epoch;
- Target DeviceID, DSK and DDHK (or exact descriptor bytes plus indexed binding columns);
- exact descriptor CBOR and descriptor digest;
- approving DeviceID and approval bytes/digest;
- status (`APPROVED`, `CHALLENGED`, `ACTIVATED`, `EXPIRED`, `CANCELLED` or a smaller reviewed state set);
- DB `accepted_at`, `expires_at`, `activated_at`;
- exact PoP/challenge digest evidence needed to resolve an ambiguous commit;
- immutable created/updated lifecycle evidence.

Do not persist private keys, recovery mnemonic, recovery private key, or raw secrets. EnrollmentID tombstones must not become reusable after evidence archival or cleanup.

### 8.2 Challenges

Approval and target PoP challenges may share a table with an explicit purpose discriminator or use separate tables. Each challenge must bind the complete protocol context and have immutable identity/binding columns. Only `consumed_at: NULL -> database-generated timestamp` may change, once. A consumed challenge cannot be cleared or re-dated.

Required immutable binding fields include challenge ID, purpose, AccountID, EnrollmentID, DeviceID (approver or target as applicable), epoch, descriptor digest, approval digest where applicable, nonce, created time and expiry.

### 8.3 Lock order and activation boundary

Proposed order for operations touching account authorization:

1. `accounts` row;
2. `authorization_accounts` row;
3. `authorization_devices` row for the approving device;
4. `devices` row for the approving device;
5. enrollment-intent row;
6. challenge row(s);
7. inserts/updates for the target device and immutable event.

The final order must be reconciled against every existing `PostgresAuthorizer.Transition`, recovery lifecycle operation, and `PostgresRequestAuthenticator` lock path before implementation. Do not introduce a reverse-order deadlock path.

All state re-checks, proof verification against database-sourced values, challenge consumption, device insertion, authorization insertion, approval evidence/event insertion and intent status transition must share one PostgreSQL transaction. Validate runtime role grants; do not assume triggers are a substitute for restricted privileges.

## 9. Native and Android boundaries

### Existing device

Add a narrow native API that signs only `DeviceEnrollmentApprovalV2` for the currently held account/device DSK. It must:

- derive AccountID, approving DeviceID and DSK from the native-owned context;
- bind exact descriptor bytes/digest, EnrollmentID, epoch, challenge ID and nonce;
- refuse a descriptor for another account or a challenge inconsistent with the descriptor;
- expose no generic arbitrary-message DSK signing oracle;
- be invoked only after the Android UI explicitly confirms the descriptor fingerprint and target details.

The native API cannot independently prove that an epoch is current or that a challenge was issued by the Gateway. Those are server-authoritative checks. Do not label a Kotlin-supplied epoch or boolean as trusted.

### Target device

Add a narrow native API that verifies/binds the exact descriptor to the native context's AccountID, DeviceID, DSK and DDHK and signs `DeviceEnrollmentPoPV2`. The API must prevent certificate/descriptor rebinding and keep private DSK/DDHK material inside Rust.

### Process death

Persist an encrypted/authenticated operation journal protected by Android Keystore. It may contain exact public descriptor bytes, approval bytes, challenge IDs/nonces, PoP bytes, digests, Gateway-origin identity/version, timestamps and state. It must not contain any private key or recovery mnemonic.

After restart, re-read and authenticate the exact operation record. Re-establish native binding to the exact descriptor through a verification/bind API; do not require persistence of a recovery mnemonic. For an uncertain activation outcome, retry only byte-identical activation bytes or use a separately designed authenticated status endpoint. Never create a new proof/challenge just because an acknowledgement was lost.

## 10. Signed-prekey bootstrap boundary (OPEN)

Current Gateway candidate activation inserts device and authorization records but does not insert initial signed prekeys. The read-only directory can list signed prekeys; the existing `DeviceProvisioner.Enroll` persistence method accepts signed prekeys but explicitly does not decide authorization.

Before calling a new device messaging-ready, the design must decide whether:

- initial signed-prekey bundle bytes/digest are included in and signed by the enrollment descriptor; or
- a separate authenticated prekey-registration step follows device activation, with an explicit state that prevents messaging use until prekeys are committed.

The bundle schema, SPK ID uniqueness/range, key validation, signature transcript, optional one-time prekeys, publication transaction and directory response are not specified by this proposal. Do not invent them inside the V2 descriptor without a separate source/schema review. This is a P2 end-to-end acceptance blocker.

## 11. Rate limiting, ingress and abuse controls

- Replace the candidate route's per-process `newDemoMessageLimiter` with a shared PostgreSQL HMAC limiter or an explicitly trusted ingress-wide quota.
- Keep candidate enrollment quotas separate from recovery API quotas; define per-account, per-approver-device and per-peer controls to limit targeted abuse.
- Use DB time for fixed-window expiry. Fail closed if the shared limiter is unavailable.
- Do not trust `Forwarded` or `X-Forwarded-For` by default. If behind a reverse proxy, define trusted proxy CIDRs and validate the forwarding chain.
- The repository's Gateway listener is plain HTTP; deployment must enforce a trusted HTTPS ingress/protected transport and block direct public access to the listener.
- Add audit metrics for approval attempts, failures, expired challenges, repeated EnrollmentIDs, stale approvers, and activation ambiguity without logging private material or sensitive payloads.

## 12. Compatibility and non-goals

- Preserve current `DeviceEnrollmentAuthorizationV1`, `EpochTransitionAuthorizationV1`, `RecoveryRequestV1`, `RecoveryAbortV1`, and `DeviceEnrollmentPoPV1` bytes and signature transcripts exactly.
- Do not mutate V1 schemas in place or reuse V1 domains for V2.
- Ordinary enrollment V2 is not the 48-hour recovery workflow. A recovery-locked account cannot use V2 ordinary enrollment.
- Do not expose the immediate `RecoveryResetAction` as the delayed recovery API.
- Do not treat the public device directory as an authorization oracle.
- Do not implement ratchet persistence, witness freshness, or messaging readiness as a side effect of this enrollment protocol.
- Do not enable candidate routes in production. A frozen enrollment contract alone does not make the messenger production-ready.

## 13. Required review decisions and acceptance gates

### DEC-V2-01 — Approver threshold

Baseline proposal: one currently active device approves. Security review must decide whether high-risk accounts should support or require a multi-device threshold. Recovery remains the only path when no active device is available.

### DEC-V2-02 — Trusted display and user presence

Specify what exact target identity/fingerprint, account identity, key details and warning are displayed; whether Android biometric/device-credential confirmation is mandatory; and how QR/handoff substitution is detected. A signed approval without trustworthy UI is not sufficient evidence of informed consent.

### DEC-V2-03 — Signed-prekey bootstrap

Decide whether prekey bundle digest is part of the descriptor or whether activation and prekey registration are distinct states. A device without required prekeys must not be exposed as ready for session establishment.

### DEC-V2-04 — Challenge/approval lifetime and replacement

Ratify the proposed five-minute challenge lifetime, ten-minute approved-intent lifetime, exact replacement rules and DB-time semantics.

### DEC-V2-05 — EnrollmentID lifecycle and cancellation

Define uniqueness scope, retention/tombstone period, user cancellation, cleanup, and exact retry semantics after process death or account/approver state change.

### DEC-V2-06 — Native signature and rebind API

Review the narrow FFI signatures, exact descriptor binding and secret-buffer handling. Do not implement a generic DSK signing API.

### DEC-V2-07 — Endpoint authentication and lock order

Confirm how PM-Device-V1 middleware is mounted on V2 approval routes, how the exact raw request body is preserved, and how transaction locks serialize against revoke/recovery.

### DEC-V2-08 — Public error/enumeration policy

Ratify public error codes, retryable states and anti-enumeration behavior before API freeze.

### DEC-V2-09 — Target challenge issuance authorization

The EnrollmentID is not secret because it is included in the descriptor shared for approval. Ratify the proposed `DeviceEnrollmentChallengeRequestV2` DSK signature plus one-time client nonce, or a separately reviewed high-entropy target capability. Do not allow possession of EnrollmentID alone to trigger unbounded challenge replacement.

### Required tests

**Rust/Go wire parity**
- Valid descriptor, approval and PoP canonical byte vectors.
- Rust-generated vectors parsed and verified by Go; Go-generated vectors parsed/verified by Rust; independent reference validation.
- Wrong domain, wrong account/device/epoch, wrong EnrollmentID, changed descriptor digest, wrong approver, wrong nonce/challenge ID, wrong approval digest, replayed target challenge-request nonce, invalid signatures and all-zero identifiers.
- Duplicate/unknown fields, non-canonical encodings, trailing bytes, truncated inputs, cap-plus-one lengths, epoch 0, epoch max, and overflow.
- Invalid/low-order X25519 DDHK and malformed Ed25519 DSK material rejected consistently.

**Gateway/PostgreSQL**
- Approval rejected for inactive/revoked/wrong-epoch approver; exact principal-to-approval mismatch rejected.
- Recovery-pending and stale-epoch enrollment rejected at both challenge and activation.
- Approval challenge replay, replacement, expiry and cross-enrollment reuse rejected.
- Target challenge-request signature and nonce are verified/consumed; unrelated callers cannot replace a target challenge.
- PoP challenge replay, replacement, expiry, cross-descriptor and cross-approval reuse rejected.
- Concurrent approvals/activations for same EnrollmentID serialize; conflicting reuse fails.
- Approval accepted, then approver revoked or epoch changed before activation: activation fails.
- Lost response after commit resolves only through exact retry; no duplicate device/event.
- Challenge binding-column mutation rejected by database trigger/permissions tests.
- Shared rate limit across two Gateway instances; storage outage fails closed.

**Android/native end-to-end**
- Existing device explicitly confirms target descriptor and creates approval using native DSK.
- Target creates descriptor and PoP from its own native key context.
- Actual Android → Gateway → PostgreSQL successful two-device activation.
- Process death before/after approval acceptance, before/after target challenge, and before/after activation commit.
- Byte-identical retry after lost acknowledgement; no fresh proof/challenge substitution.
- No recovery mnemonic or DSK/DDHK private material in operation journal or logs.
- Approval UI/handoff substitution and biometric/user-presence behavior reviewed.
- Prekey bootstrap must complete before the device is declared messaging-ready.

## 14. Proposed implementation order after approval

1. Review and ratify DEC-V2-01 through DEC-V2-08; update the CTO decision baseline if decisions change.
2. Freeze only the V2 object maps and transcript domains after canonical PM-CBOR review.
3. Produce deterministic JSON test-vector fixtures containing exact CBOR hex, digest, transcript bytes and signature values; independently validate in Python.
4. Implement Rust parser/signer/verifier and Go parser/verifier in isolated branches with byte-for-byte parity tests.
5. Design the PostgreSQL enrollment-intent/challenge schema, immutable-field guards, privileges, and concurrency tests.
6. Add Gateway V2 endpoints behind a development-only feature gate and PM-Device-V1 authentication for approver routes.
7. Implement Android native approval/PoP calls, trusted display and durable operation journal.
8. Resolve signed-prekey bootstrap and run real two-device Android-to-Gateway-to-PostgreSQL tests.
9. Conduct independent protocol/security review. Only then consider freezing the contract and enabling a controlled test deployment.

## 15. Source references at review point `6677df50051d1a89f2260060bc4758b64629392c`

- `docs/phase0/11-pmacbor-2026.md` — canonical encoding and bounds.
- `docs/phase0/13-device-lifecycle-v1.md` — current V1 lifecycle proposal and recovery boundary.
- `docs/phase-c/05-p2-enrollment-recovery-cto-decision-baseline.md` — policy baseline proposal on the separate PR #11 head branch `docs/p2-enrollment-recovery-decision-baseline`; it is not yet merged into the Phase C base.
- `native/crypto-core/src/authorization_v1.rs` — existing V1 recovery-signed authorization objects.
- `native/crypto-core/src/device_request_auth_v1.rs` — native PM-Device-V1 signed HTTP request proof.
- `services/gateway/internal/deviceauth/request_v1.go` — PM-Device-V1 parser/transcript verifier.
- `services/gateway/internal/deviceauth/postgres_authenticator.go` — authoritative active-device checks and nonce consumption.
- `services/gateway/internal/http/device_auth_middleware.go` — raw-body authentication middleware.
- `services/gateway/internal/authorization/device_enrollment_pop_v1.go` — current candidate V1 target PoP.
- `services/gateway/internal/authorization/enrollment_activation_candidate.go` — current active-account candidate activation transaction.
- `services/gateway/internal/http/enrollment_candidate_http.go` — disabled candidate HTTP surface and process-local limiter.
- `services/gateway/internal/devices/directory.go` and `services/gateway/internal/http/device_http.go` — read-only device directory and signed-prekey listing.
- `services/gateway/internal/devices/lifecycle.go` — persistence-only device provisioner; authorization is outside its boundary.
- `services/gateway/RECOVERY_API_DEPLOYMENT.md` — separate recovery API's rate-limit and ingress requirements.

**Disposition:** Candidate V2 design only. No implementation is authorized by this document. Ordinary enrollment and catastrophic recovery remain separate. Candidate routes remain disabled. P2 remains incomplete.
