# P2 Enrollment and Recovery — V2 Policy Reconciliation and Freeze Gates

**Status:** Reconciliation proposal — NOT FROZEN
**Review point:** 2026-11-05
**Applies to:** `05-p2-enrollment-recovery-cto-decision-baseline.md`, `06-ordinary-device-enrollment-v2-wire-contract-proposal.md`, and `07-ordinary-device-enrollment-v2-review-refinements.md`
**Scope:** Reconcile P2 authorization policy with ordinary-enrollment V2; close the known signed-prekey transport and short-authentication-string ambiguities; define remaining freeze gates.

## 1. Document authority and precedence

These documents have different jobs and must be read together:

1. **Document 05 — P2 Enrollment and Recovery CTO Decision Baseline** is the policy baseline for DEC-01 through DEC-08: ordinary enrollment versus catastrophic recovery, PostgreSQL epoch authority, challenge authority, restart-safe operations, error semantics, shared rate limiting, and challenge-row integrity.
2. **Document 06 — Ordinary Device Enrollment V2 Wire Contract Proposal** translates ordinary enrollment policy into candidate V2 objects, endpoints, transactions, and tests.
3. **Document 07 — V2 Review Refinements Addendum** supersedes the corresponding open alternatives in Document 06 for accepted-approval evidence delivery, trusted display/user-presence limitations, and initial signed-prekey bootstrap. Its descriptor field 8 is a proposed refinement to the seven-field descriptor in Document 06.
4. **This Document 08** reconciles the terminology and acceptance gates. It does not silently freeze any candidate value or authorize implementation.

Policy precedence: Document 05 controls the ordinary-versus-recovery security policy. For V2 wire details, Document 07 takes precedence over the specifically superseded alternatives in Document 06. This document identifies additional details that must be ratified. If a reviewer finds a genuine contradiction, stop and amend the relevant proposal; do not resolve it in code by interpretation.

All four documents remain proposals. A merge or green CI run is not protocol approval, independent security review, or production authorization.

## 2. DEC-01 through DEC-08 reconciliation

| Policy decision | V2 interpretation | Status / required gate |
|---|---|---|
| DEC-01 — Authorization authority | Ordinary V2 requires one currently active, non-revoked device in the current epoch to sign `DeviceEnrollmentApprovalV2`; target independently signs `DeviceEnrollmentPoPV2`. Recovery credentials are not used. V2 is rejected while recovery is pending. | Consistent. One approver is the minimum baseline. Multi-approver thresholds remain a separate security/product decision; do not imply they exist. |
| DEC-02 — Epoch authority | PostgreSQL Gateway account state is authoritative. Descriptor and signed objects carry a proposed epoch, which must be rechecked at approval and activation under account serialization. | Consistent. Client epoch, device-directory data, and Kotlin booleans are never authority. |
| DEC-03 — Challenge authority | Gateway PostgreSQL rows control challenge issuance, binding, expiry, replacement and one-time consumption. PM-Device-V1 authenticates existing-device HTTP requests. Target verifies the exact accepted approval bytes and digest returned over the configured HTTPS Gateway origin. | Consistent with one trust limitation: V2 trusts the configured Gateway as an authorization authority. It does not provide protection against a malicious/compromised Gateway. State this explicitly; do not claim server-compromise resistance. |
| DEC-04 — Process death and ambiguous activation | The Android journal stores exact public protocol bytes and state: descriptor, initial signed-prekey object, accepted approval, challenges, PoP, digests, Gateway-origin identity and retry state. It stores no recovery mnemonic or private key. Retry is byte-identical. | Consistent after terminology correction: ordinary V2 uses `descriptor_digest`; catastrophic recovery may still use its recovery-certificate digest. Never treat those as interchangeable fields. |
| DEC-05 — Ordinary enrollment versus recovery | V2 only enrolls a new device into an active, current-epoch account with no pending recovery. The distinct 48-hour recovery state machine remains separate and is not implemented by V2 routes. | Consistent. Recovery finalization, target binding, epoch transition and unlock require their own reviewed tests and deployment gates. |
| DEC-06 — HTTP errors | Use the V2 stable error baseline in Document 06 and the coarse public-error policy in Document 05. Invalid/non-canonical objects and signatures map to generic rejection; state conflicts map to a stable conflict; expiry, rate-limit, limiter outage, account lock and internal error remain stable classes. | Partially open. Ratify exact status/code pairs and anti-enumeration behavior before API freeze. Recommended table is in Section 7. |
| DEC-07 — Rate limiting and ingress trust | V2 uses shared, cross-instance quotas, separate from recovery buckets. Normalize peer identity, HMAC it, use DB time, fail closed, and trust forwarded addresses only through explicitly configured proxy CIDRs/chains. | Consistent. Prove the same quota is enforced across at least two Gateway instances and fails closed on storage outage. |
| DEC-08 — Challenge integrity and DB privileges | Existing V1 challenge guards are not sufficient by themselves for V2. V2 intent and challenge binding fields must be immutable; only reviewed one-way lifecycle transitions are allowed. Runtime DB privileges must be audited. | Consistent but must be made concrete for the new V2 schema; see Section 8. |

## 3. Canonical V2 descriptor and initial signed-prekey binding

The V2 descriptor in Document 06 contains fields 1–7. Document 07 proposes field 8:

| Key | Type | Meaning |
|---:|---|---|
| 8 | `bstr(32)` | SHA-256 of the exact complete canonical `SignedPrekeyV1` bytes for the target's initial signed prekey |

The field-8 refinement is required for the proposed one-step activation baseline. The descriptor digest is always:

`SHA-256(exact complete canonical DeviceEnrollmentDescriptorV2 bytes, including field 8)`

The approval signs that descriptor digest. Therefore the existing device's approval binds the exact initial signed-prekey object transitively. The target PoP also binds the descriptor digest and accepted approval digest. Do not hash a decoded/re-encoded approximation.

The `SignedPrekeyV1` candidate object remains the seven-field canonical object already present in `native/crypto-core/src/signed_prekey_v1.rs`. Its candidate signature transcript remains:

`ASCII("PM-V1-SIGNED-PREKEY-v1") || canonical_cbor(fields_1_to_6)`

Preserve the existing transcript and V1 bytes. Do not silently change the signed-prekey object version or transcript as part of enrollment V2.

## 4. Exact initial signed-prekey transport and persistence proposal

Document 07 specifies that the exact signed-prekey object travels with the descriptor during target-to-approver handoff, but Document 06's HTTP body description still names only the descriptor. The transport must be explicit before implementation.

### 4.1 Target-to-approver handoff

The target prepares, inside the native context:

- exact canonical `DeviceEnrollmentDescriptorV2` bytes, including field 8;
- exact canonical `SignedPrekeyV1` bytes whose SHA-256 equals descriptor field 8;
- a descriptor-derived short authentication string as specified in Section 6.

The handoff may encode the two public canonical objects as lowercase hex in a QR or another authenticated local pairing channel. The handoff must not include the SPK private key, DSK private key, DDHK private key, recovery mnemonic, or recovery private key.

The approving device strictly parses the exact descriptor and signed-prekey bytes. It verifies the signed-prekey signature with the target DSK in descriptor field 5, verifies AccountID/epoch/DeviceID against descriptor fields 2/3/4, recomputes the exact-object digest and compares it to field 8, and displays the SPK_ID plus a short SPK public-key fingerprint before the user confirms.

### 4.2 Approval-challenge request body

Amend the proposed `POST /v2/device-enrollments/approval-challenges` JSON envelope to carry both exact objects:

- `descriptor_cbor_hex`: exact canonical descriptor bytes;
- `initial_signed_prekey_cbor_hex`: exact canonical `SignedPrekeyV1` bytes.

The existing device sends the exact bytes it received in the pairing handoff. Both values are included in the PM-Device-V1-authenticated raw HTTP body. The Gateway must not reconstruct the signed-prekey object from decoded fields.

Candidate transport bound: `SignedPrekeyV1` raw bytes are capped at 256 bytes; the JSON request body must also have an explicit fixed maximum compatible with the Gateway's existing body limit. Reject uppercase/non-canonical hex, malformed CBOR, trailing bytes, over-limit input and digest mismatch. The 256-byte object cap is a proposal to ratify against the actual parser and HTTP limits, not a claim that a current server enforces it.

### 4.3 Gateway intent persistence

Before issuing an approval challenge, the Gateway validates the descriptor and signed-prekey object and durably stores, under the unique EnrollmentID:

- exact descriptor CBOR bytes and descriptor digest;
- exact initial signed-prekey CBOR bytes and SHA-256 digest;
- indexed AccountID, proposed epoch, target DeviceID, target DSK and DDHK;
- signed-prekey AccountID, epoch, DeviceID, SPK_ID, SPK_pub and signature;
- the intent status and database timestamps.

The Gateway must implement a Go `SignedPrekeyV1` parser/verifier with Rust/Go/independent-reference vectors before relying on the object for authorization. The target's Rust signature check alone is not a Gateway validation boundary.

An EnrollmentID retry with byte-identical descriptor and signed-prekey bytes returns the same intent/challenge outcome under the documented retry rules. Any changed descriptor or signed-prekey bytes for the same EnrollmentID is a hard conflict. The signed-prekey bytes are immutable after intent creation.

### 4.4 Atomic activation

At activation, the Gateway reads the exact accepted descriptor, approval, and initial signed-prekey evidence from the persisted intent. It ignores client-supplied replacement values. In the same PostgreSQL transaction that inserts the target device, authorization state, immutable evidence/event and consumes the final PoP challenge, it inserts the initial `signed_prekeys` row.

The current `signed_prekeys` schema stores normalized columns (including `device_id`, `spk_id`, `spk_pub`, and `signature`) rather than the complete canonical CBOR object. Preserve the exact raw CBOR bytes and digest in the immutable enrollment intent/evidence record; derive and insert normalized columns only after strict verification. Enforce uniqueness of `(device_id, spk_id)` and the V1 `u32` SPK_ID range even though PostgreSQL uses `bigint`.

Success is returned only after commit. A lost-response retry succeeds only if the exact descriptor, accepted approval, target PoP and initial signed-prekey evidence are already committed and mutually consistent. No active/messaging-ready target may appear without its verified initial signed-prekey row.

## 5. Signed-prekey private-key lifecycle proposal

The public signed-prekey object is not sufficient. The corresponding private key is required for the recipient to complete the initial X3DH handshake. The current repository review found the candidate public-object parser but did not establish a complete generated, persisted, retrieved, rotated and retired private-key lifecycle. This is a blocking design gap.

### 5.1 Generation and custody

- Generate the X25519 SPK keypair inside Rust/native crypto context using the platform CSPRNG. Never generate it in Kotlin or a JavaScript/UI layer.
- Bind the SPK private key to AccountID, DeviceID, epoch, SPK_ID and SPK_pub inside the native identity context. Sign the public `SignedPrekeyV1` object with the target DSK using the existing exact candidate transcript.
- Keep the SPK private key inside the Rust-owned sealed identity store, protected by the existing at-rest encryption boundary. Do not expose private bytes through UniFFI, Kotlin, HTTP, QR, analytics, logs, crash reports, or the enrollment journal.
- The session-establishment operation must consume the SPK private key inside native code. Kotlin receives only public/session metadata, never the SPK private scalar.
- A fresh installation or a device that cannot restore its native identity must create a new device identity/enrollment. Do not copy an SPK private key to another device as an enrollment shortcut.

The current Android Keystore wrapper protects the Storage DEK at rest; the current design does not prove per-signature biometric enforcement for DSK/SPK operations. Do not claim hardware-enforced user presence for these keys. Any change to hardware-backed key custody or per-use authentication needs a separate review of key binding, attestation, invalidation, supported-device policy and native verification.

### 5.2 ID allocation and lifecycle

- Allocate SPK_ID from a durable per-device monotonically increasing `u32` counter. Never reuse an ID, including after a key is retired or deleted. Stop and require a reviewed recovery path if the counter would overflow.
- Persist the private key and its public metadata as one authenticated native identity-store update. A partial update must not publish the public key without the matching private key or vice versa.
- A private-key lookup must require the exact AccountID, DeviceID and SPK_ID and must fail closed on mismatched epoch/key metadata.
- Do not include SPK private material in cloud backup or enrollment transfer. Define restore behavior explicitly; a restored device without the corresponding native key must not claim it can answer handshakes for that SPK_ID.

### 5.3 Rotation, overlap and retirement

Define a separate authenticated SPK rotation operation, signed by the already-enrolled device DSK and checked against current account/device epoch. It must publish a newly signed SPK before retiring the current public SPK.

The following operational values remain intentionally open and must be ratified before production use: maximum signed-prekey publication lifetime, rotation cadence, maximum client bundle-cache lifetime, overlap/grace period for old private keys, behavior for a handshake arriving during retirement, and backup/restore/secure-deletion semantics. The Gateway must not delete a public SPK while clients may legitimately hold a cached bundle unless the client failure/retry behavior is specified.

No OPK support is implied. OPKs remain outside the initial V2 activation baseline until authenticated registration, retrieval, atomic one-time consumption, replenishment, and replay tests are separately specified and implemented.

## 6. Exact short-authentication-string proposal

The current documents require both devices to display the same descriptor-derived short authentication string but do not define its derivation or encoding. Use this candidate deterministic format for review:

1. Let `descriptor_digest` be SHA-256 of the exact complete canonical V2 descriptor, including field 8.
2. Compute:

   `sas_digest = SHA-256(ASCII("PM-V2-ENROLLMENT-SAS-v1") || descriptor_digest)`

3. Take the first 40 bits (the first five bytes) of `sas_digest`, interpreted as one big-endian 40-bit value.
4. Encode those 40 bits as exactly eight 5-bit symbols using the Crockford Base32 alphabet:

   `0123456789ABCDEFGHJKMNPQRSTVWXYZ`

5. Display as `XXXX-XXXX` in uppercase. Do not accept aliases, whitespace normalization, case folding, or locale-specific digit substitution in the canonical comparison value.

Both the target and approver compute this value independently from the exact descriptor bytes. The user compares all eight symbols across the physical/local pairing interaction before approval. Scanning the same QR code is not a comparison. A mismatch, missing display, changed descriptor, or expired approval attempt aborts the operation. The approver UI must also display the target DeviceID, DSK/DDHK fingerprints, epoch, SPK_ID/SPK fingerprint and configured Gateway origin as specified by Document 07.

This 40-bit SAS is a candidate human-verification value, not a replacement for the full descriptor digest or either signature. Its exact domain, encoding and usability must be included in independent protocol/UX review before freeze.

## 7. V2 public error mapping reconciliation

Use one stable V2 mapping after ratification; do not let the two earlier documents silently diverge. Proposed baseline:

| Condition | HTTP | Public code |
|---|---:|---|
| Malformed JSON/hex, non-canonical CBOR, invalid signature or invalid object binding | 400 | `ERR_ENROLLMENT_REJECTED` |
| Expired approval/target challenge | 410 | `ERR_CHALLENGE_EXPIRED` |
| Reused EnrollmentID with changed descriptor/SPK/approval/proof, stale epoch, pending recovery, revoked approver, or other state conflict | 409 | `ERR_ENROLLMENT_CONFLICT` |
| Missing/invalid PM-Device-V1 authentication | 401 | Generic authentication rejection |
| Authenticated principal lacks required device authorization | 403 | Generic authorization rejection |
| Account explicitly recovery-locked | 423 | `ERR_ACCOUNT_LOCKED` |
| Shared quota exceeded | 429 | `ERR_RATE_LIMITED` plus `Retry-After` |
| Shared limiter/required state store unavailable | 503 | Generic service unavailable; fail closed |
| Unexpected internal failure | 500 | Generic internal error |

Do not reveal whether an AccountID, DeviceID, EnrollmentID or approver exists. Whether challenge expiry uses 410 or a generic non-disclosing conflict is a deliberate compatibility/security decision and must be fixed before clients ship. The table above is the proposed default, not a frozen contract.

## 8. V2 database immutability and serialization requirements

In addition to Document 05's V1 challenge fields and Document 06's V2 challenge fields, the V2 enrollment intent must make the following evidence immutable after creation/acceptance:

- EnrollmentID and exact descriptor bytes/digest;
- exact initial signed-prekey bytes/digest and all indexed SPK identity fields;
- AccountID, target DeviceID, target DSK/DDHK and proposed epoch;
- approving DeviceID and authoritative approver-key identity;
- exact accepted approval bytes/digest and database acceptance time;
- intent creation/expiry times and any terminal timestamp/evidence.

V2 challenge identity/binding columns are immutable: challenge ID, purpose, AccountID, EnrollmentID, approver/target DeviceID as applicable, epoch, descriptor digest, approval digest when applicable, nonce, created time and expiry. Challenge consumption is one-way: `consumed_at: NULL -> database-generated timestamp`. It cannot be cleared or changed.

Intent state transitions must be explicit and one-way; for example, pending/approved to activated, expired or cancelled, with no transition back to an earlier state. The final allowed state set and transition graph must be specified before migration. Runtime Gateway DB roles must not own the tables or have DDL/trigger-control privileges. Tests must attempt to mutate every immutable field through the actual runtime role, not only through a superuser test connection.

Reconcile the proposed lock order with every existing authorization, request-authentication, revocation, recovery and finalizer lock path before implementing any V2 transaction. The candidate order in Document 06 is not accepted until a lock-graph review and concurrent PostgreSQL tests show no reverse-order cycle.

## 9. Trust model, approver identity and user presence

V2 assumes the configured Gateway and its authoritative PostgreSQL authorization state are trusted. TLS authenticates the transport to that Gateway; the DSK approval authenticates the approval bytes. This design does not defeat a malicious Gateway that can fabricate authorization state or substitute key metadata. Do not advertise V2 as resistant to Gateway compromise, rollback, or malicious directory responses unless a separate signed-directory/transparency/witness design is approved and tested.

The target must not treat `approver_dsk_public_key_hex` in an HTTPS response as a human identity. It must compare the approver DeviceID/key fingerprint with the expected existing device in the pairing context and the trusted account/device context available to the client. If the product threat model requires security against a malicious Gateway, the current unsigned/read-only directory is insufficient; add authenticated device-key distribution and rollback protection as a separate design gate.

A fresh Android system-authentication prompt before approval signing is an application-side user-intent gate. It is not remotely verifiable proof of human presence. The current Storage DEK wrapping design does not make the DSK a per-use biometric-gated hardware key. UI confirmation, system-auth prompt outcome, and DSK signature must be described accurately; no biometric/attestation claim is allowed without a separate implementation and review.

## 10. Remaining pre-freeze decisions and acceptance gates

The following items remain open after Documents 05–07 and must close before the V2 wire contract is frozen:

1. **SPK transport contract:** accept the exact `initial_signed_prekey_cbor_hex` addition to the approval-challenge request and immutable intent persistence described in Section 4; ratify byte/body limits.
2. **SPK private-key custody:** review Rust generation, native sealed persistence, exact native lookup for X3DH, restore behavior and prohibition on private-key export.
3. **SPK rotation/retirement:** set publication lifetime, rotation cadence, overlap, private-key retention and deletion semantics.
4. **SAS:** review the exact domain, 40-bit extraction, Crockford alphabet, UI grouping and physical comparison procedure in Section 6.
5. **Approver trust:** confirm the Gateway trust assumption and define how target binds the expected approver DeviceID/DSK fingerprint. If malicious-Gateway resistance is required, stop and design authenticated directory/witness support.
6. **Approval threshold:** decide whether one approver remains the only default or whether configurable multi-approver policy is required. Do not implement an unstated threshold.
7. **Challenge/intent lifetimes and cancellation:** ratify five-minute challenge lifetimes, ten-minute approved-intent lifetime, exact retry, replacement, cancellation, tombstones and cleanup.
8. **Native APIs:** review narrow approval, descriptor binding, signed-prekey generation/storage and target PoP APIs; no generic DSK signing oracle and no secret export.
9. **HTTP compatibility:** finalize exact status/code mapping, challenge-expiry disclosure and enumeration behavior.
10. **Gateway transaction/DB controls:** Go SPK verifier, shared vectors, immutable V2 schema, grants, lock-graph proof, concurrency and rollback tests.
11. **Android end-to-end:** trusted confirmation UI, system-auth prompt behavior, encrypted operation journal, restart/lost-ack retry, initial X3DH handshake and device-readiness gate.
12. **Independent review:** obtain review from someone not authoring these documents, then record findings and disposition before declaring any contract frozen.

## 11. Implementation stop conditions

Until all pre-freeze gates close:

- Keep `GATEWAY_ENABLE_CANDIDATE_ENROLLMENT` unset.
- Keep the recovery API disabled outside explicitly controlled test environments.
- Do not add V2 production endpoints or migrations.
- Do not mark a newly activated device messaging-ready until the initial signed prekey is durably committed and a real X3DH initiation/response test passes.
- Do not claim OPK support, biometric-enforced signing, malicious-Gateway resistance, anti-rollback, production readiness or independent audit.
- Do not begin ratchet-persistence implementation on the assumption that the enrollment lifecycle is frozen.
- Preserve V1 object bytes and signature transcripts exactly.

**Disposition:** This reconciliation clarifies the relationship among the P2 policy baseline and V2 wire proposals and supplies candidate formats for review. It does not freeze V2, change application code, authorize migrations, or enable any route.
