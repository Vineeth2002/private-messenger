# Ordinary Device Enrollment V2 — Review Refinements Addendum

**Status:** Review refinement proposal — NOT FROZEN
**Applies to:** `docs/phase-c/06-ordinary-device-enrollment-v2-wire-contract-proposal.md`
**Target branch:** `phase-c/ratchet-persistence-design`
**Review point:** 2026-11-05
**Scope:** Resolve the three open V2 review items: approval-evidence delivery, trusted approval/user presence, and initial signed-prekey bootstrap.

## 1. Disposition and precedence

This addendum refines the V2 proposal but does not freeze it. If reviewers accept this addendum, it supersedes the corresponding open alternatives in Sections 5.1, 5.4, 6 Step 4, 10, and 13 DEC-V2-02/DEC-V2-03/DEC-V2-09 of the parent proposal. All other parent-proposal constraints remain in force.

No production implementation, migration, endpoint exposure, or candidate-route enablement is authorized by this addendum. Keep ordinary candidate enrollment disabled. Preserve all existing V1 object bytes and signature transcripts.

## 2. DEC-V2-10 — Deliver accepted approval evidence to the target

### Decision

The target challenge response must return the exact, Gateway-accepted `DeviceEnrollmentApprovalV2` bytes, their SHA-256 digest, and the approver's public identity metadata. The target must not be expected to reconstruct the approval digest or obtain an undocumented side channel.

### Proposed response to `POST /v2/device-enrollments/challenges`

After validating the target-signed `DeviceEnrollmentChallengeRequestV2`, the Gateway returns one response containing:

| Field | Encoding | Meaning |
|---|---|---|
| `challenge_id_hex` | lowercase hex, 16 bytes | Fresh target PoP challenge ID |
| `challenge_nonce_hex` | lowercase hex, 32 bytes | Fresh target PoP nonce |
| `expires_at` | RFC3339Nano UTC | Database-issued challenge expiry |
| `approval_cbor_hex` | lowercase hex | Exact complete canonical `DeviceEnrollmentApprovalV2` bytes stored for this EnrollmentID |
| `approval_digest_hex` | lowercase hex, 32 bytes | SHA-256 of the exact `approval_cbor_hex` decoded bytes |
| `approver_device_id_hex` | lowercase hex, 16 bytes | Approving DeviceID from the authoritative authorization row |
| `approver_dsk_public_key_hex` | lowercase hex, 32 bytes | Approver DSK from the authoritative authorization row used to verify the approval |
| `approval_accepted_at` | RFC3339Nano UTC | Database acceptance time for the durable approval intent |

The response is returned only after the Gateway has established that the target-signed challenge request matches the persisted descriptor and that the approval intent remains accepted, unexpired, and compatible with the current account epoch. The response is transported only through the validated HTTPS Gateway origin.

### Target-side checks before signing `DeviceEnrollmentPoPV2`

The target must:

1. Strictly parse the returned approval object as canonical PM-CBOR and reject unknown, duplicate, missing, non-canonical, or trailing data.
2. Recompute `SHA-256(approval_cbor_raw)` and require exact equality with `approval_digest_hex`.
3. Verify the approval signature using `approver_dsk_public_key_hex` from this same authenticated Gateway response.
4. Check that approval AccountID, epoch, EnrollmentID, descriptor digest, approval challenge ID, and nonce match the target's exact descriptor and its prior approval handoff context.
5. Check that `approver_device_id_hex` is the expected existing device for this pairing. Display the DeviceID and a short DSK fingerprint; do not invent or imply a human-readable name because the current device directory schema does not provide one.
6. Put the recomputed approval digest in `DeviceEnrollmentPoPV2` field 7. The target signs the digest of the exact complete accepted approval bytes, not a re-encoded approval core.

The target does not treat a response field or `EnrollmentID` as a bearer authorization token. The Gateway must still re-check the approval and approver state at activation. TLS authenticates the Gateway transport; the approval DSK signature authenticates the approval bytes. Neither alone proves a human's identity or informed consent.

### Retry and substitution rules

- For the same EnrollmentID, the Gateway returns the same accepted approval bytes and digest until the intent expires or reaches a terminal state.
- A changed descriptor, approval, approver, epoch, or approval digest is a conflict; never replace accepted approval evidence silently.
- If a challenge is replaced, the previous challenge is consumed/invalidated under the same transaction rules. The accepted approval bytes do not change as a side effect.
- The activation endpoint ignores any client-supplied replacement approval. It reads the exact accepted approval bytes/digest from the persisted intent and compares the PoP field 7 against that durable value.

## 3. DEC-V2-02 refinement — Trusted display and user-presence boundary

### Required approval UI

Before the existing device invokes the native DSK approval signer, the Android application must display a confirmation screen containing at least:

- the account identity in a masked but recognizable form;
- target DeviceID;
- target DSK and DDHK short fingerprints;
- descriptor fingerprint / short authentication string;
- proposed account epoch;
- initial signed-prekey ID and short SPK fingerprint (per Section 4);
- the configured Gateway origin;
- an explicit statement that this adds a new device to the active account and does not use the catastrophic recovery path.

The target and approver screens must display the same descriptor-derived short authentication string. The user compares the strings across the physical pairing interaction (for example, a QR handoff followed by a visual comparison). The approver must require a deliberate confirmation action; no background auto-approval, notification action, or mere QR scan may invoke the signer.

The accepted approval receipt shown to the target must identify the approving DeviceID and DSK fingerprint, not a guessed contact name. A local contact label may be displayed only if it was independently assigned by the user on that device.

### User-presence requirement and current-code limitation

Require a fresh Android system authentication prompt (biometric or device credential) immediately before the existing device signs an enrollment approval. The app must fail closed if the prompt is cancelled, fails, or the user changes the target descriptor after confirming it.

This is an application-side user-intent gate, **not a remotely verifiable proof of human presence**. The current `PlatformKeyProtection.kt` implementation uses Android Keystore to wrap the local Storage DEK; its `KeyGenParameterSpec` does not set `setUserAuthenticationRequired`. DSK/DDHK private material remains inside the Rust-sealed identity record and is not currently shown to be held by a per-use user-authenticated Android Keystore signing key. Therefore:

- Do not claim the current DSK signature proves biometric presence or informed human approval.
- Do not claim the current PPAL Level 2 wrapped-at-rest design enforces user presence for each signature.
- Do not add a generic DSK signing FFI. Keep approval signing narrow and context-bound.
- A stronger claim requires a separate design for a hardware-backed, user-authentication-bound approval key, its binding/attestation to the device DSK, key invalidation/re-enrollment behavior, supported-device policy, and Rust/Go/Gateway verification. That is a separate security decision and is not silently included in V2.

### Threat-model statement

V2 protects against recovery-credential-only compromise and unauthenticated callers adding a device. It does not protect against an attacker controlling an already-authorized device or compromising the app/UI to invoke the existing DSK. Independent approval-key attestation is required before claiming stronger malware-resistant or hardware-enforced user-presence assurance.

## 4. DEC-V2-03 refinement — Initial signed-prekey bootstrap

### Source facts

The Phase C source already contains `native/crypto-core/src/signed_prekey_v1.rs`. It defines a candidate seven-field `SignedPrekeyV1` object:

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 1 | Signed-prekey object version |
| 2 | `bstr(16)` nonzero | AccountID |
| 3 | uint, `1..=2^32-1` | Account epoch |
| 4 | `bstr(16)` nonzero | DeviceID |
| 5 | uint, `0..=2^32-1` | SPK_ID |
| 6 | `bstr(32)` usable X25519 public key | SPK_pub |
| 7 | `bstr(64)` | Ed25519 DSK signature |

Its candidate signature transcript is:

`ASCII("PM-V1-SIGNED-PREKEY-v1") || canonical_cbor(fields_1_to_6)`

The Rust parser rejects malformed/non-canonical shape, invalid IDs/epoch/SPK_ID, unusable/low-order X25519 keys, and invalid signatures. The module explicitly says the object is candidate and does not authorize activation. No Go `SignedPrekeyV1` parser/verifier or Rust/Go shared signed-prekey vector was found in the Phase C tree at this review point.

PostgreSQL migration `0001_init.sql` already defines `signed_prekeys` with primary key `(device_id, spk_id)`, 32-byte SPK public key and 64-byte signature. It also defines an `one_time_prekeys` table. `DeviceProvisioner.Enroll` accepts signed prekeys and inserts them in its transaction, but its comment explicitly separates persistence from authorization. The current candidate `ActivateCandidateEnrollment` inserts device/certificate/authorization/event rows but does not insert an initial signed prekey. The read-only directory can list signed prekeys. The directory projection does not return the full `SignedPrekeyV1` CBOR object; clients must reconstruct/verify it using the device's AccountID and epoch plus returned SPK fields, or the directory API must later be upgraded to return a complete signed object.

### Decision

Require **exactly one initial signed prekey** for V2 activation. Treat this as the minimum initial X3DH bootstrap material. The initial signed prekey is part of what the existing device approves and must be committed atomically with device activation. A device without a valid initial signed prekey must not be declared enrolled/messaging-ready.

### Descriptor refinement

Add field 8 to the proposed `DeviceEnrollmentDescriptorV2`:

| Key | Type | Meaning |
|---:|---|---|
| 8 | `bstr(32)` | SHA-256 of the exact complete canonical `SignedPrekeyV1` bytes for the target's initial SPK |

The exact `SignedPrekeyV1` bytes are included alongside the descriptor in the target-to-approver pairing handoff. The approver:

- strictly parses the exact signed-prekey object;
- verifies its DSK signature against field 5 (target DSK) in the descriptor;
- checks AccountID, epoch and DeviceID equal descriptor fields 2, 3 and 4;
- checks the object digest equals descriptor field 8;
- checks SPK_ID and SPK_pub are valid and displays SPK_ID plus a short SPK fingerprint.

The approval signs the descriptor digest, so it indirectly approves the exact initial signed-prekey bytes. Do not add the raw SPK private key or any other private key to the descriptor or pairing payload.

### Gateway validation and atomic persistence

At approval challenge issuance, approval acceptance, target challenge issuance, and activation as applicable, the Gateway must use the same exact descriptor and signed-prekey bytes. At activation it must:

1. Recompute the signed-prekey object digest and compare it to descriptor field 8.
2. Parse/verify the `SignedPrekeyV1` signature against the target DSK from the descriptor.
3. Confirm AccountID, epoch, DeviceID, SPK_ID and SPK_pub match the expected descriptor and authoritative account state.
4. Reject duplicate/reused `(DeviceID, SPK_ID)` and invalid/unusable X25519 SPK public keys.
5. Insert the target device, certificate, authorization device, immutable enrollment evidence/event, initial signed-prekey row, challenge consumption, and intent activation status in the same PostgreSQL transaction.
6. Return success only after commit. Exact activation retry succeeds only if the exact descriptor, approval, PoP and initial SPK are already durably installed and mutually consistent.

No partially activated device may appear in the active device directory without its initial signed prekey. Do not call the device messaging-ready until the initial SPK is available through the directory and the client verifies it.

### One-time prekeys

The database has an `one_time_prekeys` table and the frozen handshake header allows an optional recipient OPK ID. This review did not find a corresponding reviewed enrollment/bootstrap wire contract or complete HTTP publication/consumption path. Therefore:

- OPKs are **not required** for the first V2 activation baseline; the existing X3DH profile permits the optional DH4/OPK input to be absent.
- Do not create fake/dummy OPKs or claim OPK support merely because the table exists.
- Define OPK registration, authenticated bundle retrieval, atomic one-time consumption, replenishment and replay tests in a separate prekey lifecycle contract before advertising OPK-backed forward-secrecy properties.
- Additional SPK rotation/replenishment after activation is a separate authenticated operation. It must be signed by the device DSK, use unique SPK_ID values, validate public keys, and persist under account/device lifecycle checks.

### Cross-language gate

Before V2 freeze, implement the exact Go parser/verifier for `SignedPrekeyV1` or a separately versioned prekey object, with shared Rust/Go/independent-reference vectors. Do not rely on the fact that the Rust module has unit tests as evidence of Gateway verification.

## 5. Corrected target challenge response and PoP binding summary

After Sections 2 and 4 are accepted, the target PoP is bound to:

- the exact descriptor digest (which now includes the initial signed-prekey digest);
- the exact accepted approval digest returned by the Gateway;
- the exact target challenge ID and nonce returned in the same HTTPS response;
- AccountID, DeviceID, EnrollmentID and epoch.

The response transports exact approval bytes; the target independently hashes and verifies them. The Gateway remains authoritative for current account/approver status, durable approval state, challenge freshness/consumption, and activation. No response field replaces those checks.

## 6. Required source-aligned tests added to the V2 acceptance gate

### Approval evidence delivery

- Gateway response approval bytes hash to the returned approval digest.
- Target rejects response approval bytes when any field/signature/digest/EnrollmentID/descriptor binding differs.
- Wrong approver DSK, mismatched approver DeviceID, expired/terminal intent, changed approval bytes, or stale epoch is rejected.
- A target cannot submit its own replacement approval at activation.
- Exact target challenge retry returns the same accepted approval evidence; a replaced challenge invalidates the old nonce without changing the approval.

### User-presence and display

- Confirmation shows the exact target DeviceID/key fingerprints, descriptor fingerprint, epoch, initial SPK ID/fingerprint and Gateway origin.
- Approval signer is not invoked before successful explicit confirmation and the fresh Android system-authentication prompt.
- Cancelled/failed prompt or descriptor change aborts signing.
- The UI and documentation never claim that the current DSK signature is hardware-attested user presence.
- Tests cover stale QR, descriptor substitution, wrong short-authentication string, and approver identity mismatch.

### Signed-prekey bootstrap

- Rust and Go parse/verify identical `SignedPrekeyV1` vectors, including malformed CBOR, wrong domain/signature, changed account/device/epoch/SPK_ID/SPK_pub, low-order X25519 key and integer boundaries.
- Descriptor field 8 digest must match exact initial signed-prekey bytes; re-encoding or substitution fails.
- Activation fails when SPK is absent, invalid, already used, or mismatched.
- PostgreSQL tests prove device, auth row, event, challenge consumption and initial signed_prekey insert are all-or-nothing under rollback/concurrency/lost acknowledgement.
- Active directory/device messaging readiness is not exposed before a valid SPK is committed.
- No OPK claim is made until OPK API and single-use consumption tests exist.

## 7. Implementation order after review

1. Review and accept/reject the field-8 descriptor refinement and approval-evidence response contract.
2. Reconcile the trusted UI and local user-authentication requirement with the native DSK custody model; do not claim hardware-enforced presence without a separate approved design.
3. Add Go `SignedPrekeyV1` parser/verifier and shared vectors before using it in Gateway V2 activation.
4. Define the PostgreSQL V2 intent/challenge rows and insert the initial signed prekey atomically with activation.
5. Only then implement the Gateway endpoints, native signing APIs, Android UI/operation journal and two-device tests on implementation-authorized branches.
6. Keep catastrophic recovery on its separate 48-hour state machine. Ordinary V2 enrollment must reject any pending or recovery-locked account.

## 8. Source references inspected

- `native/crypto-core/src/signed_prekey_v1.rs` — current candidate seven-field SPK signature object and Rust validation.
- `docs/phase0/03-crypto-architecture.md` — PM-BI-X3DH-1 uses the signed prekey; OPK input is optional.
- `services/gateway/migrations/0001_init.sql` — `signed_prekeys` and `one_time_prekeys` tables.
- `services/gateway/internal/devices/lifecycle.go` — persistence-only `DeviceProvisioner.Enroll` accepts signed prekeys and inserts them in one transaction.
- `services/gateway/internal/authorization/enrollment_activation_candidate.go` — existing candidate activation transaction does not insert signed prekeys.
- `services/gateway/internal/devices/directory.go` and `services/gateway/internal/http/device_http.go` — read-only signed-prekey projection.
- `apps/android/app/src/main/java/org/sovereign/pm/security/PlatformKeyProtection.kt` — Keystore wraps the Storage DEK; current key spec has no per-use user-auth requirement.
- `apps/android/app/src/main/java/org/sovereign/pm/crypto/NativeDeviceEnrollmentSession.kt` — DSK/DDHK private material remains in native context; current session is in-memory and certificate binding transient.
- `docs/phase0/13-identity-persistence-v1.md` — Storage DEK/Keystore wrapper boundary and no private identity material in Kotlin.

**Disposition:** Review refinement only — NOT FROZEN. V2 remains design-only; no source changes, migrations, route enablement, or production readiness claims are authorized.
