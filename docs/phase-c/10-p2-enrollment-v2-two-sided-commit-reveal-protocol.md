# P2 Enrollment V2 — Two-Sided Commit/Reveal and Pairing Transcript

**Status:** Protocol refinement proposal — NOT FROZEN
**Review point:** 2026-11-05
**Applies to:** Documents 05–09 in this directory
**Scope:** The local two-device pairing ceremony required before ordinary V2 enrollment approval
**Change class:** Documentation only. No source code, migrations, routes, feature flags, or production configuration are changed or authorized.

> This is a candidate protocol refinement. It is not an independent security audit, cryptographic proof, implementation specification approved for coding, or deployment authorization. All maps, domains, lengths, limits, and state transitions below require independent review before freeze.

## 1. Executive disposition

**Recommendation: replace the descriptor-only SAS proposal with the two-sided protocol specified here, subject to independent review. Keep V2 NOT FROZEN.**

Documents 07 and 08 establish the need for a short code comparison but do not define a complete two-party transcript. Document 09 correctly identifies the missing commitment ordering and expected-approver binding. This document closes that design gap at the proposal level.

The protocol has these properties:

1. The target and approver identities, exact target descriptor, configured Gateway origin, PairingID, and fresh Gateway approval challenge are bound into one canonical PairingContextV2.
2. Both devices commit to independent random nonces before either nonce is revealed.
3. The target reveals only after verifying the approver commitment.
4. The approver reveals only after verifying the target reveal.
5. Both devices derive the same 60-bit SAS from the complete commit/reveal transcript.
6. Both devices must produce a signed positive match-confirmation object before the transcript is eligible for Gateway acceptance.
7. The existing-device approval signature binds both the PairingContextV2 digest and the exact full pairing-transcript digest.
8. The target verifies those digests against its locally stored transcript before creating the final target PoP.

The Gateway approval challenge is issued before the commit/reveal exchange. Its one-use challenge ID and nonce are included in the context. A transcript from an earlier attempt therefore cannot be transplanted into a new approval challenge.

A 60-bit SAS is still a candidate, not a frozen UX or security constant. The attempt budget below is also a candidate operational control and must be validated against the shared Gateway limiter and expected recovery UX.

## 2. Document precedence and compatibility

Read this proposal with Documents 05–09:

- Document 05 remains the P2 policy baseline: one active-device approval is the minimum ordinary-enrollment rule; catastrophic recovery remains separate; PostgreSQL is the Gateway's current-state authority.
- Document 06 remains the base V2 wire and endpoint proposal except where this document explicitly changes the pairing context, approval object, challenge request envelope, and transcript validation.
- Document 07 remains authoritative for exact accepted-approval evidence delivery, trusted-display limitations, the Android user-authentication prompt, and the initial SignedPrekeyV1 bootstrap, except that its descriptor-only SAS is superseded here.
- Document 08 remains authoritative for the descriptor field-8 binding to the exact initial SignedPrekeyV1 bytes, exact raw-byte persistence, and SPK lifecycle gates, except that its 40-bit descriptor-only SAS is superseded here.
- Document 09 remains authoritative for the Gateway trust boundary, KT/lifecycle distinction, SPK lifecycle blockers, database lock-order evidence, retries, and independent-review requirement. This document refines Finding A only; it does not close Findings B–E.

No V1 object or V1 signature transcript changes. The V2 approval object is not frozen or deployed, so the candidate field layout below replaces the earlier nine-field draft rather than introducing an in-place compatibility promise.

## 3. Preconditions and threat boundary

### 3.1 Preconditions

Before pairing starts:

- The target has generated its DeviceID, DSK and DDHK inside the native identity context.
- The target has generated exactly one candidate initial SignedPrekeyV1 object and has its exact canonical bytes.
- The target descriptor is the eight-field proposal from Documents 07–08. Descriptor field 8 is SHA-256 of the exact complete canonical SignedPrekeyV1 bytes.
- The target has selected one expected existing approver from the configured Gateway's authenticated active-device state. It has the expected approver DeviceID, DSK and DDHK public keys. A user-assigned contact label is not an identity authority.
- The existing device is active, non-revoked, in the current authoritative account epoch, and authenticated to the Gateway using PM-Device-V1.
- The configured Gateway origin is HTTPS and is the same origin to which the approval challenge is requested.

If the target cannot identify the expected approver public keys, or the expected approver cannot verify the target's exact descriptor and initial signed prekey, pairing stops.

### 3.2 Threat boundary

This ceremony is designed to make a pairing-channel substitution visible when at least one endpoint and its DSK remain trustworthy and the user compares the independently displayed SAS over the intended physical/local interaction.

It does not protect against:

- a compromised target or approver application that can invoke the relevant DSK signing operation;
- compromise of either endpoint's native key custody;
- a malicious/compromised configured Gateway or its PostgreSQL authority;
- a user who ignores a mismatch, confirms without comparing, or compares codes over the same attacker-controlled display/channel;
- a relay that the user cannot distinguish from the intended physical pairing interaction.

The signed positive-confirmation objects record an application-level acknowledgement. They are not remote proof of human presence, biometric verification, or a hardware-enforced approval event. Document 07's user-presence limitation remains in force.

## 4. Canonical encoding and common rules

All objects in this document are candidates using PM-CBOR-2026. Apply the repository's deterministic encoding rules:

- Definite-length maps and byte/text strings only; no floats, duplicate keys, non-minimal integers, indefinite lengths, trailing bytes, or unknown fields.
- Integer map keys are exactly the keys listed for each object. Reject missing, extra, duplicate, or wrong-type fields.
- Validate the exact supplied canonical bytes. Never decode and re-encode untrusted input to repair it.
- IDs are nonzero 16-byte strings. Ed25519 public keys are 32 bytes and signatures are 64 bytes. Nonces and digests are 32 bytes.
- Epoch is in 1..=2^32-1, with checked conversion at every Rust/Go/database boundary.
- Role values are fixed: 1 = target, 2 = approver.
- Every domain string below is exact ASCII, versioned, and concatenated directly with the specified canonical bytes. There is no implicit separator.
- Each nonce is generated independently with the platform CSPRNG. Neither nonce may be derived from the other nonce, a timestamp, a PairingID, or user input.

### 4.1 Canonical Gateway origin

The Gateway origin is included as a text string in the pairing context. Its candidate canonical form is an ASCII HTTPS origin only: https:// followed by a canonical host and, only when non-default, a canonical decimal port.

Canonicalization requirements:

- Scheme is exactly lowercase https.
- DNS names are lowercase IDNA2008 A-labels with no trailing dot.
- IPv4 literals use canonical dotted-decimal form.
- IPv6 literals use RFC 5952 text form enclosed in brackets.
- Port is omitted for 443; a non-default port is decimal with no leading zero.
- User information, path, query, fragment, whitespace, percent-encoding, and trailing slash are forbidden.

Both applications compare the origin byte-for-byte with their configured Gateway origin and display the host/port to the user. The target rejects a handoff for a different origin. The Gateway rejects a transcript whose origin does not match the configured origin handling this request. A shared Rust/Go origin canonicalization vector set is a freeze gate; do not implement separate ad hoc normalizers.

## 5. Pairing setup and Gateway challenge

### Step 1 — Target creates a PairingID and handoff offer

The target generates one fresh nonzero 16-byte PairingID using its CSPRNG. It creates a pairing offer containing:

- PairingID;
- exact canonical DeviceEnrollmentDescriptorV2 bytes;
- exact canonical initial SignedPrekeyV1 bytes.

The target shares these public bytes with the selected existing device over a bidirectional pairing transport. QR may be used for the initial target-to-approver transfer, but the ceremony requires a return path for the approver challenge handoff and all subsequent messages. A sequence of QR transfers, NFC, Bluetooth, or another local transport is possible. The transport is untrusted: signatures, exact-byte checks, commitment ordering, and SAS comparison provide the protocol checks.

The offer contains no private key, recovery mnemonic, recovery private key, or secret identity material.

### Step 2 — Approver requests a fresh Gateway approval challenge

After verifying the exact descriptor and initial signed-prekey bytes, the existing device calls the proposed endpoint:

POST /v2/device-enrollments/approval-challenges

The PM-Device-V1-authenticated raw JSON body carries:

- pairing_id_hex: lowercase hex encoding of the target-generated PairingID;
- descriptor_cbor_hex: exact canonical descriptor bytes;
- initial_signed_prekey_cbor_hex: exact canonical SignedPrekeyV1 bytes.

The Gateway must:

1. Verify the outer PM-Device-V1 request and require that its authenticated principal is the expected active approver.
2. Strictly parse and validate the descriptor and initial signed-prekey bytes, including descriptor field 8 and the exact SPK digest.
3. Check the account is active, has no pending catastrophic recovery, and the proposed epoch is current.
4. Check the target DeviceID is not already active or conflicting.
5. Check the authenticated approver is active, non-revoked, and in the same authoritative epoch.
6. Reserve the PairingID for this exact account, target, approver, descriptor and SPK tuple. A PairingID cannot be rebound to different bytes or a different approver.
7. Create a fresh one-use approval challenge ID and 32-byte nonce, with a proposed five-minute lifetime measured using PostgreSQL time.
8. Persist the challenge binding and return the exact same challenge on an exact idempotent retry.

The challenge response must include the challenge ID, nonce, expiry, authoritative approver DeviceID/DSK/DDHK, and canonical Gateway origin. A retry carrying the same PairingID and byte-identical descriptor/SPK/approver binding returns the same challenge outcome. A changed request for that PairingID is a conflict. An expired or consumed PairingID is not silently renewed.

The target-generated PairingID is an identifier, not a bearer authorization token.

### Step 3 — Approver creates a signed challenge handoff

The approver creates a canonical PairingChallengeHandoffV2 containing:

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Version |
| 2 | bstr(16) | PairingID |
| 3 | bstr(16) | AccountID |
| 4 | uint | Proposed/current account epoch |
| 5 | bstr(16) | EnrollmentID |
| 6 | bstr(32) | Descriptor digest |
| 7 | bstr(16) | Target DeviceID |
| 8 | bstr(32) | Target DSK public key |
| 9 | bstr(32) | Target DDHK public key |
| 10 | bstr(16) | Gateway approval challenge ID |
| 11 | bstr(32) | Exact Gateway approval challenge nonce |
| 12 | bstr(16) | Approver DeviceID |
| 13 | bstr(32) | Approver DSK public key |
| 14 | bstr(32) | Approver DDHK public key |
| 15 | tstr | Canonical Gateway origin |
| 16 | bstr(64) | Approver DSK signature |

Signature transcript:

    ASCII("PM-V2-PAIRING-CHALLENGE-HANDOFF-v2") || canonical_cbor(fields_1_to_15)

The approver signs this object using the narrow native enrollment-pairing signing operation. This signature does not approve the enrollment. It authenticates the challenge handoff and the approver identity before the target creates its commitment.

The approver returns the exact canonical handoff bytes to the target. The target verifies the signature against the expected approver DSK obtained from the configured Gateway's active-device state, and compares every handoff field against its own descriptor, initial SPK, selected approver, PairingID, and configured Gateway origin. Any mismatch aborts.

## 6. PairingContextV2

After validating the signed challenge handoff, both devices construct the same canonical PairingContextCoreV2:

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Version |
| 2 | uint = 1 | Purpose: ordinary additional-device enrollment |
| 3 | bstr(16) | PairingID |
| 4 | bstr(16) | AccountID |
| 5 | uint | Proposed/current account epoch |
| 6 | bstr(16) | EnrollmentID |
| 7 | bstr(32) | Descriptor digest, including descriptor field 8 |
| 8 | bstr(16) | Target DeviceID |
| 9 | bstr(32) | Target DSK public key |
| 10 | bstr(32) | Target DDHK public key |
| 11 | bstr(16) | Expected approver DeviceID |
| 12 | bstr(32) | Expected approver DSK public key |
| 13 | bstr(32) | Expected approver DDHK public key |
| 14 | tstr | Canonical configured Gateway origin |
| 15 | bstr(16) | Gateway approval challenge ID |
| 16 | bstr(32) | Gateway approval challenge nonce |

The bytes in fields 3–16 must exactly match the target descriptor, signed challenge handoff, and configured local state. The approver independently checks that fields 11–13 are its own active identity and that fields 8–10 match the target descriptor.

Compute:

    pairing_context_digest = SHA-256(ASCII("PM-V2-PAIRING-CONTEXT-v2") || exact_canonical_PairingContextCoreV2_bytes)

Both devices retain the exact context bytes and digest. A PairingID, challenge ID, nonce, descriptor, approver, target identity, epoch, or Gateway origin change creates a different context and invalidates the current attempt.

The initial signed-prekey digest is not repeated as a separate context field because it is already committed by descriptor field 8 and therefore by the descriptor digest. Both clients must still validate the exact SignedPrekeyV1 bytes before accepting the descriptor.

## 7. Two-sided commitment and reveal

### 7.1 PairingCommitV2

Each endpoint creates one independent 32-byte random nonce:

- target nonce: target_nonce;
- approver nonce: approver_nonce.

The nonce is not sent until the reveal phase. Each endpoint computes a commitment over a canonical map:

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Version |
| 2 | uint | Role: 1 target, 2 approver |
| 3 | bstr(32) | PairingContext digest |
| 4 | bstr(32) | Endpoint nonce |

For each role, compute:

    nonce_commitment = SHA-256(ASCII("PM-V2-PAIRING-NONCE-COMMIT-v2") || canonical_cbor(fields_1_to_4))

The signed PairingCommitV2 object is:

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Version |
| 2 | uint | Role |
| 3 | bstr(32) | PairingContext digest |
| 4 | bstr(32) | Nonce commitment |
| 5 | bstr(64) | Role endpoint's DSK signature |

Signature transcript:

    ASCII("PM-V2-PAIRING-COMMIT-v2") || canonical_cbor(fields_1_to_4)

The signature is verified against the role's public DSK in PairingContextCoreV2. A role/key mismatch is fatal.

Compute each commit digest over the exact complete canonical signed object:

    commit_digest = SHA-256(ASCII("PM-V2-PAIRING-COMMIT-DIGEST-v2") || exact_canonical_PairingCommitV2_bytes)

### 7.2 Exact message order

The only accepted order is:

1. **Target commits.** The target sends its signed PairingCommitV2. It has not revealed target_nonce.
2. **Approver commits.** The approver verifies the target commitment and signature, then creates and sends its own signed PairingCommitV2. It has not revealed approver_nonce.
3. **Target reveals.** The target verifies the approver commitment and signature. Only then does it send TargetPairingRevealV2 containing target_nonce and digests of both exact signed commit objects.
4. **Approver reveals.** The approver verifies the target reveal, including opening the target commitment. Only then does it send ApproverPairingRevealV2 containing approver_nonce, both commit digests, and the target-reveal digest.
5. **Target verifies.** The target verifies the approver reveal, opens the approver commitment, and checks every digest/reference and role.
6. **Both derive SAS.** Each endpoint derives the SAS from the same validated context, commit digests, and reveal digests.
7. **Both confirm.** The endpoints display the SAS and identity fingerprints. Each requires a deliberate local user action confirming that the two displayed SAS values were compared and match. Each signs a PairingMatchConfirmationV2. Both signed confirmations are required.

No endpoint may reveal its nonce before receiving and verifying the counterpart's commitment. No endpoint may sign a positive match confirmation before validating both reveals and displaying the same computed SAS. Receiving the same QR payload on both screens is not a SAS comparison.

### 7.3 TargetPairingRevealV2

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Version |
| 2 | uint = 1 | Target role |
| 3 | bstr(32) | PairingContext digest |
| 4 | bstr(32) | Exact target commit digest |
| 5 | bstr(32) | Exact approver commit digest |
| 6 | bstr(32) | Target nonce |
| 7 | bstr(64) | Target DSK signature |

Signature transcript:

    ASCII("PM-V2-PAIRING-REVEAL-TARGET-v2") || canonical_cbor(fields_1_to_6)

The target's signature is verified against the target DSK in PairingContextCoreV2. The receiver recomputes the target nonce commitment and compares it with the target commit.

### 7.4 ApproverPairingRevealV2

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Version |
| 2 | uint = 2 | Approver role |
| 3 | bstr(32) | PairingContext digest |
| 4 | bstr(32) | Exact target commit digest |
| 5 | bstr(32) | Exact approver commit digest |
| 6 | bstr(32) | Exact target reveal digest |
| 7 | bstr(32) | Approver nonce |
| 8 | bstr(64) | Approver DSK signature |

Signature transcript:

    ASCII("PM-V2-PAIRING-REVEAL-APPROVER-v2") || canonical_cbor(fields_1_to_7)

The receiver verifies the approver signature against the approver DSK in PairingContextCoreV2, verifies the target-reveal digest and both commit digests, and recomputes the approver nonce commitment.

Compute either exact reveal object's digest as:

    reveal_digest = SHA-256(ASCII("PM-V2-PAIRING-REVEAL-DIGEST-v2") || exact_canonical_signed_reveal_bytes)

### 7.5 PairingMatchConfirmationV2

After both reveals are verified and the SAS has been displayed, each endpoint may create:

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Version |
| 2 | uint | Role |
| 3 | bstr(32) | PairingContext digest |
| 4 | bstr(32) | Preconfirmation transcript digest |
| 5 | uint = 1 | Positive local decision: SAS comparison confirmed |
| 6 | bstr(64) | Role endpoint's DSK signature |

Signature transcript:

    ASCII("PM-V2-PAIRING-MATCH-CONFIRM-v2") || canonical_cbor(fields_1_to_5)

The preconfirmation transcript is the canonical map with these exact fields:

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Version |
| 2 | bstr | Exact PairingChallengeHandoffV2 bytes |
| 3 | bstr | Exact PairingContextCoreV2 bytes |
| 4 | bstr | Exact signed target PairingCommitV2 bytes |
| 5 | bstr | Exact signed approver PairingCommitV2 bytes |
| 6 | bstr | Exact signed TargetPairingRevealV2 bytes |
| 7 | bstr | Exact signed ApproverPairingRevealV2 bytes |

Compute:

    preconfirmation_transcript_digest = SHA-256(ASCII("PM-V2-PAIRING-PRECONFIRM-TRANSCRIPT-v2") || exact_canonical_PreconfirmationTranscriptV2_bytes)

The target confirmation is verified with the target DSK; the approver confirmation is verified with the approver DSK. Missing, mismatching, duplicate, or invalid confirmations abort. There is no positive confirmation object for a mismatch; the attempt is abandoned and the approval challenge expires or is explicitly invalidated under a separately reviewed lifecycle operation.

These signatures attest only that the endpoint application signed a positive decision. They do not establish that a human actually compared the displays or that the signing key was hardware-gated.

## 8. Exact full pairing transcript and SAS

### 8.1 PairingTranscriptV2

The final canonical PairingTranscriptV2 is a map containing the exact raw canonical bytes of every signed object:

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Version |
| 2 | bstr | PairingChallengeHandoffV2 bytes |
| 3 | bstr | PairingContextCoreV2 bytes |
| 4 | bstr | Signed target PairingCommitV2 bytes |
| 5 | bstr | Signed approver PairingCommitV2 bytes |
| 6 | bstr | Signed TargetPairingRevealV2 bytes |
| 7 | bstr | Signed ApproverPairingRevealV2 bytes |
| 8 | bstr | Signed target PairingMatchConfirmationV2 bytes |
| 9 | bstr | Signed approver PairingMatchConfirmationV2 bytes |

All fields are mandatory. The Gateway validates every nested object and exact byte relationship. It does not accept a client-supplied digest as a substitute for the raw transcript.

Compute:

    pairing_transcript_digest = SHA-256(ASCII("PM-V2-PAIRING-TRANSCRIPT-v2") || exact_canonical_PairingTranscriptV2_bytes)

The approver and target persist the exact transcript bytes and digest in their encrypted operation journals. These are public protocol objects; no private key or recovery secret is stored in the transcript.

### 8.2 SAS derivation and encoding

After verifying both commitments and both reveals, each endpoint computes:

    sas_digest = SHA-256(ASCII("PM-V2-ENROLLMENT-SAS-v2") || pairing_context_digest || target_commit_digest || approver_commit_digest || target_reveal_digest || approver_reveal_digest)

Take exactly the first 60 bits of sas_digest, most-significant bit first. Encode those 60 bits as exactly twelve 5-bit symbols using the Crockford Base32 alphabet:

    0123456789ABCDEFGHJKMNPQRSTVWXYZ

Display uppercase as:

    XXXX-XXXX-XXXX

No aliases, case folding, whitespace normalization, locale digit substitution, modulo reduction, or alternate grouping is allowed in the canonical value. The implementation must define extraction by bit position, not by integer conversion that could vary across languages.

Both screens display the same 12-symbol SAS and, alongside it, the target DeviceID/fingerprint, approver DeviceID/fingerprint, account epoch, SPK_ID/SPK fingerprint, and configured Gateway origin. The user must compare the complete twelve symbols across the intended local/physical interaction. A missing display, any difference, unexpected identity/origin, timeout, or uncertainty means abort. Do not truncate the string for accessibility layouts; provide a readable full-screen comparison mode.

The SAS is public and is not a password or secret. The full 256-bit digests and signatures remain the cryptographic bindings; the SAS is only a human-verifiable comparison value.

### 8.3 Candidate attempt budget

A commitment exchange must not become an unlimited online guessing oracle. Candidate initial controls:

- One active PairingID per EnrollmentID at a time.
- A PairingID is unique and single-use. It cannot be rebound or restarted with different bytes.
- At most three distinct approval-challenge PairingIDs for the same AccountID + target DeviceID + approver DeviceID tuple in a rolling 15-minute window. A fourth attempt is rejected with the stable rate-limit class.
- The quota is enforced in shared PostgreSQL-backed Gateway state across instances and also applies when the caller changes EnrollmentID, PairingID, or outer PM-Device-V1 nonce for the same tuple.
- Existing shared ingress/account/device rate limits continue to apply. Limiter storage failure follows the fail-closed policy in Document 05.
- Exact retry of the same PairingID and byte-identical request returns the same existing challenge; it does not consume another attempt.
- A changed transcript, descriptor, SPK, approver, or context for an existing PairingID is a conflict, not a new attempt.

These numeric limits are candidates for capacity and usability review, not frozen policy. The attempt budget must be tested under at least two Gateway instances and actual PostgreSQL concurrency.

## 9. Approval object and endpoint binding

### 9.1 Revised DeviceEnrollmentApprovalV2 candidate

The earlier nine-field proposal placed the signature in field 9. Replace it with this eleven-field candidate so the pairing digests are part of the signed core:

| Key | Type | Meaning |
|---:|---|---|
| 1 | uint = 2 | Version |
| 2 | bstr(16) | AccountID |
| 3 | bstr(16) | Approving DeviceID |
| 4 | uint | Account epoch |
| 5 | bstr(16) | EnrollmentID |
| 6 | bstr(32) | Descriptor digest |
| 7 | bstr(16) | Gateway approval challenge ID |
| 8 | bstr(32) | Exact Gateway approval challenge nonce |
| 9 | bstr(32) | PairingContextV2 digest |
| 10 | bstr(32) | Full PairingTranscriptV2 digest |
| 11 | bstr(64) | Approver DSK signature |

Signature transcript:

    ASCII("PM-V2-DEVICE-ENROLL-APPROVAL-v2") || canonical_cbor(fields_1_to_10)

The Gateway requires fields 7–10 to match the challenge, persisted descriptor, validated transcript, expected approver, and accepted intent. The signature key is always loaded from authoritative PostgreSQL authorization state; never trust a caller-supplied key.

The existing DeviceEnrollmentPoPV2 candidate does not need additional pairing fields: its field 7 is the SHA-256 digest of the exact complete signed DeviceEnrollmentApprovalV2 bytes, which transitively binds fields 9 and 10. The target must nevertheless compare those fields against its locally persisted pairing context/transcript before signing PoP.

### 9.2 Approval-challenge request and response

The approval-challenge request adds pairing_id_hex to the existing exact descriptor/SPK body. The Gateway challenge response includes:

- approval challenge ID and nonce;
- database-issued expiry;
- authoritative approver DeviceID, DSK and DDHK;
- canonical Gateway origin;
- PairingID and descriptor digest echoed from persisted state.

The approver constructs the signed PairingChallengeHandoffV2 from those values and transfers it to the target. The challenge nonce is public; its security value comes from one-use server state, exact transcript binding, and expiry.

### 9.3 Approval acceptance

The PM-Device-V1-authenticated approval request carries the exact canonical DeviceEnrollmentApprovalV2 bytes and the exact PairingTranscriptV2 bytes (for example as lowercase-hex fields in the authenticated JSON envelope).

Candidate size ceilings for review: PairingTranscriptV2 is at most 4 KiB of canonical CBOR; its lowercase-hex envelope field is at most 8 KiB of text. The complete JSON body must remain within the existing Gateway request-body ceiling. Confirm the actual middleware limits and reject over-limit input before allocation; do not silently increase a shared HTTP body limit.

At acceptance, the Gateway must:

1. Verify the PM-Device-V1 principal is the exact approver in the approval object and PairingContextCoreV2.
2. Verify the account, epoch, approver status, target descriptor and initial SPK against authoritative state.
3. Verify PairingChallengeHandoffV2 under the approver DSK and compare it to the persisted challenge row.
4. Verify the PairingContextCoreV2 exact bytes and digest, including the challenge ID/nonce and canonical Gateway origin.
5. Verify both commit signatures, role identities, commitment hashes, and exact commit digests.
6. Verify both reveal signatures, both nonce openings, the target-reveal linkage, and both exact reveal digests.
7. Recompute the SAS using the specified transcript formula; the Gateway does not infer that a human compared it.
8. Verify both positive match-confirmation signatures and their common preconfirmation transcript digest.
9. Verify the full PairingTranscriptV2 canonical encoding and digest.
10. Verify the revised DeviceEnrollmentApprovalV2 signature over fields 1–10.
11. Atomically consume the approval challenge and persist exact descriptor, initial SPK, approval and pairing-transcript bytes/digests as immutable evidence. Re-check account and approver state under the established account-first lock order.

The approval challenge row's original binding fields remain immutable. The validated PairingContext/Transcript digests are persisted as immutable accepted evidence associated with the consumed challenge and intent; do not mutate challenge identity/binding columns after creation.

A lost-response retry uses a fresh outer PM-Device-V1 timestamp/nonce/signature but preserves the exact inner approval bytes and exact pairing transcript bytes. Changed inner bytes for the same PairingID/EnrollmentID fail closed.

### 9.4 Target-side accepted-approval checks

Extend Document 07's accepted-approval response with:

- PairingID;
- PairingContext digest;
- PairingTranscript digest;
- authoritative approver DeviceID, DSK and DDHK;
- exact approval bytes and approval digest already required by Document 07.

Before creating DeviceEnrollmentPoPV2, the target must verify the returned approval signature and require:

- approval field 9 equals the target's locally computed PairingContext digest;
- approval field 10 equals the digest of the target's exact locally stored PairingTranscriptV2 bytes;
- the returned approver identity equals the expected approver identity selected before pairing;
- the transcript includes both valid positive match-confirmation signatures;
- the transcript challenge ID/nonce equal the exact Gateway challenge bound to the approval.

A different approver, transcript, PairingID, context, descriptor, SPK, epoch, challenge, or Gateway origin is a hard rejection. Do not accept a server-returned pairing digest merely because it is syntactically valid.

## 10. State, retry, cancellation, and crash rules

- Pairing is a single-use sub-protocol bound to one EnrollmentID, PairingID, descriptor, approver, Gateway origin and approval challenge.
- Exact duplicate message bytes at the same expected state are idempotent. Different bytes for an already accepted role/state, out-of-order reveal, role reflection, missing commit, duplicate nonce, or mismatching digest is a terminal failure for that PairingID.
- Neither device regenerates a nonce, commitment, reveal, confirmation, or approval object to retry a transport operation. Retry the exact stored bytes.
- If process death occurs, restore the exact public protocol objects and state from the encrypted Android operation journal. Do not restart from a later state with regenerated values.
- If the journal is incomplete or integrity checks fail, abort the attempt. A new attempt requires a new PairingID and consumes the shared attempt budget.
- A user mismatch or uncertain comparison aborts. Do not create a positive confirmation. The unused Gateway approval challenge expires or is invalidated using a separately reviewed one-way state transition.
- The approval challenge expires after the proposed five minutes using PostgreSQL time. Expired challenges cannot be revived; a new PairingID and a new challenge are required.
- A successful approval consumes the approval challenge once and freezes the exact accepted transcript/approval evidence. An identical retry returns the same accepted outcome; changed bytes conflict.
- Catastrophic recovery remains a separate 48-hour state machine and is never a fallback inside this ceremony.

## 11. Required adversarial and interoperability tests

### Commitment and reveal

- Target reveal before approver commitment is rejected.
- Approver reveal before validating target reveal is rejected.
- Wrong role, wrong DSK, reflected commit, replaced commit, mismatched context digest, wrong commit digest, invalid nonce opening, and altered reveal bytes are rejected.
- A target commitment from PairingID A cannot be combined with an approver commitment or reveal from PairingID B.
- A transcript from an expired approval challenge cannot be accepted under a new challenge ID/nonce.
- Reusing the same nonce under a different role, context, PairingID, descriptor, approver, or Gateway origin does not validate.
- No positive confirmation is accepted until both reveals validate and the SAS is computed.

### Identity and context substitution

Independently substitute AccountID, epoch, EnrollmentID, PairingID, descriptor digest, target DeviceID, target DSK, target DDHK, approver DeviceID, approver DSK, approver DDHK, approval challenge ID, approval nonce, and Gateway origin. Both clients and the Gateway must reject every mismatch.

- Substitute the initial SignedPrekeyV1 bytes while preserving descriptor field 8; reject.
- Substitute descriptor field 8 while preserving the SPK object; reject.
- Pair the same target with a different existing approver; reject.
- Relay the handoff to another concurrent pairing attempt; reject.
- Reuse an old PairingChallengeHandoff with a new challenge; reject.

### SAS and encoding

- Produce identical Rust, Go, Android and independent-reference vectors for context digest, nonce commitments, commit digests, reveal digests, preconfirmation transcript digest, full transcript digest and SAS.
- Verify first-60-bit extraction, most-significant-bit order, Crockford Base32 alphabet, grouping, and no-alias parsing.
- Include vectors with high-bit boundary values to catch byte-order and bit-shift errors.
- A mismatch, absent peer confirmation, incomplete code display, or user abort must never invoke the approval signer.

### Retry, quota and database behavior

- Exact approval-challenge retry returns the same challenge; changed bytes for the same PairingID conflict.
- Lost response after challenge creation is recoverable without a second quota charge.
- A fourth new PairingID within the candidate attempt window is rejected for the same account/target/approver tuple.
- Attempt limits are shared across two Gateway instances and cannot be bypassed by changing EnrollmentID or outer PM-Device-V1 nonce.
- Exact inner approval/transcript retry with a fresh outer PM-Device-V1 proof returns the same accepted intent.
- Reused outer PM-Device-V1 nonce is rejected.
- Concurrent approval, challenge expiry, cancellation, revocation, recovery begin, recovery abort, and activation tests use real PostgreSQL and the account-first lock order.
- Transaction rollback leaves no partially accepted transcript, consumed challenge, active device, initial SPK row, or messaging-ready state.

### UI and human verification

- Both screens show the target and approver identities/fingerprints, epoch, SPK ID/fingerprint, Gateway origin, and full SAS.
- QR scan alone never confirms a match.
- A local user action is required on both devices after the display comparison.
- Missing confirmation on either device, cancellation, app backgrounding before confirmation, or a code mismatch aborts.
- UX testing measures transcription/comparison errors for twelve Crockford symbols. A longer code is not automatically safer if users cannot compare it accurately.

## 12. Freeze gates and unresolved decisions

This document closes only the written pairing-transcript gap at proposal level. It does not close the other P2 freeze gates.

Before any implementation authorization:

1. Independently review the exact commit/reveal transcript, signed object maps, domain separation, nonce commitments, SAS extraction, and online attempt budget.
2. Ratify the canonical Gateway-origin algorithm and create cross-language vectors.
3. Ratify the 60-bit SAS length and two-device comparison UX using actual usability testing; do not freeze the length based only on this document.
4. Ratify the three-attempt/15-minute candidate budget against abuse analysis and recovery UX.
5. Reconcile the extended DeviceEnrollmentApprovalV2 map and approval-challenge persistence with Documents 05–09.
6. Prove Gateway validation and database transaction behavior using real PostgreSQL race, replay, replacement, and lost-response tests.
7. Complete the SPK private-key lifecycle and native identity-store versioning gates in Document 09.
8. Ratify the trusted-Gateway-only threat model or separately design the account-level lifecycle/transparency authorization bridge. Do not conflate KT's 2-of-3 quorum with the separate lifecycle-witness proposal.
9. Obtain an independent protocol/security review from a reviewer who did not author this design. Record findings and dispositions.

No application code, SQL migration, candidate endpoint, route enablement, Android UI, native signing FFI, or ratchet persistence work is authorized by this document.

## 13. Final disposition

**Proposed disposition: REVISE BEFORE FREEZE; do not implement yet.**

The two-sided commit/reveal ordering, exact pairing transcript, pairwise SAS derivation, signed local confirmations, and approval-object bindings are now specified as a candidate wire design. They remain subject to external review and interoperability testing. A green GitHub Actions run validates repository checks; it does not validate this protocol's security.

The PR must remain Draft and unmerged until all design freeze gates, including independent review, are explicitly closed.
