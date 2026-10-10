# 10 - Key Transparency

Status: ARCHITECTURAL (frozen concept); implementation NOT STARTED (sequenced after the handshake, ratchet, media and push boundaries).

Append-only structure: Sparse Merkle Tree, Signed Tree Heads, witnesses, client high-water mark.

| State | Examples | Messaging |
|---|---|---|
| VERIFIED | all checks succeed | allowed |
| DEGRADED | witness timeout, temporary network loss, incomplete quorum with valid cached state | continues |
| SECURITY FAILURE | rollback, stale tree head, inclusion-proof mismatch, conflicting STHs (equivocation), uncommitted identity parameters | outbound messaging to the affected identity BLOCKED |

Transparency leaves are signed structures: unknown cryptographic fields cause parse failure
(PM-CBOR-2026 Rule 7).

---

# Key Transparency V1 Specification Proposal

**Status:** PROPOSED â€” NOT FROZEN
**Implementation:** NOT STARTED
**Vectors:** PLACEHOLDER ONLY

This section extends the existing KT policy above. It is a proposal for review; it does not silently change the frozen policy or authorize implementation.

## 1. Existing repository boundaries

The KT design must reuse these existing rules:

- AccountID and DeviceID remain distinct.
- DSK is Ed25519; DDHK is X25519.
- Cert_dh already binds AccountID, DeviceID, DDHK_pub, and timestamp under the device DSK.
- KT wire objects use PM-CBOR-2026.
- Unknown cryptographic fields fail closed.
- The backend publishes transparency information but never decrypts E2EE content.
- Client states remain VERIFIED, DEGRADED, and SECURITY_FAILURE.
- The client high-water value never moves backwards.

## 2. Threat model

KT must detect:

1. Different identity parameters presented to different clients.
2. Rollback to an older accepted tree state.
3. Stale or invalid Signed Tree Heads.
4. Invalid inclusion or consistency proofs.
5. Conflicting valid STHs or witness statements.
6. Uncertified identity or prekey parameters.
7. Malformed or unknown cryptographic fields.
8. Silent rewriting of historical identity state.

Cryptographic failure, rollback, and confirmed equivocation must fail closed for the affected identity.

## 3. TransparencyLeafV1

**PROPOSED â€” new architectural decision.**

A leaf represents one immutable published identity state.

Candidate field map:

| Field | Type | Meaning |
|---|---|---|
| 1 | bstr(16) | AccountID |
| 2 | uint | account epoch |
| 3 | bstr(16) | DeviceID |
| 4 | bstr(32) | DSK public key |
| 5 | bstr(32) | DDHK public key |
| 6 | bstr(64) | Cert_dh |
| 7 | uint64 | publication/certification timestamp |
| 8 | uint | leaf sequence |
| 9 | bstr | version/metadata identifier |
| 10 | bstr(64) | authorization signature |

The field numbers, authorization model, and exact account/device semantics are proposed and must be frozen before implementation.

A later identity change creates a new immutable state; an existing leaf is never rewritten.

## 4. Leaf signature and hash

Candidate signature transcript:

    "PM-KT-LEAF-V1" || canonical_leaf_bytes_without_signature

Candidate leaf hash:

    SHA-256("PM-KT-LEAF-HASH-v1" || canonical_leaf_bytes)

A dedicated KT domain is proposed. Existing protocol domains must not be repurposed.

## 5. Sparse Merkle Tree

The repository freezes the use of a Sparse Merkle Tree but not its exact parameters.

Parameters requiring explicit freeze:

- tree depth;
- leaf-key derivation;
- empty-node construction;
- internal-node hashing;
- proof format.

Candidate V1:

    tree depth = 256
    leaf key = SHA-256("PM-KT-KEY-v1" || AccountID || DeviceID || Epoch)
    node hash = SHA-256("PM-KT-NODE-v1" || left || right)

Candidate empty-node construction:

    EmptyHash[0] = SHA-256("PM-KT-EMPTY-LEAF-v1")
    EmptyHash[d+1] = SHA-256(
        "PM-KT-EMPTY-NODE-v1" || EmptyHash[d] || EmptyHash[d]
    )

These are proposals, not frozen constants.

## 6. Signed Tree Head

**PROPOSED â€” new architectural decision.**

An STH commits to one exact tree state.

Candidate fields:

| Field | Type | Meaning |
|---|---|---|
| 1 | uint | protocol version |
| 2 | uint64 | tree sequence / tree size |
| 3 | bstr(32) | SMT root hash |
| 4 | uint64 | creation timestamp |
| 5 | bstr | transparency-log identifier |
| 6 | bstr(64) | log signature |

Candidate signature transcript:

    "PM-KT-STH-V1" || canonical_STH_body_without_signature

The STH signing key should be a dedicated transparency-log key, not a user/device DSK.

## 7. Inclusion and consistency proofs

An inclusion proof must show that a specific leaf reconstructs exactly to the STH root through the Sparse Merkle Tree path.

Candidate logical contents:

    leaf_key
    leaf_hash
    siblings[tree_depth]
    leaf_sequence

A consistency proof must establish the required append-only relationship between an older accepted STH and a newer STH.

**Critical open decision:** the exact consistency-proof algorithm is not currently frozen and must be selected before implementation.

Failure of an inclusion or consistency proof is SECURITY_FAILURE.

## 8. Witnesses and quorum

Witnesses independently observe STHs and sign statements about the tree state.

Candidate witness transcript:

    "PM-KT-WITNESS-V1" ||
    log_id ||
    tree_sequence ||
    root_hash

Witness identities and trust configuration must be defined independently of user identity keys.

The repository requires a distinction between full quorum and incomplete quorum, but the exact numeric threshold is not frozen.

Candidate deployment model:

- 3 configured witnesses;
- 3/3 valid statements -> VERIFIED;
- incomplete but non-conflicting evidence -> DEGRADED;
- conflicting valid statements -> SECURITY_FAILURE.

This remains a proposal.

## 9. Equivocation

At minimum, equivocation includes:

- same log identity signing different roots for the same sequence;
- incompatible valid STHs;
- conflicting valid witness statements for the same claimed tree state.

Confirmed equivocation is SECURITY_FAILURE.

The client should retain conflicting STHs, signatures, and witness statements as evidence. A later STH must not automatically erase the security failure.

## 10. High-water and state rules

The existing high-water policy remains authoritative:

    received_sequence < cached_high_water
        => SECURITY_FAILURE

Equal or newer sequences pass the high-water policy check.

High-water may only advance.

The existing VERIFIED / DEGRADED / SECURITY_FAILURE policy is retained without change.

## 11. Relationship to Cert_dh

KT does not replace Cert_dh.

Cert_dh proves the cryptographic binding of:

    AccountID + DeviceID + DDHK_pub

under the device DSK.

KT proves that the directory transparently and consistently publishes the accepted identity state.

These are separate security properties.

## 12. PM-CBOR requirements

Every KT wire object must:

1. use PM-CBOR-2026;
2. use a fixed field map;
3. reject unknown cryptographic fields;
4. reject duplicate keys;
5. reject non-canonical encoding;
6. reject trailing bytes;
7. reject malformed integer encodings;
8. validate the original received bytes before cryptographic interpretation.

Signature verification must operate over the precisely specified canonical bytes.

## 13. Vector boundary

The existing repository already reserves:

- PM-KT-LEAF
- PM-KT-EQUIVOCATION

They remain PLACEHOLDER_LOCKED until the protocol is frozen.

After freeze, vectors must cover:

- valid and invalid leaves;
- canonical and non-canonical CBOR;
- altered identity fields;
- altered signatures;
- leaf-key derivation;
- SMT roots and paths;
- valid and invalid STHs;
- inclusion proofs;
- consistency proofs;
- rollback;
- same-sequence/different-root equivocation;
- conflicting witness statements.

The independent Python generator/checker should remain the reference cross-check, with Rust tested against the resulting vectors.

## 14. Freeze gate

Implementation must NOT begin until these are explicitly frozen:

| Decision | Status |
|---|---|
| Identity model | FROZEN |
| PM-CBOR-2026 usage | FROZEN |
| Cert_dh binding | FROZEN |
| KT state machine | FROZEN |
| TransparencyLeafV1 field map | PROPOSED |
| Leaf signature authority/transcript | PROPOSED |
| Leaf hash domain | PROPOSED |
| SMT key derivation | PROPOSED |
| SMT depth and node hashing | PROPOSED |
| Empty-node rules | PROPOSED |
| STH field map | PROPOSED |
| STH signature transcript | PROPOSED |
| Inclusion proof format | PROPOSED |
| Consistency proof algorithm | OPEN / CRITICAL |
| Witness statement format | PROPOSED |
| Witness quorum | PROPOSED |
| Equivocation evidence model | PROPOSED |
| KT vector schema | PROPOSED |

**Implementation rule:** this file is currently a specification proposal. No Rust KT implementation, production KT vectors, or Android/backend KT integration should be added until the open protocol decisions are resolved and the proposal is explicitly frozen.
