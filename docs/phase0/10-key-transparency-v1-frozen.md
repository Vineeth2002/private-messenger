# 10 - Key Transparency V1 (Frozen Normative Specification)

**Status:** FROZEN CRYPTOGRAPHIC PROTOCOL BOUNDARY
**Scope:** current-state transparency, append-only history, STHs, witness quorum, equivocation evidence, and client state policy.
**Implementation status:** NOT IMPLEMENTED in Rust or Go at this freeze point.
**Reference implementation:** `tools/kt_v1_reference.py` (test tooling only).
**Vectors:** `test-vectors/v1/transparency_*.json`.

This document supersedes the **proposal-only** KT details in `docs/phase0/10-key-transparency.md` for V1 cryptographic implementation. The earlier document remains historical context and policy background.

## 1. Security boundary

KT V1 provides two distinct commitments:

1. a **current-state Sparse Merkle Tree (SMT)** proving the currently published state for a stable `(AccountID, DeviceID)` key; and
2. a separate **append-only history Merkle tree** proving ordering and append-only growth of immutable published states.

KT V1 does **not** prove account-level authorization of a device. Device enrollment, epoch-transition authorization, and recovery authorization remain separate lifecycle decisions and are not silently invented by this specification.

KT state remains the existing repository policy:

| State | Condition | Messaging effect |
|---|---|---|
| VERIFIED | valid STH, valid required proofs, and at least 2 of 3 configured witnesses agree | allowed |
| DEGRADED | cryptographic checks remain valid but witness quorum is temporarily unavailable/incomplete | continues under existing cached-state policy |
| SECURITY FAILURE | rollback, proof failure, conflicting valid STHs, conflicting valid witness statements, or other cryptographic failure | outbound messaging to the affected identity is blocked |

A confirmed security failure is sticky. A later valid STH does not silently clear recorded equivocation evidence.

## 2. Existing repository invariants reused by KT V1

KT V1 MUST preserve the existing frozen architecture:

- `AccountID` and `DeviceID` are distinct 16-byte identifiers.
- `DSK` is Ed25519; `DDHK` is X25519; key material is never reused across those algorithms.
- `Cert_dh` is the existing 64-byte Ed25519 binding of `AccountID + DeviceID + DDHK_pub + uint64_be(Timestamp)` using the frozen `PM-V1-DH-BIND` transcript.
- KT wire objects use PM-CBOR-2026.
- Unknown cryptographic fields fail closed.
- Original received bytes are validated for canonical PM-CBOR before cryptographic interpretation.
- The client high-water value never moves backwards.
- The backend remains a delivery/control plane and never decrypts E2EE content.

## 3. TransparencyLeafV1

A leaf represents one immutable published identity state. An identity-state change creates a new history entry and a new leaf; an older leaf is never rewritten.

### 3.1 Leaf map

`TransparencyLeafV1` is a PM-CBOR-2026 map with **exactly** these fields:

| Field | Type | Meaning |
|---|---|---|
| 1 | `bstr(16)` | `AccountID` |
| 2 | `uint >= 1` | account epoch |
| 3 | `bstr(16)` | `DeviceID` |
| 4 | `bstr(32)` | `DSK_pub` (Ed25519) |
| 5 | `bstr(32)` | `DDHK_pub` (X25519) |
| 6 | `bstr(64)` | `Cert_dh` |
| 7 | `bstr(32)` | current `SPK_pub` |
| 8 | `bstr(32)` | current `PushPK` |
| 9 | `bstr(64)` | DSK authorization signature |

Fields 1-8 are the immutable identity-state commitment. Field 9 is the signature over fields 1-8.

No timestamp, `spk_id`, or database primary key is added to the leaf solely for convenience. The frozen `Cert_dh` already carries its certification timestamp; history sequence provides publication ordering.

### 3.2 Leaf signature

The DSK signature transcript is:

```text
"PM-V1-KT-LEAF-SIGN-v1" || canonical_leaf_map(fields_1_to_8)
```

Field 9 is that Ed25519 signature under field 4 (`DSK_pub`). A verifier MUST reject an invalid signature.

This is a cryptographic binding signature, **not** an account-level device-authorization proof.

### 3.3 Leaf hash

```text
leaf_hash = SHA-256("PM-V1-KT-LEAF-HASH-v1" || canonical_leaf_bytes)
```

The signed, canonical nine-field leaf bytes are hashed. The signature therefore becomes part of the committed state.

## 4. Stable current-state SMT

### 4.1 Key derivation

The current-state key is stable across leaf updates for the same account/device pair:

```text
smt_key = SHA-256("PM-V1-SMT-KEY" || AccountID || DeviceID)
```

The account epoch is **not** part of the SMT key. An epoch change therefore replaces the current leaf value at the same key while the history tree records the new immutable state.

### 4.2 Tree shape

The SMT has a fixed depth of **256** and consumes the 256 bits of `smt_key` from most significant bit to least significant bit.

Node hashing is domain separated:

```text
occupied_leaf_node = SHA-256(0x00 || leaf_hash)
internal_node      = SHA-256(0x01 || left || right)
```

Empty-node hashes are deterministic and fixed for all depths:

```text
Empty[0]   = SHA-256(0x00)
Empty[d+1] = SHA-256(0x01 || Empty[d] || Empty[d])
```

An absent sibling at depth `d` is represented by the corresponding `Empty[d]` value. There is no sparse-tree shape negotiation.

### 4.3 Current-state inclusion proof

An inclusion proof contains:

- the 32-byte `smt_key`;
- the 32-byte `leaf_hash`; and
- exactly 256 sibling hashes, ordered from the root-level sibling to the leaf-level sibling.

Verification starts from `occupied_leaf_node` and walks the 256 key bits from least-significant proof level back toward the root. A computed root mismatch is `SECURITY_FAILURE`.

V1 does not define a separate non-membership proof in this freeze. Non-membership can be added only through a later protocol decision.

## 5. Append-only history tree

The history tree is independent from the current-state SMT. Every published identity state consumes exactly one monotonically increasing history sequence number starting at 1.

### 5.1 History entry

A history entry is a PM-CBOR-2026 map with exactly:

| Field | Type | Meaning |
|---|---|---|
| 1 | `uint >= 1` | history sequence |
| 2 | `bstr(32)` | stable SMT key |
| 3 | `bstr(32)` | committed leaf hash |

The complete leaf bytes do not have to be duplicated in the history entry. The SMT inclusion proof and the independently authenticated leaf provide the current identity-state content; the history tree provides ordering and append-only continuity.

### 5.2 History Merkle construction

The history tree follows the RFC 6962 Merkle Tree Hash shape and domain separation:

```text
history_leaf_hash(entry) = SHA-256(0x00 || canonical_history_entry)
history_node_hash(left, right) = SHA-256(0x01 || left || right)
MTH([]) = SHA-256("")
```

For a non-empty tree, the largest power of two strictly less than `n` divides the tree recursively exactly as specified by RFC 6962. The tree is not required to be a power-of-two shape.

### 5.3 Inclusion proofs

History inclusion proofs use the RFC 6962 audit-path construction. A proof binds:

- the exact history entry;
- the 0-based history index; and
- the history tree size.

The history entry `sequence` MUST equal `index + 1`. This is the explicit 1-based publication-order binding: the history tree position and the sequence field cannot disagree while both remaining valid.

### 5.4 Consistency proofs

History consistency proofs use the RFC 6962 `PROOF(m, D[n])` algorithm for `0 < m < n`. The proof demonstrates that the first `m` history entries are the prefix of the `n`-entry tree. Proofs MUST NOT introduce a project-specific alternative consistency algorithm.

The reference implementation follows the RFC's largest-power-of-two recursive construction and independently verifies old and new roots.

## 6. Signed Tree Head (STH)

An STH commits one exact tree state and binds the current-state root and history root together.

`SignedTreeHeadV1` is a PM-CBOR-2026 map with exactly:

| Field | Type | Meaning |
|---|---|---|
| 1 | `uint = 1` | protocol version |
| 2 | `uint64` | history tree size |
| 3 | `bstr(32)` | current-state SMT root |
| 4 | `bstr(32)` | history tree root |
| 5 | `uint64` | STH issuance timestamp |
| 6 | `bstr(32)` | transparency log identifier |
| 7 | `bstr(64)` | log Ed25519 signature |

The signed transcript is:

```text
"PM-V1-KT-STH-SIGN-v1" || canonical_STH_map(fields_1_to_6)
```

The log signing key is a dedicated transparency-log identity. It is not a user/device DSK.

`tree_size` is the high-water domain used for append-only history checks. A newer STH with a larger tree size MUST be checked against the previous accepted STH with a history consistency proof.

## 7. Witness statements and quorum

V1 uses a fixed logical deployment model of **three configured witnesses** with a **2-of-3 threshold**.

A witness registry is trusted configuration, not user identity data. Each configured witness has a stable 16-byte witness identifier and an Ed25519 public key.

`WitnessStatementV1` is a PM-CBOR-2026 map with exactly:

| Field | Type | Meaning |
|---|---|---|
| 1 | `uint = 1` | protocol version |
| 2 | `bstr(16)` | witness identifier |
| 3 | `bstr(32)` | transparency log identifier |
| 4 | `uint64` | history tree size |
| 5 | `bstr(32)` | SHA-256 of the complete signed STH bytes |
| 6 | `bstr(64)` | witness Ed25519 signature |

The signature transcript is:

```text
"PM-V1-KT-WITNESS-SIGN-v1" || canonical_WitnessStatement_map(fields_1_to_5)
```

A valid, non-duplicated set of at least **2 different configured witnesses** agreeing on the same STH digest is quorum and yields `VERIFIED`.

Zero or one valid agreeing witness statement, with otherwise valid cryptographic evidence, is `DEGRADED`.

Conflicting valid witness statements for the same `(log_id, tree_size)` that bind different STH digests are `SECURITY_FAILURE`.

## 8. Equivocation and evidence

Confirmed equivocation includes either:

1. two valid log-signed STHs with the same `log_id` and `tree_size` but different committed roots; or
2. two valid witness statements with the same `(log_id, tree_size)` but different STH digests.

An evidence envelope is a PM-CBOR-2026 map that preserves both complete STH byte strings and, when available, conflicting witness statements. Evidence is append-only client security state; a later valid observation does not erase it.

## 9. Client high-water and state transitions

The existing repository high-water rule is retained:

```text
received_tree_size < cached_high_water
    => SECURITY_FAILURE
```

Equal or greater sizes pass the high-water comparison, after which the full cryptographic checks are performed.

For a strictly newer STH:

1. verify the new STH signature;
2. verify its inclusion proof(s) as required by the calling operation;
3. verify the history consistency proof from the cached accepted STH;
4. verify the witness quorum or enter `DEGRADED` when quorum evidence is temporarily unavailable;
5. only then advance the local high-water state.

The high-water value never decreases.

## 10. PM-CBOR requirements

All KT V1 wire objects MUST comply with PM-CBOR-2026:

- canonical encoding only;
- minimal integer encodings;
- no duplicate keys;
- bytewise canonical map ordering;
- no floats;
- no indefinite-length items;
- no tags or unsupported simple values;
- no trailing bytes;
- wire/container/byte-string limits from `11-pmacbor-2026.md`;
- unknown cryptographic fields cause rejection.

Signatures and hashes operate on the exact canonical bytes specified above.

## 11. Failure mapping

| Failure | State |
|---|---|
| lower tree size than cached high-water | `SECURITY_FAILURE` |
| invalid STH signature | `SECURITY_FAILURE` |
| invalid SMT inclusion proof | `SECURITY_FAILURE` |
| invalid history inclusion proof | `SECURITY_FAILURE` |
| invalid history consistency proof | `SECURITY_FAILURE` |
| same-size conflicting valid STHs | `SECURITY_FAILURE` |
| conflicting valid witness statements | `SECURITY_FAILURE` |
| valid cryptography but incomplete witness quorum | `DEGRADED` |
| valid cryptography and 2-of-3 witness quorum | `VERIFIED` |

The exact transport timeout used to decide that a witness is unavailable is an operational configuration, not a cryptographic wire constant. It MUST NOT alter the cryptographic verification results.

## 12. Explicit non-goals at this freeze

The following are intentionally **not** frozen here and MUST NOT be invented by the Rust implementation:

- account-level authorization of newly enrolled devices;
- epoch-transition certificate schema;
- recovery/revocation workflow details;
- PostgreSQL node storage schema;
- client SQLCipher serialization format;
- HTTP endpoint bodies beyond the wire objects defined above;
- Android/iOS UI behavior.

Those are subsequent engineering boundaries.

## 13. Freeze gate

The following cryptographic choices are frozen for V1:

| Decision | Status |
|---|---|
| dual-tree architecture | FROZEN |
| leaf field map | FROZEN |
| leaf signature transcript | FROZEN |
| leaf hash domain | FROZEN |
| stable SMT key derivation | FROZEN |
| SMT depth and node domains | FROZEN |
| SMT inclusion proof order | FROZEN |
| history entry map | FROZEN |
| RFC 6962 history tree construction | FROZEN |
| RFC 6962 inclusion proof | FROZEN |
| RFC 6962 consistency proof | FROZEN |
| STH field map and signature transcript | FROZEN |
| 3-witness / 2-of-3 quorum | FROZEN |
| witness statement format | FROZEN |
| equivocation conditions | FROZEN |
| high-water state semantics | FROZEN |
| device authorization | OUT OF SCOPE / OPEN |
| HTTP/API persistence details | NEXT ENGINEERING BOUNDARY |

**Implementation rule:** the reference implementation and deterministic vectors are the first implementation artifacts. Rust/Go production KT code is not authorized until the vector and checker gate passes on the owner's machine.
