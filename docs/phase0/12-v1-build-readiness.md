# 12 - KT V1 Build Readiness

**Status:** RESOURCE/REFERENCE GATE
**Current repository baseline:** `67edc4e2416fe792f1323d6ad25f4f65737a5a83`
**Purpose:** prevent implementation from outrunning the frozen protocol and independent vectors.

## 1. Required resources now present in this tranche

- `docs/phase0/10-key-transparency-v1-frozen.md`
- `tools/kt_v1_reference.py`
- `tools/build_kt_v1_vectors.py`
- `tools/check_kt_v1_vectors.py`
- `test-vectors/v1/transparency_leaf.json`
- `test-vectors/v1/transparency_smt_proofs.json`
- `test-vectors/v1/transparency_history_proofs.json`
- `test-vectors/v1/transparency_equivocation.json`

The existing `docs/phase0/10-key-transparency.md` proposal and `native/crypto-core/src/transparency.rs` policy layer remain in place. `transparency.rs` continues to provide only the frozen state/high-water policy; it is not replaced by this resource tranche.

## 2. Reference/vector gate

Run from `C:\private-messenger` in VS Code Command Prompt:

```text
py -m pip install cryptography
py tools\build_kt_v1_vectors.py
py tools\check_kt_v1_vectors.py
git diff --check
git status --short
git diff --stat
```

The build script is deterministic and rewrites only the four KT V1 vector files plus `manifest.json`.

The checker independently validates:

- PM-CBOR canonical decoding of all KT wire objects;
- leaf signatures and leaf hashes;
- stable SMT key derivation;
- all 256 siblings in each SMT proof;
- SMT tamper failures;
- all history inclusion proofs for the generated 32-entry fixture;
- history consistency proofs for every old size `1..31` against the 32-entry fixture;
- history tamper failures;
- STH signatures;
- witness signatures and the 2-of-3 registry model;
- same-size/different-root equivocation;
- conflicting witness statements;
- VERIFIED / DEGRADED / SECURITY_FAILURE policy mapping;
- manifest hashes and file-set integrity.

## 3. Rust implementation gate

Do **not** create `native/crypto-core/src/transparency_v1.rs` or Rust KT vector tests until the above commands pass locally.

After the reference/vector gate passes, the Rust boundary must:

1. parse the exact PM-CBOR objects;
2. reject unknown cryptographic fields;
3. reproduce the exact reference hashes/proofs;
4. verify the exact frozen negative cases;
5. leave all pre-existing X3DH/ratchet/media/HPKE tests unchanged.

## 4. Go/API gate

The existing backend contract deliberately freezes responsibilities but not KT HTTP shapes. Therefore no gateway endpoint or PostgreSQL node persistence is introduced in this resource tranche.

After Rust/reference parity is demonstrated, the next engineering boundary is:

- KT STH retrieval;
- SMT inclusion proof retrieval;
- history consistency proof retrieval;
- history entry persistence;
- STH publication persistence;
- witness statement handling;
- device enrollment/revocation/epoch authorization integration.

Those changes must consume the frozen wire objects rather than inventing parallel JSON or Go-native schemas.

## 5. Explicit audit rule

A compile/test failure is fixed by inspecting the exact failing file, the frozen spec, and the existing repository interfaces first. A failure is **not** resolved by changing vector values, weakening verification, or adding compatibility fields without a recorded protocol decision.

## 6. Gate closure record

The resource/reference gate and the Rust cryptographic implementation gate were subsequently demonstrated on the owner's Windows checkout.

Verified:
- `py tools\check_kt_v1_vectors.py`
- `py tools\check_vectors.py`
- `cargo test --locked` in `native\crypto-core`
- `go test ./...` in `services\gateway`
- `git diff --check`

The Rust run includes six KT V1 integration tests covering leaf validation, current-state SMT proofs, history proofs, STH/witness/equivocation
verification, strict history/evidence objects, and fail-closed malformed/noncanonical leaf cases.
