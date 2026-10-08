# Implementation Notes (decisions, resolved items, remaining open items)

ARCHITECTURAL DECISION = frozen by the handoff; IMPLEMENTATION DECISION = chosen here, reversible.

## A. Former specification conflicts: RESOLVED
**A1. RFC 8949 negative integers.** Authoritative vector: `[-1,-24,-25,-256,-257]` = `852037381838ff390100`. The handoff's s28 "corrected" bytes
`8520373838ff390100` were a transcription error (`3838` is -57, followed by a stray `ff`), so they are malformed. The vector file keeps an entry
(array name `quarantined`, retained for loader compatibility; status `RESOLVED_AUTHORITATIVE`) and Rust, Go and Python assert that the authoritative bytes
round-trip and the handoff's bytes are rejected as `ERR_MALFORMED_CBOR`. The RFC-derived boundary array is also in `nint_array_boundaries`.
**A2. RFC 8032 intermediate.** Authoritative first 32 bytes of SHA-512(seed): `357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f`.
The handoff's s18 value (`367c...de98f`) was a transcription error; the clamped scalar `307c...e94f`, the public key and the empty-message signature were always
correct. The fixture and checker pin the authoritative value; the superseded value survives only as the historical field `spec_s18_stated_sha512_first_half_hex`.
No hex value changed when these were marked resolved: only status/note strings in `cbor_canonical_codec.json` and `ed25519_baseline.json`.

## B. Specification items: status
| Item | Status |
|---|---|
| PrekeyHandshakeHeader field numbering (fields 1-11) | RESOLVED: tabulated in 03; the complete header is in `double_ratchet_linear.json` and validated by the checker |
| MessageEnvelopeV1 field numbering (fields 1-8) | RESOLVED: full table in 11-pmacbor-2026.md; AAD inputs map to fields 1-7 |
| Cert_dh (signer, transcript, header carriage) | RESOLVED: DSK signature; vector and header cross-checked end to end |
| ALLH bucket selection | RESOLVED per architects; vectors and checker implement the smallest bucket with S >= L+1 |
| MediaChunkAAD | RESOLVED: frozen map, chunk vectors with negatives |
| Recovery-secret rotation | RESOLVED per architects; procedure text to be added to 08. Nothing is implemented in Phase A |
| Context encoding, AAD_msg, media nonce, codec bounds | RESOLVED (architecture review lock) |

Genuinely open / future (none implemented in Phase A):
- Skipped-key / out-of-order semantics (MAX_SKIP, normal-message header): `double_ratchet_reorder.json` stays a placeholder.
- Epoch-transition certificate fields and the account-level device certificate details.
- A conforming `MessageEnvelopeV1` vector (the CBOR `envelope_illustrative` vector is a generic codec vector, not an instance) is not generated yet.

## C. Implementation decisions
- CBOR codecs are hand-written over raw bytes (no `ciborium`) so strictness cannot be loosened by a library; `fxamacker/cbor/v2` is used only in `internal/cbor/typed`, always behind `DecodeStrict`.
- Extra categories `ERR_UNSUPPORTED_ITEM` (tags, simple values other than false/true/null) and `ERR_LIMIT_EXCEEDED` (all codec bounds); ints limited to [-2^64, 2^64-1]; `true/false/null` accepted.
- Error precedence is specified in 11-pmacbor-2026.md so Rust and Go agree on category.
- `IRC` = plain concatenation of ASCII domain string and public key (as written).
- Recovery fixture uses the public zero-entropy BIP-39 mnemonic; cross-checked against the published TREZOR seed.
- Unused crates (`x25519-dalek`, `chacha20poly1305`, UniFFI) deliberately not added until their boundary unlocks.
- `LICENSE` is a proprietary placeholder; Go module path is a placeholder. Android/iOS projects are skeletons that have never been built.

## D. Architecture Review Lock (ChatGPT + Gemini memo): applied
ARCHITECTURAL: the memo supersedes the original handshake KDF (salt, RootKey_0/ChainKey_0, single epoch) with the
single-SK profile, and defines the Double Ratchet KDFs, Alice/Bob message-0 transitions, media nonce, ALLH framing,
`Cert_dh` transcript, `AAD_msg` and codec bounds. Docs 03 and 11 now carry the exact formulas.
Verified: all 8 byte-length claims in the memo are correct; Context = 72, Cert_dh = 85, max bstr = 65,552.
Verified by derivation (asserted in `tools/gen_protocol_vectors.py`): initiator and responder agree on SK (with and without
OPK); Bob's step-1 RK_temp equals Alice's RK_A; Bob's chain equals Alice's message-0 chain; after Bob's reply Alice's receiving
chain equals Bob's sending chain. The memo is internally coherent.
The memo did not mention conflicts A1/A2; both were resolved afterwards (section A).
New vectors (Python reference model, recomputed by independent `cryptography` HKDF/HMAC/AEAD in `check_vectors.py`):
`bi_x3dh_handshake` (ACTIVE), `double_ratchet_linear` (ACTIVE, incl. tamper negatives), `media_chunk_aead` (ACTIVE).

### Recorded implementation assumptions (not protocol changes)
1. "Max nesting depth 8" is read as 8 nested containers (the 9th is rejected); `ERR_LIMIT_EXCEEDED` is a category added here; no array-length cap.
2. Header integers (fields 2, 6, 8, 9) are CBOR unsigned integers in minimal form; "BE" applies to the HKDF Context and AAD only.
3. The header has no device-id field, so the recipient rebuilds the Cert_dh transcript from header fields 1, 4, 6 plus the envelope's `sender_device_id`.
4. MediaChunkAAD: `chunk_index` is zero-based; `K_media` is the AEAD key; final-chunk position and chunk length are implied by `total_chunks` and `padded_container_size`.
5. Memo path `services/internal/cbor` is the real `services/gateway/internal/cbor`.

### Observations for the formal-methods review (not design changes)
- SK binds both identity keys and epochs but not the SPK/OPK identifiers or EK_pub explicitly (EK influences SK through DH2-DH4).
- The memo does not say who verifies the signed-prekey signature or when; standard X3DH requires it.
- The fixed zero AEAD nonce is safe only under strict single-use message keys.

## E. Verification status (as of 2026-10-05)
Executed on the owner's Windows PC, from real compiler and test output: Rust 1.81.0 build and 13 tests (8 library + 2 cbor_vectors + 3 recovery_vectors); Go 1.22.6 build, vet and tests
(cbor, cbor/typed, http); the independent Python vector checker; Rust/Go parity 101/101. Also executed in the authoring sandbox: Python generation/validation and deliberate-tamper tests.
NOT executed anywhere: Gradle (Android), Xcode (iOS), `tools/run_all.ps1`, the GitHub Actions workflow (nothing pushed yet).
Not written: Rust/Go implementations of X3DH, ratchet and media. The gate is met; the next stage is PM-BI-X3DH-1 in Rust against `bi_x3dh_handshake.json`.

## F. Corrections received after review (resolved; applied in place)
1. **AAD epoch**: `MessageEnvelope.field_5 == AAD account_epoch == Epoch_B` (recipient). Epoch_A stays only in the HKDF Context and in the
   authenticated `PrekeyHandshakeHeader.sender_account_epoch`. Generator uses `eb`; `double_ratchet_linear.json` ciphertext/AAD changed accordingly; the checker
   asserts the invariant and that test epochs differ. The CBOR `envelope_illustrative` vector carries Epoch_B in field 5 (it is a generic codec vector, not a MessageEnvelopeV1 instance).
2. **Cert_dh**: `Ed25519Sign(DSK_priv, "PM-V1-DH-BIND" || AccountID || DeviceID || DDHK_pub || uint64_be(Timestamp))`, signer = sender device DSK. Signature vector in
   `bi_x3dh_handshake.json`; checker recomputes, verifies, rejects a tampered transcript, and asserts DSK != DDHK material.
3. **MediaChunkAAD** is frozen: `{1:1, 2:media_id, 3:chunk_index, 4:total_chunks, 5:unpadded_file_length, 6:padded_container_size}`. Chunk AEAD vectors (single-chunk and 4-chunk
   cases, tag + SHA-256 per chunk, 4 negatives: wrong index, wrong total, reordered chunk, wrong length) are now in `media_chunk_aead.json`.
4. **Go typed wrapper**: `UnmarshalStrict` documents exactly what it does (canonical proof + hardened decode + duplicate-key mapping) and no longer claims re-encode identity;
   `RoundTripsExactly` is documented as the identity check. A test pins this (it relies on fxamacker ignoring unknown struct keys by default; unverified until Go runs).
5. **Gate**: see docs/PHASE_B_GATE.md.
6. **PrekeyHandshakeHeader** is now the complete frozen 11-field structure in the active fixture (previously a test-only {10, 11} header). Because the header is part of
   AAD_msg, the header bytes, AAD and message-0 ciphertext in `double_ratchet_linear.json` changed. Test prekey identifiers were added to the handshake inputs
   (`recipient_spk_id` = 7, `recipient_opk_id` = 42) and the fixture's `sender_device_id` was set to the Cert_dh DeviceID so the header's Cert_dh verifies end to end.
   No algorithm, label or other protocol constant changed. PM-BI-X3DH-1 production implementation remains gated (docs/PHASE_B_GATE.md).
7. **A1 and A2 marked resolved** (authoritative values in section A). Metadata-only edit: status/note strings in two vector files; no hex value, algorithm or constant changed.
   The checker now pins both authoritative values.
8. **MessageEnvelopeV1** table transcribed into 11-pmacbor-2026.md (fields 1-8). Documentation only: no vector bytes, constants, formulas or code changed. The `envelope_illustrative`
   vector's description was reworded (metadata only) to say it is a generic codec vector; its bytes are untouched.
9. **First real build (Windows, Rust 1.81.0)**: cargo could not resolve dependencies because `bip39 =2.0.0` requires `unicode-normalization =0.1.22` exactly while Cargo.toml pinned
   `=0.1.23`. Fixed by pinning `=0.1.22`. Dependency-pin correction only: no protocol, vector or algorithm change (the dependency is used for NFKD normalization).
10. **Second real-build issue**: with the pins fixed, Rust 1.81 failed on transitive `base64ct 1.8.3` (needs edition 2024). Resolution: `Cargo.lock` was generated with a newer Cargo (stable, rustc 1.99.0)
   using `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback` (49 packages; see docs/REPRODUCIBILITY.md); builds still use Rust 1.81.0. Both `Cargo.lock` and `go.sum` are now committed.
11. **Windows tooling fixes**: `gen_vectors.py` and `compare_parity.py` open JSON with explicit `encoding="utf-8"` and the vector writer uses `newline="\n"` (Windows Python would otherwise crash on
   non-ASCII vectors and write CRLF files that break byte-for-byte checks); `tools/gen_protocol_vectors.py` finds its folder with `os.path` (splitting `__file__` on "/" fails with backslashes).
   Regenerated output is byte-identical (manifest SHA-256 `39f6a02a...` on both Linux and Windows).
12. **Phase A gate met on a real machine (2026-10-05)**: Rust compiled and 13 tests passed; Go compiled, vetted and passed; the Python checker passed; Rust/Go parity 101/101. No vector value changed
   during any real-build fix.
13. **Baseline completion** (before the first push): README, docs, CI, SQL migration, run scripts and Android/iOS skeletons added to the owner's repository. Status wording updated (Phase B unlocked, not started);
   CI and run scripts now use the committed lockfiles (`--locked`, `go mod verify`); REPRODUCIBILITY.md and LOCAL_SETUP_WINDOWS.md describe the verified Windows path. No code, vector, constant or formula changed.
14. **First Phase B boundary: PM-BI-X3DH-1 handshake (2026-10-07, commit 395e372)**: `native/crypto-core/src/x3dh.rs` derives the session key SK from both the initiator and the responder side and
   implements the Cert_dh transcript, signature and fail-closed verification. On the owner's Windows PC it reproduces every value in `bi_x3dh_handshake.json` (DH1-DH4, IKM, PRK, Context, SK, transcript,
   signature): 16 library tests pass (8 CBOR + 8 X3DH) plus 2 + 3 integration tests, and the Python checker still passes. Two conservative implementation decisions, neither affecting any vector:
   non-contributory X25519 outputs are rejected, and Cert_dh is verified with `verify_strict`. No vector, constant or formula changed. Not implemented here (not specified, or later boundaries):
   signed-prekey signature verification, the PrekeyHandshakeHeader parser, the Double Ratchet.
15. **Dependency rule learned twice** (base64ct 1.8.3, then zeroize_derive 1.5.0): adding a dependency with a plain `cargo test` resolves the NEWEST versions and can pull in crates that need a newer Cargo than 1.81.
   Add dependencies with the MSRV-aware resolver: `set CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback`, `cargo +stable fetch`, clear the variable, then build with `--locked`.
   The lock gained exactly 2 packages for X3DH (`x25519-dalek 2.0.1`, `zeroize_derive 1.4.3`); it now has 51 packages.
