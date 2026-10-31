# 07 - UniFFI / FFI Interface

Status: ARCHITECTURAL (protocol rules frozen; identity Storage DEK amendment documented below; ratchet-state DEK exception is a proposal only and is not approved or implemented); UniFFI 0.28.1 is pinned.

- Protocol operational secrets never cross the Rust/native FFI boundary: ratchet root/chain/message keys,
  intermediate DH values, private identity keys, push private keys, media keys. Use opaque
  handles/state objects.
- Existing recovery exception: the recovery mnemonic, only during initial recovery setup and deliberate
  recovery import. Transient lifecycle, never persisted, screen-capture protection where supported,
  references released immediately, native secret material zeroized where controllable.
- Narrow local-storage exception for Android identity persistence: a fresh random 32-byte local
  data-encryption key (Storage DEK) may cross UniFFI only as the argument to `AccountContext.seal_for_storage`
  or `identity_restore`. It encrypts/decrypts only the local identity-at-rest record, must be wrapped by
  Android Keystore before persistence, must never be reused as a protocol key, and must be cleared from
  Kotlin `ByteArray` buffers immediately after each operation. Do not expose DSK/DDHK seeds or other
  protocol secrets to Kotlin. Managed-runtime copies cannot be guaranteed to be perfectly zeroized.
- The identity Storage DEK amendment above is limited to the identity-at-rest record; it does not permit
  arbitrary secret-bearing FFI parameters or change wire or cryptographic protocol rules.

- Proposed narrow local-storage exception for ratchet-state persistence (NOT IMPLEMENTED; NOT FROZEN):
  a fresh random 32-byte ratchet-state DEK per local session, distinct from the identity Storage DEK and
  every protocol key, may cross UniFFI only as an explicit argument to dedicated native ratchet-state
  seal/restore operations tied to an opaque native session handle. Exact method names and signatures must
  be approved with `docs/phase0/14-ratchet-state-persistence-v1.md`; do not create a general-purpose secret
  key API. Rust must own state serialization, strict decoding, invariant validation, and sealed-state
  restore; session binding must come from the native session context, not untrusted UI arguments.
  Plaintext serialized state, `RK`, `DHS_priv`, `CK_s`, `CK_r`, skipped-message keys, and message keys
  must never cross FFI. Kotlin may persist only the sealed state, the Keystore-wrapped ratchet DEK, and
  non-secret version/binding metadata.
  Android may unwrap the DEK only into a transient `ByteArray` for the dedicated native operation,
  clearing the buffer in `finally`. The DEK must not enter general UI, logs, crash reports, strings,
  Base64, analytics, or persistent plaintext storage; managed runtime copies cannot be guaranteed to be
  perfectly zeroized. Never reuse the DEK across sessions or for identity storage. This proposed
  exception is inactive until the persistence format, rollback scope, and UniFFI signatures are reviewed
  and approved.
- NON-CLAIM: managed Android/iOS memory cannot be perfectly zeroized.
- Handle-race and concurrent-processing behavior is a Phase B test criterion.
- Ratchet-state FFI tests must cover invalid DEK length, cross-session/epoch binding mismatch, tampered
  sealed records, invalid restored-state invariants, and operations on invalid, stale, or closed native
  handles. Generated bindings and logs must not expose ratchet state or protocol secrets.
