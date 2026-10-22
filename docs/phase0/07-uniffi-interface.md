# 07 - UniFFI / FFI Interface

Status: ARCHITECTURAL (protocol rules frozen; narrow Storage DEK boundary amendment documented below); UniFFI 0.28.1 is pinned.

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
- This is a documented implementation-boundary amendment for the Storage DEK only; it does not permit
  arbitrary secret-bearing FFI parameters or change any wire protocol or cryptographic protocol.
- NON-CLAIM: managed Android/iOS memory cannot be perfectly zeroized.
- Handle-race and concurrent-processing behavior is a Phase B test criterion.
