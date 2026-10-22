# Identity persistence envelope V1 — implementation draft

Status: IMPLEMENTATION DRAFT. This is a local at-rest format, not a protocol or network encoding.

## Envelope format

The proposed sealed record is exactly 133 bytes:

- 9-byte header: ASCII `PMIDSTOR` followed by format version byte `0x01`;
- 12-byte nonce generated afresh with the OS CSPRNG for each save;
- 112-byte ChaCha20-Poly1305 output containing the 96-byte plaintext plus 16-byte authentication tag.

The 96-byte plaintext is fixed-width and contains, in order: AccountID (16 bytes), DeviceID (16 bytes), DSK seed (32 bytes), DDHK seed (32 bytes). The complete 9-byte header is authenticated as associated data. No variable-length fields are accepted. On restore, the implementation verifies the record length, header/version, AEAD tag, and UUIDv7 version/variant bits. Invalid format, wrong key, and authentication failure are reported as `InvalidField` so callers do not get a useful tamper oracle.

Plaintext serialization and decryption are held in `Zeroizing` buffers inside Rust. The sealed record contains no plaintext identity fields. This does not claim perfect zeroization of every compiler temporary or managed-runtime copy.

## Native test coverage

- Save/restore preserves the account and device IDs.
- Restored DSK/DDHK public keys match, and the restored DSK produces the same deterministic signed transparency leaf.
- Wrong key, header/version tampering, nonce tampering, ciphertext/tag tampering, and truncated records fail closed.
- Repeated saves use fresh nonces.

## Android integration decision — narrowly scoped Storage DEK exception

The native identity payload remains serialized and encrypted inside Rust. A fresh random 32-byte Storage DEK is the only additional secret permitted to cross UniFFI: Kotlin passes it to native sealing/restoration and wraps it with an Android Keystore AES-GCM key before it is persisted. Kotlin must not receive DSK/DDHK seeds or a plaintext identity payload. The Storage DEK is distinct from every protocol key, never reused, and cleared from managed byte arrays immediately after use. This is an explicit, narrow amendment to `07-uniffi-interface.md`; managed-runtime copies cannot be guaranteed to be perfectly zeroized.

The Android storage layer persists only the sealed record and Keystore-wrapped Storage DEK, uses atomic replacement, fails closed on tampering or unavailable keys, and never silently initializes a replacement identity after a restore failure.

## Phase closure gates still required

- Run the Android Gradle build and the native NDK build from the updated UDL/API.
- Confirm the app creates a persisted identity on first launch and restores the same ID/key-derived public keys after process restart.
- On a disposable test device, verify missing Keystore key, malformed storage, and tampering fail closed without creating a replacement identity.
- Complete real-device/instrumentation coverage and review the final diff before declaring Phase 1 complete.
