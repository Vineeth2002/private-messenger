# 07 - UniFFI / FFI Interface

Status: ARCHITECTURAL (frozen rules); interface NOT yet implemented (pin: UniFFI 0.28.1).

- Operational secrets never cross the Rust/native FFI boundary: ratchet root/chain/message keys,
  intermediate DH values, private identity keys, push private keys, media keys. Use opaque
  handles/state objects.
- Sole audited exception: the recovery mnemonic, only during initial recovery setup and deliberate
  recovery import. Transient lifecycle, never persisted, screen-capture protection where supported,
  references released immediately, native secret material zeroized where controllable.
- NON-CLAIM: managed Android/iOS memory cannot be perfectly zeroized.
- Handle-race and concurrent-processing behavior is a Phase B test criterion.
