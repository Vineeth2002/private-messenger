# 02 - Threat Model and Non-Claims

Status: ARCHITECTURAL (frozen).

## Assets
Message plaintext, media plaintext, identity/ratchet/message/media/push/recovery private keys,
conversation graph, device directory integrity.

## Adversaries
Honest-but-curious or compromised gateway/database operator; network attacker; malicious push
provider; malicious or stale key-transparency log; stolen/seized device; attacker presenting
malformed or replayed envelopes.

## Server must never possess
User private identity keys, Double Ratchet root/chain/message keys, plaintext messages/media,
recovery private keys, push private keys. Redis never holds cryptographic state.

## Security invariants
1. Failed authentication/decryption, replay, or malformed envelope leaves ratchet state exactly unchanged.
2. DSK (Ed25519) and DDHK (X25519) are independent key pairs; no scalar reuse.
3. Invalid identity binding fails closed.
4. Push is a wake-up hint with zero authorization weight.
5. Cryptographic parsers reject non-canonical, duplicate-key, float, indefinite-length, trailing-byte input.

## NON-CLAIMS (must appear in any external description)
- Persistent data hosted in India is NOT equivalent to every network packet staying in India.
- APNs and FCM are external, untrusted transport boundaries.
- Hardware execution of Ed25519/X25519 is not universally available on Android/iOS.
- Push content is not authenticated application content.
- Unit tests are not cryptographic certification.
- Zeroization guarantees are limited by managed runtimes (JVM/ART, Swift ARC).
- PM-BI-X3DH-1 is proprietary and NOT interoperable with Signal X3DH.
- A third-party cryptographic audit remains required.
- Platform metadata (push token, IP routing, packet sizes, timing) is outside the
  "no application conversational metadata in push" guarantee.
