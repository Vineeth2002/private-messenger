# 03 - Cryptographic Architecture

Status: ARCHITECTURAL (frozen). Amended by the Architecture Review Lock (ChatGPT + Gemini consensus memo),
which SUPERSEDES the original handoff sections on the handshake KDF (old salt `PM-V1-BI-X3DH-SALT-v1`,
`RootKey_0`, `ChainKey_0`, single-epoch context) and defines the Double Ratchet, media nonce, ALLH framing,
`Cert_dh` transcript, `AAD_msg` and codec bounds. Reference vectors: `test-vectors/v1/`.

## Suite
Ed25519 (RFC 8032) signing; X25519 (RFC 7748) DH; HKDF-SHA256 (RFC 5869); HMAC-SHA256 (chain KDF);
ChaCha20-Poly1305 AEAD; SHA-256; Argon2id where password/recovery protection is needed. ML-KEM-768 is a
future hybrid extension, not part of this boundary.

## Key separation
DSK = Ed25519 (authentication, signatures, certificates, identity binding). DDHK = X25519 (DH identity,
handshake). Separate key pairs; NEVER reuse an Ed25519 scalar as an X25519 private key.

## PM-BI-X3DH-1 (Bounded-Identity X3DH Profile) - proprietary, NOT Signal-interoperable
```
DH1 = X25519(IK_dh_A_priv, SPK_B)    DH2 = X25519(EK_A_priv, IK_dh_B)
DH3 = X25519(EK_A_priv, SPK_B)       DH4 = X25519(EK_A_priv, OPK_B)     (only if an OPK exists)
IKM = DH1 || DH2 || DH3 [|| DH4]                       96 or 128 bytes
PRK = HKDF-Extract(salt = "PM-BI-X3DH-1-HKDF-SALT-v1" [25 B], IKM)
Context = IK_dh_A (32) || IK_dh_B (32) || Epoch_A (4, BE) || Epoch_B (4, BE)       72 bytes
SK  = HKDF-Expand(PRK, "PM-BI-X3DH-1-SESSION-KEY-v1" [27 B] || Context, 32)
```
SK_master, RootKey_0 and CK_init are eliminated: the handshake outputs only the 32-byte SK. Responder side:
swap private/public roles (DH1 = X25519(spk_B_priv, IK_dh_A), etc.); both sides must obtain identical DH outputs.
Epoch semantics: Epoch_A = sender account epoch, Epoch_B = recipient account epoch. Epoch_A appears only in this HKDF Context and
in the authenticated PrekeyHandshakeHeader as `sender_account_epoch`; the message envelope and AAD carry Epoch_B (see AAD_msg).
Identity binding: the initial envelope carries enough authenticated public identity material for the recipient to
verify the initiator's dual identity; invalid binding fails closed. Status: formal symbolic analysis REQUIRED
before production (ProVerif/Tamarin) plus independent review.

## Cert_dh (device DH-identity binding)
`"PM-V1-DH-BIND" (13) || AccountID (16) || DeviceID (16) || DDHK_pub (32) || uint64_be(Timestamp) (8)`.
```
Cert_dh = Ed25519Sign(DSK_priv, "PM-V1-DH-BIND" || AccountID || DeviceID || DDHK_pub || uint64_be(Timestamp))
```
The signer is the sender device's Ed25519 DSK, a key pair separate from the X25519 DDHK. `PrekeyHandshakeHeader` carries
`sender_cert_dh_timestamp` (field 6) so the recipient can rebuild the exact 85-byte transcript, verify the signature against
the sender's DSK public key, and fail closed if it does not verify.

## PrekeyHandshakeHeader (frozen)
PM-CBOR-2026 map, authenticated through `ratchet_header_bytes` in AAD_msg:

| Field | Name | Type |
|---|---|---|
| 1 | sender_account_id | bstr, 16 B |
| 2 | sender_account_epoch (Epoch_A) | uint32 |
| 3 | sender_dsk_pub | bstr, 32 B (Ed25519) |
| 4 | sender_ddhk_pub | bstr, 32 B (X25519) |
| 5 | sender_cert_dh | bstr, 64 B (Ed25519 signature) |
| 6 | sender_cert_dh_timestamp | uint64 |
| 7 | sender_ephemeral_pub | bstr, 32 B (X25519) |
| 8 | recipient_spk_id | uint32 |
| 9 | recipient_opk_id | optional uint32 (omitted when no OPK was used) |
| 10 | initial_ratchet_pub | bstr, 32 B (X25519) |
| 11 | sequence_number | uint, = 0 |

Integer fields are CBOR unsigned integers in minimal form (recorded assumption: "BE" applies to the HKDF Context and AAD only). It is an authenticated
cryptographic structure: unknown fields must fail (Rule 7). The header has no device-id field, so the recipient rebuilds the Cert_dh transcript from fields 1, 4, 6
and the envelope's `sender_device_id` (which is also in AAD_msg), verifies field 5 against field 3, and fails closed otherwise (IMPLEMENTATION DECISION).

## Double Ratchet
```
KDF_RK(RK, DH_out):  PRK_rk = HKDF-Extract(salt = RK, IKM = DH_out)
                     RK_next = HKDF-Expand(PRK_rk, "PM-DR-RATCHET-ROOT-v1"  [21 B], 32)
                     CK_out  = HKDF-Expand(PRK_rk, "PM-DR-RATCHET-CHAIN-v1" [22 B], 32)
KDF_CK(CK):          K_msg = HMAC-SHA256(CK, 0x01);  CK_next = HMAC-SHA256(CK, 0x02);  return (CK_next, K_msg)
```
**Alice (RatchetInitAlice(SK, SPK_B_pub))**: generate DHS_A0; DHR_A = SPK_B_pub;
`(RK_A, CK_s) = KDF_RK(SK, X25519(dhs_A0_priv, SPK_B_pub))`; CK_r = NULL; Ns = Nr = Pn = 0.
**Message 0**: `(CK_s, K_msg,0) = KDF_CK(CK_s)`; ChaCha20-Poly1305 with K_msg,0, nonce `0x00^12`, AAD_msg; Ns = 1;
header carries `initial_ratchet_pub = DHS_A0_pub` (field 10), `sequence_number = 0` (field 11).
**Bob ingestion**, initial state RK_B = SK, DHS_B = (spk_B_priv, SPK_B_pub), DHR_B = CK_s = CK_r = NULL, Ns = Nr = Pn = 0:
1. `DHR_B = header.initial_ratchet_pub`; `(RK_temp, CK_r) = KDF_RK(RK_B, X25519(spk_B_priv, DHR_B))`.
2. `DHS_B1 = GenerateX25519()` (SPK private key retired from the ratchet); `(RK_B, CK_s) = KDF_RK(RK_temp, X25519(dhs_B1_priv, DHR_B))`.
3. `(CK_r, K_msg,0) = KDF_CK(CK_r)`; decrypt with nonce `0x00^12` and AAD_msg.
4. Atomic commit ONLY if step 3 authenticated: RK_B, CK_s, CK_r, DHS_B1, DHR_B, Ns = 0, Nr = 1, Pn = 0.
Invariant: any failure (authentication, replay, malformed) leaves state exactly unchanged; steps 1-3 operate on temporaries.
The fixed zero nonce is safe only because every K_msg is single-use; implementations must never reuse a message key.

## AAD_msg
`"PM-V1-MSG-AAD" (13) || protocol_version (1) || envelope_id (16) || sender_device_id (16) || recipient_device_id (16)
|| uint32_be(account_epoch) || uint8(prekey_flag) || ratchet_header_bytes`.
**Invariant: `MessageEnvelopeV1.field_5 == AAD account_epoch == Epoch_B` (the RECIPIENT account epoch).** The AAD inputs correspond to `MessageEnvelopeV1` fields 1-7 (table in 11-pmacbor-2026.md).

## Media (ALLH)
`NonceSalt = HKDF-Expand(HKDF-Extract("PM-V1-MEDIA-NONCE-SALT-v1" [25 B], K_media), "PM-V1-MEDIA-NONCE-EXPAND-v1" [27 B], 4)`;
`Nonce_i = NonceSalt (4) || uint64_be(i) (8)`. Container = `plaintext[0..L] || 0x80 || 0x00...` padded to bucket size S;
valid iff S >= L+1, byte at L is 0x80, bytes L+1..S are 0x00. Buckets: 64 KiB, 256 KiB, 1, 5, 20, 100 MiB (max V1 = 100 MiB).
Chunks: 64 KiB plaintext, ChaCha20-Poly1305, ciphertext chunk 65,552 bytes. Each chunk's authenticated AAD is the PM-CBOR-2026 map
```
MediaChunkAAD = { 1 => 1, 2 => media_id (16-byte UUIDv7, allocated before encryption), 3 => chunk_index,
                  4 => total_chunks, 5 => unpadded_file_length, 6 => padded_container_size }
```
The final-chunk position and chunk length are implied by `total_chunks` and `padded_container_size`. Recorded assumptions: `chunk_index` is
zero-based (matching `Nonce_i`), and `K_media` is used directly as the AEAD key. Vectors: `media_chunk_aead.json`.

## Codec bounds
Wire input <= 256 KiB; container nesting <= 8; map entries <= 32; byte string <= 65,552; chat plaintext <= 64 KiB
(schema-level). See 11-pmacbor-2026.md.

## Recovery (Model A: identity-epoch rekeying)
24-word BIP-39 (256-bit, English, NFKD); seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048, 64);
`PRK_rec = HKDF-Extract("PM-V1-RECOVERY-KEY-SALT-v1", seed)`; `K_rec_seed = HKDF-Expand(PRK_rec, "PM-V1-RECOVERY-KEY-ED25519-v1", 32)`
= Ed25519 seed; `IRC = SHA-256("PM-V1-RECOVERY-COMMITMENT" || K_rec_pub)`. Server stores IRC only. 48-hour timelock with
alert and abort from an active device. Past device-local history is not recoverable from the server.
