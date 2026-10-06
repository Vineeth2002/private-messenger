# 11 - PM-CBOR-2026 (implemented in Phase A)

Based on RFC 8949 s4.2.1 Core Deterministic Encoding. NOT the RFC 7049 length-first order.

## Rules
1. Map keys ordered by bytewise lexicographic comparison of the deterministic encodings of the keys
   (Rust slice compare / Go `bytes.Compare`). Never length-first.
2. Shortest integer heads; non-minimal rejected (`180a` invalid for 10; canonical `0a`). The same
   minimality applies to length/count arguments of strings, arrays and maps.
3. No floats (major 7, additional info 25/26/27).
4. No indefinite lengths (additional info 31 on byte/text strings, arrays, maps).
5. Duplicate map keys rejected (never keep first/last).
6. Payloads/ciphertexts/signatures/hashes/IDs are definite-length byte strings.
7. Unknown fields: extensible application envelopes may ignore unknown unflagged fields;
   cryptographic transcripts, signed structures and transparency leaves must FAIL on unknown
   fields. (Codec-level only validates well-formedness; field-level policy belongs to the
   schema layer, not yet built.)
8. Trailing bytes rejected.

Original bytes are proven canonical during parsing; decode -> reserialize is never used to repair input.

## Error categories (the interop contract; messages are not)
`ERR_NON_CANONICAL_INTEGER` `ERR_DUPLICATE_MAP_KEY` `ERR_FLOAT_PROHIBITED`
`ERR_INDEFINITE_LENGTH_PROHIBITED` `ERR_UNSORTED_MAP_KEYS` `ERR_TRAILING_BYTES` `ERR_MALFORMED_CBOR`
plus two categories added as IMPLEMENTATION DECISIONS: `ERR_UNSUPPORTED_ITEM` (tags and simple values other
than false/true/null) and `ERR_LIMIT_EXCEEDED` (any bound below).

## Bounds (Architecture Review Lock)
| Bound | Value | Notes |
|---|---|---|
| Wire input | 256 KiB (262,144 B) | checked before parsing |
| Container nesting | 8 | arrays/maps; 8 nested accepted, 9th rejected |
| Map entries | 32 | checked right after the count is read |
| Byte string | 65,552 B | = 65,536 plaintext + 16-byte tag; checked before the body is read |
| Chat plaintext | 64 KiB | schema layer, not the codec |
Array element count has no separate cap (bounded by the wire cap). Text strings have no separate cap.

## Deterministic precedence (so Rust and Go agree)
Reserved additional info 28-30 -> MALFORMED. Additional info 31 -> INDEFINITE for major 2-5, else
MALFORMED. Tags -> UNSUPPORTED. Major 7: false/true/null accepted, floats -> FLOAT, others ->
UNSUPPORTED. Argument bytes are read (truncation -> MALFORMED) before minimality is checked. Maps:
after all pairs parse, duplicates (including non-adjacent) -> DUPLICATE, then order -> UNSORTED.
Top-level trailing bytes -> TRAILING. Wire input over the cap -> LIMIT (before anything else). Container at nesting level 9,
map count > 32, or bstr length > 65,552 -> LIMIT (depth is checked right after the head byte, count/length right after the
argument is read and found canonical). Text must be valid UTF-8.

Go note: typed (fxamacker) decoding uses `DupMapKeyEnforcedAPF` and traps `*cbor.DupMapKeyError`, mapping it to
`ERR_DUPLICATE_MAP_KEY`; it always runs behind the core strict decoder.

## Vectors
`test-vectors/v1/cbor_canonical_codec.json`. Includes the s29 ordering vector, the s30
`24` vs empty-bstr regression (`a2 1818 6161 40 6162` valid; `a2 40 6162 1818 6161` rejected), and a
resolved s28 entry (authoritative `852037381838ff390100`; see IMPLEMENTATION_NOTES.md).

## Authenticated structures defined so far
`MediaChunkAAD` (03-crypto-architecture.md): exactly fields 1-6, all unsigned integers except field 2 (16-byte bstr). It is an authenticated
cryptographic structure, so unknown fields must fail (Rule 7) at the schema layer.
`PrekeyHandshakeHeader`: fields 1-11 as tabulated in 03-crypto-architecture.md (field 9 optional); same Rule 7 treatment.
`MessageEnvelopeV1` (resolved; frozen by the architects), a PM-CBOR-2026 map:
| # | Field | Type |
|---|---|---|
| 1 | protocol_version | uint = 1 |
| 2 | envelope_id | bstr, 16 bytes |
| 3 | sender_device_id | bstr, 16 bytes |
| 4 | recipient_device_id | bstr, 16 bytes |
| 5 | account_epoch | uint32 = Epoch_B (recipient epoch) |
| 6 | is_prekey_handshake | bool |
| 7 | ratchet_header_bytes | bstr |
| 8 | ciphertext | bstr, at most 65,552 bytes |

Fields 1-7 are exactly the AAD_msg inputs (03-crypto-architecture.md), in the same order; `is_prekey_handshake` is the AAD `prekey_flag`, and for a prekey message
`ratchet_header_bytes` is the canonical `PrekeyHandshakeHeader`. The `envelope_illustrative` CBOR vector is a generic codec vector and is NOT a `MessageEnvelopeV1` instance.
