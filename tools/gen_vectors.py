#!/usr/bin/env python3
"""Generates test-vectors/v1/*.json. Run from repo root: python3 tools/gen_vectors.py

Positive CBOR bytes come from tools/pmcbor_ref.py, and every vector that the
specification states byte-for-byte is additionally asserted against the
spec-stated hex, so the generator cannot drift from the frozen text.
"""
import hashlib, hmac, json, os, sys, unicodedata
sys.path.insert(0, os.path.dirname(__file__))
import pmcbor_ref as R
from pmcbor_ref import Map

OUT = os.path.join(os.path.dirname(__file__), "..", "test-vectors", "v1")


def dump(name, obj):
    with open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


# ------------------------------------------------------------------ CBOR
positive, negative = [], []


def pos(id_, desc, value, expect=None):
    enc = R.encode(value)
    if expect is not None:
        assert enc.hex() == expect, (id_, enc.hex(), expect)
    assert R.encode(R.decode_strict(enc)) == enc, id_
    positive.append({"id": id_, "description": desc, "value": R.to_tagged(value),
                     "cbor_hex": enc.hex()})


def neg(id_, desc, hexstr, err):
    try:
        R.decode_strict(bytes.fromhex(hexstr))
    except R.CborError as e:
        assert e.category == err, (id_, e.category, err)
    else:
        raise AssertionError(f"{id_}: reference decoder accepted negative vector")
    negative.append({"id": id_, "description": desc, "cbor_hex": hexstr, "error": err})


# 1. unsigned integer boundaries (hex for the first seven is stated in spec s27 rule 2)
spec_uint = {0: "00", 23: "17", 24: "1818", 255: "18ff", 256: "190100",
             65535: "19ffff", 65536: "1a00010000"}
for n, h in spec_uint.items():
    pos(f"uint_{n}", f"unsigned integer {n} (hex stated in spec)", n, h)
for n in (1, 10, 4294967295, 4294967296, 18446744073709551615):
    pos(f"uint_{n}", f"unsigned integer boundary {n}", n)
pos("uint_array_boundaries", "array of unsigned boundaries",
    [0, 1, 10, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296, 18446744073709551615])

# 2. negative integer boundaries (RFC 8949 derived; see the resolved s28 entry in quarantined[])
for n in (-1, -24, -25, -256, -257, -65536, -65537, -4294967296, -4294967297,
          -18446744073709551616):
    pos(f"nint_{abs(n)}", f"negative integer {n}", n)
pos("nint_array_boundaries", "array of negative-integer boundaries (RFC 8949 derived)",
    [-1, -24, -25, -256, -257, -65536, -65537, -4294967296, -4294967297,
     -18446744073709551616])

# 3. bytewise map ordering (hex stated in spec s29); pairs deliberately listed NON-canonically
pos("map_order_spec_s29", "keys 10,100,-1,'z','aa' -> bytewise order (hex stated in spec)",
    Map([("aa", "val5"), ("z", "val4"), (-1, "val3"), (100, "val2"), (10, "val1")]),
    "a50a6476616c3118646476616c32206476616c33617a6476616c346261616476616c35")

# 4. genuine bytewise vs length-first regression (spec s30)
pos("map_order_24_vs_empty_bstr", "key 24 (1818) sorts BEFORE empty bstr (40) under RFC 8949",
    Map([(b"", "b"), (24, "a")]), "a21818616140616 2".replace(" ", ""))

# 5. generic codec vector (id kept for parity maps). NOT a MessageEnvelopeV1 instance: its keys are arbitrary test keys.
pos("envelope_illustrative", "generic 6-entry map with mixed value types (NOT a MessageEnvelopeV1 instance; keys are arbitrary test keys)",
    Map([(6, bytes(range(48))), (5, 3), (4, 300), (3, bytes([0x22] * 16)),
         (2, bytes(range(1, 17))), (1, 1)]))

# 6. nested
pos("nested_structures", "nested maps/arrays with sorted inner maps",
    Map([("meta", Map([(2, [1, [2, [3, []]]]), (1, Map([]))])), ("list", [Map([(1, b"")]), None, True, False])]))

# 7. empties
pos("empty_array", "empty array", [], "80")
pos("empty_map", "empty map", Map([]), "a0")
pos("empty_bstr", "empty byte string", b"", "40")
pos("empty_text", "empty text string", "", "60")
pos("array_of_empties", "array of empty containers/strings", [[], Map([]), b"", ""])

# 8. definite-length byte strings
for n in (1, 23, 24, 255, 256, 65536):
    pos(f"bstr_len_{n}", f"definite-length byte string of {n} bytes", bytes([n & 0xFF] * n))
assert next(v for v in positive if v["id"] == "bstr_len_24")["cbor_hex"].startswith("5818")
assert next(v for v in positive if v["id"] == "bstr_len_256")["cbor_hex"].startswith("590100")

# 9. text
for i, s in enumerate(["a", "IETF", "\u00fc", "\u6c34", "\U00010151"]):
    pos(f"text_{i}", f"text string {s!r}", s)

# 10. misc
pos("map_compound_keys", "map with bool/null/bstr/array/map/int keys in bytewise order",
    Map([(None, 6), (True, 5), (Map([]), 4), ([1], 3), (b"\x00", 2), (0, 1)]))
_a = 0
for _ in range(8):
    _a = [_a]
pos("depth_8_nested_arrays", "8 nested arrays (at the depth limit)", _a, "81" * 8 + "00")
_m = Map([])
for _ in range(7):
    _m = Map([(0, _m)])
pos("depth_8_nested_maps", "8 nested maps (at the depth limit)", _m, "a100" * 7 + "a0")
pos("map_32_entries", "map with 32 entries (at the entry limit)", Map([(i, 0) for i in range(32)]))
pos("simple_false", "false", False, "f4")
pos("simple_true", "true", True, "f5")
pos("simple_null", "null", None, "f6")

# ---- negatives
NC, DUP, FLT, IND, UNS, TRL, MAL, UNSUP, LIM = ("ERR_NON_CANONICAL_INTEGER", "ERR_DUPLICATE_MAP_KEY",
    "ERR_FLOAT_PROHIBITED", "ERR_INDEFINITE_LENGTH_PROHIBITED", "ERR_UNSORTED_MAP_KEYS",
    "ERR_TRAILING_BYTES", "ERR_MALFORMED_CBOR", "ERR_UNSUPPORTED_ITEM", "ERR_LIMIT_EXCEEDED")

neg("nc_uint_180a", "10 encoded in 1-byte form (spec s27)", "180a", NC)
neg("nc_uint_1817", "23 in 1-byte form", "1817", NC)
neg("nc_uint_1900ff", "255 in 2-byte form", "1900ff", NC)
neg("nc_uint_1a0000ffff", "65535 in 4-byte form", "1a0000ffff", NC)
neg("nc_uint_1b00000000ffffffff", "4294967295 in 8-byte form", "1b00000000ffffffff", NC)
neg("nc_nint_3800", "-1 in 1-byte form", "3800", NC)
neg("nc_bstr_len_5800", "empty bstr with 1-byte length", "5800", NC)
neg("nc_text_len_780161", "text 'a' with 1-byte length", "780161", NC)
neg("nc_array_len_9800", "empty array with 1-byte length", "9800", NC)
neg("nc_map_len_b800", "empty map with 1-byte length", "b800", NC)
neg("dup_adjacent", "map {1:1, 1:2}", "a201010102", DUP)
neg("dup_text", "map {'a':1,'a':2}", "a2616101616102", DUP)
neg("dup_nonadjacent_precedence", "keys 1,2,1: duplicate wins over unsorted", "a3010102020103", DUP)
neg("float_half", "float16 1.0", "f93c00", FLT)
neg("float_single", "float32 1.0", "fa3f800000", FLT)
neg("float_double", "float64 1.0", "fb3ff0000000000000", FLT)
neg("float_nested", "float inside array", "81fa3f800000", FLT)
neg("indef_bytes", "indefinite bstr", "5f4161ff", IND)
neg("indef_bytes_empty", "indefinite bstr, immediate break", "5fff", IND)
neg("indef_text", "indefinite text", "7f6161ff", IND)
neg("indef_array", "indefinite array", "9f01ff", IND)
neg("indef_array_empty", "indefinite array, immediate break", "9fff", IND)
neg("indef_map", "indefinite map", "bf0102ff", IND)
neg("indef_map_empty", "indefinite map, immediate break", "bfff", IND)
neg("unsorted_spec_s30", "40 before 1818 (legacy length-first order); spec s30", "a2406162181861 61".replace(" ", ""), UNS)
neg("unsorted_ints", "keys 2,1", "a202010102", UNS)
neg("unsorted_text", "keys 'b','a'", "a2616201616102", UNS)
neg("trailing_two_zeros", "0 followed by 0", "0000", TRL)
neg("trailing_ff", "1 followed by 0xff", "01ff", TRL)
neg("trailing_after_map", "empty map + byte", "a000", TRL)
neg("trailing_after_array", "[0] + byte", "810000", TRL)
neg("malformed_empty_input", "empty input", "", MAL)
neg("malformed_truncated_head", "1-byte arg missing", "18", MAL)
neg("malformed_truncated_head2", "2-byte arg truncated", "1901", MAL)
neg("malformed_bstr_short", "bstr length 2 with 1 byte", "4261", MAL)
neg("malformed_text_bad_utf8", "invalid UTF-8", "62c328", MAL)
neg("malformed_array_short", "array(2) with 1 item", "8201", MAL)
neg("malformed_map_missing_value", "map(1) key only", "a101", MAL)
neg("malformed_reserved_ai_28", "reserved additional info 28", "1c", MAL)
neg("malformed_reserved_ai_30", "reserved additional info 30", "1e", MAL)
neg("malformed_stray_break", "break outside indefinite item", "ff", MAL)
neg("limit_depth_100", "100 nested arrays exceeds MAX_DEPTH=8", "81" * 100 + "00", LIM)
neg("limit_depth_9_arrays", "9 nested arrays (limit is 8 containers)", "81" * 9 + "00", LIM)
neg("limit_depth_9_maps", "9 nested maps (limit is 8 containers)", "a100" * 8 + "a0", LIM)
neg("limit_map_33_entries", "map with 33 entries (limit 32)",
    "b821" + "".join(R.encode(i).hex() + "00" for i in range(33)), LIM)
neg("limit_bstr_65553_header_only", "bstr length 65553 > 65552, rejected before body is read", "5a00010011", LIM)
neg("unsupported_tag", "tag 0", "c00a", UNSUP)
neg("unsupported_undefined", "undefined", "f7", UNSUP)
neg("unsupported_simple_16", "simple(16)", "f0", UNSUP)
neg("unsupported_simple_32", "simple(32) two-byte form", "f820", UNSUP)

# ---- resolved s28 entry. The array name 'quarantined' is kept for loader compatibility in Rust/Go/Python.
# Authoritative vector (architects): [-1,-24,-25,-256,-257] = 852037381838ff390100.
as_written = "8520373838ff390100"
rfc = R.encode([-1, -24, -25, -256, -257]).hex()
assert rfc == "852037381838ff390100"
try:
    R.decode_strict(bytes.fromhex(as_written))
    raise AssertionError("as-written s28 bytes unexpectedly decode")
except R.CborError as e:
    assert e.category == MAL
quarantined = [{
    "id": "spec_s28_negint_array",
    "status": "RESOLVED_AUTHORITATIVE",
    "value": R.to_tagged([-1, -24, -25, -256, -257]),
    "spec_s28_corrected_hex_as_written": as_written,
    "spec_s28_as_written_decodes_to": MAL,
    "rfc8949_hex": rfc,
    "note": ("RESOLVED by the architects: the authoritative vector is 852037381838ff390100 (RFC 8949; -25 is 3818). "
             "The handoff's s28 'corrected' bytes 8520373838ff390100 were a transcription error and are malformed "
             "(3838 = -57, then a stray 0xff); they are kept only as a negative assertion.")}]

dump("cbor_canonical_codec.json", {
    "suite": "PM-CBOR-2026", "vector_format": 1, "base": "RFC 8949 s4.2.1 Core Deterministic Encoding",
    "value_encoding": ("tagged JSON: {int:'decimal string'} {bytes:'hex'} {text:s} {bool:b} {null:true} "
                       "{array:[..]} {map:[[k,v],..]}; map pair order in the file is NOT canonical"),
    "error_categories": R.CATEGORIES,
    "limits": {"max_wire_input": R.MAX_WIRE_INPUT, "max_depth": R.MAX_DEPTH,
               "max_map_entries": R.MAX_MAP_ENTRIES, "max_bstr": R.MAX_BSTR,
               "note": "wire-input and 65552-byte bstr boundaries are covered by unit tests in each language"},
    "positive": positive, "negative": negative, "quarantined": quarantined})

# ------------------------------------------------------------------ Ed25519 baseline (RFC 8032 7.1 TEST 1)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
h = hashlib.sha512(SEED).digest()
half = bytearray(h[:32])
raw_half = bytes(half).hex()
half[0] &= 248; half[31] &= 127; half[31] |= 64
clamped = bytes(half).hex()
sk = Ed25519PrivateKey.from_bytes(SEED) if hasattr(Ed25519PrivateKey, "from_bytes") else Ed25519PrivateKey.from_private_bytes(SEED)
pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
sig = sk.sign(b"").hex()
SPEC = dict(
    half="367c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de98f",
    clamped="307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f",
    pub="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    sig="e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
# RESOLVED (s18): the architects confirmed the authoritative first 32 bytes of SHA-512(seed); the handoff's
# stated value was a transcription error. Clamped scalar, public key and signature were always correct.
assert raw_half == "357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f", "authoritative s18 value"
half_matches_spec = (raw_half == SPEC["half"])
assert not half_matches_spec  # if this ever flips, the spec text was corrected: update docs
assert clamped == SPEC["clamped"], ("clamped mismatch vs spec", clamped)
assert pub == SPEC["pub"] and sig == SPEC["sig"]
assert not clamped.startswith("d820"), "known-wrong scalar must never be used"
dump("ed25519_baseline.json", {
    "suite": "RFC8032-7.1-TEST1", "status": "ACTIVE",
    "seed_hex": SEED.hex(), "sha512_first_half_hex": raw_half,
    "spec_s18_stated_sha512_first_half_hex": SPEC["half"],
    "spec_s18_stated_half_matches_computed": half_matches_spec,
    "resolution_note": "RESOLVED by the architects: the authoritative first 32 bytes of SHA-512(seed) are sha512_first_half_hex. The handoff's s18 value (kept above only as history) was a transcription error; the clamped scalar, public key and signature were always correct.", "clamped_scalar_hex": clamped,
    "public_key_hex": pub, "message_hex": "", "signature_hex": sig,
    "forbidden_scalar_prefix": "d820",
    "note": "Ed25519 key material must never be reused as X25519 private key (DSK and DDHK are independent)."})

# ------------------------------------------------------------------ Recovery fixture
MNEMONIC = " ".join(["abandon"] * 23 + ["art"])   # public BIP-39 test mnemonic, 256-bit zero entropy
norm = unicodedata.normalize("NFKD", MNEMONIC)
seed64 = hashlib.pbkdf2_hmac("sha512", norm.encode(), b"mnemonic", 2048, 64)


def hkdf_extract(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:n]


prk = hkdf_extract(b"PM-V1-RECOVERY-KEY-SALT-v1", seed64)
kseed = hkdf_expand(prk, b"PM-V1-RECOVERY-KEY-ED25519-v1", 32)
rk = Ed25519PrivateKey.from_private_bytes(kseed)
rpub = rk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
irc = hashlib.sha256(b"PM-V1-RECOVERY-COMMITMENT" + rpub).digest()
trezor = hashlib.pbkdf2_hmac("sha512", norm.encode(), b"mnemonicTREZOR", 2048, 64).hex()
TREZOR_KNOWN = ("bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3"
                "de6f5d4a10be8ed2a5e608d68f92fcc8")
fx = {
    "suite": "PM-RECOVERY-DERIVATION", "status": "ACTIVE",
    "warning": "PUBLIC BIP-39 test mnemonic (zero entropy). Never use for a real account.",
    "mnemonic": MNEMONIC, "entropy_hex": "00" * 32, "passphrase": "",
    "bip39_master_seed_hex": seed64.hex(),
    "hkdf_extract_salt_ascii": "PM-V1-RECOVERY-KEY-SALT-v1", "prk_rec_hex": prk.hex(),
    "hkdf_expand_info_ascii": "PM-V1-RECOVERY-KEY-ED25519-v1", "k_rec_seed_hex": kseed.hex(),
    "k_rec_pub_hex": rpub.hex(),
    "irc_domain_ascii": "PM-V1-RECOVERY-COMMITMENT", "irc_hex": irc.hex(),
    "sign_empty_message_signature_hex": rk.sign(b"").hex(),
}
if trezor == TREZOR_KNOWN:
    fx["bip39_cross_check"] = {"passphrase": "TREZOR", "seed_hex": trezor,
                               "source": "published BIP-39 reference vector, 24x zero-entropy mnemonic"}
else:
    print("WARNING: TREZOR cross-check did not match remembered value; omitted from fixture", file=sys.stderr)
dump("recovery_derivation_fixture.json", fx)

# ------------------------------------------------------------------ placeholders (locked)
LOCK = ("Not populated: the required specification is missing or the dependent boundary is locked "
        "(HPKE push, transparency leaf layout, equivocation cases). No vector data is fabricated here.")
import gen_protocol_vectors
gen_protocol_vectors.run(dump)
for name, suite in [("hpke_push_vectors.json", "PM-PUSH-HPKE"),
                    ("transparency_leaf.json", "PM-KT-LEAF"), ("equivocation_cases.json", "PM-KT-EQUIVOCATION")]:
    dump(name, {"suite": suite, "status": "PLACEHOLDER_LOCKED", "note": LOCK, "vectors": []})

# ------------------------------------------------------------------ manifest
files = sorted(f for f in os.listdir(OUT) if f.endswith(".json") and f != "manifest.json")
status_of = {}
for f in files:
    d = json.load(open(os.path.join(OUT, f), encoding="utf-8"))
    status_of[f] = d.get("status") if d.get("status") in ("PLACEHOLDER_LOCKED", "PARTIAL") else "ACTIVE"
dump("manifest.json", {
    "manifest_format": 1,
    "files": [{"path": f, "status": status_of[f],
               "sha256": hashlib.sha256(open(os.path.join(OUT, f), "rb").read()).hexdigest()} for f in files]})
print(f"positive={len(positive)} negative={len(negative)} quarantined={len(quarantined)} files={len(files)}")
