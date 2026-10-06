#!/usr/bin/env python3
"""Shared vector validation (CI step 5). Run from repo root: python3 tools/check_vectors.py

Checks: manifest hashes; CBOR vectors against the independent Python reference
codec; RFC 8032 baseline; recovery derivation. This does NOT replace the Rust/Go
parity tests: it is a third, independent implementation used to validate the
vector files themselves.
"""
import hashlib, hmac, json, os, sys, unicodedata
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pmcbor_ref as R

V = os.path.join(HERE, "..", "test-vectors", "v1")
failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def load(n):
    with open(os.path.join(V, n), "rb") as f:
        raw = f.read()
    return raw, json.loads(raw)


# manifest
_, man = load("manifest.json")
listed = {e["path"] for e in man["files"]}
for e in man["files"]:
    raw, _ = load(e["path"])
    check(hashlib.sha256(raw).hexdigest() == e["sha256"], f"manifest hash mismatch: {e['path']}")
on_disk = {f for f in os.listdir(V) if f.endswith(".json") and f != "manifest.json"}
check(listed == on_disk, f"manifest/file-set mismatch: {listed ^ on_disk}")
for e in man["files"]:
    if e["status"] == "PLACEHOLDER_LOCKED":
        _, d = load(e["path"])
        check(d.get("vectors") == [], f"placeholder {e['path']} must contain no vectors")

# CBOR
_, c = load("cbor_canonical_codec.json")
check(set(c["error_categories"]) == set(R.CATEGORIES), "error category set drift")
ids = set()
for p in c["positive"]:
    check(p["id"] not in ids, f"duplicate id {p['id']}"); ids.add(p["id"])
    want = bytes.fromhex(p["cbor_hex"])
    check(R.encode(R.from_tagged(p["value"])) == want, f"encode mismatch {p['id']}")
    try:
        check(R.encode(R.decode_strict(want)) == want, f"roundtrip mismatch {p['id']}")
    except R.CborError as e:
        check(False, f"positive {p['id']} rejected: {e.category}")
for n in c["negative"]:
    check(n["id"] not in ids, f"duplicate id {n['id']}"); ids.add(n["id"])
    check(n["error"] in R.CATEGORIES, f"unknown category {n['error']}")
    try:
        R.decode_strict(bytes.fromhex(n["cbor_hex"]))
        check(False, f"negative {n['id']} accepted")
    except R.CborError as e:
        check(e.category == n["error"], f"negative {n['id']}: got {e.category}, want {n['error']}")
for q in c["quarantined"]:
    check(q["status"] == "RESOLVED_AUTHORITATIVE", "s28 entry status")
    check(q["rfc8949_hex"] == "852037381838ff390100", "authoritative s28 vector")
    check(R.encode(R.from_tagged(q["value"])).hex() == q["rfc8949_hex"], "quarantine rfc hex")
    try:
        R.decode_strict(bytes.fromhex(q["spec_s28_corrected_hex_as_written"]))
        check(False, "spec s28 as-written bytes decoded")
    except R.CborError as e:
        check(e.category == q["spec_s28_as_written_decodes_to"], "quarantine as-written category")

# Ed25519
_, e8 = load("ed25519_baseline.json")
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(e8["seed_hex"]))
    check(sk.public_key().public_bytes(*raw).hex() == e8["public_key_hex"], "ed25519 pubkey")
    check(sk.sign(b"").hex() == e8["signature_hex"], "ed25519 empty-message signature")
    h = bytearray(hashlib.sha512(bytes.fromhex(e8["seed_hex"])).digest()[:32])
    check(h.hex() == e8["sha512_first_half_hex"], "sha512 half")
    check(e8["sha512_first_half_hex"] == "357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f", "authoritative s18 value")
    h[0] &= 248; h[31] &= 127; h[31] |= 64
    check(h.hex() == e8["clamped_scalar_hex"], "clamped scalar")
    check(not e8["clamped_scalar_hex"].startswith(e8["forbidden_scalar_prefix"]), "forbidden scalar")
    # recovery
    _, r = load("recovery_derivation_fixture.json")
    norm = unicodedata.normalize("NFKD", r["mnemonic"])
    seed = hashlib.pbkdf2_hmac("sha512", norm.encode(), b"mnemonic" + r["passphrase"].encode(), 2048, 64)
    check(seed.hex() == r["bip39_master_seed_hex"], "bip39 seed")
    prk = hmac.new(r["hkdf_extract_salt_ascii"].encode(), seed, hashlib.sha256).digest()
    check(prk.hex() == r["prk_rec_hex"], "prk_rec")
    ks = hmac.new(prk, r["hkdf_expand_info_ascii"].encode() + b"\x01", hashlib.sha256).digest()
    check(ks.hex() == r["k_rec_seed_hex"], "k_rec_seed")
    rk = Ed25519PrivateKey.from_private_bytes(ks)
    pub = rk.public_key().public_bytes(*raw)
    check(pub.hex() == r["k_rec_pub_hex"], "k_rec_pub")
    check(hashlib.sha256(r["irc_domain_ascii"].encode() + pub).hexdigest() == r["irc_hex"], "irc")
    check(rk.sign(b"").hex() == r["sign_empty_message_signature_hex"], "recovery signature")
except ImportError:
    print("SKIP: 'cryptography' not installed; Ed25519/recovery checks not run", file=sys.stderr)
    failures.append("cryptography package missing (pip install cryptography)")

# ---- codec bounds not expressible as small shared vectors
check(R.MAX_DEPTH == 8 and R.MAX_MAP_ENTRIES == 32 and R.MAX_BSTR == 65552 and R.MAX_WIRE_INPUT == 262144,
      "bounds constants drifted from the architecture-review lock")
try:
    R.decode_strict(bytes(R.MAX_WIRE_INPUT + 1)); check(False, "wire cap not enforced")
except R.CborError as e:
    check(e.category == "ERR_LIMIT_EXCEEDED", "wire cap category")
try:
    check(len(R.decode_strict(b"\x5a\x00\x01\x00\x10" + bytes(R.MAX_BSTR))) == R.MAX_BSTR, "bstr at limit")
except R.CborError as e:
    check(False, f"bstr at limit rejected: {e.category}")
check(c["limits"]["max_depth"] == 8, "limits block in vector file")

# ---- Phase B contract vectors: recompute with INDEPENDENT code (cryptography's HKDF/HMAC/AEAD)
try:
    from cryptography.hazmat.primitives import hashes, hmac as chmac
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.exceptions import InvalidTag
    import struct

    def lib_hkdf(salt, ikm, info, n):          # extract+expand in one call, library implementation
        return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ikm)

    def lib_hmac(key, msg):
        h = chmac.HMAC(key, hashes.SHA256()); h.update(msg); return h.finalize()

    def dh(priv_hex, pub_hex):
        return X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)).exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)))

    def pubhex(priv_hex):
        return X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)).public_key().public_bytes(*raw).hex()

    _, hs = load("bi_x3dh_handshake.json")
    for lab, d in hs["labels"].items():
        check(len(bytes.fromhex(d["hex"])) == d["length"] and bytes.fromhex(d["hex"]).decode() == d["ascii"], f"label {lab}")
    L = {k: bytes.fromhex(v["hex"]) for k, v in hs["labels"].items()}
    for case in hs["cases"]:
        i, dv = case["inputs"], case["derived"]
        for k in ("ik_a", "ek_a", "ik_b", "spk_b") + (("opk_b",) if "opk_b_priv" in i else ()):
            check(pubhex(i[k + "_priv"]) == i[k + "_pub"], f"{case['id']}: pub of {k}")
        dhs = [dh(i["ik_a_priv"], i["spk_b_pub"]), dh(i["ek_a_priv"], i["ik_b_pub"]), dh(i["ek_a_priv"], i["spk_b_pub"])]
        if "opk_b_pub" in i:
            dhs.append(dh(i["ek_a_priv"], i["opk_b_pub"]))
        ikm = b"".join(dhs)
        check(ikm.hex() == dv["ikm"] and len(ikm) == dv["ikm_length"], f"{case['id']}: IKM")
        ctx = bytes.fromhex(i["ik_a_pub"]) + bytes.fromhex(i["ik_b_pub"]) + struct.pack(">II", i["epoch_a"], i["epoch_b"])
        check(ctx.hex() == dv["context"] and len(ctx) == 72, f"{case['id']}: context")
        sk = lib_hkdf(L["X3DH_SALT"], ikm, L["X3DH_INFO"] + ctx, 32)
        check(sk.hex() == dv["sk"], f"{case['id']}: SK")
        # responder side computes the same SK
        rdhs = [dh(i["spk_b_priv"], i["ik_a_pub"]), dh(i["ik_b_priv"], i["ek_a_pub"]), dh(i["spk_b_priv"], i["ek_a_pub"])]
        if "opk_b_priv" in i:
            rdhs.append(dh(i["opk_b_priv"], i["ek_a_pub"]))
        check(rdhs == dhs, f"{case['id']}: responder DH mismatch")
    t = hs["cert_dh_transcript"]
    tr = L["DH_BIND"] + bytes.fromhex(t["account_id"]) + bytes.fromhex(t["device_id"]) + bytes.fromhex(t["ddhk_pub"]) + struct.pack(">Q", t["timestamp"])
    check(tr.hex() == t["transcript_hex"] and len(tr) == 85 and hashlib.sha256(tr).hexdigest() == t["transcript_sha256"], "cert_dh transcript")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EPriv, Ed25519PublicKey as _EPub
    from cryptography.exceptions import InvalidSignature
    dsk = _EPriv.from_private_bytes(bytes.fromhex(t["dsk_seed_hex"]))
    check(t["signer"].startswith("sender device DSK"), "Cert_dh signer is the sender device DSK")
    check(dsk.public_key().public_bytes(*raw).hex() == t["dsk_pub_hex"], "DSK public key")
    check(dsk.sign(tr).hex() == t["signature_hex"], "Cert_dh signature recomputed")
    check(t["dsk_pub_hex"] != t["ddhk_pub"] and t["dsk_seed_hex"] != hs["cases"][0]["inputs"]["ik_a_priv"], "DSK and DDHK are separate keys")
    try:
        _EPub.from_public_bytes(bytes.fromhex(t["dsk_pub_hex"])).verify(bytes.fromhex(t["signature_hex"]), tr)
    except InvalidSignature:
        check(False, "Cert_dh signature does not verify")
    try:
        _EPub.from_public_bytes(bytes.fromhex(t["dsk_pub_hex"])).verify(bytes.fromhex(t["signature_hex"]), tr[:-1] + bytes([tr[-1] ^ 1]))
        check(False, "Cert_dh signature verified over a tampered transcript")
    except InvalidSignature:
        pass

    _, dr = load("double_ratchet_linear.json")
    def lib_kdf_rk(rk, dh_out):
        return lib_hkdf(rk, dh_out, L["DR_ROOT_INFO"], 32), lib_hkdf(rk, dh_out, L["DR_CHAIN_INFO"], 32)
    def lib_kdf_ck(ck):
        return lib_hmac(ck, b"\x02"), lib_hmac(ck, b"\x01")       # (CK_next, K_msg)
    v = dr["kdf_ck_vector"]; ckn, km = lib_kdf_ck(bytes.fromhex(v["ck"]))
    check((ckn.hex(), km.hex()) == (v["ck_next"], v["k_msg"]), "KDF_CK vector")
    v = dr["kdf_rk_vector"]; rkn, cko = lib_kdf_rk(bytes.fromhex(v["rk"]), bytes.fromhex(v["dh_out"]))
    check((rkn.hex(), cko.hex()) == (v["rk_next"], v["ck_out"]), "KDF_RK vector")
    sk = bytes.fromhex(dr["sk"])
    check(sk.hex() == next(x for x in hs["cases"] if x["id"] == dr["handshake_case"])["derived"]["sk"], "ratchet SK matches handshake")
    hi = next(x for x in hs["cases"] if x["id"] == dr["handshake_case"])["inputs"]
    a = dr["alice"]
    check(hi["epoch_a"] != hi["epoch_b"], "test epochs must differ")
    check(dr["message_0"]["aad_inputs"]["account_epoch"] == hi["epoch_b"], "AAD account_epoch must be Epoch_B (recipient)")
    check(pubhex(a["dhs_a0_priv"]) == a["dhs_a0_pub"], "dhs_a0 pub")
    rk_a, ck_s = lib_kdf_rk(sk, dh(a["dhs_a0_priv"], hi["spk_b_pub"]))
    ck_after, k0 = lib_kdf_ck(ck_s)
    check((rk_a.hex(), ck_s.hex(), k0.hex(), ck_after.hex()) == (a["rk_a"], a["ck_s_initial"], a["k_msg_0"], a["ck_s_after_msg0"]), "Alice init + message 0 keys")
    m = dr["message_0"]; ai = m["aad_inputs"]
    aad = (L["MSG_AAD"] + bytes([ai["protocol_version"]]) + bytes.fromhex(ai["envelope_id"]) + bytes.fromhex(ai["sender_device_id"])
           + bytes.fromhex(ai["recipient_device_id"]) + struct.pack(">I", ai["account_epoch"]) + bytes([ai["prekey_flag"]])
           + bytes.fromhex(ai["ratchet_header_hex"]))
    check(aad.hex() == m["aad_hex"], "AAD_msg bytes")
    hdr = R.decode_strict(bytes.fromhex(ai["ratchet_header_hex"]))
    check(R.encode(hdr) == bytes.fromhex(ai["ratchet_header_hex"]), "PrekeyHandshakeHeader is canonical PM-CBOR")
    hd = dict(hdr)
    opk_present = "opk_b_pub" in hi
    check(set(hd) == (set(range(1, 12)) if opk_present else set(range(1, 12)) - {9}), "header field set 1-11 (field 9 only with an OPK)")
    def isb(k, n): return isinstance(hd.get(k), bytes) and len(hd[k]) == n
    def isu(k, mx): return isinstance(hd.get(k), int) and not isinstance(hd.get(k), bool) and 0 <= hd[k] <= mx
    check(isb(1, 16) and isb(3, 32) and isb(4, 32) and isb(5, 64) and isb(7, 32) and isb(10, 32), "header byte-string lengths")
    check(isu(2, 2**32 - 1) and isu(6, 2**64 - 1) and isu(8, 2**32 - 1) and (not opk_present or isu(9, 2**32 - 1)) and hd.get(11) == 0,
          "header integer fields and sequence_number == 0")
    ct_ = hs["cert_dh_transcript"]
    check(hd[2] == hi["epoch_a"], "header sender_account_epoch == Epoch_A")
    check(hd[4].hex() == hi["ik_a_pub"] and hd[7].hex() == hi["ek_a_pub"], "header DDHK/ephemeral keys match handshake vector")
    check(hd[10].hex() == a["dhs_a0_pub"], "header initial_ratchet_pub == Alice DHS_A0")
    check(hd[8] == hi["recipient_spk_id"] and (not opk_present or hd[9] == hi["recipient_opk_id"]), "header prekey ids match handshake vector")
    check(hd[1].hex() == ct_["account_id"] and hd[3].hex() == ct_["dsk_pub_hex"] and hd[5].hex() == ct_["signature_hex"]
          and hd[6] == ct_["timestamp"], "header Cert_dh fields match handshake vector")
    check(ai["sender_device_id"] == ct_["device_id"], "envelope sender_device_id == Cert_dh DeviceID")
    # recipient-side verification: transcript from header fields 1, 4, 6 plus the envelope's sender_device_id
    tr2 = L["DH_BIND"] + hd[1] + bytes.fromhex(ai["sender_device_id"]) + hd[4] + struct.pack(">Q", hd[6])
    try:
        _EPub.from_public_bytes(hd[3]).verify(hd[5], tr2)
    except InvalidSignature:
        check(False, "header sender_cert_dh does not verify under sender_dsk_pub")
    listing = {int(k.split("_")[0]): v for k, v in m["prekey_handshake_header"]["fields"].items()}
    check(set(listing) == set(hd) and all(listing[n] == (hd[n].hex() if isinstance(hd[n], bytes) else hd[n]) for n in hd),
          "human-readable header field listing matches the decoded header")
    check(ChaCha20Poly1305(k0).encrypt(bytes(12), bytes.fromhex(m["plaintext_hex"]), aad).hex() == m["ciphertext_with_tag_hex"], "message 0 ciphertext")
    b = dr["bob"]
    rk_t, ck_r = lib_kdf_rk(sk, dh(hi["spk_b_priv"], a["dhs_a0_pub"]))
    check(pubhex(b["dhs_b1_priv"]) == b["dhs_b1_pub"], "dhs_b1 pub")
    rk_b, ck_sb = lib_kdf_rk(rk_t, dh(b["dhs_b1_priv"], a["dhs_a0_pub"]))
    ck_ra, k0b = lib_kdf_ck(ck_r)
    check((rk_t.hex(), ck_r.hex(), ck_ra.hex(), rk_b.hex(), ck_sb.hex()) == (b["rk_temp"], b["ck_r_before_decrypt"], b["ck_r_after"], b["rk_b_final"], b["ck_s_final"]), "Bob ingestion state")
    check(k0b == k0, "Bob derives Alice's K_msg,0")
    check((b["ns"], b["nr"], b["pn"]) == (0, 1, 0), "Bob counters after commit")
    rk_a2, ck_ra2 = lib_kdf_rk(rk_a, dh(a["dhs_a0_priv"], b["dhs_b1_pub"]))
    check((rk_a2, ck_ra2) == (rk_b, ck_sb), "Alice/Bob chain agreement after Bob's reply")
    for n in dr["negative"]:
        try:
            ChaCha20Poly1305(k0b).decrypt(bytes(12), bytes.fromhex(n["ciphertext_hex"]), bytes.fromhex(n["aad_hex"]))
            check(False, f"negative {n['id']} authenticated")
        except InvalidTag:
            pass

    _, md = load("media_chunk_aead.json")
    check(md["status"] == "ACTIVE" and "blocked" not in md, "media vector status")
    prk = lib_hkdf(L["MEDIA_NONCE_SALT"], bytes.fromhex(md["k_media_hex"]), L["MEDIA_NONCE_INFO"], 4)
    check(prk.hex() == md["nonce_salt_hex"], "media nonce salt")
    for nn in md["nonces"]:
        check((prk + struct.pack(">Q", nn["i"])).hex() == nn["nonce_hex"], f"media nonce i={nn['i']}")
    check(len({nn["nonce_hex"] for nn in md["nonces"]}) == len(md["nonces"]), "nonces unique")
    # chunk AEAD with MediaChunkAAD (PM-CBOR-2026), recomputed independently
    k_media = bytes.fromhex(md["k_media_hex"])
    conts = {}
    for cs in md["chunk_aead_cases"]:
        ln, S, total = cs["plaintext_length"], cs["bucket"], cs["total_chunks"]
        check(S == min(b2 for b2 in md["allh_buckets"] if b2 >= ln + 1) and total == S // 65536, f"{cs['id']}: bucket/total_chunks")
        cont = (bytes(range(251)) * (ln // 251 + 1))[:ln] + b"\x80" + bytes(S - ln - 1)
        conts[cs["id"]] = cont
        mid = bytes.fromhex(cs["media_id_hex"])
        check(len(mid) == 16 and mid[6] >> 4 == 7, f"{cs['id']}: media_id is a UUIDv7")
        check(len(cs["chunks"]) == total, f"{cs['id']}: chunk count")
        for ch in cs["chunks"]:
            idx = ch["index"]
            aad_c = R.encode(R.Map([(1, 1), (2, mid), (3, idx), (4, total), (5, ln), (6, S)]))
            check(aad_c.hex() == ch["aad_hex"], f"{cs['id']}[{idx}]: MediaChunkAAD bytes")
            dec = dict(R.decode_strict(aad_c))
            check(set(dec) == {1, 2, 3, 4, 5, 6} and dec[1] == 1 and dec[3] == idx and dec[4] == total, f"{cs['id']}[{idx}]: AAD fields")
            nonce = prk + struct.pack(">Q", idx)
            check(nonce.hex() == ch["nonce_hex"], f"{cs['id']}[{idx}]: nonce")
            ct = ChaCha20Poly1305(k_media).encrypt(nonce, cont[idx * 65536:(idx + 1) * 65536], aad_c)
            check(len(ct) == ch["ciphertext_length"] == R.MAX_BSTR, f"{cs['id']}[{idx}]: ciphertext length")
            check(hashlib.sha256(ct).hexdigest() == ch["ciphertext_sha256"] and ct[:32].hex() == ch["ciphertext_first32_hex"]
                  and ct[-16:].hex() == ch["tag_hex"], f"{cs['id']}[{idx}]: ciphertext/tag")
            check(ChaCha20Poly1305(k_media).decrypt(nonce, ct, aad_c) == cont[idx * 65536:(idx + 1) * 65536], f"{cs['id']}[{idx}]: decrypt")
    for ng in md["chunk_aead_negative"]:
        cs = next(x for x in md["chunk_aead_cases"] if x["id"] == ng["case"])
        ci = ng["ciphertext_of_chunk"]
        good = ChaCha20Poly1305(k_media).encrypt(prk + struct.pack(">Q", ci), conts[cs["id"]][ci * 65536:(ci + 1) * 65536],
                                                 bytes.fromhex(cs["chunks"][ci]["aad_hex"]))
        f = ng["aad_fields"]
        bad_aad = R.encode(R.Map([(1, 1), (2, bytes.fromhex(cs["media_id_hex"])), (3, f["chunk_index"]), (4, f["total_chunks"]),
                                  (5, f["unpadded_file_length"]), (6, f["padded_container_size"])]))
        try:
            ChaCha20Poly1305(k_media).decrypt(prk + struct.pack(">Q", ng["nonce_index"]), good, bad_aad)
            check(False, f"negative chunk vector {ng['id']} authenticated")
        except InvalidTag:
            pass
    check(md["allh_buckets"] == [65536, 262144, 1048576, 5242880, 20971520, 104857600], "ALLH buckets")
    for fr in md["allh_framing"]:
        ln, S = fr["plaintext_length"], fr["bucket"]
        pt_m = (bytes(range(251)) * (ln // 251 + 1))[:ln]
        cont = pt_m + b"\x80" + bytes(S - ln - 1)
        check(hashlib.sha256(cont).hexdigest() == fr["container_sha256"] and S >= ln + 1 and S % 65536 == 0, f"ALLH framing L={ln}")
        check(fr["ciphertext_chunk_length"] == R.MAX_BSTR, "chunk ciphertext length equals codec bstr bound")
        check(all(b2 < ln + 1 for b2 in md["allh_buckets"] if b2 < S), f"bucket is smallest fit L={ln}")
    def v_allh(cx, ln):
        if len(cx) < ln + 1: return "INVALID_LENGTH"
        if cx[ln] != 0x80: return "INVALID_MARKER"
        return "INVALID_PADDING" if any(cx[ln + 1:]) else "OK"
    for vv in md["allh_validation_structural"]:
        check(v_allh(bytes.fromhex(vv["container_hex"]), vv["plaintext_length"]) == vv["expected"], f"ALLH validation {vv['id']}")
except ImportError:
    failures.append("cryptography package missing (pip install cryptography)")

if failures:
    print("VECTOR CHECK FAILED"); [print(" -", f) for f in failures]; sys.exit(1)
print(f"vector check OK: {len(c['positive'])} positive, {len(c['negative'])} negative CBOR vectors; "
      f"ed25519 + recovery fixtures verified; manifest hashes OK")
