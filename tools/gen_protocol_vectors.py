"""Derives the Phase B contract vectors from tools/pm_proto_ref.py (reference model).
Called by gen_vectors.py. Every derived fact that the memo implies (Alice/Bob agreement, chain
agreement after Bob's reply) is ASSERTED here, so an incoherent spec fails generation."""
import hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pm_proto_ref as P
import pmcbor_ref as R
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

H = lambda b: b.hex()
TESTONLY = "ALL private keys in this file are TEST-ONLY, derived from SHA-256('PM-TEST-ONLY-KEY:'+name). Never use for real keys."


def labels_json():
    return {k: {"ascii": v.decode(), "hex": H(v), "length": n} for k, (v, n) in P.LABELS.items()}


def run(dump):
    ea, eb = 1, 3                       # distinct so epoch ordering bugs are caught
    keys = {n: P.test_priv(n) for n in ("ik_a", "ek_a", "ik_b", "spk_b", "opk_b", "dhs_a0", "dhs_b1")}
    pubs = {n: P.pub_of(k) for n, k in keys.items()}

    # ------------------------------------------------ handshake
    SPK_ID, OPK_ID = 7, 42                 # test-only prekey identifiers
    cases = []
    for cid, use_opk in (("with_opk", True), ("without_opk", False)):
        opk_pub = pubs["opk_b"] if use_opk else None
        opk_priv = keys["opk_b"] if use_opk else None
        dhs_a, out_a = P.x3dh_initiator(keys["ik_a"], keys["ek_a"], pubs["ik_b"], pubs["spk_b"], opk_pub, ea, eb)
        dhs_b, out_b = P.x3dh_responder(keys["ik_b"], keys["spk_b"], opk_priv, pubs["ik_a"], pubs["ek_a"], ea, eb)
        assert dhs_a == dhs_b and out_a["sk"] == out_b["sk"], "initiator/responder disagree"
        assert len(out_a["ikm"]) == (128 if use_opk else 96)
        cases.append({
            "id": cid,
            "inputs": {"epoch_a": ea, "epoch_b": eb, "recipient_spk_id": SPK_ID,
                       **({"recipient_opk_id": OPK_ID} if use_opk else {}),
                       **{f"{n}_priv": H(keys[n]) for n in ("ik_a", "ek_a", "ik_b", "spk_b")},
                       **{f"{n}_pub": H(pubs[n]) for n in ("ik_a", "ek_a", "ik_b", "spk_b")},
                       **({"opk_b_priv": H(keys["opk_b"]), "opk_b_pub": H(pubs["opk_b"])} if use_opk else {})},
            "derived": {**{f"dh{i+1}": H(d) for i, d in enumerate(dhs_a)},
                        "ikm": H(out_a["ikm"]), "ikm_length": len(out_a["ikm"]), "prk": H(out_a["prk"]),
                        "context": H(out_a["context"]), "context_length": 72, "sk": H(out_a["sk"])}})
    # the two cases must give different SKs (OPK actually contributes)
    assert cases[0]["derived"]["sk"] != cases[1]["derived"]["sk"]

    account_id, device_id = bytes([0xA0 + i for i in range(16)]), bytes([0xB0 + i for i in range(16)])
    ts = 1760000000
    transcript = P.L["DH_BIND"] + account_id + device_id + pubs["ik_a"] + P.be64(ts)
    assert len(transcript) == 85
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    dsk_seed = P.test_priv("dsk_a")                       # DSK is a SEPARATE Ed25519 key from DDHK
    dsk = Ed25519PrivateKey.from_private_bytes(dsk_seed)
    dsk_pub = dsk.public_key().public_bytes(*P.RAW)
    assert dsk_seed != keys["ik_a"] and dsk_pub != pubs["ik_a"], "DSK must not equal DDHK material"
    cert_sig = dsk.sign(transcript)
    dsk.public_key().verify(cert_sig, transcript)
    dump("bi_x3dh_handshake.json", {
        "suite": "PM-BI-X3DH-1", "status": "ACTIVE", "origin": "python reference model; see IMPLEMENTATION_NOTES.md",
        "test_only_keys_warning": TESTONLY, "labels": labels_json(), "cases": cases,
        "cert_dh_transcript": {
            "account_id": H(account_id), "device_id": H(device_id), "ddhk_pub": H(pubs["ik_a"]),
            "timestamp": ts, "transcript_hex": H(transcript), "transcript_length": 85,
            "transcript_sha256": hashlib.sha256(transcript).hexdigest(),
            "signer": "sender device DSK (Ed25519)", "signature_scheme": "Ed25519Sign(DSK_priv, transcript)",
            "dsk_seed_hex": H(dsk_seed), "dsk_pub_hex": H(dsk_pub), "signature_hex": H(cert_sig),
            "note": "Cert_dh = Ed25519Sign(DSK_priv, transcript). PrekeyHandshakeHeader carries the timestamp (field 6) needed to rebuild the exact transcript."},
        "assumptions": ["Epoch_A = sender (initiator) account epoch, Epoch_B = recipient account epoch; 4-byte big-endian, in that order in Context."]})

    # ------------------------------------------------ ratchet: Alice init, message 0, Bob ingestion
    sk = bytes.fromhex(cases[0]["derived"]["sk"])
    dhs_a0_priv, dhs_a0_pub = keys["dhs_a0"], pubs["dhs_a0"]
    rk_a, ck_s = P.kdf_rk(sk, P.x25519(dhs_a0_priv, pubs["spk_b"]))
    ck_s_after, k0 = P.kdf_ck(ck_s)

    # Complete frozen PrekeyHandshakeHeader (fields 1-11; field 9 present because the with_opk case is used).
    assert len(cert_sig) == 64 and len(dsk_pub) == 32
    hdr_fields = [(1, account_id), (2, ea), (3, dsk_pub), (4, pubs["ik_a"]), (5, cert_sig), (6, ts),
                  (7, pubs["ek_a"]), (8, SPK_ID), (9, OPK_ID), (10, dhs_a0_pub), (11, 0)]
    header = R.encode(R.Map(hdr_fields))
    # sender_device_id must equal the Cert_dh DeviceID: the header has no device-id field, so the recipient
    # rebuilds the Cert_dh transcript from the envelope's sender_device_id.
    env_id, snd, rcv = bytes(range(0x10, 0x20)), device_id, bytes(range(0x30, 0x40))
    aad = P.aad_msg(1, env_id, snd, rcv, eb, 1, header)   # account_epoch = Epoch_B (RECIPIENT)
    assert len(aad) == 13 + 1 + 16 + 16 + 16 + 4 + 1 + len(header)
    pt = b"hello pm"
    ct = P.aead_encrypt(k0, pt, aad)

    # Bob (Steps 1-4)
    rk_temp, ck_r = P.kdf_rk(sk, P.x25519(keys["spk_b"], dhs_a0_pub))
    assert rk_temp == rk_a, "Alice RK_A must equal Bob RK_temp"
    dhs_b1_priv, dhs_b1_pub = keys["dhs_b1"], pubs["dhs_b1"]
    rk_b, ck_s_b = P.kdf_rk(rk_temp, P.x25519(dhs_b1_priv, dhs_a0_pub))
    ck_r_after, k0_b = P.kdf_ck(ck_r)
    assert k0_b == k0 and ck_r_after == ck_s_after, "Bob must derive Alice's chain"
    assert P.aead_decrypt(k0_b, ct, aad) == pt

    # Alice later receives Bob's reply: her receiving chain must equal Bob's new sending chain.
    rk_a2, ck_r_a = P.kdf_rk(rk_a, P.x25519(dhs_a0_priv, dhs_b1_pub))
    assert (rk_a2, ck_r_a) == (rk_b, ck_s_b), "post-reply chain agreement failed"

    pre_state = {"rk_b": H(sk), "dhs_b": "spk_b", "dhr_b": None, "ck_s": None, "ck_r": None, "ns": 0, "nr": 0, "pn": 0}
    negatives = []
    bad_ct = bytearray(ct); bad_ct[-1] ^= 1
    bad_aad = bytearray(aad); bad_aad[len(P.L["MSG_AAD"]) + 1] ^= 1       # flips a bit of envelope_id
    for nid, c, a in (("tampered_ciphertext_tag", bytes(bad_ct), aad), ("tampered_aad_envelope_id", ct, bytes(bad_aad))):
        try:
            P.aead_decrypt(k0, c, a)
            raise AssertionError(nid + " unexpectedly authenticated")
        except InvalidTag:
            pass
        negatives.append({"id": nid, "ciphertext_hex": H(c), "aad_hex": H(a), "expected": "AEAD_AUTH_FAILURE",
                          "expected_state_after": "UNCHANGED: Bob state must equal pre_ingestion_state exactly"})

    kck = bytes([0x01] * 32)
    ck_next_v, k_v = P.kdf_ck(kck)
    rk_v_next, ck_v_out = P.kdf_rk(bytes([0x02] * 32), bytes([0x03] * 32))
    dump("double_ratchet_linear.json", {
        "suite": "PM-DR-LINEAR", "status": "ACTIVE", "origin": "python reference model",
        "test_only_keys_warning": TESTONLY, "labels": labels_json(),
        "kdf_ck_vector": {"ck": H(kck), "k_msg": H(k_v), "ck_next": H(ck_next_v)},
        "kdf_rk_vector": {"rk": H(bytes([0x02] * 32)), "dh_out": H(bytes([0x03] * 32)),
                          "rk_next": H(rk_v_next), "ck_out": H(ck_v_out)},
        "handshake_case": "with_opk", "sk": H(sk),
        "alice": {"dhs_a0_priv": H(dhs_a0_priv), "dhs_a0_pub": H(dhs_a0_pub), "rk_a": H(rk_a),
                  "ck_s_initial": H(ck_s), "k_msg_0": H(k0), "ck_s_after_msg0": H(ck_s_after), "ns_after": 1},
        "message_0": {
            "plaintext_hex": H(pt), "nonce_hex": H(P.ZERO_NONCE),
            "aad_inputs": {"protocol_version": 1, "envelope_id": H(env_id), "sender_device_id": H(snd),
                           "recipient_device_id": H(rcv), "account_epoch": eb, "prekey_flag": 1,
                           "ratchet_header_hex": H(header)},
            "aad_hex": H(aad), "ciphertext_with_tag_hex": H(ct),
            "prekey_handshake_header": {
                "note": "Complete frozen PrekeyHandshakeHeader (PM-CBOR-2026 map, fields 1-11). Field 9 is present because the with_opk case is used.",
                "fields": {"1_sender_account_id": H(account_id), "2_sender_account_epoch": ea, "3_sender_dsk_pub": H(dsk_pub),
                           "4_sender_ddhk_pub": H(pubs["ik_a"]), "5_sender_cert_dh": H(cert_sig), "6_sender_cert_dh_timestamp": ts,
                           "7_sender_ephemeral_pub": H(pubs["ek_a"]), "8_recipient_spk_id": SPK_ID, "9_recipient_opk_id": OPK_ID,
                           "10_initial_ratchet_pub": H(dhs_a0_pub), "11_sequence_number": 0}}},
        "bob": {"pre_ingestion_state": pre_state, "dhs_b1_priv": H(dhs_b1_priv), "dhs_b1_pub": H(dhs_b1_pub),
                "rk_temp": H(rk_temp), "ck_r_before_decrypt": H(ck_r), "ck_r_after": H(ck_r_after),
                "rk_b_final": H(rk_b), "ck_s_final": H(ck_s_b), "ns": 0, "nr": 1, "pn": 0},
        "alice_after_bob_reply": {"rk_a_next": H(rk_a2), "ck_r": H(ck_r_a),
                                  "equals_bob_rk_b_final_and_ck_s_final": True},
        "negative": negatives,
        "invariants": ["MessageEnvelope.field_5 == AAD account_epoch == Epoch_B (RECIPIENT account epoch)",
                       "Epoch_A (sender) appears only in the PM-BI-X3DH-1 HKDF Context and in the authenticated PrekeyHandshakeHeader as sender_account_epoch"],
        "assumptions": ["uint32/uint64 header fields are encoded as CBOR unsigned integers (minimal form); 'BE' applies to the HKDF Context and AAD only",
                        "sender_device_id (AAD/envelope) equals the Cert_dh DeviceID, because the header has no device-id field"]})

    # ------------------------------------------------ media
    k_media = bytes(range(0x40, 0x60))
    prk_n, salt4 = P.media_nonce_salt(k_media)
    idx = [0, 1, 65535, 4294967296, 18446744073709551615]
    nonces = [{"i": i, "nonce_hex": H(P.media_nonce(salt4, i))} for i in idx]
    assert len({n["nonce_hex"] for n in nonces}) == len(idx)
    framing = []
    for ln in (0, 5, 65535, 65536, 104857599):
        s = P.allh_bucket(ln)
        pt_m = (bytes(range(251)) * (ln // 251 + 1))[:ln]
        c = P.allh_container(pt_m, s)
        assert P.allh_validate(c, ln) == "OK" and len(c) == s and s % P.CHUNK == 0
        framing.append({"plaintext_length": ln, "bucket": s, "container_sha256": hashlib.sha256(c).hexdigest(),
                        "chunks": s // P.CHUNK, "ciphertext_chunk_length": P.CHUNK + 16,
                        "plaintext_pattern": "bytes(i % 251) for i in range(L)"})
    assert P.allh_bucket(104857600) is None
    bad = [{"id": "missing_marker", "container_hex": "01020000", "plaintext_length": 2, "expected": "INVALID_MARKER"},
           {"id": "nonzero_padding", "container_hex": "01028001", "plaintext_length": 2, "expected": "INVALID_PADDING"},
           {"id": "no_room_for_marker", "container_hex": "0102", "plaintext_length": 2, "expected": "INVALID_LENGTH"}]
    for b in bad:
        assert P.allh_validate(bytes.fromhex(b["container_hex"]), b["plaintext_length"]) == b["expected"]
    ok = {"id": "minimal_valid", "container_hex": "01028000", "plaintext_length": 2, "expected": "OK"}
    assert P.allh_validate(bytes.fromhex(ok["container_hex"]), 2) == "OK"
    # ---- chunk AEAD with the frozen MediaChunkAAD structure
    media_id = bytes([0x01, 0x8F, 0x2B, 0x3C, 0x4D, 0x5E, 0x7A, 0xBC, 0x8D, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB])
    assert media_id[6] >> 4 == 7 and media_id[8] >> 6 == 0b10        # UUIDv7 shape
    def chunk_case(cid, ln):
        S = P.allh_bucket(ln)
        pt_m = (bytes(range(251)) * (ln // 251 + 1))[:ln]
        cont = P.allh_container(pt_m, S)
        total = S // P.CHUNK
        chunks = []
        for idx in range(total):
            aad_c = P.media_chunk_aad(media_id, idx, total, ln, S)
            ct_c = P.media_chunk_encrypt(k_media, salt4, aad_c, idx, cont[idx * P.CHUNK:(idx + 1) * P.CHUNK])
            assert len(ct_c) == P.CHUNK + 16
            chunks.append({"index": idx, "aad_hex": H(aad_c), "nonce_hex": H(P.media_nonce(salt4, idx)),
                           "ciphertext_length": len(ct_c), "ciphertext_sha256": hashlib.sha256(ct_c).hexdigest(),
                           "ciphertext_first32_hex": H(ct_c[:32]), "tag_hex": H(ct_c[-16:])})
        return {"id": cid, "media_id_hex": H(media_id), "plaintext_length": ln, "bucket": S, "total_chunks": total,
                "plaintext_pattern": "bytes(i % 251) for i in range(L)", "chunks": chunks}, cont
    cases_m, conts = [], {}
    for cid, ln in (("single_chunk", 65535), ("multi_chunk_4", 100000)):
        c, cont = chunk_case(cid, ln)
        cases_m.append(c); conts[cid] = cont
    mc = cases_m[1]
    neg_m = []
    def neg_chunk(nid, ct_of, nonce_idx, aad_fields):
        cc = mc["chunks"][ct_of]
        cont = conts["multi_chunk_4"]
        good_aad = P.media_chunk_aad(media_id, ct_of, mc["total_chunks"], mc["plaintext_length"], mc["bucket"])
        ct_c = P.media_chunk_encrypt(k_media, salt4, good_aad, ct_of, cont[ct_of * P.CHUNK:(ct_of + 1) * P.CHUNK])
        bad_aad = P.media_chunk_aad(media_id, aad_fields["chunk_index"], aad_fields["total_chunks"],
                                    aad_fields["unpadded_file_length"], aad_fields["padded_container_size"])
        try:
            ChaCha20Poly1305(k_media).decrypt(P.media_nonce(salt4, nonce_idx), ct_c, bad_aad)
            raise AssertionError(nid + " unexpectedly authenticated")
        except InvalidTag:
            pass
        neg_m.append({"id": nid, "case": "multi_chunk_4", "ciphertext_of_chunk": ct_of, "nonce_index": nonce_idx,
                      "aad_fields": aad_fields, "expected": "AEAD_AUTH_FAILURE"})
    base = {"unpadded_file_length": mc["plaintext_length"], "padded_container_size": mc["bucket"]}
    neg_chunk("wrong_chunk_index_in_aad", 1, 1, {**base, "chunk_index": 2, "total_chunks": 4})
    neg_chunk("wrong_total_chunks_in_aad", 1, 1, {**base, "chunk_index": 1, "total_chunks": 5})
    neg_chunk("reordered_chunk_presented_as_2", 1, 2, {**base, "chunk_index": 2, "total_chunks": 4})
    neg_chunk("wrong_unpadded_length_in_aad", 1, 1, {"unpadded_file_length": 100001, "padded_container_size": mc["bucket"],
                                                      "chunk_index": 1, "total_chunks": 4})
    dump("media_chunk_aead.json", {
        "suite": "PM-ALLH-AEAD", "status": "ACTIVE", "origin": "python reference model", "labels": labels_json(),
        "k_media_hex": H(k_media), "prk_nonce_hex": H(prk_n), "nonce_salt_hex": H(salt4), "nonces": nonces,
        "allh_buckets": P.BUCKETS, "allh_bucket_selection": "smallest bucket S with S >= L+1 (resolved by the architects)",
        "allh_max_plaintext_length": P.BUCKETS[-1] - 1,
        "allh_framing": framing, "allh_validation_structural": [ok] + bad,
        "media_chunk_aad": {
            "structure": "PM-CBOR-2026 map {1:1, 2:media_id (16-byte UUIDv7), 3:chunk_index, 4:total_chunks, 5:unpadded_file_length, 6:padded_container_size}",
            "assumptions": ["chunk_index is zero-based, matching Nonce_i = NonceSalt || uint64_be(i)",
                            "K_media is used directly as the ChaCha20-Poly1305 key (memo derives only NonceSalt from it)",
                            "final-chunk and chunk-length are implied by total_chunks and padded_container_size (all chunks are 64 KiB)"]},
        "chunk_aead_cases": cases_m, "chunk_aead_negative": neg_m})
