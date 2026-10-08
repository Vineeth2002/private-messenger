#!/usr/bin/env python3
"""
Independent cryptographic validation of test-vectors/v1/normal_ratchet_linear.json.

Run from repository root:

    python tools/check_normal_vectors.py

This checker intentionally does not call the Rust implementation. It uses the
Python cryptography package plus the independent PM-CBOR reference codec to
recompute the normal-message headers, AAD, X25519 DH outputs, HKDF/HMAC chain
advancement, ChaCha20-Poly1305 ciphertexts, and both deterministic receive-side
DH-ratchet transitions.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pmcbor_ref as R
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac as chmac, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


V = os.path.join(HERE, "..", "test-vectors", "v1")
NORMAL_PATH = os.path.join(V, "normal_ratchet_linear.json")
DOUBLE_PATH = os.path.join(V, "double_ratchet_linear.json")
X3DH_PATH = os.path.join(V, "bi_x3dh_handshake.json")
MANIFEST_PATH = os.path.join(V, "manifest.json")

ROOT_INFO = b"PM-DR-RATCHET-ROOT-v1"
CHAIN_INFO = b"PM-DR-RATCHET-CHAIN-v1"
MSG_AAD = b"PM-V1-MSG-AAD"
ZERO_NONCE = b"\x00" * 12
TEST_KEY_PREFIX = b"PM-TEST-ONLY-KEY:"

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def load_path(path: str):
    with open(path, "rb") as f:
        raw = f.read()
    return raw, json.loads(raw)


def load(name: str):
    return load_path(os.path.join(V, name))


def hx(data: bytes) -> str:
    return data.hex()


def raw(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string)


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    h = chmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    return hkdf(rk, dh_out, ROOT_INFO), hkdf(rk, dh_out, CHAIN_INFO)


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    return hmac_sha256(ck, b"\x02"), hmac_sha256(ck, b"\x01")


def dh(priv_hex: str, pub_hex: str) -> bytes:
    return X25519PrivateKey.from_private_bytes(raw(priv_hex)).exchange(
        X25519PublicKey.from_public_bytes(raw(pub_hex))
    )


def pubhex(priv_hex: str) -> str:
    pub = X25519PrivateKey.from_private_bytes(raw(priv_hex)).public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def test_key(name: str) -> bytes:
    return hashlib.sha256(TEST_KEY_PREFIX + name.encode("ascii")).digest()


def build_aad(message: dict, header_hex: str) -> bytes:
    e = message["envelope"]
    return (
        MSG_AAD
        + bytes([e["protocol_version"]])
        + raw(e["envelope_id"])
        + raw(e["sender_device_id"])
        + raw(e["recipient_device_id"])
        + struct.pack(">I", e["account_epoch"])
        + bytes([e["prekey_flag"]])
        + raw(header_hex)
    )


def check_header(message: dict) -> bytes:
    h = message["header"]
    expected = {
        1: raw(h["ratchet_public"]),
        2: h["previous_chain_length"],
        3: h["sequence_number"],
    }
    encoded = R.encode(
        R.Map(
            [
                (1, expected[1]),
                (2, expected[2]),
                (3, expected[3]),
            ]
        )
    )
    derived_hex = message["derived"]["ratchet_header_hex"]
    check(hx(encoded) == derived_hex, f"{message['id']}: header bytes")

    try:
        decoded = dict(R.decode_strict(raw(derived_hex)))
        check(set(decoded) == {1, 2, 3}, f"{message['id']}: header field set")
        check(decoded == expected, f"{message['id']}: decoded header values")
        check(R.encode(decoded and R.Map(list(decoded.items()))) == encoded, f"{message['id']}: header canonical roundtrip")
    except R.CborError as exc:
        check(False, f"{message['id']}: header rejected by reference codec: {exc}")
    return encoded


def encrypt_and_compare(message: dict, ck_sender: bytes) -> bytes:
    header_bytes = check_header(message)
    aad = build_aad(message, message["derived"]["ratchet_header_hex"])
    check(hx(aad) == message["derived"]["aad_hex"], f"{message['id']}: AAD bytes")

    ck_after, k_msg = kdf_ck(ck_sender)
    check(hx(k_msg) == message["derived"]["k_msg_hex"], f"{message['id']}: sender K_msg")
    check(
        hx(ck_after) == message["derived"]["ck_sender_after_hex"],
        f"{message['id']}: sender CK_next",
    )

    plaintext = raw(message["plaintext_hex"])
    ciphertext = ChaCha20Poly1305(k_msg).encrypt(ZERO_NONCE, plaintext, aad)
    check(
        hx(ciphertext) == message["derived"]["ciphertext_with_tag_hex"],
        f"{message['id']}: ciphertext",
    )
    check(
        len(raw(message["derived"]["ciphertext_with_tag_hex"])) == len(plaintext) + 16,
        f"{message['id']}: ciphertext/tag length",
    )
    return ck_after


def decrypt_with_key(message: dict, ck_receiver: bytes) -> tuple[bytes, bytes]:
    aad = build_aad(message, message["derived"]["ratchet_header_hex"])
    ck_after, k_msg = kdf_ck(ck_receiver)
    ciphertext = raw(message["derived"]["ciphertext_with_tag_hex"])
    try:
        plaintext = ChaCha20Poly1305(k_msg).decrypt(ZERO_NONCE, ciphertext, aad)
    except InvalidTag:
        check(False, f"{message['id']}: ciphertext failed independent decryption")
        return b"", ck_after
    check(
        hx(k_msg) == message["derived"]["receiver_transition"]["first_k_msg_hex"]
        if "receiver_transition" in message["derived"]
        else True,
        f"{message['id']}: receiver K_msg",
    )
    return plaintext, ck_after


def main() -> None:
    normal_raw, n = load("normal_ratchet_linear.json")
    double_raw, d = load("double_ratchet_linear.json")
    _, x = load("bi_x3dh_handshake.json")
    _, manifest = load("manifest.json")

    check(n["suite"] == "PM-DR-NORMAL-LINEAR", "suite identifier")
    check(n["status"] == "ACTIVE", "suite status")
    check(len(n["messages"]) == 3, "expected exactly three messages")
    check(n["protocol"]["nonce_hex"] == ZERO_NONCE.hex(), "zero nonce")
    check(n["protocol"]["prekey_flag"] == 0, "normal prekey flag")
    check(n["protocol"]["header_fields"] == {
        "1": "sender_ratchet_public_x25519_32",
        "2": "previous_chain_length_pn_uint32",
        "3": "sequence_number_n_uint32",
    }, "header schema")

    manifest_entry = next(
        (e for e in manifest["files"] if e["path"] == "normal_ratchet_linear.json"),
        None,
    )
    check(manifest_entry is not None, "normal vector manifest entry")
    if manifest_entry is not None:
        check(
            hashlib.sha256(normal_raw).hexdigest() == manifest_entry["sha256"],
            "normal vector manifest hash",
        )

    case = next(c for c in x["cases"] if c["id"] == d["handshake_case"])

    alice_device = raw(d["message_0"]["aad_inputs"]["sender_device_id"])
    bob_device = raw(d["message_0"]["aad_inputs"]["recipient_device_id"])

    alice_a0_priv = raw(d["alice"]["dhs_a0_priv"])
    alice_a0_pub = raw(d["alice"]["dhs_a0_pub"])
    alice_rk = raw(d["alice"]["rk_a"])
    alice_ck_s = raw(d["alice"]["ck_s_after_msg0"])

    bob_b1_priv = raw(d["bob"]["dhs_b1_priv"])
    bob_b1_pub = raw(d["bob"]["dhs_b1_pub"])
    bob_rk = raw(d["bob"]["rk_b_final"])
    bob_ck_s = raw(d["bob"]["ck_s_final"])
    bob_ck_r = raw(d["bob"]["ck_r_after"])

    check(
        pubhex(d["alice"]["dhs_a0_priv"]) == d["alice"]["dhs_a0_pub"],
        "Alice DHS_A0 public key",
    )
    check(
        pubhex(d["bob"]["dhs_b1_priv"]) == d["bob"]["dhs_b1_pub"],
        "Bob DHS_B1 public key",
    )

    alice_a1_priv = test_key("dhs_a1")
    alice_a1_pub = bytes.fromhex(
        n["messages"][0]["receiver_transition"]["new_local_dhs_pub_hex"]
    )
    bob_b2_priv = test_key("dhs_b2")
    bob_b2_pub = bytes.fromhex(
        n["messages"][2]["receiver_transition"]["new_local_dhs_pub_hex"]
    )

    check(hx(alice_a1_pub) == pubhex(hx(alice_a1_priv)), "Alice DHS_A1 public key")
    check(hx(bob_b2_pub) == pubhex(hx(bob_b2_priv)), "Bob DHS_B2 public key")

    initial_a = n["initial_states"]["alice_post_message_0"]
    check(initial_a["rk"] == d["alice"]["rk_a"], "Alice initial RK")
    check(initial_a["dhs_priv"] == d["alice"]["dhs_a0_priv"], "Alice initial DHS private")
    check(initial_a["dhs_pub"] == d["alice"]["dhs_a0_pub"], "Alice initial DHS public")
    check(initial_a["dhr_pub"] is None, "Alice initial DHR is empty")
    check(initial_a["ck_s"] == d["alice"]["ck_s_after_msg0"], "Alice initial CK_s")
    check(initial_a["ck_r"] is None, "Alice initial CK_r is empty")
    check((initial_a["ns"], initial_a["nr"], initial_a["pn"]) == (1, 0, 0), "Alice initial counters")

    initial_b = n["initial_states"]["bob_post_message_0"]
    check(initial_b["rk"] == d["bob"]["rk_b_final"], "Bob initial RK")
    check(initial_b["dhs_priv"] == d["bob"]["dhs_b1_priv"], "Bob initial DHS private")
    check(initial_b["dhs_pub"] == d["bob"]["dhs_b1_pub"], "Bob initial DHS public")
    check(initial_b["dhr_pub"] == d["message_0"]["prekey_handshake_header"]["fields"]["10_initial_ratchet_pub"],
          "Bob initial DHR")
    check(initial_b["ck_s"] == d["bob"]["ck_s_final"], "Bob initial CK_s")
    check(initial_b["ck_r"] == d["bob"]["ck_r_after"], "Bob initial CK_r")
    check((initial_b["ns"], initial_b["nr"], initial_b["pn"]) == (0, 1, 0), "Bob initial counters")

    messages = n["messages"]
    m0, m1, m2 = messages

    for m in messages:
        e = m["envelope"]
        check(e["protocol_version"] == 1, f"{m['id']}: protocol version")
        check(e["prekey_flag"] == 0, f"{m['id']}: normal prekey flag")
        check(len(raw(e["envelope_id"])) == 16, f"{m['id']}: envelope ID length")
        check(len(raw(e["sender_device_id"])) == 16, f"{m['id']}: sender device ID length")
        check(len(raw(e["recipient_device_id"])) == 16, f"{m['id']}: recipient device ID length")
        h = m["header"]
        check(0 <= h["previous_chain_length"] <= 0xFFFFFFFF, f"{m['id']}: Pn range")
        check(0 <= h["sequence_number"] <= 0xFFFFFFFF, f"{m['id']}: N range")
        check(len(raw(h["ratchet_public"])) == 32, f"{m['id']}: ratchet public length")
        check_header(m)

    # Message 1: Bob -> Alice, first message on Bob's current sending ratchet.
    check(m0["id"] == "bob_reply_new_ratchet", "message ordering 1")
    check(m0["ratchet_event"] == "new_receiving_ratchet", "message 1 ratchet event")
    check(m0["direction"] == "bob_to_alice", "message 1 direction")
    check(m0["header"]["ratchet_public"] == hx(bob_b1_pub), "message 1 ratchet pub")
    check(m0["header"]["previous_chain_length"] == 0, "message 1 Pn")
    check(m0["header"]["sequence_number"] == 0, "message 1 N")

    bob_ck_s_after = encrypt_and_compare(m0, bob_ck_s)

    # Alice receives that new ratchet.
    dh_recv = dh(d["alice"]["dhs_a0_priv"], d["bob"]["dhs_b1_pub"])
    rk_temp, ck_r = kdf_rk(alice_rk, dh_recv)
    dh_send = X25519PrivateKey.from_private_bytes(alice_a1_priv).exchange(
        X25519PublicKey.from_public_bytes(bob_b1_pub)
    )
    rk_final, alice_ck_s_after = kdf_rk(rk_temp, dh_send)
    ck_r_after, receiver_k_msg = kdf_ck(ck_r)

    transition = m0["receiver_transition"]
    check(hx(rk_temp) == transition["rk_temp_hex"], "message 1 RK temp")
    check(hx(ck_r) == transition["ck_r_before_decrypt_hex"], "message 1 CK_r before")
    check(hx(receiver_k_msg) == transition["first_k_msg_hex"], "message 1 first K_msg")
    check(hx(rk_final) == transition["rk_final_hex"], "message 1 RK final")
    check(hx(alice_ck_s_after) == transition["ck_s_final_hex"], "message 1 CK_s final")
    check(hx(ck_r_after) == transition["ck_r_after_hex"], "message 1 CK_r after")
    check(hx(alice_a1_pub) == transition["new_local_dhs_pub_hex"], "message 1 local ratchet pub")
    check(
        (transition["pn_after"], transition["ns_after"], transition["nr_after"])
        == (1, 0, 1),
        "message 1 receiver counters",
    )

    aad0 = build_aad(m0, m0["derived"]["ratchet_header_hex"])
    try:
        plaintext0 = ChaCha20Poly1305(receiver_k_msg).decrypt(
            ZERO_NONCE,
            raw(m0["derived"]["ciphertext_with_tag_hex"]),
            aad0,
        )
        check(plaintext0 == raw(m0["plaintext_hex"]), "message 1 plaintext")
    except InvalidTag:
        check(False, "message 1 receiver authentication")

    # Message 2: Bob -> Alice, same ratchet, N=1.
    check(m1["id"] == "bob_followup_same_ratchet", "message ordering 2")
    check(m1["ratchet_event"] == "same_ratchet", "message 2 ratchet event")
    check(m1["direction"] == "bob_to_alice", "message 2 direction")
    check(m1["header"]["ratchet_public"] == hx(bob_b1_pub), "message 2 ratchet pub")
    check(m1["header"]["previous_chain_length"] == 0, "message 2 Pn")
    check(m1["header"]["sequence_number"] == 1, "message 2 N")

    bob_ck_s_after_2 = kdf_ck(bob_ck_s_after)[0]
    bob_ck_s_after_2_again = encrypt_and_compare(m1, bob_ck_s_after)
    check(bob_ck_s_after_2_again == bob_ck_s_after_2, "message 2 sender chain")
    plaintext1, alice_ck_r_after_2 = decrypt_with_key(m1, ck_r_after)
    check(plaintext1 == raw(m1["plaintext_hex"]), "message 2 plaintext")
    check(m1["receiver_expected_nr"] == 1, "message 2 receiver expected Nr")
    check(m1["receiver_nr_after"] == 2, "message 2 receiver Nr after")
    check(hx(bob_ck_s_after_2) == m1["derived"]["ck_sender_after_hex"], "message 2 CK sender after")

    # Message 3: Alice -> Bob, new ratchet.
    check(m2["id"] == "alice_reply_new_ratchet", "message ordering 3")
    check(m2["ratchet_event"] == "new_receiving_ratchet", "message 3 ratchet event")
    check(m2["direction"] == "alice_to_bob", "message 3 direction")
    check(m2["header"]["ratchet_public"] == hx(alice_a1_pub), "message 3 ratchet pub")
    check(m2["header"]["previous_chain_length"] == 1, "message 3 Pn")
    check(m2["header"]["sequence_number"] == 0, "message 3 N")

    alice_ck_s_after_2 = encrypt_and_compare(m2, alice_ck_s_after)
    check(
        hx(alice_ck_s_after_2) == m2["derived"]["ck_sender_after_hex"],
        "message 3 sender CK after",
    )

    # Bob receives Alice's new ratchet.
    dh_recv_b = dh(d["bob"]["dhs_b1_priv"], hx(alice_a1_pub))
    rk_temp_b, ck_r_b = kdf_rk(bob_rk, dh_recv_b)
    dh_send_b = X25519PrivateKey.from_private_bytes(bob_b2_priv).exchange(
        X25519PublicKey.from_public_bytes(alice_a1_pub)
    )
    rk_final_b, bob_ck_s_final = kdf_rk(rk_temp_b, dh_send_b)
    ck_r_b_after, receiver_k_msg_b = kdf_ck(ck_r_b)

    transition_b = m2["receiver_transition"]
    check(hx(rk_temp_b) == transition_b["rk_temp_hex"], "message 3 RK temp")
    check(hx(ck_r_b) == transition_b["ck_r_before_decrypt_hex"], "message 3 CK_r before")
    check(hx(receiver_k_msg_b) == transition_b["first_k_msg_hex"], "message 3 first K_msg")
    check(hx(rk_final_b) == transition_b["rk_final_hex"], "message 3 RK final")
    check(hx(bob_ck_s_final) == transition_b["ck_s_final_hex"], "message 3 CK_s final")
    check(hx(ck_r_b_after) == transition_b["ck_r_after_hex"], "message 3 CK_r after")
    check(hx(bob_b2_pub) == transition_b["new_local_dhs_pub_hex"], "message 3 local ratchet pub")
    check(
        (transition_b["pn_after"], transition_b["ns_after"], transition_b["nr_after"])
        == (2, 0, 1),
        "message 3 receiver counters",
    )

    aad2 = build_aad(m2, m2["derived"]["ratchet_header_hex"])
    try:
        plaintext2 = ChaCha20Poly1305(receiver_k_msg_b).decrypt(
            ZERO_NONCE,
            raw(m2["derived"]["ciphertext_with_tag_hex"]),
            aad2,
        )
        check(plaintext2 == raw(m2["plaintext_hex"]), "message 3 plaintext")
    except InvalidTag:
        check(False, "message 3 receiver authentication")

    # Negative 1: ciphertext tampering must fail.
    neg1 = n["negative"][0]
    tampered = bytearray(raw(m0["derived"]["ciphertext_with_tag_hex"]))
    tampered[-1] ^= 1
    try:
        ChaCha20Poly1305(receiver_k_msg).decrypt(ZERO_NONCE, bytes(tampered), aad0)
        check(False, f"negative {neg1['id']}: tampered ciphertext authenticated")
    except InvalidTag:
        pass

    # Negative 2: changing N to 2 is rejected before KDF/AEAD state advancement.
    neg2 = n["negative"][1]
    bad_header = dict(m1["header"])
    bad_header["sequence_number"] = 2
    check(neg2["expected"] == "INVALID_INITIAL_STATE", "negative 2 expected error")
    check(2 != m1["receiver_expected_nr"], f"negative {neg2['id']}: skipped sequence was not detected")

    if failures:
        print("NORMAL VECTOR CHECK FAILED")
        for failure in failures:
            print(" -", failure)
        sys.exit(1)

    print("normal vector check OK: 3 messages, independent X25519/HKDF/HMAC/AEAD recomputation, 2 negative cases")


if __name__ == "__main__":
    main()
