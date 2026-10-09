#!/usr/bin/env python3
"""Independent validation of PM-DR-REORDER vectors."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac as chmac, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = Path(__file__).resolve().parent
V = HERE.parent / "test-vectors" / "v1"
NORMAL = V / "normal_ratchet_linear.json"
REORDER = V / "double_ratchet_reorder.json"
MANIFEST = V / "manifest.json"
ROOT_INFO = b"PM-DR-RATCHET-ROOT-v1"
CHAIN_INFO = b"PM-DR-RATCHET-CHAIN-v1"
MSG_AAD = b"PM-V1-MSG-AAD"
ZERO_NONCE = b"\x00" * 12
TEST_KEY_PREFIX = b"PM-TEST-ONLY-KEY:"
FAILURES: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILURES.append(msg)


def raw(v: str) -> bytes:
    return bytes.fromhex(v)


def hx(v: bytes) -> str:
    return v.hex()


def test_key(name: str) -> bytes:
    return hashlib.sha256(TEST_KEY_PREFIX + name.encode("ascii")).digest()


def hkdf(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    h = chmac.HMAC(key, hashes.SHA256()); h.update(message); return h.finalize()


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    return hkdf(rk, dh_out, ROOT_INFO), hkdf(rk, dh_out, CHAIN_INFO)


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    return hmac_sha256(ck, b"\x02"), hmac_sha256(ck, b"\x01")


def xpub(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def xdh(priv: bytes, pub: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))


def uint(n: int) -> bytes:
    if n < 24: return bytes([n])
    if n <= 0xFF: return b"\x18" + bytes([n])
    if n <= 0xFFFF: return b"\x19" + n.to_bytes(2, "big")
    return b"\x1a" + n.to_bytes(4, "big")


def header(pub: bytes, pn: int, n: int) -> bytes:
    return b"\xa3\x01\x58\x20" + pub + b"\x02" + uint(pn) + b"\x03" + uint(n)


def aad(msg: dict, header_bytes: bytes) -> bytes:
    e = msg
    return MSG_AAD + b"\x01" + raw(e["envelope_id"]) + raw(e["sender_device_id"]) + raw(e["recipient_device_id"]) + struct.pack(">I", e["account_epoch"]) + b"\x00" + header_bytes


def encrypt_check(msg: dict, ck: bytes) -> bytes:
    h = header(raw(msg["ratchet_public"]), msg["previous_chain_length"], msg["sequence_number"])
    check(h.hex() == msg["ratchet_header_hex"], f"{msg['id']}: header")
    a = aad(msg, h)
    check(a.hex() == msg["aad_hex"], f"{msg['id']}: AAD")
    ck_after, k_msg = kdf_ck(ck)
    check(k_msg.hex() == msg["k_msg_hex"], f"{msg['id']}: K_msg")
    check(ck_after.hex() == msg["ck_sender_after_hex"], f"{msg['id']}: CK_next")
    ct = ChaCha20Poly1305(k_msg).encrypt(ZERO_NONCE, raw(msg["plaintext_hex"]), a)
    check(ct.hex() == msg["ciphertext_with_tag_hex"], f"{msg['id']}: ciphertext")
    return ck_after


def main() -> None:
    normal = json.loads(NORMAL.read_text(encoding="utf-8"))
    reorder_raw = REORDER.read_bytes()
    reorder = json.loads(reorder_raw)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entry = next((e for e in manifest["files"] if e["path"] == REORDER.name), None)
    check(entry is not None and entry["status"] == "ACTIVE", "active manifest entry")
    if entry:
        check(hashlib.sha256(reorder_raw).hexdigest() == entry["sha256"], "manifest hash")
    check(reorder["suite"] == "PM-DR-REORDER", "suite")
    check(reorder["status"] == "ACTIVE", "status")

    s = reorder["scenario"]
    initial = s["initial_receiver"]
    old = s["old_sender"]
    new = s["new_sender"]
    messages = {m["id"]: m for m in s["messages"]}

    # Frozen normal-ratchet relationship.
    m0, m1, m2 = normal["messages"]
    check(initial["rk"] == m0["receiver_transition"]["rk_final_hex"], "initial receiver RK")
    check(initial["dhs_priv"] == m0["receiver_transition"]["new_local_dhs_priv_hex"], "initial receiver DHS")
    check(initial["ck_s"] == m2["derived"]["ck_sender_after_hex"], "initial receiver CK_s")
    check(new["rk"] == m2["receiver_transition"]["rk_final_hex"], "new sender RK")
    check(new["dhs_priv"] == m2["receiver_transition"]["new_local_dhs_priv_hex"], "new sender DHS")
    check(new["ck_s"] == m2["receiver_transition"]["ck_s_final_hex"], "new sender CK_s")

    # Sender-side ciphertext/reference checks.
    encrypt_check(messages["old_delayed"], raw(old["ck_s"]))
    ck_new0 = encrypt_check(messages["new_ratchet_0"], raw(new["ck_s"]))
    encrypt_check(messages["new_ratchet_1"], ck_new0)
    check(messages["old_delayed"]["previous_chain_length"] == 0, "old Pn")
    check(messages["old_delayed"]["sequence_number"] == 2, "old N")
    check(messages["new_ratchet_0"]["previous_chain_length"] == 3, "new Pn")
    check(messages["new_ratchet_1"]["sequence_number"] == 1, "new N")

    alice_rk = raw(initial["rk"])
    alice_dhs = raw(initial["dhs_priv"])
    bob_new_pub = raw(new["dhs_pub"])
    alice_new_priv = raw(s["new_ratchet_receiver_dhs_priv_hex"])
    alice_new_pub = raw(s["new_ratchet_receiver_dhs_pub_hex"])
    rk_temp, ck_r_initial = kdf_rk(alice_rk, xdh(alice_dhs, bob_new_pub))
    rk_final, ck_s_final = kdf_rk(rk_temp, xdh(alice_new_priv, bob_new_pub))
    ck_r_after0, k_new0 = kdf_ck(ck_r_initial)
    ck_r_after1, k_new1 = kdf_ck(ck_r_after0)
    _, k_old = kdf_ck(raw(initial["ck_r"]))

    check(rk_final.hex() == s["expected_after_new_ratchet_1"]["rk"], "receiver RK after new ratchet")
    check(alice_new_pub.hex() == s["expected_after_new_ratchet_1"]["dhs_pub"], "receiver new DHS public")
    check(ck_s_final.hex() == s["expected_after_new_ratchet_1"]["ck_s"], "receiver CK_s after new ratchet")
    check(ck_r_after1.hex() == s["expected_after_new_ratchet_1"]["ck_r"], "receiver CK_r after new ratchet")
    check(k_new1.hex() == messages["new_ratchet_1"]["k_msg_hex"], "new-ratchet target key")
    check(k_new0.hex() == messages["new_ratchet_0"]["k_msg_hex"], "new-ratchet skipped key")
    check(k_old.hex() == messages["old_delayed"]["k_msg_hex"], "old-chain skipped key")

    try:
        pt = ChaCha20Poly1305(k_new1).decrypt(ZERO_NONCE, raw(messages["new_ratchet_1"]["ciphertext_with_tag_hex"]), raw(messages["new_ratchet_1"]["aad_hex"]))
        check(pt == raw(messages["new_ratchet_1"]["plaintext_hex"]), "new-ratchet plaintext")
    except InvalidTag:
        check(False, "new-ratchet target did not authenticate")

    try:
        bad = bytearray(raw(messages["new_ratchet_1"]["ciphertext_with_tag_hex"])); bad[-1] ^= 1
        ChaCha20Poly1305(k_new1).decrypt(ZERO_NONCE, bytes(bad), raw(messages["new_ratchet_1"]["aad_hex"]))
        check(False, "tampered new-ratchet ciphertext authenticated")
    except InvalidTag:
        pass

    try:
        ChaCha20Poly1305(k_old).decrypt(ZERO_NONCE, raw(messages["old_delayed"]["ciphertext_with_tag_hex"]), raw(messages["old_delayed"]["aad_hex"]))
        ChaCha20Poly1305(k_new0).decrypt(ZERO_NONCE, raw(messages["new_ratchet_0"]["ciphertext_with_tag_hex"]), raw(messages["new_ratchet_0"]["aad_hex"]))
    except InvalidTag:
        check(False, "skipped-key delivery failed")

    check(any(k["sequence_number"] == 2 and k["ratchet_public"] == old["dhs_pub"] for k in s["expected_after_new_ratchet_1"]["skipped_keys"]), "old skipped key retained")
    check(any(k["sequence_number"] == 0 and k["ratchet_public"] == new["dhs_pub"] for k in s["expected_after_new_ratchet_1"]["skipped_keys"]), "new skipped key retained")
    check(s["delivery_order"] == ["new_ratchet_1", "old_delayed", "new_ratchet_0"], "delivery order")
    check(s["expected_after_new_ratchet_1"]["pn"] == 1, "post-transition receiver Pn")
    check(s["expected_after_new_ratchet_1"]["nr"] == 2, "post-transition Nr")
    check(s["expected_after_new_ratchet_0"]["skipped_keys"] == [], "skipped keys fully consumed")
    check(reorder["negative"][0]["expected"] == "AEAD_AUTH_FAILURE", "negative auth expectation")
    check(reorder["negative"][1]["expected"] == "REPLAY_DETECTED", "negative replay expectation")

    if FAILURES:
        print("REORDER VECTOR CHECK FAILED")
        for f in FAILURES:
            print(" -", f)
        raise SystemExit(1)
    print("reorder vector check OK: delayed old-chain delivery, new-ratchet out-of-order delivery, atomic auth failure, replay semantics")


if __name__ == "__main__":
    main()
