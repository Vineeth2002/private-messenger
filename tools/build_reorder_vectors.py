#!/usr/bin/env python3
"""Generate the deterministic PM-DR reorder/replay vector suite.

This is an independent Python reference model. It consumes the already-frozen
normal-ratchet fixture and extends it with a delayed old-chain message plus a
new-ratchet pair. The fixture is test-only and contains no production keys.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac as chmac, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT_INFO = b"PM-DR-RATCHET-ROOT-v1"
CHAIN_INFO = b"PM-DR-RATCHET-CHAIN-v1"
MSG_AAD = b"PM-V1-MSG-AAD"
ZERO_NONCE = b"\x00" * 12
TEST_KEY_PREFIX = b"PM-TEST-ONLY-KEY:"

V1 = Path(__file__).resolve().parent.parent / "test-vectors" / "v1"
NORMAL = V1 / "normal_ratchet_linear.json"
DOUBLE = V1 / "double_ratchet_linear.json"
OUT = V1 / "double_ratchet_reorder.json"
MANIFEST = V1 / "manifest.json"


def hx(value: bytes) -> str:
    return value.hex()


def raw(value: str) -> bytes:
    return bytes.fromhex(value)


def test_key(name: str) -> bytes:
    return hashlib.sha256(TEST_KEY_PREFIX + name.encode("ascii")).digest()


def hkdf(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    h = chmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    return hkdf(rk, dh_out, ROOT_INFO), hkdf(rk, dh_out, CHAIN_INFO)


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    return hmac_sha256(ck, b"\x02"), hmac_sha256(ck, b"\x01")


def x25519_public(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def x25519_dh(priv: bytes, peer_public: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(peer_public))


def uint(n: int) -> bytes:
    if n < 24:
        return bytes([n])
    if n <= 0xFF:
        return b"\x18" + bytes([n])
    if n <= 0xFFFF:
        return b"\x19" + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return b"\x1a" + n.to_bytes(4, "big")
    raise ValueError("uint too large")


def cbor_normal_header(ratchet_public: bytes, previous_chain_length: int, sequence_number: int) -> bytes:
    return b"\xa3\x01\x58\x20" + ratchet_public + b"\x02" + uint(previous_chain_length) + b"\x03" + uint(sequence_number)


def aad(envelope_id: bytes, sender_device_id: bytes, recipient_device_id: bytes, account_epoch: int, header: bytes) -> bytes:
    return (
        MSG_AAD + b"\x01" + envelope_id + sender_device_id + recipient_device_id
        + struct.pack(">I", account_epoch) + b"\x00" + header
    )


def encrypt(ck_s: bytes, *, envelope_id: bytes, sender_device_id: bytes, recipient_device_id: bytes,
            account_epoch: int, ratchet_public: bytes, previous_chain_length: int,
            sequence_number: int, plaintext: bytes) -> dict[str, str | int]:
    header = cbor_normal_header(ratchet_public, previous_chain_length, sequence_number)
    aad_bytes = aad(envelope_id, sender_device_id, recipient_device_id, account_epoch, header)
    ck_after, k_msg = kdf_ck(ck_s)
    ciphertext = ChaCha20Poly1305(k_msg).encrypt(ZERO_NONCE, plaintext, aad_bytes)
    return {
        "protocol_version": 1,
        "envelope_id": hx(envelope_id),
        "sender_device_id": hx(sender_device_id),
        "recipient_device_id": hx(recipient_device_id),
        "account_epoch": account_epoch,
        "prekey_flag": 0,
        "sequence_number": sequence_number,
        "previous_chain_length": previous_chain_length,
        "ratchet_public": hx(ratchet_public),
        "ratchet_header_hex": hx(header),
        "aad_hex": hx(aad_bytes),
        "k_msg_hex": hx(k_msg),
        "ck_sender_after_hex": hx(ck_after),
        "plaintext_hex": hx(plaintext),
        "ciphertext_with_tag_hex": hx(ciphertext),
    }


def state_snapshot(*, rk: bytes, dhs_priv: bytes, dhs_pub: bytes, dhr_pub: bytes | None,
                   ck_s: bytes | None, ck_r: bytes | None, ns: int, nr: int, pn: int,
                   skipped_keys: list[dict[str, int | str]] | None = None) -> dict:
    return {
        "rk": hx(rk),
        "dhs_priv": hx(dhs_priv),
        "dhs_pub": hx(dhs_pub),
        "dhr_pub": None if dhr_pub is None else hx(dhr_pub),
        "ck_s": None if ck_s is None else hx(ck_s),
        "ck_r": None if ck_r is None else hx(ck_r),
        "ns": ns,
        "nr": nr,
        "pn": pn,
        "skipped_keys": skipped_keys or [],
    }


def main() -> None:
    normal = json.loads(NORMAL.read_text(encoding="utf-8"))
    double = json.loads(DOUBLE.read_text(encoding="utf-8"))
    m0, m1, m2 = normal["messages"]

    alice_device = raw(m0["envelope"]["recipient_device_id"])
    bob_device = raw(m0["envelope"]["sender_device_id"])
    alice_a0_pub = raw(normal["initial_states"]["alice_post_message_0"]["dhs_pub"])
    bob_b1_pub = raw(normal["initial_states"]["bob_post_message_0"]["dhs_pub"])
    bob_b1_priv = raw(normal["initial_states"]["bob_post_message_0"]["dhs_priv"])
    bob_old_rk = raw(normal["initial_states"]["bob_post_message_0"]["rk"])
    bob_old_ck_s = raw(m1["derived"]["ck_sender_after_hex"])

    alice_rk = raw(m0["receiver_transition"]["rk_final_hex"])
    alice_a1_priv = raw(m0["receiver_transition"]["new_local_dhs_priv_hex"])
    alice_a1_pub = raw(m0["receiver_transition"]["new_local_dhs_pub_hex"])
    alice_ck_s = raw(m2["derived"]["ck_sender_after_hex"])
    alice_ck_r_after_m0 = raw(m0["receiver_transition"]["ck_r_after_hex"])
    alice_ck_r_after_m1 = kdf_ck(alice_ck_r_after_m0)[0]

    # Delayed old-chain message: this was sent as N=2 before Bob rotated to B2,
    # but it is delivered only after the B2 message arrives.
    old_message = encrypt(
        bob_old_ck_s,
        envelope_id=raw("909192939495969798999a9b9c9d9e9f"),
        sender_device_id=bob_device,
        recipient_device_id=alice_device,
        account_epoch=1,
        ratchet_public=bob_b1_pub,
        previous_chain_length=0,
        sequence_number=2,
        plaintext=b"old delayed",
    )

    # Bob's post-ratchet state is the deterministic receiver transition from the
    # frozen normal vector. The only deliberate difference is Pn=3: the delayed
    # old-chain N=2 message was emitted immediately before the rotation.
    bob_b2_priv = raw(m2["receiver_transition"]["new_local_dhs_priv_hex"])
    bob_b2_pub = raw(m2["receiver_transition"]["new_local_dhs_pub_hex"])
    bob_new_rk = raw(m2["receiver_transition"]["rk_final_hex"])
    bob_new_ck_s = raw(m2["receiver_transition"]["ck_s_final_hex"])
    bob_new_ck_r = raw(m2["receiver_transition"]["ck_r_after_hex"])

    new0 = encrypt(
        bob_new_ck_s,
        envelope_id=raw("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
        sender_device_id=bob_device,
        recipient_device_id=alice_device,
        account_epoch=1,
        ratchet_public=bob_b2_pub,
        previous_chain_length=3,
        sequence_number=0,
        plaintext=b"new ratchet 0",
    )
    new1 = encrypt(
        raw(new0["ck_sender_after_hex"]),
        envelope_id=raw("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
        sender_device_id=bob_device,
        recipient_device_id=alice_device,
        account_epoch=1,
        ratchet_public=bob_b2_pub,
        previous_chain_length=3,
        sequence_number=1,
        plaintext=b"new ratchet 1",
    )

    alice_a2_priv = test_key("dhs_a2")
    alice_a2_pub = x25519_public(alice_a2_priv)

    dh_recv = x25519_dh(alice_a1_priv, bob_b2_pub)
    rk_temp, ck_r_initial = kdf_rk(alice_rk, dh_recv)
    dh_send = x25519_dh(alice_a2_priv, bob_b2_pub)
    rk_final, ck_s_final = kdf_rk(rk_temp, dh_send)
    ck_r_after0, k_new0 = kdf_ck(ck_r_initial)
    ck_r_after1, k_new1 = kdf_ck(ck_r_after0)
    ck_r_after_old2, k_old2 = kdf_ck(alice_ck_r_after_m1)

    # Baseline consistency assertions: this fixture must extend the frozen normal vector,
    # not invent a second copy of its ratchet transition.
    assert hx(alice_a1_pub) == m0["receiver_transition"]["new_local_dhs_pub_hex"]
    assert hx(bob_b2_pub) == m2["receiver_transition"]["new_local_dhs_pub_hex"]
    assert hx(bob_new_rk) == m2["receiver_transition"]["rk_final_hex"]
    assert hx(bob_new_ck_s) == m2["receiver_transition"]["ck_s_final_hex"]
    # The receiver's first DH/KDF stage must reproduce the sender's current RK/CK_r;
    # the second DH/KDF stage intentionally creates the receiver's new sending chain.
    assert hx(rk_temp) == hx(bob_new_rk)
    assert hx(ck_r_initial) == hx(bob_new_ck_s)
    assert hx(k_old2) == old_message["k_msg_hex"]
    assert hx(k_new0) == new0["k_msg_hex"]
    assert hx(k_new1) == new1["k_msg_hex"]

    initial_receiver = state_snapshot(
        rk=alice_rk,
        dhs_priv=alice_a1_priv,
        dhs_pub=alice_a1_pub,
        dhr_pub=bob_b1_pub,
        ck_s=alice_ck_s,
        ck_r=alice_ck_r_after_m1,
        ns=1,
        nr=2,
        pn=1,
    )
    old_sender = state_snapshot(
        rk=bob_old_rk,
        dhs_priv=bob_b1_priv,
        dhs_pub=bob_b1_pub,
        dhr_pub=alice_a0_pub,
        ck_s=bob_old_ck_s,
        ck_r=raw(normal["initial_states"]["bob_post_message_0"]["ck_r"]),
        ns=2,
        nr=1,
        pn=0,
    )
    new_sender = state_snapshot(
        rk=bob_new_rk,
        dhs_priv=bob_b2_priv,
        dhs_pub=bob_b2_pub,
        dhr_pub=alice_a1_pub,
        ck_s=bob_new_ck_s,
        ck_r=bob_new_ck_r,
        ns=0,
        nr=1,
        pn=3,
    )

    after_new1 = state_snapshot(
        rk=rk_final,
        dhs_priv=alice_a2_priv,
        dhs_pub=alice_a2_pub,
        dhr_pub=bob_b2_pub,
        ck_s=ck_s_final,
        ck_r=ck_r_after1,
        ns=0,
        nr=2,
        pn=1,
        skipped_keys=[
            {"ratchet_public": hx(bob_b1_pub), "sequence_number": 2},
            {"ratchet_public": hx(bob_b2_pub), "sequence_number": 0},
        ],
    )
    after_old = dict(after_new1)
    after_old["skipped_keys"] = [{"ratchet_public": hx(bob_b2_pub), "sequence_number": 0}]
    after_new0 = dict(after_new1)
    after_new0["skipped_keys"] = []

    result = {
        "suite": "PM-DR-REORDER",
        "status": "ACTIVE",
        "origin": "python reference model extending normal_ratchet_linear.json",
        "test_only_keys_warning": "ALL private keys in this file are TEST-ONLY and must never be used for real messaging keys.",
        "protocol": {
            "header_fields": {
                "1": "sender_ratchet_public_x25519_32",
                "2": "previous_chain_length_pn_uint32",
                "3": "sequence_number_n_uint32",
            },
            "prekey_flag": 0,
            "nonce_hex": ZERO_NONCE.hex(),
            "aad_prefix_ascii": "PM-V1-MSG-AAD",
            "root_info_ascii": ROOT_INFO.decode(),
            "chain_info_ascii": CHAIN_INFO.decode(),
        },
        "scenario": {
            "id": "delayed_old_chain_survives_new_ratchet",
            "description": "Deliver a new-ratchet message out of order while a delayed old-chain message remains pending; consumed skipped keys reject replay.",
            "initial_receiver": initial_receiver,
            "old_sender": old_sender,
            "new_sender": new_sender,
            "new_ratchet_receiver_dhs_priv_hex": hx(alice_a2_priv),
            "new_ratchet_receiver_dhs_pub_hex": hx(alice_a2_pub),
            "messages": [
                {"id": "old_delayed", **old_message},
                {"id": "new_ratchet_0", **new0},
                {"id": "new_ratchet_1", **new1},
            ],
            "delivery_order": ["new_ratchet_1", "old_delayed", "new_ratchet_0"],
            "expected_after_new_ratchet_1": after_new1,
            "expected_after_old_delayed": after_old,
            "expected_after_new_ratchet_0": after_new0,
        },
        "negative": [
            {
                "id": "tampered_new_ratchet_1_is_atomic",
                "message_id": "new_ratchet_1",
                "mutation": "flip_last_ciphertext_bit",
                "expected": "AEAD_AUTH_FAILURE",
                "expected_state_after": "UNCHANGED",
            },
            {
                "id": "replay_new_ratchet_1_after_consumption",
                "message_id": "new_ratchet_1",
                "mutation": "deliver_same_envelope_again_after_success",
                "expected": "REPLAY_DETECTED",
                "expected_state_after": "UNCHANGED",
            },
        ],
        "invariants": [
            "A new-ratchet receive may carry a non-zero previous-chain gap and a non-zero new-chain gap simultaneously.",
            "The receiver retains skipped keys from the old chain and the new chain until each is consumed.",
            "A successfully consumed skipped key is removed and cannot decrypt the same envelope again.",
            "Authentication failure during a new-ratchet receive commits neither ratchet state nor skipped keys.",
            "The new-ratchet header carries Pn=3, proving an old-chain N=2 message can arrive after the ratchet transition; the receiver state keeps its own pn=1.",
        ],
    }

    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
    entries = [e for e in manifest["files"] if e["path"] != OUT.name]
    entries.append({"path": OUT.name, "status": "ACTIVE", "sha256": digest})
    entries.sort(key=lambda e: e["path"])
    manifest["files"] = entries
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"reorder vectors generated: {OUT.name}; sha256={digest}")


if __name__ == "__main__":
    main()
