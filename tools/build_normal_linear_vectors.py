#!/usr/bin/env python3
"""
Generate the shared PM-DR normal linear-message vector fixture.

This generator is intentionally independent of the Rust implementation. It uses
the Python cryptography package for X25519, HKDF-SHA256, HMAC-SHA256, and
ChaCha20-Poly1305, while taking the already-frozen Phase B handshake/Message 0
state from test-vectors/v1/double_ratchet_linear.json.

Run from the repository root:

    python tools/build_normal_linear_vectors.py

It creates/updates:
    test-vectors/v1/normal_ratchet_linear.json
and updates the SHA-256 entry for that file in:
    test-vectors/v1/manifest.json
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac as chmac, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROOT = b"PM-DR-RATCHET-ROOT-v1"
CHAIN = b"PM-DR-RATCHET-CHAIN-v1"
MSG_AAD = b"PM-V1-MSG-AAD"
ZERO_NONCE = b"\x00" * 12
TEST_KEY_PREFIX = b"PM-TEST-ONLY-KEY:"

V1 = Path("test-vectors/v1")
DOUBLE = V1 / "double_ratchet_linear.json"
OUT = V1 / "normal_ratchet_linear.json"
MANIFEST = V1 / "manifest.json"


def hx(value: bytes) -> str:
    return value.hex()


def raw(value: str) -> bytes:
    return bytes.fromhex(value)


def hkdf(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(ikm)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    mac = chmac.HMAC(key, hashes.SHA256())
    mac.update(message)
    return mac.finalize()


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    return (
        hkdf(rk, dh_out, ROOT),
        hkdf(rk, dh_out, CHAIN),
    )


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """
    Returns (CK_next, K_msg), matching the frozen Rust implementation.
    """
    return (
        hmac_sha256(ck, b"\x02"),
        hmac_sha256(ck, b"\x01"),
    )


def x25519_public(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_dh(priv: bytes, peer_public: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).exchange(
        X25519PublicKey.from_public_bytes(peer_public)
    )


def test_key(name: str) -> bytes:
    return hashlib.sha256(TEST_KEY_PREFIX + name.encode("ascii")).digest()


def cbor_normal_header(
    ratchet_public: bytes,
    previous_chain_length: int,
    sequence_number: int,
) -> bytes:
    if len(ratchet_public) != 32:
        raise ValueError("ratchet public key must be 32 bytes")
    if not 0 <= previous_chain_length <= 0xFFFFFFFF:
        raise ValueError("Pn out of range")
    if not 0 <= sequence_number <= 0xFFFFFFFF:
        raise ValueError("N out of range")

    # PM-CBOR-2026: map {1: bstr32, 2: uint, 3: uint}, canonical/minimal form.
    def uint(n: int) -> bytes:
        if n < 0:
            raise ValueError("negative uint")
        if n < 24:
            return bytes([n])
        if n <= 0xFF:
            return b"\x18" + bytes([n])
        if n <= 0xFFFF:
            return b"\x19" + n.to_bytes(2, "big")
        if n <= 0xFFFFFFFF:
            return b"\x1a" + n.to_bytes(4, "big")
        raise ValueError("uint too large")

    return (
        b"\xa3"
        + b"\x01\x58\x20"
        + ratchet_public
        + b"\x02"
        + uint(previous_chain_length)
        + b"\x03"
        + uint(sequence_number)
    )


def aad(
    envelope_id: bytes,
    sender_device_id: bytes,
    recipient_device_id: bytes,
    account_epoch: int,
    ratchet_header: bytes,
) -> bytes:
    if len(envelope_id) != 16:
        raise ValueError("envelope_id must be 16 bytes")
    if len(sender_device_id) != 16:
        raise ValueError("sender_device_id must be 16 bytes")
    if len(recipient_device_id) != 16:
        raise ValueError("recipient_device_id must be 16 bytes")
    if not 0 <= account_epoch <= 0xFFFFFFFF:
        raise ValueError("account epoch out of range")

    return (
        MSG_AAD
        + b"\x01"
        + envelope_id
        + sender_device_id
        + recipient_device_id
        + struct.pack(">I", account_epoch)
        + b"\x00"
        + ratchet_header
    )


def encrypt_message(
    ck_s: bytes,
    *,
    envelope_id: bytes,
    sender_device_id: bytes,
    recipient_device_id: bytes,
    account_epoch: int,
    ratchet_public: bytes,
    previous_chain_length: int,
    sequence_number: int,
    plaintext: bytes,
) -> dict[str, str | int]:
    header = cbor_normal_header(
        ratchet_public,
        previous_chain_length,
        sequence_number,
    )
    aad_bytes = aad(
        envelope_id,
        sender_device_id,
        recipient_device_id,
        account_epoch,
        header,
    )
    ck_next, k_msg = kdf_ck(ck_s)
    ciphertext = ChaCha20Poly1305(k_msg).encrypt(
        ZERO_NONCE,
        plaintext,
        aad_bytes,
    )
    return {
        "ratchet_header_hex": hx(header),
        "aad_hex": hx(aad_bytes),
        "plaintext_hex": hx(plaintext),
        "ciphertext_with_tag_hex": hx(ciphertext),
        "ck_next_hex": hx(ck_next),
        "k_msg_hex": hx(k_msg),
    }


def decrypt_message(
    ck_r: bytes,
    *,
    envelope_id: bytes,
    sender_device_id: bytes,
    recipient_device_id: bytes,
    account_epoch: int,
    ratchet_header: bytes,
    ciphertext: bytes,
) -> tuple[bytes, bytes]:
    aad_bytes = aad(
        envelope_id,
        sender_device_id,
        recipient_device_id,
        account_epoch,
        ratchet_header,
    )
    ck_next, k_msg = kdf_ck(ck_r)
    plaintext = ChaCha20Poly1305(k_msg).decrypt(
        ZERO_NONCE,
        ciphertext,
        aad_bytes,
    )
    return plaintext, ck_next


def new_ratchet_receive(
    *,
    rk: bytes,
    receiver_dhs_priv: bytes,
    peer_ratchet_public: bytes,
    new_local_dhs_priv: bytes,
) -> tuple[dict[str, str], bytes, bytes, bytes, bytes]:
    """
    Compute the receiver's new-ratchet state transition.

    Returns:
        state_fields, rk_final, ck_s, ck_r_after, local_dhs_pub
    """
    dh_recv = x25519_dh(receiver_dhs_priv, peer_ratchet_public)
    rk_temp, ck_r = kdf_rk(rk, dh_recv)

    local_dh_out = x25519_dh(new_local_dhs_priv, peer_ratchet_public)
    rk_final, ck_s = kdf_rk(rk_temp, local_dh_out)

    local_dhs_pub = x25519_public(new_local_dhs_priv)
    _, first_k_msg = kdf_ck(ck_r)
    ck_r_after, _ = kdf_ck(ck_r)

    return (
        {
            "rk_temp_hex": hx(rk_temp),
            "ck_r_before_decrypt_hex": hx(ck_r),
            "first_k_msg_hex": hx(first_k_msg),
        },
        rk_final,
        ck_s,
        ck_r_after,
        local_dhs_pub,
    )


def main() -> None:
    double = json.loads(DOUBLE.read_text(encoding="utf-8"))

    alice_device = raw(double["message_0"]["aad_inputs"]["sender_device_id"])
    bob_device = raw(double["message_0"]["aad_inputs"]["recipient_device_id"])

    alice_a0_priv = raw(double["alice"]["dhs_a0_priv"])
    alice_a0_pub = raw(double["alice"]["dhs_a0_pub"])
    alice_rk = raw(double["alice"]["rk_a"])
    alice_ck_s = raw(double["alice"]["ck_s_after_msg0"])

    bob_b1_priv = raw(double["bob"]["dhs_b1_priv"])
    bob_b1_pub = raw(double["bob"]["dhs_b1_pub"])
    bob_rk = raw(double["bob"]["rk_b_final"])
    bob_ck_s = raw(double["bob"]["ck_s_final"])
    bob_ck_r = raw(double["bob"]["ck_r_after"])

    alice_a1_priv = test_key("dhs_a1")
    alice_a1_pub = x25519_public(alice_a1_priv)
    bob_b2_priv = test_key("dhs_b2")
    bob_b2_pub = x25519_public(bob_b2_priv)

    assert hx(alice_a1_pub) == (
        "0afcb5bad545a4f6ead75dec66b80be392bf15dbe8ad1dcb5a794ce575c2bb41"
    )
    assert hx(bob_b2_pub) == (
        "1069ca7b17767a1deec72ffedad264d1ff7f29f185ec8a61bd47ed723be8fc01"
    )

    # 1. Bob sends the first normal message after Message 0.
    bob_reply_id = raw("202122232425262728292a2b2c2d2e2f")
    bob_reply = encrypt_message(
        bob_ck_s,
        envelope_id=bob_reply_id,
        sender_device_id=bob_device,
        recipient_device_id=alice_device,
        account_epoch=1,
        ratchet_public=bob_b1_pub,
        previous_chain_length=0,
        sequence_number=0,
        plaintext=b"bob reply",
    )
    bob_ck_s_1 = raw(str(bob_reply["ck_next_hex"]))

    assert bob_reply["ciphertext_with_tag_hex"] == (
        "7a699d0b8e1278e5a4fc5001397e0b0792f23eba0c1051b419"
    )

    # 2. Alice receives Bob's new ratchet message using a deterministic test key.
    alice_new_state, alice_rk_1, alice_ck_s_1, alice_ck_r_1, alice_a1_pub = (
        new_ratchet_receive(
            rk=alice_rk,
            receiver_dhs_priv=alice_a0_priv,
            peer_ratchet_public=bob_b1_pub,
            new_local_dhs_priv=alice_a1_priv,
        )
    )
    alice_rk_1_expected = "93d4971570674314017aac9fdf0ba19bb4e1670d6176643f0924fef28f728d78"
    assert hx(alice_rk_1) == alice_rk_1_expected

    # Verify the new-ratchet ciphertext against the independently-derived receive key.
    alice_reply_plaintext, alice_ck_r_after = decrypt_message(
        raw(alice_new_state["ck_r_before_decrypt_hex"]),
        envelope_id=bob_reply_id,
        sender_device_id=bob_device,
        recipient_device_id=alice_device,
        account_epoch=1,
        ratchet_header=raw(str(bob_reply["ratchet_header_hex"])),
        ciphertext=raw(str(bob_reply["ciphertext_with_tag_hex"])),
    )
    assert alice_reply_plaintext == b"bob reply"
    assert alice_ck_r_after == alice_ck_r_1

    # 3. Bob sends a same-ratchet follow-up.
    bob_follow_id = raw("606162636465666768696a6b6c6d6e6f")
    bob_follow = encrypt_message(
        bob_ck_s_1,
        envelope_id=bob_follow_id,
        sender_device_id=bob_device,
        recipient_device_id=alice_device,
        account_epoch=1,
        ratchet_public=bob_b1_pub,
        previous_chain_length=0,
        sequence_number=1,
        plaintext=b"bob followup",
    )
    assert bob_follow["ciphertext_with_tag_hex"] == (
        "eeb9a80e71e98f620fae61535d461b64d44954cccb1ddb5a8f04d343"
    )
    _, alice_ck_r_2 = decrypt_message(
        alice_ck_r_1,
        envelope_id=bob_follow_id,
        sender_device_id=bob_device,
        recipient_device_id=alice_device,
        account_epoch=1,
        ratchet_header=raw(str(bob_follow["ratchet_header_hex"])),
        ciphertext=raw(str(bob_follow["ciphertext_with_tag_hex"])),
    )

    # 4. Alice sends a new-ratchet reply.
    alice_reply_id = raw("404142434445464748494a4b4c4d4e4f")
    alice_reply = encrypt_message(
        alice_ck_s_1,
        envelope_id=alice_reply_id,
        sender_device_id=alice_device,
        recipient_device_id=bob_device,
        account_epoch=3,
        ratchet_public=alice_a1_pub,
        previous_chain_length=1,
        sequence_number=0,
        plaintext=b"alice reply",
    )
    assert alice_reply["ciphertext_with_tag_hex"] == (
        "80db5cb3a6d71a2fa0fa0a6e8cf7ec94764835b54e8f3452c292b4"
    )

    # 5. Bob receives Alice's new ratchet reply.
    bob_new_state, bob_rk_2, bob_ck_s_2, bob_ck_r_2, bob_b2_pub = new_ratchet_receive(
        rk=bob_rk,
        receiver_dhs_priv=bob_b1_priv,
        peer_ratchet_public=alice_a1_pub,
        new_local_dhs_priv=bob_b2_priv,
    )
    bob_reply_plaintext, bob_ck_r_2_after = decrypt_message(
        raw(bob_new_state["ck_r_before_decrypt_hex"]),
        envelope_id=alice_reply_id,
        sender_device_id=alice_device,
        recipient_device_id=bob_device,
        account_epoch=3,
        ratchet_header=raw(str(alice_reply["ratchet_header_hex"])),
        ciphertext=raw(str(alice_reply["ciphertext_with_tag_hex"])),
    )
    assert bob_reply_plaintext == b"alice reply"
    assert bob_ck_r_2_after == bob_ck_r_2

    assert hx(bob_rk_2) == (
        "f582547a40ca34a596e383c6c0304bff043a9981ec47aae41258d97d35e171c1"
    )

    result = {
        "suite": "PM-DR-NORMAL-LINEAR",
        "status": "ACTIVE",
        "origin": "python reference model",
        "test_only_keys_warning": (
            "ALL private keys in this file are TEST-ONLY and must never be used "
            "for real messaging keys."
        ),
        "protocol": {
            "header_fields": {
                "1": "sender_ratchet_public_x25519_32",
                "2": "previous_chain_length_pn_uint32",
                "3": "sequence_number_n_uint32",
            },
            "nonce_hex": "000000000000000000000000",
            "prekey_flag": 0,
            "aad_prefix_ascii": "PM-V1-MSG-AAD",
            "root_info_ascii": "PM-DR-RATCHET-ROOT-v1",
            "chain_info_ascii": "PM-DR-RATCHET-CHAIN-v1",
        },
        "initial_states": {
            "alice_post_message_0": {
                "rk": hx(alice_rk),
                "dhs_priv": hx(alice_a0_priv),
                "dhs_pub": hx(alice_a0_pub),
                "dhr_pub": None,
                "ck_s": hx(alice_ck_s),
                "ck_r": None,
                "ns": 1,
                "nr": 0,
                "pn": 0,
            },
            "bob_post_message_0": {
                "rk": hx(bob_rk),
                "dhs_priv": hx(bob_b1_priv),
                "dhs_pub": hx(bob_b1_pub),
                "dhr_pub": hx(alice_a0_pub),
                "ck_s": hx(bob_ck_s),
                "ck_r": hx(bob_ck_r),
                "ns": 0,
                "nr": 1,
                "pn": 0,
            },
        },
        "messages": [
            {
                "id": "bob_reply_new_ratchet",
                "direction": "bob_to_alice",
                "ratchet_event": "new_receiving_ratchet",
                "envelope": {
                    "protocol_version": 1,
                    "envelope_id": hx(bob_reply_id),
                    "sender_device_id": hx(bob_device),
                    "recipient_device_id": hx(alice_device),
                    "account_epoch": 1,
                    "prekey_flag": 0,
                },
                "header": {
                    "ratchet_public": hx(bob_b1_pub),
                    "previous_chain_length": 0,
                    "sequence_number": 0,
                },
                "derived": {
                    "ratchet_header_hex": bob_reply["ratchet_header_hex"],
                    "aad_hex": bob_reply["aad_hex"],
                    "k_msg_hex": bob_reply["k_msg_hex"],
                    "ck_sender_after_hex": bob_reply["ck_next_hex"],
                    "ciphertext_with_tag_hex": bob_reply["ciphertext_with_tag_hex"],
                },
                "plaintext_hex": bob_reply["plaintext_hex"],
                "receiver_transition": {
                    **alice_new_state,
                    "new_local_dhs_priv_hex": hx(alice_a1_priv),
                    "new_local_dhs_pub_hex": hx(alice_a1_pub),
                    "rk_final_hex": hx(alice_rk_1),
                    "ck_s_final_hex": hx(alice_ck_s_1),
                    "ck_r_after_hex": hx(alice_ck_r_1),
                    "pn_after": 1,
                    "ns_after": 0,
                    "nr_after": 1,
                },
            },
            {
                "id": "bob_followup_same_ratchet",
                "direction": "bob_to_alice",
                "ratchet_event": "same_ratchet",
                "envelope": {
                    "protocol_version": 1,
                    "envelope_id": hx(bob_follow_id),
                    "sender_device_id": hx(bob_device),
                    "recipient_device_id": hx(alice_device),
                    "account_epoch": 1,
                    "prekey_flag": 0,
                },
                "header": {
                    "ratchet_public": hx(bob_b1_pub),
                    "previous_chain_length": 0,
                    "sequence_number": 1,
                },
                "derived": {
                    "ratchet_header_hex": bob_follow["ratchet_header_hex"],
                    "aad_hex": bob_follow["aad_hex"],
                    "k_msg_hex": bob_follow["k_msg_hex"],
                    "ck_sender_before_hex": hx(bob_ck_s_1),
                    "ck_sender_after_hex": bob_follow["ck_next_hex"],
                    "ciphertext_with_tag_hex": bob_follow["ciphertext_with_tag_hex"],
                },
                "plaintext_hex": bob_follow["plaintext_hex"],
                "receiver_expected_nr": 1,
                "receiver_nr_after": 2,
            },
            {
                "id": "alice_reply_new_ratchet",
                "direction": "alice_to_bob",
                "ratchet_event": "new_receiving_ratchet",
                "envelope": {
                    "protocol_version": 1,
                    "envelope_id": hx(alice_reply_id),
                    "sender_device_id": hx(alice_device),
                    "recipient_device_id": hx(bob_device),
                    "account_epoch": 3,
                    "prekey_flag": 0,
                },
                "header": {
                    "ratchet_public": hx(alice_a1_pub),
                    "previous_chain_length": 1,
                    "sequence_number": 0,
                },
                "derived": {
                    "ratchet_header_hex": alice_reply["ratchet_header_hex"],
                    "aad_hex": alice_reply["aad_hex"],
                    "k_msg_hex": alice_reply["k_msg_hex"],
                    "ck_sender_after_hex": alice_reply["ck_next_hex"],
                    "ciphertext_with_tag_hex": alice_reply["ciphertext_with_tag_hex"],
                },
                "plaintext_hex": alice_reply["plaintext_hex"],
                "receiver_transition": {
                    **bob_new_state,
                    "new_local_dhs_priv_hex": hx(bob_b2_priv),
                    "new_local_dhs_pub_hex": hx(bob_b2_pub),
                    "rk_final_hex": hx(bob_rk_2),
                    "ck_s_final_hex": hx(bob_ck_s_2),
                    "ck_r_after_hex": hx(bob_ck_r_2),
                    "pn_after": 2,
                    "ns_after": 0,
                    "nr_after": 1,
                },
            },
        ],
        "negative": [
            {
                "id": "tampered_bob_reply_ciphertext",
                "message_id": "bob_reply_new_ratchet",
                "mutation": "flip_last_ciphertext_bit",
                "expected": "AEAD_AUTH_FAILURE",
                "expected_state_after": "UNCHANGED",
            },
            {
                "id": "tampered_bob_followup_sequence",
                "message_id": "bob_followup_same_ratchet",
                "mutation": "set_sequence_number_to_2",
                "expected": "INVALID_INITIAL_STATE",
                "expected_state_after": "UNCHANGED",
            },
        ],
        "invariants": [
            "Normal messages use prekey_flag=0.",
            "The normal-message nonce is fixed zero and each K_msg is single-use.",
            "Same-ratchet receive requires DHR equality and N == Nr.",
            "New-ratchet receive performs DH/KDF on temporaries and commits only after AEAD authentication.",
            "Pn is the sender's previous sending-chain length.",
            "AAD account_epoch is the recipient account epoch.",
        ],
    }

    raw_out = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    OUT.write_bytes(raw_out.encode("utf-8"))

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
    entries = [e for e in manifest["files"] if e["path"] != OUT.name]
    entries.append({"path": OUT.name, "status": "ACTIVE", "sha256": digest})
    entries.sort(key=lambda e: e["path"])
    manifest["files"] = entries
    MANIFEST.write_bytes(
        (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    )

    print(f"generated {OUT}")
    print(f"manifest hash {digest}")
    print(f"messages {len(result['messages'])}")
    print("reference assertions: OK")


if __name__ == "__main__":
    main()
