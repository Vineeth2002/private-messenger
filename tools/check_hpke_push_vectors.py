#!/usr/bin/env python3
# Independently validate the PM-PUSH-HPKE shared vector.
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

V = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test-vectors", "v1")
HPKE_V1 = b"HPKE-v1"
KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0003
failures = []

def raw(s: str) -> bytes:
    return bytes.fromhex(s)

def check(ok: bool, msg: str) -> None:
    if not ok:
        failures.append(msg)

def le(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, HPKE_V1 + suite_id + label + ikm, hashlib.sha256).digest()

def lx(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled = length.to_bytes(2, "big") + HPKE_V1 + suite_id + label + info
    out, t = b"", b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + labeled + bytes([i]), hashlib.sha256).digest()
        out += t
    return out[:length]

def main() -> None:
    path = os.path.join(V, "hpke_push_vectors.json")
    with open(path, "rb") as f:
        blob = f.read()
    v = json.loads(blob)
    c = v["cases"][0]

    sk_r = raw(c["recipient_private_hex"])
    sk_e = raw(c["ephemeral_private_hex"])
    info = raw(c["info_hex"])
    aad = raw(c["aad_hex"])
    plaintext = raw(c["plaintext_hex"])

    pk_r = X25519PrivateKey.from_private_bytes(sk_r).public_key().public_bytes_raw()
    enc = X25519PrivateKey.from_private_bytes(sk_e).public_key().public_bytes_raw()
    dh = X25519PrivateKey.from_private_bytes(sk_e).exchange(X25519PublicKey.from_public_bytes(pk_r))

    kem_suite = b"KEM" + KEM_ID.to_bytes(2, "big")
    hpke_suite = b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big") + AEAD_ID.to_bytes(2, "big")

    eae_prk = le(kem_suite, b"", b"eae_prk", dh)
    shared = lx(kem_suite, eae_prk, b"shared_secret", enc + pk_r, 32)
    psk_id_hash = le(hpke_suite, b"", b"psk_id_hash", b"")
    info_hash = le(hpke_suite, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = le(hpke_suite, shared, b"secret", b"")
    key = lx(hpke_suite, secret, b"key", context, 32)
    nonce = lx(hpke_suite, secret, b"base_nonce", context, 12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)

    check(pk_r.hex() == c["recipient_public_hex"], "recipient public key")
    check(enc.hex() == c["enc_hex"], "encapsulation")
    check(shared.hex() == c["shared_secret_hex"], "shared secret")
    check(key.hex() == c["key_hex"], "base key")
    check(nonce.hex() == c["base_nonce_hex"], "base nonce")
    check(ciphertext.hex() == c["ciphertext_hex"], "ciphertext")

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1
    try:
        ChaCha20Poly1305(key).decrypt(nonce, bytes(tampered), aad)
        check(False, "tampered ciphertext authenticated")
    except InvalidTag:
        pass

    check(v["negative"][0]["expected"] == "AEAD_OPEN_FAILED", "negative authentication expectation")
    check(v["negative"][1]["expected"] == "NON_CONTRIBUTORY_DH", "negative low-order expectation")

    with open(os.path.join(V, "manifest.json"), "r", encoding="utf-8") as f:
        m = json.load(f)
    entry = next(x for x in m["files"] if x["path"] == "hpke_push_vectors.json")
    check(hashlib.sha256(blob).hexdigest() == entry["sha256"], "manifest hash")

    if failures:
        print("HPKE PUSH VECTOR CHECK FAILED")
        for f in failures:
            print(" -", f)
        sys.exit(1)
    print("hpke push vector check OK: stateless Base setup, KEM/KDF schedule, AEAD, tamper negative, manifest hash")

if __name__ == "__main__":
    main()
