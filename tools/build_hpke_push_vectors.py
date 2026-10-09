#!/usr/bin/env python3
# Generate the shared PM-PUSH-HPKE deterministic Base-mode vector.
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

V = Path("test-vectors/v1")
OUT = V / "hpke_push_vectors.json"
MANIFEST = V / "manifest.json"

KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0003
HPKE_V1 = b"HPKE-v1"

def hx(b: bytes) -> str:
    return b.hex()

def labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, HPKE_V1 + suite_id + label + ikm, hashlib.sha256).digest()

def labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = length.to_bytes(2, "big") + HPKE_V1 + suite_id + label + info
    out = b""
    t = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + labeled_info + bytes([i]), hashlib.sha256).digest()
        out += t
    return out[:length]

def public_from_private(sk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

def build_case() -> dict[str, str]:
    sk_r = bytes.fromhex("0202030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    sk_e = bytes.fromhex("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
    info = b"pm-test-push-info"
    aad = b"pm-test-push-aad"
    plaintext = b"opaque-wakeup-test"

    pk_r = public_from_private(sk_r)
    enc = public_from_private(sk_e)
    dh = X25519PrivateKey.from_private_bytes(sk_e).exchange(X25519PublicKey.from_public_bytes(pk_r))

    kem_suite = b"KEM" + KEM_ID.to_bytes(2, "big")
    hpke_suite = (
        b"HPKE"
        + KEM_ID.to_bytes(2, "big")
        + KDF_ID.to_bytes(2, "big")
        + AEAD_ID.to_bytes(2, "big")
    )

    eae_prk = labeled_extract(kem_suite, b"", b"eae_prk", dh)
    shared_secret = labeled_expand(kem_suite, eae_prk, b"shared_secret", enc + pk_r, 32)

    psk_id_hash = labeled_extract(hpke_suite, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(hpke_suite, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = labeled_extract(hpke_suite, shared_secret, b"secret", b"")
    key = labeled_expand(hpke_suite, secret, b"key", context, 32)
    base_nonce = labeled_expand(hpke_suite, secret, b"base_nonce", context, 12)
    ciphertext = ChaCha20Poly1305(key).encrypt(base_nonce, plaintext, aad)

    return {
        "id": "stateless_push",
        "recipient_private_hex": hx(sk_r),
        "recipient_public_hex": hx(pk_r),
        "ephemeral_private_hex": hx(sk_e),
        "enc_hex": hx(enc),
        "info_hex": hx(info),
        "aad_hex": hx(aad),
        "plaintext_hex": hx(plaintext),
        "shared_secret_hex": hx(shared_secret),
        "key_hex": hx(key),
        "base_nonce_hex": hx(base_nonce),
        "ciphertext_hex": hx(ciphertext),
    }

def main() -> None:
    result = {
        "suite": "PM-PUSH-HPKE",
        "status": "ACTIVE",
        "mode": "base-stateless",
        "warning": "Private keys and opaque plaintext in this file are TEST-ONLY fixtures.",
        "scope_note": (
            "This boundary freezes the stateless HPKE Base cryptographic flow for push wake-up hints. "
            "The notification payload schema/field numbering is not introduced here because 09-notification-hpke.md "
            "does not freeze its exact PM-CBOR field map."
        ),
        "suite_ids": {
            "kem_id": "0x0020",
            "kdf_id": "0x0001",
            "aead_id": "0x0003",
        },
        "cases": [build_case()],
        "negative": [
            {
                "id": "tampered_ciphertext",
                "expected": "AEAD_OPEN_FAILED",
                "expected_state_after": "NO_PERSISTED_HPKE_STATE",
            },
            {
                "id": "low_order_enc",
                "expected": "NON_CONTRIBUTORY_DH",
                "expected_state_after": "NO_PERSISTED_HPKE_STATE",
            },
        ],
        "invariants": [
            "Each push notification uses fresh Base-mode encapsulation.",
            "The one-shot sender and receiver contexts are discarded after one notification.",
            "Push confidentiality does not authenticate the sender.",
            "Application content must be authenticated by the normal messenger connection before presentation.",
        ],
    }
    raw = (json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    OUT.write_bytes(raw)

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    digest = hashlib.sha256(raw).hexdigest()
    entries = [e for e in manifest["files"] if e["path"] != OUT.name]
    entries.append({"path": OUT.name, "status": "ACTIVE", "sha256": digest})
    entries.sort(key=lambda e: e["path"])
    manifest["files"] = entries
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"hpke push vectors generated: {OUT}; sha256={digest}")

if __name__ == "__main__":
    main()
