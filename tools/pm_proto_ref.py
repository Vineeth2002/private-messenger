"""Pure-Python REFERENCE MODEL of the locked cryptographic contracts (architecture-review lock).

TEST TOOLING ONLY. Not production code, not a security validation. It exists to derive the
shared vectors that the Rust/Go/Kotlin/Swift implementations must reproduce. HKDF here is
hand-written over hmac; tools/check_vectors.py recomputes with the `cryptography` library's
HKDF so two independent HKDF implementations must agree.
"""
import hashlib, hmac, struct
import pmcbor_ref as _R
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

# ---- protocol constants (explicit byte strings; lengths stated in the memo are asserted)
LABELS = {
    "X3DH_SALT": (b"PM-BI-X3DH-1-HKDF-SALT-v1", 25),
    "X3DH_INFO": (b"PM-BI-X3DH-1-SESSION-KEY-v1", 27),
    "DR_ROOT_INFO": (b"PM-DR-RATCHET-ROOT-v1", 21),
    "DR_CHAIN_INFO": (b"PM-DR-RATCHET-CHAIN-v1", 22),
    "MEDIA_NONCE_SALT": (b"PM-V1-MEDIA-NONCE-SALT-v1", 25),
    "MEDIA_NONCE_INFO": (b"PM-V1-MEDIA-NONCE-EXPAND-v1", 27),
    "DH_BIND": (b"PM-V1-DH-BIND", 13),
    "MSG_AAD": (b"PM-V1-MSG-AAD", 13),
}
for _k, (_v, _n) in LABELS.items():
    assert len(_v) == _n, (_k, len(_v), _n)
L = {k: v for k, (v, _) in LABELS.items()}

ZERO_NONCE = b"\x00" * 12
BUCKETS = [64 * 1024, 256 * 1024, 1 << 20, 5 << 20, 20 << 20, 100 << 20]
CHUNK = 65536


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def test_priv(name):
    """TEST-ONLY deterministic private key material. Never use outside vectors."""
    return hashlib.sha256(b"PM-TEST-ONLY-KEY:" + name.encode()).digest()


def pub_of(priv):
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(*RAW)


def x25519(priv, pub):
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))


def be32(n): return struct.pack(">I", n)
def be64(n): return struct.pack(">Q", n)


# ---- PM-BI-X3DH-1 (output: the single 32-byte SK)
def x3dh_context(ik_a_pub, ik_b_pub, epoch_a, epoch_b):
    c = ik_a_pub + ik_b_pub + be32(epoch_a) + be32(epoch_b)
    assert len(c) == 72
    return c


def x3dh_sk(dhs, ik_a_pub, ik_b_pub, epoch_a, epoch_b):
    ikm = b"".join(dhs)
    assert len(ikm) in (96, 128)
    prk = hkdf_extract(L["X3DH_SALT"], ikm)
    ctx = x3dh_context(ik_a_pub, ik_b_pub, epoch_a, epoch_b)
    sk = hkdf_expand(prk, L["X3DH_INFO"] + ctx, 32)
    return {"ikm": ikm, "prk": prk, "context": ctx, "sk": sk}


def x3dh_initiator(ik_a_priv, ek_a_priv, ik_b_pub, spk_b_pub, opk_b_pub, ea, eb):
    dhs = [x25519(ik_a_priv, spk_b_pub), x25519(ek_a_priv, ik_b_pub), x25519(ek_a_priv, spk_b_pub)]
    if opk_b_pub is not None:
        dhs.append(x25519(ek_a_priv, opk_b_pub))
    return dhs, x3dh_sk(dhs, pub_of(ik_a_priv), ik_b_pub, ea, eb)


def x3dh_responder(ik_b_priv, spk_b_priv, opk_b_priv, ik_a_pub, ek_a_pub, ea, eb):
    dhs = [x25519(spk_b_priv, ik_a_pub), x25519(ik_b_priv, ek_a_pub), x25519(spk_b_priv, ek_a_pub)]
    if opk_b_priv is not None:
        dhs.append(x25519(opk_b_priv, ek_a_pub))
    return dhs, x3dh_sk(dhs, ik_a_pub, pub_of(ik_b_priv), ea, eb)


# ---- Double Ratchet KDFs
def kdf_rk(rk, dh_out):
    prk = hkdf_extract(rk, dh_out)
    return hkdf_expand(prk, L["DR_ROOT_INFO"], 32), hkdf_expand(prk, L["DR_CHAIN_INFO"], 32)


def kdf_ck(ck):
    """Returns (CK_next, K_msg): K_msg = HMAC(CK, 0x01), CK_next = HMAC(CK, 0x02)."""
    k_msg = hmac.new(ck, b"\x01", hashlib.sha256).digest()
    ck_next = hmac.new(ck, b"\x02", hashlib.sha256).digest()
    return ck_next, k_msg


def aad_msg(version, envelope_id, sender_dev, recipient_dev, account_epoch, prekey_flag, header):
    assert len(envelope_id) == len(sender_dev) == len(recipient_dev) == 16
    return (L["MSG_AAD"] + bytes([version]) + envelope_id + sender_dev + recipient_dev
            + be32(account_epoch) + bytes([prekey_flag]) + header)


def aead_encrypt(k, pt, aad):
    return ChaCha20Poly1305(k).encrypt(ZERO_NONCE, pt, aad)


def aead_decrypt(k, ct, aad):
    return ChaCha20Poly1305(k).decrypt(ZERO_NONCE, ct, aad)   # raises InvalidTag


# ---- media
def media_nonce_salt(k_media):
    prk = hkdf_extract(L["MEDIA_NONCE_SALT"], k_media)
    return prk, hkdf_expand(prk, L["MEDIA_NONCE_INFO"], 4)


def media_nonce(salt4, i):
    return salt4 + be64(i)


def media_chunk_aad(media_id, chunk_index, total_chunks, unpadded_len, padded_size):
    """MediaChunkAAD = {1:1, 2:media_id(16B), 3:chunk_index, 4:total_chunks, 5:unpadded_len, 6:padded_size},
    encoded with PM-CBOR-2026."""
    assert len(media_id) == 16
    return _R.encode(_R.Map([(1, 1), (2, media_id), (3, chunk_index), (4, total_chunks),
                             (5, unpadded_len), (6, padded_size)]))


def media_chunk_encrypt(k_media, salt4, aad, chunk_index, chunk_plain):
    """ASSUMPTION: K_media is the ChaCha20-Poly1305 key (the memo derives only NonceSalt from it)."""
    return ChaCha20Poly1305(k_media).encrypt(media_nonce(salt4, chunk_index), chunk_plain, aad)


def allh_container(pt, s):
    assert s >= len(pt) + 1
    return pt + b"\x80" + b"\x00" * (s - len(pt) - 1)


def allh_validate(container, plain_len):
    """Structural check from the memo: S >= L+1, byte at L == 0x80, bytes L+1..S == 0x00."""
    s = len(container)
    if s < plain_len + 1:
        return "INVALID_LENGTH"
    if container[plain_len] != 0x80:
        return "INVALID_MARKER"
    if any(container[plain_len + 1:]):
        return "INVALID_PADDING"
    return "OK"


def allh_bucket(plain_len):
    """ASSUMPTION (memo silent): smallest bucket S with S >= L+1."""
    for b in BUCKETS:
        if b >= plain_len + 1:
            return b
    return None
