#!/usr/bin/env python3
"""Independent Python reference model for Sovereign Private Messenger KT V1.

This is reference/test tooling only. It defines the frozen KT V1 cryptographic
objects, deterministic tree calculations, proofs, STH/witness signatures, and
state classification. Rust/Go production code must be tested against the
resulting vectors rather than copied from this module.
"""
from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import pmcbor_ref as R

# ------------------------------ frozen protocol constants -----------------

PROTOCOL_VERSION = 1
SMT_DEPTH = 256

LEAF_SIGN_DOMAIN = b"PM-V1-KT-LEAF-SIGN-v1"
LEAF_HASH_DOMAIN = b"PM-V1-KT-LEAF-HASH-v1"
CERT_DH_DOMAIN = b"PM-V1-DH-BIND"
SMT_KEY_DOMAIN = b"PM-V1-SMT-KEY"
HISTORY_LOG_DOMAIN = b"PM-V1-KT-HISTORY-v1"  # protocol object namespace only
STH_SIGN_DOMAIN = b"PM-V1-KT-STH-SIGN-v1"
WITNESS_SIGN_DOMAIN = b"PM-V1-KT-WITNESS-SIGN-v1"
EVIDENCE_DOMAIN = b"PM-V1-KT-EQUIVOCATION-v1"
SMT_LEAF_PREFIX = b"\x00"
SMT_NODE_PREFIX = b"\x01"
RFC_LEAF_PREFIX = b"\x00"
RFC_NODE_PREFIX = b"\x01"


def h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hx(data: bytes) -> str:
    return data.hex()


def raw_hex(value: str, n: int | None = None) -> bytes:
    out = bytes.fromhex(value)
    if n is not None and len(out) != n:
        raise ValueError(f"expected {n} bytes, got {len(out)}")
    return out


def cbor_map(items: Iterable[tuple[int, object]]) -> R.Map:
    return R.Map(list(items))


def cbor_bytes(value: object) -> bytes:
    out = R.encode(value)
    if len(out) > R.MAX_BSTR:
        raise ValueError("PM-CBOR wire object exceeds maximum")
    return out


def pub_raw(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ------------------------------ Cert_dh + transparency leaf ---------------


def cert_dh_transcript(account_id: bytes, device_id: bytes, ddhk_pub: bytes, timestamp: int) -> bytes:
    if len(account_id) != 16 or len(device_id) != 16 or len(ddhk_pub) != 32:
        raise ValueError("invalid Cert_dh component length")
    return CERT_DH_DOMAIN + account_id + device_id + ddhk_pub + timestamp.to_bytes(8, "big")


def make_cert_dh(dsk: Ed25519PrivateKey, account_id: bytes, device_id: bytes,
                 ddhk_pub: bytes, timestamp: int) -> bytes:
    return dsk.sign(cert_dh_transcript(account_id, device_id, ddhk_pub, timestamp))


def leaf_core(account_id: bytes, epoch: int, device_id: bytes, dsk_pub: bytes,
              ddhk_pub: bytes, cert_dh: bytes, spk_pub: bytes, push_pk: bytes) -> R.Map:
    if len(account_id) != 16 or len(device_id) != 16:
        raise ValueError("AccountID/DeviceID must be 16 bytes")
    if len(dsk_pub) != 32 or len(ddhk_pub) != 32 or len(cert_dh) != 64:
        raise ValueError("invalid identity key/certificate length")
    if len(spk_pub) != 32 or len(push_pk) != 32:
        raise ValueError("SPK_pub/PushPK must be 32 bytes")
    if not isinstance(epoch, int) or epoch < 1:
        raise ValueError("epoch must be a positive integer")
    return cbor_map([
        (1, account_id),
        (2, epoch),
        (3, device_id),
        (4, dsk_pub),
        (5, ddhk_pub),
        (6, cert_dh),
        (7, spk_pub),
        (8, push_pk),
    ])


def leaf_core_bytes(core: R.Map) -> bytes:
    return cbor_bytes(core)


def sign_leaf(core: R.Map, dsk: Ed25519PrivateKey) -> bytes:
    return dsk.sign(LEAF_SIGN_DOMAIN + leaf_core_bytes(core))


def make_leaf(core: R.Map, dsk: Ed25519PrivateKey) -> bytes:
    sig = sign_leaf(core, dsk)
    return cbor_bytes(R.Map(list(core) + [(9, sig)]))


def _map_int_keys(obj: R.Map) -> dict[int, object]:
    result: dict[int, object] = {}
    for key, value in obj:
        if not isinstance(key, int):
            raise ValueError("KT map key must be uint")
        if key in result:
            raise ValueError("duplicate map key")
        result[key] = value
    return result


def decode_leaf(leaf_bytes: bytes) -> tuple[R.Map, bytes]:
    obj = R.decode_strict(leaf_bytes)
    if not isinstance(obj, R.Map):
        raise ValueError("leaf is not a PM-CBOR map")
    fields = _map_int_keys(obj)
    if set(fields) != set(range(1, 10)):
        raise ValueError("TransparencyLeafV1 must contain exactly fields 1..9")
    sig = fields[9]
    if not isinstance(sig, bytes) or len(sig) != 64:
        raise ValueError("leaf signature length")
    core = R.Map([(k, fields[k]) for k in range(1, 9)])
    # Canonical encoding is checked by decode_strict and this re-encode identity.
    if R.encode(obj) != leaf_bytes:
        raise ValueError("non-canonical leaf bytes")
    return core, sig


def verify_leaf(leaf_bytes: bytes) -> bytes:
    core, sig = decode_leaf(leaf_bytes)
    fields = _map_int_keys(core)
    for key, expected in [(1, 16), (3, 16), (4, 32), (5, 32), (6, 64), (7, 32), (8, 32)]:
        if not isinstance(fields[key], bytes) or len(fields[key]) != expected:
            raise ValueError(f"leaf field {key} length")
    if not isinstance(fields[2], int) or fields[2] < 1:
        raise ValueError("leaf epoch")
    try:
        Ed25519PublicKey.from_public_bytes(fields[4]).verify(sig, LEAF_SIGN_DOMAIN + leaf_core_bytes(core))
    except InvalidSignature as exc:
        raise ValueError("leaf DSK signature invalid") from exc
    return fields[4]


def leaf_hash(leaf_bytes: bytes) -> bytes:
    verify_leaf(leaf_bytes)
    return h(LEAF_HASH_DOMAIN + leaf_bytes)


def leaf_key(account_id: bytes, device_id: bytes) -> bytes:
    if len(account_id) != 16 or len(device_id) != 16:
        raise ValueError("invalid account/device ID")
    return h(SMT_KEY_DOMAIN + account_id + device_id)


def leaf_identity(leaf_bytes: bytes) -> dict[str, object]:
    core, _sig = decode_leaf(leaf_bytes)
    f = _map_int_keys(core)
    return {
        "account_id": f[1],
        "epoch": f[2],
        "device_id": f[3],
        "dsk_pub": f[4],
        "ddhk_pub": f[5],
        "cert_dh": f[6],
        "spk_pub": f[7],
        "push_pk": f[8],
    }


# ------------------------------ Current-state SMT --------------------------


def empty_hashes() -> list[bytes]:
    levels = [h(SMT_LEAF_PREFIX)]
    for _ in range(SMT_DEPTH):
        levels.append(h(SMT_NODE_PREFIX + levels[-1] + levels[-1]))
    return levels


SMT_EMPTY = empty_hashes()


def smt_leaf_node(leaf_hash_value: bytes) -> bytes:
    if len(leaf_hash_value) != 32:
        raise ValueError("SMT leaf hash length")
    return h(SMT_LEAF_PREFIX + leaf_hash_value)


def smt_node(left: bytes, right: bytes) -> bytes:
    return h(SMT_NODE_PREFIX + left + right)


def _bit(key: bytes, depth: int) -> int:
    return (key[depth // 8] >> (7 - (depth % 8))) & 1


def _smt_root(items: list[tuple[bytes, bytes]], depth: int) -> bytes:
    if not items:
        return SMT_EMPTY[SMT_DEPTH - depth]
    if depth == SMT_DEPTH:
        if len(items) != 1:
            raise ValueError("SMT key collision")
        return smt_leaf_node(items[0][1])
    left: list[tuple[bytes, bytes]] = []
    right: list[tuple[bytes, bytes]] = []
    for key, value in items:
        (right if _bit(key, depth) else left).append((key, value))
    return smt_node(_smt_root(left, depth + 1), _smt_root(right, depth + 1))


def smt_root(entries: dict[bytes, bytes]) -> bytes:
    clean = [(k, v) for k, v in entries.items()]
    for k, v in clean:
        if len(k) != 32 or len(v) != 32:
            raise ValueError("SMT entries must be 32-byte key/hash pairs")
    if len({k for k, _ in clean}) != len(clean):
        raise ValueError("duplicate SMT key")
    clean.sort(key=lambda kv: kv[0])
    return _smt_root(clean, 0)


def smt_inclusion_proof(entries: dict[bytes, bytes], target_key: bytes) -> list[bytes]:
    if target_key not in entries:
        raise KeyError("target key absent")
    siblings: list[bytes] = []
    items = sorted(entries.items(), key=lambda kv: kv[0])
    for depth in range(SMT_DEPTH):
        bit = _bit(target_key, depth)
        left = [(k, v) for k, v in items if _bit(k, depth) == 0]
        right = [(k, v) for k, v in items if _bit(k, depth) == 1]
        sibling_items = left if bit else right
        siblings.append(_smt_root(sibling_items, depth + 1))
        items = right if bit else left
    return siblings


def smt_verify_inclusion(target_key: bytes, target_leaf_hash: bytes,
                         siblings_root_to_leaf: list[bytes], expected_root: bytes) -> bool:
    if len(target_key) != 32 or len(target_leaf_hash) != 32:
        return False
    if len(siblings_root_to_leaf) != SMT_DEPTH:
        return False
    acc = smt_leaf_node(target_leaf_hash)
    for depth in range(SMT_DEPTH - 1, -1, -1):
        sibling = siblings_root_to_leaf[depth]
        if _bit(target_key, depth) == 0:
            acc = smt_node(acc, sibling)
        else:
            acc = smt_node(sibling, acc)
    return acc == expected_root


# ------------------------------ RFC 6962-shaped history tree ----------------


def rfc_leaf_hash(data: bytes) -> bytes:
    return h(RFC_LEAF_PREFIX + data)


def rfc_node_hash(left: bytes, right: bytes) -> bytes:
    return h(RFC_NODE_PREFIX + left + right)


def history_root(leaf_data: list[bytes]) -> bytes:
    if not leaf_data:
        return h(b"")
    return _history_mth_hashes([rfc_leaf_hash(x) for x in leaf_data])


def _history_mth_hashes(hashes: list[bytes]) -> bytes:
    n = len(hashes)
    if n == 0:
        return h(b"")
    if n == 1:
        return hashes[0]
    k = largest_power_less_than(n)
    return rfc_node_hash(_history_mth_hashes(hashes[:k]), _history_mth_hashes(hashes[k:]))


def largest_power_less_than(n: int) -> int:
    if n <= 1:
        return 0
    return 1 << ((n - 1).bit_length() - 1)


def history_inclusion_proof(leaf_data: list[bytes], index: int) -> list[bytes]:
    hashes = [rfc_leaf_hash(x) for x in leaf_data]
    n = len(hashes)
    if not (0 <= index < n):
        raise ValueError("history index out of range")
    return _history_path(hashes, index)


def _history_path(hashes: list[bytes], index: int) -> list[bytes]:
    n = len(hashes)
    if n <= 1:
        return []
    k = largest_power_less_than(n)
    if index < k:
        return _history_path(hashes[:k], index) + [_history_mth_hashes(hashes[k:])]
    return _history_path(hashes[k:], index - k) + [_history_mth_hashes(hashes[:k])]


def history_verify_inclusion(leaf_data: bytes, index: int, tree_size: int,
                             proof: list[bytes], expected_root: bytes) -> bool:
    if not (0 <= index < tree_size):
        return False
    if any(len(x) != 32 for x in proof):
        return False
    try:
        obj = R.decode_strict(leaf_data)
        fields = _map_int_keys(obj)
        if set(fields) != {1, 2, 3}:
            return False
        if fields[1] != index + 1:
            return False
        if not (isinstance(fields[2], bytes) and len(fields[2]) == 32
                and isinstance(fields[3], bytes) and len(fields[3]) == 32):
            return False
    except Exception:
        return False
    acc = rfc_leaf_hash(leaf_data)
    node = index
    last = tree_size - 1
    pi = 0
    while last > 0:
        if pi >= len(proof):
            return False
        sibling = proof[pi]
        if node % 2 == 1 or node == last:
            acc = rfc_node_hash(sibling, acc)
        else:
            acc = rfc_node_hash(acc, sibling)
        node //= 2
        last //= 2
        pi += 1
    return pi == len(proof) and acc == expected_root


def history_consistency_proof(leaf_data: list[bytes], old_size: int) -> list[bytes]:
    new_size = len(leaf_data)
    if not (1 <= old_size <= new_size):
        raise ValueError("consistency sizes must satisfy 1 <= old <= new")
    hashes = [rfc_leaf_hash(x) for x in leaf_data]
    return _history_subproof(hashes, old_size, new_size, True)


def _history_subproof(hashes: list[bytes], m: int, n: int, complete: bool) -> list[bytes]:
    if m == n:
        return [] if complete else [_history_mth_hashes(hashes[:m])]
    k = largest_power_less_than(n)
    if m <= k:
        return _history_subproof(hashes[:k], m, k, complete) + [_history_mth_hashes(hashes[k:n])]
    return _history_subproof(hashes[k:n], m - k, n - k, False) + [_history_mth_hashes(hashes[:k])]


def history_verify_consistency(old_size: int, new_size: int, old_root: bytes,
                               new_root: bytes, proof: list[bytes]) -> bool:
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    if old_size == new_size:
        return old_root == new_root and not proof
    if old_size == 0:
        return not proof
    node = old_size - 1
    last_node = new_size - 1
    while node % 2:
        node //= 2
        last_node //= 2
    p = iter(proof)
    try:
        if node:
            old_hash = new_hash = next(p)
        else:
            old_hash = new_hash = old_root
        while node:
            if node % 2:
                sibling = next(p)
                old_hash = rfc_node_hash(sibling, old_hash)
                new_hash = rfc_node_hash(sibling, new_hash)
            elif node < last_node:
                new_hash = rfc_node_hash(new_hash, next(p))
            node //= 2
            last_node //= 2
        while last_node:
            new_hash = rfc_node_hash(new_hash, next(p))
            last_node //= 2
        try:
            next(p)
            return False
        except StopIteration:
            pass
    except StopIteration:
        return False
    return old_hash == old_root and new_hash == new_root


# ------------------------------ History objects + STH ----------------------


def history_entry(sequence: int, leaf_key_value: bytes, leaf_hash_value: bytes) -> bytes:
    if sequence < 1 or len(leaf_key_value) != 32 or len(leaf_hash_value) != 32:
        raise ValueError("invalid history entry")
    return cbor_bytes(cbor_map([(1, sequence), (2, leaf_key_value), (3, leaf_hash_value)]))


def history_entry_hash(entry_bytes: bytes) -> bytes:
    return rfc_leaf_hash(entry_bytes)


def sth_body(tree_size: int, smt_root_value: bytes, history_root_value: bytes,
             issued_at: int, log_id: bytes) -> R.Map:
    if tree_size < 0 or issued_at < 0 or len(smt_root_value) != 32 or len(history_root_value) != 32 or len(log_id) != 32:
        raise ValueError("invalid STH components")
    return cbor_map([
        (1, PROTOCOL_VERSION),
        (2, tree_size),
        (3, smt_root_value),
        (4, history_root_value),
        (5, issued_at),
        (6, log_id),
    ])


def make_sth(body: R.Map, log_key: Ed25519PrivateKey) -> bytes:
    sig = log_key.sign(STH_SIGN_DOMAIN + cbor_bytes(body))
    return cbor_bytes(R.Map(list(body) + [(7, sig)]))


def verify_sth(sth_bytes: bytes, log_public: bytes) -> dict[str, object]:
    obj = R.decode_strict(sth_bytes)
    if not isinstance(obj, R.Map):
        raise ValueError("STH must be a map")
    fields = _map_int_keys(obj)
    if set(fields) != set(range(1, 8)):
        raise ValueError("STH fields must be exactly 1..7")
    sig = fields[7]
    if not isinstance(sig, bytes) or len(sig) != 64:
        raise ValueError("STH signature")
    body = cbor_map([(k, fields[k]) for k in range(1, 7)])
    if fields[1] != PROTOCOL_VERSION or not isinstance(fields[2], int):
        raise ValueError("STH protocol/tree_size")
    for k in (3, 4, 6):
        if not isinstance(fields[k], bytes) or len(fields[k]) != 32:
            raise ValueError("STH hash/log id field")
    if not isinstance(fields[5], int) or fields[5] < 0:
        raise ValueError("STH timestamp")
    try:
        Ed25519PublicKey.from_public_bytes(log_public).verify(sig, STH_SIGN_DOMAIN + cbor_bytes(body))
    except InvalidSignature as exc:
        raise ValueError("STH signature invalid") from exc
    return {
        "tree_size": fields[2],
        "smt_root": fields[3],
        "history_root": fields[4],
        "issued_at": fields[5],
        "log_id": fields[6],
        "sth_digest": h(sth_bytes),
    }


def witness_body(witness_id: bytes, log_id: bytes, tree_size: int, sth_digest: bytes) -> R.Map:
    if len(witness_id) != 16 or len(log_id) != 32 or len(sth_digest) != 32:
        raise ValueError("invalid witness statement components")
    return cbor_map([
        (1, PROTOCOL_VERSION),
        (2, witness_id),
        (3, log_id),
        (4, tree_size),
        (5, sth_digest),
    ])


def make_witness_statement(witness_key: Ed25519PrivateKey, witness_id: bytes,
                           sth_bytes: bytes) -> bytes:
    sth = R.decode_strict(sth_bytes)
    fields = _map_int_keys(sth)
    body = witness_body(witness_id, fields[6], fields[2], h(sth_bytes))
    sig = witness_key.sign(WITNESS_SIGN_DOMAIN + cbor_bytes(body))
    return cbor_bytes(R.Map(list(body) + [(6, sig)]))


def verify_witness_statement(statement_bytes: bytes, registry: dict[bytes, bytes]) -> dict[str, object]:
    obj = R.decode_strict(statement_bytes)
    if not isinstance(obj, R.Map):
        raise ValueError("witness statement must be a map")
    fields = _map_int_keys(obj)
    if set(fields) != set(range(1, 7)):
        raise ValueError("witness statement fields must be exactly 1..6")
    wid, log_id, seq, sth_digest, sig = fields[2], fields[3], fields[4], fields[5], fields[6]
    if not (isinstance(wid, bytes) and len(wid) == 16 and isinstance(log_id, bytes) and len(log_id) == 32
            and isinstance(seq, int) and seq >= 0 and isinstance(sth_digest, bytes) and len(sth_digest) == 32
            and isinstance(sig, bytes) and len(sig) == 64):
        raise ValueError("invalid witness statement field")
    pub = registry.get(wid)
    if pub is None:
        raise ValueError("unknown witness")
    body = witness_body(wid, log_id, seq, sth_digest)
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, WITNESS_SIGN_DOMAIN + cbor_bytes(body))
    except InvalidSignature as exc:
        raise ValueError("witness signature invalid") from exc
    return {"witness_id": wid, "log_id": log_id, "tree_size": seq, "sth_digest": sth_digest}

def witness_conflict_exists(statements: list[dict[str, object]]) -> bool:
    seen: dict[tuple[bytes, int], bytes] = {}
    for statement in statements:
        key = (statement["log_id"], statement["tree_size"])
        digest = statement["sth_digest"]
        previous_digest = seen.get(key)
        if previous_digest is not None and previous_digest != digest:
            return True
        seen[key] = digest
    return False



# ------------------------------ state machine + evidence --------------------

@dataclass(frozen=True)
class TransparencyObservation:
    cached_high_water: int
    received_sequence: int
    cryptography_valid: bool
    witness_valid_count: int
    witness_conflict: bool = False
    consistency_valid: bool = True

    def state(self) -> str:
        if self.received_sequence < self.cached_high_water:
            return "SECURITY_FAILURE"
        if not self.cryptography_valid or not self.consistency_valid or self.witness_conflict:
            return "SECURITY_FAILURE"
        if self.witness_valid_count >= 2:
            return "VERIFIED"
        return "DEGRADED"


def equivocation_evidence(sth_a: bytes, sth_b: bytes,
                          witness_statements: list[bytes] | None = None) -> bytes:
    if h(sth_a) == h(sth_b):
        raise ValueError("equivocation evidence requires distinct STH bytes")
    items: list[tuple[int, object]] = [(1, PROTOCOL_VERSION), (2, EVIDENCE_DOMAIN), (3, sth_a), (4, sth_b)]
    if witness_statements:
        items.append((5, list(witness_statements)))
    return cbor_bytes(cbor_map(items))
