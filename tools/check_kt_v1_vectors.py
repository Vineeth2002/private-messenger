#!/usr/bin/env python3
"""Independently check all KT V1 vectors and protocol invariants."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import kt_v1_reference as K

V = HERE.parent / "test-vectors" / "v1"
FAILURES: list[str] = []


def check(ok: bool, message: str) -> None:
    if not ok:
        FAILURES.append(message)


def load(name: str) -> tuple[bytes, dict]:
    raw = (V / name).read_bytes()
    return raw, json.loads(raw)


def flip_hex(hx: str | bytes, index: int = 0) -> bytes:
    data = bytearray.fromhex(hx) if isinstance(hx, str) else bytearray(hx)
    if not data:
        raise ValueError("cannot mutate empty value")
    data[index % len(data)] ^= 1
    return bytes(data)


def check_manifest() -> None:
    _raw, man = load("manifest.json")
    listed = {e["path"] for e in man["files"]}
    on_disk = {p.name for p in V.glob("*.json") if p.name != "manifest.json"}
    check(listed == on_disk, f"manifest file set mismatch: {listed ^ on_disk}")
    for entry in man["files"]:
        raw, doc = load(entry["path"])
        check(hashlib.sha256(raw).hexdigest() == entry["sha256"], f"manifest hash mismatch: {entry['path']}")
        if entry["status"] == "PLACEHOLDER_LOCKED":
            check(doc.get("vectors") == [], f"placeholder drift: {entry['path']}")


def check_leaf_vectors() -> None:
    _raw, doc = load("transparency_leaf.json")
    check(doc["suite"] == "PM-KT-LEAF-V1", "leaf suite")
    for case in doc["cases"]:
        leaf = bytes.fromhex(case["leaf_cbor_hex"])
        core, sig = K.decode_leaf(leaf)
        check(K.leaf_core_bytes(core).hex() == case["leaf_core_cbor_hex"], f"{case['id']}: core encoding")
        check(sig.hex() == case["leaf_signature_hex"], f"{case['id']}: signature")
        check(K.leaf_hash(leaf).hex() == case["leaf_hash_hex"], f"{case['id']}: leaf hash")
        f = K.leaf_identity(leaf)
        check(K.leaf_key(f["account_id"], f["device_id"]).hex() == case["leaf_key_hex"], f"{case['id']}: leaf key")
        try:
            K.verify_leaf(leaf)
        except Exception as exc:
            check(False, f"{case['id']}: valid leaf rejected: {exc}")
        # Signature mutation must fail closed.
        mutated = bytearray(leaf)
        mutated[-1] ^= 1
        try:
            K.verify_leaf(bytes(mutated))
            check(False, f"{case['id']}: tampered leaf accepted")
        except Exception:
            pass


def check_smt_vectors() -> None:
    _raw, doc = load("transparency_smt_proofs.json")
    entries = {}
    for proof in doc["proofs"]:
        entries[bytes.fromhex(proof["leaf_key_hex"])] = bytes.fromhex(proof["leaf_hash_hex"])
    root = K.smt_root(entries)
    check(root.hex() == doc["root_hex"], "SMT root")
    for i, proof in enumerate(doc["proofs"]):
        key = bytes.fromhex(proof["leaf_key_hex"])
        leaf_hash = bytes.fromhex(proof["leaf_hash_hex"])
        siblings = [bytes.fromhex(x) for x in proof["siblings_root_to_leaf_hex"]]
        check(len(siblings) == K.SMT_DEPTH, f"SMT proof {i}: depth")
        check(K.smt_verify_inclusion(key, leaf_hash, siblings, root), f"SMT proof {i}: verification")
        bad = siblings.copy(); bad[-1] = flip_hex(bad[-1])
        check(not K.smt_verify_inclusion(key, leaf_hash, bad, root), f"SMT proof {i}: tamper accepted")
    # Demonstrate key replacement only changes the path-affected root, with no variable-depth ambiguity.
    first = next(iter(entries))
    mutated = dict(entries); mutated[first] = flip_hex(mutated[first])
    check(K.smt_root(mutated) != root, "SMT mutated leaf changed root")


def check_history_vectors() -> None:
    _raw, doc = load("transparency_history_proofs.json")
    entries = [bytes.fromhex(e["entry_hex"]) for e in doc["entries"]]
    root = K.history_root(entries)
    check(root.hex() == doc["history_root_hex"], "history root")
    for item in doc["inclusion"]:
        idx = item["index"]
        proof = [bytes.fromhex(x) for x in item["proof_hex"]]
        check(K.history_verify_inclusion(entries[idx], idx, len(entries), proof, root), f"history inclusion {idx}")
        bad = proof.copy()
        if bad:
            bad[0] = flip_hex(bad[0])
            check(not K.history_verify_inclusion(entries[idx], idx, len(entries), bad, root), f"history inclusion tamper {idx}")
    for item in doc["consistency"]:
        old = item["old_size"]
        proof = [bytes.fromhex(x) for x in item["proof_hex"]]
        old_root = bytes.fromhex(item["old_root_hex"])
        new_root = bytes.fromhex(item["new_root_hex"])
        check(K.history_verify_consistency(old, len(entries), old_root, new_root, proof), f"history consistency {old}")
        if proof:
            bad = proof.copy(); bad[-1] = flip_hex(bad[-1])
            check(not K.history_verify_consistency(old, len(entries), old_root, new_root, bad), f"history consistency tamper {old}")
    check(K.history_root(entries[:1]).hex() != K.history_root(entries).hex(), "history append changed root")

    # The history sequence is the 1-based publication position. A valid Merkle proof
    # with a mismatched sequence must therefore fail closed.
    first_fields = K._map_int_keys(K.R.decode_strict(entries[0]))
    mismatched = K.history_entry(2, first_fields[2], first_fields[3])
    bad_entries = [mismatched] + entries[1:]
    bad_root = K.history_root(bad_entries)
    bad_proof = K.history_inclusion_proof(bad_entries, 0)
    check(not K.history_verify_inclusion(mismatched, 0, len(bad_entries), bad_proof, bad_root), "history sequence/index mismatch accepted")


def check_equivocation_vectors() -> None:
    _raw, doc = load("transparency_equivocation.json")
    log_pub = bytes.fromhex(doc["log"]["public_key_hex"])
    a = bytes.fromhex(doc["sth_a_hex"])
    b = bytes.fromhex(doc["sth_b_hex"])
    va = K.verify_sth(a, log_pub)
    vb = K.verify_sth(b, log_pub)
    check(va["tree_size"] == vb["tree_size"], "equivocation tree size")
    check(va["log_id"] == vb["log_id"], "equivocation log id")
    check(va["sth_digest"] != vb["sth_digest"], "equivocation distinct STHs")
    registry = {bytes.fromhex(x["witness_id_hex"]): bytes.fromhex(x["public_key_hex"]) for x in doc["witness_registry"]}
    witness_obs = []
    for x in doc["witness_registry"]:
        try:
            obs = K.verify_witness_statement(bytes.fromhex(x["statement_hex"]), registry)
            witness_obs.append(obs)
        except Exception as exc:
            check(False, f"witness statement {x['id']} invalid: {exc}")
    check({o["sth_digest"] for o in witness_obs} == {va["sth_digest"], vb["sth_digest"]}, "witness conflicts")
    check(K.witness_conflict_exists(witness_obs), "witness conflict not detected")
    check(not K.witness_conflict_exists(witness_obs[:2]), "unexpected witness conflict")
    evidence = bytes.fromhex(doc["equivocation_evidence_hex"])
    check(len(K.R.decode_strict(evidence)) == 5, "equivocation evidence structure")
    check(doc["expected_state"] == "SECURITY_FAILURE", "equivocation state")


def check_state_policy() -> None:
    checks = [
        (K.TransparencyObservation(10, 9, True, 3).state(), "SECURITY_FAILURE"),
        (K.TransparencyObservation(10, 10, True, 2).state(), "VERIFIED"),
        (K.TransparencyObservation(10, 11, True, 1).state(), "DEGRADED"),
        (K.TransparencyObservation(10, 11, False, 3).state(), "SECURITY_FAILURE"),
        (K.TransparencyObservation(10, 11, True, 3, witness_conflict=True).state(), "SECURITY_FAILURE"),
        (K.TransparencyObservation(10, 11, True, 3, consistency_valid=False).state(), "SECURITY_FAILURE"),
    ]
    for got, want in checks:
        check(got == want, f"state policy: got {got}, want {want}")


def main() -> None:
    check_manifest()
    check_leaf_vectors()
    check_smt_vectors()
    check_history_vectors()
    check_equivocation_vectors()
    check_state_policy()
    if FAILURES:
        print("KT V1 VECTOR CHECK FAILED")
        for f in FAILURES:
            print(" -", f)
        raise SystemExit(1)
    print("KT V1 vector check OK: leaf, current-state SMT, history inclusion/consistency, STH/witness, equivocation, state policy")


if __name__ == "__main__":
    main()
