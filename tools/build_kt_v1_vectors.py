#!/usr/bin/env python3
"""Generate deterministic Key Transparency V1 reference vectors."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import kt_v1_reference as K

V = HERE.parent / "test-vectors" / "v1"
MANIFEST = V / "manifest.json"


def dump_json(path: Path, value: object) -> bytes:
    raw = (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False) + "\n").encode("utf-8")
    path.write_bytes(raw)
    return raw


def seed_bytes(start: int) -> bytes:
    return bytes(((start + i) & 0xFF) for i in range(32))


def make_device(account: bytes, device: bytes, seed_start: int, epoch: int, version: int) -> dict:
    dsk = K.Ed25519PrivateKey.from_private_bytes(seed_bytes(seed_start))
    dsk_pub = K.pub_raw(dsk)
    ddhk = hashlib.sha256(b"ddhk-v1" + device + bytes([version])).digest()
    spk = hashlib.sha256(b"spk-v1" + device + version.to_bytes(2, "big")).digest()
    push = hashlib.sha256(b"push-v1" + device + version.to_bytes(2, "big")).digest()
    timestamp = 1_700_000_000 + version
    cert = K.make_cert_dh(dsk, account, device, ddhk, timestamp)
    core = K.leaf_core(account, epoch, device, dsk_pub, ddhk, cert, spk, push)
    leaf = K.make_leaf(core, dsk)
    return {
        "account_id": account,
        "device_id": device,
        "epoch": epoch,
        "dsk": dsk,
        "leaf": leaf,
        "leaf_hash": K.leaf_hash(leaf),
        "leaf_key": K.leaf_key(account, device),
    }


def device_id(i: int) -> bytes:
    return (i.to_bytes(1, "big") * 16)


def make_histories() -> tuple[list[dict], dict[bytes, dict]]:
    account = bytes.fromhex("00112233445566778899aabbccddeeff")
    states: list[dict] = []
    current: dict[bytes, dict] = {}
    for seq in range(1, 33):
        i = ((seq - 1) % 9) + 1
        d = make_device(account, device_id(i), 0x10 + i, 1 + ((seq - 1) // 16), seq)
        entry = K.history_entry(seq, d["leaf_key"], d["leaf_hash"])
        states.append({"sequence": seq, **d, "history_entry": entry})
        current[d["leaf_key"]] = d
    return states, current


def leaf_vectors() -> dict:
    account = bytes.fromhex("00112233445566778899aabbccddeeff")
    cases = []
    for idx, seed in enumerate((0x10, 0x20, 0x30), start=1):
        d = make_device(account, device_id(idx), seed, 1, idx)
        core, sig = K.decode_leaf(d["leaf"])
        ident = K.leaf_identity(d["leaf"])
        cases.append({
            "id": f"leaf_{idx}",
            "fields": {k: (v.hex() if isinstance(v, bytes) else v) for k, v in ident.items() if k != "cert_dh"},
            "cert_dh_hex": ident["cert_dh"].hex(),
            "leaf_cbor_hex": d["leaf"].hex(),
            "leaf_core_cbor_hex": K.leaf_core_bytes(core).hex(),
            "leaf_signature_hex": sig.hex(),
            "leaf_hash_hex": d["leaf_hash"].hex(),
            "leaf_key_hex": d["leaf_key"].hex(),
        })
    return {
        "suite": "PM-KT-LEAF-V1",
        "status": "ACTIVE",
        "protocol_version": K.PROTOCOL_VERSION,
        "note": "Deterministic test-only fixtures. Device authorization is intentionally outside the KT V1 proof boundary.",
        "domains": {
            "cert_dh": K.CERT_DH_DOMAIN.decode(),
            "leaf_sign": K.LEAF_SIGN_DOMAIN.decode(),
            "leaf_hash": K.LEAF_HASH_DOMAIN.decode(),
            "smt_key": K.SMT_KEY_DOMAIN.decode(),
        },
        "cases": cases,
        "negative": [
            {"id": "tampered_leaf_signature", "expected": "LEAF_SIGNATURE_INVALID"},
            {"id": "unknown_leaf_field", "expected": "PM_CBOR_UNKNOWN_FIELD"},
            {"id": "noncanonical_leaf", "expected": "PM_CBOR_NON_CANONICAL"},
        ],
    }


def smt_vectors(current: dict[bytes, dict]) -> dict:
    entries = {k: v["leaf_hash"] for k, v in current.items()}
    root = K.smt_root(entries)
    proofs = []
    for key in sorted(entries):
        proofs.append({
            "leaf_key_hex": key.hex(),
            "leaf_hash_hex": entries[key].hex(),
            "siblings_root_to_leaf_hex": [x.hex() for x in K.smt_inclusion_proof(entries, key)],
            "verifies": K.smt_verify_inclusion(key, entries[key], K.smt_inclusion_proof(entries, key), root),
        })
    return {
        "suite": "PM-KT-SMT-V1",
        "status": "ACTIVE",
        "depth": K.SMT_DEPTH,
        "key_derivation": "SHA-256(\"PM-V1-SMT-KEY\" || AccountID || DeviceID)",
        "leaf_node": "SHA-256(0x00 || leaf_hash)",
        "internal_node": "SHA-256(0x01 || left || right)",
        "empty_node": "Empty[0] = SHA-256(0x00); Empty[d+1] = SHA-256(0x01 || Empty[d] || Empty[d])",
        "current_state_leaf_count": len(entries),
        "root_hex": root.hex(),
        "proofs": proofs,
        "negative": [
            {"id": "tamper_sibling_1", "source_proof_index": 0, "mutation": "flip_first_bit", "expected": "SMT_ROOT_MISMATCH"},
            {"id": "tamper_leaf_hash_1", "source_proof_index": 1, "mutation": "flip_first_bit", "expected": "SMT_ROOT_MISMATCH"},
            {"id": "wrong_key_1", "source_proof_index": 2, "mutation": "use_other_key", "expected": "SMT_ROOT_MISMATCH"},
            {"id": "short_proof_1", "source_proof_index": 3, "mutation": "remove_last_sibling", "expected": "INVALID_PROOF_LENGTH"},
            {"id": "wrong_root_1", "source_proof_index": 4, "mutation": "flip_root_bit", "expected": "SMT_ROOT_MISMATCH"},
            {"id": "tamper_sibling_2", "source_proof_index": 5, "mutation": "flip_first_bit", "expected": "SMT_ROOT_MISMATCH"},
            {"id": "tamper_leaf_hash_2", "source_proof_index": 6, "mutation": "flip_first_bit", "expected": "SMT_ROOT_MISMATCH"},
        ],
    }


def history_vectors(states: list[dict]) -> dict:
    data = [s["history_entry"] for s in states]
    root = K.history_root(data)
    inclusion = []
    for idx, entry in enumerate(data):
        proof = K.history_inclusion_proof(data, idx)
        inclusion.append({
            "sequence": idx + 1,
            "index": idx,
            "entry_hex": entry.hex(),
            "proof_hex": [p.hex() for p in proof],
            "verifies": K.history_verify_inclusion(entry, idx, len(data), proof, root),
        })
    consistency = []
    for old in range(1, len(data)):
        proof = K.history_consistency_proof(data, old)
        old_root = K.history_root(data[:old])
        consistency.append({
            "old_size": old,
            "new_size": len(data),
            "old_root_hex": old_root.hex(),
            "new_root_hex": root.hex(),
            "proof_hex": [p.hex() for p in proof],
            "verifies": K.history_verify_consistency(old, len(data), old_root, root, proof),
        })
    return {
        "suite": "PM-KT-HISTORY-V1",
        "status": "ACTIVE",
        "tree": "RFC 6962-shaped binary Merkle tree",
        "leaf_hash": "SHA-256(0x00 || canonical_history_entry)",
        "internal_hash": "SHA-256(0x01 || left || right)",
        "empty_tree": "SHA-256(empty string)",
        "tree_size": len(data),
        "history_root_hex": root.hex(),
        "entries": [{"sequence": s["sequence"], "entry_hex": s["history_entry"].hex()} for s in states],
        "inclusion": inclusion,
        "consistency": consistency,
        "negative": [
            {"id": "tamper_inclusion_1", "source_index": 0, "mutation": "flip_proof_bit", "expected": "PROOF_REJECTED"},
            {"id": "tamper_inclusion_2", "source_index": 7, "mutation": "flip_entry_bit", "expected": "PROOF_REJECTED"},
            {"id": "tamper_inclusion_3", "source_index": 13, "mutation": "wrong_index", "expected": "PROOF_REJECTED"},
            {"id": "tamper_inclusion_4", "source_index": 19, "mutation": "wrong_tree_size", "expected": "PROOF_REJECTED"},
            {"id": "tamper_inclusion_5", "source_index": 25, "mutation": "flip_root_bit", "expected": "PROOF_REJECTED"},
            {"id": "tamper_inclusion_6", "source_index": 30, "mutation": "remove_proof_node", "expected": "PROOF_REJECTED"},
            {"id": "tamper_consistency_1", "old_size": 1, "mutation": "flip_proof_bit", "expected": "PROOF_REJECTED"},
            {"id": "tamper_consistency_2", "old_size": 7, "mutation": "flip_new_root_bit", "expected": "PROOF_REJECTED"},
            {"id": "tamper_consistency_3", "old_size": 13, "mutation": "flip_old_root_bit", "expected": "PROOF_REJECTED"},
            {"id": "tamper_consistency_4", "old_size": 19, "mutation": "remove_proof_node", "expected": "PROOF_REJECTED"},
            {"id": "tamper_consistency_5", "old_size": 29, "mutation": "swap_proof_nodes", "expected": "PROOF_REJECTED"},
        ],
    }


def sth_and_equivocation(states: list[dict], current: dict[bytes, dict]) -> dict:
    log_key = K.Ed25519PrivateKey.from_private_bytes(seed_bytes(0xA0))
    log_pub = K.pub_raw(log_key)
    log_id = hashlib.sha256(b"pm-kt-v1-test-log" + log_pub).digest()
    entries = [s["history_entry"] for s in states]
    hroot = K.history_root(entries)
    smt = {k: v["leaf_hash"] for k, v in current.items()}
    sroot = K.smt_root(smt)
    body = K.sth_body(len(entries), sroot, hroot, 1_700_100_000, log_id)
    sth_a = K.make_sth(body, log_key)
    verified_a = K.verify_sth(sth_a, log_pub)
    assert verified_a["tree_size"] == 32

    mutated_root = bytearray(sroot)
    mutated_root[0] ^= 1
    body_b = K.sth_body(len(entries), bytes(mutated_root), hroot, 1_700_100_001, log_id)
    sth_b = K.make_sth(body_b, log_key)
    verified_b = K.verify_sth(sth_b, log_pub)
    assert verified_a["sth_digest"] != verified_b["sth_digest"]

    witness = []
    registry = {}
    for idx, start in enumerate((0xC0, 0xE0, 0x100), start=1):
        sk = K.Ed25519PrivateKey.from_private_bytes(seed_bytes(start & 0xFF))
        wid = bytes([idx]) * 16
        registry[wid] = K.pub_raw(sk)
        target = sth_a if idx < 3 else sth_b
        witness.append({"id": idx, "witness_id_hex": wid.hex(), "public_key_hex": registry[wid].hex(),
                        "statement_hex": K.make_witness_statement(sk, wid, target).hex()})
    stmt_a1 = bytes.fromhex(witness[0]["statement_hex"])
    stmt_a2 = bytes.fromhex(witness[1]["statement_hex"])
    stmt_b3 = bytes.fromhex(witness[2]["statement_hex"])
    assert K.verify_witness_statement(stmt_a1, registry)["sth_digest"] == verified_a["sth_digest"]
    assert K.verify_witness_statement(stmt_b3, registry)["sth_digest"] == verified_b["sth_digest"]

    evidence = K.equivocation_evidence(sth_a, sth_b, [stmt_a1, stmt_b3])
    return {
        "suite": "PM-KT-EQUIVOCATION-V1",
        "status": "ACTIVE",
        "log": {"private_seed_hex": seed_bytes(0xA0).hex(), "public_key_hex": log_pub.hex(), "log_id_hex": log_id.hex()},
        "sth_a_hex": sth_a.hex(),
        "sth_b_hex": sth_b.hex(),
        "sth_a_digest_hex": verified_a["sth_digest"].hex(),
        "sth_b_digest_hex": verified_b["sth_digest"].hex(),
        "witness_registry": witness,
        "equivocation_evidence_hex": evidence.hex(),
        "expected_state": "SECURITY_FAILURE",
        "rules": [
            "Two valid STHs for the same log_id and tree_size with different roots are equivocation.",
            "Two witness statements for the same log_id and tree_size that validly bind different STH digests are conflicting witness evidence.",
            "Equivocation is sticky: later valid STHs do not clear the recorded security failure automatically.",
        ],
    }


def main() -> None:
    states, current = make_histories()
    dump_json(V / "transparency_leaf.json", leaf_vectors())
    dump_json(V / "transparency_smt_proofs.json", smt_vectors(current))
    dump_json(V / "transparency_history_proofs.json", history_vectors(states))
    dump_json(V / "transparency_equivocation.json", sth_and_equivocation(states, current))

    # Keep the existing legacy placeholder untouched; it is superseded by the explicit V1 file above.
    entries = []
    for p in sorted(V.glob("*.json")):
        if p.name == "manifest.json":
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        status = d.get("status") if d.get("status") in {"PLACEHOLDER_LOCKED", "PARTIAL"} else "ACTIVE"
        entries.append({"path": p.name, "status": status, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
    dump_json(MANIFEST, {"manifest_format": 1, "files": entries})
    print("KT V1 vectors generated; manifest updated")


if __name__ == "__main__":
    main()
