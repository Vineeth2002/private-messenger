//! Shared-vector conformance for frozen Key Transparency V1.

use pm_crypto_core::transparency_v1::{
    decode_equivocation_evidence, decode_history_entry, decode_leaf, history_root, is_sth_equivocation,
    leaf_hash, smt_key, smt_root, verify_history_consistency, verify_history_inclusion,
    verify_smt_inclusion, verify_sth, verify_witness_statement, witness_conflict_exists, witness_quorum_count,
};
use serde_json::Value as J;
use std::collections::BTreeMap;

fn load(name: &str) -> J {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/v1")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("valid JSON")
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

#[test]
fn leaf_vectors_match_reference() {
    let v = load("transparency_leaf.json");
    for case in v["cases"].as_array().unwrap() {
        let leaf = hex(case["leaf_cbor_hex"].as_str().unwrap());
        let decoded = decode_leaf(&leaf).unwrap();
        assert_eq!(hex(case["cert_dh_hex"].as_str().unwrap()), decoded.cert_dh.to_vec());
        let core = pm_crypto_core::cbor::encode_canonical(&pm_crypto_core::cbor::Value::Map(vec![
            (pm_crypto_core::cbor::Value::Int(1), pm_crypto_core::cbor::Value::Bytes(decoded.account_id.to_vec())),
            (pm_crypto_core::cbor::Value::Int(2), pm_crypto_core::cbor::Value::Int(decoded.epoch as i128)),
            (pm_crypto_core::cbor::Value::Int(3), pm_crypto_core::cbor::Value::Bytes(decoded.device_id.to_vec())),
            (pm_crypto_core::cbor::Value::Int(4), pm_crypto_core::cbor::Value::Bytes(decoded.dsk_pub.to_vec())),
            (pm_crypto_core::cbor::Value::Int(5), pm_crypto_core::cbor::Value::Bytes(decoded.ddhk_pub.to_vec())),
            (pm_crypto_core::cbor::Value::Int(6), pm_crypto_core::cbor::Value::Bytes(decoded.cert_dh.to_vec())),
            (pm_crypto_core::cbor::Value::Int(7), pm_crypto_core::cbor::Value::Bytes(decoded.spk_pub.to_vec())),
            (pm_crypto_core::cbor::Value::Int(8), pm_crypto_core::cbor::Value::Bytes(decoded.push_pk.to_vec())),
        ])).unwrap();
        assert_eq!(core, hex(case["leaf_core_cbor_hex"].as_str().unwrap()));
        let signature = match pm_crypto_core::cbor::decode_strict(&leaf).unwrap() {
            pm_crypto_core::cbor::Value::Map(pairs) => pairs.into_iter().find_map(|(k, v)| {
                if k == pm_crypto_core::cbor::Value::Int(9) { Some(v) } else { None }
            }).unwrap(),
            _ => panic!("leaf is not map"),
        };
        let signature = match signature { pm_crypto_core::cbor::Value::Bytes(v) => v, _ => panic!("signature") };
        assert_eq!(signature, hex(case["leaf_signature_hex"].as_str().unwrap()));
        assert_eq!(leaf_hash(&leaf).unwrap(), arr::<32>(case["leaf_hash_hex"].as_str().unwrap()));
        assert_eq!(smt_key(&decoded.account_id, &decoded.device_id), arr::<32>(case["leaf_key_hex"].as_str().unwrap()));
        // Signature is checked by leaf_hash/decode path.
        assert!(leaf_hash(&leaf).is_ok());
    }
}

#[test]
fn smt_vectors_match_reference_and_tamper_rejects() {
    let v = load("transparency_smt_proofs.json");
    let proofs = v["proofs"].as_array().unwrap();
    let mut entries = Vec::new();
    for proof in proofs {
        entries.push((arr::<32>(proof["leaf_key_hex"].as_str().unwrap()), arr::<32>(proof["leaf_hash_hex"].as_str().unwrap())));
    }
    let root = smt_root(&entries).unwrap();
    assert_eq!(root, arr::<32>(v["root_hex"].as_str().unwrap()));
    for proof in proofs {
        let key = arr::<32>(proof["leaf_key_hex"].as_str().unwrap());
        let leaf_hash = arr::<32>(proof["leaf_hash_hex"].as_str().unwrap());
        let siblings = proof["siblings_root_to_leaf_hex"].as_array().unwrap().iter().map(|x| arr::<32>(x.as_str().unwrap())).collect::<Vec<_>>();
        verify_smt_inclusion(&key, &leaf_hash, &siblings, &root).unwrap();
        let mut tampered = siblings.clone();
        tampered[0][0] ^= 1;
        assert!(verify_smt_inclusion(&key, &leaf_hash, &tampered, &root).is_err());
    }
    let mut short = proofs[0]["siblings_root_to_leaf_hex"].as_array().unwrap().iter().map(|x| arr::<32>(x.as_str().unwrap())).collect::<Vec<_>>();
    short.pop();
    assert!(verify_smt_inclusion(&arr::<32>(proofs[0]["leaf_key_hex"].as_str().unwrap()), &arr::<32>(proofs[0]["leaf_hash_hex"].as_str().unwrap()), &short, &root).is_err());
}

#[test]
fn history_vectors_match_reference_and_tamper_rejects() {
    let v = load("transparency_history_proofs.json");
    let entries = v["entries"].as_array().unwrap().iter().map(|e| hex(e["entry_hex"].as_str().unwrap())).collect::<Vec<_>>();
    let root = history_root(&entries);
    assert_eq!(root, arr::<32>(v["history_root_hex"].as_str().unwrap()));

    for item in v["inclusion"].as_array().unwrap() {
        let idx = item["index"].as_u64().unwrap() as usize;
        let proof = item["proof_hex"].as_array().unwrap().iter().map(|x| arr::<32>(x.as_str().unwrap())).collect::<Vec<_>>();
        verify_history_inclusion(&entries[idx], idx, entries.len(), &proof, &root).unwrap();
        if !proof.is_empty() {
            let mut bad = proof.clone(); bad[0][0] ^= 1;
            assert!(verify_history_inclusion(&entries[idx], idx, entries.len(), &bad, &root).is_err());
        }
    }

    for item in v["consistency"].as_array().unwrap() {
        let old = item["old_size"].as_u64().unwrap() as usize;
        let old_root = arr::<32>(item["old_root_hex"].as_str().unwrap());
        let new_root = arr::<32>(item["new_root_hex"].as_str().unwrap());
        let proof = item["proof_hex"].as_array().unwrap().iter().map(|x| arr::<32>(x.as_str().unwrap())).collect::<Vec<_>>();
        verify_history_consistency(old, entries.len(), &old_root, &new_root, &proof).unwrap();
        if !proof.is_empty() {
            let mut bad = proof.clone(); bad[0][0] ^= 1;
            assert!(verify_history_consistency(old, entries.len(), &old_root, &new_root, &bad).is_err());
        }
    }

    let first = pm_crypto_core::cbor::decode_strict(&entries[0]).unwrap();
    let first_fields = match first {
        pm_crypto_core::cbor::Value::Map(pairs) => pairs
            .into_iter()
            .map(|(k, v)| match k {
                pm_crypto_core::cbor::Value::Int(n) => (n as u64, v),
                _ => panic!("history key"),
            })
            .collect::<BTreeMap<_, _>>(),
        _ => panic!("history entry must be map"),
    };
    let mismatched_sequence = pm_crypto_core::cbor::Value::Map(vec![
        (pm_crypto_core::cbor::Value::Int(1), pm_crypto_core::cbor::Value::Int(2)),
        (pm_crypto_core::cbor::Value::Int(2), first_fields.get(&2).cloned().unwrap()),
        (pm_crypto_core::cbor::Value::Int(3), first_fields.get(&3).cloned().unwrap()),
    ]);
    let bad_entry = pm_crypto_core::cbor::encode_canonical(&mismatched_sequence).unwrap();
    let bad_entries = vec![bad_entry.clone(), entries[1].clone()];
    let bad_root = history_root(&bad_entries);
    let bad_proof = {
        let mut proof = Vec::<[u8; 32]>::new();
        // The first two-entry tree has one sibling, which is the hash of entry 2.
        proof.push({
            let h = {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update([0x00]);
                hasher.update(&bad_entries[1]);
                hasher.finalize().into()
            };
            h
        });
        proof
    };
    assert!(verify_history_inclusion(&bad_entry, 0, bad_entries.len(), &bad_proof, &bad_root).is_err());
}

#[test]
fn sth_witness_and_equivocation_vectors_match_reference() {
    let v = load("transparency_equivocation.json");
    let log_pub = arr::<32>(v["log"]["public_key_hex"].as_str().unwrap());
    let sth_a_bytes = hex(v["sth_a_hex"].as_str().unwrap());
    let sth_b_bytes = hex(v["sth_b_hex"].as_str().unwrap());
    let sth_a = verify_sth(&sth_a_bytes, &log_pub).unwrap();
    let sth_b = verify_sth(&sth_b_bytes, &log_pub).unwrap();
    assert!(is_sth_equivocation(&sth_a, &sth_b));
    assert_eq!(sth_a.sth_digest, arr::<32>(v["sth_a_digest_hex"].as_str().unwrap()));
    assert_eq!(sth_b.sth_digest, arr::<32>(v["sth_b_digest_hex"].as_str().unwrap()));

    let mut registry = BTreeMap::new();
    let mut statements = Vec::new();
    for item in v["witness_registry"].as_array().unwrap() {
        registry.insert(arr::<16>(item["witness_id_hex"].as_str().unwrap()), arr::<32>(item["public_key_hex"].as_str().unwrap()));
    }
    for item in v["witness_registry"].as_array().unwrap() {
        statements.push(verify_witness_statement(&hex(item["statement_hex"].as_str().unwrap()), &registry).unwrap());
    }
    assert_eq!(witness_quorum_count(&statements, &sth_a), 2);
    assert_eq!(witness_quorum_count(&statements, &sth_b), 1);
    assert!(witness_conflict_exists(&statements));
    assert!(!witness_conflict_exists(&statements[..2]));
}



#[test]
fn history_entries_and_equivocation_evidence_are_strict_objects() {
    let history = load("transparency_history_proofs.json");
    for entry in history["entries"].as_array().unwrap() {
        let bytes = hex(entry["entry_hex"].as_str().unwrap());
        let decoded = decode_history_entry(&bytes).unwrap();
        assert_eq!(decoded.sequence, entry["sequence"].as_u64().unwrap());
    }

    let eq = load("transparency_equivocation.json");
    let evidence = decode_equivocation_evidence(&hex(eq["equivocation_evidence_hex"].as_str().unwrap())).unwrap();
    assert_eq!(evidence.sth_a, hex(eq["sth_a_hex"].as_str().unwrap()));
    assert_eq!(evidence.sth_b, hex(eq["sth_b_hex"].as_str().unwrap()));
    assert!(!evidence.witness_statements.is_empty());
}

#[test]
fn leaf_unknown_and_noncanonical_fields_fail_closed() {
    let v = load("transparency_leaf.json");
    let leaf = hex(v["cases"][0]["leaf_cbor_hex"].as_str().unwrap());
    let decoded = pm_crypto_core::cbor::decode_strict(&leaf).unwrap();
    let mut pairs = match decoded {
        pm_crypto_core::cbor::Value::Map(p) => p,
        _ => panic!("leaf must be a map"),
    };
    pairs.push((
        pm_crypto_core::cbor::Value::Int(10),
        pm_crypto_core::cbor::Value::Int(1),
    ));
    let unknown = pm_crypto_core::cbor::encode_canonical(&pm_crypto_core::cbor::Value::Map(pairs)).unwrap();
    assert!(decode_leaf(&unknown).is_err());

    let mut noncanonical = leaf.clone();
    assert_eq!(noncanonical[0], 0xa9);
    assert_eq!(noncanonical[1], 0x01);
    noncanonical[1] = 0x18;
    noncanonical.insert(2, 0x01);
    assert!(decode_leaf(&noncanonical).is_err());
}
