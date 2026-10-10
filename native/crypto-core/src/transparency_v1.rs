//! Frozen Key Transparency V1 cryptographic verification boundary.
//!
//! This module implements the exact wire objects and verification rules frozen in
//! `docs/phase0/10-key-transparency-v1-frozen.md`. It deliberately does not implement
//! device authorization, epoch-transition authorization, persistence, or HTTP APIs.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::cbor::{self, CborError, Value};

pub const PROTOCOL_VERSION: u64 = 1;
pub const SMT_DEPTH: usize = 256;

pub const LEAF_SIGN_DOMAIN: &[u8] = b"PM-V1-KT-LEAF-SIGN-v1";
pub const LEAF_HASH_DOMAIN: &[u8] = b"PM-V1-KT-LEAF-HASH-v1";
pub const CERT_DH_DOMAIN: &[u8] = b"PM-V1-DH-BIND";
pub const SMT_KEY_DOMAIN: &[u8] = b"PM-V1-SMT-KEY";
pub const STH_SIGN_DOMAIN: &[u8] = b"PM-V1-KT-STH-SIGN-v1";
pub const WITNESS_SIGN_DOMAIN: &[u8] = b"PM-V1-KT-WITNESS-SIGN-v1";
pub const EVIDENCE_DOMAIN: &[u8] = b"PM-V1-KT-EQUIVOCATION-v1";

const SMT_LEAF_PREFIX: &[u8] = b"\x00";
const SMT_NODE_PREFIX: &[u8] = b"\x01";
const RFC_LEAF_PREFIX: &[u8] = b"\x00";
const RFC_NODE_PREFIX: &[u8] = b"\x01";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransparencyV1Error {
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    #[error("unknown cryptographic field")]
    UnknownField,
    #[error("missing cryptographic field")]
    MissingField,
    #[error("invalid cryptographic field")]
    InvalidField,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("unknown witness")]
    UnknownWitness,
    #[error("duplicate witness")]
    DuplicateWitness,
    #[error("invalid proof length")]
    InvalidProofLength,
    #[error("SMT root mismatch")]
    SmtRootMismatch,
    #[error("history proof rejected")]
    HistoryProofRejected,
    #[error("history consistency proof rejected")]
    HistoryConsistencyRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparencyLeafV1 {
    pub account_id: [u8; 16],
    pub epoch: u64,
    pub device_id: [u8; 16],
    pub dsk_pub: [u8; 32],
    pub ddhk_pub: [u8; 32],
    pub cert_dh: [u8; 64],
    pub spk_pub: [u8; 32],
    pub push_pk: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHeadV1 {
    pub tree_size: u64,
    pub smt_root: [u8; 32],
    pub history_root: [u8; 32],
    pub issued_at: u64,
    pub log_id: [u8; 32],
    pub signature: [u8; 64],
    pub sth_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessStatementV1 {
    pub witness_id: [u8; 16],
    pub log_id: [u8; 32],
    pub tree_size: u64,
    pub sth_digest: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntryV1 {
    pub sequence: u64,
    pub smt_key: [u8; 32],
    pub leaf_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationEvidenceV1 {
    pub sth_a: Vec<u8>,
    pub sth_b: Vec<u8>,
    pub witness_statements: Vec<Vec<u8>>,
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn expect_map(value: Value) -> Result<BTreeMap<u64, Value>, TransparencyV1Error> {
    let Value::Map(pairs) = value else {
        return Err(TransparencyV1Error::InvalidField);
    };
    let mut fields = BTreeMap::new();
    for (key, value) in pairs {
        let Value::Int(n) = key else {
            return Err(TransparencyV1Error::UnknownField);
        };
        if n < 0 || n > u64::MAX as i128 {
            return Err(TransparencyV1Error::UnknownField);
        }
        if fields.insert(n as u64, value).is_some() {
            return Err(TransparencyV1Error::Cbor(CborError::DuplicateMapKey));
        }
    }
    Ok(fields)
}

fn exact_fields(
    fields: &BTreeMap<u64, Value>,
    last: u64,
) -> Result<(), TransparencyV1Error> {
    if fields.keys().any(|key| *key == 0 || *key > last) {
        return Err(TransparencyV1Error::UnknownField);
    }
    if fields.len() != last as usize {
        return Err(TransparencyV1Error::MissingField);
    }
    Ok(())
}

fn take<const N: usize>(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<[u8; N], TransparencyV1Error> {
    let value = fields.remove(&key).ok_or(TransparencyV1Error::MissingField)?;
    let Value::Bytes(bytes) = value else {
        return Err(TransparencyV1Error::InvalidField);
    };
    bytes.try_into().map_err(|_| TransparencyV1Error::InvalidField)
}

fn take_uint(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<u64, TransparencyV1Error> {
    let value = fields.remove(&key).ok_or(TransparencyV1Error::MissingField)?;
    match value {
        Value::Int(n) if (0..=u64::MAX as i128).contains(&n) => Ok(n as u64),
        _ => Err(TransparencyV1Error::InvalidField),
    }
}

fn leaf_core_value(leaf: &TransparencyLeafV1) -> Value {
    Value::Map(vec![
        (Value::Int(1), Value::Bytes(leaf.account_id.to_vec())),
        (Value::Int(2), Value::Int(leaf.epoch as i128)),
        (Value::Int(3), Value::Bytes(leaf.device_id.to_vec())),
        (Value::Int(4), Value::Bytes(leaf.dsk_pub.to_vec())),
        (Value::Int(5), Value::Bytes(leaf.ddhk_pub.to_vec())),
        (Value::Int(6), Value::Bytes(leaf.cert_dh.to_vec())),
        (Value::Int(7), Value::Bytes(leaf.spk_pub.to_vec())),
        (Value::Int(8), Value::Bytes(leaf.push_pk.to_vec())),
    ])
}

fn leaf_core_bytes(leaf: &TransparencyLeafV1) -> Result<Vec<u8>, TransparencyV1Error> {
    Ok(cbor::encode_canonical(&leaf_core_value(leaf))?)
}

pub fn decode_leaf(bytes: &[u8]) -> Result<TransparencyLeafV1, TransparencyV1Error> {
    let value = cbor::decode_strict(bytes)?;
    let mut fields = expect_map(value)?;
    exact_fields(&fields, 9)?;
    let account_id = take::<16>(&mut fields, 1)?;
    let epoch = take_uint(&mut fields, 2)?;
    if epoch < 1 {
        return Err(TransparencyV1Error::InvalidField);
    }
    let device_id = take::<16>(&mut fields, 3)?;
    let dsk_pub = take::<32>(&mut fields, 4)?;
    let ddhk_pub = take::<32>(&mut fields, 5)?;
    let cert_dh = take::<64>(&mut fields, 6)?;
    let spk_pub = take::<32>(&mut fields, 7)?;
    let push_pk = take::<32>(&mut fields, 8)?;
    let signature = take::<64>(&mut fields, 9)?;
    if !fields.is_empty() {
        return Err(TransparencyV1Error::UnknownField);
    }
    Ok(TransparencyLeafV1 {
        account_id,
        epoch,
        device_id,
        dsk_pub,
        ddhk_pub,
        cert_dh,
        spk_pub,
        push_pk,
        signature,
    })
}

pub fn verify_leaf(bytes: &[u8]) -> Result<TransparencyLeafV1, TransparencyV1Error> {
    let leaf = decode_leaf(bytes)?;
    let public = VerifyingKey::from_bytes(&leaf.dsk_pub).map_err(|_| TransparencyV1Error::InvalidField)?;
    let signature = Signature::from_bytes(&leaf.signature);
    let core = leaf_core_bytes(&leaf)?;
    public
        .verify_strict(&[LEAF_SIGN_DOMAIN, &core].concat(), &signature)
        .map_err(|_| TransparencyV1Error::InvalidSignature)?;
    Ok(leaf)
}

pub fn leaf_hash(bytes: &[u8]) -> Result<[u8; 32], TransparencyV1Error> {
    verify_leaf(bytes)?;
    Ok(sha256(&[LEAF_HASH_DOMAIN, bytes]))
}

pub fn smt_key(account_id: &[u8; 16], device_id: &[u8; 16]) -> [u8; 32] {
    sha256(&[SMT_KEY_DOMAIN, account_id, device_id])
}

fn smt_leaf_node(leaf_hash_value: &[u8; 32]) -> [u8; 32] {
    sha256(&[SMT_LEAF_PREFIX, leaf_hash_value])
}

fn smt_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[SMT_NODE_PREFIX, left, right])
}

fn smt_bit(key: &[u8; 32], depth: usize) -> u8 {
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

fn smt_empty_hashes() -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(SMT_DEPTH + 1);
    out.push(sha256(&[SMT_LEAF_PREFIX]));
    for _ in 0..SMT_DEPTH {
        let prev = *out.last().expect("at least Empty[0]");
        out.push(smt_node(&prev, &prev));
    }
    out
}

fn smt_root_rec(items: &[( [u8; 32], [u8; 32])], depth: usize, empty: &[[u8; 32]]) -> [u8; 32] {
    if items.is_empty() {
        return empty[SMT_DEPTH - depth];
    }
    if depth == SMT_DEPTH {
        return smt_leaf_node(&items[0].1);
    }
    let mut split = 0usize;
    while split < items.len() && smt_bit(&items[split].0, depth) == 0 {
        split += 1;
    }
    smt_node(
        &smt_root_rec(&items[..split], depth + 1, empty),
        &smt_root_rec(&items[split..], depth + 1, empty),
    )
}

pub fn smt_root(entries: &[( [u8; 32], [u8; 32])]) -> Result<[u8; 32], TransparencyV1Error> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    if sorted.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(TransparencyV1Error::InvalidField);
    }
    Ok(smt_root_rec(&sorted, 0, &smt_empty_hashes()))
}

pub fn verify_smt_inclusion(
    target_key: &[u8; 32],
    target_leaf_hash: &[u8; 32],
    siblings_root_to_leaf: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), TransparencyV1Error> {
    if siblings_root_to_leaf.len() != SMT_DEPTH {
        return Err(TransparencyV1Error::InvalidProofLength);
    }
    let mut acc = smt_leaf_node(target_leaf_hash);
    for depth in (0..SMT_DEPTH).rev() {
        let sibling = &siblings_root_to_leaf[depth];
        acc = if smt_bit(target_key, depth) == 0 {
            smt_node(&acc, sibling)
        } else {
            smt_node(sibling, &acc)
        };
    }
    if &acc == expected_root {
        Ok(())
    } else {
        Err(TransparencyV1Error::SmtRootMismatch)
    }
}

pub fn decode_history_entry(bytes: &[u8]) -> Result<HistoryEntryV1, TransparencyV1Error> {
    let value = cbor::decode_strict(bytes)?;
    let mut fields = expect_map(value)?;
    exact_fields(&fields, 3)?;
    let sequence = take_uint(&mut fields, 1)?;
    if sequence < 1 {
        return Err(TransparencyV1Error::InvalidField);
    }
    let smt_key = take::<32>(&mut fields, 2)?;
    let leaf_hash = take::<32>(&mut fields, 3)?;
    Ok(HistoryEntryV1 { sequence, smt_key, leaf_hash })
}

fn rfc_leaf_hash(data: &[u8]) -> [u8; 32] {
    sha256(&[RFC_LEAF_PREFIX, data])
}

fn rfc_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[RFC_NODE_PREFIX, left, right])
}

fn largest_power_less_than(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let mut k = 1usize;
    while k < n {
        k <<= 1;
    }
    k >> 1
}

fn history_mth_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
    match hashes.len() {
        0 => sha256(&[b""]),
        1 => hashes[0],
        n => {
            let k = largest_power_less_than(n);
            let left = history_mth_hashes(&hashes[..k]);
            let right = history_mth_hashes(&hashes[k..]);
            rfc_node_hash(&left, &right)
        }
    }
}

pub fn history_root(entries: &[Vec<u8>]) -> [u8; 32] {
    if entries.is_empty() {
        return sha256(&[b""]);
    }
    let hashes: Vec<[u8; 32]> = entries.iter().map(|entry| rfc_leaf_hash(entry)).collect();
    history_mth_hashes(&hashes)
}

pub fn verify_history_inclusion(
    entry: &[u8],
    index: usize,
    tree_size: usize,
    proof: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), TransparencyV1Error> {
    if index >= tree_size || proof.iter().any(|p| p.len() != 32) {
        return Err(TransparencyV1Error::HistoryProofRejected);
    }
    let history_entry = decode_history_entry(entry)
        .map_err(|_| TransparencyV1Error::HistoryProofRejected)?;
    let expected_sequence = u64::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(TransparencyV1Error::HistoryProofRejected)?;
    if history_entry.sequence != expected_sequence {
        return Err(TransparencyV1Error::HistoryProofRejected);
    }
    let mut acc = rfc_leaf_hash(entry);
    let mut node = index;
    let mut last = tree_size.saturating_sub(1);
    let mut pi = 0usize;
    while last > 0 {
        let Some(sibling) = proof.get(pi) else {
            return Err(TransparencyV1Error::HistoryProofRejected);
        };
        if node % 2 == 1 || node == last {
            acc = rfc_node_hash(sibling, &acc);
        } else {
            acc = rfc_node_hash(&acc, sibling);
        }
        node /= 2;
        last /= 2;
        pi += 1;
    }
    if pi == proof.len() && &acc == expected_root {
        Ok(())
    } else {
        Err(TransparencyV1Error::HistoryProofRejected)
    }
}

pub fn verify_history_consistency(
    old_size: usize,
    new_size: usize,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> Result<(), TransparencyV1Error> {
    if old_size == new_size {
        return if old_root == new_root && proof.is_empty() {
            Ok(())
        } else {
            Err(TransparencyV1Error::HistoryConsistencyRejected)
        };
    }
    if old_size == 0 || old_size > new_size {
        return Err(TransparencyV1Error::HistoryConsistencyRejected);
    }

    let mut node = old_size - 1;
    let mut last_node = new_size - 1;
    while node % 2 == 1 {
        node /= 2;
        last_node /= 2;
    }

    let mut pi = 0usize;
    let mut next = || {
        let item = proof.get(pi);
        pi += 1;
        item
    };

    let (mut old_hash, mut new_hash) = if node != 0 {
        let Some(first) = next() else {
            return Err(TransparencyV1Error::HistoryConsistencyRejected);
        };
        (*first, *first)
    } else {
        (*old_root, *old_root)
    };

    while node != 0 {
        if node % 2 == 1 {
            let Some(sibling) = next() else {
                return Err(TransparencyV1Error::HistoryConsistencyRejected);
            };
            old_hash = rfc_node_hash(sibling, &old_hash);
            new_hash = rfc_node_hash(sibling, &new_hash);
        } else if node < last_node {
            let Some(sibling) = next() else {
                return Err(TransparencyV1Error::HistoryConsistencyRejected);
            };
            new_hash = rfc_node_hash(&new_hash, sibling);
        }
        node /= 2;
        last_node /= 2;
    }

    while last_node != 0 {
        let Some(sibling) = next() else {
            return Err(TransparencyV1Error::HistoryConsistencyRejected);
        };
        new_hash = rfc_node_hash(&new_hash, sibling);
        last_node /= 2;
    }

    if pi != proof.len() || &old_hash != old_root || &new_hash != new_root {
        return Err(TransparencyV1Error::HistoryConsistencyRejected);
    }
    Ok(())
}

fn sth_body_value(sth: &SignedTreeHeadV1) -> Value {
    Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Int(sth.tree_size as i128)),
        (Value::Int(3), Value::Bytes(sth.smt_root.to_vec())),
        (Value::Int(4), Value::Bytes(sth.history_root.to_vec())),
        (Value::Int(5), Value::Int(sth.issued_at as i128)),
        (Value::Int(6), Value::Bytes(sth.log_id.to_vec())),
    ])
}

pub fn verify_sth(bytes: &[u8], log_public: &[u8; 32]) -> Result<SignedTreeHeadV1, TransparencyV1Error> {
    let value = cbor::decode_strict(bytes)?;
    let mut fields = expect_map(value)?;
    exact_fields(&fields, 7)?;
    let version = take_uint(&mut fields, 1)?;
    let tree_size = take_uint(&mut fields, 2)?;
    let smt_root = take::<32>(&mut fields, 3)?;
    let history_root = take::<32>(&mut fields, 4)?;
    let issued_at = take_uint(&mut fields, 5)?;
    let log_id = take::<32>(&mut fields, 6)?;
    let signature = take::<64>(&mut fields, 7)?;
    if version != PROTOCOL_VERSION {
        return Err(TransparencyV1Error::InvalidField);
    }
    let public = VerifyingKey::from_bytes(log_public).map_err(|_| TransparencyV1Error::InvalidField)?;
    let sig = Signature::from_bytes(&signature);
    let body = SignedTreeHeadV1 {
        tree_size,
        smt_root,
        history_root,
        issued_at,
        log_id,
        signature,
        sth_digest: sha256(&[bytes]),
    };
    let body_bytes = cbor::encode_canonical(&sth_body_value(&body))?;
    public
        .verify_strict(&[STH_SIGN_DOMAIN, &body_bytes].concat(), &sig)
        .map_err(|_| TransparencyV1Error::InvalidSignature)?;
    Ok(body)
}

fn witness_body_value(statement: &WitnessStatementV1) -> Value {
    Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(statement.witness_id.to_vec())),
        (Value::Int(3), Value::Bytes(statement.log_id.to_vec())),
        (Value::Int(4), Value::Int(statement.tree_size as i128)),
        (Value::Int(5), Value::Bytes(statement.sth_digest.to_vec())),
    ])
}

pub fn verify_witness_statement(
    bytes: &[u8],
    registry: &BTreeMap<[u8; 16], [u8; 32]>,
) -> Result<WitnessStatementV1, TransparencyV1Error> {
    let value = cbor::decode_strict(bytes)?;
    let mut fields = expect_map(value)?;
    exact_fields(&fields, 6)?;
    let version = take_uint(&mut fields, 1)?;
    let witness_id = take::<16>(&mut fields, 2)?;
    let log_id = take::<32>(&mut fields, 3)?;
    let tree_size = take_uint(&mut fields, 4)?;
    let sth_digest = take::<32>(&mut fields, 5)?;
    let signature = take::<64>(&mut fields, 6)?;
    if version != PROTOCOL_VERSION {
        return Err(TransparencyV1Error::InvalidField);
    }
    let public = registry.get(&witness_id).ok_or(TransparencyV1Error::UnknownWitness)?;
    let sig = Signature::from_bytes(&signature);
    let statement = WitnessStatementV1 {
        witness_id,
        log_id,
        tree_size,
        sth_digest,
        signature,
    };
    let body = cbor::encode_canonical(&witness_body_value(&statement))?;
    let public = VerifyingKey::from_bytes(public).map_err(|_| TransparencyV1Error::InvalidField)?;
    public
        .verify_strict(&[WITNESS_SIGN_DOMAIN, &body].concat(), &sig)
        .map_err(|_| TransparencyV1Error::InvalidSignature)?;
    Ok(statement)
}

pub fn decode_equivocation_evidence(bytes: &[u8]) -> Result<EquivocationEvidenceV1, TransparencyV1Error> {
    let value = cbor::decode_strict(bytes)?;
    let mut fields = expect_map(value)?;
    if fields.keys().any(|key| *key == 0 || *key > 5) || !(fields.len() == 4 || fields.len() == 5) {
        return Err(TransparencyV1Error::UnknownField);
    }
    let version = take_uint(&mut fields, 1)?;
    if version != PROTOCOL_VERSION {
        return Err(TransparencyV1Error::InvalidField);
    }
    let domain = match fields.remove(&2).ok_or(TransparencyV1Error::MissingField)? {
        Value::Bytes(v) => v,
        _ => return Err(TransparencyV1Error::InvalidField),
    };
    if domain != EVIDENCE_DOMAIN {
        return Err(TransparencyV1Error::InvalidField);
    }
    let sth_a = match fields.remove(&3).ok_or(TransparencyV1Error::MissingField)? {
        Value::Bytes(v) => v,
        _ => return Err(TransparencyV1Error::InvalidField),
    };
    let sth_b = match fields.remove(&4).ok_or(TransparencyV1Error::MissingField)? {
        Value::Bytes(v) => v,
        _ => return Err(TransparencyV1Error::InvalidField),
    };
    let witness_statements = match fields.remove(&5) {
        None => Vec::new(),
        Some(Value::Array(items)) => items.into_iter().map(|item| match item {
            Value::Bytes(v) => Ok(v),
            _ => Err(TransparencyV1Error::InvalidField),
        }).collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(TransparencyV1Error::InvalidField),
    };
    if !fields.is_empty() {
        return Err(TransparencyV1Error::UnknownField);
    }
    Ok(EquivocationEvidenceV1 { sth_a, sth_b, witness_statements })
}

/// Return true when two valid STHs are a same-size equivocation for the same log.
pub fn is_sth_equivocation(a: &SignedTreeHeadV1, b: &SignedTreeHeadV1) -> bool {
    a.tree_size == b.tree_size && a.log_id == b.log_id && (a.smt_root != b.smt_root || a.history_root != b.history_root)
}

/// Return true when already-verified witness statements conflict for the same log and tree size.
pub fn witness_conflict_exists(statements: &[WitnessStatementV1]) -> bool {
    let mut seen = BTreeMap::<([u8; 32], u64), [u8; 32]>::new();
    for statement in statements {
        let key = (statement.log_id, statement.tree_size);
        if let Some(previous_digest) = seen.get(&key) {
            if previous_digest != &statement.sth_digest {
                return true;
            }
        } else {
            seen.insert(key, statement.sth_digest);
        }
    }
    false
}

/// Return the number of distinct witnesses agreeing with one STH digest.
pub fn witness_quorum_count(statements: &[WitnessStatementV1], sth: &SignedTreeHeadV1) -> usize {
    let mut ids = std::collections::BTreeSet::new();
    for statement in statements {
        if statement.log_id == sth.log_id && statement.tree_size == sth.tree_size && statement.sth_digest == sth.sth_digest {
            ids.insert(statement.witness_id);
        }
    }
    ids.len()
}
