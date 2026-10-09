//! Step 3 shared vector tests for reorder, delayed old-chain delivery and replay rejection.

use super::*;
use crate::double_ratchet::{MessageEnvelopeRef, RatchetError, RatchetKey, RatchetState};
use serde_json::Value as J;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn load() -> J {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/double_ratchet_reorder.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("reorder vector file")).expect("valid JSON")
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex_decode(s).try_into().expect("wrong length")
}

fn hex_encode<T: AsRef<[u8]>>(b: T) -> String {
    b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn state_from(v: &J, name: &str) -> RatchetState {
    let s = &v["scenario"][name];
    RatchetState {
        rk: Zeroizing::new(arr::<32>(s["rk"].as_str().unwrap())),
        dhs_priv: Zeroizing::new(arr::<32>(s["dhs_priv"].as_str().unwrap())),
        dhs_pub: arr::<32>(s["dhs_pub"].as_str().unwrap()),
        dhr_pub: s["dhr_pub"].as_str().map(arr::<32>),
        ck_s: s["ck_s"].as_str().map(|x| Zeroizing::new(arr::<32>(x))),
        ck_r: s["ck_r"].as_str().map(|x| Zeroizing::new(arr::<32>(x))),
        ns: s["ns"].as_u64().unwrap() as u32,
        nr: s["nr"].as_u64().unwrap() as u32,
        pn: s["pn"].as_u64().unwrap() as u32,
        skipped_keys: BTreeMap::new(),
    }
}

struct EnvelopeIds {
    envelope_id: [u8; 16],
    sender_device_id: [u8; 16],
    recipient_device_id: [u8; 16],
}

fn ids(msg: &J) -> EnvelopeIds {
    EnvelopeIds {
        envelope_id: arr::<16>(msg["envelope_id"].as_str().unwrap()),
        sender_device_id: arr::<16>(msg["sender_device_id"].as_str().unwrap()),
        recipient_device_id: arr::<16>(msg["recipient_device_id"].as_str().unwrap()),
    }
}

fn env<'a>(ids: &'a EnvelopeIds, header: &'a [u8], ciphertext: &'a [u8]) -> MessageEnvelopeRef<'a> {
    MessageEnvelopeRef {
        protocol_version: 1,
        envelope_id: &ids.envelope_id,
        sender_device_id: &ids.sender_device_id,
        recipient_device_id: &ids.recipient_device_id,
        account_epoch: 1,
        is_prekey_handshake: false,
        ratchet_header_bytes: header,
        ciphertext,
    }
}

fn message(v: &J, id: &str) -> J {
    v["scenario"]["messages"].as_array().unwrap().iter().find(|m| m["id"] == id).unwrap().clone()
}

fn state_snapshot(state: &RatchetState) -> (
    RatchetKey,
    RatchetKey,
    [u8; 32],
    Option<[u8; 32]>,
    Option<RatchetKey>,
    Option<RatchetKey>,
    u32,
    u32,
    u32,
    Vec<([u8; 32], u32, RatchetKey)>,
) {
    (
        *state.rk,
        *state.dhs_priv,
        state.dhs_pub,
        state.dhr_pub,
        state.ck_s.as_ref().map(|v| **v),
        state.ck_r.as_ref().map(|v| **v),
        state.ns,
        state.nr,
        state.pn,
        state.skipped_keys.iter().map(|(id, key)| (id.ratchet_public, id.sequence_number, **key)).collect(),
    )
}

fn assert_frozen_state(state: &RatchetState, expected: &J) {
    assert_eq!(hex_encode(&state.rk), expected["rk"]);
    assert_eq!(hex_encode(&state.dhs_priv), expected["dhs_priv"]);
    assert_eq!(hex_encode(state.dhs_pub), expected["dhs_pub"]);
    assert_eq!(state.dhr_pub.map(|v| hex_encode(v)), expected["dhr_pub"].as_str().map(str::to_owned));
    assert_eq!(state.ck_s.as_ref().map(|v| hex_encode(**v)), expected["ck_s"].as_str().map(str::to_owned));
    assert_eq!(state.ck_r.as_ref().map(|v| hex_encode(**v)), expected["ck_r"].as_str().map(str::to_owned));
    assert_eq!(state.ns, expected["ns"].as_u64().unwrap() as u32);
    assert_eq!(state.nr, expected["nr"].as_u64().unwrap() as u32);
    assert_eq!(state.pn, expected["pn"].as_u64().unwrap() as u32);
    let mut got: Vec<(String, u32)> = state.skipped_keys.iter().map(|(id, _)| (hex_encode(id.ratchet_public), id.sequence_number)).collect();
    got.sort();
    let mut want: Vec<(String, u32)> = expected["skipped_keys"].as_array().unwrap().iter().map(|x| (x["ratchet_public"].as_str().unwrap().to_owned(), x["sequence_number"].as_u64().unwrap() as u32)).collect();
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn reorder_vector_matches_sender_and_receive_state_machine() {
    let v = load();
    let old = message(&v, "old_delayed");
    let new0 = message(&v, "new_ratchet_0");
    let new1 = message(&v, "new_ratchet_1");

    let mut old_sender = state_from(&v, "old_sender");
    let old_ids = ids(&old);
    let old_header = NormalMessageHeader::decode(&hex_decode(old["ratchet_header_hex"].as_str().unwrap())).unwrap();
    let old_header_bytes = old_header.encode().unwrap();
    let old_pt = hex_decode(old["plaintext_hex"].as_str().unwrap());
    let old_env = env(&old_ids, &old_header_bytes, &[]);
    let (_, old_ct) = encrypt_message(&mut old_sender, old_env, &old_header, &old_pt).unwrap();
    assert_eq!(hex_encode(&old_ct), old["ciphertext_with_tag_hex"]);

    let mut new_sender = state_from(&v, "new_sender");
    let n0_ids = ids(&new0);
    let n0_header = NormalMessageHeader::decode(&hex_decode(new0["ratchet_header_hex"].as_str().unwrap())).unwrap();
    let n0_header_bytes = n0_header.encode().unwrap();
    let n0_pt = hex_decode(new0["plaintext_hex"].as_str().unwrap());
    let n0_env = env(&n0_ids, &n0_header_bytes, &[]);
    let (_, n0_ct) = encrypt_message(&mut new_sender, n0_env, &n0_header, &n0_pt).unwrap();
    assert_eq!(hex_encode(&n0_ct), new0["ciphertext_with_tag_hex"]);

    let n1_ids = ids(&new1);
    let n1_header = NormalMessageHeader::decode(&hex_decode(new1["ratchet_header_hex"].as_str().unwrap())).unwrap();
    let n1_header_bytes = n1_header.encode().unwrap();
    let n1_pt = hex_decode(new1["plaintext_hex"].as_str().unwrap());
    let n1_env = env(&n1_ids, &n1_header_bytes, &[]);
    let (_, n1_ct) = encrypt_message(&mut new_sender, n1_env, &n1_header, &n1_pt).unwrap();
    assert_eq!(hex_encode(&n1_ct), new1["ciphertext_with_tag_hex"]);

    let mut alice = state_from(&v, "initial_receiver");
    let a2_priv = arr::<32>(v["scenario"]["new_ratchet_receiver_dhs_priv_hex"].as_str().unwrap());

    let n1_env = env(&n1_ids, &n1_header_bytes, &n1_ct);
    let plaintext = decrypt_new_ratchet_message_inner(&mut alice, n1_env, a2_priv).unwrap();
    assert_eq!(plaintext, n1_pt);
    assert_frozen_state(&alice, &v["scenario"]["expected_after_new_ratchet_1"]);

    let old_env = env(&old_ids, &old_header_bytes, &old_ct);
    assert_eq!(decrypt_message(&mut alice, old_env).unwrap(), old_pt);
    assert_frozen_state(&alice, &v["scenario"]["expected_after_old_delayed"]);

    let n0_env = env(&n0_ids, &n0_header_bytes, &n0_ct);
    assert_eq!(decrypt_message(&mut alice, n0_env).unwrap(), n0_pt);
    assert_frozen_state(&alice, &v["scenario"]["expected_after_new_ratchet_0"]);

    let before_replay = state_snapshot(&alice);
    let replay_env = env(&n1_ids, &n1_header_bytes, &n1_ct);
    assert_eq!(decrypt_message(&mut alice, replay_env).unwrap_err(), RatchetError::ReplayDetected);
    assert_eq!(state_snapshot(&alice), before_replay);
}

#[test]
fn reorder_vector_tampered_new_ratchet_is_atomic() {
    let v = load();
    let new1 = message(&v, "new_ratchet_1");
    let new1_ids = ids(&new1);
    let header = hex_decode(new1["ratchet_header_hex"].as_str().unwrap());
    let mut ciphertext = hex_decode(new1["ciphertext_with_tag_hex"].as_str().unwrap());
    *ciphertext.last_mut().unwrap() ^= 1;

    let mut alice = state_from(&v, "initial_receiver");
    let before = state_snapshot(&alice);
    let a2_priv = arr::<32>(v["scenario"]["new_ratchet_receiver_dhs_priv_hex"].as_str().unwrap());
    let env = env(&new1_ids, &header, &ciphertext);
    assert_eq!(
        decrypt_new_ratchet_message_inner(&mut alice, env, a2_priv).unwrap_err(),
        RatchetError::AeadAuthFailure
    );
    assert_eq!(state_snapshot(&alice), before);
}
