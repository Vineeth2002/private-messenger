//! Tests for the shared normal post-handshake Double Ratchet vectors.
//!
//! This file is included as a child module of `normal_ratchet_linear`, so the
//! tests can inspect the private ratchet state while keeping the production
//! implementation unchanged.

use super::{
    decrypt_message, decrypt_new_ratchet_message_inner, encrypt_message, NormalMessageHeader,
};
use crate::double_ratchet::{
    kdf_ck, MessageEnvelopeRef, PrekeyHandshakeHeader, RatchetError, RatchetKey, RatchetState,
};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex_encode<T: AsRef<[u8]>>(b: T) -> String {
    b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex_decode(s).try_into().expect("wrong length")
}

fn load_normal() -> JsonValue {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/v1/normal_ratchet_linear.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("normal vector file"))
        .expect("valid normal vector JSON")
}

fn load_double() -> JsonValue {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/v1/double_ratchet_linear.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("double vector file"))
        .expect("valid double vector JSON")
}

fn load_x3dh() -> JsonValue {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/v1/bi_x3dh_handshake.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("x3dh vector file"))
        .expect("valid x3dh vector JSON")
}

fn test_key(name: &str) -> RatchetKey {
    let mut h = Sha256::new();
    h.update(b"PM-TEST-ONLY-KEY:");
    h.update(name.as_bytes());
    h.finalize().into()
}

fn state_snapshot(
    state: &RatchetState,
) -> (
    RatchetKey,
    RatchetKey,
    [u8; 32],
    Option<[u8; 32]>,
    Option<RatchetKey>,
    Option<RatchetKey>,
    u32,
    u32,
    u32,
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
    )
}

fn bob_after_message_zero() -> RatchetState {
    let v = load_double();
    let x = load_x3dh();
    let case = &x["cases"][0];

    let sk = arr::<32>(v["sk"].as_str().unwrap());
    let spk_priv = arr::<32>(case["inputs"]["spk_b_priv"].as_str().unwrap());
    let dhs_b1_priv = arr::<32>(v["bob"]["dhs_b1_priv"].as_str().unwrap());
    let msg = &v["message_0"];
    let f = &msg["prekey_handshake_header"]["fields"];

    let header = PrekeyHandshakeHeader {
        sender_account_id: arr::<16>(f["1_sender_account_id"].as_str().unwrap()),
        sender_account_epoch: f["2_sender_account_epoch"].as_u64().unwrap() as u32,
        sender_dsk_pub: arr::<32>(f["3_sender_dsk_pub"].as_str().unwrap()),
        sender_ddhk_pub: arr::<32>(f["4_sender_ddhk_pub"].as_str().unwrap()),
        sender_cert_dh: arr::<64>(f["5_sender_cert_dh"].as_str().unwrap()),
        sender_cert_dh_timestamp: f["6_sender_cert_dh_timestamp"].as_u64().unwrap(),
        sender_ephemeral_pub: arr::<32>(f["7_sender_ephemeral_pub"].as_str().unwrap()),
        recipient_spk_id: f["8_recipient_spk_id"].as_u64().unwrap() as u32,
        recipient_opk_id: Some(f["9_recipient_opk_id"].as_u64().unwrap() as u32),
        initial_ratchet_pub: arr::<32>(f["10_initial_ratchet_pub"].as_str().unwrap()),
        sequence_number: 0,
    };

    let header_bytes = header.encode().unwrap();
    let envelope_id = arr::<16>(msg["aad_inputs"]["envelope_id"].as_str().unwrap());
    let sender = arr::<16>(msg["aad_inputs"]["sender_device_id"].as_str().unwrap());
    let recipient = arr::<16>(msg["aad_inputs"]["recipient_device_id"].as_str().unwrap());
    let ciphertext = hex_decode(msg["ciphertext_with_tag_hex"].as_str().unwrap());

    let env = MessageEnvelopeRef {
        protocol_version: 1,
        envelope_id: &envelope_id,
        sender_device_id: &sender,
        recipient_device_id: &recipient,
        account_epoch: 3,
        is_prekey_handshake: true,
        ratchet_header_bytes: &header_bytes,
        ciphertext: &ciphertext,
    };

    let mut bob = RatchetState::init_bob(&sk, spk_priv);
    super::super::ingest_message_0_inner(&mut bob, env, 7, Some(42), dhs_b1_priv)
        .expect("frozen Message 0 ingestion");
    bob
}

fn alice_post_message_zero() -> RatchetState {
    let v = load_double();
    let x = load_x3dh();
    let case = &x["cases"][0];

    let sk = arr::<32>(v["sk"].as_str().unwrap());
    let spk_pub = arr::<32>(case["inputs"]["spk_b_pub"].as_str().unwrap());
    let a0_priv = arr::<32>(v["alice"]["dhs_a0_priv"].as_str().unwrap());

    let mut alice = RatchetState::init_alice(&sk, &spk_pub, a0_priv).unwrap();
    alice.rk = Zeroizing::new(arr::<32>(v["alice"]["rk_a"].as_str().unwrap()));
    alice.ck_s = Some(Zeroizing::new(
        arr::<32>(v["alice"]["ck_s_after_msg0"].as_str().unwrap()),
    ));
    alice.ns = v["alice"]["ns_after"].as_u64().unwrap() as u32;
    alice
}

fn vector_header(message: &JsonValue) -> NormalMessageHeader {
    let h = &message["header"];
    NormalMessageHeader {
        ratchet_public: arr::<32>(h["ratchet_public"].as_str().unwrap()),
        previous_chain_length: h["previous_chain_length"].as_u64().unwrap() as u32,
        sequence_number: h["sequence_number"].as_u64().unwrap() as u32,
    }
}

fn vector_envelope<'a>(
    message: &'a JsonValue,
    header_bytes: &'a [u8],
    ciphertext: &'a [u8],
    alice_device: &'a [u8; 16],
    bob_device: &'a [u8; 16],
) -> MessageEnvelopeRef<'a> {
    let e = &message["envelope"];
    let envelope_id = arr::<16>(e["envelope_id"].as_str().unwrap());
    let sender = arr::<16>(e["sender_device_id"].as_str().unwrap());
    let recipient = arr::<16>(e["recipient_device_id"].as_str().unwrap());

    // The returned envelope owns references to locals only if we return the
    // arrays, so the test keeps the concrete values outside this helper.
    let _ = (alice_device, bob_device);
    MessageEnvelopeRef {
        protocol_version: e["protocol_version"].as_u64().unwrap() as u8,
        envelope_id: Box::leak(Box::new(envelope_id)),
        sender_device_id: Box::leak(Box::new(sender)),
        recipient_device_id: Box::leak(Box::new(recipient)),
        account_epoch: e["account_epoch"].as_u64().unwrap() as u32,
        is_prekey_handshake: e["prekey_flag"].as_u64().unwrap() != 0,
        ratchet_header_bytes: header_bytes,
        ciphertext,
    }
}

fn aad_for_vector(message: &JsonValue, header_bytes: &[u8]) -> Vec<u8> {
    let e = &message["envelope"];
    let envelope_id = arr::<16>(e["envelope_id"].as_str().unwrap());
    let sender = arr::<16>(e["sender_device_id"].as_str().unwrap());
    let recipient = arr::<16>(e["recipient_device_id"].as_str().unwrap());

    super::super::aad_msg(
        e["protocol_version"].as_u64().unwrap() as u8,
        &envelope_id,
        &sender,
        &recipient,
        e["account_epoch"].as_u64().unwrap() as u32,
        e["prekey_flag"].as_u64().unwrap() != 0,
        header_bytes,
    )
}

#[test]
fn normal_vector_suite_is_active_and_has_three_messages() {
    let v = load_normal();
    assert_eq!(v["suite"], "PM-DR-NORMAL-LINEAR");
    assert_eq!(v["status"], "ACTIVE");
    assert_eq!(v["messages"].as_array().unwrap().len(), 3);
    assert_eq!(v["protocol"]["nonce_hex"], "000000000000000000000000");
    assert_eq!(v["protocol"]["prekey_flag"], 0);
}

#[test]
fn normal_vector_headers_and_ciphertexts_match_rust() {
    let v = load_normal();
    let alice_device = arr::<16>("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let bob_device = arr::<16>("303132333435363738393a3b3c3d3e3f");

    for message in v["messages"].as_array().unwrap() {
        let header = vector_header(message);
        let header_bytes = header.encode().unwrap();
        assert_eq!(
            hex_encode(&header_bytes),
            message["derived"]["ratchet_header_hex"]
        );
        let decoded = NormalMessageHeader::decode(&header_bytes).unwrap();
        assert_eq!(decoded, header);

        let aad = aad_for_vector(message, &header_bytes);
        assert_eq!(hex_encode(&aad), message["derived"]["aad_hex"]);

        let ciphertext = hex_decode(
            message["derived"]["ciphertext_with_tag_hex"]
                .as_str()
                .unwrap(),
        );
        let envelope = vector_envelope(
            message,
            &header_bytes,
            &ciphertext,
            &alice_device,
            &bob_device,
        );
        assert!(!envelope.is_prekey_handshake);
    }
}

#[test]
fn normal_vector_bidirectional_ratchet_path_matches() {
    let v = load_normal();
    let messages = v["messages"].as_array().unwrap();
    let bob_reply = &messages[0];
    let bob_follow = &messages[1];
    let alice_reply = &messages[2];

    let alice_device = arr::<16>("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let bob_device = arr::<16>("303132333435363738393a3b3c3d3e3f");

    let mut bob = bob_after_message_zero();

    // Bob -> Alice, new ratchet.
    let bob_reply_header = vector_header(bob_reply);
    let bob_reply_header_bytes = bob_reply_header.encode().unwrap();
    let bob_reply_id = arr::<16>(
        bob_reply["envelope"]["envelope_id"]
            .as_str()
            .unwrap(),
    );
    let bob_reply_ct =
        hex_decode(bob_reply["derived"]["ciphertext_with_tag_hex"].as_str().unwrap());

    let (_, encrypted) = encrypt_message(
        &mut bob,
        normal_env_from_parts(
            &bob_reply_id,
            &bob_device,
            &alice_device,
            bob_reply["envelope"]["account_epoch"]
                .as_u64()
                .unwrap() as u32,
            &bob_reply_header_bytes,
            &[],
        ),
        &bob_reply_header,
        &hex_decode(bob_reply["plaintext_hex"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(encrypted, bob_reply_ct);
    assert_eq!(hex_encode(bob.ck_s.as_ref().unwrap()), bob_reply["derived"]["ck_sender_after_hex"]);

    // Bob's second message is same-ratchet N=1.
    let bob_follow_header = vector_header(bob_follow);
    let bob_follow_header_bytes = bob_follow_header.encode().unwrap();
    let bob_follow_id = arr::<16>(
        bob_follow["envelope"]["envelope_id"]
            .as_str()
            .unwrap(),
    );
    let bob_follow_ct =
        hex_decode(bob_follow["derived"]["ciphertext_with_tag_hex"].as_str().unwrap());
    let (_, encrypted_follow) = encrypt_message(
        &mut bob,
        normal_env_from_parts(
            &bob_follow_id,
            &bob_device,
            &alice_device,
            bob_follow["envelope"]["account_epoch"].as_u64().unwrap() as u32,
            &bob_follow_header_bytes,
            &[],
        ),
        &bob_follow_header,
        &hex_decode(bob_follow["plaintext_hex"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(encrypted_follow, bob_follow_ct);

    // Alice receives Bob's first normal message with deterministic test key.
    let mut alice = alice_post_message_zero();
    let alice_before = state_snapshot(&alice);
    let plaintext = decrypt_new_ratchet_message_inner(
        &mut alice,
        normal_env_from_parts(
            &bob_reply_id,
            &bob_device,
            &alice_device,
            1,
            &bob_reply_header_bytes,
            &bob_reply_ct,
        ),
        test_key("dhs_a1"),
    )
    .unwrap();
    assert_eq!(
        hex_encode(&alice_before.0),
        v["initial_states"]["alice_post_message_0"]["rk"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        hex_encode(&alice.rk),
        bob_reply["receiver_transition"]["rk_final_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(hex_encode(alice.dhs_pub), bob_reply["receiver_transition"]["new_local_dhs_pub_hex"]);
    assert_eq!(alice.pn, 1);
    assert_eq!(alice.ns, 0);
    assert_eq!(alice.nr, 1);
    assert_eq!(plaintext, hex_decode(bob_reply["plaintext_hex"].as_str().unwrap()));

    // Same-ratchet follow-up.
    let plaintext_follow = decrypt_message(
        &mut alice,
        normal_env_from_parts(
            &bob_follow_id,
            &bob_device,
            &alice_device,
            1,
            &bob_follow_header_bytes,
            &bob_follow_ct,
        ),
    )
    .unwrap();
    assert_eq!(
        plaintext_follow,
        hex_decode(bob_follow["plaintext_hex"].as_str().unwrap())
    );
    assert_eq!(alice.nr, 2);

    // Alice -> Bob, new ratchet.
    let alice_reply_header = vector_header(alice_reply);
    let alice_reply_header_bytes = alice_reply_header.encode().unwrap();
    let alice_reply_id = arr::<16>(
        alice_reply["envelope"]["envelope_id"]
            .as_str()
            .unwrap(),
    );
    let alice_reply_ct =
        hex_decode(alice_reply["derived"]["ciphertext_with_tag_hex"].as_str().unwrap());

    let (_, encrypted_reply) = encrypt_message(
        &mut alice,
        normal_env_from_parts(
            &alice_reply_id,
            &alice_device,
            &bob_device,
            3,
            &alice_reply_header_bytes,
            &[],
        ),
        &alice_reply_header,
        &hex_decode(alice_reply["plaintext_hex"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(encrypted_reply, alice_reply_ct);
    assert_eq!(
        hex_encode(alice.ck_s.as_ref().unwrap()),
        alice_reply["derived"]["ck_sender_after_hex"]
            .as_str()
            .unwrap()
    );

    // Bob receives Alice's new ratchet.
    let plaintext_reply = decrypt_new_ratchet_message_inner(
        &mut bob,
        normal_env_from_parts(
            &alice_reply_id,
            &alice_device,
            &bob_device,
            3,
            &alice_reply_header_bytes,
            &alice_reply_ct,
        ),
        test_key("dhs_b2"),
    )
    .unwrap();
    assert_eq!(
        plaintext_reply,
        hex_decode(alice_reply["plaintext_hex"].as_str().unwrap())
    );
    assert_eq!(
        hex_encode(&bob.rk),
        alice_reply["receiver_transition"]["rk_final_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        hex_encode(bob.dhs_pub),
        alice_reply["receiver_transition"]["new_local_dhs_pub_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(bob.pn, 2);
    assert_eq!(bob.ns, 0);
    assert_eq!(bob.nr, 1);
}

#[test]
fn normal_vector_negative_cases_are_enforced_atomically() {
    let v = load_normal();
    let messages = v["messages"].as_array().unwrap();
    let bob_reply = &messages[0];
    let bob_follow = &messages[1];

    let alice_device = arr::<16>("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let bob_device = arr::<16>("303132333435363738393a3b3c3d3e3f");

    // Negative 1: authenticated ciphertext mutation must not change state.
    let header = vector_header(bob_reply);
    let header_bytes = header.encode().unwrap();
    let id = arr::<16>(bob_reply["envelope"]["envelope_id"].as_str().unwrap());
    let mut ciphertext =
        hex_decode(bob_reply["derived"]["ciphertext_with_tag_hex"].as_str().unwrap());
    *ciphertext.last_mut().unwrap() ^= 1;

    let mut alice = alice_post_message_zero();
    let before = state_snapshot(&alice);
    let err = decrypt_new_ratchet_message_inner(
        &mut alice,
        normal_env_from_parts(&id, &bob_device, &alice_device, 1, &header_bytes, &ciphertext),
        test_key("dhs_a1"),
    )
    .unwrap_err();
    assert_eq!(err, RatchetError::AeadAuthFailure);
    assert_eq!(state_snapshot(&alice), before);

    // Negative 2: skipped sequence is rejected before KDF/AEAD state advance.
    let follow_header = vector_header(bob_follow);
    let mut bad_header = follow_header.clone();
    bad_header.sequence_number = 2;
    let bad_header_bytes = bad_header.encode().unwrap();
    let follow_id = arr::<16>(bob_follow["envelope"]["envelope_id"].as_str().unwrap());
    let follow_ct =
        hex_decode(bob_follow["derived"]["ciphertext_with_tag_hex"].as_str().unwrap());

    // Advance to Nr=0 for the current Bob->Alice sending ratchet by putting
    // Alice on the corresponding post-new-ratchet receiving state first.
    let mut alice_state = alice_post_message_zero();
    decrypt_new_ratchet_message_inner(
        &mut alice_state,
        normal_env_from_parts(
            &id,
            &bob_device,
            &alice_device,
            1,
            &header_bytes,
            &hex_decode(bob_reply["derived"]["ciphertext_with_tag_hex"].as_str().unwrap()),
        ),
        test_key("dhs_a1"),
    )
    .unwrap();

    // Bob's state is unrelated to this negative receive check; the
    // receiver is Alice and should have Nr=1 here.
    let before_alice = state_snapshot(&alice_state);
    let err = decrypt_message(
        &mut alice_state,
        normal_env_from_parts(
            &follow_id,
            &bob_device,
            &alice_device,
            1,
            &bad_header_bytes,
            &follow_ct,
        ),
    )
    .unwrap_err();
    assert_eq!(err, RatchetError::InvalidInitialState);
    assert_eq!(state_snapshot(&alice_state), before_alice);

}

fn normal_env_from_parts<'a>(
    envelope_id: &'a [u8; 16],
    sender: &'a [u8; 16],
    recipient: &'a [u8; 16],
    epoch: u32,
    header_bytes: &'a [u8],
    ciphertext: &'a [u8],
) -> MessageEnvelopeRef<'a> {
    MessageEnvelopeRef {
        protocol_version: 1,
        envelope_id,
        sender_device_id: sender,
        recipient_device_id: recipient,
        account_epoch: epoch,
        is_prekey_handshake: false,
        ratchet_header_bytes: header_bytes,
        ciphertext,
    }
}

#[test]
fn normal_vector_kdf_ck_values_match_rust() {
    let v = load_normal();

    for message in v["messages"].as_array().unwrap() {
        let k_msg = arr::<32>(message["derived"]["k_msg_hex"].as_str().unwrap());

        // Recover the sender chain key indirectly from the public fixture:
        // the first message's receiver-side CK is enough to reproduce K_msg.
        if message["id"] == "bob_reply_new_ratchet" {
            let ck_r_before = arr::<32>(
                message["receiver_transition"]["ck_r_before_decrypt_hex"]
                    .as_str()
                    .unwrap(),
            );
            let (_, expected_k_msg) = kdf_ck(&ck_r_before);
            assert_eq!(expected_k_msg.as_ref(), &k_msg);
        }
    }
}
