//! Step 2 unit tests for skipped-message keys and the complete in-memory ratchet receive state machine.

use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex_decode(s).try_into().expect("wrong length")
}

fn test_key(label: &str) -> RatchetKey {
    let mut h = Sha256::new();
    h.update(b"PM-TEST-ONLY-KEY:");
    h.update(label.as_bytes());
    h.finalize().into()
}

fn pair_states() -> (RatchetState, RatchetState) {
    let root = test_key("root");
    let chain = test_key("chain");
    let bob_priv = test_key("bob-dhs");
    let alice_priv = test_key("alice-dhs");
    let bob_dhs = StaticSecret::from(bob_priv);
    let alice_dhs = StaticSecret::from(alice_priv);
    let bob_pub = PublicKey::from(&bob_dhs).to_bytes();
    let alice_pub = PublicKey::from(&alice_dhs).to_bytes();

    let bob = RatchetState {
        rk: Zeroizing::new(root),
        dhs_priv: Zeroizing::new(bob_priv),
        dhs_pub: bob_pub,
        dhr_pub: Some(alice_pub),
        ck_s: Some(Zeroizing::new(chain)),
        ck_r: None,
        ns: 0,
        nr: 0,
        pn: 0,
        skipped_keys: BTreeMap::new(),
    };
    let alice = RatchetState {
        rk: Zeroizing::new(root),
        dhs_priv: Zeroizing::new(alice_priv),
        dhs_pub: alice_pub,
        dhr_pub: Some(bob_pub),
        ck_s: None,
        ck_r: Some(Zeroizing::new(chain)),
        ns: 0,
        nr: 0,
        pn: 0,
        skipped_keys: BTreeMap::new(),
    };
    (bob, alice)
}

fn env<'a>(
    id: &'a [u8; 16],
    sender: &'a [u8; 16],
    recipient: &'a [u8; 16],
    epoch: u32,
    header: &'a [u8],
    ciphertext: &'a [u8],
) -> MessageEnvelopeRef<'a> {
    MessageEnvelopeRef {
        protocol_version: 1,
        envelope_id: id,
        sender_device_id: sender,
        recipient_device_id: recipient,
        account_epoch: epoch,
        is_prekey_handshake: false,
        ratchet_header_bytes: header,
        ciphertext,
    }
}

fn send_message(
    state: &mut RatchetState,
    id: &[u8; 16],
    sender: &[u8; 16],
    recipient: &[u8; 16],
    plaintext: &[u8],
) -> (NormalMessageHeader, Vec<u8>, Vec<u8>) {
    let header = NormalMessageHeader {
        ratchet_public: state.dhs_pub,
        previous_chain_length: state.pn,
        sequence_number: state.ns,
    };
    let header_bytes = header.encode().unwrap();
    let (_, ciphertext) = encrypt_message(
        state,
        env(id, sender, recipient, 1, &header_bytes, &[]),
        &header,
        plaintext,
    )
    .unwrap();
    (header, header_bytes, ciphertext)
}

fn snapshot(state: &RatchetState) -> (
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
        state
            .skipped_keys
            .iter()
            .map(|(id, key)| (id.ratchet_public, id.sequence_number, **key))
            .collect(),
    )
}

#[test]
fn same_chain_out_of_order_messages_use_one_time_skipped_keys() {
    let (mut bob, mut alice) = pair_states();
    let alice_device = arr::<16>("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let bob_device = arr::<16>("303132333435363738393a3b3c3d3e3f");
    let ids = [
        arr::<16>("202122232425262728292a2b2c2d2e2f"),
        arr::<16>("404142434445464748494a4b4c4d4e4f"),
        arr::<16>("606162636465666768696a6b6c6d6e6f"),
    ];

    let first = send_message(&mut bob, &ids[0], &bob_device, &alice_device, b"message-0");
    let second = send_message(&mut bob, &ids[1], &bob_device, &alice_device, b"message-1");
    let third = send_message(&mut bob, &ids[2], &bob_device, &alice_device, b"message-2");

    assert_eq!(
        decrypt_message(&mut alice, env(&ids[2], &bob_device, &alice_device, 1, &third.1, &third.2)).unwrap(),
        b"message-2"
    );
    assert_eq!(alice.nr, 3);
    assert_eq!(alice.skipped_keys.len(), 2);
    assert_eq!(
        decrypt_message(&mut alice, env(&ids[0], &bob_device, &alice_device, 1, &first.1, &first.2)).unwrap(),
        b"message-0"
    );
    assert_eq!(alice.skipped_keys.len(), 1);
    assert_eq!(
        decrypt_message(&mut alice, env(&ids[1], &bob_device, &alice_device, 1, &second.1, &second.2)).unwrap(),
        b"message-1"
    );
    assert!(alice.skipped_keys.is_empty());

    let before = snapshot(&alice);
    let err = decrypt_message(
        &mut alice,
        env(&ids[0], &bob_device, &alice_device, 1, &first.1, &first.2),
    )
    .unwrap_err();
    assert_eq!(err, RatchetError::ReplayDetected);
    assert_eq!(snapshot(&alice), before);
}

#[test]
fn new_ratchet_retains_old_and_new_chain_skipped_keys() {
    let (mut bob, mut alice) = pair_states();
    let alice_device = arr::<16>("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let bob_device = arr::<16>("303132333435363738393a3b3c3d3e3f");
    let old0_id = arr::<16>("202122232425262728292a2b2c2d2e2f");
    let old1_id = arr::<16>("404142434445464748494a4b4c4d4e4f");
    let new0_id = arr::<16>("606162636465666768696a6b6c6d6e6f");
    let new1_id = arr::<16>("808182838485868788898a8b8c8d8e8f");

    let old0 = send_message(&mut bob, &old0_id, &bob_device, &alice_device, b"old-0");
    let old1 = send_message(&mut bob, &old1_id, &bob_device, &alice_device, b"old-1");

    let new_priv = test_key("bob-dhs-b2");
    let new_dhs = StaticSecret::from(new_priv);
    let peer = PublicKey::from(bob.dhr_pub.unwrap());
    let shared = new_dhs.diffie_hellman(&peer);
    assert!(shared.was_contributory());
    let (rk_next, ck_s_next) = kdf_rk(&bob.rk, shared.as_bytes());
    bob.rk = rk_next;
    bob.dhs_priv = Zeroizing::new(new_priv);
    bob.dhs_pub = PublicKey::from(&new_dhs).to_bytes();
    bob.pn = bob.ns;
    bob.ns = 0;
    bob.ck_s = Some(ck_s_next);

    let new0 = send_message(&mut bob, &new0_id, &bob_device, &alice_device, b"new-0");
    let new1 = send_message(&mut bob, &new1_id, &bob_device, &alice_device, b"new-1");

    assert_eq!(
        decrypt_message(&mut alice, env(&new1_id, &bob_device, &alice_device, 1, &new1.1, &new1.2)).unwrap(),
        b"new-1"
    );
    assert_eq!(alice.skipped_keys.len(), 3);
    assert_eq!(
        decrypt_message(&mut alice, env(&old0_id, &bob_device, &alice_device, 1, &old0.1, &old0.2)).unwrap(),
        b"old-0"
    );
    assert_eq!(
        decrypt_message(&mut alice, env(&old1_id, &bob_device, &alice_device, 1, &old1.1, &old1.2)).unwrap(),
        b"old-1"
    );
    assert_eq!(
        decrypt_message(&mut alice, env(&new0_id, &bob_device, &alice_device, 1, &new0.1, &new0.2)).unwrap(),
        b"new-0"
    );
    assert!(alice.skipped_keys.is_empty());

    let before = snapshot(&alice);
    let err = decrypt_message(
        &mut alice,
        env(&new1_id, &bob_device, &alice_device, 1, &new1.1, &new1.2),
    )
    .unwrap_err();
    assert_eq!(err, RatchetError::ReplayDetected);
    assert_eq!(snapshot(&alice), before);
}

#[test]
fn new_ratchet_auth_failure_does_not_commit_skipped_keys_or_ratchet_state() {
    let (mut bob, mut alice) = pair_states();
    let alice_device = arr::<16>("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let bob_device = arr::<16>("303132333435363738393a3b3c3d3e3f");
    let new_priv = test_key("bob-dhs-b2-auth");
    let new_dhs = StaticSecret::from(new_priv);
    let peer = PublicKey::from(bob.dhr_pub.unwrap());
    let shared = new_dhs.diffie_hellman(&peer);
    let (rk_next, ck_s_next) = kdf_rk(&bob.rk, shared.as_bytes());
    bob.rk = rk_next;
    bob.dhs_priv = Zeroizing::new(new_priv);
    bob.dhs_pub = PublicKey::from(&new_dhs).to_bytes();
    bob.pn = bob.ns;
    bob.ns = 0;
    bob.ck_s = Some(ck_s_next);

    let new_id = arr::<16>("606162636465666768696a6b6c6d6e6f");
    let new_message = send_message(&mut bob, &new_id, &bob_device, &alice_device, b"new");
    let mut bad_ciphertext = new_message.2.clone();
    bad_ciphertext[0] ^= 1;

    let before = snapshot(&alice);
    let err = decrypt_new_ratchet_message_inner(
        &mut alice,
        env(&new_id, &bob_device, &alice_device, 1, &new_message.1, &bad_ciphertext),
        test_key("alice-dhs-next"),
    )
    .unwrap_err();
    assert_eq!(err, RatchetError::AeadAuthFailure);
    assert_eq!(snapshot(&alice), before);
}

#[test]
fn max_skip_is_enforced_before_key_derivation_and_is_atomic() {
    let (_bob, mut alice) = pair_states();
    let alice_device = arr::<16>("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let bob_device = arr::<16>("303132333435363738393a3b3c3d3e3f");
    let id = arr::<16>("202122232425262728292a2b2c2d2e2f");
    let header = NormalMessageHeader {
        ratchet_public: alice.dhr_pub.unwrap(),
        previous_chain_length: 0,
        sequence_number: MAX_SKIP + 1,
    };
    let header_bytes = header.encode().unwrap();
    let before = snapshot(&alice);

    let err = decrypt_message(
        &mut alice,
        env(&id, &bob_device, &alice_device, 1, &header_bytes, &[]),
    )
    .unwrap_err();
    assert_eq!(err, RatchetError::MaxSkipExceeded);
    assert_eq!(snapshot(&alice), before);
}

#[test]
fn unknown_lower_pn_new_ratchet_is_rejected_as_replay() {
    let (_bob, mut alice) = pair_states();
    alice.nr = 2;
    let header = NormalMessageHeader {
        ratchet_public: test_key("unknown-ratchet-pub"),
        previous_chain_length: 1,
        sequence_number: 0,
    };
    let header_bytes = header.encode().unwrap();
    let id = arr::<16>("202122232425262728292a2b2c2d2e2f");
    let sender = arr::<16>("303132333435363738393a3b3c3d3e3f");
    let recipient = arr::<16>("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let before = snapshot(&alice);

    let err = decrypt_new_ratchet_message_inner(
        &mut alice,
        env(&id, &sender, &recipient, 1, &header_bytes, &[]),
        test_key("alice-dhs-next"),
    )
    .unwrap_err();
    assert_eq!(err, RatchetError::ReplayDetected);
    assert_eq!(snapshot(&alice), before);
}
