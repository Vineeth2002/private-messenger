use super::*;

use crate::{
    signed_prekey_v1::{
        sign_signed_prekey_v1,
        SignedPrekeyV1,
    },
    x3dh,
};

use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey, StaticSecret};

fn message_envelope<'a>(
    id: &'a [u8; 16],
    sender: &'a [u8; 16],
    recipient: &'a [u8; 16],
    epoch: u32,
    prekey: bool,
    header: &'a [u8],
    ciphertext: &'a [u8],
) -> MessageEnvelopeRef<'a> {
    MessageEnvelopeRef {
        protocol_version: 1,
        envelope_id: id,
        sender_device_id: sender,
        recipient_device_id: recipient,
        account_epoch: epoch,
        is_prekey_handshake: prekey,
        ratchet_header_bytes: header,
        ciphertext,
    }
}

fn encrypt_normal(
    state: &mut RatchetState,
    id: &[u8; 16],
    sender: &[u8; 16],
    recipient: &[u8; 16],
    epoch: u32,
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let header = NormalMessageHeader {
        ratchet_public: state.dhs_pub,
        previous_chain_length: state.pn,
        sequence_number: state.ns,
    };

    let header_bytes = header.encode().unwrap();

    let envelope = message_envelope(
        id,
        sender,
        recipient,
        epoch,
        false,
        &header_bytes,
        &[],
    );

    let (_, ciphertext) = encrypt_message(
        state,
        envelope,
        &header,
        plaintext,
    )
    .unwrap();

    (header_bytes, ciphertext)
}

#[test]
fn real_x3dh_handshake_then_bidirectional_double_ratchet_exchange() {
    // Separate account and device identities.
    let alice_account = [0xA1; 16];
    let alice_device = [0xA2; 16];

    let bob_account = [0xB1; 16];
    let bob_device = [0xB2; 16];

    // Device A identity and ephemeral DH keys.
    let alice_ik_bytes = [0x21; 32];
    let alice_ek_bytes = [0x22; 32];

    let alice_ik = StaticSecret::from(alice_ik_bytes);
    let alice_ek = StaticSecret::from(alice_ek_bytes);

    let alice_ik_pub =
        PublicKey::from(&alice_ik).to_bytes();

    let alice_ek_pub =
        PublicKey::from(&alice_ek).to_bytes();

    // Device B identity and signed prekey.
    let bob_ik_bytes = [0x11; 32];
    let bob_spk_bytes = [0x12; 32];

    let bob_ik = StaticSecret::from(bob_ik_bytes);
    let bob_spk = StaticSecret::from(bob_spk_bytes);

    let bob_ik_pub =
        PublicKey::from(&bob_ik).to_bytes();

    let bob_spk_pub =
        PublicKey::from(&bob_spk).to_bytes();

    // Test-only device signing keys.
    let alice_dsk =
        SigningKey::from_bytes(&[0x31; 32]);

    let bob_dsk =
        SigningKey::from_bytes(&[0x32; 32]);

    // B signs its signed-prekey object.
    let signed_spk = sign_signed_prekey_v1(
        &bob_dsk,
        bob_account,
        1,
        bob_device,
        17,
        bob_spk_pub,
    )
    .unwrap();

    // A verifies B's signed-prekey signature and identity binding.
    let parsed_spk =
        SignedPrekeyV1::parse(&signed_spk).unwrap();

    parsed_spk
        .verify(&bob_dsk.verifying_key().to_bytes())
        .unwrap();

    assert_eq!(parsed_spk.account_id, bob_account);
    assert_eq!(parsed_spk.device_id, bob_device);
    assert_eq!(parsed_spk.account_epoch, 1);
    assert_eq!(parsed_spk.spk_id, 17);
    assert_eq!(parsed_spk.spk_pub, bob_spk_pub);

    // A derives X3DH session key.
    let alice_sk = x3dh::initiator_derive_sk(
        &alice_ik,
        &alice_ek,
        &bob_ik_pub,
        &bob_spk_pub,
        None,
        1,
        1,
    )
    .unwrap();

    // B independently derives the same X3DH session key.
    let bob_sk = x3dh::responder_derive_sk(
        &bob_ik,
        &bob_spk,
        None,
        &alice_ik_pub,
        &alice_ek_pub,
        1,
        1,
    )
    .unwrap();

    assert_eq!(&*alice_sk, &*bob_sk);

    // A creates the initial ratchet state.
    let alice_ratchet_priv = [0x41; 32];

    let alice_ratchet_pub =
        PublicKey::from(&StaticSecret::from(alice_ratchet_priv))
            .to_bytes();

    let mut alice = RatchetState::init_alice_from_test_bytes(
        &*alice_sk,
        &bob_spk_pub,
        alice_ratchet_priv,
    )
    .unwrap();

    // B waits for authenticated Message 0.
    let mut bob = RatchetState::init_bob_from_test_bytes(
        &*bob_sk,
        bob_spk_bytes,
    );

    // Cert_dh binds A's account/device identity to its DH key.
    let timestamp = 1_800_000_000u64;

    let alice_cert = x3dh::cert_dh_sign(
        &alice_dsk,
        &alice_account,
        &alice_device,
        &alice_ik_pub,
        timestamp,
    );

    let handshake_header = PrekeyHandshakeHeader {
        sender_account_id: alice_account,
        sender_account_epoch: 1,
        sender_dsk_pub: alice_dsk.verifying_key().to_bytes(),
        sender_ddhk_pub: alice_ik_pub,
        sender_cert_dh: alice_cert,
        sender_cert_dh_timestamp: timestamp,
        sender_ephemeral_pub: alice_ek_pub,
        recipient_spk_id: 17,
        recipient_opk_id: None,
        initial_ratchet_pub: alice_ratchet_pub,
        sequence_number: 0,
    };

    let handshake_header_bytes =
        handshake_header.encode().unwrap();

    let message0_id = [0x61; 16];

    // A encrypts the first handshake message.
    let alice_message0_context = message_envelope(
        &message0_id,
        &alice_device,
        &bob_device,
        1,
        true,
        &handshake_header_bytes,
        &[],
    );

    let (_, message0_ciphertext) = encrypt_message_0(
        &mut alice,
        alice_message0_context,
        &handshake_header,
        b"first encrypted message from Alice",
    )
    .unwrap();

    // B verifies the handshake certificate and decrypts Message 0.
    let bob_message0_context = message_envelope(
        &message0_id,
        &alice_device,
        &bob_device,
        1,
        true,
        &handshake_header_bytes,
        &message0_ciphertext,
    );

    let opened0 = ingest_message_0(
        &mut bob,
        bob_message0_context,
        17,
        None,
    )
    .unwrap();

    assert_eq!(
        opened0,
        b"first encrypted message from Alice"
    );

    // B sends the first normal ratchet message.
    let message1_id = [0x62; 16];

    let (header1, ciphertext1) = encrypt_normal(
        &mut bob,
        &message1_id,
        &bob_device,
        &alice_device,
        1,
        b"reply from Bob",
    );

    // Tampering must fail without advancing A's state.
    let before_failure = (
        *alice.rk,
        alice.dhs_priv.to_bytes(),
        alice.dhs_pub,
        alice.dhr_pub,
        alice.ns,
        alice.nr,
        alice.pn,
    );

    let mut tampered = ciphertext1.clone();
    tampered[0] ^= 0x80;

    let bad_context = message_envelope(
        &message1_id,
        &bob_device,
        &alice_device,
        1,
        false,
        &header1,
        &tampered,
    );

    let error = decrypt_message(
        &mut alice,
        bad_context,
    )
    .unwrap_err();

    assert_eq!(error, RatchetError::AeadAuthFailure);

    let after_failure = (
        *alice.rk,
        alice.dhs_priv.to_bytes(),
        alice.dhs_pub,
        alice.dhr_pub,
        alice.ns,
        alice.nr,
        alice.pn,
    );

    assert_eq!(before_failure, after_failure);

    // A successfully decrypts B's exact original message.
    let good_context = message_envelope(
        &message1_id,
        &bob_device,
        &alice_device,
        1,
        false,
        &header1,
        &ciphertext1,
    );

    let opened1 = decrypt_message(
        &mut alice,
        good_context,
    )
    .unwrap();

    assert_eq!(opened1, b"reply from Bob");

    // Replaying the consumed message must fail.
    let replay_context = message_envelope(
        &message1_id,
        &bob_device,
        &alice_device,
        1,
        false,
        &header1,
        &ciphertext1,
    );

    assert_eq!(
        decrypt_message(&mut alice, replay_context).unwrap_err(),
        RatchetError::ReplayDetected
    );

    // A replies using its advanced sending chain.
    let message2_id = [0x63; 16];

    let (header2, ciphertext2) = encrypt_normal(
        &mut alice,
        &message2_id,
        &alice_device,
        &bob_device,
        1,
        b"reply from Alice",
    );

    let bob_message2_context = message_envelope(
        &message2_id,
        &alice_device,
        &bob_device,
        1,
        false,
        &header2,
        &ciphertext2,
    );

    let opened2 = decrypt_message(
        &mut bob,
        bob_message2_context,
    )
    .unwrap();

    assert_eq!(opened2, b"reply from Alice");

    // B sends again after the ratchet transition.
    let message3_id = [0x64; 16];

    let (header3, ciphertext3) = encrypt_normal(
        &mut bob,
        &message3_id,
        &bob_device,
        &alice_device,
        1,
        b"second reply from Bob",
    );

    let alice_message3_context = message_envelope(
        &message3_id,
        &bob_device,
        &alice_device,
        1,
        false,
        &header3,
        &ciphertext3,
    );

    let opened3 = decrypt_message(
        &mut alice,
        alice_message3_context,
    )
    .unwrap();

    assert_eq!(opened3, b"second reply from Bob");
}