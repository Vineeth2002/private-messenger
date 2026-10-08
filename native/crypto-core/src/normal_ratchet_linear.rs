//! Linear post-handshake Double Ratchet messaging.
//!
//! This module is intentionally a child of `double_ratchet` so it can operate on
//! the existing private `RatchetState` without duplicating the ratchet state model.
//!
//! Boundary implemented here:
//! - canonical normal-message header
//! - linear send-chain advancement
//! - linear receive-chain advancement
//! - explicit receiving-side DH ratchet transition
//! - atomic authentication/commit on both same-chain and new-ratchet receives
//!
//! Not implemented here:
//! - skipped-message keys / out-of-order delivery
//! - bounded MAX_SKIP processing
//! - replay windows across retired ratchet public keys
//! - persistence/serialization of ratchet state

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::{
    aad_msg, cbor, dh_bytes, kdf_ck, kdf_rk, MessageEnvelopeRef, RatchetError, RatchetKey,
    RatchetState, Value, ZERO_MESSAGE_NONCE,
};

/// Canonical PM-CBOR normal post-handshake header.
///
/// Fields:
/// 1 = sender ratchet public key (X25519, 32 bytes)
/// 2 = previous sending-chain length (Pn)
/// 3 = message number in the current sending chain (N)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalMessageHeader {
    pub ratchet_public: [u8; 32],
    pub previous_chain_length: u32,
    pub sequence_number: u32,
}

impl NormalMessageHeader {
    pub fn encode(&self) -> Result<Vec<u8>, RatchetError> {
        let pairs = vec![
            (Value::Int(1), Value::Bytes(self.ratchet_public.to_vec())),
            (
                Value::Int(2),
                Value::Int(self.previous_chain_length as i128),
            ),
            (Value::Int(3), Value::Int(self.sequence_number as i128)),
        ];
        Ok(cbor::encode_canonical(&Value::Map(pairs))?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RatchetError> {
        let value = cbor::decode_strict(bytes)?;
        let pairs = match value {
            Value::Map(pairs) => pairs,
            _ => return Err(RatchetError::InvalidHeader),
        };

        let mut f1 = None;
        let mut f2 = None;
        let mut f3 = None;

        for (key, value) in pairs {
            let key = match key {
                Value::Int(n) => n,
                _ => return Err(RatchetError::InvalidHeader),
            };
            let slot = match key {
                1 => &mut f1,
                2 => &mut f2,
                3 => &mut f3,
                _ => return Err(RatchetError::InvalidHeader),
            };
            if slot.is_some() {
                return Err(RatchetError::InvalidHeader);
            }
            *slot = Some(value);
        }

        let ratchet_public = match f1.take() {
            Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
                bytes.try_into().expect("length checked")
            }
            _ => return Err(RatchetError::InvalidHeader),
        };
        let previous_chain_length = match f2.take() {
            Some(Value::Int(n)) if (0..=u32::MAX as i128).contains(&n) => n as u32,
            _ => return Err(RatchetError::InvalidHeader),
        };
        let sequence_number = match f3.take() {
            Some(Value::Int(n)) if (0..=u32::MAX as i128).contains(&n) => n as u32,
            _ => return Err(RatchetError::InvalidHeader),
        };

        Ok(Self {
            ratchet_public,
            previous_chain_length,
            sequence_number,
        })
    }
}

fn validate_normal_envelope(envelope: &MessageEnvelopeRef<'_>) -> Result<(), RatchetError> {
    if envelope.is_prekey_handshake {
        return Err(RatchetError::InvalidHeader);
    }
    Ok(())
}

/// Encrypt one normal message from the current sending chain.
///
/// `Ns`, `Pn`, the local sending ratchet public key, and the supplied canonical
/// header must agree exactly. State advances only after encryption succeeds.
pub fn encrypt_message(
    state: &mut RatchetState,
    envelope: MessageEnvelopeRef<'_>,
    header: &NormalMessageHeader,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), RatchetError> {
    validate_normal_envelope(&envelope)?;

    let header_bytes = header.encode()?;
    if envelope.ratchet_header_bytes != header_bytes.as_slice() {
        return Err(RatchetError::InvalidHeader);
    }
    if header.ratchet_public != state.dhs_pub
        || header.previous_chain_length != state.pn
        || header.sequence_number != state.ns
    {
        return Err(RatchetError::InvalidInitialState);
    }

    let ck_s = state
        .ck_s
        .as_ref()
        .ok_or(RatchetError::InvalidInitialState)?;
    let (ck_next, k_msg) = kdf_ck(ck_s);
    let aad = aad_msg(
        envelope.protocol_version,
        envelope.envelope_id,
        envelope.sender_device_id,
        envelope.recipient_device_id,
        envelope.account_epoch,
        false,
        &header_bytes,
    );
    let cipher =
        ChaCha20Poly1305::new_from_slice(k_msg.as_ref()).map_err(|_| RatchetError::AeadEncrypt)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&ZERO_MESSAGE_NONCE),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| RatchetError::AeadEncrypt)?;

    state.ns = state
        .ns
        .checked_add(1)
        .ok_or(RatchetError::InvalidInitialState)?;
    state.ck_s = Some(ck_next);
    Ok((header_bytes, ciphertext))
}

/// Decrypt the next message in the current receiving chain.
///
/// Linear delivery is required: the header ratchet public key must equal the
/// current `DHR`, and `N` must equal `Nr`. Out-of-order/skipped messages are
/// rejected until the skipped-key boundary is implemented.
pub fn decrypt_message(
    state: &mut RatchetState,
    envelope: MessageEnvelopeRef<'_>,
) -> Result<Vec<u8>, RatchetError> {
    validate_normal_envelope(&envelope)?;
    let header = NormalMessageHeader::decode(envelope.ratchet_header_bytes)?;

    if state.dhr_pub != Some(header.ratchet_public) {
        return Err(RatchetError::InvalidInitialState);
    }
    if header.sequence_number != state.nr {
        return Err(RatchetError::InvalidInitialState);
    }

    let ck_r = state
        .ck_r
        .as_ref()
        .ok_or(RatchetError::InvalidInitialState)?;
    let (ck_next, k_msg) = kdf_ck(ck_r);
    let aad = aad_msg(
        envelope.protocol_version,
        envelope.envelope_id,
        envelope.sender_device_id,
        envelope.recipient_device_id,
        envelope.account_epoch,
        false,
        envelope.ratchet_header_bytes,
    );
    let cipher =
        ChaCha20Poly1305::new_from_slice(k_msg.as_ref()).map_err(|_| RatchetError::AeadDecrypt)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&ZERO_MESSAGE_NONCE),
            Payload {
                msg: envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| RatchetError::AeadAuthFailure)?;

    state.nr = state
        .nr
        .checked_add(1)
        .ok_or(RatchetError::InvalidInitialState)?;
    state.ck_r = Some(ck_next);
    Ok(plaintext)
}

/// Decrypt the first message of a newly observed peer ratchet public key.
///
/// The DH transition is computed entirely on temporaries. The new local sending
/// ratchet key and both derived chains are committed only after AEAD authentication
/// succeeds, preserving the atomic-failure invariant.
pub fn decrypt_new_ratchet_message(
    state: &mut RatchetState,
    envelope: MessageEnvelopeRef<'_>,
) -> Result<Vec<u8>, RatchetError> {
    let new_dhs = StaticSecret::random_from_rng(OsRng);
    decrypt_new_ratchet_message_inner(state, envelope, new_dhs.to_bytes())
}

fn decrypt_new_ratchet_message_inner(
    state: &mut RatchetState,
    envelope: MessageEnvelopeRef<'_>,
    new_dhs_priv: RatchetKey,
) -> Result<Vec<u8>, RatchetError> {
    validate_normal_envelope(&envelope)?;
    let header = NormalMessageHeader::decode(envelope.ratchet_header_bytes)?;

    if state.dhr_pub == Some(header.ratchet_public) {
        return Err(RatchetError::InvalidInitialState);
    }
    if header.sequence_number != 0 {
        return Err(RatchetError::InvalidInitialState);
    }

    let dh_recv = dh_bytes(&state.dhs_priv, &header.ratchet_public)?;
    let (rk_temp, ck_r) = kdf_rk(&state.rk, &dh_recv);

    let new_dhs = StaticSecret::from(new_dhs_priv);
    let new_dh_out = {
        let peer = PublicKey::from(header.ratchet_public);
        let shared = new_dhs.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(RatchetError::NonContributoryDh);
        }
        *shared.as_bytes()
    };
    let (rk_final, ck_s) = kdf_rk(&rk_temp, &new_dh_out);
    let (ck_r_after, k_msg) = kdf_ck(&ck_r);

    let aad = aad_msg(
        envelope.protocol_version,
        envelope.envelope_id,
        envelope.sender_device_id,
        envelope.recipient_device_id,
        envelope.account_epoch,
        false,
        envelope.ratchet_header_bytes,
    );
    let cipher =
        ChaCha20Poly1305::new_from_slice(k_msg.as_ref()).map_err(|_| RatchetError::AeadDecrypt)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&ZERO_MESSAGE_NONCE),
            Payload {
                msg: envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| RatchetError::AeadAuthFailure)?;

    state.rk = rk_final;
    state.dhs_priv = Zeroizing::new(new_dhs_priv);
    state.dhs_pub = PublicKey::from(&new_dhs).to_bytes();
    state.dhr_pub = Some(header.ratchet_public);
    state.ck_s = Some(ck_s);
    state.ck_r = Some(ck_r_after);
    state.pn = state.ns;
    state.ns = 0;
    state.nr = 1;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as JsonValue;
    use sha2::{Digest, Sha256};

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

    fn load() -> JsonValue {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/v1/double_ratchet_linear.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("vector file"))
            .expect("valid JSON")
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

    fn test_key(name: &str) -> RatchetKey {
        let mut h = Sha256::new();
        h.update(b"PM-TEST-ONLY-KEY:");
        h.update(name.as_bytes());
        h.finalize().into()
    }

    fn normal_env<'a>(
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

    fn bob_after_message_zero() -> RatchetState {
        let v = load();
        let x_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/v1/bi_x3dh_handshake.json"
        );
        let x: JsonValue =
            serde_json::from_str(&std::fs::read_to_string(x_path).expect("x3dh vector file"))
                .expect("valid JSON");
        let case = &x["cases"][0];
        let sk = arr::<32>(v["sk"].as_str().unwrap());
        let spk_priv = arr::<32>(case["inputs"]["spk_b_priv"].as_str().unwrap());
        let dhs_b1_priv = arr::<32>(v["bob"]["dhs_b1_priv"].as_str().unwrap());
        let msg = &v["message_0"];
        let f = &msg["prekey_handshake_header"]["fields"];
        let header = super::super::PrekeyHandshakeHeader {
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
        super::super::ingest_message_0_inner(&mut bob, env, 7, Some(42), dhs_b1_priv).unwrap();
        bob
    }

    #[test]
    fn normal_header_is_canonical_and_strict() {
        let header = NormalMessageHeader {
            ratchet_public: arr::<32>(
                "8dd70537c92edb2333c8dd56fa60a43649c50d2ea41041e8786678888161047d",
            ),
            previous_chain_length: 0,
            sequence_number: 0,
        };
        let bytes = header.encode().unwrap();
        assert_eq!(
            hex_encode(&bytes),
            "a30158208dd70537c92edb2333c8dd56fa60a43649c50d2ea41041e8786678888161047d02000300"
        );
        assert_eq!(NormalMessageHeader::decode(&bytes).unwrap(), header);

        let mut non_canonical = bytes.clone();
        non_canonical.insert(0, 0x00);
        assert!(NormalMessageHeader::decode(&non_canonical).is_err());
    }

    #[test]
    fn normal_linear_bidirectional_path_matches_reference_values() {
        let mut bob = bob_after_message_zero();
        let alice_device = arr::<16>("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        let bob_device = arr::<16>("303132333435363738393a3b3c3d3e3f");

        let bob_reply_header = NormalMessageHeader {
            ratchet_public: arr::<32>(
                "8dd70537c92edb2333c8dd56fa60a43649c50d2ea41041e8786678888161047d",
            ),
            previous_chain_length: 0,
            sequence_number: 0,
        };
        let bob_reply_header_bytes = bob_reply_header.encode().unwrap();
        let bob_reply_id = arr::<16>("202122232425262728292a2b2c2d2e2f");
        let (_, bob_reply_ct) = encrypt_message(
            &mut bob,
            normal_env(
                &bob_reply_id,
                &bob_device,
                &alice_device,
                1,
                &bob_reply_header_bytes,
                &[],
            ),
            &bob_reply_header,
            b"bob reply",
        )
        .unwrap();
        assert_eq!(
            hex_encode(&bob_reply_ct),
            "7a699d0b8e1278e5a4fc5001397e0b0792f23eba0c1051b419"
        );
        assert_eq!(bob.ns, 1);

        let follow_header = NormalMessageHeader {
            ratchet_public: bob_reply_header.ratchet_public,
            previous_chain_length: 0,
            sequence_number: 1,
        };
        let follow_header_bytes = follow_header.encode().unwrap();
        let follow_id = arr::<16>("606162636465666768696a6b6c6d6e6f");
        let (_, follow_ct) = encrypt_message(
            &mut bob,
            normal_env(
                &follow_id,
                &bob_device,
                &alice_device,
                1,
                &follow_header_bytes,
                &[],
            ),
            &follow_header,
            b"bob followup",
        )
        .unwrap();
        assert_eq!(
            hex_encode(&follow_ct),
            "eeb9a80e71e98f620fae61535d461b64d44954cccb1ddb5a8f04d343"
        );
        assert_eq!(bob.ns, 2);

        let sk = arr::<32>(load()["sk"].as_str().unwrap());
        let mut alice = RatchetState::init_alice(
            &sk,
            &arr::<32>("ec8c415e81fc6095efe84f8c418d7387acea1cd8faad6f48dc2d7f486c9ecb57"),
            arr::<32>(load()["alice"]["dhs_a0_priv"].as_str().unwrap()),
        )
        .unwrap();
        alice.rk = Zeroizing::new(arr::<32>(load()["alice"]["rk_a"].as_str().unwrap()));
        alice.ck_s = Some(Zeroizing::new(arr::<32>(
            load()["alice"]["ck_s_after_msg0"].as_str().unwrap(),
        )));
        alice.ns = 1;

        assert_eq!(
            decrypt_new_ratchet_message_inner(
                &mut alice,
                normal_env(
                    &bob_reply_id,
                    &bob_device,
                    &alice_device,
                    1,
                    &bob_reply_header_bytes,
                    &bob_reply_ct,
                ),
                test_key("dhs_a1"),
            )
            .unwrap(),
            b"bob reply"
        );
        assert_eq!(
            hex_encode(&alice.rk),
            "93d4971570674314017aac9fdf0ba19bb4e1670d6176643f0924fef28f728d78"
        );
        assert_eq!(
            hex_encode(alice.dhs_pub),
            "0afcb5bad545a4f6ead75dec66b80be392bf15dbe8ad1dcb5a794ce575c2bb41"
        );
        assert_eq!(alice.pn, 1);
        assert_eq!(alice.ns, 0);
        assert_eq!(alice.nr, 1);

        assert_eq!(
            decrypt_message(
                &mut alice,
                normal_env(
                    &follow_id,
                    &bob_device,
                    &alice_device,
                    1,
                    &follow_header_bytes,
                    &follow_ct,
                ),
            )
            .unwrap(),
            b"bob followup"
        );
        assert_eq!(alice.nr, 2);

        let alice_header = NormalMessageHeader {
            ratchet_public: alice.dhs_pub,
            previous_chain_length: 1,
            sequence_number: 0,
        };
        let alice_header_bytes = alice_header.encode().unwrap();
        let alice_reply_id = arr::<16>("404142434445464748494a4b4c4d4e4f");
        let (_, alice_ct) = encrypt_message(
            &mut alice,
            normal_env(
                &alice_reply_id,
                &alice_device,
                &bob_device,
                3,
                &alice_header_bytes,
                &[],
            ),
            &alice_header,
            b"alice reply",
        )
        .unwrap();
        assert_eq!(
            hex_encode(&alice_ct),
            "80db5cb3a6d71a2fa0fa0a6e8cf7ec94764835b54e8f3452c292b4"
        );

        assert_eq!(
            decrypt_new_ratchet_message_inner(
                &mut bob,
                normal_env(
                    &alice_reply_id,
                    &alice_device,
                    &bob_device,
                    3,
                    &alice_header_bytes,
                    &alice_ct,
                ),
                test_key("dhs_b2"),
            )
            .unwrap(),
            b"alice reply"
        );
        assert_eq!(
            hex_encode(&bob.rk),
            "f582547a40ca34a596e383c6c0304bff043a9981ec47aae41258d97d35e171c1"
        );
        assert_eq!(
            hex_encode(bob.dhs_pub),
            "1069ca7b17767a1deec72ffedad264d1ff7f29f185ec8a61bd47ed723be8fc01"
        );
        assert_eq!(bob.pn, 2);
        assert_eq!(bob.ns, 0);
        assert_eq!(bob.nr, 1);
    }

    #[test]
    fn normal_new_ratchet_auth_failure_is_atomic() {
        let mut alice = {
            let v = load();
            let sk = arr::<32>(v["sk"].as_str().unwrap());
            let mut state = RatchetState::init_alice(
                &sk,
                &arr::<32>("ec8c415e81fc6095efe84f8c418d7387acea1cd8faad6f48dc2d7f486c9ecb57"),
                arr::<32>(v["alice"]["dhs_a0_priv"].as_str().unwrap()),
            )
            .unwrap();
            state.rk = Zeroizing::new(arr::<32>(v["alice"]["rk_a"].as_str().unwrap()));
            state.ck_s = Some(Zeroizing::new(arr::<32>(
                v["alice"]["ck_s_after_msg0"].as_str().unwrap(),
            )));
            state.ns = 1;
            state
        };

        let bob_device = arr::<16>("303132333435363738393a3b3c3d3e3f");
        let alice_device = arr::<16>("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        let header = NormalMessageHeader {
            ratchet_public: arr::<32>(
                "8dd70537c92edb2333c8dd56fa60a43649c50d2ea41041e8786678888161047d",
            ),
            previous_chain_length: 0,
            sequence_number: 0,
        };
        let header_bytes = header.encode().unwrap();
        let id = arr::<16>("202122232425262728292a2b2c2d2e2f");
        let mut ciphertext = hex_decode("7a699d0b8e1278e5a4fc5001397e0b0792f23eba0c1051b419");
        ciphertext[0] ^= 1;
        let before = state_snapshot(&alice);

        let err = decrypt_new_ratchet_message_inner(
            &mut alice,
            normal_env(
                &id,
                &bob_device,
                &alice_device,
                1,
                &header_bytes,
                &ciphertext,
            ),
            test_key("dhs_a1"),
        )
        .unwrap_err();
        assert_eq!(err, RatchetError::AeadAuthFailure);
        assert_eq!(state_snapshot(&alice), before);
    }
}
