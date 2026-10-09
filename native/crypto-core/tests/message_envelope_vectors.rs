use pm_crypto_core::message_envelope::{MessageEnvelopeError, MessageEnvelopeV1};
use serde_json::Value as JsonValue;

fn hex_decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn load() -> JsonValue {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/v1/message_envelope.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn shared_message_envelope_vector_matches() {
    let v = load();
    let p = &v["positive"][0];
    let envelope = MessageEnvelopeV1::new(
        hex_decode(p["envelope_id_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
        hex_decode(p["sender_device_id_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
        hex_decode(p["recipient_device_id_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
        p["account_epoch"].as_u64().unwrap() as u32,
        p["is_prekey_handshake"].as_bool().unwrap(),
        hex_decode(p["ratchet_header_hex"].as_str().unwrap()),
        hex_decode(p["ciphertext_hex"].as_str().unwrap()),
    );

    let encoded = envelope.encode().unwrap();
    assert_eq!(
        encoded,
        hex_decode(p["canonical_cbor_hex"].as_str().unwrap())
    );

    let decoded = MessageEnvelopeV1::decode(&encoded).unwrap();
    assert_eq!(decoded, envelope);
    assert_eq!(decoded.encode().unwrap(), encoded);
}

#[test]
fn shared_negative_message_envelope_cases_are_rejected() {
    let v = load();
    for case in v["negative"].as_array().unwrap() {
        let bytes = hex_decode(case["cbor_hex"].as_str().unwrap());
        let err = MessageEnvelopeV1::decode(&bytes).unwrap_err();
        let expected = case["error"].as_str().unwrap();
        let category = match err {
            MessageEnvelopeError::Cbor(e) => e.category(),
            MessageEnvelopeError::InvalidField => "ERR_INVALID_MESSAGE_ENVELOPE_FIELD",
            MessageEnvelopeError::UnknownField => "ERR_UNKNOWN_MESSAGE_ENVELOPE_FIELD",
            MessageEnvelopeError::MissingField => "ERR_MISSING_MESSAGE_ENVELOPE_FIELD",
        };
        assert_eq!(category, expected, "case {}", case["id"]);
    }
}
