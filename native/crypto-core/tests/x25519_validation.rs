use ed25519_dalek::SigningKey;
use pm_crypto_core::authorization_v1::{
    sign_device_enrollment, AuthorizationV1Error, DeviceEnrollmentAuthorizationV1,
};
use pm_crypto_core::cbor::{self, Value};
use pm_crypto_core::transparency_v1::{decode_leaf, sign_leaf, TransparencyV1Error};
use x25519_dalek::{PublicKey, StaticSecret};

fn usable_public(seed: u8) -> [u8; 32] {
    let private = StaticSecret::from([seed; 32]);
    PublicKey::from(&private).to_bytes()
}

fn non_contributory_public_keys() -> [[u8; 32]; 2] {
    let zero = [0u8; 32];
    let mut one = [0u8; 32];
    one[0] = 1;
    [zero, one]
}

fn replace_bytes_field(raw: &[u8], field_number: i128, replacement: [u8; 32]) -> Vec<u8> {
    let mut value = cbor::decode_strict(raw).expect("valid canonical CBOR");
    let Value::Map(fields) = &mut value else {
        panic!("expected CBOR map");
    };
    let slot = fields
        .iter_mut()
        .find_map(|(key, value)| {
            if matches!(key, Value::Int(number) if *number == field_number) {
                Some(value)
            } else {
                None
            }
        })
        .expect("field exists");
    *slot = Value::Bytes(replacement.to_vec());
    cbor::encode_canonical(&value).expect("encode mutated canonical CBOR")
}

fn valid_enrollment(ddhk: [u8; 32]) -> Vec<u8> {
    let recovery_key = SigningKey::from_bytes(&[0x23u8; 32]);
    sign_device_enrollment(&recovery_key, [0x11; 16], 1, [0x22; 16], [0x33; 32], ddhk)
        .expect("valid DDHK enrollment certificate")
}

fn valid_transparency_leaf(ddhk: [u8; 32], spk: [u8; 32]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&[0x23u8; 32]);
    sign_leaf(
        &signing_key,
        [0x11; 16],
        1,
        [0x22; 16],
        ddhk,
        [0x00; 64],
        spk,
        [0x00; 32],
    )
    .expect("valid transparency leaf")
}

#[test]
fn x25519_validation_enrollment_signing_rejects_non_contributory_ddhk() {
    let recovery_key = SigningKey::from_bytes(&[0x23u8; 32]);
    for invalid_ddhk in non_contributory_public_keys() {
        assert!(matches!(
            sign_device_enrollment(
                &recovery_key,
                [0x11; 16],
                1,
                [0x22; 16],
                [0x33; 32],
                invalid_ddhk,
            ),
            Err(AuthorizationV1Error::InvalidField)
        ));
    }
}

#[test]
fn x25519_validation_enrollment_parser_rejects_non_contributory_ddhk() {
    let raw = valid_enrollment(usable_public(0x44));
    for invalid_ddhk in non_contributory_public_keys() {
        let mutated = replace_bytes_field(&raw, 6, invalid_ddhk);
        assert!(matches!(
            DeviceEnrollmentAuthorizationV1::parse(&mutated),
            Err(AuthorizationV1Error::InvalidField)
        ));
    }
}

#[test]
fn x25519_validation_transparency_signer_rejects_non_contributory_ddhk() {
    let valid_spk = usable_public(0x32);
    let signing_key = SigningKey::from_bytes(&[0x23u8; 32]);
    for invalid_ddhk in non_contributory_public_keys() {
        assert!(matches!(
            sign_leaf(
                &signing_key,
                [0x11; 16],
                1,
                [0x22; 16],
                invalid_ddhk,
                [0x00; 64],
                valid_spk,
                [0x00; 32],
            ),
            Err(TransparencyV1Error::InvalidField)
        ));
    }
}

#[test]
fn x25519_validation_transparency_signer_rejects_non_contributory_spk() {
    let valid_ddhk = usable_public(0x31);
    let signing_key = SigningKey::from_bytes(&[0x23u8; 32]);
    for invalid_spk in non_contributory_public_keys() {
        assert!(matches!(
            sign_leaf(
                &signing_key,
                [0x11; 16],
                1,
                [0x22; 16],
                valid_ddhk,
                [0x00; 64],
                invalid_spk,
                [0x00; 32],
            ),
            Err(TransparencyV1Error::InvalidField)
        ));
    }
}

#[test]
fn x25519_validation_transparency_decoder_rejects_non_contributory_ddhk() {
    let raw = valid_transparency_leaf(usable_public(0x31), usable_public(0x32));
    for invalid_ddhk in non_contributory_public_keys() {
        let mutated = replace_bytes_field(&raw, 5, invalid_ddhk);
        assert!(matches!(
            decode_leaf(&mutated),
            Err(TransparencyV1Error::InvalidField)
        ));
    }
}

#[test]
fn x25519_validation_transparency_decoder_rejects_non_contributory_spk() {
    let raw = valid_transparency_leaf(usable_public(0x31), usable_public(0x32));
    for invalid_spk in non_contributory_public_keys() {
        let mutated = replace_bytes_field(&raw, 7, invalid_spk);
        assert!(matches!(
            decode_leaf(&mutated),
            Err(TransparencyV1Error::InvalidField)
        ));
    }
}
