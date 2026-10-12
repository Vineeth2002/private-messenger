//! Shared-vector conformance for Authorization V1.
//!
//! The fixture is generated from the Rust authorization implementation and
//! checked here as an exact byte-level contract. Positive vectors exercise
//! deterministic signing; negative vectors prove signature tampering is rejected.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use pm_crypto_core::authorization_v1::{
    recovery_commitment, sign_device_enrollment, sign_epoch_transition,
    RECOVERY_RESET_ACTION, REVOKE_DEVICE_ACTION,
};
use pm_crypto_core::cbor::{decode_strict, encode_canonical, Value};
use pm_crypto_core::recovery::recovery_signing_key;
use serde_json::Value as J;
use std::path::PathBuf;

fn fixture(name: &str) -> J {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/v1")
        .join(name);
    serde_json::from_str(
        &std::fs::read_to_string(path).expect("vector fixture"),
    )
    .expect("valid JSON")
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

fn field_bytes(raw: &[u8], key: i128) -> Vec<u8> {
    let Value::Map(fields) = decode_strict(raw).expect("certificate must decode") else {
        panic!("certificate must be a map");
    };
    fields
        .into_iter()
        .find(|(k, _)| *k == Value::Int(key))
        .and_then(|(_, value)| match value {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        })
        .unwrap_or_else(|| panic!("field {key} must be bytes"))
}

fn core_without_signature(raw: &[u8]) -> Vec<u8> {
    let Value::Map(fields) = decode_strict(raw).expect("certificate must decode") else {
        panic!("certificate must be a map");
    };
    encode_canonical(&Value::Map(
        fields
            .into_iter()
            .filter(|(key, _)| *key != Value::Int(7))
            .collect(),
    ))
    .unwrap()
}

fn assert_tampered_signature_rejected(raw: &[u8], domain: &[u8], public_key: &[u8; 32]) {
    let core = core_without_signature(raw);
    let signature_bytes = field_bytes(raw, 7);
    let signature = Signature::from_slice(&signature_bytes).unwrap();
    let verifying_key = VerifyingKey::from_bytes(public_key).unwrap();
    assert!(
        verifying_key.verify(&[domain, core.as_slice()].concat(), &signature).is_err(),
        "tampered authorization signature was accepted"
    );
}

#[test]
fn authorization_v1_shared_vectors_match_exact_bytes() {
    let vectors = fixture("authorization_v1.json");
    assert_eq!(vectors["protocol"], "authorization-v1");

    let recovery = &vectors["recovery"];
    let recovery_pub = arr::<32>(recovery["public_key_hex"].as_str().unwrap());
    let expected_commitment = arr::<32>(recovery["commitment_hex"].as_str().unwrap());
    assert_eq!(recovery_commitment(&recovery_pub), expected_commitment);

    let recovery_fixture = fixture("recovery_derivation_fixture.json");
    let mnemonic = recovery_fixture["mnemonic"].as_str().unwrap();
    let signing_key = recovery_signing_key(mnemonic).expect("recovery fixture mnemonic");
    assert_eq!(signing_key.verifying_key().to_bytes(), recovery_pub);

    let enrollment = &vectors["enrollment"];
    let account = arr::<16>(enrollment["account_id_hex"].as_str().unwrap());
    let device = arr::<16>(enrollment["device_id_hex"].as_str().unwrap());
    let dsk = arr::<32>(enrollment["dsk_pub_hex"].as_str().unwrap());
    let ddhk = arr::<32>(enrollment["ddhk_pub_hex"].as_str().unwrap());

    let generated = sign_device_enrollment(
        &signing_key,
        account,
        enrollment["epoch"].as_u64().unwrap(),
        device,
        dsk,
        ddhk,
    )
    .unwrap();

    assert_eq!(
        generated,
        hex(enrollment["certificate_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        core_without_signature(&generated),
        hex(enrollment["core_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        field_bytes(&generated, 7),
        hex(enrollment["signature_hex"].as_str().unwrap())
    );
    assert_eq!(
        hex(enrollment["domain_hex"].as_str().unwrap()),
        b"PM-V1-DEVICE-ENROLL-v1"
    );

    let transitions = vectors["transitions"].as_array().unwrap();

    let revoke = &transitions[0];
    let revoke_account = arr::<16>(revoke["account_id_hex"].as_str().unwrap());
    let revoke_device = arr::<16>(revoke["device_id_hex"].as_str().unwrap());
    let revoke_generated = sign_epoch_transition(
        &signing_key,
        revoke_account,
        revoke["old_epoch"].as_u64().unwrap(),
        revoke["new_epoch"].as_u64().unwrap(),
        revoke["action"].as_u64().unwrap(),
        &revoke_device,
    )
    .unwrap();

    assert_eq!(
        revoke_generated,
        hex(revoke["certificate_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        core_without_signature(&revoke_generated),
        hex(revoke["core_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        field_bytes(&revoke_generated, 7),
        hex(revoke["signature_hex"].as_str().unwrap())
    );
    assert_eq!(
        hex(revoke["domain_hex"].as_str().unwrap()),
        b"PM-V1-EPOCH-TRANSITION-v1"
    );

    let reset = &transitions[1];
    let reset_account = arr::<16>(reset["account_id_hex"].as_str().unwrap());
    let reset_generated = sign_epoch_transition(
        &signing_key,
        reset_account,
        reset["old_epoch"].as_u64().unwrap(),
        reset["new_epoch"].as_u64().unwrap(),
        reset["action"].as_u64().unwrap(),
        &[],
    )
    .unwrap();

    assert_eq!(
        reset_generated,
        hex(reset["certificate_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        core_without_signature(&reset_generated),
        hex(reset["core_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        field_bytes(&reset_generated, 7),
        hex(reset["signature_hex"].as_str().unwrap())
    );
}

#[test]
fn authorization_v1_signature_tamper_vectors_are_rejected() {
    let vectors = fixture("authorization_v1.json");
    let recovery_pub = arr::<32>(vectors["recovery"]["public_key_hex"].as_str().unwrap());

    for case in vectors["negative"].as_array().unwrap() {
        assert_eq!(case["type"], "signature_tamper");
        let raw = hex(case["certificate_cbor_hex"].as_str().unwrap());
        match case["id"].as_str().unwrap() {
            "enrollment-basic-signature-tamper" => {
                assert_tampered_signature_rejected(
                    &raw,
                    b"PM-V1-DEVICE-ENROLL-v1",
                    &recovery_pub,
                );
            }
            "revoke-device-signature-tamper" | "recovery-reset-signature-tamper" => {
                assert_tampered_signature_rejected(
                    &raw,
                    b"PM-V1-EPOCH-TRANSITION-v1",
                    &recovery_pub,
                );
            }
            other => panic!("unexpected negative vector {other}"),
        }
    }
}
