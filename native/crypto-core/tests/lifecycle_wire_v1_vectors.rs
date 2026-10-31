use pm_crypto_core::{
    authorization_v1::{
        recovery_commitment, DeviceEnrollmentAuthorizationV1, RecoveryRequestV1,
        DEVICE_ENROLL_DOMAIN, PROTOCOL_VERSION, RECOVERY_REQUEST_DOMAIN,
        RecoveryAbortV1, RECOVERY_ABORT_DOMAIN,
        DeviceEnrollmentPoPV1, DEVICE_ENROLLMENT_POP_DOMAIN,
    },
    cbor::{self, Value},
};
use sha2::{Digest, Sha256};

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "odd-length hex vector");
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("valid hex vector"))
        .collect()
}

fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
    let bytes = decode_hex(value);
    assert_eq!(bytes.len(), N, "wrong vector byte length");
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

#[test]
fn lifecycle_wire_v1_candidate_vectors_match_rust_exactly() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/lifecycle_wire_v1.json");
    let raw = std::fs::read_to_string(path).expect("shared lifecycle candidate vector file");
    let vectors: serde_json::Value = serde_json::from_str(&raw).expect("valid lifecycle vector JSON");
    assert_eq!(vectors["schema"].as_str(), Some("lifecycle-wire-v1-candidate"));
    assert_eq!(vectors["status"].as_str(), Some("candidate_not_frozen"));

    let recovery_pub = fixed_hex::<32>(vectors["recovery"]["public_key_hex"].as_str().unwrap());
    assert_eq!(
        hex(&recovery_commitment(&recovery_pub)),
        vectors["recovery"]["commitment_hex"].as_str().unwrap(),
        "recovery commitment vector mismatch",
    );

    let enrollment_vector = &vectors["enrollment"];
    assert_eq!(enrollment_vector["domain_ascii"].as_str(), Some(std::str::from_utf8(DEVICE_ENROLL_DOMAIN).unwrap()));
    let enrollment_wire = decode_hex(enrollment_vector["certificate_cbor_hex"].as_str().unwrap());
    assert_eq!(hex(&enrollment_wire), enrollment_vector["certificate_cbor_hex"].as_str().unwrap());
    let enrollment = DeviceEnrollmentAuthorizationV1::parse(&enrollment_wire).expect("enrollment parses strictly");
    enrollment.verify(&recovery_pub).expect("enrollment recovery signature verifies");
    assert_eq!(enrollment.account_id, fixed_hex::<16>(enrollment_vector["account_id_hex"].as_str().unwrap()));
    assert_eq!(enrollment.epoch, enrollment_vector["epoch"].as_u64().unwrap());
    assert_eq!(enrollment.device_id, fixed_hex::<16>(enrollment_vector["device_id_hex"].as_str().unwrap()));
    assert_eq!(enrollment.dsk_pub, fixed_hex::<32>(enrollment_vector["dsk_public_key_hex"].as_str().unwrap()));
    assert_eq!(enrollment.ddhk_pub, fixed_hex::<32>(enrollment_vector["ddhk_public_key_hex"].as_str().unwrap()));
    assert_eq!(enrollment.signature, fixed_hex::<64>(enrollment_vector["signature_hex"].as_str().unwrap()));
    assert_eq!(enrollment.raw, enrollment_wire);

    let enrollment_core = cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(enrollment.account_id.to_vec())),
        (Value::Int(3), Value::Int(enrollment.epoch as i128)),
        (Value::Int(4), Value::Bytes(enrollment.device_id.to_vec())),
        (Value::Int(5), Value::Bytes(enrollment.dsk_pub.to_vec())),
        (Value::Int(6), Value::Bytes(enrollment.ddhk_pub.to_vec())),
    ])).unwrap();
    assert_eq!(hex(&enrollment_core), enrollment_vector["core_cbor_hex"].as_str().unwrap());
    let enrollment_message = [DEVICE_ENROLL_DOMAIN, enrollment_core.as_slice()].concat();
    assert_eq!(hex(&enrollment_message), enrollment_vector["signed_message_hex"].as_str().unwrap());
    let certificate_digest: [u8; 32] = Sha256::digest(&enrollment_wire).into();
    assert_eq!(hex(&certificate_digest), enrollment_vector["sha256_certificate_hex"].as_str().unwrap());

    let request_vector = &vectors["recovery_request"];
    assert_eq!(request_vector["domain_ascii"].as_str(), Some(std::str::from_utf8(RECOVERY_REQUEST_DOMAIN).unwrap()));
    let request_wire = decode_hex(request_vector["request_cbor_hex"].as_str().unwrap());
    assert_eq!(hex(&request_wire), request_vector["request_cbor_hex"].as_str().unwrap());
    let request = RecoveryRequestV1::parse(&request_wire).expect("recovery request parses strictly");
    request.verify(&recovery_pub).expect("request recovery signature verifies");
    request.verify_for_enrollment(&recovery_pub, &enrollment_wire)
        .expect("both signatures, exact certificate digest, account, target and epoch verify");
    assert_eq!(request.account_id, fixed_hex::<16>(request_vector["account_id_hex"].as_str().unwrap()));
    assert_eq!(request.old_epoch, request_vector["old_epoch"].as_u64().unwrap());
    assert_eq!(request.new_epoch, request_vector["new_epoch"].as_u64().unwrap());
    assert_eq!(request.request_id, fixed_hex::<16>(request_vector["request_id_hex"].as_str().unwrap()));
    assert_eq!(request.target_device_id, fixed_hex::<16>(request_vector["target_device_id_hex"].as_str().unwrap()));
    assert_eq!(request.enrollment_cert_digest, fixed_hex::<32>(request_vector["enrollment_certificate_digest_sha256_hex"].as_str().unwrap()));
    assert_eq!(request.signature, fixed_hex::<64>(request_vector["signature_hex"].as_str().unwrap()));
    assert_eq!(request.raw, request_wire);
    assert_eq!(request.enrollment_cert_digest, certificate_digest);

    let request_core = cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(request.account_id.to_vec())),
        (Value::Int(3), Value::Int(request.old_epoch as i128)),
        (Value::Int(4), Value::Int(request.new_epoch as i128)),
        (Value::Int(5), Value::Bytes(request.request_id.to_vec())),
        (Value::Int(6), Value::Bytes(request.target_device_id.to_vec())),
        (Value::Int(7), Value::Bytes(request.enrollment_cert_digest.to_vec())),
    ])).unwrap();
    assert_eq!(hex(&request_core), request_vector["core_cbor_hex"].as_str().unwrap());
    let request_message = [RECOVERY_REQUEST_DOMAIN, request_core.as_slice()].concat();
    assert_eq!(hex(&request_message), request_vector["signed_message_hex"].as_str().unwrap());
}
#[test]
fn recovery_abort_candidate_vectors_match_rust_exactly() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/lifecycle_wire_v1.json");
    let raw = std::fs::read_to_string(path).expect("shared lifecycle candidate vector file");
    let vectors: serde_json::Value = serde_json::from_str(&raw).expect("valid lifecycle vector JSON");
    let recovery_pub = fixed_hex::<32>(vectors["recovery"]["public_key_hex"].as_str().unwrap());
    let request_wire = decode_hex(vectors["recovery_request"]["request_cbor_hex"].as_str().unwrap());
    let vector = &vectors["recovery_abort"];
    assert_eq!(vector["domain_ascii"].as_str(), Some("PM-V1-RECOVERY-ABORT-v1"));
    assert_eq!(vector["domain_ascii"].as_str(), Some(std::str::from_utf8(RECOVERY_ABORT_DOMAIN).unwrap()));
    let abort_wire = decode_hex(vector["abort_cbor_hex"].as_str().unwrap());
    assert_eq!(hex(&abort_wire), vector["abort_cbor_hex"].as_str().unwrap());
    let device_pub = fixed_hex::<32>(vector["aborting_dsk_public_key_hex"].as_str().unwrap());
    let abort = RecoveryAbortV1::parse(&abort_wire).expect("recovery abort parses strictly");
    abort.verify_for_request(&recovery_pub, &device_pub, &request_wire)
        .expect("device signature and exact signed-request binding verify");
    assert_eq!(abort.account_id, fixed_hex::<16>(vector["account_id_hex"].as_str().unwrap()));
    assert_eq!(abort.device_id, fixed_hex::<16>(vector["aborting_device_id_hex"].as_str().unwrap()));
    assert_eq!(abort.old_epoch, vector["old_epoch"].as_u64().unwrap());
    assert_eq!(abort.new_epoch, vector["new_epoch"].as_u64().unwrap());
    assert_eq!(abort.request_id, fixed_hex::<16>(vector["request_id_hex"].as_str().unwrap()));
    assert_eq!(abort.recovery_request_digest, fixed_hex::<32>(vector["recovery_request_digest_sha256_hex"].as_str().unwrap()));
    assert_eq!(abort.signature, fixed_hex::<64>(vector["signature_hex"].as_str().unwrap()));
    assert_eq!(abort.raw, abort_wire);
    let core = cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(abort.account_id.to_vec())),
        (Value::Int(3), Value::Bytes(abort.device_id.to_vec())),
        (Value::Int(4), Value::Int(abort.old_epoch as i128)),
        (Value::Int(5), Value::Int(abort.new_epoch as i128)),
        (Value::Int(6), Value::Bytes(abort.request_id.to_vec())),
        (Value::Int(7), Value::Bytes(abort.recovery_request_digest.to_vec())),
    ])).unwrap();
    assert_eq!(hex(&core), vector["core_cbor_hex"].as_str().unwrap());
    let signed_message = [RECOVERY_ABORT_DOMAIN, core.as_slice()].concat();
    assert_eq!(hex(&signed_message), vector["signed_message_hex"].as_str().unwrap());
    let request_digest: [u8; 32] = Sha256::digest(&request_wire).into();
    assert_eq!(hex(&request_digest), vector["recovery_request_digest_sha256_hex"].as_str().unwrap());
}
#[test]
fn device_enrollment_pop_candidate_vectors_match_rust_exactly() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/lifecycle_wire_v1.json");
    let raw = std::fs::read_to_string(path).expect("shared lifecycle candidate vector file");
    let vectors: serde_json::Value = serde_json::from_str(&raw).expect("valid lifecycle vector JSON");
    let recovery_pub = fixed_hex::<32>(vectors["recovery"]["public_key_hex"].as_str().unwrap());
    let enrollment_vector = &vectors["pop_enrollment_certificate"];
    let enrollment_raw = decode_hex(enrollment_vector["certificate_cbor_hex"].as_str().unwrap());
    assert_eq!(hex(&enrollment_raw), enrollment_vector["certificate_cbor_hex"].as_str().unwrap());
    let enrollment = DeviceEnrollmentAuthorizationV1::parse(&enrollment_raw).expect("PoP enrollment cert parses");
    enrollment.verify(&recovery_pub).expect("PoP enrollment certificate recovery signature verifies");
    assert_eq!(enrollment.account_id, fixed_hex::<16>(enrollment_vector["account_id_hex"].as_str().unwrap()));
    assert_eq!(enrollment.device_id, fixed_hex::<16>(enrollment_vector["device_id_hex"].as_str().unwrap()));
    assert_eq!(enrollment.epoch, enrollment_vector["epoch"].as_u64().unwrap());
    assert_eq!(enrollment.dsk_pub, fixed_hex::<32>(enrollment_vector["dsk_public_key_hex"].as_str().unwrap()));
    assert_eq!(enrollment.ddhk_pub, fixed_hex::<32>(enrollment_vector["ddhk_public_key_hex"].as_str().unwrap()));
    let exact_certificate_digest: [u8; 32] = Sha256::digest(&enrollment_raw).into();
    assert_eq!(hex(&exact_certificate_digest), enrollment_vector["sha256_certificate_hex"].as_str().unwrap());

    let vector = &vectors["device_enrollment_pop"];
    assert_eq!(vector["domain_ascii"].as_str(), Some("PM-V1-DEVICE-POP-v1"));
    assert_eq!(vector["domain_ascii"].as_str(), Some(std::str::from_utf8(DEVICE_ENROLLMENT_POP_DOMAIN).unwrap()));
    let proof_raw = decode_hex(vector["proof_cbor_hex"].as_str().unwrap());
    assert_eq!(hex(&proof_raw), vector["proof_cbor_hex"].as_str().unwrap());
    let proof = DeviceEnrollmentPoPV1::parse(&proof_raw).expect("PoP response parses strictly");
    let expected_challenge_id = fixed_hex::<16>(vector["challenge_id_hex"].as_str().unwrap());
    let expected_challenge_nonce = fixed_hex::<32>(vector["challenge_nonce_hex"].as_str().unwrap());
    proof.verify_for_enrollment_and_challenge(
        &recovery_pub, &enrollment_raw, &expected_challenge_id, &expected_challenge_nonce,
    ).expect("PoP DSK signature, exact certificate digest, and challenge values verify");
    assert_eq!(proof.account_id, fixed_hex::<16>(vector["account_id_hex"].as_str().unwrap()));
    assert_eq!(proof.device_id, fixed_hex::<16>(vector["device_id_hex"].as_str().unwrap()));
    assert_eq!(proof.epoch, vector["epoch"].as_u64().unwrap());
    assert_eq!(proof.enrollment_cert_digest, exact_certificate_digest);
    assert_eq!(proof.enrollment_cert_digest, fixed_hex::<32>(vector["enrollment_certificate_digest_sha256_hex"].as_str().unwrap()));
    assert_eq!(proof.challenge_id, expected_challenge_id);
    assert_eq!(proof.challenge_nonce, expected_challenge_nonce);
    assert_eq!(proof.signature, fixed_hex::<64>(vector["signature_hex"].as_str().unwrap()));
    assert_eq!(proof.raw, proof_raw);

    let core = cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(proof.account_id.to_vec())),
        (Value::Int(3), Value::Bytes(proof.device_id.to_vec())),
        (Value::Int(4), Value::Int(proof.epoch as i128)),
        (Value::Int(5), Value::Bytes(proof.enrollment_cert_digest.to_vec())),
        (Value::Int(6), Value::Bytes(proof.challenge_id.to_vec())),
        (Value::Int(7), Value::Bytes(proof.challenge_nonce.to_vec())),
    ])).unwrap();
    assert_eq!(hex(&core), vector["core_cbor_hex"].as_str().unwrap());
    let signed_message = [DEVICE_ENROLLMENT_POP_DOMAIN, core.as_slice()].concat();
    assert_eq!(hex(&signed_message), vector["signed_message_hex"].as_str().unwrap());
}
