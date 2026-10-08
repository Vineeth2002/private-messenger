//! PM-DR-LINEAR foundational vector checks for KDF_RK, KDF_CK, and AAD_msg.

use pm_crypto_core::double_ratchet::{aad_msg, kdf_ck, kdf_rk};
use serde_json::Value as J;

fn hex_decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex32(v: &J) -> [u8; 32] {
    let b = hex_decode(v.as_str().unwrap());
    b.try_into().unwrap()
}

fn hex_encode<T: AsRef<[u8]>>(b: T) -> String {
    b.as_ref().iter().map(|x| format!("{:02x}", x)).collect()
}

fn load() -> J {
    let p = format!(
        "{}/../../test-vectors/v1/double_ratchet_linear.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn kdf_vectors_match_frozen_reference() {
    let v = load();

    let ck = hex32(&v["kdf_ck_vector"]["ck"]);
    let (ck_next, k_msg) = kdf_ck(&ck);
    assert_eq!(hex_encode(&k_msg), v["kdf_ck_vector"]["k_msg"]);
    assert_eq!(hex_encode(&ck_next), v["kdf_ck_vector"]["ck_next"]);

    let rk = hex32(&v["kdf_rk_vector"]["rk"]);
    let dh_out = hex32(&v["kdf_rk_vector"]["dh_out"]);
    let (rk_next, ck_out) = kdf_rk(&rk, &dh_out);
    assert_eq!(hex_encode(&rk_next), v["kdf_rk_vector"]["rk_next"]);
    assert_eq!(hex_encode(&ck_out), v["kdf_rk_vector"]["ck_out"]);
}

#[test]
fn aad_vector_matches_frozen_reference() {
    let v = load();
    let inputs = &v["message_0"]["aad_inputs"];

    let envelope_id: [u8; 16] = hex_decode(inputs["envelope_id"].as_str().unwrap())
        .try_into()
        .unwrap();
    let sender_device_id: [u8; 16] = hex_decode(inputs["sender_device_id"].as_str().unwrap())
        .try_into()
        .unwrap();
    let recipient_device_id: [u8; 16] = hex_decode(inputs["recipient_device_id"].as_str().unwrap())
        .try_into()
        .unwrap();
    let header = hex_decode(inputs["ratchet_header_hex"].as_str().unwrap());

    let aad = aad_msg(
        inputs["protocol_version"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        &envelope_id,
        &sender_device_id,
        &recipient_device_id,
        inputs["account_epoch"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        inputs["prekey_flag"].as_u64().unwrap() != 0,
        &header,
    );

    assert_eq!(hex_encode(&aad), v["message_0"]["aad_hex"]);
}
