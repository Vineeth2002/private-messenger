use super::*;
use serde_json::Value as J;

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

fn load() -> J {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/v1/hpke_push_vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("hpke push vector file"))
        .expect("valid hpke push vector JSON")
}

#[test]
fn hpke_push_vector_matches_stateless_base() {
    let v = load();
    let c = &v["cases"][0];

    let sk_r = arr::<32>(c["recipient_private_hex"].as_str().unwrap());
    let sk_e = arr::<32>(c["ephemeral_private_hex"].as_str().unwrap());
    let info = hex_decode(c["info_hex"].as_str().unwrap());
    let aad = hex_decode(c["aad_hex"].as_str().unwrap());
    let plaintext = hex_decode(c["plaintext_hex"].as_str().unwrap());

    let sk_r_static = StaticSecret::from(sk_r);
    let pk_r = PublicKey::from(&sk_r_static).to_bytes();
    assert_eq!(hex_encode(pk_r), c["recipient_public_hex"].as_str().unwrap());

    let sk_e_static = StaticSecret::from(sk_e);
    let (enc, shared_secret) = dhkem_encap(&sk_e_static, &pk_r).unwrap();
    assert_eq!(hex_encode(enc), c["enc_hex"].as_str().unwrap());
    assert_eq!(hex_encode(&shared_secret), c["shared_secret_hex"].as_str().unwrap());

    let (key, base_nonce) = key_schedule_base(&shared_secret, &info).unwrap();
    assert_eq!(hex_encode(&key), c["key_hex"].as_str().unwrap());
    assert_eq!(hex_encode(base_nonce), c["base_nonce_hex"].as_str().unwrap());

    let (enc2, ciphertext) = seal_base_stateless_with_ephemeral(
        &pk_r, &info, &aad, &plaintext, sk_e
    )
    .unwrap();
    assert_eq!(enc2.enc, enc);
    assert_eq!(hex_encode(&ciphertext), c["ciphertext_hex"].as_str().unwrap());

    let opened = open_base_stateless(sk_r, &enc, &info, &aad, &ciphertext).unwrap();
    assert_eq!(opened, plaintext);

    let (random_enc, random_ciphertext) =
        seal_base_stateless(&pk_r, &info, &aad, &plaintext).unwrap();
    assert_eq!(
        open_base_stateless(sk_r, &random_enc.enc, &info, &aad, &random_ciphertext).unwrap(),
        plaintext
    );

    let mut tampered = ciphertext.clone();
    tampered[0] ^= 1;
    assert_eq!(
        open_base_stateless(sk_r, &enc, &info, &aad, &tampered),
        Err(HpkeError::AeadOpenFailed)
    );

    assert!(matches!(
        setup_base_receiver(sk_r, &[0u8; 32], &info),
        Err(HpkeError::NonContributoryDh)
    ));
}
