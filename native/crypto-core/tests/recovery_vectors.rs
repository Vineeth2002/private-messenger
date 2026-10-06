//! RFC 8032 baseline + BIP-39 -> HKDF -> Ed25519 recovery fixture (Rust side).
use ed25519_dalek::{Signer, SigningKey};
use pm_crypto_core::recovery::*;
use serde_json::Value as J;
use sha2::{Digest, Sha512};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn load(name: &str) -> J {
    let p = format!("{}/../../test-vectors/v1/{}", env!("CARGO_MANIFEST_DIR"), name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn rfc8032_baseline() {
    let v = load("ed25519_baseline.json");
    let seed: [u8; 32] = hex_decode(v["seed_hex"].as_str().unwrap()).try_into().unwrap();

    let digest = Sha512::digest(seed);
    let mut half = [0u8; 32];
    half.copy_from_slice(&digest[..32]);
    assert_eq!(hex_encode(&half), v["sha512_first_half_hex"].as_str().unwrap());
    half[0] &= 248;
    half[31] &= 127;
    half[31] |= 64;
    let clamped = hex_encode(&half);
    assert_eq!(clamped, v["clamped_scalar_hex"].as_str().unwrap());
    assert!(!clamped.starts_with(v["forbidden_scalar_prefix"].as_str().unwrap()));

    let sk = SigningKey::from_bytes(&seed);
    assert_eq!(hex_encode(&sk.verifying_key().to_bytes()), v["public_key_hex"].as_str().unwrap());
    assert_eq!(hex_encode(&sk.sign(b"").to_bytes()), v["signature_hex"].as_str().unwrap());
}

#[test]
fn recovery_fixture() {
    let v = load("recovery_derivation_fixture.json");
    let mn = v["mnemonic"].as_str().unwrap();

    let master = bip39_master_seed(mn).unwrap();
    assert_eq!(hex_encode(&master[..]), v["bip39_master_seed_hex"].as_str().unwrap());

    let seed = derive_recovery_seed(&master).unwrap();
    assert_eq!(hex_encode(&seed[..]), v["k_rec_seed_hex"].as_str().unwrap());

    let key = recovery_signing_key(mn).unwrap();
    let pubkey = key.verifying_key().to_bytes();
    assert_eq!(hex_encode(&pubkey), v["k_rec_pub_hex"].as_str().unwrap());
    assert_eq!(hex_encode(&identity_recovery_commitment(&pubkey)), v["irc_hex"].as_str().unwrap());
    assert_eq!(hex_encode(&recovery_sign(&key, b"")), v["sign_empty_message_signature_hex"].as_str().unwrap());
}

#[test]
fn recovery_rejects_bad_mnemonics() {
    // 12-word valid mnemonic: wrong length for this profile.
    let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert_eq!(bip39_master_seed(twelve).unwrap_err(), RecoveryError::WrongWordCount);
    // Bad checksum (24x abandon).
    let bad = ["abandon"; 24].join(" ");
    assert_eq!(bip39_master_seed(&bad).unwrap_err(), RecoveryError::InvalidMnemonic);
    // Not in wordlist.
    assert!(bip39_master_seed("notaword").is_err());
}
