//! Candidate PM-V1 authenticated HTTP request proof.
//!
//! Wire proof (145 bytes):
//! version[1] || account_id[16] || device_id[16] || epoch_be[8] ||
//! timestamp_unix_seconds_be[8] || nonce[32] || ed25519_signature[64].
//!
//! The signature binds the complete proof header to the exact HTTP method,
//! request target, and SHA-256 digest of the raw request body. The server must
//! separately enforce timestamp freshness, atomically consume the nonce, and
//! compare the principal to authoritative account/device state.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

pub const VERSION: u8 = 1;
pub const PROOF_LEN: usize = 145;
pub const MAX_EPOCH: u64 = u32::MAX as u64;
pub const MAX_METHOD_LEN: usize = 16;
pub const MAX_TARGET_LEN: usize = 2048;
pub const MAX_BODY_LEN: usize = 1024 * 1024;

const DOMAIN: &[u8] = b"PM-V1-DEVICE-HTTP-REQUEST-AUTH-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAuthError {
    InvalidField,
    LimitExceeded,
}

/// Sign one request using the device signing key. The caller supplies a
/// server-current epoch, timestamp and nonce; this deterministic primitive is
/// kept separate from the UniFFI wrapper that obtains time and CSPRNG entropy.
pub fn sign_v1(
    signing_key: &SigningKey,
    account_id: &[u8; 16],
    device_id: &[u8; 16],
    epoch: u64,
    timestamp: u64,
    nonce: &[u8; 32],
    method: &str,
    request_target: &str,
    body: &[u8],
) -> Result<Vec<u8>, RequestAuthError> {
    validate_fields(account_id, device_id, epoch, timestamp, nonce, method, request_target, body)?;

    let mut transcript = Vec::with_capacity(
        DOMAIN.len() + 1 + 16 + 16 + 8 + 8 + 32 + 2 + method.len() + 4
            + request_target.len() + 32,
    );
    transcript.extend_from_slice(DOMAIN);
    transcript.push(VERSION);
    transcript.extend_from_slice(account_id);
    transcript.extend_from_slice(device_id);
    transcript.extend_from_slice(&epoch.to_be_bytes());
    transcript.extend_from_slice(&timestamp.to_be_bytes());
    transcript.extend_from_slice(nonce);
    transcript.extend_from_slice(&(method.len() as u16).to_be_bytes());
    transcript.extend_from_slice(method.as_bytes());
    transcript.extend_from_slice(&(request_target.len() as u32).to_be_bytes());
    transcript.extend_from_slice(request_target.as_bytes());
    transcript.extend_from_slice(&Sha256::digest(body));

    let signature = signing_key.sign(&transcript).to_bytes();
    let mut proof = Vec::with_capacity(PROOF_LEN);
    proof.push(VERSION);
    proof.extend_from_slice(account_id);
    proof.extend_from_slice(device_id);
    proof.extend_from_slice(&epoch.to_be_bytes());
    proof.extend_from_slice(&timestamp.to_be_bytes());
    proof.extend_from_slice(nonce);
    proof.extend_from_slice(&signature);
    debug_assert_eq!(proof.len(), PROOF_LEN);
    Ok(proof)
}

fn validate_fields(
    account_id: &[u8; 16],
    device_id: &[u8; 16],
    epoch: u64,
    timestamp: u64,
    nonce: &[u8; 32],
    method: &str,
    request_target: &str,
    body: &[u8],
) -> Result<(), RequestAuthError> {
    if account_id.iter().all(|b| *b == 0)
        || device_id.iter().all(|b| *b == 0)
        || nonce.iter().all(|b| *b == 0)
        || epoch == 0
        || epoch > MAX_EPOCH
        || timestamp == 0
    {
        return Err(RequestAuthError::InvalidField);
    }
    if method.is_empty()
        || method.len() > MAX_METHOD_LEN
        || !method.bytes().enumerate().all(|(i, b)| {
            if i == 0 { b.is_ascii_uppercase() }
            else { b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' }
        })
        || !request_target.is_ascii()
        || !request_target.starts_with('/')
        || request_target.is_empty()
        || request_target.len() > MAX_TARGET_LEN
        || request_target.bytes().any(|b| !(0x21..=0x7e).contains(&b) || b == b'#')
    {
        return Err(RequestAuthError::InvalidField);
    }
    if body.len() > MAX_BODY_LEN {
        return Err(RequestAuthError::LimitExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    const FIXTURE_PROOF_HEX: &str = "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000000007000000006b49d200a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfa0df5dff74291171e1ca91e689ef8dcdc719e6851bd64f8695460e47e9d69304808eec02c3555d26e761732b5656d8f10c6700af67f01db3d4298692b80bec0b";

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn fixture() -> (SigningKey, [u8; 16], [u8; 16], [u8; 32]) {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() { *byte = i as u8; }
        let key = SigningKey::from_bytes(&seed);
        let mut account = [0u8; 16];
        let mut device = [0u8; 16];
        let mut nonce = [0u8; 32];
        for (i, byte) in account.iter_mut().enumerate() { *byte = i as u8; }
        for (i, byte) in device.iter_mut().enumerate() { *byte = (i + 16) as u8; }
        for (i, byte) in nonce.iter_mut().enumerate() { *byte = (i + 0xa0) as u8; }
        (key, account, device, nonce)
    }

    #[test]
    fn rust_signer_matches_cross_language_fixture() {
        let (key, account, device, nonce) = fixture();
        let proof = sign_v1(
            &key, &account, &device, 7, 1_800_000_000, &nonce,
            "POST", "/v1/candidate/messages?limit=10", b"{\"ciphertext\":\"fixture\"}",
        ).unwrap();
        assert_eq!(proof.len(), PROOF_LEN);
        assert_eq!(hex(&proof), FIXTURE_PROOF_HEX);

        let verifying_key = VerifyingKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
        assert_eq!(&proof[1..17], &account);
        assert_eq!(&proof[17..33], &device);
        assert_eq!(u64::from_be_bytes(proof[33..41].try_into().unwrap()), 7);
        assert_eq!(u64::from_be_bytes(proof[41..49].try_into().unwrap()), 1_800_000_000);
        assert_eq!(&proof[49..81], &nonce);
        assert_eq!(verifying_key.as_bytes(), &[
            0x03,0xa1,0x07,0xbf,0xf3,0xce,0x10,0xbe,0x1d,0x70,0xdd,0x18,0xe7,0x4b,0xc0,0x99,
            0x67,0xe4,0xd6,0x30,0x9b,0xa5,0x0d,0x5f,0x1d,0xdc,0x86,0x64,0x12,0x55,0x31,0xb8,
        ]);
    }

    #[test]
    fn request_context_changes_the_signature() {
        let (key, account, device, nonce) = fixture();
        let first = sign_v1(&key, &account, &device, 7, 1_800_000_000, &nonce,
            "POST", "/v1/candidate/messages", b"body").unwrap();
        let changed = sign_v1(&key, &account, &device, 7, 1_800_000_000, &nonce,
            "POST", "/v1/candidate/messages", b"body!").unwrap();
        assert_ne!(&first[81..], &changed[81..]);
    }

    #[test]
    fn rejects_invalid_request_fields_and_oversized_body() {
        let (key, account, device, nonce) = fixture();
        assert!(sign_v1(&key, &account, &device, 0, 1_800_000_000, &nonce,
            "POST", "/x", b"").is_err());
        assert!(sign_v1(&key, &account, &device, 7, 1_800_000_000, &nonce,
            "post", "/x", b"").is_err());
        assert!(sign_v1(&key, &account, &device, 7, 1_800_000_000, &nonce,
            "POST", "https://host/x", b"").is_err());
        assert!(sign_v1(&key, &account, &device, 7, 1_800_000_000, &nonce,
            "POST", "/x#fragment", b"").is_err());
        let oversized = vec![0u8; MAX_BODY_LEN + 1];
        assert_eq!(sign_v1(&key, &account, &device, 7, 1_800_000_000, &nonce,
            "POST", "/x", &oversized), Err(RequestAuthError::LimitExceeded));
    }
}
