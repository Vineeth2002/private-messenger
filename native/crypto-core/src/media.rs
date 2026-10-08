//! Media encryption boundary for the Sovereign Private Messenger.
//!
//! Frozen protocol: PM-ALLH-AEAD. Media plaintext is padded to the smallest
//! allowed ALLH bucket that can hold `plaintext_length + 0x80`, then split into
//! fixed 64 KiB chunks. Each chunk uses ChaCha20-Poly1305 with the per-media
//! K_media key and a unique nonce derived from K_media. Chunk metadata is
//! authenticated as PM-CBOR-2026 AAD.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::cbor::{self, CborError, Value};

pub const MEDIA_NONCE_SALT: &[u8] = b"PM-V1-MEDIA-NONCE-SALT-v1";
pub const MEDIA_NONCE_INFO: &[u8] = b"PM-V1-MEDIA-NONCE-EXPAND-v1";
pub const MEDIA_CHUNK_SIZE: usize = 65_536;
pub const MEDIA_TAG_SIZE: usize = 16;
pub const MEDIA_CIPHERTEXT_CHUNK_SIZE: usize = MEDIA_CHUNK_SIZE + MEDIA_TAG_SIZE;
pub const MEDIA_MAX_PLAINTEXT: usize = 104_857_599;

const ALLH_BUCKETS: [usize; 6] = [
    65_536,
    262_144,
    1_048_576,
    5_242_880,
    20_971_520,
    104_857_600,
];

const _: () = assert!(MEDIA_NONCE_SALT.len() == 25);
const _: () = assert!(MEDIA_NONCE_INFO.len() == 27);
const _: () = assert!(MEDIA_CIPHERTEXT_CHUNK_SIZE == 65_552);
const _: () = assert!(MEDIA_MAX_PLAINTEXT == 104_857_599);

pub type MediaKey = [u8; 32];
pub type NonceSalt = [u8; 4];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MediaError {
    #[error("media plaintext length exceeds V1 maximum")]
    PlaintextTooLarge,
    #[error("media bucket unavailable for plaintext length")]
    BucketUnavailable,
    #[error("media container is too short for the padding marker")]
    InvalidLength,
    #[error("media padding marker is missing or invalid")]
    InvalidMarker,
    #[error("media bytes after the padding marker are non-zero")]
    InvalidPadding,
    #[error("media plaintext chunk must be exactly 65536 bytes")]
    InvalidPlaintextChunk,
    #[error("media ciphertext chunk must be exactly 65552 bytes")]
    InvalidCiphertextChunk,
    #[error("media id must be a UUIDv7-shaped 16-byte identifier")]
    InvalidMediaId,
    #[error("media chunk index is outside the padded container")]
    InvalidChunkIndex,
    #[error("media AAD is invalid")]
    InvalidAad,
    #[error("media encryption failed")]
    AeadEncrypt,
    #[error("media authentication failed")]
    AeadAuthFailure,
    #[error("media CBOR error: {0}")]
    Cbor(#[from] CborError),
}

/// Generate a fresh random 32-byte K_media for one media object.
pub fn generate_media_key() -> Zeroizing<MediaKey> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut key[..]);
    key
}

/// Select the smallest frozen ALLH bucket S with S >= L + 1.
pub fn allh_bucket_for_len(plaintext_len: usize) -> Result<usize, MediaError> {
    if plaintext_len > MEDIA_MAX_PLAINTEXT {
        return Err(MediaError::PlaintextTooLarge);
    }
    let needed = plaintext_len
        .checked_add(1)
        .ok_or(MediaError::BucketUnavailable)?;
    ALLH_BUCKETS
        .iter()
        .copied()
        .find(|&bucket| bucket >= needed)
        .ok_or(MediaError::BucketUnavailable)
}

/// Build the padded ALLH container: plaintext || 0x80 || zeros, to bucket S.
pub fn pad_allh(plaintext: &[u8]) -> Result<Vec<u8>, MediaError> {
    let bucket = allh_bucket_for_len(plaintext.len())?;
    let mut container = vec![0u8; bucket];
    container[..plaintext.len()].copy_from_slice(plaintext);
    container[plaintext.len()] = 0x80;
    Ok(container)
}

/// Validate only the structural padding rule. This validator is deliberately
/// independent of the frozen bucket set so tiny structural test vectors can be
/// checked without allocating real media-sized buckets.
pub fn validate_allh_padding(container: &[u8], plaintext_len: usize) -> Result<(), MediaError> {
    let marker_pos = plaintext_len
        .checked_add(1)
        .ok_or(MediaError::InvalidLength)?;
    if container.len() < marker_pos {
        return Err(MediaError::InvalidLength);
    }
    if container[plaintext_len] != 0x80 {
        return Err(MediaError::InvalidMarker);
    }
    if container[marker_pos..].iter().any(|&byte| byte != 0) {
        return Err(MediaError::InvalidPadding);
    }
    Ok(())
}

/// Validate a real V1 ALLH container and return its frozen bucket size.
pub fn validate_allh(container: &[u8], plaintext_len: usize) -> Result<usize, MediaError> {
    if plaintext_len > MEDIA_MAX_PLAINTEXT {
        return Err(MediaError::PlaintextTooLarge);
    }
    if !ALLH_BUCKETS.contains(&container.len()) || container.len() < plaintext_len + 1 {
        return Err(MediaError::InvalidLength);
    }
    validate_allh_padding(container, plaintext_len)?;
    Ok(container.len())
}

/// Derive the four-byte NonceSalt from K_media using the frozen HKDF labels.
pub fn derive_nonce_salt(k_media: &MediaKey) -> Zeroizing<NonceSalt> {
    let hk = Hkdf::<Sha256>::new(Some(MEDIA_NONCE_SALT), k_media);
    let mut salt = Zeroizing::new([0u8; 4]);
    hk.expand(MEDIA_NONCE_INFO, &mut salt[..])
        .expect("4-byte HKDF expansion is always valid");
    salt
}

/// Construct Nonce_i = NonceSalt || uint64_be(i).
pub fn media_nonce(nonce_salt: &NonceSalt, chunk_index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(nonce_salt);
    nonce[4..].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

fn validate_media_id(media_id: &[u8; 16]) -> Result<(), MediaError> {
    if media_id[6] >> 4 != 7 || (media_id[8] & 0xc0) != 0x80 {
        return Err(MediaError::InvalidMediaId);
    }
    Ok(())
}

/// Build the exact MediaChunkAAD PM-CBOR-2026 map:
/// {1:1, 2:media_id, 3:chunk_index, 4:total_chunks,
///  5:unpadded_file_length, 6:padded_container_size}.
pub fn media_chunk_aad(
    media_id: &[u8; 16],
    chunk_index: u64,
    total_chunks: u64,
    unpadded_file_length: u64,
    padded_container_size: u64,
) -> Result<Vec<u8>, MediaError> {
    validate_media_id(media_id)?;
    if total_chunks == 0 || chunk_index >= total_chunks {
        return Err(MediaError::InvalidChunkIndex);
    }
    if padded_container_size == 0 || padded_container_size % MEDIA_CHUNK_SIZE as u64 != 0 {
        return Err(MediaError::InvalidAad);
    }
    if usize::try_from(unpadded_file_length)
        .ok()
        .and_then(|len| allh_bucket_for_len(len).ok())
        != usize::try_from(padded_container_size).ok()
    {
        return Err(MediaError::InvalidAad);
    }

    let value = Value::Map(vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(2), Value::Bytes(media_id.to_vec())),
        (Value::Int(3), Value::Int(chunk_index as i128)),
        (Value::Int(4), Value::Int(total_chunks as i128)),
        (Value::Int(5), Value::Int(unpadded_file_length as i128)),
        (Value::Int(6), Value::Int(padded_container_size as i128)),
    ]);
    Ok(cbor::encode_canonical(&value)?)
}

/// Encrypt one fully padded 64 KiB chunk.
pub fn encrypt_chunk(
    k_media: &MediaKey,
    nonce_salt: &NonceSalt,
    chunk_index: u64,
    plaintext_chunk: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, MediaError> {
    if plaintext_chunk.len() != MEDIA_CHUNK_SIZE {
        return Err(MediaError::InvalidPlaintextChunk);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(k_media).map_err(|_| MediaError::AeadEncrypt)?;
    let nonce = media_nonce(nonce_salt, chunk_index);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext_chunk,
                aad,
            },
        )
        .map_err(|_| MediaError::AeadEncrypt)
}

/// Decrypt and authenticate one fully padded 64 KiB chunk.
pub fn decrypt_chunk(
    k_media: &MediaKey,
    nonce_salt: &NonceSalt,
    chunk_index: u64,
    ciphertext_chunk: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, MediaError> {
    if ciphertext_chunk.len() != MEDIA_CIPHERTEXT_CHUNK_SIZE {
        return Err(MediaError::InvalidCiphertextChunk);
    }
    let cipher =
        ChaCha20Poly1305::new_from_slice(k_media).map_err(|_| MediaError::AeadAuthFailure)?;
    let nonce = media_nonce(nonce_salt, chunk_index);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext_chunk,
                aad,
            },
        )
        .map_err(|_| MediaError::AeadAuthFailure)?;
    if plaintext.len() != MEDIA_CHUNK_SIZE {
        return Err(MediaError::InvalidPlaintextChunk);
    }
    Ok(plaintext)
}

/// SHA-256 of a complete padded ALLH container.
pub fn allh_container_sha256(container: &[u8]) -> [u8; 32] {
    Sha256::digest(container).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex_decode(s).try_into().expect("wrong length")
    }

    fn load() -> J {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/v1/media_chunk_aead.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("media vector file"))
            .expect("valid media JSON")
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn labels_and_nonce_vectors_match() {
        let v = load();
        assert_eq!(
            hex_encode(MEDIA_NONCE_SALT),
            v["labels"]["MEDIA_NONCE_SALT"]["hex"]
        );
        assert_eq!(
            hex_encode(MEDIA_NONCE_INFO),
            v["labels"]["MEDIA_NONCE_INFO"]["hex"]
        );
        let key = arr::<32>(v["k_media_hex"].as_str().unwrap());
        let salt = derive_nonce_salt(&key);
        assert_eq!(hex_encode(&*salt), v["nonce_salt_hex"]);
        for vector in v["nonces"].as_array().unwrap() {
            let index = vector["i"].as_u64().unwrap();
            assert_eq!(hex_encode(&media_nonce(&*salt, index)), vector["nonce_hex"]);
        }
    }

    #[test]
    fn allh_framing_matches_frozen_hashes() {
        let v = load();
        for vector in v["allh_framing"].as_array().unwrap() {
            let len = vector["plaintext_length"].as_u64().unwrap() as usize;
            let bucket = vector["bucket"].as_u64().unwrap() as usize;
            let plaintext = pattern(len);
            let container = pad_allh(&plaintext).unwrap();
            assert_eq!(allh_bucket_for_len(len).unwrap(), bucket);
            assert_eq!(container.len(), bucket);
            assert_eq!(validate_allh(&container, len).unwrap(), bucket);
            assert_eq!(
                hex_encode(&allh_container_sha256(&container)),
                vector["container_sha256"]
            );
            assert_eq!(container[len], 0x80);
            assert!(container[len + 1..].iter().all(|&byte| byte == 0));
            assert_eq!(bucket % MEDIA_CHUNK_SIZE, 0);
            assert_eq!(
                bucket / MEDIA_CHUNK_SIZE,
                vector["chunks"].as_u64().unwrap() as usize
            );
        }
    }

    #[test]
    fn structural_padding_vectors_match() {
        let v = load();
        for vector in v["allh_validation_structural"].as_array().unwrap() {
            let container = hex_decode(vector["container_hex"].as_str().unwrap());
            let len = vector["plaintext_length"].as_u64().unwrap() as usize;
            let result = validate_allh_padding(&container, len);
            match vector["expected"].as_str().unwrap() {
                "OK" => assert!(result.is_ok(), "{}", vector["id"]),
                "INVALID_MARKER" => assert_eq!(result.unwrap_err(), MediaError::InvalidMarker),
                "INVALID_PADDING" => assert_eq!(result.unwrap_err(), MediaError::InvalidPadding),
                "INVALID_LENGTH" => assert_eq!(result.unwrap_err(), MediaError::InvalidLength),
                other => panic!("unknown expected category: {other}"),
            }
        }
    }

    #[test]
    fn chunk_aead_vectors_match_frozen_reference() {
        let v = load();
        let key = arr::<32>(v["k_media_hex"].as_str().unwrap());
        let salt = arr::<4>(v["nonce_salt_hex"].as_str().unwrap());
        for case in v["chunk_aead_cases"].as_array().unwrap() {
            let media_id = arr::<16>(case["media_id_hex"].as_str().unwrap());
            let plaintext_len = case["plaintext_length"].as_u64().unwrap() as usize;
            let bucket = case["bucket"].as_u64().unwrap();
            let total = case["total_chunks"].as_u64().unwrap();
            let container = pad_allh(&pattern(plaintext_len)).unwrap();
            for chunk in case["chunks"].as_array().unwrap() {
                let index = chunk["index"].as_u64().unwrap();
                let aad =
                    media_chunk_aad(&media_id, index, total, plaintext_len as u64, bucket).unwrap();
                assert_eq!(hex_encode(&aad), chunk["aad_hex"]);
                assert_eq!(hex_encode(&media_nonce(&salt, index)), chunk["nonce_hex"]);
                let start = index as usize * MEDIA_CHUNK_SIZE;
                let end = start + MEDIA_CHUNK_SIZE;
                let plaintext = &container[start..end];
                let ciphertext = encrypt_chunk(&key, &salt, index, plaintext, &aad).unwrap();
                assert_eq!(ciphertext.len(), MEDIA_CIPHERTEXT_CHUNK_SIZE);
                assert_eq!(
                    hex_encode(&Sha256::digest(&ciphertext)),
                    chunk["ciphertext_sha256"]
                );
                assert_eq!(
                    hex_encode(&ciphertext[..32]),
                    chunk["ciphertext_first32_hex"]
                );
                assert_eq!(
                    hex_encode(&ciphertext[ciphertext.len() - 16..]),
                    chunk["tag_hex"]
                );
                assert_eq!(
                    decrypt_chunk(&key, &salt, index, &ciphertext, &aad).unwrap(),
                    plaintext
                );
            }
        }
    }

    #[test]
    fn chunk_aead_negative_vectors_fail_authentication() {
        let v = load();
        let key = arr::<32>(v["k_media_hex"].as_str().unwrap());
        let salt = arr::<4>(v["nonce_salt_hex"].as_str().unwrap());
        let case = &v["chunk_aead_cases"][1];
        let media_id = arr::<16>(case["media_id_hex"].as_str().unwrap());
        let plaintext_len = case["plaintext_length"].as_u64().unwrap() as usize;
        let bucket = case["bucket"].as_u64().unwrap();
        let total = case["total_chunks"].as_u64().unwrap();
        let container = pad_allh(&pattern(plaintext_len)).unwrap();

        for negative in v["chunk_aead_negative"].as_array().unwrap() {
            let ciphertext_index = negative["ciphertext_of_chunk"].as_u64().unwrap();
            let nonce_index = negative["nonce_index"].as_u64().unwrap();
            let fields = &negative["aad_fields"];
            let good_aad = media_chunk_aad(
                &media_id,
                ciphertext_index,
                total,
                plaintext_len as u64,
                bucket,
            )
            .unwrap();
            let bad_aad = media_chunk_aad(
                &media_id,
                fields["chunk_index"].as_u64().unwrap(),
                fields["total_chunks"].as_u64().unwrap(),
                fields["unpadded_file_length"].as_u64().unwrap(),
                fields["padded_container_size"].as_u64().unwrap(),
            )
            .unwrap();
            let start = ciphertext_index as usize * MEDIA_CHUNK_SIZE;
            let plaintext = &container[start..start + MEDIA_CHUNK_SIZE];
            let ciphertext =
                encrypt_chunk(&key, &salt, ciphertext_index, plaintext, &good_aad).unwrap();
            assert_eq!(
                decrypt_chunk(&key, &salt, nonce_index, &ciphertext, &bad_aad).unwrap_err(),
                MediaError::AeadAuthFailure,
                "{}",
                negative["id"]
            );
        }
    }

    #[test]
    fn bucket_boundaries_and_limits_are_frozen() {
        assert_eq!(allh_bucket_for_len(0).unwrap(), 65_536);
        assert_eq!(allh_bucket_for_len(65_535).unwrap(), 65_536);
        assert_eq!(allh_bucket_for_len(65_536).unwrap(), 262_144);
        assert_eq!(
            allh_bucket_for_len(MEDIA_MAX_PLAINTEXT).unwrap(),
            104_857_600
        );
        assert_eq!(
            allh_bucket_for_len(MEDIA_MAX_PLAINTEXT + 1).unwrap_err(),
            MediaError::PlaintextTooLarge
        );
    }
}
