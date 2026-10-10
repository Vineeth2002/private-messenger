use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cbor::CborError;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    #[error("non-canonical integer")]
    NonCanonicalInteger,

    #[error("duplicate map key")]
    DuplicateMapKey,

    #[error("float prohibited")]
    FloatProhibited,

    #[error("indefinite length prohibited")]
    IndefiniteLengthProhibited,

    #[error("unsorted map keys")]
    UnsortedMapKeys,

    #[error("trailing bytes")]
    TrailingBytes,

    #[error("malformed CBOR")]
    MalformedCbor,

    #[error("unsupported CBOR item")]
    UnsupportedItem,

    #[error("CBOR limit exceeded")]
    LimitExceeded,

    #[error("internal OS CSPRNG entropy failure")]
    EntropyFailure,
}

/// Opaque account handle.
///
/// Private identity material remains inside Rust:
/// DSK seed and DDHK seed never cross UniFFI.
pub struct AccountContext {
    account_id: [u8; 16],
    device_id: [u8; 16],
    dsk_seed: Zeroizing<[u8; 32]>,
    ddhk_seed: Zeroizing<[u8; 32]>,
}

impl AccountContext {
    pub fn account_id(&self) -> Vec<u8> {
        self.account_id.to_vec()
    }

    pub fn device_id(&self) -> Vec<u8> {
        self.device_id.to_vec()
    }

    pub fn dsk_public_key(&self) -> Vec<u8> {
        SigningKey::from_bytes(&self.dsk_seed)
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    pub fn ddhk_public_key(&self) -> Vec<u8> {
        let secret = StaticSecret::from(*self.ddhk_seed);
        PublicKey::from(&secret).to_bytes().to_vec()
    }
}

fn uuid_v7(rng: &mut OsRng) -> Result<[u8; 16], CryptoError> {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CryptoError::EntropyFailure)?
        .as_millis();

    if timestamp_ms > ((1u128 << 48) - 1) {
        return Err(CryptoError::EntropyFailure);
    }

    let mut out = [0u8; 16];
    rng.try_fill_bytes(&mut out)
        .map_err(|_| CryptoError::EntropyFailure)?;

    // RFC 9562 UUIDv7 layout:
    // 48-bit Unix epoch milliseconds | version 7 | random_a | variant | random_b.
    let ts = timestamp_ms as u64;
    out[0] = (ts >> 40) as u8;
    out[1] = (ts >> 32) as u8;
    out[2] = (ts >> 24) as u8;
    out[3] = (ts >> 16) as u8;
    out[4] = (ts >> 8) as u8;
    out[5] = ts as u8;
    out[6] = (out[6] & 0x0f) | 0x70;
    out[8] = (out[8] & 0x3f) | 0x80;

    Ok(out)
}

/// Generate a fresh in-memory account identity.
///
/// Only public identifiers and public keys cross the UniFFI boundary.
/// Private identity seeds remain in this opaque Rust handle.
pub fn identity_initialize() -> Result<Arc<AccountContext>, CryptoError> {
    let mut rng = OsRng;

    let account_id = uuid_v7(&mut rng)?;
    let device_id = uuid_v7(&mut rng)?;

    let mut dsk_seed = Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(&mut *dsk_seed)
        .map_err(|_| CryptoError::EntropyFailure)?;

    let mut ddhk_seed = Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(&mut *ddhk_seed)
        .map_err(|_| CryptoError::EntropyFailure)?;

    Ok(Arc::new(AccountContext {
        account_id,
        device_id,
        dsk_seed,
        ddhk_seed,
    }))
}

/// UniFFI-safe validation boundary retained as a regression API.
impl From<CborError> for CryptoError {
    fn from(error: CborError) -> Self {
        match error {
            CborError::NonCanonicalInteger => Self::NonCanonicalInteger,
            CborError::DuplicateMapKey => Self::DuplicateMapKey,
            CborError::FloatProhibited => Self::FloatProhibited,
            CborError::IndefiniteLengthProhibited => Self::IndefiniteLengthProhibited,
            CborError::UnsortedMapKeys => Self::UnsortedMapKeys,
            CborError::TrailingBytes => Self::TrailingBytes,
            CborError::MalformedCbor => Self::MalformedCbor,
            CborError::UnsupportedItem => Self::UnsupportedItem,
            CborError::LimitExceeded => Self::LimitExceeded,
        }
    }
}

pub fn decode_strict_canonical(input: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    crate::cbor::decode_strict(&input).map_err(CryptoError::from)?;
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_input_is_returned_byte_for_byte() {
        let input = vec![0x18, 0x18];
        assert_eq!(decode_strict_canonical(input.clone()).unwrap(), input);
    }

    #[test]
    fn noncanonical_input_returns_categorized_error() {
        let input = vec![0x18, 0x0a];
        assert_eq!(
            decode_strict_canonical(input),
            Err(CryptoError::NonCanonicalInteger)
        );
    }

    #[test]
    fn identity_handle_keeps_private_material_inside_rust() {
        let handle = identity_initialize().unwrap();

        assert_eq!(handle.account_id().len(), 16);
        assert_eq!(handle.device_id().len(), 16);
        assert_eq!(handle.dsk_public_key().len(), 32);
        assert_eq!(handle.ddhk_public_key().len(), 32);

        let dsk = SigningKey::from_bytes(&handle.dsk_seed);
        assert_eq!(handle.dsk_public_key(), dsk.verifying_key().to_bytes().to_vec());

        let ddhk = StaticSecret::from(*handle.ddhk_seed);
        assert_eq!(handle.ddhk_public_key(), PublicKey::from(&ddhk).to_bytes().to_vec());
    }

    #[test]
    fn identity_ids_are_uuid_v7() {
        let handle = identity_initialize().unwrap();

        for id in [handle.account_id, handle.device_id] {
            assert_eq!(id[6] >> 4, 0x7);
            assert_eq!(id[8] >> 6, 0b10);
        }
    }
}
