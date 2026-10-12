use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cbor::CborError;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

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

    #[error("limit exceeded")]
    LimitExceeded,

    #[error("invalid cryptographic field")]
    InvalidField,

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

pub struct RecoveryContext {
    recovery_key: SigningKey,
}

impl RecoveryContext {
    pub fn recovery_public_key(&self) -> Vec<u8> {
        self.recovery_key.verifying_key().to_bytes().to_vec()
    }

    pub fn recovery_commitment(&self) -> Vec<u8> {
        crate::authorization_v1::recovery_commitment(&self.recovery_key.verifying_key().to_bytes())
            .to_vec()
    }

    pub fn sign_device_enrollment(
        &self,
        account_id: Vec<u8>,
        epoch: u64,
        device_id: Vec<u8>,
        dsk_pub: Vec<u8>,
        ddhk_pub: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let account_id = fixed::<16>(&account_id)?;
        let device_id = fixed::<16>(&device_id)?;
        let dsk_pub = fixed::<32>(&dsk_pub)?;
        let ddhk_pub = fixed::<32>(&ddhk_pub)?;

        crate::authorization_v1::sign_device_enrollment(
            &self.recovery_key,
            account_id,
            epoch,
            device_id,
            dsk_pub,
            ddhk_pub,
        )
        .map_err(map_authorization_error)
    }

    pub fn sign_epoch_transition(
        &self,
        account_id: Vec<u8>,
        old_epoch: u64,
        new_epoch: u64,
        action: u64,
        device_id: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let account_id = fixed::<16>(&account_id)?;
        if device_id.len() != 0 && device_id.len() != 16 {
            return Err(CryptoError::InvalidField);
        }

        crate::authorization_v1::sign_epoch_transition(
            &self.recovery_key,
            account_id,
            old_epoch,
            new_epoch,
            action,
            &device_id,
        )
        .map_err(map_authorization_error)
    }
}

fn fixed<const N: usize>(input: &[u8]) -> Result<[u8; N], CryptoError> {
    input.try_into().map_err(|_| CryptoError::InvalidField)
}

fn map_authorization_error(error: crate::authorization_v1::AuthorizationV1Error) -> CryptoError {
    match error {
        crate::authorization_v1::AuthorizationV1Error::InvalidField
        | crate::authorization_v1::AuthorizationV1Error::Cbor
        | crate::authorization_v1::AuthorizationV1Error::InvalidEpoch
        | crate::authorization_v1::AuthorizationV1Error::InvalidAction => CryptoError::InvalidField,
    }
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

    pub fn sign_transparency_leaf(
        &self,
        epoch: u64,
        cert_dh: Vec<u8>,
        spk_pub: Vec<u8>,
        push_pk: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        if epoch < 1 || cert_dh.len() != 64 || spk_pub.len() != 32 || push_pk.len() != 32 {
            return Err(CryptoError::InvalidField);
        }

        let mut cert = [0u8; 64];
        cert.copy_from_slice(&cert_dh);

        let mut spk = [0u8; 32];
        spk.copy_from_slice(&spk_pub);

        let mut push = [0u8; 32];
        push.copy_from_slice(&push_pk);

        let signing_key = SigningKey::from_bytes(&self.dsk_seed);
        let ddhk_secret = StaticSecret::from(*self.ddhk_seed);
        let ddhk_pub = PublicKey::from(&ddhk_secret).to_bytes();

        crate::transparency_v1::sign_leaf(
            &signing_key,
            self.account_id,
            epoch,
            self.device_id,
            ddhk_pub,
            cert,
            spk,
            push,
        )
        .map_err(|_| CryptoError::InvalidField)
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

/// Initialize an opaque recovery signing context from the recovery mnemonic.
///
/// The derived Ed25519 recovery signing key remains inside Rust; only its
/// public key, commitment, and signed certificate bytes cross the UniFFI boundary.
pub fn recovery_initialize(mnemonic: String) -> Result<Arc<RecoveryContext>, CryptoError> {
    let recovery_key =
        crate::recovery::recovery_signing_key(&mnemonic).map_err(|_| CryptoError::InvalidField)?;
    Ok(Arc::new(RecoveryContext { recovery_key }))
}

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
        assert_eq!(
            handle.dsk_public_key(),
            dsk.verifying_key().to_bytes().to_vec()
        );

        let ddhk = StaticSecret::from(*handle.ddhk_seed);
        assert_eq!(
            handle.ddhk_public_key(),
            PublicKey::from(&ddhk).to_bytes().to_vec()
        );
    }

    #[test]
    fn identity_ids_are_uuid_v7() {
        let handle = identity_initialize().unwrap();

        for id in [handle.account_id, handle.device_id] {
            assert_eq!(id[6] >> 4, 0x7);
            assert_eq!(id[8] >> 6, 0b10);
        }
    }

    #[test]
    fn transparency_leaf_signing_returns_verifiable_leaf() {
        let handle = identity_initialize().unwrap();
        let cert = vec![0x11; 64];
        let spk = vec![0x22; 32];
        let push = vec![0x33; 32];

        let raw = handle
            .sign_transparency_leaf(1, cert.clone(), spk.clone(), push.clone())
            .unwrap();

        let leaf = crate::transparency_v1::verify_leaf(&raw).unwrap();

        assert_eq!(leaf.account_id, handle.account_id);
        assert_eq!(leaf.epoch, 1);
        assert_eq!(leaf.device_id, handle.device_id);
        assert_eq!(
            leaf.dsk_pub,
            SigningKey::from_bytes(&handle.dsk_seed)
                .verifying_key()
                .to_bytes()
        );
        assert_eq!(
            leaf.ddhk_pub.as_slice(),
            handle.ddhk_public_key().as_slice()
        );
        assert_eq!(leaf.cert_dh.as_slice(), cert.as_slice());
        assert_eq!(leaf.spk_pub.as_slice(), spk.as_slice());
        assert_eq!(leaf.push_pk.as_slice(), push.as_slice());
    }
    #[test]
    fn recovery_authorization_signing_produces_verifiable_enrollment_and_transition() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art".to_owned();
        let handle = recovery_initialize(mnemonic).unwrap();

        assert_eq!(handle.recovery_public_key().len(), 32);
        assert_eq!(handle.recovery_commitment().len(), 32);

        let account = vec![0x11; 16];
        let device = vec![0x22; 16];
        let dsk = vec![0x33; 32];
        let ddhk = vec![0x44; 32];
        let enrollment = handle
            .sign_device_enrollment(account.clone(), 1, device.clone(), dsk, ddhk)
            .unwrap();
        assert_eq!(enrollment[0], 0xa7);

        let revoke = handle
            .sign_epoch_transition(account.clone(), 1, 2, 1, device)
            .unwrap();
        assert_eq!(revoke[0], 0xa7);

        let reset = handle
            .sign_epoch_transition(account, 2, 3, 2, Vec::new())
            .unwrap();
        assert_eq!(reset[0], 0xa7);
    }
}
