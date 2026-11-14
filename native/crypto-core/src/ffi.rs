use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cbor::CborError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
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

struct EnrollmentBinding {
    certificate_raw: Vec<u8>,
    recovery_public_key: [u8; 32],
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
    // Transient enrollment binding; it is intentionally not part of the identity storage record.
    enrollment_binding: Mutex<Option<EnrollmentBinding>>,
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
    /// Create the recovery-signed enrollment certificate using identity values and public keys
    /// derived from the opaque target device context, then bind that exact certificate to it.
    /// The server remains responsible for validating the authoritative account epoch/state.
    pub fn sign_device_enrollment_for_device(
        &self,
        device: Arc<AccountContext>,
        epoch: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        if epoch == 0 || epoch > u32::MAX as u64 {
            return Err(CryptoError::InvalidField);
        }
        let dsk_public_key = SigningKey::from_bytes(&device.dsk_seed).verifying_key().to_bytes();
        let ddhk_secret = StaticSecret::from(*device.ddhk_seed);
        let ddhk_public_key = PublicKey::from(&ddhk_secret).to_bytes();
        let certificate_raw = crate::authorization_v1::sign_device_enrollment(
            &self.recovery_key,
            device.account_id,
            epoch,
            device.device_id,
            dsk_public_key,
            ddhk_public_key,
        )
        .map_err(map_authorization_error)?;
        let recovery_public_key = self.recovery_key.verifying_key().to_bytes();
        let mut binding = device.enrollment_binding.lock().map_err(|_| CryptoError::InvalidField)?;
        match binding.as_ref() {
            Some(existing)
                if existing.certificate_raw == certificate_raw
                    && existing.recovery_public_key == recovery_public_key =>
            {
                Ok(existing.certificate_raw.clone())
            }
            Some(_) => Err(CryptoError::InvalidField),
            None => {
                *binding = Some(EnrollmentBinding {
                    certificate_raw: certificate_raw.clone(),
                    recovery_public_key,
                });
                Ok(certificate_raw)
            }
        }
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

    /// Sign a request using this device's DSK. The nonce and timestamp are
    /// generated inside the native boundary; the private key never leaves Rust.
    pub fn sign_device_http_request_v1(
        &self,
        epoch: u64,
        method: String,
        request_target: String,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        if epoch == 0 || epoch > crate::device_request_auth_v1::MAX_EPOCH {
            return Err(CryptoError::InvalidField);
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::EntropyFailure)?
            .as_secs();
        if timestamp == 0 {
            return Err(CryptoError::EntropyFailure);
        }
        let mut rng = OsRng;
        let mut nonce = [0u8; 32];
        rng.try_fill_bytes(&mut nonce).map_err(|_| CryptoError::EntropyFailure)?;
        let signing_key = SigningKey::from_bytes(&self.dsk_seed);
        crate::device_request_auth_v1::sign_v1(
            &signing_key,
            &self.account_id,
            &self.device_id,
            epoch,
            timestamp,
            &nonce,
            &method,
            &request_target,
            &body,
        ).map_err(|_| CryptoError::InvalidField)
    }
    /// Sign PoP only for the exact recovery-authorized certificate this context signed through
    /// RecoveryContext.sign_device_enrollment_for_device. The server must independently verify
    /// challenge freshness and atomically consume the challenge during activation.
    pub fn sign_device_enrollment_pop_for_challenge(
        &self,
        enrollment_certificate: Vec<u8>,
        challenge_id: Vec<u8>,
        challenge_nonce: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let challenge_id = fixed::<16>(&challenge_id)?;
        let challenge_nonce = fixed::<32>(&challenge_nonce)?;
        let binding = self.enrollment_binding.lock().map_err(|_| CryptoError::InvalidField)?;
        let binding = binding.as_ref().ok_or(CryptoError::InvalidField)?;
        if binding.certificate_raw != enrollment_certificate {
            return Err(CryptoError::InvalidField);
        }

        let signing_key = SigningKey::from_bytes(&self.dsk_seed);
        let ddhk_secret = StaticSecret::from(*self.ddhk_seed);
        let ddhk_public_key = PublicKey::from(&ddhk_secret).to_bytes();
        crate::authorization_v1::sign_device_enrollment_pop_for_context(
            &signing_key,
            &binding.recovery_public_key,
            &enrollment_certificate,
            self.account_id,
            self.device_id,
            signing_key.verifying_key().to_bytes(),
            ddhk_public_key,
            challenge_id,
            challenge_nonce,
        )
        .map_err(map_authorization_error)
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

// Local at-rest format; this is not a protocol/network encoding. The storage
// key is supplied to these Rust-only helpers and is never part of a
// stored record. Only the narrowly scoped Storage DEK API crosses UniFFI;
// private protocol key material remains native-only.
const IDENTITY_STORE_HEADER: &[u8; 9] = b"PMIDSTOR\x01";
const IDENTITY_STORE_NONCE_LEN: usize = 12;
const IDENTITY_STORE_PLAINTEXT_LEN: usize = 96; // account ID + device ID + two 32-byte seeds
const IDENTITY_STORE_TAG_LEN: usize = 16;
const IDENTITY_STORE_PREFIX_LEN: usize = IDENTITY_STORE_HEADER.len() + IDENTITY_STORE_NONCE_LEN;
const IDENTITY_STORE_RECORD_LEN: usize =
    IDENTITY_STORE_PREFIX_LEN + IDENTITY_STORE_PLAINTEXT_LEN + IDENTITY_STORE_TAG_LEN;

impl AccountContext {
    /// Produce an authenticated, versioned at-rest record without returning
    /// the plaintext identity or its private seeds to the caller.
    fn seal_for_storage_key(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let mut plaintext = Zeroizing::new([0u8; IDENTITY_STORE_PLAINTEXT_LEN]);
        plaintext[0..16].copy_from_slice(&self.account_id);
        plaintext[16..32].copy_from_slice(&self.device_id);
        plaintext[32..64].copy_from_slice(&self.dsk_seed[..]);
        plaintext[64..96].copy_from_slice(&self.ddhk_seed[..]);

        let cipher = ChaCha20Poly1305::new_from_slice(storage_key)
            .map_err(|_| CryptoError::InvalidField)?;
        let mut rng = OsRng;
        let mut nonce = [0u8; IDENTITY_STORE_NONCE_LEN];
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| CryptoError::EntropyFailure)?;

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext[..],
                    aad: IDENTITY_STORE_HEADER.as_slice(),
                },
            )
            .map_err(|_| CryptoError::InvalidField)?;

        let mut record = Vec::with_capacity(IDENTITY_STORE_RECORD_LEN);
        record.extend_from_slice(IDENTITY_STORE_HEADER);
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&ciphertext);
        if record.len() != IDENTITY_STORE_RECORD_LEN {
            return Err(CryptoError::InvalidField);
        }
        Ok(record)
    }

    /// UniFFI boundary for the local-storage DEK; protocol private keys remain native-only.
    pub fn seal_for_storage(&self, storage_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let storage_key = Zeroizing::new(storage_key);
        let fixed_key = Zeroizing::new(fixed::<32>(&storage_key)?);
        self.seal_for_storage_key(&fixed_key)
    }

    /// Restore only a structurally valid and authenticated identity record.
    /// Authentication, wrong-key, and malformed-record failures are returned
    /// as the same generic error; callers must never create a replacement
    /// identity automatically after a restore failure.
    pub fn restore_from_storage(
        record: &[u8],
        storage_key: &[u8; 32],
    ) -> Result<Arc<Self>, CryptoError> {
        if record.len() != IDENTITY_STORE_RECORD_LEN
            || record.get(..IDENTITY_STORE_HEADER.len())
                != Some(IDENTITY_STORE_HEADER.as_slice())
        {
            return Err(CryptoError::InvalidField);
        }

        let cipher = ChaCha20Poly1305::new_from_slice(storage_key)
            .map_err(|_| CryptoError::InvalidField)?;
        let nonce = Nonce::from_slice(
            &record[IDENTITY_STORE_HEADER.len()..IDENTITY_STORE_PREFIX_LEN],
        );
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &record[IDENTITY_STORE_PREFIX_LEN..],
                    aad: IDENTITY_STORE_HEADER.as_slice(),
                },
            )
            .map_err(|_| CryptoError::InvalidField)?;
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() != IDENTITY_STORE_PLAINTEXT_LEN {
            return Err(CryptoError::InvalidField);
        }

        let account_id = fixed::<16>(&plaintext[0..16])?;
        let device_id = fixed::<16>(&plaintext[16..32])?;
        // Both IDs are generated as UUIDv7. Reject records that violate that
        // invariant, even if their AEAD tag is valid.
        for id in [&account_id, &device_id] {
            if id[6] >> 4 != 0x7 || id[8] >> 6 != 0b10 {
                return Err(CryptoError::InvalidField);
            }
        }

        let mut dsk_seed = Zeroizing::new([0u8; 32]);
        dsk_seed.copy_from_slice(&plaintext[32..64]);
        let mut ddhk_seed = Zeroizing::new([0u8; 32]);
        ddhk_seed.copy_from_slice(&plaintext[64..96]);

        Ok(Arc::new(Self {
            account_id,
            device_id,
            dsk_seed,
            ddhk_seed,
            enrollment_binding: Mutex::new(None),
        }))
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

/// Generate a recovery phrase from native OS entropy. Treat the returned phrase as a secret.
pub fn recovery_mnemonic_generate() -> Result<String, CryptoError> {
    crate::recovery::generate_recovery_mnemonic().map_err(|error| match error {
        crate::recovery::RecoveryError::EntropyFailure => CryptoError::EntropyFailure,
        _ => CryptoError::InvalidField,
    })
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


/// Create a fresh device identity under an existing UUIDv7 account ID.
/// DSK and DDHK seeds are generated and remain inside Rust; no key material crosses UniFFI.
pub fn device_initialize_for_account(account_id: Vec<u8>) -> Result<Arc<AccountContext>, CryptoError> {
    let account_id = fixed::<16>(&account_id)?;
    if account_id == [0u8; 16] || account_id[6] >> 4 != 0x7 || account_id[8] >> 6 != 0b10 {
        return Err(CryptoError::InvalidField);
    }

    let mut rng = OsRng;
    let device_id = loop {
        let candidate = uuid_v7(&mut rng)?;
        if candidate != account_id {
            break candidate;
        }
    };
    let mut dsk_seed = Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(&mut *dsk_seed).map_err(|_| CryptoError::EntropyFailure)?;
    let mut ddhk_seed = Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(&mut *ddhk_seed).map_err(|_| CryptoError::EntropyFailure)?;

    Ok(Arc::new(AccountContext {
        account_id,
        device_id,
        dsk_seed,
        ddhk_seed,
        enrollment_binding: Mutex::new(None),
    }))
}pub fn identity_initialize() -> Result<Arc<AccountContext>, CryptoError> {
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
        enrollment_binding: Mutex::new(None),
    }))
}

/// Restore an identity from an authenticated local-storage record; the transient Storage DEK is zeroized.
pub fn identity_restore(
    record: Vec<u8>,
    storage_key: Vec<u8>,
) -> Result<Arc<AccountContext>, CryptoError> {
    let storage_key = Zeroizing::new(storage_key);
    let fixed_key = Zeroizing::new(fixed::<32>(&storage_key)?);
    AccountContext::restore_from_storage(&record, &fixed_key)
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
    fn identity_storage_roundtrip_preserves_ids_keys_and_signing() {
        let original = identity_initialize().unwrap();
        let storage_key = [0xA5; 32];
        let record = original.seal_for_storage_key(&storage_key).unwrap();

        assert_eq!(record.len(), IDENTITY_STORE_RECORD_LEN);
        assert_eq!(
            &record[..IDENTITY_STORE_HEADER.len()],
            IDENTITY_STORE_HEADER.as_slice()
        );
        assert!(!record.windows(32).any(|window| window == &original.dsk_seed[..]));
        assert!(!record.windows(32).any(|window| window == &original.ddhk_seed[..]));

        let restored = AccountContext::restore_from_storage(&record, &storage_key).unwrap();
        assert_eq!(restored.account_id(), original.account_id());
        assert_eq!(restored.device_id(), original.device_id());
        assert_eq!(restored.dsk_public_key(), original.dsk_public_key());
        assert_eq!(restored.ddhk_public_key(), original.ddhk_public_key());

        let cert = vec![0x11; 64];
        let spk = vec![0x22; 32];
        let push = vec![0x33; 32];
        assert_eq!(
            restored
                .sign_transparency_leaf(1, cert.clone(), spk.clone(), push.clone())
                .unwrap(),
            original
                .sign_transparency_leaf(1, cert, spk, push)
                .unwrap()
        );
    }

    #[test]
    fn identity_storage_rejects_wrong_key_and_tampering() {
        let original = identity_initialize().unwrap();
        let storage_key = [0xA5; 32];
        let record = original.seal_for_storage_key(&storage_key).unwrap();

        assert_eq!(
            AccountContext::restore_from_storage(&record, &[0x5A; 32]).err(),
            Some(CryptoError::InvalidField)
        );

        for offset in [
            0,
            IDENTITY_STORE_HEADER.len() - 1,
            IDENTITY_STORE_HEADER.len(),
            IDENTITY_STORE_RECORD_LEN - 1,
        ] {
            let mut tampered = record.clone();
            tampered[offset] ^= 0x01;
            assert_eq!(
                AccountContext::restore_from_storage(&tampered, &storage_key).err(),
                Some(CryptoError::InvalidField),
                "tamper at offset {offset} must fail closed"
            );
        }

        assert_eq!(
            AccountContext::restore_from_storage(&record[..record.len() - 1], &storage_key).err(),
            Some(CryptoError::InvalidField)
        );
    }

    #[test]
    fn identity_storage_uses_fresh_nonce_and_rejects_unknown_version() {
        let original = identity_initialize().unwrap();
        let storage_key = [0xA5; 32];
        let first = original.seal_for_storage_key(&storage_key).unwrap();
        let second = original.seal_for_storage_key(&storage_key).unwrap();
        assert_ne!(first, second, "fresh records should use fresh nonces");

        let mut unsupported = first;
        unsupported[IDENTITY_STORE_HEADER.len() - 1] = 2;
        assert_eq!(
            AccountContext::restore_from_storage(&unsupported, &storage_key).err(),
            Some(CryptoError::InvalidField)
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

    #[test]
    fn additional_device_enrollment_and_pop_are_bound_to_native_context() {
        let existing = identity_initialize().unwrap();
        let account_id = existing.account_id();
        let device = device_initialize_for_account(account_id.clone()).unwrap();
        assert_eq!(device.account_id(), account_id);
        assert_ne!(device.device_id(), account_id);
        assert_eq!(device.device_id()[6] >> 4, 0x7);
        assert_eq!(device.device_id()[8] >> 6, 0b10);
        assert!(device_initialize_for_account(vec![0u8; 16]).is_err());
        assert!(device_initialize_for_account(vec![0x44u8; 16]).is_err(), "non-UUIDv7 account IDs must fail closed");

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art".to_owned();
        let recovery = recovery_initialize(mnemonic).unwrap();
        let recovery_public_key = fixed::<32>(&recovery.recovery_public_key()).unwrap();
        let certificate = recovery.sign_device_enrollment_for_device(Arc::clone(&device), 2).unwrap();
        let enrollment = crate::authorization_v1::DeviceEnrollmentAuthorizationV1::parse(&certificate).unwrap();
        enrollment.verify(&recovery_public_key).unwrap();
        assert_eq!(enrollment.account_id, fixed::<16>(&account_id).unwrap());
        assert_eq!(enrollment.device_id, fixed::<16>(&device.device_id()).unwrap());
        assert_eq!(enrollment.dsk_pub, fixed::<32>(&device.dsk_public_key()).unwrap());
        assert_eq!(enrollment.ddhk_pub, fixed::<32>(&device.ddhk_public_key()).unwrap());

        let challenge_id = vec![0x51; 16];
        let challenge_nonce = vec![0x62; 32];
        let proof_raw = device.sign_device_enrollment_pop_for_challenge(
            certificate.clone(), challenge_id.clone(), challenge_nonce.clone(),
        ).unwrap();
        let proof = crate::authorization_v1::DeviceEnrollmentPoPV1::parse(&proof_raw).unwrap();
        proof.verify_for_enrollment_and_challenge(
            &recovery_public_key,
            &certificate,
            &fixed::<16>(&challenge_id).unwrap(),
            &fixed::<32>(&challenge_nonce).unwrap(),
        ).unwrap();

        let mut changed_certificate = certificate.clone();
        changed_certificate[0] ^= 0x01;
        assert_eq!(
            device.sign_device_enrollment_pop_for_challenge(
                changed_certificate, challenge_id.clone(), challenge_nonce.clone(),
            ).unwrap_err(),
            CryptoError::InvalidField,
        );
        assert_eq!(
            device.sign_device_enrollment_pop_for_challenge(
                certificate.clone(), vec![0x51; 15], challenge_nonce.clone(),
            ).unwrap_err(),
            CryptoError::InvalidField,
        );
        assert!(device.sign_device_enrollment_pop_for_challenge(
            certificate.clone(), vec![0u8; 16], challenge_nonce.clone(),
        ).is_err(), "zero challenge ID must fail closed");
        assert_eq!(
            recovery.sign_device_enrollment_for_device(Arc::clone(&device), 3).unwrap_err(),
            CryptoError::InvalidField,
            "a native device context must not be rebound to a conflicting enrollment certificate",
        );
    }
}


// Native message/session API for the UniFFI surface.
// Appended to ffi.rs so AccountContext's long-term private keys remain inaccessible
// outside this module. All ratchet and X3DH secrets stay in Rust.

use crate::double_ratchet::{
    decrypt_message, encrypt_message, encrypt_message_0, ingest_message_0, MessageEnvelopeRef,
    PrekeyHandshakeHeader, RatchetState,
};
use crate::message_envelope::MessageEnvelopeV1;
use crate::ratchet_persistence::{
    restore_ratchet_state, seal_ratchet_state, stage_ratchet_transition,
    StagedRatchetTransition,
};
use crate::signed_prekey_v1::{sign_signed_prekey_v1, SignedPrekeyV1};
use crate::storage_record::{StorageRecordCipher, StorageRecordContext, StorageRecordType};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecret};

fn messaging_fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::InvalidField)
}

fn messaging_epoch(value: u64) -> Result<u32, CryptoError> {
    if value == 0 || value > u32::MAX as u64 {
        return Err(CryptoError::InvalidField);
    }
    Ok(value as u32)
}

fn messaging_storage_cipher(storage_key: Vec<u8>) -> Result<StorageRecordCipher, CryptoError> {
    let storage_key = Zeroizing::new(storage_key);
    let key = Zeroizing::new(messaging_fixed::<32>(&storage_key)?);
    Ok(StorageRecordCipher::new(*key))
}

fn messaging_session_id(bytes: &[u8]) -> Result<[u8; 16], CryptoError> {
    let id = messaging_fixed::<16>(bytes)?;
    if id == [0u8; 16] {
        return Err(CryptoError::InvalidField);
    }
    Ok(id)
}

fn signed_prekey_storage_context(
    account_id: [u8; 16],
    device_id: [u8; 16],
    epoch: u32,
    spk_id: u32,
) -> StorageRecordContext {
    StorageRecordContext {
        record_type: StorageRecordType::SignedPrekeyPrivate,
        account_id,
        device_id,
        session_id: [0u8; 16],
        generation: ((epoch as u64) << 32) | spk_id as u64,
    }
}

/// Opaque signed-prekey handle. The private key is generated, retained, sealed,
/// restored and consumed only in Rust. The public signed object may be published.
pub struct SignedPrekeyContext {
    account_id: [u8; 16],
    device_id: [u8; 16],
    epoch: u32,
    spk_id: u32,
    raw_signed_prekey: Vec<u8>,
    spk_private: Zeroizing<[u8; 32]>,
}

impl SignedPrekeyContext {
    pub fn raw_signed_prekey(&self) -> Vec<u8> {
        self.raw_signed_prekey.clone()
    }

    /// Encrypted private-prekey record. Persist this together with raw_signed_prekey().
    pub fn seal_for_storage(&self, storage_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let cipher = messaging_storage_cipher(storage_key)?;
        let context = signed_prekey_storage_context(
            self.account_id,
            self.device_id,
            self.epoch,
            self.spk_id,
        );
        cipher
            .seal(&context, &self.spk_private[..])
            .map_err(|_| CryptoError::InvalidField)
    }
}

#[derive(Clone, Copy)]
enum PendingTransitionKind {
    SendMessageZero,
    ReceiveMessageZero,
    Normal,
}

struct MessagingSessionInner {
    active: RatchetState,
    generation: u64,
    pending: Option<StagedRatchetTransition<Vec<u8>>>,
    pending_kind: Option<PendingTransitionKind>,
    first_send_header: Option<PrekeyHandshakeHeader>,
    first_receive_spk_id: Option<u32>,
}

/// Opaque E2EE session handle. At-rest encryption is performed by the native
/// StorageRecordCipher. A transition is promoted only after the caller commits
/// its message row and pending_snapshot() in one SQLite transaction.
pub struct MessagingSession {
    local_account_id: [u8; 16],
    local_device_id: [u8; 16],
    local_epoch: u32,
    peer_account_id: [u8; 16],
    peer_device_id: [u8; 16],
    peer_epoch: u32,
    session_id: [u8; 16],
    cipher: StorageRecordCipher,
    inner: Mutex<MessagingSessionInner>,
}

impl MessagingSession {
    fn storage_context(&self, generation: u64) -> StorageRecordContext {
        StorageRecordContext {
            record_type: StorageRecordType::RatchetSnapshot,
            account_id: self.local_account_id,
            device_id: self.local_device_id,
            session_id: self.session_id,
            generation,
        }
    }

    pub fn session_id(&self) -> Vec<u8> {
        self.session_id.to_vec()
    }

    /// Empty after the initial prekey message has been committed. Store this
    /// public header if persisting an initiator session before its first send.
    pub fn initial_prekey_header(&self) -> Result<Vec<u8>, CryptoError> {
        let inner = self.inner.lock().map_err(|_| CryptoError::InvalidField)?;
        match inner.first_send_header.as_ref() {
            Some(header) => header.encode().map_err(|_| CryptoError::InvalidField),
            None => Ok(Vec::new()),
        }
    }

    pub fn current_snapshot(&self) -> Result<Vec<u8>, CryptoError> {
        let inner = self.inner.lock().map_err(|_| CryptoError::InvalidField)?;
        if inner.pending.is_some() {
            return Err(CryptoError::InvalidField);
        }
        seal_ratchet_state(
            &inner.active,
            &self.cipher,
            &self.storage_context(inner.generation),
        )
        .map_err(|_| CryptoError::InvalidField)
    }

    /// Encrypt and stage one outbound message. The returned bytes are the exact
    /// canonical MessageEnvelopeV1 wire object to enqueue at the gateway.
    /// The caller MUST persist these bytes and pending_snapshot() atomically,
    /// then call commit_staged(); on transaction failure call discard_staged().
    pub fn stage_encrypt_message(
        &self,
        envelope_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let envelope_id = messaging_session_id(&envelope_id)?;
        let mut inner = self.inner.lock().map_err(|_| CryptoError::InvalidField)?;
        if inner.pending.is_some() {
            return Err(CryptoError::InvalidField);
        }
        let next_generation = inner
            .generation
            .checked_add(1)
            .ok_or(CryptoError::InvalidField)?;
        let context = self.storage_context(next_generation);
        let local_device_id = self.local_device_id;
        let peer_device_id = self.peer_device_id;
        let peer_epoch = self.peer_epoch;
        let first_header = inner.first_send_header.clone();

        let staged = stage_ratchet_transition(
            &inner.active,
            &self.cipher,
            &context,
            move |candidate| {
                if let Some(header) = first_header.as_ref() {
                    let header_bytes = header.encode()?;
                    let envelope_ref = MessageEnvelopeRef {
                        protocol_version: MessageEnvelopeV1::PROTOCOL_VERSION,
                        envelope_id: &envelope_id,
                        sender_device_id: &local_device_id,
                        recipient_device_id: &peer_device_id,
                        account_epoch: peer_epoch,
                        is_prekey_handshake: true,
                        ratchet_header_bytes: &header_bytes,
                        ciphertext: &[],
                    };
                    let (encoded_header, ciphertext) =
                        encrypt_message_0(candidate, envelope_ref, header, &plaintext)?;
                    MessageEnvelopeV1::new(
                        envelope_id,
                        local_device_id,
                        peer_device_id,
                        peer_epoch,
                        true,
                        encoded_header,
                        ciphertext,
                    )
                    .encode()
                    .map_err(|_| crate::double_ratchet::RatchetError::InvalidHeader)
                } else {
                    let header = candidate.next_normal_message_header();
                    let header_bytes = header.encode()?;
                    let envelope_ref = MessageEnvelopeRef {
                        protocol_version: MessageEnvelopeV1::PROTOCOL_VERSION,
                        envelope_id: &envelope_id,
                        sender_device_id: &local_device_id,
                        recipient_device_id: &peer_device_id,
                        account_epoch: peer_epoch,
                        is_prekey_handshake: false,
                        ratchet_header_bytes: &header_bytes,
                        ciphertext: &[],
                    };
                    let (encoded_header, ciphertext) =
                        encrypt_message(candidate, envelope_ref, &header, &plaintext)?;
                    MessageEnvelopeV1::new(
                        envelope_id,
                        local_device_id,
                        peer_device_id,
                        peer_epoch,
                        false,
                        encoded_header,
                        ciphertext,
                    )
                    .encode()
                    .map_err(|_| crate::double_ratchet::RatchetError::InvalidHeader)
                }
            },
        )
        .map_err(|_| CryptoError::InvalidField)?;

        let output = staged.output().clone();
        inner.pending_kind = Some(if inner.first_send_header.is_some() {
            PendingTransitionKind::SendMessageZero
        } else {
            PendingTransitionKind::Normal
        });
        inner.pending = Some(staged);
        Ok(output)
    }

    /// Authenticate and stage one inbound MessageEnvelopeV1. Plaintext is
    /// returned only after AEAD verification. Persist plaintext and the
    /// encrypted pending snapshot atomically before commit_staged().
    pub fn stage_decrypt_message(&self, envelope_wire: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let envelope = MessageEnvelopeV1::decode(&envelope_wire)
            .map_err(|_| CryptoError::InvalidField)?;
        if envelope.sender_device_id != self.peer_device_id
            || envelope.recipient_device_id != self.local_device_id
            || envelope.account_epoch != self.local_epoch
        {
            return Err(CryptoError::InvalidField);
        }

        let mut inner = self.inner.lock().map_err(|_| CryptoError::InvalidField)?;
        if inner.pending.is_some() {
            return Err(CryptoError::InvalidField);
        }
        let next_generation = inner
            .generation
            .checked_add(1)
            .ok_or(CryptoError::InvalidField)?;
        let context = self.storage_context(next_generation);
        let first_receive_spk_id = inner.first_receive_spk_id;
        if envelope.is_prekey_handshake != first_receive_spk_id.is_some() {
            return Err(CryptoError::InvalidField);
        }
        if let Some(expected_spk_id) = first_receive_spk_id {
            let header = PrekeyHandshakeHeader::decode(&envelope.ratchet_header_bytes)
                .map_err(|_| CryptoError::InvalidField)?;
            if header.sender_account_id != self.peer_account_id
                || header.sender_account_epoch != self.peer_epoch
                || header.recipient_spk_id != expected_spk_id
                || header.recipient_opk_id.is_some()
            {
                return Err(CryptoError::InvalidField);
            }
        }

        let staged = stage_ratchet_transition(
            &inner.active,
            &self.cipher,
            &context,
            move |candidate| {
                let envelope_ref = MessageEnvelopeRef {
                    protocol_version: envelope.protocol_version,
                    envelope_id: &envelope.envelope_id,
                    sender_device_id: &envelope.sender_device_id,
                    recipient_device_id: &envelope.recipient_device_id,
                    account_epoch: envelope.account_epoch,
                    is_prekey_handshake: envelope.is_prekey_handshake,
                    ratchet_header_bytes: &envelope.ratchet_header_bytes,
                    ciphertext: &envelope.ciphertext,
                };
                if let Some(expected_spk_id) = first_receive_spk_id {
                    ingest_message_0(candidate, envelope_ref, expected_spk_id, None)
                } else {
                    decrypt_message(candidate, envelope_ref)
                }
            },
        )
        .map_err(|_| CryptoError::InvalidField)?;

        let plaintext = staged.output().clone();
        inner.pending_kind = Some(if first_receive_spk_id.is_some() {
            PendingTransitionKind::ReceiveMessageZero
        } else {
            PendingTransitionKind::Normal
        });
        inner.pending = Some(staged);
        Ok(plaintext)
    }

    /// Must be called only after the SQLite transaction containing the staged
    /// message and pending_snapshot() has committed.
    pub fn commit_staged(&self) -> Result<(), CryptoError> {
        let mut inner = self.inner.lock().map_err(|_| CryptoError::InvalidField)?;
        let next_generation = inner
            .generation
            .checked_add(1)
            .ok_or(CryptoError::InvalidField)?;
        let staged = inner.pending.take().ok_or(CryptoError::InvalidField)?;
        let kind = inner.pending_kind.take().ok_or(CryptoError::InvalidField)?;
        inner.active = staged.into_committed_state();
        inner.generation = next_generation;
        match kind {
            PendingTransitionKind::SendMessageZero => inner.first_send_header = None,
            PendingTransitionKind::ReceiveMessageZero => inner.first_receive_spk_id = None,
            PendingTransitionKind::Normal => {}
        }
        Ok(())
    }

    /// Call when the SQLite transaction fails. The active ratchet state remains unchanged.
    pub fn discard_staged(&self) -> Result<(), CryptoError> {
        let mut inner = self.inner.lock().map_err(|_| CryptoError::InvalidField)?;
        inner.pending = None;
        inner.pending_kind = None;
        Ok(())
    }

    /// Seal the user's displayable message body for local persistence. `generation`
    /// must be the generation assigned to this message in the ratchet transaction.
    pub fn seal_local_message_body(
        &self,
        generation: u64,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        if generation == 0 {
            return Err(CryptoError::InvalidField);
        }
        let context = StorageRecordContext {
            record_type: StorageRecordType::MessageBody,
            generation,
            ..self.storage_context(generation)
        };
        let plaintext = Zeroizing::new(plaintext);
        self.cipher
            .seal(&context, &plaintext)
            .map_err(|_| CryptoError::InvalidField)
    }

    /// Open a previously sealed local message body. Wrong conversation or generation
    /// fails authentication; plaintext exists only for the returned UI/application buffer.
    pub fn open_local_message_body(
        &self,
        generation: u64,
        sealed_body: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        if generation == 0 {
            return Err(CryptoError::InvalidField);
        }
        let context = StorageRecordContext {
            record_type: StorageRecordType::MessageBody,
            generation,
            ..self.storage_context(generation)
        };
        let plaintext = self
            .cipher
            .open(&context, &sealed_body)
            .map_err(|_| CryptoError::InvalidField)?;
        Ok(plaintext.to_vec())
    }
    pub fn pending_snapshot(&self) -> Result<Vec<u8>, CryptoError> {
        let inner = self.inner.lock().map_err(|_| CryptoError::InvalidField)?;
        inner
            .pending
            .as_ref()
            .map(|pending| pending.encrypted_snapshot().to_vec())
            .ok_or(CryptoError::InvalidField)
    }
}

impl AccountContext {
    /// Generate a new DSK-signed SPK. Publish raw_signed_prekey(); persist
    /// seal_for_storage() beside it. OPKs are deliberately not represented here.
    pub fn generate_signed_prekey(
        &self,
        epoch: u64,
        spk_id: u32,
    ) -> Result<std::sync::Arc<SignedPrekeyContext>, CryptoError> {
        let epoch = messaging_epoch(epoch)?;
        if spk_id == 0 {
            return Err(CryptoError::InvalidField);
        }
        let spk_private = XSecret::random_from_rng(OsRng);
        let spk_private_bytes = Zeroizing::new(spk_private.to_bytes());
        let spk_public = XPublicKey::from(&spk_private).to_bytes();
        let dsk = SigningKey::from_bytes(&self.dsk_seed);
        let raw_signed_prekey = sign_signed_prekey_v1(
            &dsk,
            self.account_id,
            epoch as u64,
            self.device_id,
            spk_id,
            spk_public,
        )
        .map_err(|_| CryptoError::InvalidField)?;
        Ok(std::sync::Arc::new(SignedPrekeyContext {
            account_id: self.account_id,
            device_id: self.device_id,
            epoch,
            spk_id,
            raw_signed_prekey,
            spk_private: spk_private_bytes,
        }))
    }

    /// Restore a private SPK only when its public signed object belongs to this
    /// exact account, device and DSK, and the encrypted private record matches.
    pub fn restore_signed_prekey(
        &self,
        raw_signed_prekey: Vec<u8>,
        encrypted_private_record: Vec<u8>,
        storage_key: Vec<u8>,
    ) -> Result<std::sync::Arc<SignedPrekeyContext>, CryptoError> {
        let parsed = SignedPrekeyV1::parse(&raw_signed_prekey)
            .map_err(|_| CryptoError::InvalidField)?;
        let dsk_public = SigningKey::from_bytes(&self.dsk_seed).verifying_key().to_bytes();
        parsed.verify(&dsk_public).map_err(|_| CryptoError::InvalidField)?;
        if parsed.account_id != self.account_id || parsed.device_id != self.device_id {
            return Err(CryptoError::InvalidField);
        }
        let cipher = messaging_storage_cipher(storage_key)?;
        let context = signed_prekey_storage_context(
            self.account_id,
            self.device_id,
            parsed.account_epoch,
            parsed.spk_id,
        );
        let plaintext = cipher
            .open(&context, &encrypted_private_record)
            .map_err(|_| CryptoError::InvalidField)?;
        let private_bytes = Zeroizing::new(messaging_fixed::<32>(&plaintext)?);
        let private = XSecret::from(*private_bytes);
        if XPublicKey::from(&private).to_bytes() != parsed.spk_pub {
            return Err(CryptoError::InvalidField);
        }
        Ok(std::sync::Arc::new(SignedPrekeyContext {
            account_id: parsed.account_id,
            device_id: parsed.device_id,
            epoch: parsed.account_epoch,
            spk_id: parsed.spk_id,
            raw_signed_prekey,
            spk_private: private_bytes,
        }))
    }

    /// Create the initiating side of a first-contact session. The peer's signed
    /// prekey is verified before X3DH. The only supported first release is SPK-only.
    #[allow(clippy::too_many_arguments)]
    pub fn create_initiator_session(
        &self,
        peer_account_id: Vec<u8>,
        peer_device_id: Vec<u8>,
        peer_epoch: u64,
        peer_dsk_public: Vec<u8>,
        peer_ddhk_public: Vec<u8>,
        peer_signed_prekey: Vec<u8>,
        session_id: Vec<u8>,
        local_epoch: u64,
        storage_key: Vec<u8>,
    ) -> Result<std::sync::Arc<MessagingSession>, CryptoError> {
        let local_epoch = messaging_epoch(local_epoch)?;
        let peer_epoch = messaging_epoch(peer_epoch)?;
        let peer_account_id = messaging_fixed::<16>(&peer_account_id)?;
        let peer_device_id = messaging_fixed::<16>(&peer_device_id)?;
        let peer_dsk_public = messaging_fixed::<32>(&peer_dsk_public)?;
        let peer_ddhk_public = messaging_fixed::<32>(&peer_ddhk_public)?;
        let session_id = messaging_session_id(&session_id)?;
        if peer_account_id == [0u8; 16] || peer_device_id == [0u8; 16] {
            return Err(CryptoError::InvalidField);
        }

        let signed_prekey = SignedPrekeyV1::parse(&peer_signed_prekey)
            .map_err(|_| CryptoError::InvalidField)?;
        signed_prekey
            .verify(&peer_dsk_public)
            .map_err(|_| CryptoError::InvalidField)?;
        if signed_prekey.account_id != peer_account_id
            || signed_prekey.device_id != peer_device_id
            || signed_prekey.account_epoch != peer_epoch
        {
            return Err(CryptoError::InvalidField);
        }

        let ik_a = XSecret::from(*self.ddhk_seed);
        let ek_a = XSecret::random_from_rng(OsRng);
        let ek_a_public = XPublicKey::from(&ek_a).to_bytes();
        let shared_secret = crate::x3dh::initiator_derive_sk(
            &ik_a,
            &ek_a,
            &peer_ddhk_public,
            &signed_prekey.spk_pub,
            None,
            local_epoch,
            peer_epoch,
        )
        .map_err(|_| CryptoError::InvalidField)?;

        let ratchet_private = XSecret::random_from_rng(OsRng);
        let ratchet_public = XPublicKey::from(&ratchet_private).to_bytes();
        let ratchet = RatchetState::init_alice(
            &*shared_secret,
            &signed_prekey.spk_pub,
            ratchet_private,
        )
        .map_err(|_| CryptoError::InvalidField)?;

        let local_ddhk_public = XPublicKey::from(&ik_a).to_bytes();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CryptoError::EntropyFailure)?
            .as_secs();
        if timestamp == 0 {
            return Err(CryptoError::EntropyFailure);
        }
        let local_dsk = SigningKey::from_bytes(&self.dsk_seed);
        let cert_dh = crate::x3dh::cert_dh_sign(
            &local_dsk,
            &self.account_id,
            &self.device_id,
            &local_ddhk_public,
            timestamp,
        );
        let first_header = PrekeyHandshakeHeader {
            sender_account_id: self.account_id,
            sender_account_epoch: local_epoch,
            sender_dsk_pub: local_dsk.verifying_key().to_bytes(),
            sender_ddhk_pub: local_ddhk_public,
            sender_cert_dh: cert_dh,
            sender_cert_dh_timestamp: timestamp,
            sender_ephemeral_pub: ek_a_public,
            recipient_spk_id: signed_prekey.spk_id,
            recipient_opk_id: None,
            initial_ratchet_pub: ratchet_public,
            sequence_number: 0,
        };
        let cipher = messaging_storage_cipher(storage_key)?;

        Ok(std::sync::Arc::new(MessagingSession {
            local_account_id: self.account_id,
            local_device_id: self.device_id,
            local_epoch,
            peer_account_id,
            peer_device_id,
            peer_epoch,
            session_id,
            cipher,
            inner: Mutex::new(MessagingSessionInner {
                active: ratchet,
                generation: 0,
                pending: None,
                pending_kind: None,
                first_send_header: Some(first_header),
                first_receive_spk_id: None,
            }),
        }))
    }

    /// Create the responder session from a locally held signed-prekey handle
    /// and the sender's canonical first envelope. stage_decrypt_message() then
    /// authenticates Message 0 and returns plaintext only on success.
    pub fn accept_prekey_message(
        &self,
        prekey: std::sync::Arc<SignedPrekeyContext>,
        session_id: Vec<u8>,
        local_epoch: u64,
        envelope_wire: Vec<u8>,
        storage_key: Vec<u8>,
    ) -> Result<std::sync::Arc<MessagingSession>, CryptoError> {
        let local_epoch = messaging_epoch(local_epoch)?;
        let session_id = messaging_session_id(&session_id)?;
        if prekey.account_id != self.account_id
            || prekey.device_id != self.device_id
            || prekey.epoch != local_epoch
        {
            return Err(CryptoError::InvalidField);
        }
        let envelope = MessageEnvelopeV1::decode(&envelope_wire)
            .map_err(|_| CryptoError::InvalidField)?;
        if !envelope.is_prekey_handshake
            || envelope.recipient_device_id != self.device_id
            || envelope.account_epoch != local_epoch
        {
            return Err(CryptoError::InvalidField);
        }
        let header = PrekeyHandshakeHeader::decode(&envelope.ratchet_header_bytes)
            .map_err(|_| CryptoError::InvalidField)?;
        if header.recipient_spk_id != prekey.spk_id || header.recipient_opk_id.is_some() {
            return Err(CryptoError::InvalidField);
        }

        let ik_b = XSecret::from(*self.ddhk_seed);
        let spk_b = XSecret::from(*prekey.spk_private);
        let shared_secret = crate::x3dh::responder_derive_sk(
            &ik_b,
            &spk_b,
            None,
            &header.sender_ddhk_pub,
            &header.sender_ephemeral_pub,
            header.sender_account_epoch,
            local_epoch,
        )
        .map_err(|_| CryptoError::InvalidField)?;
        let ratchet = RatchetState::init_bob(&*shared_secret, spk_b);
        let cipher = messaging_storage_cipher(storage_key)?;

        Ok(std::sync::Arc::new(MessagingSession {
            local_account_id: self.account_id,
            local_device_id: self.device_id,
            local_epoch,
            peer_account_id: header.sender_account_id,
            peer_device_id: envelope.sender_device_id,
            peer_epoch: header.sender_account_epoch,
            session_id,
            cipher,
            inner: Mutex::new(MessagingSessionInner {
                active: ratchet,
                generation: 0,
                pending: None,
                pending_kind: None,
                first_send_header: None,
                first_receive_spk_id: Some(prekey.spk_id),
            }),
        }))
    }

    /// Restore a session snapshot from the application's encrypted SQLite row.
    /// The optional public prekey header is needed only for an initiator that
    /// persisted a newly-created session before sending Message 0.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_messaging_session(
        &self,
        peer_account_id: Vec<u8>,
        peer_device_id: Vec<u8>,
        local_epoch: u64,
        peer_epoch: u64,
        session_id: Vec<u8>,
        generation: u64,
        encrypted_snapshot: Vec<u8>,
        first_prekey_header: Vec<u8>,
        storage_key: Vec<u8>,
    ) -> Result<std::sync::Arc<MessagingSession>, CryptoError> {
        let local_epoch = messaging_epoch(local_epoch)?;
        let peer_epoch = messaging_epoch(peer_epoch)?;
        let peer_account_id = messaging_fixed::<16>(&peer_account_id)?;
        let peer_device_id = messaging_fixed::<16>(&peer_device_id)?;
        let session_id = messaging_session_id(&session_id)?;
        if peer_account_id == [0u8; 16] || peer_device_id == [0u8; 16] {
            return Err(CryptoError::InvalidField);
        }
        let cipher = messaging_storage_cipher(storage_key)?;
        let context = StorageRecordContext {
            record_type: StorageRecordType::RatchetSnapshot,
            account_id: self.account_id,
            device_id: self.device_id,
            session_id,
            generation,
        };
        let active = restore_ratchet_state(&encrypted_snapshot, &cipher, &context)
            .map_err(|_| CryptoError::InvalidField)?;
        // The public first-prekey header remains in the SQLite row as historical metadata.
        // It is actionable only before Message 0. Once the persisted ratchet has advanced,
        // restore it as an established session and use normal Double Ratchet encryption.
        let first_send_header = if generation == 0 && !first_prekey_header.is_empty() {
            Some(
                PrekeyHandshakeHeader::decode(&first_prekey_header)
                    .map_err(|_| CryptoError::InvalidField)?,
            )
        } else {
            None
        };
        if let Some(header) = first_send_header.as_ref() {
            if header.sender_account_id != self.account_id
                || header.sender_account_epoch != local_epoch
            {
                return Err(CryptoError::InvalidField);
            }
        }

        Ok(std::sync::Arc::new(MessagingSession {
            local_account_id: self.account_id,
            local_device_id: self.device_id,
            local_epoch,
            peer_account_id,
            peer_device_id,
            peer_epoch,
            session_id,
            cipher,
            inner: Mutex::new(MessagingSessionInner {
                active,
                generation,
                pending: None,
                pending_kind: None,
                first_send_header,
                first_receive_spk_id: None,
            }),
        }))
    }
}

#[cfg(test)]
mod messaging_session_tests {
    use super::*;

    #[test]
    fn two_native_accounts_complete_prekey_and_bidirectional_ratchet_messages() {
        let alice = identity_initialize().expect("initialize Alice");
        let bob = identity_initialize().expect("initialize Bob");
        let storage_a = vec![0xA1; 32];
        let storage_b = vec![0xB2; 32];
        let session_id = vec![0x33; 16];
        let spk = bob.generate_signed_prekey(1, 7).expect("generate Bob SPK");

        let alice_session = alice
            .create_initiator_session(
                bob.account_id(),
                bob.device_id(),
                1,
                bob.dsk_public_key(),
                bob.ddhk_public_key(),
                spk.raw_signed_prekey(),
                session_id.clone(),
                1,
                storage_a.clone(),
            )
            .expect("create Alice session");

        // Simulate the historical public header retained in the initiator's SQLite row.
        let alice_first_prekey_header = alice_session
            .initial_prekey_header()
            .expect("capture Alice initial prekey header");
        assert!(!alice_first_prekey_header.is_empty());

        let first_wire = alice_session            .stage_encrypt_message(vec![0x51; 16], b"hello from Alice".to_vec())
            .expect("stage first message");
        let alice_pending = alice_session.pending_snapshot().expect("Alice snapshot");
        assert!(!alice_pending.is_empty());
        alice_session.commit_staged().expect("commit Alice message");

        let bob_session = bob
            .accept_prekey_message(
                spk,
                session_id.clone(),
                1,
                first_wire.clone(),
                storage_b.clone(),
            )
            .expect("create Bob responder session");
        let first_plaintext = bob_session
            .stage_decrypt_message(first_wire)
            .expect("authenticate and decrypt Message 0");
        assert_eq!(first_plaintext, b"hello from Alice");
        assert!(!bob_session.pending_snapshot().expect("Bob snapshot").is_empty());
        bob_session.commit_staged().expect("commit Bob receive");

        let follow_up = alice_session
            .stage_encrypt_message(vec![0x52; 16], b"second Alice message".to_vec())
            .expect("stage Alice follow-up");
        let follow_plaintext = bob_session
            .stage_decrypt_message(follow_up)
            .expect("decrypt Alice follow-up");
        assert_eq!(follow_plaintext, b"second Alice message");
        bob_session.commit_staged().expect("commit Bob follow-up");
        alice_session.commit_staged().expect("commit Alice follow-up");

        // Regression: initiator rows retain their original public first-prekey header.
        // After generation advances, restoring that row must send a normal ratchet message,
        // not incorrectly attempt to encrypt a second Message 0.
        let alice_durable_snapshot = alice_session
            .current_snapshot()
            .expect("durable Alice snapshot");
        let alice_restored = alice
            .restore_messaging_session(
                bob.account_id(),
                bob.device_id(),
                1,
                1,
                session_id.clone(),
                2,
                alice_durable_snapshot,
                alice_first_prekey_header,
                storage_a.clone(),
            )
            .expect("restore established Alice initiator with historical prekey header");

        let after_restart = alice_restored
            .stage_encrypt_message(vec![0x54; 16], b"Alice after initiator restore".to_vec())
            .expect("restored established initiator must send a normal ratchet message");
        let after_restart_plaintext = bob_session
            .stage_decrypt_message(after_restart)
            .expect("Bob decrypts message after Alice initiator restore");
        assert_eq!(after_restart_plaintext, b"Alice after initiator restore");
        bob_session
            .commit_staged()
            .expect("commit Bob post-restore receive");
        alice_restored
            .commit_staged()
            .expect("commit Alice post-restore send");

        let bob_durable_snapshot = bob_session.current_snapshot().expect("durable Bob snapshot");
        let bob_restored = bob
            .restore_messaging_session(
                alice.account_id(),
                alice.device_id(),
                1,
                1,
                session_id,
                3,
                bob_durable_snapshot,
                Vec::new(),
                storage_b,
            )
            .expect("restore Bob after restart");

        let reply = bob_restored
            .stage_encrypt_message(vec![0x53; 16], b"reply from Bob".to_vec())
            .expect("stage Bob reply");
        let reply_plaintext = alice_restored
            .stage_decrypt_message(reply)
            .expect("decrypt Bob reply after Alice restore");
        assert_eq!(reply_plaintext, b"reply from Bob");
        assert!(!alice_restored.pending_snapshot().expect("Alice reply snapshot").is_empty());
        alice_restored
            .commit_staged()
            .expect("commit Alice receive after restore");
        bob_restored.commit_staged().expect("commit Bob send");
    }
}

#[cfg(test)]
mod messaging_body_storage_tests {
    use super::*;

    #[test]
    fn message_body_storage_is_encrypted_and_bound_to_session_generation() {
        let alice = identity_initialize().expect("initialize Alice");
        let bob = identity_initialize().expect("initialize Bob");
        let storage_key = vec![0xA7; 32];
        let bob_spk = bob.generate_signed_prekey(1, 19).expect("generate Bob SPK");
        let session = alice
            .create_initiator_session(
                bob.account_id(),
                bob.device_id(),
                1,
                bob.dsk_public_key(),
                bob.ddhk_public_key(),
                bob_spk.raw_signed_prekey(),
                vec![0x29; 16],
                1,
                storage_key,
            )
            .expect("create messaging session");

        let plaintext = b"private message body must not be stored in SQLite".to_vec();
        let sealed = session
            .seal_local_message_body(1, plaintext.clone())
            .expect("seal message body");
        assert!(!sealed.windows(plaintext.len()).any(|part| part == plaintext.as_slice()));
        assert_eq!(
            session.open_local_message_body(1, sealed.clone()).unwrap(),
            plaintext
        );
        assert!(session.open_local_message_body(2, sealed.clone()).is_err());

        let mut tampered = sealed;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        assert!(session.open_local_message_body(1, tampered).is_err());
        assert!(session.seal_local_message_body(0, b"invalid generation".to_vec()).is_err());
    }
}

// Key Transparency V1 verification bridge.
// All cryptographic parsing and proof verification stays in native Rust.

fn kt_fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::InvalidField)
}

fn kt_decode_exact_map(raw: &[u8], expected_fields: u64) -> Result<std::collections::BTreeMap<u64, crate::cbor::Value>, CryptoError> {
    if raw.is_empty() || !crate::cbor::is_canonical(raw) {
        return Err(CryptoError::InvalidField);
    }
    let decoded = crate::cbor::decode_strict(raw).map_err(|_| CryptoError::InvalidField)?;
    let crate::cbor::Value::Map(pairs) = decoded else {
        return Err(CryptoError::InvalidField);
    };
    let mut fields = std::collections::BTreeMap::new();
    for (key, value) in pairs {
        let crate::cbor::Value::Int(key) = key else {
            return Err(CryptoError::InvalidField);
        };
        if key < 1 || key > expected_fields as i128 {
            return Err(CryptoError::InvalidField);
        }
        if fields.insert(key as u64, value).is_some() {
            return Err(CryptoError::InvalidField);
        }
    }
    if fields.len() != expected_fields as usize {
        return Err(CryptoError::InvalidField);
    }
    Ok(fields)
}

fn kt_take_uint(
    fields: &mut std::collections::BTreeMap<u64, crate::cbor::Value>,
    key: u64,
) -> Result<u64, CryptoError> {
    match fields.remove(&key) {
        Some(crate::cbor::Value::Int(value)) if (0..=u64::MAX as i128).contains(&value) => {
            Ok(value as u64)
        }
        _ => Err(CryptoError::InvalidField),
    }
}

fn kt_take_bytes(
    fields: &mut std::collections::BTreeMap<u64, crate::cbor::Value>,
    key: u64,
) -> Result<Vec<u8>, CryptoError> {
    match fields.remove(&key) {
        Some(crate::cbor::Value::Bytes(value)) => Ok(value),
        _ => Err(CryptoError::InvalidField),
    }
}

fn kt_take_fixed<const N: usize>(
    fields: &mut std::collections::BTreeMap<u64, crate::cbor::Value>,
    key: u64,
) -> Result<[u8; N], CryptoError> {
    let value = kt_take_bytes(fields, key)?;
    kt_fixed::<N>(&value)
}

fn kt_take_hash_array(
    value: crate::cbor::Value,
    max_items: usize,
    exact_items: Option<usize>,
) -> Result<Vec<[u8; 32]>, CryptoError> {
    let crate::cbor::Value::Array(items) = value else {
        return Err(CryptoError::InvalidField);
    };
    if items.len() > max_items || exact_items.is_some_and(|expected| items.len() != expected) {
        return Err(CryptoError::InvalidField);
    }
    items
        .into_iter()
        .map(|item| match item {
            crate::cbor::Value::Bytes(bytes) => kt_fixed::<32>(&bytes),
            _ => Err(CryptoError::InvalidField),
        })
        .collect()
}

fn kt_parse_witness_registry(
    raw: &[u8],
) -> Result<std::collections::BTreeMap<[u8; 16], [u8; 32]>, CryptoError> {
    if raw.is_empty() || !crate::cbor::is_canonical(raw) {
        return Err(CryptoError::InvalidField);
    }
    let decoded = crate::cbor::decode_strict(raw).map_err(|_| CryptoError::InvalidField)?;
    let crate::cbor::Value::Map(pairs) = decoded else {
        return Err(CryptoError::InvalidField);
    };
    // V1 has three configured witnesses and a 2-of-3 threshold. Registry keys are
    // trusted configuration supplied by the client, never taken from the response.
    if pairs.len() != 3 {
        return Err(CryptoError::InvalidField);
    }
    let mut registry = std::collections::BTreeMap::new();
    for (key, value) in pairs {
        let crate::cbor::Value::Bytes(id) = key else {
            return Err(CryptoError::InvalidField);
        };
        let crate::cbor::Value::Bytes(public) = value else {
            return Err(CryptoError::InvalidField);
        };
        let id = kt_fixed::<16>(&id)?;
        let public = kt_fixed::<32>(&public)?;
        if registry.insert(id, public).is_some() {
            return Err(CryptoError::InvalidField);
        }
    }
    Ok(registry)
}

/// Verify a complete gateway current-device proof bundle and (when a prior STH
/// is supplied) the history consistency transition from that prior STH.
///
/// `proof_bundle` and `consistency_bundle` are the exact canonical PM-CBOR
/// responses from the candidate KT proof endpoints. `previous_sth` is the
/// previously accepted signed tree head, or empty on first contact. The log
/// public key, log ID, expected account/device IDs, and three-witness registry
/// are trusted client configuration / caller context, not response fields.
///
/// The result is canonical PM-CBOR map:
///  1 version, 2 status (1 VERIFIED, 2 DEGRADED), 3 tree_size,
///  4 signed_sth, 5 sth_digest, 6 log_id, 7 smt_root, 8 history_root,
///  9 leaf_wire, 10 account_id, 11 epoch, 12 device_id, 13 dsk_pub,
/// 14 ddhk_pub, 15 cert_dh, 16 spk_pub, 17 push_pk.
pub fn kt_verify_device_proof_v1(
    proof_bundle: Vec<u8>,
    consistency_bundle: Vec<u8>,
    previous_sth: Vec<u8>,
    log_public_key: Vec<u8>,
    expected_log_id: Vec<u8>,
    expected_account_id: Vec<u8>,
    expected_device_id: Vec<u8>,
    witness_registry: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    use crate::cbor::Value;

    let log_public_key = kt_fixed::<32>(&log_public_key)?;
    let expected_log_id = kt_fixed::<32>(&expected_log_id)?;
    let expected_account_id = kt_fixed::<16>(&expected_account_id)?;
    let expected_device_id = kt_fixed::<16>(&expected_device_id)?;
    let registry = kt_parse_witness_registry(&witness_registry)?;

    // Current-device proof response: exact fields 1..14.
    let mut fields = kt_decode_exact_map(&proof_bundle, 14)?;
    if kt_take_uint(&mut fields, 1)? != 1 {
        return Err(CryptoError::InvalidField);
    }
    let leaf_wire = kt_take_bytes(&mut fields, 2)?;
    let supplied_smt_key = kt_take_fixed::<32>(&mut fields, 3)?;
    let supplied_leaf_hash = kt_take_fixed::<32>(&mut fields, 4)?;
    let supplied_smt_root = kt_take_fixed::<32>(&mut fields, 5)?;
    let smt_siblings_value = fields.remove(&6).ok_or(CryptoError::InvalidField)?;
    let smt_siblings = kt_take_hash_array(smt_siblings_value, 256, Some(256))?;
    let history_sequence = kt_take_uint(&mut fields, 7)?;
    let supplied_history_root = kt_take_fixed::<32>(&mut fields, 8)?;
    let history_index = kt_take_uint(&mut fields, 9)?;
    let history_entry_wire = kt_take_bytes(&mut fields, 10)?;
    let history_proof_value = fields.remove(&11).ok_or(CryptoError::InvalidField)?;
    let history_proof = kt_take_hash_array(history_proof_value, 64, None)?;
    let sth_wire = kt_take_bytes(&mut fields, 12)?;
    let supplied_tree_size = kt_take_uint(&mut fields, 13)?;
    let witness_values = match fields.remove(&14) {
        Some(Value::Array(items)) if items.len() <= 3 => items,
        _ => return Err(CryptoError::InvalidField),
    };
    if !fields.is_empty() {
        return Err(CryptoError::InvalidField);
    }

    let leaf = crate::transparency_v1::verify_leaf(&leaf_wire)
        .map_err(|_| CryptoError::InvalidField)?;
    if leaf.account_id != expected_account_id || leaf.device_id != expected_device_id {
        return Err(CryptoError::InvalidField);
    }
    let computed_smt_key = crate::transparency_v1::smt_key(&leaf.account_id, &leaf.device_id);
    if supplied_smt_key != computed_smt_key {
        return Err(CryptoError::InvalidField);
    }
    let computed_leaf_hash = crate::transparency_v1::leaf_hash(&leaf_wire)
        .map_err(|_| CryptoError::InvalidField)?;
    if supplied_leaf_hash != computed_leaf_hash {
        return Err(CryptoError::InvalidField);
    }
    crate::transparency_v1::verify_smt_inclusion(
        &computed_smt_key,
        &computed_leaf_hash,
        &smt_siblings,
        &supplied_smt_root,
    )
    .map_err(|_| CryptoError::InvalidField)?;

    let history_entry = crate::transparency_v1::decode_history_entry(&history_entry_wire)
        .map_err(|_| CryptoError::InvalidField)?;
    if history_entry.sequence != history_sequence
        || history_entry.smt_key != computed_smt_key
        || history_entry.leaf_hash != computed_leaf_hash
    {
        return Err(CryptoError::InvalidField);
    }
    let history_index = usize::try_from(history_index).map_err(|_| CryptoError::InvalidField)?;
    let tree_size = usize::try_from(supplied_tree_size).map_err(|_| CryptoError::InvalidField)?;
    if tree_size == 0 {
        return Err(CryptoError::InvalidField);
    }
    crate::transparency_v1::verify_history_inclusion(
        &history_entry_wire,
        history_index,
        tree_size,
        &history_proof,
        &supplied_history_root,
    )
    .map_err(|_| CryptoError::InvalidField)?;

    let sth = crate::transparency_v1::verify_sth(&sth_wire, &log_public_key)
        .map_err(|_| CryptoError::InvalidField)?;
    if sth.log_id != expected_log_id
        || sth.tree_size != supplied_tree_size
        || sth.smt_root != supplied_smt_root
        || sth.history_root != supplied_history_root
    {
        return Err(CryptoError::InvalidField);
    }

    // Check append-only continuity. First contact has no previous STH and must
    // not submit a consistency response. Subsequent observations must not roll
    // back and must carry a valid RFC6962-style history consistency proof.
    if previous_sth.is_empty() {
        if !consistency_bundle.is_empty() {
            return Err(CryptoError::InvalidField);
        }
    } else {
        let previous = crate::transparency_v1::verify_sth(&previous_sth, &log_public_key)
            .map_err(|_| CryptoError::InvalidField)?;
        if previous.log_id != expected_log_id || previous.tree_size > sth.tree_size {
            return Err(CryptoError::InvalidField);
        }
        if previous.tree_size == sth.tree_size {
            if crate::transparency_v1::is_sth_equivocation(&previous, &sth)
                || !consistency_bundle.is_empty()
            {
                return Err(CryptoError::InvalidField);
            }
        } else {
            let mut consistency = kt_decode_exact_map(&consistency_bundle, 7)?;
            if kt_take_uint(&mut consistency, 1)? != 1 {
                return Err(CryptoError::InvalidField);
            }
            let old_size = kt_take_uint(&mut consistency, 2)?;
            let new_size = kt_take_uint(&mut consistency, 3)?;
            let old_root = kt_take_fixed::<32>(&mut consistency, 4)?;
            let new_root = kt_take_fixed::<32>(&mut consistency, 5)?;
            let proof_value = consistency.remove(&6).ok_or(CryptoError::InvalidField)?;
            let consistency_proof = kt_take_hash_array(proof_value, 64, None)?;
            let consistency_sth_wire = kt_take_bytes(&mut consistency, 7)?;
            if !consistency.is_empty()
                || old_size != previous.tree_size
                || new_size != sth.tree_size
                || old_root != previous.history_root
                || new_root != sth.history_root
                || consistency_sth_wire != sth_wire
            {
                return Err(CryptoError::InvalidField);
            }
            crate::transparency_v1::verify_history_consistency(
                usize::try_from(old_size).map_err(|_| CryptoError::InvalidField)?,
                usize::try_from(new_size).map_err(|_| CryptoError::InvalidField)?,
                &old_root,
                &new_root,
                &consistency_proof,
            )
            .map_err(|_| CryptoError::InvalidField)?;
        }
    }

    // Verify each supplied witness statement against the pinned three-key
    // registry. Unknown, duplicate, malformed, invalidly signed, mismatched,
    // or conflicting statements are security failures. Missing quorum is a
    // valid DEGRADED result, never silently upgraded to VERIFIED.
    let mut statements = Vec::with_capacity(witness_values.len());
    let mut witness_ids = std::collections::BTreeSet::new();
    for item in witness_values {
        let Value::Bytes(raw_statement) = item else {
            return Err(CryptoError::InvalidField);
        };
        let statement = crate::transparency_v1::verify_witness_statement(&raw_statement, &registry)
            .map_err(|_| CryptoError::InvalidField)?;
        if statement.log_id != sth.log_id
            || statement.tree_size != sth.tree_size
            || statement.sth_digest != sth.sth_digest
            || !witness_ids.insert(statement.witness_id)
        {
            return Err(CryptoError::InvalidField);
        }
        statements.push(statement);
    }
    if crate::transparency_v1::witness_conflict_exists(&statements) {
        return Err(CryptoError::InvalidField);
    }
    let status = if crate::transparency_v1::witness_quorum_count(&statements, &sth) >= 2 {
        1u64 // VERIFIED
    } else {
        2u64 // DEGRADED
    };

    crate::cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(2), Value::Int(status as i128)),
        (Value::Int(3), Value::Int(sth.tree_size as i128)),
        (Value::Int(4), Value::Bytes(sth_wire)),
        (Value::Int(5), Value::Bytes(sth.sth_digest.to_vec())),
        (Value::Int(6), Value::Bytes(sth.log_id.to_vec())),
        (Value::Int(7), Value::Bytes(sth.smt_root.to_vec())),
        (Value::Int(8), Value::Bytes(sth.history_root.to_vec())),
        (Value::Int(9), Value::Bytes(leaf_wire)),
        (Value::Int(10), Value::Bytes(leaf.account_id.to_vec())),
        (Value::Int(11), Value::Int(leaf.epoch as i128)),
        (Value::Int(12), Value::Bytes(leaf.device_id.to_vec())),
        (Value::Int(13), Value::Bytes(leaf.dsk_pub.to_vec())),
        (Value::Int(14), Value::Bytes(leaf.ddhk_pub.to_vec())),
        (Value::Int(15), Value::Bytes(leaf.cert_dh.to_vec())),
        (Value::Int(16), Value::Bytes(leaf.spk_pub.to_vec())),
        (Value::Int(17), Value::Bytes(leaf.push_pk.to_vec())),
    ]))
    .map_err(|_| CryptoError::InvalidField)
}

/// Verify that a separately fetched signed-prekey is the exact DSK-signed key
/// committed in the already-verified KT leaf. Returns the original raw object.
/// Controlled-alpha pairing verifier. The caller must already have compared the
/// identity fingerprint out of band. This verifies the candidate SPK signature
/// and binds its account/device/epoch fields to that pinned identity. It does
/// not prove enrollment, revocation, transparency or production authorization.
pub fn verify_signed_prekey_for_peer_v1(
    raw_signed_prekey: Vec<u8>,
    dsk_public_key: Vec<u8>,
    expected_account_id: Vec<u8>,
    expected_epoch: u64,
    expected_device_id: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    if dsk_public_key.len() != 32
        || expected_account_id.len() != 16
        || expected_device_id.len() != 16
        || !(1..=u32::MAX as u64).contains(&expected_epoch)
        || raw_signed_prekey.is_empty()
        || raw_signed_prekey.len() > 4096
    {
        return Err(CryptoError::InvalidField);
    }

    let dsk: [u8; 32] = dsk_public_key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidField)?;
    let account: [u8; 16] = expected_account_id
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidField)?;
    let device: [u8; 16] = expected_device_id
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidField)?;

    let prekey = crate::signed_prekey_v1::SignedPrekeyV1::parse(&raw_signed_prekey)
        .map_err(|_| CryptoError::InvalidField)?;
    prekey.verify(&dsk).map_err(|_| CryptoError::InvalidField)?;
    if prekey.account_id != account
        || prekey.account_epoch as u64 != expected_epoch
        || prekey.device_id != device
    {
        return Err(CryptoError::InvalidField);
    }
    Ok(prekey.raw().to_vec())
}
pub fn kt_verify_signed_prekey_binding_v1(
    leaf_wire: Vec<u8>,
    signed_prekey_wire: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let leaf = crate::transparency_v1::verify_leaf(&leaf_wire)
        .map_err(|_| CryptoError::InvalidField)?;
    let prekey = crate::signed_prekey_v1::SignedPrekeyV1::parse(&signed_prekey_wire)
        .map_err(|_| CryptoError::InvalidField)?;
    prekey
        .verify(&leaf.dsk_pub)
        .map_err(|_| CryptoError::InvalidField)?;
    if prekey.account_id != leaf.account_id
        || prekey.account_epoch as u64 != leaf.epoch
        || prekey.device_id != leaf.device_id
        || prekey.spk_pub != leaf.spk_pub
    {
        return Err(CryptoError::InvalidField);
    }
    Ok(prekey.raw().to_vec())
}

#[cfg(test)]
mod kt_ffi_v1_tests {
    use super::*;
    use crate::cbor::Value;

    #[test]
    fn kt_witness_registry_requires_exactly_three_unique_entries() {
        let registry = Value::Map((1u8..=3u8).map(|id| {
            (Value::Bytes(vec![id; 16]), Value::Bytes(vec![id; 32]))
        }).collect());
        let raw = crate::cbor::encode_canonical(&registry).unwrap();
        assert_eq!(kt_parse_witness_registry(&raw).unwrap().len(), 3);

        let short = Value::Map(vec![
            (Value::Bytes(vec![1; 16]), Value::Bytes(vec![1; 32])),
            (Value::Bytes(vec![2; 16]), Value::Bytes(vec![2; 32])),
        ]);
        let short_raw = crate::cbor::encode_canonical(&short).unwrap();
        assert!(kt_parse_witness_registry(&short_raw).is_err());
    }

    #[test]
    fn kt_proof_map_rejects_unknown_or_missing_fields() {
        let missing = crate::cbor::encode_canonical(&Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
        ])).unwrap();
        assert!(kt_decode_exact_map(&missing, 2).is_err());

        let unknown = crate::cbor::encode_canonical(&Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(3), Value::Int(3)),
        ])).unwrap();
        assert!(kt_decode_exact_map(&unknown, 2).is_err());
    }
}
