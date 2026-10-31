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
