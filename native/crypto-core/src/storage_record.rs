//! Authenticated encryption for application records stored on the device.
//!
//! This module is deliberately below the UniFFI boundary. Ratchet snapshots must be
//! serialized, sealed, opened and restored inside Rust; plaintext ratchet snapshots must
//! never be returned to Kotlin or written to SQLite.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const RECORD_MAGIC: &[u8; 8] = b"PMSREC01";
const RECORD_DOMAIN: &[u8] = b"SOVEREIGN-PM-LOCAL-RECORD-v1";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = RECORD_MAGIC.len() + NONCE_BYTES;
pub(crate) const MAX_RECORD_PLAINTEXT: usize = 1_048_576;

/// Stable record classes. Changing these values is a storage-format migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum StorageRecordType {
    RatchetSnapshot = 1,
    SignedPrekeyPrivate = 2,
    OutboxEnvelope = 3,
    InboxMessage = 4,
    MessageBody = 5,
}

/// Values supplied by the trusted local database layer and authenticated as AEAD AAD.
/// Session ID may be zero only for account/device-scoped records such as a signed prekey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StorageRecordContext {
    pub(crate) record_type: StorageRecordType,
    pub(crate) account_id: [u8; 16],
    pub(crate) device_id: [u8; 16],
    pub(crate) session_id: [u8; 16],
    pub(crate) generation: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum StorageRecordError {
    #[error("invalid storage record context")]
    InvalidContext,
    #[error("storage record exceeds the configured size bound")]
    TooLarge,
    #[error("storage record is malformed or unsupported")]
    InvalidRecord,
    #[error("secure random generation failed")]
    EntropyFailure,
    #[error("storage record authentication failed")]
    AuthenticationFailed,
}

/// Holds the local Storage DEK only in zeroizing Rust memory.
pub(crate) struct StorageRecordCipher {
    key: Zeroizing<[u8; 32]>,
}

impl StorageRecordCipher {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    /// Encrypts one record. A fresh random nonce is generated for every call.
    /// The returned record is: magic/version || nonce || ciphertext || Poly1305 tag.
    pub(crate) fn seal(
        &self,
        context: &StorageRecordContext,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, StorageRecordError> {
        validate_context(context)?;
        if plaintext.len() > MAX_RECORD_PLAINTEXT {
            return Err(StorageRecordError::TooLarge);
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key[..])
            .map_err(|_| StorageRecordError::InvalidRecord)?;
        let aad = build_aad(context);
        let mut nonce = [0u8; NONCE_BYTES];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| StorageRecordError::EntropyFailure)?;

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| StorageRecordError::AuthenticationFailed)?;

        let mut record = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
        record.extend_from_slice(RECORD_MAGIC);
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&ciphertext);
        nonce.zeroize();
        Ok(record)
    }

    /// Authenticates metadata before returning plaintext. Plaintext is zeroized on drop.
    pub(crate) fn open(
        &self,
        context: &StorageRecordContext,
        record: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StorageRecordError> {
        validate_context(context)?;
        if record.len() < HEADER_BYTES + TAG_BYTES || &record[..RECORD_MAGIC.len()] != RECORD_MAGIC
        {
            return Err(StorageRecordError::InvalidRecord);
        }
        let ciphertext_len = record.len() - HEADER_BYTES;
        if ciphertext_len < TAG_BYTES || ciphertext_len > MAX_RECORD_PLAINTEXT + TAG_BYTES {
            return Err(StorageRecordError::TooLarge);
        }

        let nonce_start = RECORD_MAGIC.len();
        let nonce_end = nonce_start + NONCE_BYTES;
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key[..])
            .map_err(|_| StorageRecordError::InvalidRecord)?;
        let aad = build_aad(context);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&record[nonce_start..nonce_end]),
                Payload {
                    msg: &record[nonce_end..],
                    aad: &aad,
                },
            )
            .map_err(|_| StorageRecordError::AuthenticationFailed)?;

        if plaintext.len() > MAX_RECORD_PLAINTEXT {
            let mut plaintext = plaintext;
            plaintext.zeroize();
            return Err(StorageRecordError::TooLarge);
        }
        Ok(Zeroizing::new(plaintext))
    }
}

fn validate_context(context: &StorageRecordContext) -> Result<(), StorageRecordError> {
    if context.account_id == [0u8; 16] || context.device_id == [0u8; 16] {
        return Err(StorageRecordError::InvalidContext);
    }
    if matches!(
        context.record_type,
        StorageRecordType::RatchetSnapshot
            | StorageRecordType::OutboxEnvelope
            | StorageRecordType::InboxMessage
            | StorageRecordType::MessageBody
    ) && context.session_id == [0u8; 16]
    {
        return Err(StorageRecordError::InvalidContext);
    }
    Ok(())
}

fn build_aad(context: &StorageRecordContext) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECORD_DOMAIN.len() + 4 + 16 + 16 + 16 + 8);
    aad.extend_from_slice(RECORD_DOMAIN);
    aad.extend_from_slice(&(context.record_type as u32).to_be_bytes());
    aad.extend_from_slice(&context.account_id);
    aad.extend_from_slice(&context.device_id);
    aad.extend_from_slice(&context.session_id);
    aad.extend_from_slice(&context.generation.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> StorageRecordContext {
        StorageRecordContext {
            record_type: StorageRecordType::RatchetSnapshot,
            account_id: [0x11; 16],
            device_id: [0x22; 16],
            session_id: [0x33; 16],
            generation: 7,
        }
    }

    #[test]
    fn roundtrip_and_random_nonce() {
        let cipher = StorageRecordCipher::new([0x44; 32]);
        let plaintext = b"ratchet snapshot test payload";
        let first = cipher.seal(&context(), plaintext).unwrap();
        let second = cipher.seal(&context(), plaintext).unwrap();
        assert_ne!(first, second, "each record must use a fresh nonce");
        assert_eq!(
            cipher.open(&context(), &first).unwrap().as_slice(),
            plaintext
        );
        assert_eq!(
            cipher.open(&context(), &second).unwrap().as_slice(),
            plaintext
        );
    }

    #[test]
    fn rejects_metadata_substitution() {
        let cipher = StorageRecordCipher::new([0x44; 32]);
        let record = cipher.seal(&context(), b"secret").unwrap();

        let mut wrong = context();
        wrong.generation += 1;
        assert_eq!(
            cipher.open(&wrong, &record).unwrap_err(),
            StorageRecordError::AuthenticationFailed
        );

        let mut wrong = context();
        wrong.device_id = [0x55; 16];
        assert_eq!(
            cipher.open(&wrong, &record).unwrap_err(),
            StorageRecordError::AuthenticationFailed
        );

        let mut wrong = context();
        wrong.record_type = StorageRecordType::MessageBody;
        assert_eq!(
            cipher.open(&wrong, &record).unwrap_err(),
            StorageRecordError::AuthenticationFailed
        );
    }

    #[test]
    fn rejects_wrong_key_and_tampering() {
        let cipher = StorageRecordCipher::new([0x44; 32]);
        let record = cipher.seal(&context(), b"secret").unwrap();
        let wrong_key = StorageRecordCipher::new([0x45; 32]);
        assert_eq!(
            wrong_key.open(&context(), &record).unwrap_err(),
            StorageRecordError::AuthenticationFailed
        );

        let mut tampered = record.clone();
        *tampered.last_mut().unwrap() ^= 0x80;
        assert_eq!(
            cipher.open(&context(), &tampered).unwrap_err(),
            StorageRecordError::AuthenticationFailed
        );
    }

    #[test]
    fn rejects_truncated_and_oversized_records() {
        let cipher = StorageRecordCipher::new([0x44; 32]);
        assert_eq!(
            cipher.open(&context(), b"short").unwrap_err(),
            StorageRecordError::InvalidRecord
        );
        let mut too_large = vec![0u8; HEADER_BYTES + MAX_RECORD_PLAINTEXT + TAG_BYTES + 1];
        too_large[..RECORD_MAGIC.len()].copy_from_slice(RECORD_MAGIC);
        assert_eq!(
            cipher.open(&context(), &too_large).unwrap_err(),
            StorageRecordError::TooLarge
        );
    }

    #[test]
    fn rejects_invalid_contexts() {
        let cipher = StorageRecordCipher::new([0x44; 32]);
        let mut invalid = context();
        invalid.session_id = [0u8; 16];
        assert_eq!(
            cipher.seal(&invalid, b"secret").unwrap_err(),
            StorageRecordError::InvalidContext
        );
    }
}
