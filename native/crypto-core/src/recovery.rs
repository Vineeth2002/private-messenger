//! Recovery key derivation (Model A, identity-epoch rekeying):
//!   BIP-39 (24 words, English, NFKD) -> PBKDF2-HMAC-SHA512 (salt "mnemonic", 2048, 64 B)
//!   -> HKDF-SHA256 -> Ed25519 recovery seed -> public key -> IRC commitment.
//!
//! The server stores only the IRC commitment, never any private recovery material.
//! The mnemonic is a deliberate, audited FFI exception (setup/import only); callers
//! must not persist it and must release references immediately. Managed-runtime
//! zeroization is best-effort and is NOT guaranteed on Android/iOS.
//!
//! IMPLEMENTATION DECISION: `IRC = SHA-256(ascii("PM-V1-RECOVERY-COMMITMENT") || K_rec_pub)`
//! is a plain byte concatenation (no length prefix), exactly as written in the spec.

use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

pub const BIP39_SALT: &[u8] = b"mnemonic";
pub const BIP39_ITERATIONS: u32 = 2048;
pub const RECOVERY_HKDF_SALT: &[u8] = b"PM-V1-RECOVERY-KEY-SALT-v1";
pub const RECOVERY_HKDF_INFO: &[u8] = b"PM-V1-RECOVERY-KEY-ED25519-v1";
pub const RECOVERY_COMMITMENT_DOMAIN: &[u8] = b"PM-V1-RECOVERY-COMMITMENT";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecoveryError {
    #[error("invalid BIP-39 mnemonic (wordlist/checksum)")]
    InvalidMnemonic,
    #[error("mnemonic must be exactly 24 words (256-bit entropy)")]
    WrongWordCount,
    #[error("HKDF expansion failed")]
    Hkdf,
    #[error("secure entropy generation failed")]
    EntropyFailure,
    #[error("invalid BIP-39 entropy length")]
    InvalidEntropy,
}

/// Normalize (NFKD) and validate a 24-word English BIP-39 mnemonic; return the
/// 64-byte BIP-39 master seed (empty passphrase).
pub fn bip39_master_seed(mnemonic: &str) -> Result<Zeroizing<[u8; 64]>, RecoveryError> {
    let normalized: Zeroizing<String> = Zeroizing::new(mnemonic.nfkd().collect::<String>());
    let parsed = Mnemonic::parse_in_normalized(Language::English, normalized.as_str())
        .map_err(|_| RecoveryError::InvalidMnemonic)?;
    if parsed.word_count() != 24 {
        return Err(RecoveryError::WrongWordCount);
    }
    let mut seed = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<Sha512>(
        normalized.as_bytes(),
        BIP39_SALT,
        BIP39_ITERATIONS,
        &mut seed[..],
    );
    Ok(seed)
}

/// `K_rec_seed` (== Ed25519 private seed `K_rec_priv`) from the 64-byte master seed.
pub fn derive_recovery_seed(master_seed: &[u8; 64]) -> Result<Zeroizing<[u8; 32]>, RecoveryError> {
    let hk = Hkdf::<Sha256>::new(Some(RECOVERY_HKDF_SALT), master_seed); // HKDF-Extract
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(RECOVERY_HKDF_INFO, &mut okm[..])
        .map_err(|_| RecoveryError::Hkdf)?; // HKDF-Expand
    Ok(okm)
}

/// Ed25519 recovery signing key (RFC 8032). Zeroizes on drop (dalek `zeroize` feature).
pub fn recovery_signing_key(mnemonic: &str) -> Result<SigningKey, RecoveryError> {
    let master = bip39_master_seed(mnemonic)?;
    let seed = derive_recovery_seed(&master)?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn identity_recovery_commitment(k_rec_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RECOVERY_COMMITMENT_DOMAIN);
    h.update(k_rec_pub);
    h.finalize().into()
}

/// Sign with the recovery key (used for epoch-transition certificates later).
pub fn recovery_sign(key: &SigningKey, msg: &[u8]) -> [u8; 64] {
    key.sign(msg).to_bytes()
}


/// Generate a fresh English BIP-39 recovery phrase from 256 bits of OS-backed entropy.
/// The phrase is secret recovery material: callers must display it only during setup and
/// must not log it, persist it in ordinary application storage, or send it to the gateway.
pub fn generate_recovery_mnemonic() -> Result<String, RecoveryError> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut *entropy)
        .map_err(|_| RecoveryError::EntropyFailure)?;

    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy[..])
        .map_err(|_| RecoveryError::InvalidEntropy)?;
    Ok(mnemonic.to_string())
}

#[cfg(test)]
mod generated_mnemonic_tests {
    use super::*;

    #[test]
    fn generated_phrase_is_valid_24_word_english_bip39() {
        let phrase = generate_recovery_mnemonic().expect("OS entropy and BIP-39 generation");
        let parsed = Mnemonic::parse_in_normalized(Language::English, &phrase)
            .expect("generated phrase must pass the BIP-39 checksum");
        assert_eq!(parsed.word_count(), 24);
        let seed = bip39_master_seed(&phrase).expect("generated phrase must derive a seed");
        assert_eq!(seed.len(), 64);
    }
}