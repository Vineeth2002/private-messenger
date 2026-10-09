//! RFC 9180 HPKE Base mode for the Sovereign Private Messenger push boundary.
//!
//! Suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305.
//! This module implements only Base mode. It provides confidentiality, not
//! sender authentication; callers must treat the push channel as a wake-up
//! hint and authenticate application content separately.

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

type Secret32 = Zeroizing<[u8; 32]>;

pub const KEM_ID: u16 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
pub const KDF_ID: u16 = 0x0001; // HKDF-SHA256
pub const AEAD_ID: u16 = 0x0003; // ChaCha20Poly1305
pub const NK: usize = 32;
pub const NN: usize = 12;
pub const NT: usize = 16;
pub const NSECRET: usize = 32;

const MODE_BASE: u8 = 0x00;
const HPKE_V1: &[u8] = b"HPKE-v1";
const KEM_LABEL_EAE_PRK: &[u8] = b"eae_prk";
const KEM_LABEL_SHARED_SECRET: &[u8] = b"shared_secret";
const KDF_LABEL_PSK_ID_HASH: &[u8] = b"psk_id_hash";
const KDF_LABEL_INFO_HASH: &[u8] = b"info_hash";
const KDF_LABEL_SECRET: &[u8] = b"secret";
const KDF_LABEL_KEY: &[u8] = b"key";
const KDF_LABEL_BASE_NONCE: &[u8] = b"base_nonce";

const _: () = assert!(NK == 32);
const _: () = assert!(NN == 12);
const _: () = assert!(NT == 16);
const _: () = assert!(NSECRET == 32);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HpkeError {
    #[error("non-contributory X25519 output")]
    NonContributoryDh,
    #[error("HPKE KDF failure")]
    Kdf,
    #[error("HPKE AEAD sealing failed")]
    AeadSealFailed,
    #[error("HPKE AEAD authentication failed")]
    AeadOpenFailed,
    #[error("HPKE sequence exhausted")]
    SequenceExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncapsulatedKey {
    pub enc: [u8; 32],
}

pub struct HpkeSenderContext {
    key: Secret32,
    base_nonce: [u8; NN],
    seq: u64,
}

pub struct HpkeReceiverContext {
    key: Secret32,
    base_nonce: [u8; NN],
    seq: u64,
}

fn kem_suite_id() -> [u8; 5] {
    [b'K', b'E', b'M', (KEM_ID >> 8) as u8, KEM_ID as u8]
}

fn hpke_suite_id() -> [u8; 10] {
    [
        b'H',
        b'P',
        b'K',
        b'E',
        (KEM_ID >> 8) as u8,
        KEM_ID as u8,
        (KDF_ID >> 8) as u8,
        KDF_ID as u8,
        (AEAD_ID >> 8) as u8,
        AEAD_ID as u8,
    ]
}

fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Secret32 {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(HPKE_V1);
    mac.update(suite_id);
    mac.update(label);
    mac.update(ikm);
    let out = mac.finalize().into_bytes();
    let mut r = Zeroizing::new([0u8; 32]);
    r.copy_from_slice(out.as_slice());
    r
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Secret32, HpkeError> {
    if len > u16::MAX as usize || len > 255 * 32 {
        return Err(HpkeError::Kdf);
    }
    let mut labeled_info =
        Vec::with_capacity(2 + HPKE_V1.len() + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(len as u16).to_be_bytes());
    labeled_info.extend_from_slice(HPKE_V1);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| HpkeError::Kdf)?;
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&labeled_info, &mut out[..len])
        .map_err(|_| HpkeError::Kdf)?;
    Ok(out)
}

fn dhkem_encap(sk_e: &StaticSecret, pk_r: &[u8; 32]) -> Result<([u8; 32], Secret32), HpkeError> {
    let pk_e = PublicKey::from(sk_e);
    let pk_r = PublicKey::from(*pk_r);
    let dh = sk_e.diffie_hellman(&pk_r);
    if !dh.was_contributory() {
        return Err(HpkeError::NonContributoryDh);
    }

    let enc = pk_e.to_bytes();
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(&enc);
    kem_context[32..].copy_from_slice(pk_r.as_bytes());

    let suite = kem_suite_id();
    let eae_prk = labeled_extract(&suite, &[], KEM_LABEL_EAE_PRK, dh.as_bytes());
    let shared_secret = labeled_expand(
        &suite,
        &eae_prk,
        KEM_LABEL_SHARED_SECRET,
        &kem_context,
        NSECRET,
    )?;
    Ok((enc, shared_secret))
}

fn dhkem_decap(sk_r: &StaticSecret, enc: &[u8; 32]) -> Result<Secret32, HpkeError> {
    let pk_e = PublicKey::from(*enc);
    let pk_r = PublicKey::from(sk_r);
    let dh = sk_r.diffie_hellman(&pk_e);
    if !dh.was_contributory() {
        return Err(HpkeError::NonContributoryDh);
    }

    let suite = kem_suite_id();
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(enc);
    kem_context[32..].copy_from_slice(pk_r.as_bytes());

    let eae_prk = labeled_extract(&suite, &[], KEM_LABEL_EAE_PRK, dh.as_bytes());
    labeled_expand(
        &suite,
        &eae_prk,
        KEM_LABEL_SHARED_SECRET,
        &kem_context,
        NSECRET,
    )
}

fn key_schedule_base(
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<(Secret32, [u8; NN]), HpkeError> {
    let suite = hpke_suite_id();
    let psk_id_hash = labeled_extract(&suite, &[], KDF_LABEL_PSK_ID_HASH, &[]);
    let info_hash = labeled_extract(&suite, &[], KDF_LABEL_INFO_HASH, info);

    let mut context = Vec::with_capacity(1 + 32 + 32);
    context.push(MODE_BASE);
    context.extend_from_slice(&psk_id_hash[..]);
    context.extend_from_slice(&info_hash[..]);

    let secret = labeled_extract(&suite, shared_secret, KDF_LABEL_SECRET, &[]);
    let key = labeled_expand(&suite, &secret, KDF_LABEL_KEY, &context, NK)?;
    let base_nonce_secret = labeled_expand(&suite, &secret, KDF_LABEL_BASE_NONCE, &context, NN)?;

    let mut base_nonce = [0u8; NN];
    base_nonce.copy_from_slice(&base_nonce_secret[..NN]);
    Ok((key, base_nonce))
}

fn nonce_for(base_nonce: &[u8; NN], seq: u64) -> [u8; NN] {
    let mut seq_bytes = [0u8; NN];
    seq_bytes[NN - 8..].copy_from_slice(&seq.to_be_bytes());
    let mut nonce = [0u8; NN];
    for i in 0..NN {
        nonce[i] = base_nonce[i] ^ seq_bytes[i];
    }
    nonce
}

impl HpkeSenderContext {
    fn new(key: Secret32, base_nonce: [u8; NN]) -> Self {
        Self {
            key,
            base_nonce,
            seq: 0,
        }
    }

    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        if self.seq == u64::MAX {
            return Err(HpkeError::SequenceExhausted);
        }
        let nonce = nonce_for(&self.base_nonce, self.seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key[..]));
        let mut ct = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut ct)
            .map_err(|_| HpkeError::AeadSealFailed)?;
        ct.extend_from_slice(&tag);
        self.seq += 1;
        Ok(ct)
    }
}

impl HpkeReceiverContext {
    fn new(key: Secret32, base_nonce: [u8; NN]) -> Self {
        Self {
            key,
            base_nonce,
            seq: 0,
        }
    }

    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        if self.seq == u64::MAX {
            return Err(HpkeError::SequenceExhausted);
        }
        if ciphertext.len() < NT {
            return Err(HpkeError::AeadOpenFailed);
        }
        let nonce = nonce_for(&self.base_nonce, self.seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key[..]));
        let split = ciphertext.len() - NT;
        let (ct, tag_bytes) = ciphertext.split_at(split);
        let tag = chacha20poly1305::Tag::from_slice(tag_bytes);
        let mut pt = ct.to_vec();
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut pt, tag)
            .map_err(|_| HpkeError::AeadOpenFailed)?;
        self.seq += 1;
        Ok(pt)
    }
}

/// Sender setup for HPKE Base mode with a caller-supplied ephemeral private key.
pub fn setup_base_sender_with_ephemeral(
    recipient_public: &[u8; 32],
    info: &[u8],
    ephemeral_private: [u8; 32],
) -> Result<(EncapsulatedKey, HpkeSenderContext), HpkeError> {
    let sk_e = StaticSecret::from(ephemeral_private);
    let (enc, shared_secret) = dhkem_encap(&sk_e, recipient_public)?;
    let (key, base_nonce) = key_schedule_base(&shared_secret, info)?;
    Ok((
        EncapsulatedKey { enc },
        HpkeSenderContext::new(key, base_nonce),
    ))
}

/// Sender setup for HPKE Base mode using a fresh random ephemeral private key.
pub fn setup_base_sender(
    recipient_public: &[u8; 32],
    info: &[u8],
) -> Result<(EncapsulatedKey, HpkeSenderContext), HpkeError> {
    let mut ephemeral_private = [0u8; 32];
    OsRng.fill_bytes(&mut ephemeral_private);
    setup_base_sender_with_ephemeral(recipient_public, info, ephemeral_private)
}

/// Recipient setup for HPKE Base mode.
pub fn setup_base_receiver(
    recipient_private: [u8; 32],
    enc: &[u8; 32],
    info: &[u8],
) -> Result<HpkeReceiverContext, HpkeError> {
    let sk_r = StaticSecret::from(recipient_private);
    let shared_secret = dhkem_decap(&sk_r, enc)?;
    let (key, base_nonce) = key_schedule_base(&shared_secret, info)?;
    Ok(HpkeReceiverContext::new(key, base_nonce))
}

/// One-shot HPKE Base seal for the notification wake-up boundary.
///
/// A fresh sender context is created for one notification and the sequence is fixed
/// at zero. The push transport is stateless: no HPKE sender context is persisted.
pub fn seal_base_stateless(
    recipient_public: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(EncapsulatedKey, Vec<u8>), HpkeError> {
    let (enc, mut sender) = setup_base_sender(recipient_public, info)?;
    let ciphertext = sender.seal(aad, plaintext)?;
    Ok((enc, ciphertext))
}

/// Deterministic one-shot variant used only by shared test vectors.
pub(crate) fn seal_base_stateless_with_ephemeral(
    recipient_public: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ephemeral_private: [u8; 32],
) -> Result<(EncapsulatedKey, Vec<u8>), HpkeError> {
    let (enc, mut sender) =
        setup_base_sender_with_ephemeral(recipient_public, info, ephemeral_private)?;
    let ciphertext = sender.seal(aad, plaintext)?;
    Ok((enc, ciphertext))
}

/// One-shot HPKE Base open for the notification wake-up boundary.
pub fn open_base_stateless(
    recipient_private: [u8; 32],
    enc: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    let mut receiver = setup_base_receiver(recipient_private, enc, info)?;
    receiver.open(aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().expect("wrong length")
    }

    #[test]
    fn rfc9180_a2_base_chacha20poly1305_matches() {
        let info = hex("4f6465206f6e2061204772656369616e2055726e");
        let sk_e = arr::<32>("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
        let sk_r = arr::<32>("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let expected_enc =
            arr::<32>("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let expected_shared =
            arr::<32>("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7");
        let expected_key =
            arr::<32>("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91");
        let expected_base_nonce = arr::<12>("5c4d98150661b848853b547f");
        let expected_secret =
            arr::<32>("5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6");

        let sk_r_static = StaticSecret::from(sk_r);
        let pk_r = PublicKey::from(&sk_r_static).to_bytes();
        assert_eq!(
            hex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"),
            pk_r
        );

        let sk_e_static = StaticSecret::from(sk_e);
        let (enc, shared_secret) = dhkem_encap(&sk_e_static, &pk_r).unwrap();
        assert_eq!(enc, expected_enc);
        assert_eq!(&shared_secret[..], &expected_shared[..]);

        let suite = hpke_suite_id();
        let psk_id_hash = labeled_extract(&suite, &[], KDF_LABEL_PSK_ID_HASH, &[]);
        let info_hash = labeled_extract(&suite, &[], KDF_LABEL_INFO_HASH, &info);
        let mut context = Vec::with_capacity(65);
        context.push(MODE_BASE);
        context.extend_from_slice(&psk_id_hash[..]);
        context.extend_from_slice(&info_hash[..]);
        let secret = labeled_extract(&suite, &shared_secret[..], KDF_LABEL_SECRET, &[]);
        assert_eq!(&secret[..], &expected_secret[..]);

        assert_eq!(
            hex("00431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5b69c5718a60cc5876c358d3f7fc31ddb598503f67be58ea1e798c0bb19eb9796"),
            context
        );
        let (key, base_nonce) = key_schedule_base(&shared_secret, &info).unwrap();
        assert_eq!(&key[..], &expected_key[..]);
        assert_eq!(base_nonce, expected_base_nonce);

        let plaintext = hex("4265617574792069732074727574682c20747275746820626561757479");
        let aad = hex("436f756e742d30");
        let expected_ct = hex("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28");

        let mut sender = HpkeSenderContext::new(key.clone(), base_nonce);
        let ct = sender.seal(&aad, &plaintext).unwrap();
        assert_eq!(ct, expected_ct);

        let mut receiver = HpkeReceiverContext::new(key, base_nonce);
        assert_eq!(receiver.open(&aad, &ct).unwrap(), plaintext);

        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        let mut receiver = HpkeReceiverContext::new(
            labeled_expand(&suite, &secret, KDF_LABEL_KEY, &context, NK).unwrap(),
            base_nonce,
        );
        assert_eq!(
            receiver.open(&aad, &tampered),
            Err(HpkeError::AeadOpenFailed)
        );
    }

    #[test]
    fn rfc9180_base_round_trip_changes_nonce_by_sequence() {
        let sk_r = arr::<32>("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let sk_r_static = StaticSecret::from(sk_r);
        let pk_r = PublicKey::from(&sk_r_static).to_bytes();
        let info = b"pm-push-test";
        let (enc, mut sender) = setup_base_sender_with_ephemeral(&pk_r, info, [7u8; 32]).unwrap();
        let mut receiver = setup_base_receiver(sk_r, &enc.enc, info).unwrap();
        let a = sender.seal(b"aad-0", b"one").unwrap();
        let b = sender.seal(b"aad-1", b"two").unwrap();
        assert_ne!(a, b);
        assert_eq!(receiver.open(b"aad-0", &a).unwrap(), b"one");
        assert_eq!(receiver.open(b"aad-1", &b).unwrap(), b"two");
    }

    #[test]
    fn low_order_enc_fails_closed() {
        let sk_r = [9u8; 32];
        assert!(matches!(
            setup_base_receiver(sk_r, &[0u8; 32], b""),
            Err(HpkeError::NonContributoryDh)
        ));
    }
}

#[cfg(test)]
#[path = "hpke_push_vector_tests.rs"]
mod push_vector_tests;
