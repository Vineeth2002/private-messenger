//! Double Ratchet foundational primitives for the Sovereign Private Messenger.
//!
//! Frozen protocol formulas (docs/phase0/03-crypto-architecture.md):
//!   KDF_RK(RK, DH_out):
//!       PRK_rk = HKDF-Extract(salt = RK, IKM = DH_out)
//!       RK_next = HKDF-Expand(PRK_rk, "PM-DR-RATCHET-ROOT-v1", 32)
//!       CK_out  = HKDF-Expand(PRK_rk, "PM-DR-RATCHET-CHAIN-v1", 32)
//!   KDF_CK(CK):
//!       K_msg = HMAC-SHA256(CK, 0x01)
//!       CK_next = HMAC-SHA256(CK, 0x02)
//!       return (CK_next, K_msg)
//!
//! This boundary intentionally does NOT implement the Double Ratchet state machine,
//! message encryption/decryption, skipped-message keys, replay handling, or
//! prekey-handshake ingestion.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const DR_ROOT_INFO: &[u8] = b"PM-DR-RATCHET-ROOT-v1";
pub const DR_CHAIN_INFO: &[u8] = b"PM-DR-RATCHET-CHAIN-v1";
pub const MSG_AAD: &[u8] = b"PM-V1-MSG-AAD";

const _: () = assert!(DR_ROOT_INFO.len() == 21);
const _: () = assert!(DR_CHAIN_INFO.len() == 22);
const _: () = assert!(MSG_AAD.len() == 13);

type HmacSha256 = Hmac<Sha256>;
pub type RatchetKey = [u8; 32];

/// Derive the next root key and an output chain key from a DH ratchet result.
///
/// Returns `(RK_next, CK_out)`.
pub fn kdf_rk(
    rk: &RatchetKey,
    dh_out: &RatchetKey,
) -> (Zeroizing<RatchetKey>, Zeroizing<RatchetKey>) {
    // Hkdf::new performs HKDF-Extract with salt = rk.
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);

    let mut rk_next = Zeroizing::new([0u8; 32]);
    let mut ck_out = Zeroizing::new([0u8; 32]);

    hk.expand(DR_ROOT_INFO, &mut rk_next[..])
        .expect("32-byte HKDF expansion is always valid");
    hk.expand(DR_CHAIN_INFO, &mut ck_out[..])
        .expect("32-byte HKDF expansion is always valid");

    (rk_next, ck_out)
}

/// Advance a symmetric sending/receiving chain.
///
/// Returns `(CK_next, K_msg)`. The message key is single-use and the caller must
/// discard the old chain key after advancing.
pub fn kdf_ck(ck: &RatchetKey) -> (Zeroizing<RatchetKey>, Zeroizing<RatchetKey>) {
    let mut msg_mac =
        <HmacSha256 as Mac>::new_from_slice(ck).expect("HMAC-SHA256 accepts a 32-byte key");
    msg_mac.update(&[0x01]);
    let msg = msg_mac.finalize().into_bytes();

    let mut next_mac =
        <HmacSha256 as Mac>::new_from_slice(ck).expect("HMAC-SHA256 accepts a 32-byte key");
    next_mac.update(&[0x02]);
    let next = next_mac.finalize().into_bytes();

    let mut k_msg = Zeroizing::new([0u8; 32]);
    let mut ck_next = Zeroizing::new([0u8; 32]);
    k_msg.copy_from_slice(&msg);
    ck_next.copy_from_slice(&next);

    (ck_next, k_msg)
}

/// Construct the frozen message AAD bytes.
///
/// `account_epoch` is the recipient's account epoch (`Epoch_B`).
/// `prekey_flag` is encoded as a single byte, 0 or 1.
/// `ratchet_header_bytes` are already canonical PM-CBOR-2026 bytes.
pub fn aad_msg(
    protocol_version: u8,
    envelope_id: &[u8; 16],
    sender_device_id: &[u8; 16],
    recipient_device_id: &[u8; 16],
    account_epoch: u32,
    prekey_flag: bool,
    ratchet_header_bytes: &[u8],
) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(MSG_AAD.len() + 1 + 16 + 16 + 16 + 4 + 1 + ratchet_header_bytes.len());
    aad.extend_from_slice(MSG_AAD);
    aad.push(protocol_version);
    aad.extend_from_slice(envelope_id);
    aad.extend_from_slice(sender_device_id);
    aad.extend_from_slice(recipient_device_id);
    aad.extend_from_slice(&account_epoch.to_be_bytes());
    aad.push(u8::from(prekey_flag));
    aad.extend_from_slice(ratchet_header_bytes);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_frozen() {
        assert_eq!(DR_ROOT_INFO, b"PM-DR-RATCHET-ROOT-v1");
        assert_eq!(DR_CHAIN_INFO, b"PM-DR-RATCHET-CHAIN-v1");
        assert_eq!(MSG_AAD, b"PM-V1-MSG-AAD");
    }

    #[test]
    fn kdf_ck_is_deterministic_and_advances() {
        let ck = [0x01u8; 32];
        let (ck_next, k_msg) = kdf_ck(&ck);

        assert_ne!(*ck_next, ck);
        assert_ne!(k_msg, ck_next);

        let (ck_next_2, k_msg_2) = kdf_ck(&ck);
        assert_eq!(ck_next_2, ck_next);
        assert_eq!(k_msg_2, k_msg);

        let (_, k_msg_advanced) = kdf_ck(&ck_next);
        assert_ne!(k_msg_advanced, k_msg);
    }

    #[test]
    fn aad_msg_uses_big_endian_recipient_epoch_and_boolean_flag() {
        let aad = aad_msg(
            1,
            &[0x10; 16],
            &[0x20; 16],
            &[0x30; 16],
            0x01020304,
            true,
            &[0xAB, 0xCD],
        );

        assert_eq!(&aad[..13], MSG_AAD);
        assert_eq!(aad[13], 1);
        assert_eq!(&aad[14..30], &[0x10; 16]);
        assert_eq!(&aad[30..46], &[0x20; 16]);
        assert_eq!(&aad[46..62], &[0x30; 16]);
        assert_eq!(&aad[62..66], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(aad[66], 1);
        assert_eq!(&aad[67..], &[0xAB, 0xCD]);
    }

    #[test]
    fn aad_msg_can_encode_false_prekey_flag() {
        let aad = aad_msg(1, &[0; 16], &[1; 16], &[2; 16], 0, false, &[]);
        assert_eq!(aad.last().copied(), Some(0));
        assert_eq!(aad.len(), 13 + 1 + 16 + 16 + 16 + 4 + 1);
    }
}
