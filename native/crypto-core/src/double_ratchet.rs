//! Double Ratchet foundational primitives and the frozen Message 0 boundary.
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
//! This boundary implements the frozen Message 0 path only. Normal post-handshake
//! messages, skipped-message keys, replay windows, and the complete DH ratchet state
//! machine are still outside this boundary.

use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::cbor::{self, CborError, Value};
use crate::x3dh::{self, X3dhError};

pub const DR_ROOT_INFO: &[u8] = b"PM-DR-RATCHET-ROOT-v1";
pub const DR_CHAIN_INFO: &[u8] = b"PM-DR-RATCHET-CHAIN-v1";
pub const MSG_AAD: &[u8] = b"PM-V1-MSG-AAD";
pub const ZERO_MESSAGE_NONCE: [u8; 12] = [0u8; 12];

const _: () = assert!(DR_ROOT_INFO.len() == 21);
const _: () = assert!(DR_CHAIN_INFO.len() == 22);
const _: () = assert!(MSG_AAD.len() == 13);

type HmacSha256 = Hmac<Sha256>;
pub type RatchetKey = [u8; 32];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RatchetError {
    #[error("non-contributory X25519 output")]
    NonContributoryDh,
    #[error("malformed prekey handshake header")]
    InvalidHeader,
    #[error("unsupported or unknown prekey handshake header field")]
    UnknownHeaderField,
    #[error("prekey handshake header sequence number must be zero")]
    InvalidHeaderSequence,
    #[error("recipient signed prekey id mismatch")]
    RecipientSpkIdMismatch,
    #[error("recipient one-time prekey id mismatch")]
    RecipientOpkIdMismatch,
    #[error("ratchet state is not in the expected initial state")]
    InvalidInitialState,
    #[error("message authentication failed")]
    AeadAuthFailure,
    #[error("certificate verification failed: {0}")]
    CertDh(#[from] X3dhError),
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    #[error("AEAD encryption failed")]
    AeadEncrypt,
    #[error("message decryption failed")]
    AeadDecrypt,
}

/// Frozen PM-CBOR-2026 PrekeyHandshakeHeader (fields 1-11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrekeyHandshakeHeader {
    pub sender_account_id: [u8; 16],
    pub sender_account_epoch: u32,
    pub sender_dsk_pub: [u8; 32],
    pub sender_ddhk_pub: [u8; 32],
    pub sender_cert_dh: [u8; 64],
    pub sender_cert_dh_timestamp: u64,
    pub sender_ephemeral_pub: [u8; 32],
    pub recipient_spk_id: u32,
    pub recipient_opk_id: Option<u32>,
    pub initial_ratchet_pub: [u8; 32],
    pub sequence_number: u32,
}

impl PrekeyHandshakeHeader {
    /// Encode the exact canonical PM-CBOR-2026 bytes used inside AAD_msg.
    pub fn encode(&self) -> Result<Vec<u8>, RatchetError> {
        if self.sequence_number != 0 {
            return Err(RatchetError::InvalidHeaderSequence);
        }

        let mut pairs = vec![
            (Value::Int(1), Value::Bytes(self.sender_account_id.to_vec())),
            (
                Value::Int(2),
                Value::Int(self.sender_account_epoch as i128),
            ),
            (Value::Int(3), Value::Bytes(self.sender_dsk_pub.to_vec())),
            (Value::Int(4), Value::Bytes(self.sender_ddhk_pub.to_vec())),
            (Value::Int(5), Value::Bytes(self.sender_cert_dh.to_vec())),
            (
                Value::Int(6),
                Value::Int(self.sender_cert_dh_timestamp as i128),
            ),
            (Value::Int(7), Value::Bytes(self.sender_ephemeral_pub.to_vec())),
            (Value::Int(8), Value::Int(self.recipient_spk_id as i128)),
        ];
        if let Some(id) = self.recipient_opk_id {
            pairs.push((Value::Int(9), Value::Int(id as i128)));
        }
        pairs.push((
            Value::Int(10),
            Value::Bytes(self.initial_ratchet_pub.to_vec()),
        ));
        pairs.push((Value::Int(11), Value::Int(0)));
        Ok(cbor::encode_canonical(&Value::Map(pairs))?)
    }

    /// Decode and strictly validate the frozen 11-field header.
    /// `decode_strict` rejects non-canonical wire bytes before this semantic validation runs.
    pub fn decode(bytes: &[u8]) -> Result<Self, RatchetError> {
        let value = cbor::decode_strict(bytes)?;
        let pairs = match value {
            Value::Map(pairs) => pairs,
            _ => return Err(RatchetError::InvalidHeader),
        };

        let mut f1 = None;
        let mut f2 = None;
        let mut f3 = None;
        let mut f4 = None;
        let mut f5 = None;
        let mut f6 = None;
        let mut f7 = None;
        let mut f8 = None;
        let mut f9 = None;
        let mut f10 = None;
        let mut f11 = None;

        for (key, val) in pairs {
            let key = match key {
                Value::Int(n) => n,
                _ => return Err(RatchetError::UnknownHeaderField),
            };
            let slot = match key {
                1 => &mut f1,
                2 => &mut f2,
                3 => &mut f3,
                4 => &mut f4,
                5 => &mut f5,
                6 => &mut f6,
                7 => &mut f7,
                8 => &mut f8,
                9 => &mut f9,
                10 => &mut f10,
                11 => &mut f11,
                _ => return Err(RatchetError::UnknownHeaderField),
            };
            *slot = Some(val);
        }

        Ok(Self {
            sender_account_id: bytes16(take_required(&mut f1)?)?,
            sender_account_epoch: u32_value(take_required(&mut f2)?)?,
            sender_dsk_pub: bytes32(take_required(&mut f3)?)?,
            sender_ddhk_pub: bytes32(take_required(&mut f4)?)?,
            sender_cert_dh: bytes64(take_required(&mut f5)?)?,
            sender_cert_dh_timestamp: u64_value(take_required(&mut f6)?)?,
            sender_ephemeral_pub: bytes32(take_required(&mut f7)?)?,
            recipient_spk_id: u32_value(take_required(&mut f8)?)?,
            recipient_opk_id: match f9.take() {
                Some(v) => Some(u32_value(v)?),
                None => None,
            },
            initial_ratchet_pub: bytes32(take_required(&mut f10)?)?,
            sequence_number: u32_value(take_required(&mut f11)?)?,
        })
        .and_then(|h| {
            if h.sequence_number != 0 {
                Err(RatchetError::InvalidHeaderSequence)
            } else {
                Ok(h)
            }
        })
    }
}

fn take_required(slot: &mut Option<Value>) -> Result<Value, RatchetError> {
    slot.take().ok_or(RatchetError::InvalidHeader)
}

fn bytes_exact<const N: usize>(v: Value) -> Result<[u8; N], RatchetError> {
    match v {
        Value::Bytes(b) if b.len() == N => Ok(b.try_into().expect("length checked")),
        _ => Err(RatchetError::InvalidHeader),
    }
}

fn bytes16(v: Value) -> Result<[u8; 16], RatchetError> { bytes_exact(v) }
fn bytes32(v: Value) -> Result<[u8; 32], RatchetError> { bytes_exact(v) }
fn bytes64(v: Value) -> Result<[u8; 64], RatchetError> { bytes_exact(v) }

fn u32_value(v: Value) -> Result<u32, RatchetError> {
    match v {
        Value::Int(n) if (0..=u32::MAX as i128).contains(&n) => Ok(n as u32),
        _ => Err(RatchetError::InvalidHeader),
    }
}

fn u64_value(v: Value) -> Result<u64, RatchetError> {
    match v {
        Value::Int(n) if (0..=u64::MAX as i128).contains(&n) => Ok(n as u64),
        _ => Err(RatchetError::InvalidHeader),
    }
}

/// The minimum state representation needed by this boundary.
///
/// `dhs_priv` and chain/root keys are zeroized on drop. The state is deliberately
/// mutated only after Message 0 authentication succeeds on the Bob path.
pub struct RatchetState {
    rk: Zeroizing<RatchetKey>,
    dhs_priv: Zeroizing<RatchetKey>,
    dhs_pub: [u8; 32],
    dhr_pub: Option<[u8; 32]>,
    ck_s: Option<Zeroizing<RatchetKey>>,
    ck_r: Option<Zeroizing<RatchetKey>>,
    ns: u32,
    nr: u32,
    pn: u32,
}

impl RatchetState {
    /// Alice initialization from the X3DH session key and Bob's signed-prekey public key.
    /// `dhs_a0_priv` is supplied by the caller here; a later client integration boundary
    /// will generate it from the platform RNG.
    pub fn init_alice(
        sk: &RatchetKey,
        spk_b_pub: &[u8; 32],
        dhs_a0_priv: RatchetKey,
    ) -> Result<Self, RatchetError> {
        let dhs = StaticSecret::from(dhs_a0_priv);
        let dhr = PublicKey::from(*spk_b_pub);
        let dh = dhs.diffie_hellman(&dhr);
        if !dh.was_contributory() {
            return Err(RatchetError::NonContributoryDh);
        }
        let dh_out = *dh.as_bytes();
        let (rk, ck_s) = kdf_rk(sk, &dh_out);
        Ok(Self {
            rk,
            dhs_priv: Zeroizing::new(dhs_a0_priv),
            dhs_pub: PublicKey::from(&dhs).to_bytes(),
            dhr_pub: Some(*spk_b_pub),
            ck_s: Some(ck_s),
            ck_r: None,
            ns: 0,
            nr: 0,
            pn: 0,
        })
    }

    /// Bob's pre-ingestion state: DHS_B is the signed-prekey private key.
    pub fn init_bob(sk: &RatchetKey, spk_b_priv: RatchetKey) -> Self {
        let spk = StaticSecret::from(spk_b_priv);
        Self {
            rk: Zeroizing::new(*sk),
            dhs_priv: Zeroizing::new(spk_b_priv),
            dhs_pub: PublicKey::from(&spk).to_bytes(),
            dhr_pub: None,
            ck_s: None,
            ck_r: None,
            ns: 0,
            nr: 0,
            pn: 0,
        }
    }
}

/// The frozen MessageEnvelopeV1 fields used by Message 0 authentication.
pub struct MessageEnvelopeRef<'a> {
    pub protocol_version: u8,
    pub envelope_id: &'a [u8; 16],
    pub sender_device_id: &'a [u8; 16],
    pub recipient_device_id: &'a [u8; 16],
    pub account_epoch: u32,
    pub is_prekey_handshake: bool,
    pub ratchet_header_bytes: &'a [u8],
    pub ciphertext: &'a [u8],
}

/// Derive the next root key and an output chain key from a DH ratchet result.
/// Returns `(RK_next, CK_out)`.
pub fn kdf_rk(
    rk: &RatchetKey,
    dh_out: &RatchetKey,
) -> (Zeroizing<RatchetKey>, Zeroizing<RatchetKey>) {
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
/// Returns `(CK_next, K_msg)`.
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
/// `account_epoch` is the recipient's account epoch (`Epoch_B`).
pub fn aad_msg(
    protocol_version: u8,
    envelope_id: &[u8; 16],
    sender_device_id: &[u8; 16],
    recipient_device_id: &[u8; 16],
    account_epoch: u32,
    prekey_flag: bool,
    ratchet_header_bytes: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        MSG_AAD.len() + 1 + 16 + 16 + 16 + 4 + 1 + ratchet_header_bytes.len(),
    );
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

fn dh_bytes(priv_bytes: &[u8; 32], peer_pub: &[u8; 32]) -> Result<RatchetKey, RatchetError> {
    let secret = StaticSecret::from(*priv_bytes);
    let peer = PublicKey::from(*peer_pub);
    let dh = secret.diffie_hellman(&peer);
    if !dh.was_contributory() {
        return Err(RatchetError::NonContributoryDh);
    }
    Ok(*dh.as_bytes())
}

fn initial_state(state: &RatchetState) -> bool {
    state.dhr_pub.is_none()
        && state.ck_s.is_none()
        && state.ck_r.is_none()
        && state.ns == 0
        && state.nr == 0
        && state.pn == 0
}

/// Encrypt Message 0 and advance Alice's sending chain from Ns=0 to Ns=1.
/// The caller supplies the already validated complete PrekeyHandshakeHeader.
pub fn encrypt_message_0(
    state: &mut RatchetState,
    envelope: MessageEnvelopeRef<'_>,
    header: &PrekeyHandshakeHeader,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), RatchetError> {
    if state.ns != 0 || state.ck_s.is_none() || header.sequence_number != 0 {
        return Err(RatchetError::InvalidInitialState);
    }
    if header.initial_ratchet_pub != state.dhs_pub {
        return Err(RatchetError::InvalidHeader);
    }
    if !envelope.is_prekey_handshake {
        return Err(RatchetError::InvalidHeader);
    }

    let header_bytes = header.encode()?;
    if envelope.ratchet_header_bytes != header_bytes.as_slice() {
        return Err(RatchetError::InvalidHeader);
    }

    let (ck_next, k_msg) = kdf_ck(state.ck_s.as_ref().expect("checked Some"));
    let aad = aad_msg(
        envelope.protocol_version,
        envelope.envelope_id,
        envelope.sender_device_id,
        envelope.recipient_device_id,
        envelope.account_epoch,
        true,
        &header_bytes,
    );
    let cipher = ChaCha20Poly1305::new_from_slice(k_msg.as_ref()).map_err(|_| RatchetError::AeadEncrypt)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&ZERO_MESSAGE_NONCE),
            Payload { msg: plaintext, aad: &aad },
        )
        .map_err(|_| RatchetError::AeadEncrypt)?;

    state.ck_s = Some(ck_next);
    state.ns = 1;
    Ok((header_bytes, ciphertext))
}

fn ingest_message_0_inner(
    state: &mut RatchetState,
    envelope: MessageEnvelopeRef<'_>,
    expected_spk_id: u32,
    expected_opk_id: Option<u32>,
    dhs_b1_priv: RatchetKey,
) -> Result<Vec<u8>, RatchetError> {
    if !initial_state(state) {
        return Err(RatchetError::InvalidInitialState);
    }
    if !envelope.is_prekey_handshake {
        return Err(RatchetError::InvalidHeader);
    }

    let header = PrekeyHandshakeHeader::decode(envelope.ratchet_header_bytes)?;
    if header.recipient_spk_id != expected_spk_id {
        return Err(RatchetError::RecipientSpkIdMismatch);
    }
    if header.recipient_opk_id != expected_opk_id {
        return Err(RatchetError::RecipientOpkIdMismatch);
    }
    x3dh::cert_dh_verify(
        &header.sender_dsk_pub,
        &header.sender_account_id,
        envelope.sender_device_id,
        &header.sender_ddhk_pub,
        header.sender_cert_dh_timestamp,
        &header.sender_cert_dh,
    )?;

    // Step 1: temporary DH with Bob's current signed-prekey private key.
    let rk_b = &state.rk;
    let dh1 = dh_bytes(&state.dhs_priv, &header.initial_ratchet_pub)?;
    let (rk_temp, ck_r) = kdf_rk(rk_b, &dh1);

    // Step 2: generate a new Bob DH ratchet key. The old SPK private key is retired
    // only after successful authentication of Message 0.
    let dhs_b1 = StaticSecret::from(dhs_b1_priv);
    let dh2 = {
        let peer = PublicKey::from(header.initial_ratchet_pub);
        let shared = dhs_b1.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(RatchetError::NonContributoryDh);
        }
        *shared.as_bytes()
    };
    let (rk_final, ck_s) = kdf_rk(&rk_temp, &dh2);

    // Step 3: derive the first receiving message key and authenticate/decrypt.
    let (ck_r_after, k_msg) = kdf_ck(&ck_r);
    let aad = aad_msg(
        envelope.protocol_version,
        envelope.envelope_id,
        envelope.sender_device_id,
        envelope.recipient_device_id,
        envelope.account_epoch,
        true,
        envelope.ratchet_header_bytes,
    );
    let cipher = ChaCha20Poly1305::new_from_slice(k_msg.as_ref()).map_err(|_| RatchetError::AeadDecrypt)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&ZERO_MESSAGE_NONCE),
            Payload { msg: envelope.ciphertext, aad: &aad },
        )
        .map_err(|_| RatchetError::AeadAuthFailure)?;

    // Step 4: atomic commit ONLY after authentication succeeds.
    state.rk = rk_final;
    state.dhs_priv = Zeroizing::new(dhs_b1_priv);
    state.dhs_pub = PublicKey::from(&dhs_b1).to_bytes();
    state.dhr_pub = Some(header.initial_ratchet_pub);
    state.ck_s = Some(ck_s);
    state.ck_r = Some(ck_r_after);
    state.ns = 0;
    state.nr = 1;
    state.pn = 0;
    Ok(plaintext)
}

/// Bob ingestion with a fresh OS-backed X25519 ratchet key.
pub fn ingest_message_0(
    state: &mut RatchetState,
    envelope: MessageEnvelopeRef<'_>,
    expected_spk_id: u32,
    expected_opk_id: Option<u32>,
) -> Result<Vec<u8>, RatchetError> {
    let dhs_b1 = StaticSecret::random_from_rng(OsRng);
    ingest_message_0_inner(
        state,
        envelope,
        expected_spk_id,
        expected_opk_id,
        dhs_b1.to_bytes(),
    )
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

    fn hex_encode<T: AsRef<[u8]>>(b: T) -> String {
        b.as_ref()
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect()
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex_decode(s).try_into().expect("wrong length")
    }

    fn load() -> J {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/double_ratchet_linear.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("valid JSON")
    }

    fn load_x3dh() -> J {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/bi_x3dh_handshake.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("x3dh vector file"))
            .expect("valid JSON")
    }

    fn message_vector() -> J {
        load()["message_0"].clone()
    }

    fn header_from_vector(v: &J) -> PrekeyHandshakeHeader {
        let f = &v["prekey_handshake_header"]["fields"];
        PrekeyHandshakeHeader {
            sender_account_id: arr::<16>(f["1_sender_account_id"].as_str().unwrap()),
            sender_account_epoch: f["2_sender_account_epoch"].as_u64().unwrap() as u32,
            sender_dsk_pub: arr::<32>(f["3_sender_dsk_pub"].as_str().unwrap()),
            sender_ddhk_pub: arr::<32>(f["4_sender_ddhk_pub"].as_str().unwrap()),
            sender_cert_dh: arr::<64>(f["5_sender_cert_dh"].as_str().unwrap()),
            sender_cert_dh_timestamp: f["6_sender_cert_dh_timestamp"].as_u64().unwrap(),
            sender_ephemeral_pub: arr::<32>(f["7_sender_ephemeral_pub"].as_str().unwrap()),
            recipient_spk_id: f["8_recipient_spk_id"].as_u64().unwrap() as u32,
            recipient_opk_id: Some(f["9_recipient_opk_id"].as_u64().unwrap() as u32),
            initial_ratchet_pub: arr::<32>(f["10_initial_ratchet_pub"].as_str().unwrap()),
            sequence_number: f["11_sequence_number"].as_u64().unwrap() as u32,
        }
    }

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
        assert_ne!(*k_msg, *ck_next);
        let (ck_next_2, k_msg_2) = kdf_ck(&ck);
        assert_eq!(*ck_next_2, *ck_next);
        assert_eq!(*k_msg_2, *k_msg);
    }

    #[test]
    fn aad_msg_uses_big_endian_recipient_epoch_and_boolean_flag() {
        let aad = aad_msg(1, &[0x10; 16], &[0x20; 16], &[0x30; 16], 0x01020304, true, &[0xAB, 0xCD]);
        assert_eq!(&aad[..13], MSG_AAD);
        assert_eq!(&aad[62..66], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(aad[66], 1);
        assert_eq!(&aad[67..], &[0xAB, 0xCD]);
    }

    #[test]
    fn aad_msg_can_encode_false_prekey_flag() {
        let aad = aad_msg(1, &[0; 16], &[1; 16], &[2; 16], 0, false, &[]);
        assert_eq!(aad.last().copied(), Some(0));
    }

    #[test]
    fn header_round_trip_matches_frozen_bytes() {
        let v = message_vector();
        let header = header_from_vector(&v);
        let bytes = header.encode().unwrap();
        assert_eq!(hex_encode(&bytes), v["aad_inputs"]["ratchet_header_hex"]);
        assert_eq!(PrekeyHandshakeHeader::decode(&bytes).unwrap(), header);
    }

    #[test]
    fn message_zero_matches_frozen_vector() {
        let v = load();
        let msg = &v["message_0"];
        let x = load_x3dh();
        let case = &x["cases"][0];
        let sk = arr::<32>(v["sk"].as_str().unwrap());
        let spk_b_pub = arr::<32>(case["inputs"]["spk_b_pub"].as_str().unwrap());
        let dhs_a0_priv = arr::<32>(v["alice"]["dhs_a0_priv"].as_str().unwrap());
        let mut alice = RatchetState::init_alice(&sk, &spk_b_pub, dhs_a0_priv).unwrap();
        assert_eq!(hex_encode(&alice.rk), v["alice"]["rk_a"]);
        assert_eq!(hex_encode(alice.ck_s.as_ref().unwrap()), v["alice"]["ck_s_initial"]);
        assert_eq!(hex_encode(alice.dhs_pub), v["alice"]["dhs_a0_pub"]);

        let header = header_from_vector(msg);
        let header_bytes = header.encode().unwrap();
        let plaintext = hex_decode(msg["plaintext_hex"].as_str().unwrap());
        let a = &msg["aad_inputs"];
        let env_id = arr::<16>(a["envelope_id"].as_str().unwrap());
        let sender = arr::<16>(a["sender_device_id"].as_str().unwrap());
        let recipient = arr::<16>(a["recipient_device_id"].as_str().unwrap());
        let aad = aad_msg(
            a["protocol_version"].as_u64().unwrap() as u8,
            &env_id,
            &sender,
            &recipient,
            a["account_epoch"].as_u64().unwrap() as u32,
            true,
            &header_bytes,
        );
        assert_eq!(hex_encode(&aad), msg["aad_hex"]);

        let env = MessageEnvelopeRef {
            protocol_version: a["protocol_version"].as_u64().unwrap() as u8,
            envelope_id: &env_id,
            sender_device_id: &sender,
            recipient_device_id: &recipient,
            account_epoch: a["account_epoch"].as_u64().unwrap() as u32,
            is_prekey_handshake: true,
            ratchet_header_bytes: &header_bytes,
            ciphertext: &[],
        };
        let (_header_bytes, ciphertext) = encrypt_message_0(&mut alice, env, &header, &plaintext).unwrap();
        assert_eq!(hex_encode(&ciphertext), msg["ciphertext_with_tag_hex"]);
        assert_eq!(alice.ns, 1);
        assert_eq!(hex_encode(alice.ck_s.as_ref().unwrap()), v["alice"]["ck_s_after_msg0"]);
    }

    #[test]
    fn bob_message_zero_matches_frozen_vector() {
        let v = load();
        let msg = &v["message_0"];
        let x = load_x3dh();
        let case = &x["cases"][0];
        let sk = arr::<32>(v["sk"].as_str().unwrap());
        let spk_priv = arr::<32>(case["inputs"]["spk_b_priv"].as_str().unwrap());
        let dhs_b1_priv = arr::<32>(v["bob"]["dhs_b1_priv"].as_str().unwrap());
        let header = header_from_vector(msg);
        let header_bytes = header.encode().unwrap();
        let ciphertext = hex_decode(msg["ciphertext_with_tag_hex"].as_str().unwrap());
        let a = &msg["aad_inputs"];
        let env_id = arr::<16>(a["envelope_id"].as_str().unwrap());
        let sender = arr::<16>(a["sender_device_id"].as_str().unwrap());
        let recipient = arr::<16>(a["recipient_device_id"].as_str().unwrap());
        let env = MessageEnvelopeRef {
            protocol_version: a["protocol_version"].as_u64().unwrap() as u8,
            envelope_id: &env_id,
            sender_device_id: &sender,
            recipient_device_id: &recipient,
            account_epoch: a["account_epoch"].as_u64().unwrap() as u32,
            is_prekey_handshake: true,
            ratchet_header_bytes: &header_bytes,
            ciphertext: &ciphertext,
        };
        let mut bob = RatchetState::init_bob(&sk, spk_priv);
        assert_eq!(hex_encode(&bob.rk), v["bob"]["pre_ingestion_state"]["rk_b"]);
        assert_eq!(hex_encode(bob.dhs_pub), case["inputs"]["spk_b_pub"]);
        let plaintext = ingest_message_0_inner(&mut bob, env, 7, Some(42), dhs_b1_priv).unwrap();
        assert_eq!(plaintext, b"hello pm");
        assert_eq!(hex_encode(&bob.rk), v["bob"]["rk_b_final"]);
        assert_eq!(hex_encode(bob.ck_r.as_ref().unwrap()), v["bob"]["ck_r_after"]);
        assert_eq!(hex_encode(bob.ck_s.as_ref().unwrap()), v["bob"]["ck_s_final"]);
        assert_eq!(hex_encode(bob.dhs_pub), v["bob"]["dhs_b1_pub"]);
        assert_eq!(hex_encode(bob.dhr_pub.unwrap()), v["message_0"]["prekey_handshake_header"]["fields"]["10_initial_ratchet_pub"]);
        assert_eq!(bob.ns, 0);
        assert_eq!(bob.nr, 1);
        assert_eq!(bob.pn, 0);
    }

    fn state_snapshot(state: &RatchetState) -> (
        RatchetKey,
        RatchetKey,
        [u8; 32],
        Option<[u8; 32]>,
        Option<RatchetKey>,
        Option<RatchetKey>,
        u32,
        u32,
        u32,
    ) {
        (
            *state.rk,
            *state.dhs_priv,
            state.dhs_pub,
            state.dhr_pub,
            state.ck_s.as_ref().map(|v| **v),
            state.ck_r.as_ref().map(|v| **v),
            state.ns,
            state.nr,
            state.pn,
        )
    }

    #[test]
    fn tampered_message_zero_leaves_state_unchanged() {
        let v = load();
        let msg = &v["message_0"];
        let x = load_x3dh();
        let case = &x["cases"][0];
        let sk = arr::<32>(v["sk"].as_str().unwrap());
        let spk_priv = arr::<32>(case["inputs"]["spk_b_priv"].as_str().unwrap());
        let dhs_b1_priv = arr::<32>(v["bob"]["dhs_b1_priv"].as_str().unwrap());
        let header = header_from_vector(msg);
        let header_bytes = header.encode().unwrap();
        let mut ciphertext = hex_decode(msg["ciphertext_with_tag_hex"].as_str().unwrap());
        let a = &msg["aad_inputs"];
        let env_id = arr::<16>(a["envelope_id"].as_str().unwrap());
        let sender = arr::<16>(a["sender_device_id"].as_str().unwrap());
        let recipient = arr::<16>(a["recipient_device_id"].as_str().unwrap());
        let mut state = RatchetState::init_bob(&sk, spk_priv);
        let before = state_snapshot(&state);

        *ciphertext.last_mut().unwrap() ^= 1;
        let bad = MessageEnvelopeRef {
            protocol_version: 1,
            envelope_id: &env_id,
            sender_device_id: &sender,
            recipient_device_id: &recipient,
            account_epoch: 3,
            is_prekey_handshake: true,
            ratchet_header_bytes: &header_bytes,
            ciphertext: &ciphertext,
        };
        assert_eq!(
            ingest_message_0_inner(&mut state, bad, 7, Some(42), dhs_b1_priv).unwrap_err(),
            RatchetError::AeadAuthFailure
        );
        assert_eq!(state_snapshot(&state), before);

        let mut state2 = RatchetState::init_bob(&sk, arr::<32>(case["inputs"]["spk_b_priv"].as_str().unwrap()));
        let before2 = state_snapshot(&state2);
        let mut bad_env_id = env_id;
        bad_env_id[0] ^= 1;
        let good_ciphertext = hex_decode(msg["ciphertext_with_tag_hex"].as_str().unwrap());
        let bad_aad = MessageEnvelopeRef {
            protocol_version: 1,
            envelope_id: &bad_env_id,
            sender_device_id: &sender,
            recipient_device_id: &recipient,
            account_epoch: 3,
            is_prekey_handshake: true,
            ratchet_header_bytes: &header_bytes,
            ciphertext: &good_ciphertext,
        };
        assert_eq!(
            ingest_message_0_inner(&mut state2, bad_aad, 7, Some(42), dhs_b1_priv).unwrap_err(),
            RatchetError::AeadAuthFailure
        );
        assert_eq!(state_snapshot(&state2), before2);
    }

    #[test]
    fn unknown_header_field_is_rejected() {
        let v = message_vector();
        let header = header_from_vector(&v);
        let mut pairs = vec![
            (Value::Int(1), Value::Bytes(header.sender_account_id.to_vec())),
            (Value::Int(2), Value::Int(header.sender_account_epoch as i128)),
            (Value::Int(3), Value::Bytes(header.sender_dsk_pub.to_vec())),
            (Value::Int(4), Value::Bytes(header.sender_ddhk_pub.to_vec())),
            (Value::Int(5), Value::Bytes(header.sender_cert_dh.to_vec())),
            (Value::Int(6), Value::Int(header.sender_cert_dh_timestamp as i128)),
            (Value::Int(7), Value::Bytes(header.sender_ephemeral_pub.to_vec())),
            (Value::Int(8), Value::Int(header.recipient_spk_id as i128)),
            (Value::Int(9), Value::Int(header.recipient_opk_id.unwrap() as i128)),
            (Value::Int(10), Value::Bytes(header.initial_ratchet_pub.to_vec())),
            (Value::Int(11), Value::Int(0)),
            (Value::Int(12), Value::Int(0)),
        ];
        let bytes = cbor::encode_canonical(&Value::Map(std::mem::take(&mut pairs))).unwrap();
        assert_eq!(PrekeyHandshakeHeader::decode(&bytes).unwrap_err(), RatchetError::UnknownHeaderField);
    }
}
