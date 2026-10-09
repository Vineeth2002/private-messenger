//! Sovereign Private Messenger native crypto core.
//!
//! Phase A: `cbor` (PM-CBOR-2026) and `recovery` (BIP-39 -> HKDF -> Ed25519).
//! Phase B, one boundary at a time: `x3dh` (PM-BI-X3DH-1 handshake + Cert_dh)
//! and `double_ratchet` (Message 0 plus the bounded normal-message ratchet state machine).
//! Not yet started: HPKE push and transparency.
#![forbid(unsafe_code)]

pub mod cbor;
pub mod double_ratchet;
pub mod hpke;
pub mod media;
pub mod message_envelope;
pub mod recovery;
pub mod transparency;
pub mod x3dh;
