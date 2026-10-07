//! Sovereign Private Messenger native crypto core.
//!
//! Phase A: `cbor` (PM-CBOR-2026) and `recovery` (BIP-39 -> HKDF -> Ed25519).
//! Phase B, one boundary at a time: `x3dh` (PM-BI-X3DH-1 handshake + Cert_dh).
//! Not yet started: Double Ratchet, media AEAD, HPKE push, transparency.
#![forbid(unsafe_code)]

pub mod cbor;
pub mod recovery;
pub mod x3dh;
