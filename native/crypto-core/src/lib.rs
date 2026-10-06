//! Sovereign Private Messenger native crypto core.
//!
//! Phase A scope only: `cbor` (PM-CBOR-2026) and `recovery` (BIP-39 -> HKDF -> Ed25519).
//! Phase B (PM-BI-X3DH-1, Double Ratchet, media AEAD, HPKE push) is LOCKED.
#![forbid(unsafe_code)]

pub mod cbor;
pub mod recovery;
