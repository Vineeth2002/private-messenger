//! Sovereign Private Messenger native crypto core.
//!
//! Phase A: `cbor` (PM-CBOR-2026) and `recovery` (BIP-39 -> HKDF -> Ed25519).
//! Phase B, one boundary at a time: `x3dh` (PM-BI-X3DH-1 handshake + Cert_dh)
//! and `double_ratchet` (Message 0 plus the bounded normal message ratchet state machine).
//! Not yet started: HPKE push and transparency.
#![allow(unsafe_code)]

#[deny(unsafe_code)]
pub mod cbor;
#[deny(unsafe_code)]
pub mod double_ratchet;
#[deny(unsafe_code)]
pub mod hpke;
#[deny(unsafe_code)]
pub mod media;
#[deny(unsafe_code)]
pub mod message_envelope;
#[deny(unsafe_code)]
pub mod recovery;
#[deny(unsafe_code)]
pub mod transparency;
#[deny(unsafe_code)]
pub mod x3dh;

#[deny(unsafe_code)]
mod ffi;

pub use cbor::CborError;
pub use ffi::{
    decode_strict_canonical,
    identity_initialize,
    AccountContext,
    CryptoError,
};

// UniFFI-generated C-ABI scaffolding must remain at crate root.
uniffi::include_scaffolding!("pm_crypto_core");
