//! Sovereign Private Messenger native crypto core.
//!
//! Phase A: `cbor` (PM-CBOR-2026) and `recovery` (BIP-39 -> HKDF -> Ed25519).
//! Phase B, one boundary at a time: `x3dh` (PM-BI-X3DH-1 handshake + Cert_dh)
//! and `double_ratchet` (Message 0 plus the bounded normal message ratchet state machine).
//! Not yet started: HPKE push and transparency.
#![allow(unsafe_code)]

use crate::ffi::identity_restore;

#[deny(unsafe_code)]
pub mod authorization_v1;
#[deny(unsafe_code)]
pub mod device_request_auth_v1;
#[deny(unsafe_code)]
pub mod cbor;
#[deny(unsafe_code)]
pub mod double_ratchet;
#[allow(dead_code)]
mod storage_record;

pub(crate) mod ratchet_persistence;
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
pub mod transparency_v1;
#[deny(unsafe_code)]
pub mod x3dh;

#[deny(unsafe_code)]
mod ffi;

pub use cbor::CborError;
pub use ffi::{
    decode_strict_canonical, device_initialize_for_account, identity_initialize,
    recovery_initialize, recovery_mnemonic_generate,
    AccountContext, CryptoError, RecoveryContext,
};

pub use ffi::{MessagingSession, SignedPrekeyContext};

pub use ffi::{kt_verify_device_proof_v1, kt_verify_signed_prekey_binding_v1, verify_signed_prekey_for_peer_v1};

// UniFFI-generated C-ABI scaffolding must remain at crate root.
uniffi::include_scaffolding!("pm_crypto_core");

pub mod signed_prekey_v1;
