//! Recovery-authorized device enrollment and epoch-transition certificates.
//!
//! This module implements the exact PM-CBOR-2026 cores frozen by
//! `docs/phase0/13-device-lifecycle-v1.md`. The recovery signing key never
//! leaves Rust; only the signed canonical certificate bytes cross UniFFI.

use crate::cbor::{self, Value};
use ed25519_dalek::{Signer, SigningKey};
use thiserror::Error;

pub const PROTOCOL_VERSION: u64 = 1;
pub const DEVICE_ENROLL_DOMAIN: &[u8] = b"PM-V1-DEVICE-ENROLL-v1";
pub const EPOCH_TRANSITION_DOMAIN: &[u8] = b"PM-V1-EPOCH-TRANSITION-v1";
pub const RECOVERY_COMMITMENT_DOMAIN: &[u8] = b"PM-V1-RECOVERY-COMMITMENT";

pub const REVOKE_DEVICE_ACTION: u64 = 1;
pub const RECOVERY_RESET_ACTION: u64 = 2;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationV1Error {
    #[error("invalid cryptographic field")]
    InvalidField,
    #[error("CBOR encoding failed")]
    Cbor,
    #[error("invalid epoch transition")]
    InvalidEpoch,
    #[error("invalid epoch transition action")]
    InvalidAction,
}

fn core_enrollment(
    account_id: [u8; 16],
    epoch: u64,
    device_id: [u8; 16],
    dsk_pub: [u8; 32],
    ddhk_pub: [u8; 32],
) -> Result<Vec<u8>, AuthorizationV1Error> {
    cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(account_id.to_vec())),
        (Value::Int(3), Value::Int(epoch as i128)),
        (Value::Int(4), Value::Bytes(device_id.to_vec())),
        (Value::Int(5), Value::Bytes(dsk_pub.to_vec())),
        (Value::Int(6), Value::Bytes(ddhk_pub.to_vec())),
    ]))
    .map_err(|_| AuthorizationV1Error::Cbor)
}

fn core_transition(
    account_id: [u8; 16],
    old_epoch: u64,
    new_epoch: u64,
    action: u64,
    device_id: &[u8],
) -> Result<Vec<u8>, AuthorizationV1Error> {
    cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(account_id.to_vec())),
        (Value::Int(3), Value::Int(old_epoch as i128)),
        (Value::Int(4), Value::Int(new_epoch as i128)),
        (Value::Int(5), Value::Int(action as i128)),
        (Value::Int(6), Value::Bytes(device_id.to_vec())),
    ]))
    .map_err(|_| AuthorizationV1Error::Cbor)
}

pub fn recovery_commitment(recovery_pub: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_COMMITMENT_DOMAIN);
    hasher.update(recovery_pub);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn sign_device_enrollment(
    signing_key: &SigningKey,
    account_id: [u8; 16],
    epoch: u64,
    device_id: [u8; 16],
    dsk_pub: [u8; 32],
    ddhk_pub: [u8; 32],
) -> Result<Vec<u8>, AuthorizationV1Error> {
    if account_id == [0u8; 16] || device_id == [0u8; 16] || epoch == 0 {
        return Err(AuthorizationV1Error::InvalidField);
    }

    let core = core_enrollment(account_id, epoch, device_id, dsk_pub, ddhk_pub)?;
    let signature = signing_key.sign(&[DEVICE_ENROLL_DOMAIN, core.as_slice()].concat());

    cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(account_id.to_vec())),
        (Value::Int(3), Value::Int(epoch as i128)),
        (Value::Int(4), Value::Bytes(device_id.to_vec())),
        (Value::Int(5), Value::Bytes(dsk_pub.to_vec())),
        (Value::Int(6), Value::Bytes(ddhk_pub.to_vec())),
        (Value::Int(7), Value::Bytes(signature.to_bytes().to_vec())),
    ]))
    .map_err(|_| AuthorizationV1Error::Cbor)
}

pub fn sign_epoch_transition(
    signing_key: &SigningKey,
    account_id: [u8; 16],
    old_epoch: u64,
    new_epoch: u64,
    action: u64,
    device_id: &[u8],
) -> Result<Vec<u8>, AuthorizationV1Error> {
    if account_id == [0u8; 16]
        || old_epoch == 0
        || old_epoch == u64::MAX
        || new_epoch != old_epoch + 1
    {
        return Err(AuthorizationV1Error::InvalidEpoch);
    }

    match action {
        REVOKE_DEVICE_ACTION if device_id.len() == 16 && device_id.iter().any(|b| *b != 0) => {}
        RECOVERY_RESET_ACTION if device_id.is_empty() => {}
        _ => {
            return Err(AuthorizationV1Error::InvalidAction);
        }
    }

    let core = core_transition(account_id, old_epoch, new_epoch, action, device_id)?;
    let signature = signing_key.sign(&[EPOCH_TRANSITION_DOMAIN, core.as_slice()].concat());

    cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(account_id.to_vec())),
        (Value::Int(3), Value::Int(old_epoch as i128)),
        (Value::Int(4), Value::Int(new_epoch as i128)),
        (Value::Int(5), Value::Int(action as i128)),
        (Value::Int(6), Value::Bytes(device_id.to_vec())),
        (Value::Int(7), Value::Bytes(signature.to_bytes().to_vec())),
    ]))
    .map_err(|_| AuthorizationV1Error::Cbor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::recovery_signing_key;
    use ed25519_dalek::{Signature, Verifier};

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn key() -> SigningKey {
        recovery_signing_key(TEST_MNEMONIC).unwrap()
    }

    fn bytes<const N: usize>(value: u8) -> [u8; N] {
        [value; N]
    }

    #[test]
    fn enrollment_is_signed_over_canonical_core_and_round_trips() {
        let signing_key = key();
        let account = bytes::<16>(0x11);
        let device = bytes::<16>(0x22);
        let dsk = bytes::<32>(0x33);
        let ddhk = bytes::<32>(0x44);

        let raw = sign_device_enrollment(&signing_key, account, 3, device, dsk, ddhk).unwrap();
        let value = crate::cbor::decode_strict(&raw).unwrap();
        let Value::Map(fields) = value else {
            panic!("expected map")
        };
        assert_eq!(fields.len(), 7);

        let core = core_enrollment(account, 3, device, dsk, ddhk).unwrap();
        let signature_bytes = fields
            .iter()
            .find(|(k, _)| matches!(k, Value::Int(7)))
            .and_then(|(_, v)| match v {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .unwrap();

        let signature = Signature::from_slice(&signature_bytes).unwrap();
        signing_key
            .verifying_key()
            .verify(
                &[DEVICE_ENROLL_DOMAIN, core.as_slice()].concat(),
                &signature,
            )
            .unwrap();

        let parsed = crate::cbor::decode_strict(&raw).unwrap();
        assert!(matches!(parsed, Value::Map(_)));
    }

    #[test]
    fn transition_revoke_uses_target_device_and_verifies() {
        let signing_key = key();
        let account = bytes::<16>(0x11);
        let device = bytes::<16>(0x55);

        let raw = sign_epoch_transition(&signing_key, account, 4, 5, REVOKE_DEVICE_ACTION, &device)
            .unwrap();
        let Value::Map(fields) = crate::cbor::decode_strict(&raw).unwrap() else {
            panic!("expected map")
        };
        assert_eq!(fields.len(), 7);

        let core = core_transition(account, 4, 5, REVOKE_DEVICE_ACTION, &device).unwrap();
        let signature_bytes = fields
            .iter()
            .find(|(k, _)| matches!(k, Value::Int(7)))
            .and_then(|(_, v)| match v {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .unwrap();
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        signing_key
            .verifying_key()
            .verify(
                &[EPOCH_TRANSITION_DOMAIN, core.as_slice()].concat(),
                &signature,
            )
            .unwrap();
    }

    #[test]
    fn transition_reset_uses_empty_target() {
        let signing_key = key();
        let account = bytes::<16>(0x11);
        let raw =
            sign_epoch_transition(&signing_key, account, 1, 2, RECOVERY_RESET_ACTION, &[]).unwrap();
        assert!(crate::cbor::decode_strict(&raw).is_ok());
    }

    #[test]
    fn invalid_shapes_are_rejected() {
        let signing_key = key();
        assert_eq!(
            sign_device_enrollment(
                &signing_key,
                [0u8; 16],
                1,
                bytes::<16>(1),
                bytes::<32>(2),
                bytes::<32>(3)
            ),
            Err(AuthorizationV1Error::InvalidField)
        );
        assert_eq!(
            sign_epoch_transition(
                &signing_key,
                bytes::<16>(1),
                1,
                3,
                REVOKE_DEVICE_ACTION,
                &bytes::<16>(2)
            ),
            Err(AuthorizationV1Error::InvalidEpoch)
        );
        assert_eq!(
            sign_epoch_transition(
                &signing_key,
                bytes::<16>(1),
                1,
                2,
                REVOKE_DEVICE_ACTION,
                &[]
            ),
            Err(AuthorizationV1Error::InvalidAction)
        );
        assert_eq!(
            sign_epoch_transition(
                &signing_key,
                bytes::<16>(1),
                1,
                2,
                RECOVERY_RESET_ACTION,
                &bytes::<16>(2)
            ),
            Err(AuthorizationV1Error::InvalidAction)
        );
    }

    #[test]
    fn commitment_matches_recovery_protocol_domain() {
        let signing_key = key();
        let public = signing_key.verifying_key().to_bytes();
        assert_eq!(
            recovery_commitment(&public),
            crate::recovery::identity_recovery_commitment(&public)
        );
    }
}
