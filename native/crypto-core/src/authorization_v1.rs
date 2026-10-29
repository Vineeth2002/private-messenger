//! Recovery-authorized device enrollment and epoch-transition certificates.
//!
//! This module implements the current candidate PM-CBOR-2026 certificate schemas documented in
//! `docs/phase0/13-device-lifecycle-v1.md`. The recovery signing key never
//! leaves Rust; only the signed canonical certificate bytes cross UniFFI.

use crate::cbor::{self, Value};
use ed25519_dalek::{Signer, SigningKey};
use thiserror::Error;

pub const PROTOCOL_VERSION: u64 = 1;
pub const DEVICE_ENROLL_DOMAIN: &[u8] = b"PM-V1-DEVICE-ENROLL-v1";
pub const EPOCH_TRANSITION_DOMAIN: &[u8] = b"PM-V1-EPOCH-TRANSITION-v1";
pub const RECOVERY_COMMITMENT_DOMAIN: &[u8] = b"PM-V1-RECOVERY-COMMITMENT";
/// Candidate RecoveryRequestV1 domain. The lifecycle wire contract remains NOT FROZEN.
pub const RECOVERY_REQUEST_DOMAIN: &[u8] = b"PM-V1-RECOVERY-REQUEST-v1";
/// Candidate V1 lifecycle epoch ceiling; this does not change legacy certificate parsing.
pub const LIFECYCLE_EPOCH_MAX: u64 = u32::MAX as u64;

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

fn validate_recovery_request_fields(
    account_id: [u8; 16],
    old_epoch: u64,
    new_epoch: u64,
    request_id: [u8; 16],
    target_device_id: [u8; 16],
) -> Result<(), AuthorizationV1Error> {
    if account_id == [0; 16] || request_id == [0; 16] || target_device_id == [0; 16] {
        return Err(AuthorizationV1Error::InvalidField);
    }
    if old_epoch == 0
        || old_epoch >= LIFECYCLE_EPOCH_MAX
        || new_epoch > LIFECYCLE_EPOCH_MAX
        || new_epoch != old_epoch + 1
    {
        return Err(AuthorizationV1Error::InvalidEpoch);
    }
    Ok(())
}

fn core_recovery_request(
    account_id: [u8; 16],
    old_epoch: u64,
    new_epoch: u64,
    request_id: [u8; 16],
    target_device_id: [u8; 16],
    enrollment_cert_digest: [u8; 32],
) -> Result<Vec<u8>, AuthorizationV1Error> {
    cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(account_id.to_vec())),
        (Value::Int(3), Value::Int(old_epoch as i128)),
        (Value::Int(4), Value::Int(new_epoch as i128)),
        (Value::Int(5), Value::Bytes(request_id.to_vec())),
        (Value::Int(6), Value::Bytes(target_device_id.to_vec())),
        (Value::Int(7), Value::Bytes(enrollment_cert_digest.to_vec())),
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

/// Sign a candidate RecoveryRequestV1 and bind it to the exact signed enrollment certificate.
/// This is a wire-format helper only; it does not persist or authorize a recovery request.
pub fn sign_recovery_request(
    signing_key: &SigningKey,
    account_id: [u8; 16],
    old_epoch: u64,
    new_epoch: u64,
    request_id: [u8; 16],
    target_device_id: [u8; 16],
    enrollment_certificate_raw: &[u8],
) -> Result<Vec<u8>, AuthorizationV1Error> {
    validate_recovery_request_fields(
        account_id, old_epoch, new_epoch, request_id, target_device_id,
    )?;

    let enrollment = DeviceEnrollmentAuthorizationV1::parse(enrollment_certificate_raw)?;
    let recovery_pub = signing_key.verifying_key().to_bytes();
    enrollment.verify(&recovery_pub)?;
    if enrollment.account_id != account_id
        || enrollment.device_id != target_device_id
        || enrollment.epoch != new_epoch
    {
        return Err(AuthorizationV1Error::InvalidField);
    }

    use sha2::{Digest, Sha256};
    let enrollment_cert_digest: [u8; 32] = Sha256::digest(enrollment_certificate_raw).into();
    let core = core_recovery_request(
        account_id, old_epoch, new_epoch, request_id, target_device_id, enrollment_cert_digest,
    )?;
    let signature = signing_key.sign(&[RECOVERY_REQUEST_DOMAIN, core.as_slice()].concat());

    cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(account_id.to_vec())),
        (Value::Int(3), Value::Int(old_epoch as i128)),
        (Value::Int(4), Value::Int(new_epoch as i128)),
        (Value::Int(5), Value::Bytes(request_id.to_vec())),
        (Value::Int(6), Value::Bytes(target_device_id.to_vec())),
        (Value::Int(7), Value::Bytes(enrollment_cert_digest.to_vec())),
        (Value::Int(8), Value::Bytes(signature.to_bytes().to_vec())),
    ]))
    .map_err(|_| AuthorizationV1Error::Cbor)
}

/// Parsed candidate recovery request. Parsing/signature checks alone do not
/// establish database freshness, request-ID uniqueness, pending state, or activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequestV1 {
    pub raw: Vec<u8>,
    pub account_id: [u8; 16],
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub request_id: [u8; 16],
    pub target_device_id: [u8; 16],
    pub enrollment_cert_digest: [u8; 32],
    pub signature: [u8; 64],
}

/// Parsed recovery-authorized enrollment certificate. This verifies the wire
/// object and recovery signature only; it does not establish current lifecycle
/// state, proof of possession, or authorization to activate a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrollmentAuthorizationV1 {
    pub raw: Vec<u8>,
    pub account_id: [u8; 16],
    pub epoch: u64,
    pub device_id: [u8; 16],
    pub dsk_pub: [u8; 32],
    pub ddhk_pub: [u8; 32],
    pub signature: [u8; 64],
}

/// Parsed recovery-authorized epoch transition. Signature verification alone
/// does not apply this transition or prove that it matches current server state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTransitionAuthorizationV1 {
    pub raw: Vec<u8>,
    pub account_id: [u8; 16],
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub action: u64,
    pub device_id: [u8; 16],
    pub signature: [u8; 64],
}

fn authorization_map(raw: &[u8]) -> Result<Vec<(Value, Value)>, AuthorizationV1Error> {
    let value = cbor::decode_strict(raw).map_err(|_| AuthorizationV1Error::InvalidField)?;
    let Value::Map(fields) = value else {
        return Err(AuthorizationV1Error::InvalidField);
    };
    if fields.len() != 7 {
        return Err(AuthorizationV1Error::InvalidField);
    }
    for (key, _) in &fields {
        match key {
            Value::Int(k) if (1..=7).contains(k) => {}
            _ => return Err(AuthorizationV1Error::InvalidField),
        }
    }
    for key in 1..=7 {
        if !fields.iter().any(|(candidate, _)| matches!(candidate, Value::Int(k) if *k == key)) {
            return Err(AuthorizationV1Error::InvalidField);
        }
    }
    Ok(fields)
}

fn recovery_request_map(raw: &[u8]) -> Result<Vec<(Value, Value)>, AuthorizationV1Error> {
    let value = cbor::decode_strict(raw).map_err(|_| AuthorizationV1Error::InvalidField)?;
    let Value::Map(fields) = value else {
        return Err(AuthorizationV1Error::InvalidField);
    };
    if fields.len() != 8 {
        return Err(AuthorizationV1Error::InvalidField);
    }
    for (key, _) in &fields {
        match key {
            Value::Int(k) if (1..=8).contains(k) => {}
            _ => return Err(AuthorizationV1Error::InvalidField),
        }
    }
    for key in 1..=8 {
        if !fields.iter().any(|(candidate, _)| matches!(candidate, Value::Int(k) if *k == key)) {
            return Err(AuthorizationV1Error::InvalidField);
        }
    }
    Ok(fields)
}

fn authorization_field<'a>(
    fields: &'a [(Value, Value)],
    key: i128,
) -> Result<&'a Value, AuthorizationV1Error> {
    fields
        .iter()
        .find_map(|(candidate, value)| match candidate {
            Value::Int(k) if *k == key => Some(value),
            _ => None,
        })
        .ok_or(AuthorizationV1Error::InvalidField)
}

fn authorization_uint(
    fields: &[(Value, Value)],
    key: i128,
) -> Result<u64, AuthorizationV1Error> {
    match authorization_field(fields, key)? {
        Value::Int(value) if *value >= 0 => {
            u64::try_from(*value).map_err(|_| AuthorizationV1Error::InvalidField)
        }
        _ => Err(AuthorizationV1Error::InvalidField),
    }
}

fn authorization_bytes(
    fields: &[(Value, Value)],
    key: i128,
) -> Result<Vec<u8>, AuthorizationV1Error> {
    match authorization_field(fields, key)? {
        Value::Bytes(value) => Ok(value.clone()),
        _ => Err(AuthorizationV1Error::InvalidField),
    }
}

fn authorization_fixed<const N: usize>(
    fields: &[(Value, Value)],
    key: i128,
) -> Result<[u8; N], AuthorizationV1Error> {
    let value = authorization_bytes(fields, key)?;
    value.try_into().map_err(|_| AuthorizationV1Error::InvalidField)
}

impl DeviceEnrollmentAuthorizationV1 {
    pub fn parse(raw: &[u8]) -> Result<Self, AuthorizationV1Error> {
        let fields = authorization_map(raw)?;
        if authorization_uint(&fields, 1)? != PROTOCOL_VERSION {
            return Err(AuthorizationV1Error::InvalidField);
        }
        let account_id = authorization_fixed::<16>(&fields, 2)?;
        let epoch = authorization_uint(&fields, 3)?;
        let device_id = authorization_fixed::<16>(&fields, 4)?;
        let dsk_pub = authorization_fixed::<32>(&fields, 5)?;
        let ddhk_pub = authorization_fixed::<32>(&fields, 6)?;
        let signature = authorization_fixed::<64>(&fields, 7)?;
        if account_id == [0; 16] || device_id == [0; 16] || epoch == 0 {
            return Err(AuthorizationV1Error::InvalidField);
        }
        Ok(Self {
            raw: raw.to_vec(), account_id, epoch, device_id, dsk_pub, ddhk_pub, signature,
        })
    }

    pub fn verify(&self, recovery_pub: &[u8; 32]) -> Result<(), AuthorizationV1Error> {
        use ed25519_dalek::{Signature, VerifyingKey};
        let public = VerifyingKey::from_bytes(recovery_pub)
            .map_err(|_| AuthorizationV1Error::InvalidField)?;
        let signature = Signature::from_bytes(&self.signature);
        let core = core_enrollment(
            self.account_id, self.epoch, self.device_id, self.dsk_pub, self.ddhk_pub,
        )?;
        public.verify_strict(&[DEVICE_ENROLL_DOMAIN, core.as_slice()].concat(), &signature)
            .map_err(|_| AuthorizationV1Error::InvalidField)
    }
}

impl EpochTransitionAuthorizationV1 {
    pub fn parse(raw: &[u8]) -> Result<Self, AuthorizationV1Error> {
        let fields = authorization_map(raw)?;
        if authorization_uint(&fields, 1)? != PROTOCOL_VERSION {
            return Err(AuthorizationV1Error::InvalidField);
        }
        let account_id = authorization_fixed::<16>(&fields, 2)?;
        let old_epoch = authorization_uint(&fields, 3)?;
        let new_epoch = authorization_uint(&fields, 4)?;
        let action = authorization_uint(&fields, 5)?;
        let target = authorization_bytes(&fields, 6)?;
        let signature = authorization_fixed::<64>(&fields, 7)?;
        if account_id == [0; 16] || old_epoch == 0 || old_epoch == u64::MAX
            || new_epoch != old_epoch + 1
        {
            return Err(AuthorizationV1Error::InvalidEpoch);
        }
        let device_id = match action {
            REVOKE_DEVICE_ACTION if target.len() == 16 => {
                let id: [u8; 16] = target.try_into().map_err(|_| AuthorizationV1Error::InvalidAction)?;
                if id == [0; 16] { return Err(AuthorizationV1Error::InvalidAction); }
                id
            }
            RECOVERY_RESET_ACTION if target.is_empty() => [0; 16],
            _ => return Err(AuthorizationV1Error::InvalidAction),
        };
        Ok(Self {
            raw: raw.to_vec(), account_id, old_epoch, new_epoch, action, device_id, signature,
        })
    }

    pub fn verify(&self, recovery_pub: &[u8; 32]) -> Result<(), AuthorizationV1Error> {
        use ed25519_dalek::{Signature, VerifyingKey};
        let public = VerifyingKey::from_bytes(recovery_pub)
            .map_err(|_| AuthorizationV1Error::InvalidField)?;
        let signature = Signature::from_bytes(&self.signature);
        let target = if self.action == RECOVERY_RESET_ACTION {
            &[][..]
        } else {
            &self.device_id[..]
        };
        let core = core_transition(
            self.account_id, self.old_epoch, self.new_epoch, self.action, target,
        )?;
        public.verify_strict(&[EPOCH_TRANSITION_DOMAIN, core.as_slice()].concat(), &signature)
            .map_err(|_| AuthorizationV1Error::InvalidField)
    }
}
impl RecoveryRequestV1 {
    pub fn parse(raw: &[u8]) -> Result<Self, AuthorizationV1Error> {
        let fields = recovery_request_map(raw)?;
        if authorization_uint(&fields, 1)? != PROTOCOL_VERSION {
            return Err(AuthorizationV1Error::InvalidField);
        }
        let account_id = authorization_fixed::<16>(&fields, 2)?;
        let old_epoch = authorization_uint(&fields, 3)?;
        let new_epoch = authorization_uint(&fields, 4)?;
        let request_id = authorization_fixed::<16>(&fields, 5)?;
        let target_device_id = authorization_fixed::<16>(&fields, 6)?;
        let enrollment_cert_digest = authorization_fixed::<32>(&fields, 7)?;
        let signature = authorization_fixed::<64>(&fields, 8)?;
        validate_recovery_request_fields(
            account_id, old_epoch, new_epoch, request_id, target_device_id,
        )?;
        Ok(Self {
            raw: raw.to_vec(),
            account_id,
            old_epoch,
            new_epoch,
            request_id,
            target_device_id,
            enrollment_cert_digest,
            signature,
        })
    }

    pub fn verify(&self, recovery_pub: &[u8; 32]) -> Result<(), AuthorizationV1Error> {
        use ed25519_dalek::{Signature, VerifyingKey};
        let public = VerifyingKey::from_bytes(recovery_pub)
            .map_err(|_| AuthorizationV1Error::InvalidField)?;
        let signature = Signature::from_bytes(&self.signature);
        let core = core_recovery_request(
            self.account_id,
            self.old_epoch,
            self.new_epoch,
            self.request_id,
            self.target_device_id,
            self.enrollment_cert_digest,
        )?;
        public
            .verify_strict(&[RECOVERY_REQUEST_DOMAIN, core.as_slice()].concat(), &signature)
            .map_err(|_| AuthorizationV1Error::InvalidField)
    }

    /// Verify both signatures and exact certificate-byte digest/bindings under the same recovery key.
    pub fn verify_for_enrollment(
        &self,
        recovery_pub: &[u8; 32],
        enrollment_certificate_raw: &[u8],
    ) -> Result<(), AuthorizationV1Error> {
        self.verify(recovery_pub)?;
        let enrollment = DeviceEnrollmentAuthorizationV1::parse(enrollment_certificate_raw)?;
        enrollment.verify(recovery_pub)?;
        use sha2::{Digest, Sha256};
        let supplied_digest: [u8; 32] = Sha256::digest(enrollment_certificate_raw).into();
        if supplied_digest != self.enrollment_cert_digest
            || enrollment.account_id != self.account_id
            || enrollment.device_id != self.target_device_id
            || enrollment.epoch != self.new_epoch
        {
            return Err(AuthorizationV1Error::InvalidField);
        }
        Ok(())
    }
}

/// Candidate RecoveryAbortV1 domain. The lifecycle wire contract remains NOT FROZEN.
pub const RECOVERY_ABORT_DOMAIN: &[u8] = b"PM-V1-RECOVERY-ABORT-v1";
/// Candidate DeviceEnrollmentPoPV1 domain. The lifecycle wire contract remains NOT FROZEN.
pub const DEVICE_ENROLLMENT_POP_DOMAIN: &[u8] = b"PM-V1-DEVICE-POP-v1";

fn core_recovery_abort(
    account_id: [u8; 16],
    device_id: [u8; 16],
    old_epoch: u64,
    new_epoch: u64,
    request_id: [u8; 16],
    recovery_request_digest: [u8; 32],
) -> Result<Vec<u8>, AuthorizationV1Error> {
    cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(account_id.to_vec())),
        (Value::Int(3), Value::Bytes(device_id.to_vec())),
        (Value::Int(4), Value::Int(old_epoch as i128)),
        (Value::Int(5), Value::Int(new_epoch as i128)),
        (Value::Int(6), Value::Bytes(request_id.to_vec())),
        (Value::Int(7), Value::Bytes(recovery_request_digest.to_vec())),
    ]))
    .map_err(|_| AuthorizationV1Error::Cbor)
}

fn validate_recovery_abort_fields(
    account_id: [u8; 16],
    device_id: [u8; 16],
    old_epoch: u64,
    new_epoch: u64,
    request_id: [u8; 16],
) -> Result<(), AuthorizationV1Error> {
    if account_id == [0; 16] || device_id == [0; 16] || request_id == [0; 16] {
        return Err(AuthorizationV1Error::InvalidField);
    }
    if old_epoch == 0
        || old_epoch >= LIFECYCLE_EPOCH_MAX
        || new_epoch != old_epoch + 1
        || new_epoch > LIFECYCLE_EPOCH_MAX
    {
        return Err(AuthorizationV1Error::InvalidEpoch);
    }
    Ok(())
}

/// Sign a candidate abort for the exact RecoveryRequestV1 wire bytes.
/// This helper verifies the recovery signature but cannot establish that the request is still
/// pending or that this device is active; those checks require authoritative server state.
pub fn sign_recovery_abort(
    device_signing_key: &SigningKey,
    recovery_pub: &[u8; 32],
    aborting_device_id: [u8; 16],
    recovery_request_raw: &[u8],
) -> Result<Vec<u8>, AuthorizationV1Error> {
    let request = RecoveryRequestV1::parse(recovery_request_raw)?;
    request.verify(recovery_pub)?;
    validate_recovery_abort_fields(
        request.account_id,
        aborting_device_id,
        request.old_epoch,
        request.new_epoch,
        request.request_id,
    )?;

    use sha2::{Digest, Sha256};
    let request_digest: [u8; 32] = Sha256::digest(recovery_request_raw).into();
    let core = core_recovery_abort(
        request.account_id,
        aborting_device_id,
        request.old_epoch,
        request.new_epoch,
        request.request_id,
        request_digest,
    )?;
    let signature = device_signing_key.sign(&[RECOVERY_ABORT_DOMAIN, core.as_slice()].concat());
    cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(request.account_id.to_vec())),
        (Value::Int(3), Value::Bytes(aborting_device_id.to_vec())),
        (Value::Int(4), Value::Int(request.old_epoch as i128)),
        (Value::Int(5), Value::Int(request.new_epoch as i128)),
        (Value::Int(6), Value::Bytes(request.request_id.to_vec())),
        (Value::Int(7), Value::Bytes(request_digest.to_vec())),
        (Value::Int(8), Value::Bytes(signature.to_bytes().to_vec())),
    ]))
    .map_err(|_| AuthorizationV1Error::Cbor)
}

/// Parsed RecoveryAbortV1 wire candidate. It does not encode active-device status or deadline checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAbortV1 {
    pub raw: Vec<u8>,
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub request_id: [u8; 16],
    pub recovery_request_digest: [u8; 32],
    pub signature: [u8; 64],
}

fn recovery_abort_map(raw: &[u8]) -> Result<Vec<(Value, Value)>, AuthorizationV1Error> {
    let value = cbor::decode_strict(raw).map_err(|_| AuthorizationV1Error::InvalidField)?;
    let Value::Map(fields) = value else {
        return Err(AuthorizationV1Error::InvalidField);
    };
    if fields.len() != 8 {
        return Err(AuthorizationV1Error::InvalidField);
    }
    for (key, _) in &fields {
        match key {
            Value::Int(k) if (1..=8).contains(k) => {}
            _ => return Err(AuthorizationV1Error::InvalidField),
        }
    }
    for key in 1..=8 {
        if !fields.iter().any(|(candidate, _)| matches!(candidate, Value::Int(k) if *k == key)) {
            return Err(AuthorizationV1Error::InvalidField);
        }
    }
    Ok(fields)
}

impl RecoveryAbortV1 {
    pub fn parse(raw: &[u8]) -> Result<Self, AuthorizationV1Error> {
        let fields = recovery_abort_map(raw)?;
        if authorization_uint(&fields, 1)? != PROTOCOL_VERSION {
            return Err(AuthorizationV1Error::InvalidField);
        }
        let account_id = authorization_fixed::<16>(&fields, 2)?;
        let device_id = authorization_fixed::<16>(&fields, 3)?;
        let old_epoch = authorization_uint(&fields, 4)?;
        let new_epoch = authorization_uint(&fields, 5)?;
        let request_id = authorization_fixed::<16>(&fields, 6)?;
        let recovery_request_digest = authorization_fixed::<32>(&fields, 7)?;
        let signature = authorization_fixed::<64>(&fields, 8)?;
        validate_recovery_abort_fields(account_id, device_id, old_epoch, new_epoch, request_id)?;
        Ok(Self {
            raw: raw.to_vec(),
            account_id,
            device_id,
            old_epoch,
            new_epoch,
            request_id,
            recovery_request_digest,
            signature,
        })
    }

    /// Verify only the aborting device's signature and canonical fields.
    pub fn verify(&self, device_signing_pub: &[u8; 32]) -> Result<(), AuthorizationV1Error> {
        validate_recovery_abort_fields(
            self.account_id, self.device_id, self.old_epoch, self.new_epoch, self.request_id,
        )?;
        use ed25519_dalek::{Signature, VerifyingKey};
        let public = VerifyingKey::from_bytes(device_signing_pub)
            .map_err(|_| AuthorizationV1Error::InvalidField)?;
        let signature = Signature::from_bytes(&self.signature);
        let core = core_recovery_abort(
            self.account_id,
            self.device_id,
            self.old_epoch,
            self.new_epoch,
            self.request_id,
            self.recovery_request_digest,
        )?;
        public
            .verify_strict(&[RECOVERY_ABORT_DOMAIN, core.as_slice()].concat(), &signature)
            .map_err(|_| AuthorizationV1Error::InvalidField)
    }

    /// Verify the abort signature, the recovery request signature, and exact request identity/digest.
    /// Server-side pending status, current device status, and deadline remain external checks.
    pub fn verify_for_request(
        &self,
        recovery_pub: &[u8; 32],
        device_signing_pub: &[u8; 32],
        recovery_request_raw: &[u8],
    ) -> Result<(), AuthorizationV1Error> {
        self.verify(device_signing_pub)?;
        let request = RecoveryRequestV1::parse(recovery_request_raw)?;
        request.verify(recovery_pub)?;
        use sha2::{Digest, Sha256};
        let supplied_digest: [u8; 32] = Sha256::digest(recovery_request_raw).into();
        if supplied_digest != self.recovery_request_digest
            || self.account_id != request.account_id
            || self.old_epoch != request.old_epoch
            || self.new_epoch != request.new_epoch
            || self.request_id != request.request_id
        {
            return Err(AuthorizationV1Error::InvalidField);
        }
        Ok(())
    }
}
fn validate_device_enrollment_pop_fields(
    account_id: [u8; 16],
    device_id: [u8; 16],
    epoch: u64,
    challenge_id: [u8; 16],
) -> Result<(), AuthorizationV1Error> {
    if account_id == [0; 16] || device_id == [0; 16] || challenge_id == [0; 16] {
        return Err(AuthorizationV1Error::InvalidField);
    }
    if epoch == 0 || epoch > LIFECYCLE_EPOCH_MAX {
        return Err(AuthorizationV1Error::InvalidEpoch);
    }
    Ok(())
}

fn core_device_enrollment_pop(
    account_id: [u8; 16],
    device_id: [u8; 16],
    epoch: u64,
    enrollment_cert_digest: [u8; 32],
    challenge_id: [u8; 16],
    challenge_nonce: [u8; 32],
) -> Result<Vec<u8>, AuthorizationV1Error> {
    validate_device_enrollment_pop_fields(account_id, device_id, epoch, challenge_id)?;
    cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(account_id.to_vec())),
        (Value::Int(3), Value::Bytes(device_id.to_vec())),
        (Value::Int(4), Value::Int(epoch as i128)),
        (Value::Int(5), Value::Bytes(enrollment_cert_digest.to_vec())),
        (Value::Int(6), Value::Bytes(challenge_id.to_vec())),
        (Value::Int(7), Value::Bytes(challenge_nonce.to_vec())),
    ]))
    .map_err(|_| AuthorizationV1Error::Cbor)
}

/// Parsed DeviceEnrollmentPoPV1 wire candidate. A valid signature is not activation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrollmentPoPV1 {
    pub raw: Vec<u8>,
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    pub epoch: u64,
    pub enrollment_cert_digest: [u8; 32],
    pub challenge_id: [u8; 16],
    pub challenge_nonce: [u8; 32],
    pub signature: [u8; 64],
}

fn device_enrollment_pop_map(raw: &[u8]) -> Result<Vec<(Value, Value)>, AuthorizationV1Error> {
    let value = cbor::decode_strict(raw).map_err(|_| AuthorizationV1Error::InvalidField)?;
    let Value::Map(fields) = value else {
        return Err(AuthorizationV1Error::InvalidField);
    };
    if fields.len() != 8 {
        return Err(AuthorizationV1Error::InvalidField);
    }
    for (key, _) in &fields {
        match key {
            Value::Int(k) if (1..=8).contains(k) => {}
            _ => return Err(AuthorizationV1Error::InvalidField),
        }
    }
    for key in 1..=8 {
        if !fields.iter().any(|(candidate, _)| matches!(candidate, Value::Int(k) if *k == key)) {
            return Err(AuthorizationV1Error::InvalidField);
        }
    }
    Ok(fields)
}

impl DeviceEnrollmentPoPV1 {
    /// Strictly parse the separate 8-field proof-of-possession candidate.
    pub fn parse(raw: &[u8]) -> Result<Self, AuthorizationV1Error> {
        let fields = device_enrollment_pop_map(raw)?;
        if authorization_uint(&fields, 1)? != PROTOCOL_VERSION {
            return Err(AuthorizationV1Error::InvalidField);
        }
        let account_id = authorization_fixed::<16>(&fields, 2)?;
        let device_id = authorization_fixed::<16>(&fields, 3)?;
        let epoch = authorization_uint(&fields, 4)?;
        let enrollment_cert_digest = authorization_fixed::<32>(&fields, 5)?;
        let challenge_id = authorization_fixed::<16>(&fields, 6)?;
        let challenge_nonce = authorization_fixed::<32>(&fields, 7)?;
        let signature = authorization_fixed::<64>(&fields, 8)?;
        validate_device_enrollment_pop_fields(account_id, device_id, epoch, challenge_id)?;
        Ok(Self {
            raw: raw.to_vec(), account_id, device_id, epoch, enrollment_cert_digest,
            challenge_id, challenge_nonce, signature,
        })
    }

    /// Verify the proof signature only. The public key must come from the verified enrollment certificate.
    pub fn verify(&self, device_signing_pub: &[u8; 32]) -> Result<(), AuthorizationV1Error> {
        validate_device_enrollment_pop_fields(
            self.account_id, self.device_id, self.epoch, self.challenge_id,
        )?;
        use ed25519_dalek::{Signature, VerifyingKey};
        let public = VerifyingKey::from_bytes(device_signing_pub)
            .map_err(|_| AuthorizationV1Error::InvalidField)?;
        let signature = Signature::from_bytes(&self.signature);
        let core = core_device_enrollment_pop(
            self.account_id, self.device_id, self.epoch, self.enrollment_cert_digest,
            self.challenge_id, self.challenge_nonce,
        )?;
        public.verify_strict(&[DEVICE_ENROLLMENT_POP_DOMAIN, core.as_slice()].concat(), &signature)
            .map_err(|_| AuthorizationV1Error::InvalidField)
    }

    /// Verify the recovery-signed enrollment, exact certificate digest, and challenge values.
    /// The expected challenge ID/nonce MUST be loaded from authoritative server storage;
    /// passing caller-provided values does not prove challenge freshness or one-time use.
    pub fn verify_for_enrollment_and_challenge(
        &self,
        recovery_pub: &[u8; 32],
        enrollment_certificate_raw: &[u8],
        expected_challenge_id: &[u8; 16],
        expected_challenge_nonce: &[u8; 32],
    ) -> Result<(), AuthorizationV1Error> {
        let enrollment = DeviceEnrollmentAuthorizationV1::parse(enrollment_certificate_raw)?;
        enrollment.verify(recovery_pub)?;
        use sha2::{Digest, Sha256};
        let exact_digest: [u8; 32] = Sha256::digest(enrollment_certificate_raw).into();
        if self.enrollment_cert_digest != exact_digest
            || self.account_id != enrollment.account_id
            || self.device_id != enrollment.device_id
            || self.epoch != enrollment.epoch
            || &self.challenge_id != expected_challenge_id
            || &self.challenge_nonce != expected_challenge_nonce
        {
            return Err(AuthorizationV1Error::InvalidField);
        }
        self.verify(&enrollment.dsk_pub)
    }
}
/// Produce a DeviceEnrollmentPoPV1 only for a recovery-authorized certificate whose
/// identity and public keys match the native context holding the signing key.
/// The caller/server must still check the challenge against authoritative, one-time server state.
pub(crate) fn sign_device_enrollment_pop_for_context(
    device_signing_key: &SigningKey,
    recovery_public_key: &[u8; 32],
    enrollment_certificate_raw: &[u8],
    expected_account_id: [u8; 16],
    expected_device_id: [u8; 16],
    expected_dsk_public_key: [u8; 32],
    expected_ddhk_public_key: [u8; 32],
    challenge_id: [u8; 16],
    challenge_nonce: [u8; 32],
) -> Result<Vec<u8>, AuthorizationV1Error> {
    use sha2::{Digest, Sha256};

    let enrollment = DeviceEnrollmentAuthorizationV1::parse(enrollment_certificate_raw)?;
    enrollment.verify(recovery_public_key)?;
    if enrollment.account_id != expected_account_id
        || enrollment.device_id != expected_device_id
        || enrollment.dsk_pub != expected_dsk_public_key
        || enrollment.ddhk_pub != expected_ddhk_public_key
        || device_signing_key.verifying_key().to_bytes() != expected_dsk_public_key
    {
        return Err(AuthorizationV1Error::InvalidField);
    }

    let enrollment_cert_digest: [u8; 32] = Sha256::digest(enrollment_certificate_raw).into();
    let core = core_device_enrollment_pop(
        expected_account_id,
        expected_device_id,
        enrollment.epoch,
        enrollment_cert_digest,
        challenge_id,
        challenge_nonce,
    )?;
    let signature = device_signing_key.sign(&[DEVICE_ENROLLMENT_POP_DOMAIN, core.as_slice()].concat());
    cbor::encode_canonical(&Value::Map(vec![
        (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
        (Value::Int(2), Value::Bytes(expected_account_id.to_vec())),
        (Value::Int(3), Value::Bytes(expected_device_id.to_vec())),
        (Value::Int(4), Value::Int(enrollment.epoch as i128)),
        (Value::Int(5), Value::Bytes(enrollment_cert_digest.to_vec())),
        (Value::Int(6), Value::Bytes(challenge_id.to_vec())),
        (Value::Int(7), Value::Bytes(challenge_nonce.to_vec())),
        (Value::Int(8), Value::Bytes(signature.to_bytes().to_vec())),
    ]))
    .map_err(|_| AuthorizationV1Error::Cbor)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::recovery_signing_key;
    use ed25519_dalek::{Signature, SigningKey, Verifier};

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

    /// Explicitly ignored generator for the separate lifecycle candidate vector file.
    /// Run only through the dedicated PowerShell script; this never changes authorization_v1.json.
    #[test]
    #[ignore = "manual generator for lifecycle_wire_v1.json candidate fixture"]
    fn generate_lifecycle_wire_v1_candidate_vector() {
        use ed25519_dalek::SigningKey;
        use sha2::{Digest, Sha256};
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

        fn hex(bytes: &[u8]) -> String {
            const TABLE: &[u8; 16] = b"0123456789abcdef";
            let mut out = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                out.push(TABLE[(byte >> 4) as usize] as char);
                out.push(TABLE[(byte & 0x0f) as usize] as char);
            }
            out
        }

        let recovery = key();
        let recovery_pub = recovery.verifying_key().to_bytes();
        let account_id = bytes::<16>(0x11);
        let device_id = bytes::<16>(0x22);
        let request_id = bytes::<16>(0x66);
        let dsk_secret = SigningKey::from_bytes(&[0x33u8; 32]);
        let dsk_pub = dsk_secret.verifying_key().to_bytes();
        let ddhk_secret = StaticSecret::from([0x44u8; 32]);
        let ddhk_pub = X25519PublicKey::from(&ddhk_secret).to_bytes();

        let legacy_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/authorization_v1.json");
        let legacy_raw = std::fs::read_to_string(legacy_path).expect("existing authorization vectors");
        let legacy: serde_json::Value = serde_json::from_str(&legacy_raw).expect("valid existing vector JSON");
        assert_eq!(hex(&recovery_pub), legacy["recovery"]["public_key_hex"].as_str().unwrap(),
            "generator recovery key must remain consistent with existing authorization vectors");
        assert_eq!(hex(&recovery_commitment(&recovery_pub)), legacy["recovery"]["commitment_hex"].as_str().unwrap(),
            "generator recovery commitment must remain consistent with existing authorization vectors");

        let enrollment_wire = sign_device_enrollment(
            &recovery, account_id, 4, device_id, dsk_pub, ddhk_pub,
        ).expect("candidate enrollment certificate");
        let enrollment = DeviceEnrollmentAuthorizationV1::parse(&enrollment_wire)
            .expect("parse candidate enrollment certificate");
        enrollment.verify(&recovery_pub).expect("verify enrollment certificate");
        let enrollment_core = cbor::encode_canonical(&Value::Map(vec![
            (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
            (Value::Int(2), Value::Bytes(account_id.to_vec())),
            (Value::Int(3), Value::Int(4)),
            (Value::Int(4), Value::Bytes(device_id.to_vec())),
            (Value::Int(5), Value::Bytes(dsk_pub.to_vec())),
            (Value::Int(6), Value::Bytes(ddhk_pub.to_vec())),
        ])).expect("canonical enrollment core");
        let enrollment_signed_message = [DEVICE_ENROLL_DOMAIN, enrollment_core.as_slice()].concat();
        let enrollment_digest: [u8; 32] = Sha256::digest(&enrollment_wire).into();

        let request_wire = sign_recovery_request(
            &recovery, account_id, 3, 4, request_id, device_id, &enrollment_wire,
        ).expect("candidate recovery request");
        let request = RecoveryRequestV1::parse(&request_wire).expect("parse candidate recovery request");
        request.verify_for_enrollment(&recovery_pub, &enrollment_wire)
            .expect("verify request and exact referenced enrollment under same recovery key");
        let request_core = cbor::encode_canonical(&Value::Map(vec![
            (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
            (Value::Int(2), Value::Bytes(request.account_id.to_vec())),
            (Value::Int(3), Value::Int(request.old_epoch as i128)),
            (Value::Int(4), Value::Int(request.new_epoch as i128)),
            (Value::Int(5), Value::Bytes(request.request_id.to_vec())),
            (Value::Int(6), Value::Bytes(request.target_device_id.to_vec())),
            (Value::Int(7), Value::Bytes(request.enrollment_cert_digest.to_vec())),
        ])).expect("canonical recovery-request core");
        let request_signed_message = [RECOVERY_REQUEST_DOMAIN, request_core.as_slice()].concat();

        let recovery_json = format!(
            r#"{{"public_key_hex":"{}","commitment_hex":"{}"}}"#,
            hex(&recovery_pub), hex(&recovery_commitment(&recovery_pub)),
        );
        let enrollment_json = format!(
            r#"{{"domain_ascii":"PM-V1-DEVICE-ENROLL-v1","account_id_hex":"{}","epoch":4,"device_id_hex":"{}","dsk_public_key_hex":"{}","ddhk_public_key_hex":"{}","core_cbor_hex":"{}","signed_message_hex":"{}","signature_hex":"{}","sha256_certificate_hex":"{}","certificate_cbor_hex":"{}"}}"#,
            hex(&enrollment.account_id), hex(&enrollment.device_id), hex(&enrollment.dsk_pub),
            hex(&enrollment.ddhk_pub), hex(&enrollment_core), hex(&enrollment_signed_message),
            hex(&enrollment.signature), hex(&enrollment_digest), hex(&enrollment_wire),
        );
        let request_json = format!(
            r#"{{"domain_ascii":"PM-V1-RECOVERY-REQUEST-v1","account_id_hex":"{}","old_epoch":{},"new_epoch":{},"request_id_hex":"{}","target_device_id_hex":"{}","enrollment_certificate_digest_sha256_hex":"{}","core_cbor_hex":"{}","signed_message_hex":"{}","signature_hex":"{}","request_cbor_hex":"{}"}}"#,
            hex(&request.account_id), request.old_epoch, request.new_epoch, hex(&request.request_id),
            hex(&request.target_device_id), hex(&request.enrollment_cert_digest), hex(&request_core),
            hex(&request_signed_message), hex(&request.signature), hex(&request_wire),
        );
        let json = format!(
            concat!(
                "{{\n",
                "  \"schema\": \"lifecycle-wire-v1-candidate\",\n",
                "  \"status\": \"candidate_not_frozen\",\n",
                "  \"note\": \"Candidate reference vector generated by Rust; not a production authorization or frozen protocol.\",\n",
                "  \"recovery\": {},\n",
                "  \"enrollment\": {},\n",
                "  \"recovery_request\": {},\n",
                "  \"negative_cases_to_test\": [\n",
                "    \"wrong recovery key\",\n",
                "    \"request and enrollment signed by different recovery keys\",\n",
                "    \"tampered signature\",\n",
                "    \"altered exact enrollment certificate digest\",\n",
                "    \"mismatched account, target device, or epoch\",\n",
                "    \"zero request identifier\",\n",
                "    \"epoch overflow or non-consecutive transition\",\n",
                "    \"unknown fields, non-canonical CBOR, truncation, or trailing bytes\"\n",
                "  ]\n",
                "}}\n"
            ),
            recovery_json, enrollment_json, request_json,
        );
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/lifecycle_wire_v1.json");
        assert!(!std::path::Path::new(path).exists(), "refusing to overwrite an existing lifecycle vector file");
        std::fs::write(path, json).expect("write candidate lifecycle vector JSON");
        println!("Generated candidate vector: {path}");
    }
    #[test]
    fn recovery_request_candidate_round_trips_and_binds_exact_enrollment_certificate() {
        use sha2::{Digest, Sha256};
        let recovery = key();
        let account = bytes::<16>(0x11);
        let target_device = bytes::<16>(0x22);
        let request_id = bytes::<16>(0x66);
        let dsk = bytes::<32>(0x33);
        let ddhk = bytes::<32>(0x44);
        let enrollment = sign_device_enrollment(
            &recovery, account, 4, target_device, dsk, ddhk,
        ).unwrap();
        let request = sign_recovery_request(
            &recovery, account, 3, 4, request_id, target_device, &enrollment,
        ).unwrap();

        let parsed = RecoveryRequestV1::parse(&request).expect("candidate request parses");
        assert_eq!(parsed.raw, request);
        assert_eq!(parsed.account_id, account);
        assert_eq!(parsed.old_epoch, 3);
        assert_eq!(parsed.new_epoch, 4);
        assert_eq!(parsed.request_id, request_id);
        assert_eq!(parsed.target_device_id, target_device);
        let expected_digest: [u8; 32] = Sha256::digest(&enrollment).into();
        assert_eq!(parsed.enrollment_cert_digest, expected_digest);
        parsed.verify(&recovery.verifying_key().to_bytes()).unwrap();
        parsed.verify_for_enrollment(&recovery.verifying_key().to_bytes(), &enrollment).unwrap();

        let Value::Map(fields) = crate::cbor::decode_strict(&request).unwrap() else {
            panic!("expected canonical request map");
        };
        assert_eq!(fields.len(), 8);
        let core = core_recovery_request(
            account, 3, 4, request_id, target_device, expected_digest,
        ).unwrap();
        let signature = Signature::from_bytes(&parsed.signature);
        recovery.verifying_key()
            .verify(&[RECOVERY_REQUEST_DOMAIN, core.as_slice()].concat(), &signature)
            .unwrap();
    }

    #[test]
    fn recovery_request_candidate_rejects_wrong_keys_tampering_and_malformed_wire() {
        use ed25519_dalek::SigningKey;
        let recovery = key();
        let other = SigningKey::from_bytes(&[0x42; 32]);
        let account = bytes::<16>(0x11);
        let target_device = bytes::<16>(0x22);
        let request_id = bytes::<16>(0x66);
        let enrollment = sign_device_enrollment(
            &recovery, account, 4, target_device, bytes::<32>(0x33), bytes::<32>(0x44),
        ).unwrap();
        assert!(sign_recovery_request(
            &recovery, account, 3, 4, [0u8; 16], target_device, &enrollment,
        ).is_err(), "zero request ID rejected");
        let raw = sign_recovery_request(
            &recovery, account, 3, 4, request_id, target_device, &enrollment,
        ).unwrap();
        let parsed = RecoveryRequestV1::parse(&raw).unwrap();
        assert!(parsed.verify(&other.verifying_key().to_bytes()).is_err());

        let mut noncanonical_map_length = vec![0xb8, 0x08];
        noncanonical_map_length.extend_from_slice(&raw[1..]);
        assert!(RecoveryRequestV1::parse(&noncanonical_map_length).is_err(),
            "non-minimal map length rejected");
        let Value::Map(mut unknown_fields) = crate::cbor::decode_strict(&raw).unwrap() else {
            panic!("expected request map");
        };
        unknown_fields.push((Value::Int(9), Value::Int(0)));
        let unknown_field_raw = cbor::encode_canonical(&Value::Map(unknown_fields)).unwrap();
        assert!(RecoveryRequestV1::parse(&unknown_field_raw).is_err(),
            "unknown field rejected");

        let mut tampered = raw.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let tampered_parsed = RecoveryRequestV1::parse(&tampered)
            .expect("signature tampering remains structurally parseable");
        assert!(tampered_parsed.verify(&recovery.verifying_key().to_bytes()).is_err());
        assert!(RecoveryRequestV1::parse(&raw[..raw.len() - 1]).is_err(), "truncated request rejected");
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(RecoveryRequestV1::parse(&trailing).is_err(), "trailing bytes rejected");
        let mut wrong_version = raw.clone();
        wrong_version[2] = 0x02;
        assert!(RecoveryRequestV1::parse(&wrong_version).is_err(), "unsupported version rejected");

        let other_key_certificate = sign_device_enrollment(
            &other, account, 4, target_device, bytes::<32>(0x33), bytes::<32>(0x44),
        ).unwrap();
        assert!(sign_recovery_request(
            &recovery, account, 3, 4, bytes::<16>(0x67), target_device, &other_key_certificate,
        ).is_err(), "request and enrollment must use the same recovery key");
    }

    #[test]
    fn recovery_request_candidate_rejects_binding_mismatch_and_epoch_overflow() {
        let recovery = key();
        let account = bytes::<16>(0x11);
        let target_device = bytes::<16>(0x22);
        let request_id = bytes::<16>(0x66);
        let enrollment = sign_device_enrollment(
            &recovery, account, 4, target_device, bytes::<32>(0x33), bytes::<32>(0x44),
        ).unwrap();

        assert!(sign_recovery_request(
            &recovery, account, 3, 4, request_id, bytes::<16>(0x23), &enrollment,
        ).is_err(), "target device must match enrollment certificate");
        assert!(sign_recovery_request(
            &recovery, bytes::<16>(0x12), 3, 4, request_id, target_device, &enrollment,
        ).is_err(), "account must match enrollment certificate");
        assert_eq!(
            sign_recovery_request(
                &recovery, account, LIFECYCLE_EPOCH_MAX, LIFECYCLE_EPOCH_MAX + 1,
                request_id, target_device, &enrollment,
            ),
            Err(AuthorizationV1Error::InvalidEpoch),
        );
        assert_eq!(
            sign_recovery_request(
                &recovery, account, 0, 1, request_id, target_device, &enrollment,
            ),
            Err(AuthorizationV1Error::InvalidEpoch),
        );

        let alternate_certificate = sign_device_enrollment(
            &recovery, account, 4, target_device, bytes::<32>(0x35), bytes::<32>(0x44),
        ).unwrap();
        let request = sign_recovery_request(
            &recovery, account, 3, 4, request_id, target_device, &enrollment,
        ).unwrap();
        let parsed = RecoveryRequestV1::parse(&request).unwrap();
        assert!(parsed.verify_for_enrollment(
            &recovery.verifying_key().to_bytes(), &alternate_certificate,
        ).is_err(), "different exact enrollment certificate digest must fail");
    }

    fn sign_test_device_enrollment_pop(
        device_signing_key: &SigningKey,
        account_id: [u8; 16],
        device_id: [u8; 16],
        epoch: u64,
        enrollment_cert_digest: [u8; 32],
        challenge_id: [u8; 16],
        challenge_nonce: [u8; 32],
    ) -> Result<Vec<u8>, AuthorizationV1Error> {
        let core = core_device_enrollment_pop(
            account_id, device_id, epoch, enrollment_cert_digest, challenge_id, challenge_nonce,
        )?;
        let signature = device_signing_key.sign(&[DEVICE_ENROLLMENT_POP_DOMAIN, core.as_slice()].concat());
        cbor::encode_canonical(&Value::Map(vec![
            (Value::Int(1), Value::Int(PROTOCOL_VERSION as i128)),
            (Value::Int(2), Value::Bytes(account_id.to_vec())),
            (Value::Int(3), Value::Bytes(device_id.to_vec())),
            (Value::Int(4), Value::Int(epoch as i128)),
            (Value::Int(5), Value::Bytes(enrollment_cert_digest.to_vec())),
            (Value::Int(6), Value::Bytes(challenge_id.to_vec())),
            (Value::Int(7), Value::Bytes(challenge_nonce.to_vec())),
            (Value::Int(8), Value::Bytes(signature.to_bytes().to_vec())),
        ]))
        .map_err(|_| AuthorizationV1Error::Cbor)
    }

    #[test]
    fn device_enrollment_pop_candidate_round_trips_and_binds_exact_certificate_and_challenge() {
        use sha2::{Digest, Sha256};
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

        let recovery = key();
        let recovery_pub = recovery.verifying_key().to_bytes();
        let account = bytes::<16>(0x71);
        let device = bytes::<16>(0x72);
        let epoch = 7;
        let device_signer = SigningKey::from_bytes(&[0x37u8; 32]);
        let ddhk_secret = StaticSecret::from([0x48u8; 32]);
        let ddhk_public = X25519PublicKey::from(&ddhk_secret).to_bytes();
        let enrollment_raw = sign_device_enrollment(
            &recovery, account, epoch, device, device_signer.verifying_key().to_bytes(), ddhk_public,
        ).unwrap();
        let digest: [u8; 32] = Sha256::digest(&enrollment_raw).into();
        let challenge_id = bytes::<16>(0x73);
        let challenge_nonce = bytes::<32>(0x74);
        let raw = sign_test_device_enrollment_pop(
            &device_signer, account, device, epoch, digest, challenge_id, challenge_nonce,
        ).unwrap();
        let parsed = DeviceEnrollmentPoPV1::parse(&raw).unwrap();
        parsed.verify_for_enrollment_and_challenge(
            &recovery_pub, &enrollment_raw, &challenge_id, &challenge_nonce,
        ).unwrap();
        assert_eq!(parsed.account_id, account);
        assert_eq!(parsed.device_id, device);
        assert_eq!(parsed.epoch, epoch);
        assert_eq!(parsed.enrollment_cert_digest, digest);
        assert_eq!(parsed.challenge_id, challenge_id);
        assert_eq!(parsed.challenge_nonce, challenge_nonce);
        assert_eq!(parsed.raw, raw);
        assert!(parsed.verify_for_enrollment_and_challenge(
            &recovery_pub, &enrollment_raw, &bytes::<16>(0x75), &challenge_nonce,
        ).is_err(), "different challenge ID must fail");
        assert!(parsed.verify_for_enrollment_and_challenge(
            &recovery_pub, &enrollment_raw, &challenge_id, &bytes::<32>(0x76),
        ).is_err(), "different challenge nonce must fail");
    }

    #[test]
    fn device_enrollment_pop_candidate_rejects_wrong_keys_tampering_mismatched_certificate_and_bad_shape() {
        use sha2::{Digest, Sha256};
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

        let recovery = key();
        let recovery_pub = recovery.verifying_key().to_bytes();
        let wrong_recovery = SigningKey::from_bytes(&[0x19u8; 32]).verifying_key().to_bytes();
        let account = bytes::<16>(0x71);
        let device = bytes::<16>(0x72);
        let epoch = 7;
        let device_signer = SigningKey::from_bytes(&[0x37u8; 32]);
        let other_device_signer = SigningKey::from_bytes(&[0x38u8; 32]);
        let ddhk_secret = StaticSecret::from([0x48u8; 32]);
        let ddhk_public = X25519PublicKey::from(&ddhk_secret).to_bytes();
        let enrollment_raw = sign_device_enrollment(
            &recovery, account, epoch, device, device_signer.verifying_key().to_bytes(), ddhk_public,
        ).unwrap();
        let other_enrollment_raw = sign_device_enrollment(
            &recovery, account, epoch, device, other_device_signer.verifying_key().to_bytes(), ddhk_public,
        ).unwrap();
        let digest: [u8; 32] = Sha256::digest(&enrollment_raw).into();
        let challenge_id = bytes::<16>(0x73);
        let challenge_nonce = bytes::<32>(0x74);
        let raw = sign_test_device_enrollment_pop(
            &device_signer, account, device, epoch, digest, challenge_id, challenge_nonce,
        ).unwrap();
        let parsed = DeviceEnrollmentPoPV1::parse(&raw).unwrap();
        assert!(parsed.verify_for_enrollment_and_challenge(
            &wrong_recovery, &enrollment_raw, &challenge_id, &challenge_nonce,
        ).is_err(), "enrollment signed under wrong recovery key must fail");
        assert!(parsed.verify_for_enrollment_and_challenge(
            &recovery_pub, &other_enrollment_raw, &challenge_id, &challenge_nonce,
        ).is_err(), "different signed certificate and DSK must fail exact binding");
        assert!(parsed.verify_for_enrollment_and_challenge(
            &recovery_pub, &enrollment_raw, &bytes::<16>(0x75), &challenge_nonce,
        ).is_err());

        let mut tampered = raw.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let parsed_tampered = DeviceEnrollmentPoPV1::parse(&tampered).expect("signature mutation remains structurally parseable");
        assert!(parsed_tampered.verify_for_enrollment_and_challenge(
            &recovery_pub, &enrollment_raw, &challenge_id, &challenge_nonce,
        ).is_err(), "tampered proof signature must fail");
        assert!(DeviceEnrollmentPoPV1::parse(&raw[..raw.len() - 1]).is_err(), "truncated proof must fail");
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(DeviceEnrollmentPoPV1::parse(&trailing).is_err(), "trailing bytes must fail");
        assert!(validate_device_enrollment_pop_fields([0; 16], device, epoch, challenge_id).is_err());
        assert!(validate_device_enrollment_pop_fields(account, device, epoch, [0; 16]).is_err());
        assert!(validate_device_enrollment_pop_fields(account, device, LIFECYCLE_EPOCH_MAX + 1, challenge_id).is_err());
    }

    /// Ignored, explicit fixture augmenter. The private test key stays in Rust test code and is not emitted into JSON.
    #[test]
    #[ignore = "manual generator for DeviceEnrollmentPoPV1 candidate vector fixture"]
    fn generate_device_enrollment_pop_candidate_vector() {
        use sha2::{Digest, Sha256};
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

        fn hex(bytes: &[u8]) -> String {
            const TABLE: &[u8; 16] = b"0123456789abcdef";
            let mut out = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                out.push(TABLE[(byte >> 4) as usize] as char);
                out.push(TABLE[(byte & 0x0f) as usize] as char);
            }
            out
        }
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/lifecycle_wire_v1.json");
        let raw_json = std::fs::read_to_string(path).expect("existing lifecycle candidate fixture");
        let mut fixture: serde_json::Value = serde_json::from_str(&raw_json).expect("valid lifecycle JSON");
        assert_eq!(fixture["schema"].as_str(), Some("lifecycle-wire-v1-candidate"));
        assert_eq!(fixture["status"].as_str(), Some("candidate_not_frozen"));
        assert!(fixture.get("device_enrollment_pop").is_none(), "refusing to overwrite existing PoP vector");
        assert!(fixture.get("pop_enrollment_certificate").is_none(), "refusing to overwrite existing PoP enrollment cert");

        let recovery = key();
        let recovery_pub = recovery.verifying_key().to_bytes();
        let mut expected_recovery_pub = [0u8; 32];
        for (i, pair) in fixture["recovery"]["public_key_hex"].as_str().unwrap().as_bytes().chunks_exact(2).enumerate() {
            expected_recovery_pub[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        assert_eq!(recovery_pub, expected_recovery_pub, "test recovery key differs from shared lifecycle fixture");

        // Test keys are real derived Ed25519/X25519 public keys; no placeholder public keys are used.
        let account = bytes::<16>(0x71);
        let device = bytes::<16>(0x72);
        let epoch = 7u64;
        let device_signer = SigningKey::from_bytes(&[0x37u8; 32]);
        let device_pub = device_signer.verifying_key().to_bytes();
        let ddhk_secret = StaticSecret::from([0x48u8; 32]);
        let ddhk_public = X25519PublicKey::from(&ddhk_secret).to_bytes();
        let enrollment_raw = sign_device_enrollment(
            &recovery, account, epoch, device, device_pub, ddhk_public,
        ).expect("valid candidate enrollment certificate");
        let enrollment = DeviceEnrollmentAuthorizationV1::parse(&enrollment_raw).expect("parse generated enrollment");
        enrollment.verify(&recovery_pub).expect("verify generated enrollment");
        let enrollment_digest: [u8; 32] = Sha256::digest(&enrollment_raw).into();
        let challenge_id = bytes::<16>(0x73);
        let challenge_nonce = bytes::<32>(0x74);
        let proof_raw = sign_test_device_enrollment_pop(
            &device_signer, account, device, epoch, enrollment_digest, challenge_id, challenge_nonce,
        ).expect("generated proof-of-possession response");
        let proof = DeviceEnrollmentPoPV1::parse(&proof_raw).expect("parse generated proof");
        proof.verify_for_enrollment_and_challenge(
            &recovery_pub, &enrollment_raw, &challenge_id, &challenge_nonce,
        ).expect("verify proof against signed certificate and issued test challenge");

        let enrollment_core = core_enrollment(account, epoch, device, device_pub, ddhk_public).expect("enrollment core");
        let enrollment_message = [DEVICE_ENROLL_DOMAIN, enrollment_core.as_slice()].concat();
        let enrollment_json = serde_json::json!({
            "domain_ascii": "PM-V1-DEVICE-ENROLL-v1",
            "account_id_hex": hex(&account),
            "epoch": epoch,
            "device_id_hex": hex(&device),
            "dsk_public_key_hex": hex(&device_pub),
            "ddhk_public_key_hex": hex(&ddhk_public),
            "core_cbor_hex": hex(&enrollment_core),
            "signed_message_hex": hex(&enrollment_message),
            "signature_hex": hex(&enrollment.signature),
            "sha256_certificate_hex": hex(&enrollment_digest),
            "certificate_cbor_hex": hex(&enrollment_raw),
            "note": "Dedicated PoP test enrollment; public keys are derived from test-only private keys held in Rust tests."
        });
        let proof_core = core_device_enrollment_pop(
            proof.account_id, proof.device_id, proof.epoch, proof.enrollment_cert_digest,
            proof.challenge_id, proof.challenge_nonce,
        ).expect("proof core");
        let signed_message = [DEVICE_ENROLLMENT_POP_DOMAIN, proof_core.as_slice()].concat();
        fixture["pop_enrollment_certificate"] = enrollment_json;
        fixture["device_enrollment_pop"] = serde_json::json!({
            "domain_ascii": "PM-V1-DEVICE-POP-v1",
            "account_id_hex": hex(&proof.account_id),
            "device_id_hex": hex(&proof.device_id),
            "epoch": proof.epoch,
            "enrollment_certificate_digest_sha256_hex": hex(&proof.enrollment_cert_digest),
            "challenge_id_hex": hex(&proof.challenge_id),
            "challenge_nonce_hex": hex(&proof.challenge_nonce),
            "core_cbor_hex": hex(&proof_core),
            "signed_message_hex": hex(&signed_message),
            "signature_hex": hex(&proof.signature),
            "proof_cbor_hex": hex(&proof_raw),
            "note": "Candidate wire vector only; challenge issuance, expiry, single-use, device-context DDHK ownership and activation are server/native-context responsibilities."
        });
        let output = serde_json::to_string_pretty(&fixture).expect("serialize lifecycle fixture");
        std::fs::write(path, format!("{output}\n")).expect("write lifecycle PoP candidate fixture");
        println!("Added DeviceEnrollmentPoPV1 candidate vector: {path}");
    }
    #[test]
    fn recovery_abort_candidate_round_trips_and_binds_exact_request() {
        let recovery = key();
        let recovery_pub = recovery.verifying_key().to_bytes();
        let account = bytes::<16>(0x11);
        let target_device = bytes::<16>(0x22);
        let target_signer = SigningKey::from_bytes(&[0x33u8; 32]);
        let enrollment = sign_device_enrollment(
            &recovery,
            account,
            4,
            target_device,
            target_signer.verifying_key().to_bytes(),
            bytes::<32>(0x44),
        ).unwrap();
        let request = sign_recovery_request(
            &recovery, account, 3, 4, bytes::<16>(0x66), target_device, &enrollment,
        ).unwrap();
        let device_signer = SigningKey::from_bytes(&[0x77u8; 32]);
        let device_id = bytes::<16>(0x55);
        let raw = sign_recovery_abort(&device_signer, &recovery_pub, device_id, &request).unwrap();
        let parsed = RecoveryAbortV1::parse(&raw).unwrap();
        parsed.verify_for_request(&recovery_pub, &device_signer.verifying_key().to_bytes(), &request).unwrap();
        assert_eq!(parsed.account_id, account);
        assert_eq!(parsed.device_id, device_id);
        assert_eq!(parsed.old_epoch, 3);
        assert_eq!(parsed.new_epoch, 4);
        assert_eq!(parsed.request_id, bytes::<16>(0x66));
        assert_eq!(parsed.raw, raw);
    }

    #[test]
    fn recovery_abort_candidate_rejects_wrong_keys_tampering_and_wrong_request() {
        let recovery = key();
        let recovery_pub = recovery.verifying_key().to_bytes();
        let account = bytes::<16>(0x11);
        let target_device = bytes::<16>(0x22);
        let target_signer = SigningKey::from_bytes(&[0x33u8; 32]);
        let enrollment = sign_device_enrollment(
            &recovery, account, 4, target_device, target_signer.verifying_key().to_bytes(), bytes::<32>(0x44),
        ).unwrap();
        let request = sign_recovery_request(
            &recovery, account, 3, 4, bytes::<16>(0x66), target_device, &enrollment,
        ).unwrap();
        let device_signer = SigningKey::from_bytes(&[0x77u8; 32]);
        let device_pub = device_signer.verifying_key().to_bytes();
        let raw = sign_recovery_abort(&device_signer, &recovery_pub, bytes::<16>(0x55), &request).unwrap();
        let parsed = RecoveryAbortV1::parse(&raw).unwrap();

        let wrong_device = SigningKey::from_bytes(&[0x78u8; 32]).verifying_key().to_bytes();
        assert!(parsed.verify(&wrong_device).is_err());
        let wrong_recovery = SigningKey::from_bytes(&[0x42u8; 32]).verifying_key().to_bytes();
        assert!(parsed.verify_for_request(&wrong_recovery, &device_pub, &request).is_err());

        let mut tampered = raw.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let parsed_tampered = RecoveryAbortV1::parse(&tampered).unwrap();
        assert!(parsed_tampered.verify(&device_pub).is_err());
        assert!(RecoveryAbortV1::parse(&raw[..raw.len() - 1]).is_err());
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(RecoveryAbortV1::parse(&trailing).is_err());

        let another_request = sign_recovery_request(
            &recovery, account, 3, 4, bytes::<16>(0x67), target_device, &enrollment,
        ).unwrap();
        assert!(parsed.verify_for_request(&recovery_pub, &device_pub, &another_request).is_err());
        assert!(sign_recovery_abort(&device_signer, &recovery_pub, [0u8; 16], &request).is_err());
        assert!(sign_recovery_abort(&device_signer, &recovery_pub, bytes::<16>(0x55), b"not-cbor").is_err());
    }

    /// Explicitly ignored vector augmentation. It only adds recovery_abort to the separate lifecycle candidate fixture.
    #[test]
    #[ignore = "manual generator for RecoveryAbortV1 candidate vector fixture"]
    fn generate_recovery_abort_candidate_vector() {
        use ed25519_dalek::SigningKey;
        use sha2::{Digest, Sha256};

        fn hex(bytes: &[u8]) -> String {
            const TABLE: &[u8; 16] = b"0123456789abcdef";
            let mut out = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                out.push(TABLE[(byte >> 4) as usize] as char);
                out.push(TABLE[(byte & 0x0f) as usize] as char);
            }
            out
        }
        fn decode_hex(value: &str) -> Vec<u8> {
            assert_eq!(value.len() % 2, 0, "odd-length fixture hex");
            (0..value.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("valid fixture hex"))
                .collect()
        }
        fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
            let decoded = decode_hex(value);
            assert_eq!(decoded.len(), N, "fixture value has the wrong size");
            let mut out = [0u8; N];
            out.copy_from_slice(&decoded);
            out
        }

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/lifecycle_wire_v1.json");
        let raw_json = std::fs::read_to_string(path).expect("existing lifecycle candidate vectors");
        let mut fixture: serde_json::Value = serde_json::from_str(&raw_json).expect("valid lifecycle JSON");
        assert_eq!(fixture["schema"].as_str(), Some("lifecycle-wire-v1-candidate"));
        assert_eq!(fixture["status"].as_str(), Some("candidate_not_frozen"));
        assert!(fixture.get("recovery_abort").is_none(), "refusing to overwrite an existing recovery_abort vector");

        let recovery_pub = fixed_hex::<32>(fixture["recovery"]["public_key_hex"].as_str().unwrap());
        let request_raw = decode_hex(fixture["recovery_request"]["request_cbor_hex"].as_str().unwrap());
        let request = RecoveryRequestV1::parse(&request_raw).expect("fixture request parses");
        request.verify(&recovery_pub).expect("fixture request signature verifies");
        let device_signer = SigningKey::from_bytes(&[0x77u8; 32]);
        let device_pub = device_signer.verifying_key().to_bytes();
        let aborter_id = bytes::<16>(0x55);
        let abort_raw = sign_recovery_abort(&device_signer, &recovery_pub, aborter_id, &request_raw)
            .expect("candidate RecoveryAbortV1");
        let abort = RecoveryAbortV1::parse(&abort_raw).expect("parse candidate abort");
        abort.verify_for_request(&recovery_pub, &device_pub, &request_raw)
            .expect("abort DSK signature and exact request binding verify");

        let core = core_recovery_abort(
            abort.account_id, abort.device_id, abort.old_epoch, abort.new_epoch,
            abort.request_id, abort.recovery_request_digest,
        ).expect("canonical abort core");
        let signed_message = [RECOVERY_ABORT_DOMAIN, core.as_slice()].concat();
        let request_digest: [u8; 32] = Sha256::digest(&request_raw).into();
        assert_eq!(abort.recovery_request_digest, request_digest);
        fixture["recovery_abort"] = serde_json::json!({
            "domain_ascii": "PM-V1-RECOVERY-ABORT-v1",
            "account_id_hex": hex(&abort.account_id),
            "aborting_device_id_hex": hex(&abort.device_id),
            "old_epoch": abort.old_epoch,
            "new_epoch": abort.new_epoch,
            "request_id_hex": hex(&abort.request_id),
            "recovery_request_digest_sha256_hex": hex(&abort.recovery_request_digest),
            "aborting_dsk_public_key_hex": hex(&device_pub),
            "core_cbor_hex": hex(&core),
            "signed_message_hex": hex(&signed_message),
            "signature_hex": hex(&abort.signature),
            "abort_cbor_hex": hex(&abort_raw),
            "note": "Test-only DSK fixture; active-device status and deadline are not represented by this wire vector."
        });
        let output = serde_json::to_string_pretty(&fixture).expect("serialize augmented lifecycle vector JSON");
        std::fs::write(path, format!("{output}\n")).expect("write augmented lifecycle candidate vector file");
        println!("Added RecoveryAbortV1 candidate vector: {path}");
    }
    #[test]
    fn received_authorization_verifiers_reject_wrong_key_version_and_trailing_data() {
        use ed25519_dalek::SigningKey;

        fn decode_hex(value: &str) -> Vec<u8> {
            assert_eq!(value.len() % 2, 0, "odd-length hex vector");
            (0..value.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("valid hex vector"))
                .collect()
        }
        fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
            let bytes = decode_hex(value);
            assert_eq!(bytes.len(), N, "wrong vector byte length");
            let mut out = [0u8; N];
            out.copy_from_slice(&bytes);
            out
        }

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/authorization_v1.json");
        let raw = std::fs::read_to_string(path).expect("shared authorization vector file");
        let vectors: serde_json::Value = serde_json::from_str(&raw).expect("valid authorization vector JSON");
        let recovery_pub = fixed_hex::<32>(vectors["recovery"]["public_key_hex"].as_str().unwrap());
        let wrong_recovery_pub = SigningKey::from_bytes(&[0x42; 32]).verifying_key().to_bytes();

        let enrollment_raw = decode_hex(vectors["enrollment"]["certificate_cbor_hex"].as_str().unwrap());
        let enrollment = DeviceEnrollmentAuthorizationV1::parse(&enrollment_raw).expect("valid enrollment vector parses");
        assert!(enrollment.verify(&wrong_recovery_pub).is_err(), "wrong recovery key must not verify enrollment");

        let mut enrollment_bad_signature = enrollment_raw.clone();
        *enrollment_bad_signature.last_mut().expect("nonempty enrollment certificate") ^= 1;
        let parsed_bad_enrollment = DeviceEnrollmentAuthorizationV1::parse(&enrollment_bad_signature)
            .expect("signature tampering must remain structurally parseable");
        assert!(parsed_bad_enrollment.verify(&recovery_pub).is_err(), "tampered enrollment signature must fail");
        assert!(DeviceEnrollmentAuthorizationV1::parse(&enrollment_raw[..enrollment_raw.len() - 1]).is_err(),
            "truncated enrollment certificate must fail parsing");
        let mut enrollment_trailing = enrollment_raw.clone();
        enrollment_trailing.push(0);
        assert!(DeviceEnrollmentAuthorizationV1::parse(&enrollment_trailing).is_err(),
            "trailing data must fail strict enrollment parsing");
        assert!(enrollment_raw.len() > 2 && enrollment_raw[0] == 0xa7 && enrollment_raw[1] == 0x01,
            "fixture encoding changed; revisit the version mutation test");
        let mut enrollment_wrong_version = enrollment_raw.clone();
        enrollment_wrong_version[2] = 0x02;
        assert!(DeviceEnrollmentAuthorizationV1::parse(&enrollment_wrong_version).is_err(),
            "unsupported enrollment version must fail parsing");

        for transition_value in vectors["transitions"].as_array().expect("transition vectors") {
            let transition_raw = decode_hex(transition_value["certificate_cbor_hex"].as_str().unwrap());
            let transition = EpochTransitionAuthorizationV1::parse(&transition_raw).expect("valid transition vector parses");
            assert!(transition.verify(&wrong_recovery_pub).is_err(), "wrong recovery key must not verify transition");

            let mut transition_bad_signature = transition_raw.clone();
            *transition_bad_signature.last_mut().expect("nonempty transition certificate") ^= 1;
            let parsed_bad_transition = EpochTransitionAuthorizationV1::parse(&transition_bad_signature)
                .expect("signature tampering must remain structurally parseable");
            assert!(parsed_bad_transition.verify(&recovery_pub).is_err(), "tampered transition signature must fail");
            assert!(EpochTransitionAuthorizationV1::parse(&transition_raw[..transition_raw.len() - 1]).is_err(),
                "truncated transition certificate must fail parsing");
            let mut transition_trailing = transition_raw.clone();
            transition_trailing.push(0);
            assert!(EpochTransitionAuthorizationV1::parse(&transition_trailing).is_err(),
                "trailing data must fail strict transition parsing");
            assert!(transition_raw.len() > 2 && transition_raw[0] == 0xa7 && transition_raw[1] == 0x01,
                "fixture encoding changed; revisit the version mutation test");
            let mut transition_wrong_version = transition_raw.clone();
            transition_wrong_version[2] = 0x02;
            assert!(EpochTransitionAuthorizationV1::parse(&transition_wrong_version).is_err(),
                "unsupported transition version must fail parsing");
        }
    }
    #[test]
    fn existing_authorization_json_certificates_parse_and_verify_in_rust() {
        fn decode_hex(value: &str) -> Vec<u8> {
            assert_eq!(value.len() % 2, 0, "odd-length hex vector");
            (0..value.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("valid hex vector"))
                .collect()
        }
        fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
            let bytes = decode_hex(value);
            assert_eq!(bytes.len(), N, "wrong vector byte length");
            let mut out = [0u8; N];
            out.copy_from_slice(&bytes);
            out
        }

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/authorization_v1.json");
        let raw = std::fs::read_to_string(path).expect("shared authorization vector file");
        let vectors: serde_json::Value = serde_json::from_str(&raw).expect("valid authorization vector JSON");
        let recovery_pub = fixed_hex::<32>(vectors["recovery"]["public_key_hex"].as_str().unwrap());

        let enrollment_raw = decode_hex(vectors["enrollment"]["certificate_cbor_hex"].as_str().unwrap());
        let enrollment = DeviceEnrollmentAuthorizationV1::parse(&enrollment_raw).unwrap();
        enrollment.verify(&recovery_pub).unwrap();
        assert_eq!(enrollment.raw, enrollment_raw);
        let mut tampered_enrollment = enrollment_raw.clone();
        *tampered_enrollment.last_mut().unwrap() ^= 1;
        assert!(DeviceEnrollmentAuthorizationV1::parse(&tampered_enrollment).unwrap().verify(&recovery_pub).is_err());
        assert!(DeviceEnrollmentAuthorizationV1::parse(&enrollment_raw[..enrollment_raw.len() - 1]).is_err());

        for transition in vectors["transitions"].as_array().unwrap() {
            let transition_raw = decode_hex(transition["certificate_cbor_hex"].as_str().unwrap());
            let parsed = EpochTransitionAuthorizationV1::parse(&transition_raw).unwrap();
            parsed.verify(&recovery_pub).unwrap();
            assert_eq!(parsed.raw, transition_raw);
            let mut tampered = transition_raw.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(EpochTransitionAuthorizationV1::parse(&tampered).unwrap().verify(&recovery_pub).is_err());
            assert!(EpochTransitionAuthorizationV1::parse(&transition_raw[..transition_raw.len() - 1]).is_err());
        }
    }
    #[test]
    fn existing_authorization_json_vectors_match_rust_signers() {
        fn decode_hex(value: &str) -> Vec<u8> {
            assert_eq!(value.len() % 2, 0, "odd-length hex vector");
            (0..value.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("valid hex vector"))
                .collect()
        }

        fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
            let bytes = decode_hex(value);
            assert_eq!(bytes.len(), N, "wrong vector byte length");
            let mut out = [0u8; N];
            out.copy_from_slice(&bytes);
            out
        }

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/authorization_v1.json");
        let raw = std::fs::read_to_string(path).expect("shared authorization vector file");
        let vectors: serde_json::Value = serde_json::from_str(&raw).expect("valid authorization vector JSON");
        assert_eq!(vectors["protocol"].as_str(), Some("authorization-v1"));

        let signing_key = key();
        let recovery_public = fixed_hex::<32>(
            vectors["recovery"]["public_key_hex"].as_str().expect("recovery public key"),
        );
        assert_eq!(signing_key.verifying_key().to_bytes(), recovery_public);
        assert_eq!(
            recovery_commitment(&recovery_public),
            fixed_hex::<32>(vectors["recovery"]["commitment_hex"].as_str().expect("recovery commitment")),
        );

        let enrollment = &vectors["enrollment"];
        let enrollment_domain = decode_hex(enrollment["domain_hex"].as_str().expect("enrollment domain"));
        assert_eq!(enrollment_domain.as_slice(), DEVICE_ENROLL_DOMAIN);
        let enrollment_bytes = sign_device_enrollment(
            &signing_key,
            fixed_hex::<16>(enrollment["account_id_hex"].as_str().expect("enrollment account ID")),
            enrollment["epoch"].as_u64().expect("enrollment epoch"),
            fixed_hex::<16>(enrollment["device_id_hex"].as_str().expect("enrollment device ID")),
            fixed_hex::<32>(enrollment["dsk_pub_hex"].as_str().expect("enrollment DSK")),
            fixed_hex::<32>(enrollment["ddhk_pub_hex"].as_str().expect("enrollment DDHK")),
        )
        .expect("Rust enrollment signing");
        assert_eq!(
            enrollment_bytes,
            decode_hex(enrollment["certificate_cbor_hex"].as_str().expect("enrollment certificate bytes")),
            "Rust enrollment bytes differ from shared Rust/Go vector",
        );

        let transitions = vectors["transitions"].as_array().expect("transition vectors");
        assert_eq!(transitions.len(), 2, "current vector suite should contain revoke and recovery-reset baselines");
        for transition in transitions {
            let domain = decode_hex(transition["domain_hex"].as_str().expect("transition domain"));
            assert_eq!(domain.as_slice(), EPOCH_TRANSITION_DOMAIN);
            let device_id = decode_hex(transition["device_id_hex"].as_str().expect("transition device ID"));
            let bytes = sign_epoch_transition(
                &signing_key,
                fixed_hex::<16>(transition["account_id_hex"].as_str().expect("transition account ID")),
                transition["old_epoch"].as_u64().expect("old epoch"),
                transition["new_epoch"].as_u64().expect("new epoch"),
                transition["action"].as_u64().expect("transition action"),
                &device_id,
            )
            .expect("Rust transition signing");
            assert_eq!(
                bytes,
                decode_hex(transition["certificate_cbor_hex"].as_str().expect("transition certificate bytes")),
                "Rust transition bytes differ from shared vector for {}",
                transition["id"].as_str().unwrap_or("unknown"),
            );
        }
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
