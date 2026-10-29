//! Candidate signed-prekey signature contract for Private Messenger.
//!
//! IMPORTANT: This wire contract is a candidate and is NOT FROZEN. Do not expose
//! enrollment routes or rely on this object for activation authorization until
//! Rust/Go shared vectors and lifecycle review are complete.
//!
//! Candidate signature:
//! Ed25519Sign(DSK_priv,
//!   b"PM-V1-SIGNED-PREKEY-v1" || canonical_cbor({
//!      1: 1,                 // protocol version
//!      2: AccountID,         // bstr(16)
//!      3: account_epoch,     // uint, 1..=u32::MAX
//!      4: DeviceID,          // bstr(16)
//!      5: SPK_ID,            // uint, 0..=u32::MAX
//!      6: SPK_pub,           // bstr(32), usable X25519 public key
//!   }))
//!
//! The complete signed object adds field 7 = bstr(64) signature. The ID range
//! matches PrekeyHandshakeHeader's existing u32 recipient_spk_id field.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::cbor::{self, Value};

pub const SIGNED_PREKEY_V1_DOMAIN: &[u8] = b"PM-V1-SIGNED-PREKEY-v1";
pub const SIGNED_PREKEY_V1_VERSION: u64 = 1;
pub const SIGNED_PREKEY_V1_MAX_EPOCH: u64 = u32::MAX as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedPrekeyV1Error {
    InvalidCbor,
    InvalidShape,
    UnsupportedVersion,
    InvalidField,
    InvalidX25519PublicKey,
    InvalidSignature,
}

/// Parsed candidate signed-prekey object.
///
/// This verifies cryptographic format only. Callers must separately compare
/// AccountID, epoch, DeviceID, SPK_ID and SPK_pub to authoritative lifecycle and
/// database state. It does not authorize enrollment or activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPrekeyV1 {
    raw: Vec<u8>,
    pub account_id: [u8; 16],
    pub account_epoch: u32,
    pub device_id: [u8; 16],
    pub spk_id: u32,
    pub spk_pub: [u8; 32],
    pub signature: [u8; 64],
}

impl SignedPrekeyV1 {
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn parse(raw: &[u8]) -> Result<Self, SignedPrekeyV1Error> {
        let decoded = cbor::decode_strict(raw).map_err(|_| SignedPrekeyV1Error::InvalidCbor)?;
        if !cbor::is_canonical(raw) {
            return Err(SignedPrekeyV1Error::InvalidCbor);
        }

        let Value::Map(pairs) = decoded else {
            return Err(SignedPrekeyV1Error::InvalidShape);
        };
        if pairs.len() != 7 {
            return Err(SignedPrekeyV1Error::InvalidShape);
        }

        let mut fields = BTreeMap::<u64, Value>::new();
        for (key, value) in pairs {
            let Value::Int(key) = key else {
                return Err(SignedPrekeyV1Error::InvalidShape);
            };
            if key < 0 || key > u64::MAX as i128 {
                return Err(SignedPrekeyV1Error::InvalidShape);
            }
            if fields.insert(key as u64, value).is_some() {
                return Err(SignedPrekeyV1Error::InvalidShape);
            }
        }
        if (1..=7).any(|key| !fields.contains_key(&key))
            || fields.keys().any(|key| !(1..=7).contains(key))
        {
            return Err(SignedPrekeyV1Error::InvalidShape);
        }

        let version = take_uint(&mut fields, 1)?;
        if version != SIGNED_PREKEY_V1_VERSION {
            return Err(SignedPrekeyV1Error::UnsupportedVersion);
        }
        let account_id = take_fixed::<16>(&mut fields, 2)?;
        let epoch = take_uint(&mut fields, 3)?;
        let device_id = take_fixed::<16>(&mut fields, 4)?;
        let spk_id = take_uint(&mut fields, 5)?;
        let spk_pub = take_fixed::<32>(&mut fields, 6)?;
        let signature = take_fixed::<64>(&mut fields, 7)?;

        validate_fields(&account_id, epoch, &device_id, spk_id, &spk_pub)?;

        Ok(Self {
            raw: raw.to_vec(),
            account_id,
            account_epoch: epoch as u32,
            device_id,
            spk_id: spk_id as u32,
            spk_pub,
            signature,
        })
    }

    /// Verifies the candidate signature using the DSK from a separately
    /// verified enrollment certificate or authorized device record.
    pub fn verify(&self, dsk_pub: &[u8; 32]) -> Result<(), SignedPrekeyV1Error> {
        validate_fields(
            &self.account_id,
            self.account_epoch as u64,
            &self.device_id,
            self.spk_id as u64,
            &self.spk_pub,
        )?;

        let public = VerifyingKey::from_bytes(dsk_pub)
            .map_err(|_| SignedPrekeyV1Error::InvalidSignature)?;
        let core = core_bytes(
            &self.account_id,
            self.account_epoch as u64,
            &self.device_id,
            self.spk_id,
            &self.spk_pub,
        )?;
        let mut message = Vec::with_capacity(SIGNED_PREKEY_V1_DOMAIN.len() + core.len());
        message.extend_from_slice(SIGNED_PREKEY_V1_DOMAIN);
        message.extend_from_slice(&core);
        let signature = Signature::from_bytes(&self.signature);
        public
            .verify_strict(&message, &signature)
            .map_err(|_| SignedPrekeyV1Error::InvalidSignature)
    }
}

/// Creates a complete candidate signed-prekey object using the device's DSK.
pub fn sign_signed_prekey_v1(
    dsk: &SigningKey,
    account_id: [u8; 16],
    account_epoch: u64,
    device_id: [u8; 16],
    spk_id: u32,
    spk_pub: [u8; 32],
) -> Result<Vec<u8>, SignedPrekeyV1Error> {
    validate_fields(
        &account_id,
        account_epoch,
        &device_id,
        spk_id as u64,
        &spk_pub,
    )?;

    let core = core_bytes(&account_id, account_epoch, &device_id, spk_id, &spk_pub)?;
    let mut message = Vec::with_capacity(SIGNED_PREKEY_V1_DOMAIN.len() + core.len());
    message.extend_from_slice(SIGNED_PREKEY_V1_DOMAIN);
    message.extend_from_slice(&core);
    let signature = dsk.sign(&message).to_bytes();

    let mut pairs = core_value(&account_id, account_epoch, &device_id, spk_id, &spk_pub)
        .map_pairs()
        .ok_or(SignedPrekeyV1Error::InvalidShape)?;
    pairs.push((Value::Int(7), Value::Bytes(signature.to_vec())));
    cbor::encode_canonical(&Value::Map(pairs)).map_err(|_| SignedPrekeyV1Error::InvalidCbor)
}

fn validate_fields(
    account_id: &[u8; 16],
    epoch: u64,
    device_id: &[u8; 16],
    spk_id: u64,
    spk_pub: &[u8; 32],
) -> Result<(), SignedPrekeyV1Error> {
    if *account_id == [0u8; 16]
        || *device_id == [0u8; 16]
        || !(1..=SIGNED_PREKEY_V1_MAX_EPOCH).contains(&epoch)
        || spk_id > u32::MAX as u64
    {
        return Err(SignedPrekeyV1Error::InvalidField);
    }
    if !is_usable_x25519_public_key(spk_pub) {
        return Err(SignedPrekeyV1Error::InvalidX25519PublicKey);
    }
    Ok(())
}

/// X25519 low-order public keys produce an all-zero shared secret for every
/// scalar. A fixed, non-zero scalar is sufficient to reject those points here.
fn is_usable_x25519_public_key(public: &[u8; 32]) -> bool {
    let private = StaticSecret::from([0x42u8; 32]);
    let public = X25519PublicKey::from(*public);
    private.diffie_hellman(&public).was_contributory()
}

fn core_value(
    account_id: &[u8; 16],
    epoch: u64,
    device_id: &[u8; 16],
    spk_id: u32,
    spk_pub: &[u8; 32],
) -> Value {
    Value::Map(vec![
        (Value::Int(1), Value::Int(SIGNED_PREKEY_V1_VERSION as i128)),
        (Value::Int(2), Value::Bytes(account_id.to_vec())),
        (Value::Int(3), Value::Int(epoch as i128)),
        (Value::Int(4), Value::Bytes(device_id.to_vec())),
        (Value::Int(5), Value::Int(spk_id as i128)),
        (Value::Int(6), Value::Bytes(spk_pub.to_vec())),
    ])
}

fn core_bytes(
    account_id: &[u8; 16],
    epoch: u64,
    device_id: &[u8; 16],
    spk_id: u32,
    spk_pub: &[u8; 32],
) -> Result<Vec<u8>, SignedPrekeyV1Error> {
    cbor::encode_canonical(&core_value(account_id, epoch, device_id, spk_id, spk_pub))
        .map_err(|_| SignedPrekeyV1Error::InvalidCbor)
}

fn take_uint(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
) -> Result<u64, SignedPrekeyV1Error> {
    match fields.remove(&key) {
        Some(Value::Int(value)) if value >= 0 && value <= u64::MAX as i128 => {
            Ok(value as u64)
        }
        _ => Err(SignedPrekeyV1Error::InvalidField),
    }
}

fn take_fixed<const N: usize>(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
) -> Result<[u8; N], SignedPrekeyV1Error> {
    match fields.remove(&key) {
        Some(Value::Bytes(value)) if value.len() == N => {
            let mut out = [0u8; N];
            out.copy_from_slice(&value);
            Ok(out)
        }
        _ => Err(SignedPrekeyV1Error::InvalidField),
    }
}

trait MapPairs {
    fn map_pairs(self) -> Option<Vec<(Value, Value)>>;
}

impl MapPairs for Value {
    fn map_pairs(self) -> Option<Vec<(Value, Value)>> {
        match self {
            Value::Map(pairs) => Some(pairs),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_spk_pub() -> [u8; 32] {
        let secret = StaticSecret::from([0x22u8; 32]);
        X25519PublicKey::from(&secret).to_bytes()
    }

    #[test]
    fn candidate_round_trips_and_verifies() {
        let dsk = SigningKey::from_bytes(&[0x37u8; 32]);
        let account_id = [1u8; 16];
        let device_id = [2u8; 16];
        let spk_pub = valid_spk_pub();
        let raw = sign_signed_prekey_v1(
            &dsk,
            account_id,
            3,
            device_id,
            7,
            spk_pub,
        )
        .expect("sign candidate prekey");

        let parsed = SignedPrekeyV1::parse(&raw).expect("parse candidate prekey");
        assert_eq!(parsed.raw(), raw.as_slice());
        assert_eq!(parsed.account_id, account_id);
        assert_eq!(parsed.account_epoch, 3);
        assert_eq!(parsed.device_id, device_id);
        assert_eq!(parsed.spk_id, 7);
        assert_eq!(parsed.spk_pub, spk_pub);
        parsed
            .verify(&dsk.verifying_key().to_bytes())
            .expect("verify candidate signature");
    }

    #[test]
    fn signature_and_bound_fields_tampering_are_rejected() {
        let dsk = SigningKey::from_bytes(&[0x37u8; 32]);
        let raw = sign_signed_prekey_v1(
            &dsk,
            [1u8; 16],
            3,
            [2u8; 16],
            7,
            valid_spk_pub(),
        )
        .expect("sign candidate prekey");

        let mut parsed = SignedPrekeyV1::parse(&raw).expect("parse candidate prekey");
        parsed.spk_id = 8;
        assert_eq!(
            parsed.verify(&dsk.verifying_key().to_bytes()),
            Err(SignedPrekeyV1Error::InvalidSignature)
        );

        let mut tampered = raw;
        *tampered.last_mut().expect("wire nonempty") ^= 1;
        let parsed = SignedPrekeyV1::parse(&tampered).expect("signature tamper stays parseable");
        assert_eq!(
            parsed.verify(&dsk.verifying_key().to_bytes()),
            Err(SignedPrekeyV1Error::InvalidSignature)
        );
    }

    #[test]
    fn invalid_ids_epochs_and_low_order_spk_keys_are_rejected() {
        let dsk = SigningKey::from_bytes(&[0x37u8; 32]);
        assert_eq!(
            sign_signed_prekey_v1(&dsk, [0u8; 16], 3, [2u8; 16], 7, valid_spk_pub()),
            Err(SignedPrekeyV1Error::InvalidField)
        );
        assert_eq!(
            sign_signed_prekey_v1(&dsk, [1u8; 16], 0, [2u8; 16], 7, valid_spk_pub()),
            Err(SignedPrekeyV1Error::InvalidField)
        );
        assert_eq!(
            sign_signed_prekey_v1(&dsk, [1u8; 16], 3, [2u8; 16], 7, [0u8; 32]),
            Err(SignedPrekeyV1Error::InvalidX25519PublicKey)
        );
    }
}
