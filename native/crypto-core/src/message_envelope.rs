//! Frozen PM-CBOR-2026 `MessageEnvelopeV1` wire structure.
//!
//! The envelope is the authenticated message container described by
//! `docs/phase0/11-pmacbor-2026.md`. Fields 1-7 are the exact inputs to
//! `aad_msg`; field 8 is the ciphertext.

use thiserror::Error;

use crate::cbor::{self, CborError, Value, MAX_BSTR};

pub const MESSAGE_ENVELOPE_V1_PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MessageEnvelopeError {
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    #[error("invalid MessageEnvelopeV1 field")]
    InvalidField,
    #[error("unknown MessageEnvelopeV1 field")]
    UnknownField,
    #[error("missing MessageEnvelopeV1 field")]
    MissingField,
}

/// Frozen PM-CBOR-2026 MessageEnvelopeV1.
///
/// Field mapping:
/// 1 = protocol_version (uint = 1)
/// 2 = envelope_id (16-byte bstr)
/// 3 = sender_device_id (16-byte bstr)
/// 4 = recipient_device_id (16-byte bstr)
/// 5 = account_epoch (uint32 = recipient Epoch_B)
/// 6 = is_prekey_handshake (bool)
/// 7 = ratchet_header_bytes (bstr)
/// 8 = ciphertext (bstr <= 65,552 bytes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageEnvelopeV1 {
    pub protocol_version: u8,
    pub envelope_id: [u8; 16],
    pub sender_device_id: [u8; 16],
    pub recipient_device_id: [u8; 16],
    pub account_epoch: u32,
    pub is_prekey_handshake: bool,
    pub ratchet_header_bytes: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl MessageEnvelopeV1 {
    pub const PROTOCOL_VERSION: u8 = MESSAGE_ENVELOPE_V1_PROTOCOL_VERSION;
    pub const MAX_CIPHERTEXT: usize = MAX_BSTR;

    /// Construct a V1 envelope. The protocol version is fixed to 1.
    pub fn new(
        envelope_id: [u8; 16],
        sender_device_id: [u8; 16],
        recipient_device_id: [u8; 16],
        account_epoch: u32,
        is_prekey_handshake: bool,
        ratchet_header_bytes: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            protocol_version: Self::PROTOCOL_VERSION,
            envelope_id,
            sender_device_id,
            recipient_device_id,
            account_epoch,
            is_prekey_handshake,
            ratchet_header_bytes,
            ciphertext,
        }
    }

    /// Encode the exact canonical PM-CBOR-2026 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, MessageEnvelopeError> {
        self.validate()?;
        Ok(cbor::encode_canonical(&Value::Map(vec![
            (Value::Int(1), Value::Int(self.protocol_version as i128)),
            (Value::Int(2), Value::Bytes(self.envelope_id.to_vec())),
            (Value::Int(3), Value::Bytes(self.sender_device_id.to_vec())),
            (Value::Int(4), Value::Bytes(self.recipient_device_id.to_vec())),
            (Value::Int(5), Value::Int(self.account_epoch as i128)),
            (Value::Int(6), Value::Bool(self.is_prekey_handshake)),
            (
                Value::Int(7),
                Value::Bytes(self.ratchet_header_bytes.clone()),
            ),
            (Value::Int(8), Value::Bytes(self.ciphertext.clone())),
        ]))?)
    }

    /// Strictly decode and semantically validate a V1 envelope.
    ///
    /// `decode_strict` rejects non-canonical bytes, duplicate map keys,
    /// unsupported items, trailing bytes, and codec-limit violations before
    /// schema validation runs.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageEnvelopeError> {
        let value = cbor::decode_strict(bytes)?;
        let pairs = match value {
            Value::Map(pairs) => pairs,
            _ => return Err(MessageEnvelopeError::InvalidField),
        };

        let mut f1 = None;
        let mut f2 = None;
        let mut f3 = None;
        let mut f4 = None;
        let mut f5 = None;
        let mut f6 = None;
        let mut f7 = None;
        let mut f8 = None;

        for (key, value) in pairs {
            let key = match key {
                Value::Int(n) => n,
                _ => return Err(MessageEnvelopeError::UnknownField),
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
                _ => return Err(MessageEnvelopeError::UnknownField),
            };
            if slot.is_some() {
                // Defensive guard. The strict CBOR layer already rejects
                // duplicate wire keys before returning a Value::Map.
                return Err(MessageEnvelopeError::Cbor(CborError::DuplicateMapKey));
            }
            *slot = Some(value);
        }

        let protocol_version = match take_required(&mut f1)? {
            Value::Int(1) => Self::PROTOCOL_VERSION,
            _ => return Err(MessageEnvelopeError::InvalidField),
        };
        let envelope_id = bytes16(take_required(&mut f2)?)?;
        let sender_device_id = bytes16(take_required(&mut f3)?)?;
        let recipient_device_id = bytes16(take_required(&mut f4)?)?;
        let account_epoch = u32_value(take_required(&mut f5)?)?;
        let is_prekey_handshake = match take_required(&mut f6)? {
            Value::Bool(v) => v,
            _ => return Err(MessageEnvelopeError::InvalidField),
        };
        let ratchet_header_bytes = match take_required(&mut f7)? {
            Value::Bytes(v) if v.len() <= MAX_BSTR => v,
            _ => return Err(MessageEnvelopeError::InvalidField),
        };
        let ciphertext = match take_required(&mut f8)? {
            Value::Bytes(v) if v.len() <= Self::MAX_CIPHERTEXT => v,
            _ => return Err(MessageEnvelopeError::InvalidField),
        };

        Ok(Self {
            protocol_version,
            envelope_id,
            sender_device_id,
            recipient_device_id,
            account_epoch,
            is_prekey_handshake,
            ratchet_header_bytes,
            ciphertext,
        })
    }

    pub fn validate(&self) -> Result<(), MessageEnvelopeError> {
        if self.protocol_version != Self::PROTOCOL_VERSION {
            return Err(MessageEnvelopeError::InvalidField);
        }
        if self.ratchet_header_bytes.len() > MAX_BSTR
            || self.ciphertext.len() > Self::MAX_CIPHERTEXT
        {
            return Err(MessageEnvelopeError::Cbor(CborError::LimitExceeded));
        }
        Ok(())
    }
}

fn take_required(slot: &mut Option<Value>) -> Result<Value, MessageEnvelopeError> {
    slot.take().ok_or(MessageEnvelopeError::MissingField)
}

fn bytes16(value: Value) -> Result<[u8; 16], MessageEnvelopeError> {
    match value {
        Value::Bytes(bytes) if bytes.len() == 16 => {
            Ok(bytes.try_into().expect("length checked"))
        }
        _ => Err(MessageEnvelopeError::InvalidField),
    }
}

fn u32_value(value: Value) -> Result<u32, MessageEnvelopeError> {
    match value {
        Value::Int(value) if (0..=u32::MAX as i128).contains(&value) => Ok(value as u32),
        _ => Err(MessageEnvelopeError::InvalidField),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;

    fn envelope() -> MessageEnvelopeV1 {
        MessageEnvelopeV1::new(
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f],
            [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f],
            0x0102_0304,
            true,
            vec![0x01, 0xa0],
            vec![0xde, 0xad, 0xbe, 0xef],
        )
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn canonical_encoding_matches_frozen_vector() {
        let encoded = envelope().encode().unwrap();
        assert_eq!(
            hex(&encoded),
            "a801010250000102030405060708090a0b0c0d0e0f0350101112131415161718191a1b1c1d1e1f0450202122232425262728292a2b2c2d2e2f051a0102030406f5074201a00844deadbeef"
        );
    }

    #[test]
    fn decode_round_trips_exactly() {
        let value = envelope();
        let bytes = value.encode().unwrap();
        let decoded = MessageEnvelopeV1::decode(&bytes).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    #[test]
    fn wrong_protocol_version_is_rejected() {
        let bytes = crate::cbor::encode_canonical(&Value::Map(vec![
            (Value::Int(1), Value::Int(2)),
            (Value::Int(2), Value::Bytes(vec![0; 16])),
            (Value::Int(3), Value::Bytes(vec![1; 16])),
            (Value::Int(4), Value::Bytes(vec![2; 16])),
            (Value::Int(5), Value::Int(0)),
            (Value::Int(6), Value::Bool(false)),
            (Value::Int(7), Value::Bytes(Vec::new())),
            (Value::Int(8), Value::Bytes(Vec::new())),
        ]))
        .unwrap();
        assert_eq!(
            MessageEnvelopeV1::decode(&bytes).unwrap_err(),
            MessageEnvelopeError::InvalidField
        );
    }

    #[test]
    fn wrong_field_types_are_rejected() {
        let bytes = crate::cbor::encode_canonical(&Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Int(7)),
            (Value::Int(3), Value::Bytes(vec![1; 16])),
            (Value::Int(4), Value::Bytes(vec![2; 16])),
            (Value::Int(5), Value::Int(0)),
            (Value::Int(6), Value::Bool(false)),
            (Value::Int(7), Value::Bytes(Vec::new())),
            (Value::Int(8), Value::Bytes(Vec::new())),
        ]))
        .unwrap();
        assert_eq!(
            MessageEnvelopeV1::decode(&bytes).unwrap_err(),
            MessageEnvelopeError::InvalidField
        );
    }

    #[test]
    fn missing_and_unknown_fields_are_rejected() {
        let missing = crate::cbor::encode_canonical(&Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(vec![0; 16])),
            (Value::Int(3), Value::Bytes(vec![1; 16])),
            (Value::Int(4), Value::Bytes(vec![2; 16])),
            (Value::Int(5), Value::Int(0)),
            (Value::Int(6), Value::Bool(false)),
            (Value::Int(7), Value::Bytes(Vec::new())),
        ]))
        .unwrap();
        assert_eq!(
            MessageEnvelopeV1::decode(&missing).unwrap_err(),
            MessageEnvelopeError::MissingField
        );

        let unknown = crate::cbor::encode_canonical(&Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(vec![0; 16])),
            (Value::Int(3), Value::Bytes(vec![1; 16])),
            (Value::Int(4), Value::Bytes(vec![2; 16])),
            (Value::Int(5), Value::Int(0)),
            (Value::Int(6), Value::Bool(false)),
            (Value::Int(7), Value::Bytes(Vec::new())),
            (Value::Int(8), Value::Bytes(Vec::new())),
            (Value::Int(9), Value::Int(0)),
        ]))
        .unwrap();
        assert_eq!(
            MessageEnvelopeV1::decode(&unknown).unwrap_err(),
            MessageEnvelopeError::UnknownField
        );
    }

    #[test]
    fn noncanonical_and_duplicate_wire_inputs_are_rejected_by_cbor_layer() {
        let canonical = envelope().encode().unwrap();

        let mut noncanonical = canonical.clone();
        noncanonical[1] = 0x18;
        noncanonical.insert(2, 0x01);
        assert_eq!(
            MessageEnvelopeV1::decode(&noncanonical).unwrap_err(),
            MessageEnvelopeError::Cbor(CborError::NonCanonicalInteger)
        );

        let duplicate = vec![
            0xa9, 0x01, 0x01, 0x02, 0x50,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x03, 0x50,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            0x04, 0x50,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            0x05, 0x00, 0x06, 0xf4, 0x07, 0x40, 0x08, 0x40, 0x08, 0x40, 0x09, 0x00,
        ];
        assert_eq!(
            MessageEnvelopeV1::decode(&duplicate).unwrap_err(),
            MessageEnvelopeError::Cbor(CborError::DuplicateMapKey)
        );
    }

    #[test]
    fn ciphertext_limit_is_enforced() {
        let mut value = envelope();
        value.ciphertext = vec![0u8; MessageEnvelopeV1::MAX_CIPHERTEXT];
        assert!(value.encode().is_ok());

        value.ciphertext.push(0);
        assert_eq!(
            value.encode().unwrap_err(),
            MessageEnvelopeError::Cbor(CborError::LimitExceeded)
        );
    }
}
