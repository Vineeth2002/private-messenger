//! Private, strict snapshot codec for `RatchetState`.
//!
//! This is a closed PM-CBOR-2026 subset with a fixed map schema. It writes directly into a
//! `Zeroizing<Vec<u8>>` and parses from borrowed input, avoiding a generic CBOR `Value` tree
//! containing unzeroized copies of ratchet secrets. The snapshot is plaintext and is not an
//! at-rest security boundary; the persistence layer must authenticate and encrypt it.

use std::collections::BTreeMap;

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::{
    RatchetError, RatchetKey, RatchetState, SkippedMessageKeyId, MAX_SKIPPED_MESSAGE_KEYS,
};
use crate::cbor::{MAX_BSTR, MAX_WIRE_INPUT};

const SNAPSHOT_VERSION: u64 = 1;
const MAP_FIELDS: u64 = 11;
const SKIPPED_RECORD_BYTES: usize = 32 + 4 + 32;
const SKIPPED_KEYS_PER_CHUNK: usize = MAX_BSTR / SKIPPED_RECORD_BYTES;
const MAX_SKIPPED_CHUNKS: usize = 2;

pub(super) fn encode(state: &RatchetState) -> Result<Zeroizing<Vec<u8>>, RatchetError> {
    validate_state(state)?;

    let skipped_count = state.skipped_keys.len();
    let chunk_count = div_ceil(skipped_count, SKIPPED_KEYS_PER_CHUNK);
    if chunk_count > MAX_SKIPPED_CHUNKS {
        return Err(RatchetError::InvalidSnapshot);
    }

    // The encoded plaintext contains root, chain, DH and skipped-message secrets. Keep the
    // only output allocation zeroizing, including on every early return below.
    let estimated = 512usize
        .checked_add(
            skipped_count
                .checked_mul(SKIPPED_RECORD_BYTES)
                .ok_or(RatchetError::InvalidSnapshot)?,
        )
        .ok_or(RatchetError::InvalidSnapshot)?;
    let mut out = Zeroizing::new(Vec::with_capacity(estimated));

    // Fixed integer keys 1..=11 are already in canonical PM-CBOR map-key order.
    write_head(&mut out, 5, MAP_FIELDS);

    write_uint(&mut out, 1);
    write_uint(&mut out, SNAPSHOT_VERSION);

    write_uint(&mut out, 2);
    write_bstr(&mut out, &state.rk[..]);

    write_uint(&mut out, 3);
    let dhs_private = Zeroizing::new(state.dhs_priv.to_bytes());
    write_bstr(&mut out, &dhs_private[..]);

    write_uint(&mut out, 4);
    write_bstr(&mut out, &state.dhs_pub);

    write_uint(&mut out, 5);
    match state.dhr_pub {
        Some(public) => write_bstr(&mut out, &public),
        None => out.push(0xf6),
    }

    write_uint(&mut out, 6);
    write_optional_secret(&mut out, state.ck_s.as_ref());

    write_uint(&mut out, 7);
    write_optional_secret(&mut out, state.ck_r.as_ref());

    write_uint(&mut out, 8);
    write_uint(&mut out, state.ns as u64);

    write_uint(&mut out, 9);
    write_uint(&mut out, state.nr as u64);

    write_uint(&mut out, 10);
    write_uint(&mut out, state.pn as u64);

    write_uint(&mut out, 11);
    write_head(&mut out, 4, chunk_count as u64);

    let mut entries = state.skipped_keys.iter();
    for chunk_index in 0..chunk_count {
        let start = chunk_index * SKIPPED_KEYS_PER_CHUNK;
        let remaining = skipped_count - start;
        let records_in_chunk = remaining.min(SKIPPED_KEYS_PER_CHUNK);
        let chunk_bytes = records_in_chunk
            .checked_mul(SKIPPED_RECORD_BYTES)
            .ok_or(RatchetError::InvalidSnapshot)?;
        write_head(&mut out, 2, chunk_bytes as u64);

        for _ in 0..records_in_chunk {
            let (id, key) = entries.next().ok_or(RatchetError::InvalidSnapshot)?;
            out.extend_from_slice(&id.ratchet_public);
            out.extend_from_slice(&id.sequence_number.to_be_bytes());
            out.extend_from_slice(&key[..]);
        }
    }
    if entries.next().is_some() || out.len() > MAX_WIRE_INPUT {
        return Err(RatchetError::InvalidSnapshot);
    }

    Ok(out)
}

pub(super) fn decode(input: &[u8]) -> Result<RatchetState, RatchetError> {
    if input.is_empty() || input.len() > MAX_WIRE_INPUT {
        return Err(RatchetError::InvalidSnapshot);
    }

    let mut reader = Reader::new(input);
    if reader.read_container_len(5)? != MAP_FIELDS as usize {
        return Err(RatchetError::InvalidSnapshot);
    }

    // Require every field exactly once, in the canonical integer-key order. This avoids a
    // generic map allocation and rejects duplicate, missing, reordered and unknown fields.
    reader.expect_uint(1)?;
    if reader.read_uint()? != SNAPSHOT_VERSION {
        return Err(RatchetError::InvalidSnapshot);
    }

    reader.expect_uint(2)?;
    let rk = reader.read_secret32()?;

    reader.expect_uint(3)?;
    let dhs_private_bytes = reader.read_secret32()?;
    let dhs_priv = StaticSecret::from(*dhs_private_bytes);

    reader.expect_uint(4)?;
    let dhs_pub = reader.read_public32()?;

    reader.expect_uint(5)?;
    let dhr_pub = reader.read_optional_public32()?;

    reader.expect_uint(6)?;
    let ck_s = reader.read_optional_secret32()?;

    reader.expect_uint(7)?;
    let ck_r = reader.read_optional_secret32()?;

    reader.expect_uint(8)?;
    let ns = reader.read_u32()?;

    reader.expect_uint(9)?;
    let nr = reader.read_u32()?;

    reader.expect_uint(10)?;
    let pn = reader.read_u32()?;

    reader.expect_uint(11)?;
    let skipped_keys = reader.read_skipped_keys()?;

    if !reader.is_finished() {
        return Err(RatchetError::InvalidSnapshot);
    }

    let state = RatchetState {
        rk,
        dhs_priv,
        dhs_pub,
        dhr_pub,
        ck_s,
        ck_r,
        ns,
        nr,
        pn,
        skipped_keys,
    };
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &RatchetState) -> Result<(), RatchetError> {
    if state.skipped_keys.len() > MAX_SKIPPED_MESSAGE_KEYS {
        return Err(RatchetError::InvalidSnapshot);
    }

    if PublicKey::from(&state.dhs_priv).to_bytes() != state.dhs_pub {
        return Err(RatchetError::InvalidSnapshot);
    }

    if (state.ck_s.is_none() && state.ns != 0) || (state.ck_r.is_none() && state.nr != 0) {
        return Err(RatchetError::InvalidSnapshot);
    }

    // A missing remote DH key is only valid for Bob's untouched pre-Message-0 state.
    if state.dhr_pub.is_none()
        && (state.ck_s.is_some()
            || state.ck_r.is_some()
            || state.ns != 0
            || state.nr != 0
            || state.pn != 0
            || !state.skipped_keys.is_empty())
    {
        return Err(RatchetError::InvalidSnapshot);
    }

    // Reject low-order remote ratchet public keys, including keys retained in the skipped-key
    // table. The fixed probe secret is used only for contributory-DH validation.
    let probe = StaticSecret::from([0x42; 32]);
    if let Some(remote) = state.dhr_pub {
        if !probe
            .diffie_hellman(&PublicKey::from(remote))
            .was_contributory()
        {
            return Err(RatchetError::InvalidSnapshot);
        }
    }
    for id in state.skipped_keys.keys() {
        if !probe
            .diffie_hellman(&PublicKey::from(id.ratchet_public))
            .was_contributory()
        {
            return Err(RatchetError::InvalidSnapshot);
        }
    }

    Ok(())
}

fn div_ceil(value: usize, divisor: usize) -> usize {
    if value == 0 {
        0
    } else {
        1 + (value - 1) / divisor
    }
}

fn write_head(out: &mut Zeroizing<Vec<u8>>, major: u8, value: u64) {
    let prefix = major << 5;
    if value < 24 {
        out.push(prefix | value as u8);
    } else if value <= u8::MAX as u64 {
        out.push(prefix | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(prefix | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(prefix | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(prefix | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn write_uint(out: &mut Zeroizing<Vec<u8>>, value: u64) {
    write_head(out, 0, value);
}

fn write_bstr(out: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    write_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn write_optional_secret(out: &mut Zeroizing<Vec<u8>>, value: Option<&Zeroizing<RatchetKey>>) {
    match value {
        Some(key) => write_bstr(out, &key[..]),
        None => out.push(0xf6),
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn read_byte(&mut self) -> Result<u8, RatchetError> {
        let value = *self
            .input
            .get(self.position)
            .ok_or(RatchetError::InvalidSnapshot)?;
        self.position += 1;
        Ok(value)
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], RatchetError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RatchetError::InvalidSnapshot)?;
        if end > self.input.len() {
            return Err(RatchetError::InvalidSnapshot);
        }
        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    /// Read one canonical CBOR head of the required major type. Non-minimal arguments,
    /// indefinite lengths, reserved additional-info values and wrong major types are rejected.
    fn read_head(&mut self, expected_major: u8) -> Result<u64, RatchetError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if major != expected_major {
            return Err(RatchetError::InvalidSnapshot);
        }

        let value = match additional {
            0..=23 => additional as u64,
            24 => {
                let value = self.read_byte()? as u64;
                if value < 24 {
                    return Err(RatchetError::InvalidSnapshot);
                }
                value
            }
            25 => {
                let bytes: [u8; 2] = self
                    .read_exact(2)?
                    .try_into()
                    .map_err(|_| RatchetError::InvalidSnapshot)?;
                let value = u16::from_be_bytes(bytes) as u64;
                if value <= u8::MAX as u64 {
                    return Err(RatchetError::InvalidSnapshot);
                }
                value
            }
            26 => {
                let bytes: [u8; 4] = self
                    .read_exact(4)?
                    .try_into()
                    .map_err(|_| RatchetError::InvalidSnapshot)?;
                let value = u32::from_be_bytes(bytes) as u64;
                if value <= u16::MAX as u64 {
                    return Err(RatchetError::InvalidSnapshot);
                }
                value
            }
            27 => {
                let bytes: [u8; 8] = self
                    .read_exact(8)?
                    .try_into()
                    .map_err(|_| RatchetError::InvalidSnapshot)?;
                let value = u64::from_be_bytes(bytes);
                if value <= u32::MAX as u64 {
                    return Err(RatchetError::InvalidSnapshot);
                }
                value
            }
            _ => return Err(RatchetError::InvalidSnapshot),
        };
        Ok(value)
    }

    fn read_uint(&mut self) -> Result<u64, RatchetError> {
        self.read_head(0)
    }

    fn expect_uint(&mut self, expected: u64) -> Result<(), RatchetError> {
        if self.read_uint()? == expected {
            Ok(())
        } else {
            Err(RatchetError::InvalidSnapshot)
        }
    }

    fn read_container_len(&mut self, major: u8) -> Result<usize, RatchetError> {
        usize::try_from(self.read_head(major)?).map_err(|_| RatchetError::InvalidSnapshot)
    }

    fn read_bstr(&mut self) -> Result<&'a [u8], RatchetError> {
        let length = self.read_container_len(2)?;
        if length > MAX_BSTR {
            return Err(RatchetError::InvalidSnapshot);
        }
        self.read_exact(length)
    }

    fn read_secret32(&mut self) -> Result<Zeroizing<RatchetKey>, RatchetError> {
        let bytes = self.read_bstr()?;
        let key: RatchetKey = bytes
            .try_into()
            .map_err(|_| RatchetError::InvalidSnapshot)?;
        Ok(Zeroizing::new(key))
    }

    fn read_public32(&mut self) -> Result<[u8; 32], RatchetError> {
        let bytes = self.read_bstr()?;
        bytes.try_into().map_err(|_| RatchetError::InvalidSnapshot)
    }

    fn read_optional_public32(&mut self) -> Result<Option<[u8; 32]>, RatchetError> {
        if self.input.get(self.position) == Some(&0xf6) {
            self.position += 1;
            Ok(None)
        } else {
            self.read_public32().map(Some)
        }
    }

    fn read_optional_secret32(&mut self) -> Result<Option<Zeroizing<RatchetKey>>, RatchetError> {
        if self.input.get(self.position) == Some(&0xf6) {
            self.position += 1;
            Ok(None)
        } else {
            self.read_secret32().map(Some)
        }
    }

    fn read_u32(&mut self) -> Result<u32, RatchetError> {
        u32::try_from(self.read_uint()?).map_err(|_| RatchetError::InvalidSnapshot)
    }

    fn read_skipped_keys(
        &mut self,
    ) -> Result<BTreeMap<SkippedMessageKeyId, Zeroizing<RatchetKey>>, RatchetError> {
        let chunk_count = self.read_container_len(4)?;
        if chunk_count > MAX_SKIPPED_CHUNKS {
            return Err(RatchetError::InvalidSnapshot);
        }

        let mut skipped = BTreeMap::new();
        let mut previous_id: Option<SkippedMessageKeyId> = None;

        for chunk_index in 0..chunk_count {
            let chunk = self.read_bstr()?;
            if chunk.is_empty() || chunk.len() % SKIPPED_RECORD_BYTES != 0 {
                return Err(RatchetError::InvalidSnapshot);
            }
            if chunk_count == 2 && chunk_index == 0 && chunk.len() != MAX_BSTR {
                return Err(RatchetError::InvalidSnapshot);
            }

            for record in chunk.chunks_exact(SKIPPED_RECORD_BYTES) {
                if skipped.len() >= MAX_SKIPPED_MESSAGE_KEYS {
                    return Err(RatchetError::InvalidSnapshot);
                }

                let ratchet_public: [u8; 32] = record[0..32]
                    .try_into()
                    .map_err(|_| RatchetError::InvalidSnapshot)?;
                let sequence_number = u32::from_be_bytes(
                    record[32..36]
                        .try_into()
                        .map_err(|_| RatchetError::InvalidSnapshot)?,
                );
                let message_key: RatchetKey = record[36..68]
                    .try_into()
                    .map_err(|_| RatchetError::InvalidSnapshot)?;

                let id = SkippedMessageKeyId {
                    ratchet_public,
                    sequence_number,
                };
                if previous_id.is_some_and(|previous| id <= previous) {
                    return Err(RatchetError::InvalidSnapshot);
                }
                previous_id = Some(id);
                if skipped.insert(id, Zeroizing::new(message_key)).is_some() {
                    return Err(RatchetError::InvalidSnapshot);
                }
            }
        }

        Ok(skipped)
    }

    fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::double_ratchet::{encrypt_message, MessageEnvelopeRef, NormalMessageHeader};

    fn alice_state() -> RatchetState {
        let shared_secret = [0x11; 32];
        let remote_private = StaticSecret::from([0x22; 32]);
        let remote_public = PublicKey::from(&remote_private).to_bytes();
        let mut state =
            RatchetState::init_alice_from_test_bytes(&shared_secret, &remote_public, [0x33; 32])
                .unwrap();
        // Model the valid post-Message-0 state: Message 0 consumed chain message number 0.
        let current_sending_chain = state
            .ck_s
            .as_ref()
            .expect("Alice has an initial sending chain");
        let (next_sending_chain, _message_zero_key) = super::super::kdf_ck(current_sending_chain);
        state.ck_s = Some(next_sending_chain);
        state.ns = 1;
        state
    }

    #[test]
    fn snapshot_roundtrip_preserves_state_and_next_ciphertext() {
        let mut original = alice_state();
        let remote_private = StaticSecret::from([0x44; 32]);
        let skipped_public = PublicKey::from(&remote_private).to_bytes();
        original.skipped_keys.insert(
            SkippedMessageKeyId {
                ratchet_public: skipped_public,
                sequence_number: 7,
            },
            Zeroizing::new([0x55; 32]),
        );

        let snapshot = encode(&original).unwrap();
        let mut restored = decode(&snapshot).unwrap();
        let restored_snapshot = encode(&restored).unwrap();
        assert_eq!(snapshot.as_slice(), restored_snapshot.as_slice());

        let header_original = NormalMessageHeader {
            ratchet_public: original.dhs_pub,
            previous_chain_length: original.pn,
            sequence_number: original.ns,
        };
        let header_restored = NormalMessageHeader {
            ratchet_public: restored.dhs_pub,
            previous_chain_length: restored.pn,
            sequence_number: restored.ns,
        };
        let header_bytes_original = header_original.encode().unwrap();
        let header_bytes_restored = header_restored.encode().unwrap();
        assert_eq!(header_bytes_original, header_bytes_restored);

        let envelope_id = [0x61; 16];
        let sender = [0x62; 16];
        let recipient = [0x63; 16];
        let envelope_original = MessageEnvelopeRef {
            protocol_version: 1,
            envelope_id: &envelope_id,
            sender_device_id: &sender,
            recipient_device_id: &recipient,
            account_epoch: 1,
            is_prekey_handshake: false,
            ratchet_header_bytes: &header_bytes_original,
            ciphertext: &[],
        };
        let envelope_restored = MessageEnvelopeRef {
            protocol_version: 1,
            envelope_id: &envelope_id,
            sender_device_id: &sender,
            recipient_device_id: &recipient,
            account_epoch: 1,
            is_prekey_handshake: false,
            ratchet_header_bytes: &header_bytes_restored,
            ciphertext: &[],
        };

        let original_output = encrypt_message(
            &mut original,
            envelope_original,
            &header_original,
            b"snapshot continuation",
        )
        .unwrap();
        let restored_output = encrypt_message(
            &mut restored,
            envelope_restored,
            &header_restored,
            b"snapshot continuation",
        )
        .unwrap();
        assert_eq!(original_output, restored_output);
        assert_eq!(
            encode(&original).unwrap().as_slice(),
            encode(&restored).unwrap().as_slice(),
        );
    }

    #[test]
    fn snapshot_chunks_and_restores_the_maximum_skipped_key_count() {
        let mut state = alice_state();
        let remote_private = StaticSecret::from([0x44; 32]);
        let ratchet_public = PublicKey::from(&remote_private).to_bytes();
        for sequence_number in 0..MAX_SKIPPED_MESSAGE_KEYS as u32 {
            state.skipped_keys.insert(
                SkippedMessageKeyId {
                    ratchet_public,
                    sequence_number,
                },
                Zeroizing::new([sequence_number as u8; 32]),
            );
        }

        let snapshot = encode(&state).unwrap();
        assert!(snapshot.len() < MAX_WIRE_INPUT);
        let restored = decode(&snapshot).unwrap();
        assert_eq!(restored.skipped_keys.len(), MAX_SKIPPED_MESSAGE_KEYS);
        assert_eq!(encode(&restored).unwrap().as_slice(), snapshot.as_slice());
    }

    #[test]
    fn snapshot_rejects_wrong_version_trailing_bytes_and_wrong_map_size() {
        let state = alice_state();
        let snapshot = encode(&state).unwrap();

        let mut wrong_version = snapshot.to_vec();
        // Canonical 11-entry map, key 1, then value 1.
        wrong_version[2] = 2;
        assert_eq!(
            decode(&wrong_version).err().unwrap(),
            RatchetError::InvalidSnapshot
        );

        let mut trailing = snapshot.to_vec();
        trailing.push(0);
        assert_eq!(
            decode(&trailing).err().unwrap(),
            RatchetError::InvalidSnapshot
        );

        let mut wrong_map_size = snapshot.to_vec();
        wrong_map_size[0] = 0xaa; // map(10), not the required map(11)
        assert_eq!(
            decode(&wrong_map_size).err().unwrap(),
            RatchetError::InvalidSnapshot
        );
    }

    #[test]
    fn snapshot_rejects_inconsistent_state_before_encoding() {
        let mut state = alice_state();
        state.dhr_pub = Some([0u8; 32]);
        assert_eq!(encode(&state).unwrap_err(), RatchetError::InvalidSnapshot);

        let mut state = alice_state();
        state.ck_s = None;
        state.ns = 1;
        assert_eq!(encode(&state).unwrap_err(), RatchetError::InvalidSnapshot);
    }
}
