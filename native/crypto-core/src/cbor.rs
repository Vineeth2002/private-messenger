//! PM-CBOR-2026: RFC 8949 s4.2.1 Core Deterministic Encoding, strict profile.
//!
//! Design: `decode_strict` validates the ORIGINAL BYTES while parsing. It never
//! decodes-then-reserializes to "fix" input, so malformed or non-canonical input
//! can never be normalized into something that is accepted.
//!
//! Rules enforced (see docs/phase0/11-pmacbor-2026.md):
//!  minimal integer/length heads, no floats, no indefinite lengths, no duplicate
//!  keys, bytewise-lexicographic map-key order of the encoded keys, no trailing
//!  bytes, valid UTF-8 text.
//! Bounds (architecture-review lock): wire input <= 256 KiB, container nesting <= 8,
//! map entries <= 32, byte string <= 65,552 bytes. Violations -> ERR_LIMIT_EXCEEDED.
//! IMPLEMENTATION DECISIONS: tags and simple values other than false/true/null are
//! rejected (ERR_UNSUPPORTED_ITEM); ERR_LIMIT_EXCEEDED is a category added here;
//! integers are limited to the CBOR range [-2^64, 2^64-1].

use thiserror::Error;

/// Maximum wire input accepted by `decode_strict` (256 KiB).
pub const MAX_WIRE_INPUT: usize = 256 * 1024;
/// Maximum container (array/map) nesting levels.
pub const MAX_DEPTH: usize = 8;
/// Maximum map entries.
pub const MAX_MAP_ENTRIES: usize = 32;
/// Maximum byte-string length (65,536 plaintext + 16-byte Poly1305 tag).
pub const MAX_BSTR: usize = 65_552;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Range [-2^64, 2^64 - 1].
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Pair order is NOT significant for encoding; decoding yields canonical wire order.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

/// Stable semantic error categories. Display text == category string; the
/// category (not any message) is the interoperability contract.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CborError {
    #[error("ERR_NON_CANONICAL_INTEGER")]
    NonCanonicalInteger,
    #[error("ERR_DUPLICATE_MAP_KEY")]
    DuplicateMapKey,
    #[error("ERR_FLOAT_PROHIBITED")]
    FloatProhibited,
    #[error("ERR_INDEFINITE_LENGTH_PROHIBITED")]
    IndefiniteLengthProhibited,
    #[error("ERR_UNSORTED_MAP_KEYS")]
    UnsortedMapKeys,
    #[error("ERR_TRAILING_BYTES")]
    TrailingBytes,
    #[error("ERR_MALFORMED_CBOR")]
    MalformedCbor,
    #[error("ERR_UNSUPPORTED_ITEM")]
    UnsupportedItem,
    #[error("ERR_LIMIT_EXCEEDED")]
    LimitExceeded,
}

impl CborError {
    pub fn category(&self) -> &'static str {
        match self {
            CborError::NonCanonicalInteger => "ERR_NON_CANONICAL_INTEGER",
            CborError::DuplicateMapKey => "ERR_DUPLICATE_MAP_KEY",
            CborError::FloatProhibited => "ERR_FLOAT_PROHIBITED",
            CborError::IndefiniteLengthProhibited => "ERR_INDEFINITE_LENGTH_PROHIBITED",
            CborError::UnsortedMapKeys => "ERR_UNSORTED_MAP_KEYS",
            CborError::TrailingBytes => "ERR_TRAILING_BYTES",
            CborError::MalformedCbor => "ERR_MALFORMED_CBOR",
            CborError::UnsupportedItem => "ERR_UNSUPPORTED_ITEM",
            CborError::LimitExceeded => "ERR_LIMIT_EXCEEDED",
        }
    }
}

// ------------------------------------------------------------------ encoding

fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encode_into(v: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), CborError> {
    match v {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Int(n) => {
            if *n >= 0 {
                let a = u64::try_from(*n).map_err(|_| CborError::UnsupportedItem)?;
                write_head(out, 0, a);
            } else {
                let a = u64::try_from(-1 - *n).map_err(|_| CborError::UnsupportedItem)?;
                write_head(out, 1, a);
            }
        }
        Value::Bytes(b) => {
            if b.len() > MAX_BSTR {
                return Err(CborError::LimitExceeded);
            }
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            if depth >= MAX_DEPTH {
                return Err(CborError::LimitExceeded);
            }
            write_head(out, 4, items.len() as u64);
            for it in items {
                encode_into(it, out, depth + 1)?;
            }
        }
        Value::Map(pairs) => {
            if depth >= MAX_DEPTH || pairs.len() > MAX_MAP_ENTRIES {
                return Err(CborError::LimitExceeded);
            }
            let mut enc: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(pairs.len());
            for (k, val) in pairs {
                let mut kb = Vec::new();
                encode_into(k, &mut kb, depth + 1)?;
                let mut vb = Vec::new();
                encode_into(val, &mut vb, depth + 1)?;
                enc.push((kb, vb));
            }
            // RFC 8949 s4.2.1: bytewise lexicographic order of the ENCODED keys
            // (NOT length-first). Vec<u8> ordering is exactly that.
            enc.sort_by(|a, b| a.0.cmp(&b.0));
            if enc.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(CborError::DuplicateMapKey);
            }
            write_head(out, 5, enc.len() as u64);
            for (kb, vb) in enc {
                out.extend_from_slice(&kb);
                out.extend_from_slice(&vb);
            }
        }
    }
    Ok(())
}

/// Encode to PM-CBOR-2026. Map keys are sorted; duplicate keys are an error.
pub fn encode_canonical(v: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    encode_into(v, &mut out, 0)?;
    Ok(out)
}

// ------------------------------------------------------------------ decoding

fn take<'a>(input: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], CborError> {
    let end = pos.checked_add(n).ok_or(CborError::MalformedCbor)?;
    if end > input.len() {
        return Err(CborError::MalformedCbor);
    }
    let s = &input[*pos..end];
    *pos = end;
    Ok(s)
}

fn read_arg(input: &[u8], pos: &mut usize, ai: u8) -> Result<u64, CborError> {
    match ai {
        0..=23 => Ok(ai as u64),
        24 => {
            let v = take(input, pos, 1)?[0] as u64;
            if v < 24 { Err(CborError::NonCanonicalInteger) } else { Ok(v) }
        }
        25 => {
            let s = take(input, pos, 2)?;
            let v = u16::from_be_bytes([s[0], s[1]]) as u64;
            if v <= 0xff { Err(CborError::NonCanonicalInteger) } else { Ok(v) }
        }
        26 => {
            let s = take(input, pos, 4)?;
            let v = u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64;
            if v <= 0xffff { Err(CborError::NonCanonicalInteger) } else { Ok(v) }
        }
        27 => {
            let s = take(input, pos, 8)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            let v = u64::from_be_bytes(a);
            if v <= 0xffff_ffff { Err(CborError::NonCanonicalInteger) } else { Ok(v) }
        }
        _ => Err(CborError::MalformedCbor),
    }
}

fn read_len(input: &[u8], pos: &mut usize, ai: u8) -> Result<usize, CborError> {
    let n = read_arg(input, pos, ai)?;
    usize::try_from(n).map_err(|_| CborError::MalformedCbor)
}

fn decode_item(input: &[u8], pos: &mut usize, depth: usize) -> Result<Value, CborError> {
    let ib = take(input, pos, 1)?[0];
    let major = ib >> 5;
    let ai = ib & 0x1f;
    if (28..=30).contains(&ai) {
        return Err(CborError::MalformedCbor);
    }
    if ai == 31 {
        return Err(match major {
            2 | 3 | 4 | 5 => CborError::IndefiniteLengthProhibited,
            _ => CborError::MalformedCbor, // includes stray break (0xff)
        });
    }
    match major {
        0 => Ok(Value::Int(read_arg(input, pos, ai)? as i128)),
        1 => Ok(Value::Int(-1 - (read_arg(input, pos, ai)? as i128))),
        2 => {
            let n = read_len(input, pos, ai)?;
            if n > MAX_BSTR {
                return Err(CborError::LimitExceeded);
            }
            Ok(Value::Bytes(take(input, pos, n)?.to_vec()))
        }
        3 => {
            let n = read_len(input, pos, ai)?;
            let b = take(input, pos, n)?;
            let s = std::str::from_utf8(b).map_err(|_| CborError::MalformedCbor)?;
            Ok(Value::Text(s.to_owned()))
        }
        4 => {
            if depth >= MAX_DEPTH {
                return Err(CborError::LimitExceeded);
            }
            let n = read_len(input, pos, ai)?;
            let mut items = Vec::new();
            for _ in 0..n {
                items.push(decode_item(input, pos, depth + 1)?);
            }
            Ok(Value::Array(items))
        }
        5 => {
            if depth >= MAX_DEPTH {
                return Err(CborError::LimitExceeded);
            }
            let n = read_len(input, pos, ai)?;
            if n > MAX_MAP_ENTRIES {
                return Err(CborError::LimitExceeded);
            }
            let mut pairs = Vec::new();
            let mut key_ranges: Vec<(usize, usize)> = Vec::new();
            for _ in 0..n {
                let start = *pos;
                let k = decode_item(input, pos, depth + 1)?;
                key_ranges.push((start, *pos));
                let v = decode_item(input, pos, depth + 1)?;
                pairs.push((k, v));
            }
            let keys: Vec<&[u8]> = key_ranges.iter().map(|&(s, e)| &input[s..e]).collect();
            // Duplicate check first (covers non-adjacent duplicates), then order.
            let mut sorted = keys.clone();
            sorted.sort();
            if sorted.windows(2).any(|w| w[0] == w[1]) {
                return Err(CborError::DuplicateMapKey);
            }
            if keys.windows(2).any(|w| w[0] > w[1]) {
                return Err(CborError::UnsortedMapKeys);
            }
            Ok(Value::Map(pairs))
        }
        6 => Err(CborError::UnsupportedItem),
        _ => match ai {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            25 | 26 | 27 => Err(CborError::FloatProhibited),
            _ => Err(CborError::UnsupportedItem),
        },
    }
}

/// Strictly decode exactly one PM-CBOR-2026 item that consumes ALL of `input`.
pub fn decode_strict(input: &[u8]) -> Result<Value, CborError> {
    if input.len() > MAX_WIRE_INPUT {
        return Err(CborError::LimitExceeded);
    }
    let mut pos = 0usize;
    let v = decode_item(input, &mut pos, 0)?;
    if pos != input.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(v)
}

/// True iff `input` is a valid PM-CBOR-2026 encoding (re-encoding is byte-identical).
pub fn is_canonical(input: &[u8]) -> bool {
    match decode_strict(input) {
        Ok(v) => encode_canonical(&v).map(|e| e == input).unwrap_or(false),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn integer_heads() {
        for (n, hex) in [(0i128, "00"), (23, "17"), (24, "1818"), (255, "18ff"), (256, "190100"),
                         (65535, "19ffff"), (65536, "1a00010000"), (10, "0a")] {
            assert_eq!(encode_canonical(&Value::Int(n)).unwrap(), h(hex));
            assert_eq!(decode_strict(&h(hex)).unwrap(), Value::Int(n));
        }
        assert_eq!(decode_strict(&h("180a")), Err(CborError::NonCanonicalInteger));
    }

    #[test]
    fn length_first_regression() {
        let bad = h("a240616218186161");
        assert_eq!(decode_strict(&bad), Err(CborError::UnsortedMapKeys));
        let good = h("a218186161406162");
        assert!(decode_strict(&good).is_ok());
    }

    #[test]
    fn encoder_sorts_bytewise() {
        let m = Value::Map(vec![
            (Value::Bytes(vec![]), Value::Text("b".into())),
            (Value::Int(24), Value::Text("a".into())),
        ]);
        assert_eq!(encode_canonical(&m).unwrap(), h("a218186161406162"));
    }

    fn nested(n: usize) -> Vec<u8> {
        let mut v = vec![0x81u8; n];
        v.push(0x00);
        v
    }

    #[test]
    fn depth_limit_is_eight_containers() {
        assert!(decode_strict(&nested(8)).is_ok());
        assert_eq!(decode_strict(&nested(9)), Err(CborError::LimitExceeded));
    }

    #[test]
    fn bstr_limit_is_65552() {
        let mut ok = vec![0x5a, 0x00, 0x01, 0x00, 0x10];
        ok.extend(vec![0u8; MAX_BSTR]);
        assert!(decode_strict(&ok).is_ok());
        assert_eq!(decode_strict(&[0x5a, 0x00, 0x01, 0x00, 0x11]), Err(CborError::LimitExceeded));
        assert_eq!(encode_canonical(&Value::Bytes(vec![0; MAX_BSTR + 1])), Err(CborError::LimitExceeded));
    }

    #[test]
    fn wire_input_limit() {
        assert_eq!(decode_strict(&vec![0u8; MAX_WIRE_INPUT + 1]), Err(CborError::LimitExceeded));
    }

    #[test]
    fn map_entry_limit_is_32() {
        let m = |n: i128| Value::Map((0..n).map(|i| (Value::Int(i), Value::Int(0))).collect());
        let enc = encode_canonical(&m(32)).unwrap();
        assert!(decode_strict(&enc).is_ok());
        assert_eq!(encode_canonical(&m(33)), Err(CborError::LimitExceeded));
    }

    #[test]
    fn duplicate_keys_rejected_by_encoder() {
        let m = Value::Map(vec![(Value::Int(1), Value::Int(1)), (Value::Int(1), Value::Int(2))]);
        assert_eq!(encode_canonical(&m), Err(CborError::DuplicateMapKey));
    }
}
