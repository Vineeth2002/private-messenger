//! Shared-vector conformance for PM-CBOR-2026 (Rust side of the parity gate).
//! If PM_PARITY_OUT is set, writes {"positive:<id>": hex, "negative:<id>": category}.
use pm_crypto_core::cbor::{decode_strict, encode_canonical, is_canonical, Value};
use serde_json::Value as J;
use std::collections::BTreeMap;

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn parse_tagged(j: &J) -> Value {
    let o = j.as_object().expect("tagged value must be an object");
    assert_eq!(o.len(), 1);
    let (tag, body) = o.iter().next().unwrap();
    match tag.as_str() {
        "int" => Value::Int(body.as_str().unwrap().parse::<i128>().unwrap()),
        "bytes" => Value::Bytes(hex_decode(body.as_str().unwrap())),
        "text" => Value::Text(body.as_str().unwrap().to_string()),
        "bool" => Value::Bool(body.as_bool().unwrap()),
        "null" => Value::Null,
        "array" => Value::Array(body.as_array().unwrap().iter().map(parse_tagged).collect()),
        "map" => Value::Map(
            body.as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    let p = p.as_array().unwrap();
                    assert_eq!(p.len(), 2);
                    (parse_tagged(&p[0]), parse_tagged(&p[1]))
                })
                .collect(),
        ),
        other => panic!("unknown tag {other}"),
    }
}

fn load() -> J {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/cbor_canonical_codec.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("valid JSON")
}

#[test]
fn cbor_shared_vectors() {
    let v = load();
    let mut parity: BTreeMap<String, String> = BTreeMap::new();

    for p in v["positive"].as_array().unwrap() {
        let id = p["id"].as_str().unwrap();
        let want = hex_decode(p["cbor_hex"].as_str().unwrap());
        let value = parse_tagged(&p["value"]);
        let got = encode_canonical(&value).unwrap_or_else(|e| panic!("{id}: encode failed {e}"));
        assert_eq!(got, want, "{id}: encode mismatch");
        let dec = decode_strict(&want).unwrap_or_else(|e| panic!("{id}: decode rejected {e}"));
        assert_eq!(encode_canonical(&dec).unwrap(), want, "{id}: roundtrip");
        assert!(is_canonical(&want), "{id}: is_canonical");
        parity.insert(format!("positive:{id}"), hex_encode(&got));
    }

    for n in v["negative"].as_array().unwrap() {
        let id = n["id"].as_str().unwrap();
        let want = n["error"].as_str().unwrap();
        let bytes = hex_decode(n["cbor_hex"].as_str().unwrap());
        match decode_strict(&bytes) {
            Ok(_) => panic!("{id}: negative vector was ACCEPTED"),
            Err(e) => assert_eq!(e.category(), want, "{id}: wrong error category"),
        }
        assert!(!is_canonical(&bytes), "{id}");
        parity.insert(format!("negative:{id}"), want.to_string());
    }

    // Resolved s28 entry (array name "quarantined" kept for loader compatibility): the handoff's bytes are malformed; the authoritative RFC bytes are valid.
    for q in v["quarantined"].as_array().unwrap() {
        let as_written = hex_decode(q["spec_s28_corrected_hex_as_written"].as_str().unwrap());
        assert_eq!(decode_strict(&as_written).unwrap_err().category(),
                   q["spec_s28_as_written_decodes_to"].as_str().unwrap());
        let rfc = hex_decode(q["rfc8949_hex"].as_str().unwrap());
        assert_eq!(encode_canonical(&parse_tagged(&q["value"])).unwrap(), rfc);
    }

    if let Ok(out) = std::env::var("PM_PARITY_OUT") {
        std::fs::write(out, serde_json::to_string(&parity).unwrap()).unwrap();
    }
}

#[test]
fn decode_never_normalizes_noncanonical_input() {
    // Non-minimal int must be rejected even though it would re-encode to a valid value.
    assert!(decode_strict(&hex_decode("180a")).is_err());
    assert!(decode_strict(&hex_decode("a201010102")).is_err());
    assert!(decode_strict(&hex_decode("0000")).is_err());
}
