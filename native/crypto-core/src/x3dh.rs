//! PM-BI-X3DH-1 (Bounded-Identity X3DH Profile): handshake session-key derivation and the
//! Cert_dh identity binding. Proprietary profile, NOT Signal-X3DH interoperable.
//!
//! Frozen formulas (docs/phase0/03-crypto-architecture.md):
//!   DH1 = X25519(IK_dh_A_priv, SPK_B)   DH2 = X25519(EK_A_priv, IK_dh_B)
//!   DH3 = X25519(EK_A_priv, SPK_B)      DH4 = X25519(EK_A_priv, OPK_B)   (only if an OPK exists)
//!   IKM = DH1 || DH2 || DH3 [|| DH4]    (96 or 128 bytes)
//!   PRK = HKDF-Extract(salt = "PM-BI-X3DH-1-HKDF-SALT-v1", IKM)
//!   Context = IK_dh_A || IK_dh_B || Epoch_A (4 B BE) || Epoch_B (4 B BE)          (72 bytes)
//!   SK  = HKDF-Expand(PRK, "PM-BI-X3DH-1-SESSION-KEY-v1" || Context, 32)
//!   Cert_dh = Ed25519Sign(DSK_priv, "PM-V1-DH-BIND" || AccountID || DeviceID || DDHK_pub || u64_be(ts))
//!
//! IMPLEMENTATION DECISIONS (not in the frozen text, conservative, vectors unaffected):
//!  * a non-contributory X25519 output (all-zero shared secret from a low-order public key) is
//!    rejected (fail closed, RFC 7748 s6.1);
//!  * Cert_dh is verified with `verify_strict` (rejects small-order keys / non-canonical signatures);
//!  * the DH outputs, IKM and PRK never leave this module; callers get only the 32-byte SK.
//! Not implemented here (not specified): signed-prekey signature verification, prekey selection,
//! the PrekeyHandshakeHeader parser, and the Double Ratchet that consumes SK.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroizing;

pub const X3DH_SALT: &[u8] = b"PM-BI-X3DH-1-HKDF-SALT-v1";
pub const X3DH_INFO: &[u8] = b"PM-BI-X3DH-1-SESSION-KEY-v1";
pub const DH_BIND: &[u8] = b"PM-V1-DH-BIND";
const _: () = assert!(X3DH_SALT.len() == 25);
const _: () = assert!(X3DH_INFO.len() == 27);
const _: () = assert!(DH_BIND.len() == 13);

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum X3dhError {
    #[error("non-contributory X25519 output (degenerate public key)")]
    NonContributoryDh,
    #[error("HKDF failure")]
    Kdf,
    #[error("malformed public key")]
    BadPublicKey,
    #[error("Cert_dh signature invalid")]
    BadCertDh,
}

/// `Context = IK_dh_A || IK_dh_B || Epoch_A (4 B BE) || Epoch_B (4 B BE)`.
pub fn x3dh_context(ik_a_pub: &[u8; 32], ik_b_pub: &[u8; 32], epoch_a: u32, epoch_b: u32) -> [u8; 72] {
    let mut c = [0u8; 72];
    c[..32].copy_from_slice(ik_a_pub);
    c[32..64].copy_from_slice(ik_b_pub);
    c[64..68].copy_from_slice(&epoch_a.to_be_bytes());
    c[68..72].copy_from_slice(&epoch_b.to_be_bytes());
    c
}

/// HKDF-Extract(salt, ikm) = HMAC-SHA256(key = salt, msg = ikm).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    let out = mac.finalize().into_bytes();
    let mut prk = Zeroizing::new([0u8; 32]);
    prk[..].copy_from_slice(out.as_slice());
    prk
}

fn ikm_of(dhs: &[SharedSecret]) -> Zeroizing<Vec<u8>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * dhs.len()));
    for d in dhs {
        ikm.extend_from_slice(d.as_bytes());
    }
    ikm
}

fn derive_sk(
    dhs: &[SharedSecret],
    ik_a_pub: &[u8; 32],
    ik_b_pub: &[u8; 32],
    epoch_a: u32,
    epoch_b: u32,
) -> Result<Zeroizing<[u8; 32]>, X3dhError> {
    if dhs.len() != 3 && dhs.len() != 4 {
        return Err(X3dhError::Kdf);
    }
    if dhs.iter().any(|d| !d.was_contributory()) {
        return Err(X3dhError::NonContributoryDh);
    }
    let ikm = ikm_of(dhs);
    let prk = hkdf_extract(X3DH_SALT, &ikm);
    let mut info = Vec::with_capacity(X3DH_INFO.len() + 72);
    info.extend_from_slice(X3DH_INFO);
    info.extend_from_slice(&x3dh_context(ik_a_pub, ik_b_pub, epoch_a, epoch_b));
    let hk = Hkdf::<Sha256>::from_prk(&prk[..]).map_err(|_| X3dhError::Kdf)?;
    let mut sk = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut sk[..]).map_err(|_| X3dhError::Kdf)?;
    Ok(sk)
}

fn initiator_dhs(
    ik_a_priv: &StaticSecret,
    ek_a_priv: &StaticSecret,
    ik_b_pub: &[u8; 32],
    spk_b_pub: &[u8; 32],
    opk_b_pub: Option<&[u8; 32]>,
) -> Vec<SharedSecret> {
    let ik_b = PublicKey::from(*ik_b_pub);
    let spk_b = PublicKey::from(*spk_b_pub);
    let mut dhs = vec![
        ik_a_priv.diffie_hellman(&spk_b), // DH1
        ek_a_priv.diffie_hellman(&ik_b),  // DH2
        ek_a_priv.diffie_hellman(&spk_b), // DH3
    ];
    if let Some(opk) = opk_b_pub {
        dhs.push(ek_a_priv.diffie_hellman(&PublicKey::from(*opk))); // DH4
    }
    dhs
}

fn responder_dhs(
    ik_b_priv: &StaticSecret,
    spk_b_priv: &StaticSecret,
    opk_b_priv: Option<&StaticSecret>,
    ik_a_pub: &[u8; 32],
    ek_a_pub: &[u8; 32],
) -> Vec<SharedSecret> {
    let ik_a = PublicKey::from(*ik_a_pub);
    let ek_a = PublicKey::from(*ek_a_pub);
    let mut dhs = vec![
        spk_b_priv.diffie_hellman(&ik_a), // DH1 (initiator: IK_A_priv x SPK_B)
        ik_b_priv.diffie_hellman(&ek_a),  // DH2 (initiator: EK_A_priv x IK_B)
        spk_b_priv.diffie_hellman(&ek_a), // DH3 (initiator: EK_A_priv x SPK_B)
    ];
    if let Some(opk) = opk_b_priv {
        dhs.push(opk.diffie_hellman(&ek_a)); // DH4 (initiator: EK_A_priv x OPK_B)
    }
    dhs
}

/// Alice (initiator): derive the 32-byte session key SK. `opk_b_pub` is `None` when Bob had no OPK left.
#[allow(clippy::too_many_arguments)]
pub fn initiator_derive_sk(
    ik_a_priv: &StaticSecret,
    ek_a_priv: &StaticSecret,
    ik_b_pub: &[u8; 32],
    spk_b_pub: &[u8; 32],
    opk_b_pub: Option<&[u8; 32]>,
    epoch_a: u32,
    epoch_b: u32,
) -> Result<Zeroizing<[u8; 32]>, X3dhError> {
    let dhs = initiator_dhs(ik_a_priv, ek_a_priv, ik_b_pub, spk_b_pub, opk_b_pub);
    let ik_a_pub = PublicKey::from(ik_a_priv).to_bytes();
    derive_sk(&dhs, &ik_a_pub, ik_b_pub, epoch_a, epoch_b)
}

/// Bob (responder): derive the same SK from the initiator's public values.
#[allow(clippy::too_many_arguments)]
pub fn responder_derive_sk(
    ik_b_priv: &StaticSecret,
    spk_b_priv: &StaticSecret,
    opk_b_priv: Option<&StaticSecret>,
    ik_a_pub: &[u8; 32],
    ek_a_pub: &[u8; 32],
    epoch_a: u32,
    epoch_b: u32,
) -> Result<Zeroizing<[u8; 32]>, X3dhError> {
    let dhs = responder_dhs(ik_b_priv, spk_b_priv, opk_b_priv, ik_a_pub, ek_a_pub);
    let ik_b_pub = PublicKey::from(ik_b_priv).to_bytes();
    derive_sk(&dhs, ik_a_pub, &ik_b_pub, epoch_a, epoch_b)
}

// ---------------------------------------------------------------- Cert_dh

/// The 85-byte Cert_dh transcript: "PM-V1-DH-BIND" || AccountID || DeviceID || DDHK_pub || u64_be(ts).
pub fn cert_dh_transcript(
    account_id: &[u8; 16],
    device_id: &[u8; 16],
    ddhk_pub: &[u8; 32],
    timestamp: u64,
) -> [u8; 85] {
    let mut t = [0u8; 85];
    t[..13].copy_from_slice(DH_BIND);
    t[13..29].copy_from_slice(account_id);
    t[29..45].copy_from_slice(device_id);
    t[45..77].copy_from_slice(ddhk_pub);
    t[77..85].copy_from_slice(&timestamp.to_be_bytes());
    t
}

/// Cert_dh = Ed25519Sign(DSK_priv, transcript). The signer is the sender device's DSK (never the DDHK).
pub fn cert_dh_sign(
    dsk: &SigningKey,
    account_id: &[u8; 16],
    device_id: &[u8; 16],
    ddhk_pub: &[u8; 32],
    timestamp: u64,
) -> [u8; 64] {
    dsk.sign(&cert_dh_transcript(account_id, device_id, ddhk_pub, timestamp)).to_bytes()
}

/// Recipient-side check. Any failure must abort the handshake (fail closed).
pub fn cert_dh_verify(
    dsk_pub: &[u8; 32],
    account_id: &[u8; 16],
    device_id: &[u8; 16],
    ddhk_pub: &[u8; 32],
    timestamp: u64,
    cert: &[u8; 64],
) -> Result<(), X3dhError> {
    let vk = VerifyingKey::from_bytes(dsk_pub).map_err(|_| X3dhError::BadPublicKey)?;
    let sig = Signature::from_bytes(cert);
    vk.verify_strict(&cert_dh_transcript(account_id, device_id, ddhk_pub, timestamp), &sig)
        .map_err(|_| X3dhError::BadCertDh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }
    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex_decode(s).try_into().expect("wrong length")
    }
    fn load() -> J {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/v1/bi_x3dh_handshake.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("valid JSON")
    }
    fn secret(v: &J, k: &str) -> StaticSecret {
        StaticSecret::from(arr::<32>(v[k].as_str().unwrap()))
    }
    fn pubkey(v: &J, k: &str) -> [u8; 32] {
        arr::<32>(v[k].as_str().unwrap())
    }
    fn case<'a>(v: &'a J, id: &str) -> &'a J {
        v["cases"].as_array().unwrap().iter().find(|c| c["id"] == id).unwrap()
    }
    fn epochs(i: &J) -> (u32, u32) {
        (i["epoch_a"].as_u64().unwrap() as u32, i["epoch_b"].as_u64().unwrap() as u32)
    }

    #[test]
    fn labels_match_the_vector_file() {
        let v = load();
        for (key, bytes) in [("X3DH_SALT", X3DH_SALT), ("X3DH_INFO", X3DH_INFO), ("DH_BIND", DH_BIND)] {
            let l = &v["labels"][key];
            assert_eq!(hex_encode(bytes), l["hex"].as_str().unwrap(), "{key}");
            assert_eq!(bytes.len() as u64, l["length"].as_u64().unwrap(), "{key}");
        }
    }

    #[test]
    fn every_intermediate_and_the_session_key_match_the_vectors() {
        let v = load();
        for c in v["cases"].as_array().unwrap() {
            let id = c["id"].as_str().unwrap();
            let (i, d) = (&c["inputs"], &c["derived"]);
            let (ea, eb) = epochs(i);
            let has_opk = i.get("opk_b_priv").is_some();

            // public keys follow from the private keys
            for k in ["ik_a", "ek_a", "ik_b", "spk_b"] {
                let p = PublicKey::from(&secret(i, &format!("{k}_priv"))).to_bytes();
                assert_eq!(hex_encode(&p), i[format!("{k}_pub")].as_str().unwrap(), "{id}: {k}");
            }

            let ik_a = secret(i, "ik_a_priv");
            let ek_a = secret(i, "ek_a_priv");
            let ik_b = secret(i, "ik_b_priv");
            let spk_b = secret(i, "spk_b_priv");
            let opk_b = if has_opk { Some(secret(i, "opk_b_priv")) } else { None };
            let (ik_a_pub, ek_a_pub) = (pubkey(i, "ik_a_pub"), pubkey(i, "ek_a_pub"));
            let (ik_b_pub, spk_b_pub) = (pubkey(i, "ik_b_pub"), pubkey(i, "spk_b_pub"));
            let opk_b_pub = if has_opk { Some(pubkey(i, "opk_b_pub")) } else { None };

            // DH1..DH4, IKM, PRK, Context (initiator side)
            let dhs = initiator_dhs(&ik_a, &ek_a, &ik_b_pub, &spk_b_pub, opk_b_pub.as_ref());
            assert_eq!(dhs.len(), if has_opk { 4 } else { 3 }, "{id}");
            for (n, dh) in dhs.iter().enumerate() {
                assert_eq!(hex_encode(dh.as_bytes()), d[format!("dh{}", n + 1)].as_str().unwrap(), "{id}: dh{}", n + 1);
            }
            let ikm = ikm_of(&dhs);
            assert_eq!(ikm.len() as u64, d["ikm_length"].as_u64().unwrap(), "{id}");
            assert_eq!(hex_encode(&ikm), d["ikm"].as_str().unwrap(), "{id}: ikm");
            assert_eq!(hex_encode(&hkdf_extract(X3DH_SALT, &ikm)[..]), d["prk"].as_str().unwrap(), "{id}: prk");
            let ctx = x3dh_context(&ik_a_pub, &ik_b_pub, ea, eb);
            assert_eq!(ctx.len() as u64, d["context_length"].as_u64().unwrap(), "{id}");
            assert_eq!(hex_encode(&ctx), d["context"].as_str().unwrap(), "{id}: context");

            // the session key, from BOTH sides
            let sk_a = initiator_derive_sk(&ik_a, &ek_a, &ik_b_pub, &spk_b_pub, opk_b_pub.as_ref(), ea, eb).unwrap();
            assert_eq!(hex_encode(&sk_a[..]), d["sk"].as_str().unwrap(), "{id}: initiator sk");
            let sk_b = responder_derive_sk(&ik_b, &spk_b, opk_b.as_ref(), &ik_a_pub, &ek_a_pub, ea, eb).unwrap();
            assert_eq!(hex_encode(&sk_b[..]), d["sk"].as_str().unwrap(), "{id}: responder sk");
        }
    }

    #[test]
    fn the_one_time_prekey_changes_the_session_key() {
        let v = load();
        let a = case(&v, "with_opk")["derived"]["sk"].as_str().unwrap().to_string();
        let b = case(&v, "without_opk")["derived"]["sk"].as_str().unwrap().to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn swapped_epochs_give_a_different_session_key() {
        let v = load();
        let c = case(&v, "with_opk");
        let i = &c["inputs"];
        let (ea, eb) = epochs(i);
        assert_ne!(ea, eb, "test epochs must differ");
        let sk = initiator_derive_sk(
            &secret(i, "ik_a_priv"), &secret(i, "ek_a_priv"), &pubkey(i, "ik_b_pub"), &pubkey(i, "spk_b_pub"),
            Some(&pubkey(i, "opk_b_pub")), eb, ea,
        )
        .unwrap();
        assert_ne!(hex_encode(&sk[..]), c["derived"]["sk"].as_str().unwrap());
    }

    #[test]
    fn responder_without_the_opk_disagrees_with_an_initiator_that_used_it() {
        let v = load();
        let i = &case(&v, "with_opk")["inputs"];
        let (ea, eb) = epochs(i);
        let sk = responder_derive_sk(
            &secret(i, "ik_b_priv"), &secret(i, "spk_b_priv"), None, &pubkey(i, "ik_a_pub"), &pubkey(i, "ek_a_pub"), ea, eb,
        )
        .unwrap();
        assert_ne!(hex_encode(&sk[..]), case(&v, "with_opk")["derived"]["sk"].as_str().unwrap());
    }

    #[test]
    fn low_order_public_keys_are_rejected_fail_closed() {
        let v = load();
        let i = &case(&v, "with_opk")["inputs"];
        let (ea, eb) = epochs(i);
        let zero = [0u8; 32]; // low-order point: X25519 output is all zero
        let r = initiator_derive_sk(
            &secret(i, "ik_a_priv"), &secret(i, "ek_a_priv"), &pubkey(i, "ik_b_pub"), &zero, None, ea, eb,
        );
        assert_eq!(r.unwrap_err(), X3dhError::NonContributoryDh);
        let r = responder_derive_sk(
            &secret(i, "ik_b_priv"), &secret(i, "spk_b_priv"), None, &zero, &pubkey(i, "ek_a_pub"), ea, eb,
        );
        assert_eq!(r.unwrap_err(), X3dhError::NonContributoryDh);
    }

    // ------------------------------------------------------------ Cert_dh
    struct Cert {
        account_id: [u8; 16],
        device_id: [u8; 16],
        ddhk_pub: [u8; 32],
        ts: u64,
        dsk_pub: [u8; 32],
        sig: [u8; 64],
        seed: [u8; 32],
    }
    fn cert() -> Cert {
        let v = load();
        let t = &v["cert_dh_transcript"];
        Cert {
            account_id: arr(t["account_id"].as_str().unwrap()),
            device_id: arr(t["device_id"].as_str().unwrap()),
            ddhk_pub: arr(t["ddhk_pub"].as_str().unwrap()),
            ts: t["timestamp"].as_u64().unwrap(),
            dsk_pub: arr(t["dsk_pub_hex"].as_str().unwrap()),
            sig: arr(t["signature_hex"].as_str().unwrap()),
            seed: arr(t["dsk_seed_hex"].as_str().unwrap()),
        }
    }

    #[test]
    fn cert_dh_transcript_signature_and_verification_match_the_vector() {
        let v = load();
        let t = &v["cert_dh_transcript"];
        let c = cert();
        let tr = cert_dh_transcript(&c.account_id, &c.device_id, &c.ddhk_pub, c.ts);
        assert_eq!(tr.len() as u64, t["transcript_length"].as_u64().unwrap());
        assert_eq!(hex_encode(&tr), t["transcript_hex"].as_str().unwrap());

        let dsk = SigningKey::from_bytes(&c.seed);
        assert_eq!(hex_encode(&dsk.verifying_key().to_bytes()), hex_encode(&c.dsk_pub));
        // Ed25519 is deterministic: our signature must equal the reference signature.
        assert_eq!(cert_dh_sign(&dsk, &c.account_id, &c.device_id, &c.ddhk_pub, c.ts), c.sig);
        assert!(cert_dh_verify(&c.dsk_pub, &c.account_id, &c.device_id, &c.ddhk_pub, c.ts, &c.sig).is_ok());
    }

    #[test]
    fn cert_dh_fails_closed_on_any_change() {
        let c = cert();
        let bad = |r: Result<(), X3dhError>| assert_eq!(r.unwrap_err(), X3dhError::BadCertDh);

        bad(cert_dh_verify(&c.dsk_pub, &c.account_id, &c.device_id, &c.ddhk_pub, c.ts + 1, &c.sig));
        let mut acct = c.account_id;
        acct[0] ^= 1;
        bad(cert_dh_verify(&c.dsk_pub, &acct, &c.device_id, &c.ddhk_pub, c.ts, &c.sig));
        let mut dev = c.device_id;
        dev[15] ^= 1;
        bad(cert_dh_verify(&c.dsk_pub, &c.account_id, &dev, &c.ddhk_pub, c.ts, &c.sig));
        let mut ddhk = c.ddhk_pub;
        ddhk[31] ^= 1;
        bad(cert_dh_verify(&c.dsk_pub, &c.account_id, &c.device_id, &ddhk, c.ts, &c.sig));
        let mut sig = c.sig;
        sig[63] ^= 1;
        bad(cert_dh_verify(&c.dsk_pub, &c.account_id, &c.device_id, &c.ddhk_pub, c.ts, &sig));
        // a different device signing key must not verify
        let other = SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes();
        bad(cert_dh_verify(&other, &c.account_id, &c.device_id, &c.ddhk_pub, c.ts, &c.sig));
    }
}
