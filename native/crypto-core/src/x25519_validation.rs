//! Shared X25519 public-key usability validation.
//!
//! A public key is usable only when X25519 with a fixed non-zero scalar produces
//! a contributory shared secret. This rejects low-order/non-contributory points.

use x25519_dalek::{PublicKey, StaticSecret};

pub(crate) fn is_usable_x25519_public_key(public: &[u8; 32]) -> bool {
    let private = StaticSecret::from([0x42u8; 32]);
    let public = PublicKey::from(*public);
    private.diffie_hellman(&public).was_contributory()
}

#[cfg(test)]
mod tests {
    use super::is_usable_x25519_public_key;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn x25519_validation_rejects_zero_and_low_order_public_keys() {
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1;

        assert!(!is_usable_x25519_public_key(&zero));
        assert!(!is_usable_x25519_public_key(&one));
    }

    #[test]
    fn x25519_validation_accepts_a_derived_public_key() {
        let private = StaticSecret::from([0x11u8; 32]);
        let public = PublicKey::from(&private).to_bytes();

        assert!(is_usable_x25519_public_key(&public));
    }
}
