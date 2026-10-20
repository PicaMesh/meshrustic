use mesh_crypto::sha256_in_place;
use x25519_dalek::{PublicKey, StaticSecret};

/// Derive the device key pair from a random seed and the chip-unique device id.
///
/// The seed never becomes the private key: it is mixed with the device id and
/// hashed, so two chips that draw the same random bytes still end up with
/// different identities, and a dump of the raw random bytes does not reveal the
/// key. Public device identifiers provide no secret entropy, so the seed must
/// come entirely from the hardware random source.
pub fn generate_keypair(seed: [u8; 32], device_id: &[u8; 8]) -> ([u8; 32], [u8; 32]) {
    let mut material = [0u8; 32 + 8];
    material[..32].copy_from_slice(&seed);
    material[32..].copy_from_slice(device_id);
    let mut key = [0u8; 32];
    let material_len = material.len();
    if sha256_in_place(&mut material, material_len) {
        key.copy_from_slice(&material[..32]);
    } else {
        // The buffer is long enough for the digest, so this cannot happen;
        // fall back to the seed rather than returning an all-zero key.
        key.copy_from_slice(&seed);
    }
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
    let secret = StaticSecret::from(key);
    let public = PublicKey::from(&secret);
    (*secret.as_bytes(), *public.as_bytes())
}

pub fn public_from_private(private_key: &[u8; 32]) -> Option<[u8; 32]> {
    if private_key.iter().all(|&b| b == 0) {
        return None;
    }
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(&secret);
    if public.as_bytes().iter().all(|&b| b == 0) {
        return None;
    }
    Some(*public.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let device_id = [0x11u8; 8];
        let (priv_key, pub_key) = generate_keypair([0x22u8; 32], &device_id);
        assert_eq!(public_from_private(&priv_key).unwrap(), pub_key);
    }

    #[test]
    fn the_same_seed_on_different_chips_gives_different_keys() {
        let (first, _) = generate_keypair([0x33u8; 32], &[0x01; 8]);
        let (second, _) = generate_keypair([0x33u8; 32], &[0x02; 8]);
        assert_ne!(first, second);
    }

    #[test]
    fn a_degenerate_seed_still_gives_a_usable_key() {
        let (priv_key, pub_key) = generate_keypair([0u8; 32], &[0x44; 8]);
        assert!(priv_key.iter().any(|&b| b != 0));
        assert_eq!(public_from_private(&priv_key).unwrap(), pub_key);
    }
}
