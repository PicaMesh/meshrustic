use x25519_dalek::{PublicKey, StaticSecret};

// Public device identifiers provide no secret entropy; firmware must obtain the entire seed from its
// hardware RNG.
pub fn generate_keypair(mut seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    seed[0] &= 248;
    seed[31] = (seed[31] & 127) | 64;
    let secret = StaticSecret::from(seed);
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
        let device_id = [0x11u8; 16];
        let (priv_key, pub_key) = generate_keypair([device_id[0]; 32]);
        assert_eq!(public_from_private(&priv_key).unwrap(), pub_key);
    }
}
