use x25519_dalek::{PublicKey, StaticSecret};

/// Generate a Curve25519 key pair, stirring optional 16-byte device id into the secret.
///
/// Device id (optional) plus extra entropy
/// before `Curve25519::dh1`. The caller supplies `extra_entropy` from a TRNG on device.
pub fn generate_keypair(device_id: Option<&[u8; 16]>, extra_entropy: u64) -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    if let Some(id) = device_id {
        seed[..16].copy_from_slice(id);
    }
    seed[16..24].copy_from_slice(&extra_entropy.to_le_bytes());
    seed[24..32].copy_from_slice(&(extra_entropy.rotate_left(17)).to_le_bytes());

    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);
    (*secret.as_bytes(), *public.as_bytes())
}

/// Derive the public key from an existing private key.
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
        let (priv_key, pub_key) = generate_keypair(Some(&device_id), 0xDEAD_BEEF);
        assert_eq!(public_from_private(&priv_key).unwrap(), pub_key);
    }
}
