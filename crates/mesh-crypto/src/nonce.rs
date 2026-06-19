/// Build the 128-bit AES-CTR nonce for channel encryption.
pub fn init_nonce(out: &mut [u8; 16], from_node: u32, packet_id: u64, extra_nonce: u32) {
    out.fill(0);
    out[..8].copy_from_slice(&packet_id.to_le_bytes());
    out[8..12].copy_from_slice(&from_node.to_le_bytes());
    if extra_nonce != 0 {
        out[4..8].copy_from_slice(&extra_nonce.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pki_nonce_golden_vector() {
        let mut nonce = [0u8; 16];
        init_nonce(&mut nonce, 0x0929, 0x13b2d662, 0x036a792b);
        let expected = hex::decode("62d6b213036a792b2909000000").unwrap();
        assert_eq!(&nonce[..13], expected.as_slice());
    }
}
