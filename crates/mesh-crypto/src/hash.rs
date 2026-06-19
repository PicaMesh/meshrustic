use sha2::{Digest, Sha256};

/// SHA-256 over the first `input_len` bytes of `data`, writing the digest into `data[..32]`.
///
/// Chunked SHA-256 digest into a 32-byte output buffer.
pub fn sha256_in_place(data: &mut [u8], input_len: usize) {
    let len = input_len.min(data.len());
    let digest = Sha256::digest(&data[..len]);
    data[..32].copy_from_slice(&digest);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
        let decoded = hex::decode(hex).unwrap();
        let mut out = [0u8; N];
        out.copy_from_slice(&decoded);
        out
    }

    #[test]
    fn sha256_empty_and_short_inputs() {
        let mut hash = [0u8; 32];
        sha256_in_place(&mut hash, 0);
        assert_eq!(
            hash,
            hex_to_bytes::<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );

        let mut hash = [0u8; 32];
        hash[0] = 0xd3;
        sha256_in_place(&mut hash, 1);
        assert_eq!(
            hash,
            hex_to_bytes::<32>("28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1")
        );
    }
}
