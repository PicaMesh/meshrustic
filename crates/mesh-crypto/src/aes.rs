use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};

use crate::key::CryptoKey;

/// Single-block AES-ECB encrypt.
pub fn aes_ecb_encrypt_block(key: &[u8], input: &[u8; 16], output: &mut [u8; 16]) {
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).expect("valid AES-128 key");
            let mut block = Block::from(*input);
            cipher.encrypt_block(&mut block);
            output.copy_from_slice(block.as_slice());
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).expect("valid AES-256 key");
            let mut block = Block::from(*input);
            cipher.encrypt_block(&mut block);
            output.copy_from_slice(block.as_slice());
        }
        _ => panic!("unsupported AES key length"),
    }
}

/// In-place AES-CTR matching Arduino Crypto `CTR` with 16-byte IV and 4-byte counter.
pub fn aes_ctr_crypt(key: &CryptoKey, nonce: &[u8; 16], data: &mut [u8]) {
    if key.length <= 0 {
        return;
    }

    let key_len = key.length as usize;
    let mut iv = *nonce;
    const COUNTER_SIZE: usize = 4;
    const BLOCK_SIZE: usize = 16;

    let mut offset = 0usize;
    while offset < data.len() {
        let mut keystream = [0u8; BLOCK_SIZE];
        aes_ecb_encrypt_block(&key.bytes[..key_len], &iv, &mut keystream);

        let chunk = (data.len() - offset).min(BLOCK_SIZE);
        for i in 0..chunk {
            data[offset + i] ^= keystream[i];
        }
        offset += chunk;

        // Big-endian increment of the counter field (last COUNTER_SIZE bytes).
        for i in (BLOCK_SIZE - COUNTER_SIZE..BLOCK_SIZE).rev() {
            iv[i] = iv[i].wrapping_add(1);
            if iv[i] != 0 {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::CryptoKey;

    fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
        let decoded = hex::decode(hex).unwrap();
        let mut out = [0u8; N];
        out.copy_from_slice(&decoded);
        out
    }

    #[test]
    fn ecb_aes256_nist_vectors() {
        let key =
            hex_to_bytes::<32>("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4");

        let mut plain = hex_to_bytes::<16>("6BC1BEE22E409F96E93D7E117393172A");
        let mut out = [0u8; 16];
        aes_ecb_encrypt_block(&key, &plain, &mut out);
        assert_eq!(out, hex_to_bytes::<16>("F3EED1BDB5D2A03C064B5A7E3DB181F8"));

        plain = hex_to_bytes::<16>("AE2D8A571E03AC9C9EB76FAC45AF8E51");
        aes_ecb_encrypt_block(&key, &plain, &mut out);
        assert_eq!(out, hex_to_bytes::<16>("591CCB10D410ED26DC5BA74A31362870"));
    }

    #[test]
    fn aes_ctr_rfc3686_vectors() {
        let mut k = CryptoKey::none();
        k.length = 32;
        k.bytes =
            hex_to_bytes::<32>("776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104");
        let nonce = hex_to_bytes::<16>("00000060DB5672C97AA8F0B200000001");
        let mut plain = *b"Single block msg";
        aes_ctr_crypt(&k, &nonce, &mut plain);
        assert_eq!(
            plain,
            hex_to_bytes::<16>("145AD01DBF824EC7560863DC71E3E0C0")
        );

        k.length = 16;
        k.bytes[..16].copy_from_slice(&hex_to_bytes::<16>("AE6852F8121067CC4BF7A5765577F39E"));
        let nonce = hex_to_bytes::<16>("00000030000000000000000000000001");
        let mut plain = *b"Single block msg";
        aes_ctr_crypt(&k, &nonce, &mut plain);
        assert_eq!(
            plain,
            hex_to_bytes::<16>("E4095D4FB7A7B3792D6175A3261311B8")
        );
    }
}
