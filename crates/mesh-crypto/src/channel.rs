use crate::aes::aes_ctr_crypt;
use crate::key::CryptoKey;
use crate::nonce::init_nonce;
use crate::MAX_BLOCKSIZE;

/// Encrypt a channel payload in place (AES-CTR).
pub fn encrypt_packet(key: &CryptoKey, from_node: u32, packet_id: u64, bytes: &mut [u8]) {
    if !key.is_enabled() || bytes.is_empty() {
        return;
    }
    if bytes.len() > MAX_BLOCKSIZE {
        return;
    }
    let mut nonce = [0u8; 16];
    init_nonce(&mut nonce, from_node, packet_id, 0);
    aes_ctr_crypt(key, &nonce, bytes);
}

/// Decrypt a channel payload in place (AES-CTR; symmetric with encrypt).
pub fn decrypt_packet(key: &CryptoKey, from_node: u32, packet_id: u64, bytes: &mut [u8]) {
    encrypt_packet(key, from_node, packet_id, bytes);
}
