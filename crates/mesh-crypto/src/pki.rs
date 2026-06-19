use x25519_dalek::{PublicKey, StaticSecret};

use crate::aes_ccm::{aes_ccm_ad, aes_ccm_ae};
use crate::hash::sha256_in_place;
use crate::key::CryptoKey;
use crate::nonce::init_nonce;

/// Mutable crypto state for channel and PKI paths.
pub struct CryptoEngine {
    pub key: CryptoKey,
    pub nonce: [u8; 16],
    pub private_key: [u8; 32],
    pub shared_key: [u8; 32],
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoEngine {
    pub const fn new() -> Self {
        Self {
            key: CryptoKey::none(),
            nonce: [0; 16],
            private_key: [0; 32],
            shared_key: [0; 32],
        }
    }

    pub fn set_key(&mut self, key: CryptoKey) {
        self.key = key;
    }

    pub fn set_dh_private_key(&mut self, private_key: &[u8; 32]) {
        self.private_key = *private_key;
    }

    pub fn hash(&mut self, bytes: &mut [u8]) {
        sha256_in_place(bytes, bytes.len());
    }

    /// X25519 DH with remote public key; `false` on weak/all-zero result.
    pub fn set_dh_public_key(&mut self, pub_key: &[u8; 32]) -> bool {
        if pub_key.iter().all(|&b| b == 0) {
            self.shared_key.fill(0);
            return false;
        }

        let secret = StaticSecret::from(self.private_key);
        let public = PublicKey::from(*pub_key);
        let shared = secret.diffie_hellman(&public);
        self.shared_key.copy_from_slice(shared.as_bytes());

        if self.shared_key.iter().all(|&b| b == 0) {
            return false;
        }
        true
    }

    pub fn decrypt_curve25519(
        &mut self,
        from_node: u32,
        remote_public: &[u8; 32],
        packet_num: u64,
        bytes: &[u8],
        bytes_out: &mut [u8],
    ) -> bool {
        if bytes.len() < 12 {
            return false;
        }

        let auth_start = bytes.len() - 12;
        let auth = &bytes[auth_start..];
        let mut extra_nonce = [0u8; 4];
        extra_nonce.copy_from_slice(&auth[8..12]);
        let extra_nonce = u32::from_le_bytes(extra_nonce);

        if !self.set_dh_public_key(remote_public) {
            return false;
        }
        let mut shared = self.shared_key;
        sha256_in_place(&mut shared, 32);
        self.shared_key = shared;

        init_nonce(&mut self.nonce, from_node, packet_num, extra_nonce);

        let crypt_len = bytes.len() - 12;
        if bytes_out.len() < crypt_len {
            return false;
        }

        aes_ccm_ad(
            &self.shared_key,
            &self.nonce,
            8,
            &bytes[..crypt_len],
            &[],
            &auth[..8],
            bytes_out,
        )
    }

    pub fn encrypt_curve25519(
        &mut self,
        remote_public: &[u8; 32],
        from_node: u32,
        packet_num: u64,
        extra_nonce: u32,
        plain: &[u8],
        bytes_out: &mut [u8],
    ) -> bool {
        if bytes_out.len() < plain.len() + 12 {
            return false;
        }

        if !self.set_dh_public_key(remote_public) {
            return false;
        }
        let mut shared = self.shared_key;
        sha256_in_place(&mut shared, 32);
        self.shared_key = shared;
        init_nonce(&mut self.nonce, from_node, packet_num, extra_nonce);

        let crypt_end = plain.len();
        let (crypt, tail) = bytes_out.split_at_mut(crypt_end);
        let (tag, extra) = tail.split_at_mut(8);
        if !aes_ccm_ae(&self.shared_key, &self.nonce, 8, plain, &[], crypt, tag) {
            return false;
        }

        extra.copy_from_slice(&extra_nonce.to_le_bytes());
        true
    }
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

    fn hex_to_bytes_vec(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    #[test]
    fn dh25519_wycheproof_vectors() {
        let mut crypto = CryptoEngine::new();

        let public_key =
            hex_to_bytes::<32>("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829");
        let private_key =
            hex_to_bytes::<32>("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475");
        let expected_shared =
            hex_to_bytes::<32>("436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320");
        crypto.set_dh_private_key(&private_key);
        assert!(crypto.set_dh_public_key(&public_key));
        assert_eq!(crypto.shared_key, expected_shared);

        let public_key =
            hex_to_bytes::<32>("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let private_key =
            hex_to_bytes::<32>("18630f93598637c35da623a74559cf944374a559114c7937811041fc8605564a");
        crypto.set_dh_private_key(&private_key);
        assert!(!crypto.set_dh_public_key(&public_key));
    }

    #[test]
    fn pkc_decrypt_golden_vector() {
        let mut crypto = CryptoEngine::new();
        let public_key =
            hex_to_bytes::<32>("db18fc50eea47f00251cb784819a3cf5fc361882597f589f0d7ff820e8064457");
        let private_key =
            hex_to_bytes::<32>("a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277");
        let mut radio_bytes = [0u8; 128];
        let loaded = hex_to_bytes_vec(
            "8c646d7a2909000062d6b2136b00000040df24abfcc30a17a3d9046726099e796a1c036a792b",
        );
        radio_bytes[..loaded.len()].copy_from_slice(&loaded);

        crypto.set_dh_private_key(&private_key);
        let mut decrypted = [0u8; 32];
        assert!(crypto.decrypt_curve25519(
            0x0929,
            &public_key,
            0x13b2d662,
            &radio_bytes[16..38],
            &mut decrypted,
        ));
        assert_eq!(
            &crypto.shared_key[..8],
            hex_to_bytes::<8>("777b1545c9d6f9a2")
        );
        assert_eq!(
            &crypto.nonce[..13],
            hex::decode("62d6b213036a792b2909000000").unwrap()
        );
        assert_eq!(
            &decrypted[..10],
            hex::decode("08011204746573744800").unwrap()
        );
    }
}
