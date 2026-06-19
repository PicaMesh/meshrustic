//! Mesh channel and PKI crypto (original PicaMesh implementation).

#![no_std]

mod aes;
mod channel;
mod channel_hash;
mod hash;
mod key;
mod nonce;

#[cfg(feature = "pki")]
mod aes_ccm;
#[cfg(feature = "pki")]
mod pki;

pub use channel::{decrypt_packet, encrypt_packet};
pub use channel_hash::{
    channel_hash, default_primary_channel_hash, short_slow_channel_hash, xor_hash,
    DEFAULT_PSK, SHORT_SLOW_CHANNEL_NAME,
};
pub use hash::sha256_in_place;
pub use key::CryptoKey;
pub use nonce::init_nonce;

pub use aes::{aes_ctr_crypt, aes_ecb_encrypt_block};

#[cfg(feature = "pki")]
pub use pki::CryptoEngine;

/// Maximum payload size for one AES-CTR channel encrypt/decrypt call.
pub const MAX_BLOCKSIZE: usize = 256;
