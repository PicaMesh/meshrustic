//! Flash-backed node configuration (keys, channel PSK, hardcoded LoRa defaults).

#![no_std]

mod config;
mod keygen;
mod layout;

pub use config::{default_channel_key, LoRaConfig, NodeConfig, DEFAULT_PSK};
pub use keygen::{generate_keypair, public_from_private};
pub use layout::{decode, encode, StoreError, STORE_RECORD_LEN};
