//! Flash-backed node configuration (keys, channel PSK, LoRa preset, admin keys).

#![no_std]

mod admin_keys;
mod config;
mod keygen;
mod layout;
mod store_trait;

pub use admin_keys::{is_admin_authorized, BUILTIN_ADMIN_PUBLIC_KEYS, EMPTY_ADMIN_KEY};
pub use config::{
    default_channel_key, LoRaConfig, NodeConfig, ADMIN_KEY_SLOTS, DEFAULT_PSK,
};
pub use keygen::{generate_keypair, public_from_private};
pub use layout::{
    decode, encode, StoreError, STORE_RECORD_LEN, STORE_RESERVED_END, STORE_RESERVED_START,
    STORE_VERSION,
};
pub use store_trait::{ConfigStore, RamConfigStore};
