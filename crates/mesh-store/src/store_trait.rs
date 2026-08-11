//! ConfigStore trait — RAM for tests, NVMC for firmware.

use crate::config::NodeConfig;
use crate::layout::{decode, encode, StoreError, STORE_RECORD_LEN};

/// Persistent node configuration backend.
pub trait ConfigStore {
    /// Load config; return first-boot defaults when the record is missing/invalid.
    fn load(&mut self) -> NodeConfig;
    fn save(&mut self, config: &NodeConfig) -> Result<(), StoreError>;
}

/// In-memory store for host tests.
pub struct RamConfigStore {
    buf: [u8; STORE_RECORD_LEN],
    valid: bool,
    defaults: NodeConfig,
}

impl RamConfigStore {
    pub fn new(defaults: NodeConfig) -> Self {
        Self {
            buf: [0; STORE_RECORD_LEN],
            valid: false,
            defaults,
        }
    }

    /// Seed with an already-encoded record (e.g. corrupt CRC tests).
    pub fn from_bytes(defaults: NodeConfig, bytes: &[u8]) -> Self {
        let mut store = Self::new(defaults);
        let len = bytes.len().min(STORE_RECORD_LEN);
        store.buf[..len].copy_from_slice(&bytes[..len]);
        store.valid = true;
        store
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

impl ConfigStore for RamConfigStore {
    fn load(&mut self) -> NodeConfig {
        if !self.valid {
            return self.defaults;
        }
        match decode(&self.buf) {
            Ok(cfg) => cfg,
            Err(_) => self.defaults,
        }
    }

    fn save(&mut self, config: &NodeConfig) -> Result<(), StoreError> {
        encode(config, &mut self.buf)?;
        self.valid = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use mesh_radio::MODEM_SHORT_FAST;

    #[test]
    fn ram_store_persist_and_reload() {
        let defaults = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        let mut store = RamConfigStore::new(defaults);
        assert_eq!(store.load().lora.modem_preset, defaults.lora.modem_preset);

        let mut cfg = defaults;
        cfg.lora.apply_modem_preset(MODEM_SHORT_FAST);
        cfg.admin_public_keys[0] = [0xAB; 32];
        store.save(&cfg).unwrap();

        let loaded = store.load();
        assert_eq!(loaded.lora.modem_preset, MODEM_SHORT_FAST);
        assert_eq!(loaded.admin_public_keys[0], [0xAB; 32]);
        assert_eq!(
            loaded.primary_channel_hash(),
            cfg.primary_channel_hash()
        );
    }

    #[test]
    fn corrupt_magic_yields_defaults() {
        let defaults = NodeConfig::first_boot(7, [3; 32], [4; 32]);
        let mut bad = [0u8; STORE_RECORD_LEN];
        bad[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let mut store = RamConfigStore::from_bytes(defaults, &bad);
        let loaded = store.load();
        assert_eq!(loaded.node_num, 7);
        assert_eq!(loaded.admin_public_keys, [[0u8; 32]; 3]);
    }
}
