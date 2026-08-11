use mesh_crypto::CryptoKey;
use mesh_radio::{
    modem_preset_params, RegionInfo, EU_868, EU_868_DEFAULT_FREQ_MHZ, MODEM_SHORT_SLOW, SYNC_WORD,
};

/// 16-byte default public-channel PSK (factory primary channel).
pub const DEFAULT_PSK: [u8; 16] = [
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
];

/// Number of configurable (flash) admin public-key slots.
pub const ADMIN_KEY_SLOTS: usize = 3;

/// Hardcoded LoRa settings for Phase 2 bring-up / persisted modem preset.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LoRaConfig {
    pub region: RegionInfo,
    pub modem_preset: u8,
    pub frequency_mhz: f32,
    pub bandwidth_khz: f32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub sync_word: u8,
    pub hop_limit: u8,
    pub tx_power_dbm: u8,
    pub use_preset: bool,
}

impl LoRaConfig {
    pub const fn eu868_short_slow() -> Self {
        Self {
            region: EU_868,
            modem_preset: MODEM_SHORT_SLOW,
            frequency_mhz: EU_868_DEFAULT_FREQ_MHZ,
            bandwidth_khz: 250.0,
            spreading_factor: 8,
            coding_rate: 5,
            sync_word: SYNC_WORD,
            hop_limit: 3,
            tx_power_dbm: 27,
            use_preset: true,
        }
    }

    /// Apply a modem preset (EU_868), deriving SF/BW/CR from `modem_preset_params`.
    pub fn apply_modem_preset(&mut self, modem_preset: u8) {
        let params = modem_preset_params(modem_preset, false);
        self.modem_preset = modem_preset;
        self.use_preset = true;
        self.region = EU_868;
        self.frequency_mhz = EU_868_DEFAULT_FREQ_MHZ;
        self.bandwidth_khz = params.bandwidth_khz;
        self.spreading_factor = params.spreading_factor;
        self.coding_rate = params.coding_rate;
        self.sync_word = SYNC_WORD;
    }
}

/// Runtime node configuration persisted to flash.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NodeConfig {
    pub node_num: u32,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub channel_key: CryptoKey,
    pub lora: LoRaConfig,
    /// Configurable admin public keys only (built-ins are firmware constants).
    pub admin_public_keys: [[u8; 32]; ADMIN_KEY_SLOTS],
}

impl NodeConfig {
    pub fn first_boot(node_num: u32, private_key: [u8; 32], public_key: [u8; 32]) -> Self {
        Self {
            node_num,
            private_key,
            public_key,
            channel_key: default_channel_key(),
            lora: LoRaConfig::eu868_short_slow(),
            admin_public_keys: [[0u8; 32]; ADMIN_KEY_SLOTS],
        }
    }

    /// Primary channel hash (empty stored name → preset display name + PSK).
    pub fn primary_channel_hash(&self) -> u8 {
        let len = self.channel_key.length.max(0) as usize;
        mesh_radio::primary_channel_hash(
            "",
            self.lora.modem_preset,
            self.lora.use_preset,
            &self.channel_key.bytes[..len],
        )
    }
}

/// Expand default PSK index byte `1` to the 16-byte default key.
pub fn default_channel_key() -> CryptoKey {
    CryptoKey::from_bytes(&DEFAULT_PSK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_radio::{modem_preset_params, MODEM_SHORT_SLOW, REGION_EU_868};

    #[test]
    fn primary_channel_hash_matches_short_slow() {
        let config = NodeConfig::first_boot(1, [0; 32], [0; 32]);
        assert_eq!(config.primary_channel_hash(), 0x77);
    }

    #[test]
    fn hardcoded_lora_golden_constants() {
        let lora = LoRaConfig::eu868_short_slow();
        assert_eq!(lora.region.code, REGION_EU_868);
        assert_eq!(lora.modem_preset, MODEM_SHORT_SLOW);
        let params = modem_preset_params(MODEM_SHORT_SLOW, false);
        assert_eq!(lora.bandwidth_khz, params.bandwidth_khz);
        assert_eq!(lora.spreading_factor, params.spreading_factor);
        assert!(lora.use_preset);
    }

    #[test]
    fn apply_modem_preset_short_fast_updates_sf() {
        use mesh_radio::MODEM_SHORT_FAST;
        let mut lora = LoRaConfig::eu868_short_slow();
        assert_eq!(lora.spreading_factor, 8);
        lora.apply_modem_preset(MODEM_SHORT_FAST);
        assert_eq!(lora.modem_preset, MODEM_SHORT_FAST);
        assert_eq!(lora.spreading_factor, 7);
        assert_eq!(lora.bandwidth_khz, 250.0);
        assert_eq!(lora.coding_rate, 5);
    }
}
