//! EU_868 mesh radio parameters (public wire-compatible preset values).

/// Region code for EU_868.
pub const REGION_EU_868: u8 = 3;

/// Modem preset LONG_FAST (Meshtastic EU_868 factory default).
pub const MODEM_LONG_FAST: u8 = 0;
/// Modem preset LONG_SLOW (deprecated in Meshtastic 2.7).
pub const MODEM_LONG_SLOW: u8 = 1;
/// Modem preset VERY_LONG_SLOW (deprecated).
pub const MODEM_VERY_LONG_SLOW: u8 = 2;
/// Modem preset MEDIUM_SLOW.
pub const MODEM_MEDIUM_SLOW: u8 = 3;
/// Modem preset MEDIUM_FAST.
pub const MODEM_MEDIUM_FAST: u8 = 4;
/// Modem preset SHORT_SLOW.
pub const MODEM_SHORT_SLOW: u8 = 5;
/// Modem preset SHORT_FAST.
pub const MODEM_SHORT_FAST: u8 = 6;
/// Modem preset LONG_MODERATE.
pub const MODEM_LONG_MODERATE: u8 = 7;
/// Modem preset SHORT_TURBO.
pub const MODEM_SHORT_TURBO: u8 = 8;
/// Modem preset LONG_TURBO.
pub const MODEM_LONG_TURBO: u8 = 9;

/// Regulatory and band metadata for EU_868.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RegionInfo {
    pub code: u8,
    pub name: &'static str,
    pub freq_start_mhz: f32,
    pub freq_end_mhz: f32,
    /// Duty cycle limit as a percentage (10 = 10%).
    pub duty_cycle_percent: u8,
    pub power_limit_dbm: u8,
}

pub const EU_868: RegionInfo = RegionInfo {
    code: REGION_EU_868,
    name: "EU_868",
    freq_start_mhz: 869.4,
    freq_end_mhz: 869.65,
    duty_cycle_percent: 10,
    power_limit_dbm: 27,
};

/// Default operating frequency for EU_868 SHORT_SLOW (plan + HT-RA62 bring-up).
pub const EU_868_DEFAULT_FREQ_MHZ: f32 = 869.525;

/// LoRa modem parameters for a preset id.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ModemParams {
    pub bandwidth_khz: f32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
}

pub fn modem_preset_params(preset: u8, wide_lora: bool) -> ModemParams {
    match preset {
        MODEM_SHORT_TURBO | MODEM_LONG_TURBO => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 500.0 },
            spreading_factor: 7,
            coding_rate: 5,
        },
        MODEM_SHORT_FAST => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 250.0 },
            spreading_factor: 7,
            coding_rate: 5,
        },
        MODEM_SHORT_SLOW => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 250.0 },
            spreading_factor: 8,
            coding_rate: 5,
        },
        MODEM_MEDIUM_FAST => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 250.0 },
            spreading_factor: 9,
            coding_rate: 5,
        },
        MODEM_MEDIUM_SLOW => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 250.0 },
            spreading_factor: 10,
            coding_rate: 5,
        },
        MODEM_LONG_MODERATE => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 250.0 },
            spreading_factor: 10,
            coding_rate: 5,
        },
        MODEM_LONG_FAST => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 250.0 },
            spreading_factor: 11,
            coding_rate: 5,
        },
        MODEM_LONG_SLOW | MODEM_VERY_LONG_SLOW => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 250.0 },
            spreading_factor: 12,
            coding_rate: 5,
        },
        _ => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 250.0 },
            spreading_factor: 11,
            coding_rate: 5,
        },
    }
}

/// Display name for a modem preset (e.g. `ShortSlow`, `LongFast`).
pub const fn modem_preset_channel_name(preset: u8) -> &'static str {
    match preset {
        MODEM_SHORT_TURBO => "ShortTurbo",
        MODEM_SHORT_SLOW => "ShortSlow",
        MODEM_SHORT_FAST => "ShortFast",
        MODEM_MEDIUM_SLOW => "MediumSlow",
        MODEM_MEDIUM_FAST => "MediumFast",
        MODEM_LONG_SLOW => "LongSlow",
        MODEM_LONG_FAST => "LongFast",
        MODEM_LONG_TURBO => "LongTurbo",
        MODEM_LONG_MODERATE => "LongMod",
        MODEM_VERY_LONG_SLOW => "VeryLongSlow",
        _ => "Invalid",
    }
}

/// Standard mesh LoRa sync word on the air (`0x2B` → SX126x register `0x1424`).
pub const SYNC_WORD: u8 = 0x2B;

/// SX126x control bits paired with the sync word (datasheet default).
pub const SX126X_SYNC_CONTROL_BITS: u8 = 0x44;

/// Semtech SX126x register value for a 1-byte sync word.
///
/// The air sync word `0x2B` maps to register `0x1424` — not raw `0x2B2B`.
pub const fn sync_word_sx126x(sync_word: u8) -> u16 {
    let msb = (sync_word & 0xF0) | ((SX126X_SYNC_CONTROL_BITS & 0xF0) >> 4);
    let lsb = ((sync_word & 0x0F) << 4) | (SX126X_SYNC_CONTROL_BITS & 0x0F);
    ((msb as u16) << 8) | lsb as u16
}

/// LoRa preamble length (SX126x default).
pub const PREAMBLE_LENGTH: u16 = 16;

/// On-air packet header size in bytes.
pub const PACKET_HEADER_LEN: usize = 16;

/// Hardcoded Phase 3 radio configuration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RadioConfig {
    pub region: RegionInfo,
    pub modem_preset: u8,
    pub frequency_mhz: f32,
    pub bandwidth_khz: f32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub sync_word: u8,
    pub preamble_length: u16,
    pub tx_power_dbm: i8,
    pub hop_limit: u8,
}

impl RadioConfig {
    /// Meshtastic EU_868 LONG_FAST (optional — not used in this deployment).
    pub const fn eu868_long_fast() -> Self {
        Self {
            region: EU_868,
            modem_preset: MODEM_LONG_FAST,
            frequency_mhz: EU_868_DEFAULT_FREQ_MHZ,
            bandwidth_khz: 250.0,
            spreading_factor: 11,
            coding_rate: 5,
            sync_word: SYNC_WORD,
            preamble_length: PREAMBLE_LENGTH,
            tx_power_dbm: 22,
            hop_limit: 3,
        }
    }

    pub const fn eu868_short_slow() -> Self {
        Self {
            region: EU_868,
            modem_preset: MODEM_SHORT_SLOW,
            frequency_mhz: EU_868_DEFAULT_FREQ_MHZ,
            bandwidth_khz: 250.0,
            spreading_factor: 8,
            coding_rate: 5,
            sync_word: SYNC_WORD,
            preamble_length: PREAMBLE_LENGTH,
            tx_power_dbm: 22,
            hop_limit: 3,
        }
    }

    pub const fn preset_name(self) -> &'static str {
        modem_preset_channel_name(self.modem_preset)
    }

    /// SCREAMING_SNAKE preset id for logs (not the channel hash name).
    pub const fn preset_log_name(self) -> &'static str {
        match self.modem_preset {
            MODEM_LONG_FAST => "LONG_FAST",
            MODEM_LONG_SLOW => "LONG_SLOW",
            MODEM_VERY_LONG_SLOW => "VERY_LONG_SLOW",
            MODEM_MEDIUM_SLOW => "MEDIUM_SLOW",
            MODEM_MEDIUM_FAST => "MEDIUM_FAST",
            MODEM_SHORT_SLOW => "SHORT_SLOW",
            MODEM_SHORT_FAST => "SHORT_FAST",
            MODEM_LONG_MODERATE => "LONG_MODERATE",
            MODEM_SHORT_TURBO => "SHORT_TURBO",
            MODEM_LONG_TURBO => "LONG_TURBO",
            _ => "CUSTOM",
        }
    }
}
