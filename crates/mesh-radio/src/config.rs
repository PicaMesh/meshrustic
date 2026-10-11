pub const REGION_EU_868: u8 = 3;

pub const MODEM_LONG_FAST: u8 = 0;
pub const MODEM_LONG_SLOW: u8 = 1;
pub const MODEM_VERY_LONG_SLOW: u8 = 2;
pub const MODEM_MEDIUM_SLOW: u8 = 3;
pub const MODEM_MEDIUM_FAST: u8 = 4;
pub const MODEM_SHORT_SLOW: u8 = 5;
pub const MODEM_SHORT_FAST: u8 = 6;
pub const MODEM_LONG_MODERATE: u8 = 7;
pub const MODEM_SHORT_TURBO: u8 = 8;
pub const MODEM_LONG_TURBO: u8 = 9;

pub const MODEM_DEFAULT_PRESET: u8 = MODEM_LONG_FAST;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RegionInfo {
    pub code: u8,
    pub name: &'static str,
    pub freq_start_mhz: f32,
    pub freq_end_mhz: f32,
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

pub const EU_868_DEFAULT_FREQ_MHZ: f32 = 869.525;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ModemParams {
    pub bandwidth_khz: f32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
}

/// Preset parameters determine RF interoperability as well as every derived scheduling delay.
pub fn modem_preset_params(preset: u8, wide_lora: bool) -> ModemParams {
    match preset {
        MODEM_SHORT_TURBO => ModemParams {
            bandwidth_khz: if wide_lora { 1625.0 } else { 500.0 },
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
        MODEM_LONG_TURBO => ModemParams {
            bandwidth_khz: if wide_lora { 1625.0 } else { 500.0 },
            spreading_factor: 11,
            coding_rate: 8,
        },
        MODEM_LONG_MODERATE => ModemParams {
            bandwidth_khz: if wide_lora { 406.25 } else { 125.0 },
            spreading_factor: 11,
            coding_rate: 8,
        },
        MODEM_LONG_FAST => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 250.0 },
            spreading_factor: 11,
            coding_rate: 5,
        },
        MODEM_LONG_SLOW => ModemParams {
            bandwidth_khz: if wide_lora { 406.25 } else { 125.0 },
            spreading_factor: 12,
            coding_rate: 8,
        },
        _ => ModemParams {
            bandwidth_khz: if wide_lora { 812.5 } else { 250.0 },
            spreading_factor: 11,
            coding_rate: 5,
        },
    }
}

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

pub const SYNC_WORD: u8 = 0x2B;

pub const SX126X_SYNC_CONTROL_BITS: u8 = 0x44;

pub const fn sync_word_sx126x(sync_word: u8) -> u16 {
    let msb = (sync_word & 0xF0) | ((SX126X_SYNC_CONTROL_BITS & 0xF0) >> 4);
    let lsb = ((sync_word & 0x0F) << 4) | (SX126X_SYNC_CONTROL_BITS & 0x0F);
    ((msb as u16) << 8) | lsb as u16
}

pub const PREAMBLE_LENGTH: u16 = 16;

pub const PACKET_HEADER_LEN: usize = 16;

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

    pub const fn eu868_default() -> Self {
        match MODEM_DEFAULT_PRESET {
            MODEM_LONG_FAST => Self::eu868_long_fast(),
            MODEM_SHORT_SLOW => Self::eu868_short_slow(),
            _ => Self::eu868_long_fast(),
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

#[cfg(test)]
mod preset_table_tests {
    use super::*;

    #[test]
    fn modem_presets_match_stock() {
        let expected: &[(u8, f32, f32, u8, u8)] = &[
            (MODEM_SHORT_TURBO, 500.0, 1625.0, 7, 5),
            (MODEM_SHORT_FAST, 250.0, 812.5, 7, 5),
            (MODEM_SHORT_SLOW, 250.0, 812.5, 8, 5),
            (MODEM_MEDIUM_FAST, 250.0, 812.5, 9, 5),
            (MODEM_MEDIUM_SLOW, 250.0, 812.5, 10, 5),
            (MODEM_LONG_TURBO, 500.0, 1625.0, 11, 8),
            (MODEM_LONG_MODERATE, 125.0, 406.25, 11, 8),
            (MODEM_LONG_FAST, 250.0, 812.5, 11, 5),
            (MODEM_LONG_SLOW, 125.0, 406.25, 12, 8),
            (MODEM_VERY_LONG_SLOW, 250.0, 812.5, 11, 5),
        ];
        for &(preset, narrow, wide, sf, cr) in expected {
            let n = modem_preset_params(preset, false);
            assert_eq!(
                n.bandwidth_khz, narrow,
                "narrow bandwidth for preset {preset}"
            );
            assert_eq!(
                n.spreading_factor, sf,
                "spreading factor for preset {preset}"
            );
            assert_eq!(n.coding_rate, cr, "coding rate for preset {preset}");
            let w = modem_preset_params(preset, true);
            assert_eq!(w.bandwidth_khz, wide, "wide bandwidth for preset {preset}");
            assert_eq!(
                w.spreading_factor, sf,
                "wide spreading factor for preset {preset}"
            );
            assert_eq!(w.coding_rate, cr, "wide coding rate for preset {preset}");
        }
    }

    #[test]
    fn long_moderate_is_not_medium_slow() {
        let lm = modem_preset_params(MODEM_LONG_MODERATE, false);
        let ms = modem_preset_params(MODEM_MEDIUM_SLOW, false);
        assert_ne!(
            (lm.bandwidth_khz, lm.spreading_factor, lm.coding_rate),
            (ms.bandwidth_khz, ms.spreading_factor, ms.coding_rate)
        );
    }

    #[test]
    fn long_turbo_is_not_short_turbo() {
        let lt = modem_preset_params(MODEM_LONG_TURBO, false);
        let st = modem_preset_params(MODEM_SHORT_TURBO, false);
        assert_eq!(
            lt.bandwidth_khz, st.bandwidth_khz,
            "both are 500 kHz narrow"
        );
        assert_ne!(lt.spreading_factor, st.spreading_factor);
        assert_ne!(lt.coding_rate, st.coding_rate);
    }
}
