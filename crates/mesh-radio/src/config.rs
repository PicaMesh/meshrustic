//! EU_868 mesh radio parameters (public wire-compatible preset values).

/// Region code for EU_868.
pub const REGION_EU_868: u8 = 3;

/// Modem preset LONG_FAST.
pub const MODEM_LONG_FAST: u8 = 0;
/// Modem preset LONG_SLOW (deprecated in mesh wire enum 2.7).
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

/// Factory / first-boot modem preset for MeshRustic EU_868 deployments.
///
/// Change this single alias to retarget all `Router::new`, `NodeConfig::first_boot`,
/// and related defaults — keep named `MODEM_*` constants for explicit presets.
pub const MODEM_DEFAULT_PRESET: u8 = MODEM_LONG_FAST;

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

/// Modem parameters per preset, matching stock Meshtastic's own table field for field.
///
/// Five rows disagreed before: SHORT_TURBO's wide bandwidth, and LONG_TURBO, LONG_MODERATE and
/// LONG_SLOW in spreading factor, bandwidth or coding rate — LONG_MODERATE was a copy of
/// MEDIUM_SLOW's row, and LONG_TURBO was grouped with SHORT_TURBO, which is where its spreading
/// factor 7 came from. VERY_LONG_SLOW was grouped with LONG_SLOW while stock has no case for it at
/// all, so it takes the same default as any unknown value. Symbol time, airtime, the relay slot
/// spacing and the CAD slot time all derive from these, so a wrong row is wrong everywhere
/// downstream.
///
/// Changing them changes the radio configuration: two nodes on either side of this cannot hear
/// each other at the four affected presets. The fleet runs SHORT_SLOW, which was already correct.
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
        // VERY_LONG_SLOW included: stock has no case for it, so it lands on the LONG_FAST default.
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
    /// EU_868 LONG_FAST radio parameters (named preset; prefer [`Self::eu868_default`] for boot).
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

    /// EU_868 factory default ([`MODEM_DEFAULT_PRESET`]).
    pub const fn eu868_default() -> Self {
        match MODEM_DEFAULT_PRESET {
            MODEM_LONG_FAST => Self::eu868_long_fast(),
            MODEM_SHORT_SLOW => Self::eu868_short_slow(),
            // Named constructors cover current MODEM_DEFAULT_PRESET values only.
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

#[cfg(test)]
mod preset_table_tests {
    use super::*;

    /// Every preset, both bandwidth columns, against stock Meshtastic's own table.
    ///
    /// Written as literals taken from stock rather than from what this file computes, so the test
    /// fails if either side moves. Four rows were wrong before — LONG_MODERATE was a copy of
    /// MEDIUM_SLOW, LONG_TURBO was grouped with SHORT_TURBO and inherited its spreading factor,
    /// LONG_SLOW had the wrong bandwidth and coding rate, and SHORT_TURBO's wide bandwidth was
    /// 812.5 instead of 1625 — and VERY_LONG_SLOW was grouped with LONG_SLOW although stock has no
    /// case for it and lands it on the LONG_FAST default.
    #[test]
    fn modem_presets_match_stock() {
        // (preset, narrow bw, wide bw, sf, cr)
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
            // Absent from stock's switch, so it takes the same default as any unknown value.
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

    /// LONG_MODERATE must stop being a copy of MEDIUM_SLOW's row, which is how it was wrong.
    #[test]
    fn long_moderate_is_not_medium_slow() {
        let lm = modem_preset_params(MODEM_LONG_MODERATE, false);
        let ms = modem_preset_params(MODEM_MEDIUM_SLOW, false);
        assert_ne!(
            (lm.bandwidth_khz, lm.spreading_factor, lm.coding_rate),
            (ms.bandwidth_khz, ms.spreading_factor, ms.coding_rate)
        );
    }

    /// LONG_TURBO must stop inheriting SHORT_TURBO's spreading factor.
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
