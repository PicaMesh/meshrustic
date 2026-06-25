//! LoRa slot time and SR contention-window constants from modem preset.

use crate::config::{
    modem_preset_params, RadioConfig, EU_868, EU_868_DEFAULT_FREQ_MHZ, MODEM_LONG_FAST,
    MODEM_LONG_MODERATE, MODEM_LONG_SLOW, MODEM_SHORT_FAST, MODEM_SHORT_TURBO,
    MODEM_VERY_LONG_SLOW, PREAMBLE_LENGTH, SYNC_WORD,
};

/// CAD symbol count (SX126x, RadioLib 6.3+ default).
const NUM_SYM_CAD_NUMER: u32 = 5;
const NUM_SYM_CAD_DENOM: u32 = 2;
/// Propagation + turnaround + MAC processing (ms × 1000 for fixed-point math).
const PROP_TURNAROUND_MAC_MS_X1000: u32 = 7600;

/// Build an EU_868 `RadioConfig` for a modem preset id (narrow band).
pub fn eu868_config_for_preset(modem_preset: u8) -> RadioConfig {
    let params = modem_preset_params(modem_preset, false);
    RadioConfig {
        region: EU_868,
        modem_preset,
        frequency_mhz: EU_868_DEFAULT_FREQ_MHZ,
        bandwidth_khz: params.bandwidth_khz,
        spreading_factor: params.spreading_factor,
        coding_rate: params.coding_rate,
        sync_word: SYNC_WORD,
        preamble_length: PREAMBLE_LENGTH,
        tx_power_dbm: 22,
        hop_limit: 3,
    }
}

/// LoRa CAD slot time in milliseconds (`computeSlotTimeMsec` formula).
pub fn slot_time_ms(config: &RadioConfig) -> u32 {
    let sf = config.spreading_factor as u32;
    let bw_khz = config.bandwidth_khz as u32;
    if bw_khz == 0 {
        return 1;
    }
    // symbolTime (ms) = 2^sf / bw_khz
    let symbol_time_x1000 = ((1u32 << sf).saturating_mul(1000)) / bw_khz;
    let cad_ms_x1000 = (NUM_SYM_CAD_NUMER * symbol_time_x1000) / NUM_SYM_CAD_DENOM;
    (cad_ms_x1000 + PROP_TURNAROUND_MAC_MS_X1000).div_ceil(1000)
}

/// SR transmission-memory / edge-aging window from modem preset.
pub fn contention_window_ms(modem_preset: u8) -> u32 {
    match modem_preset {
        MODEM_LONG_FAST | MODEM_LONG_MODERATE => 3000,
        MODEM_VERY_LONG_SLOW | MODEM_LONG_SLOW => 5000,
        MODEM_SHORT_TURBO | MODEM_SHORT_FAST => 1500,
        _ => 2000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MODEM_SHORT_SLOW;

    #[test]
    fn short_slow_slot_time_derived_from_sf_bw() {
        let cfg = RadioConfig::eu868_short_slow();
        let slot = slot_time_ms(&cfg);
        assert!(slot >= 8 && slot <= 15);
    }

    #[test]
    fn short_slow_contention_window_is_default_two_seconds() {
        assert_eq!(contention_window_ms(MODEM_SHORT_SLOW), 2000);
    }
}
