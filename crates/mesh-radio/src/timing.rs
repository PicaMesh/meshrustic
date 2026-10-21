use crate::config::{
    modem_preset_params, RadioConfig, DEFAULT_HOP_LIMIT, EU_868, EU_868_DEFAULT_FREQ_MHZ,
    MODEM_LONG_FAST, MODEM_LONG_MODERATE, MODEM_LONG_SLOW, MODEM_SHORT_FAST, MODEM_SHORT_TURBO,
    MODEM_VERY_LONG_SLOW, PREAMBLE_LENGTH, SYNC_WORD,
};

const NUM_SYM_CAD_NUMER: u32 = 5;
const NUM_SYM_CAD_DENOM: u32 = 2;
const PROP_TURNAROUND_MAC_MS_X1000: u32 = 7600;

/// The longest slot time a legal preset produces. A malformed configuration
/// must not be able to push the coordinated ladder out by hours.
pub const MAX_SLOT_TIME_MS: u32 = 1_000;

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
        hop_limit: DEFAULT_HOP_LIMIT,
    }
}

/// Integer truncation keeps coordinated relay slots on the protocol timing grid.
pub fn slot_time_ms(config: &RadioConfig) -> u32 {
    if !(5..=12).contains(&config.spreading_factor)
        || !config.bandwidth_khz.is_finite()
        || config.bandwidth_khz < 1.0
    {
        return MAX_SLOT_TIME_MS;
    }
    let sf = config.spreading_factor as u32;
    let bw_hz = (config.bandwidth_khz * 1000.0) as u32;
    let symbol_time_x1000 = ((1u32 << sf).saturating_mul(1_000_000)) / bw_hz;
    let cad_ms_x1000 = (NUM_SYM_CAD_NUMER * symbol_time_x1000) / NUM_SYM_CAD_DENOM;
    (cad_ms_x1000 + PROP_TURNAROUND_MAC_MS_X1000) / 1000
}
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
    use crate::config::{MODEM_SHORT_FAST, MODEM_SHORT_SLOW};

    #[test]
    fn short_slow_slot_time_derived_from_sf_bw() {
        let cfg = RadioConfig::eu868_short_slow();
        let slot = slot_time_ms(&cfg);
        assert!((8..=15).contains(&slot));
    }

    #[test]
    fn slot_time_matches_the_public_table_at_every_preset() {
        use crate::config::{
            MODEM_LONG_FAST, MODEM_LONG_MODERATE, MODEM_LONG_SLOW, MODEM_LONG_TURBO,
            MODEM_MEDIUM_FAST, MODEM_MEDIUM_SLOW, MODEM_SHORT_TURBO, MODEM_VERY_LONG_SLOW,
        };
        let expected: &[(u8, u32)] = &[
            (MODEM_SHORT_TURBO, 8),
            (MODEM_SHORT_FAST, 8),
            (MODEM_SHORT_SLOW, 10),
            (MODEM_MEDIUM_FAST, 12),
            (MODEM_MEDIUM_SLOW, 17),
            (MODEM_LONG_TURBO, 17),
            (MODEM_LONG_MODERATE, 48),
            (MODEM_LONG_FAST, 28),
            (MODEM_LONG_SLOW, 89),
            // VeryLongSlow has its own preset row (62.5 kHz, SF12), so it gets the
            // long symbol time instead of the LONG_FAST default.
            (MODEM_VERY_LONG_SLOW, 171),
        ];
        for &(preset, slot) in expected {
            let cfg = eu868_config_for_preset(preset);
            assert_eq!(
                slot_time_ms(&cfg),
                slot,
                "slot time for preset {preset} must match the public table"
            );
        }
    }

    #[test]
    fn short_slow_contention_window_is_default_two_seconds() {
        assert_eq!(contention_window_ms(MODEM_SHORT_SLOW), 2000);
    }

    #[test]
    fn short_slow_to_short_fast_changes_spreading_factor() {
        let slow = eu868_config_for_preset(MODEM_SHORT_SLOW);
        let fast = eu868_config_for_preset(MODEM_SHORT_FAST);
        assert_eq!(slow.modem_preset, MODEM_SHORT_SLOW);
        assert_eq!(fast.modem_preset, MODEM_SHORT_FAST);
        assert_eq!(slow.spreading_factor, 8);
        assert_eq!(fast.spreading_factor, 7);
        assert_eq!(slow.bandwidth_khz, 250.0);
        assert_eq!(fast.bandwidth_khz, 250.0);
        assert_eq!(slow.coding_rate, 5);
        assert_eq!(fast.coding_rate, 5);
        assert_eq!(slow.frequency_mhz, fast.frequency_mhz);
        assert_eq!(slow.sync_word, fast.sync_word);
        assert!(
            crate::packet_time::packet_time_ms(&fast, 32, false)
                < crate::packet_time::packet_time_ms(&slow, 32, false)
        );
        assert_eq!(contention_window_ms(MODEM_SHORT_FAST), 1500);
        assert_eq!(contention_window_ms(MODEM_SHORT_SLOW), 2000);
    }
}
