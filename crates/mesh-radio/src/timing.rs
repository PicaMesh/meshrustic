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
///
/// Truncated, not rounded up, because stock computes the same expression in floating point and
/// assigns it to an integer. The formula never lands on a whole millisecond at any preset, so
/// rounding up made this exactly 1 ms longer than stock everywhere — 11 % at SHORT_TURBO down to
/// 1.1 % at LONG_SLOW. Every coordinated delay is a multiple of this value, so the two
/// implementations placed their relay slots on different grids.
///
/// Note the bandwidth truncation on the line below: the wide-band presets are fractional
/// (406.25, 812.5, 1625) and MR has no wide-band path, so those values would truncate here as
/// well. That is dead today and stated rather than fixed.
pub fn slot_time_ms(config: &RadioConfig) -> u32 {
    let sf = config.spreading_factor as u32;
    let bw_khz = config.bandwidth_khz as u32;
    if bw_khz == 0 {
        return 1;
    }
    // symbolTime (ms) = 2^sf / bw_khz
    let symbol_time_x1000 = ((1u32 << sf).saturating_mul(1000)) / bw_khz;
    let cad_ms_x1000 = (NUM_SYM_CAD_NUMER * symbol_time_x1000) / NUM_SYM_CAD_DENOM;
    (cad_ms_x1000 + PROP_TURNAROUND_MAC_MS_X1000) / 1000
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
    use crate::config::{MODEM_SHORT_FAST, MODEM_SHORT_SLOW};

    #[test]
    fn short_slow_slot_time_derived_from_sf_bw() {
        let cfg = RadioConfig::eu868_short_slow();
        let slot = slot_time_ms(&cfg);
        assert!(slot >= 8 && slot <= 15);
    }

    /// The slot time is the grid every coordinated delay is a multiple of, so it must equal
    /// stock's to the millisecond at every preset.
    ///
    /// Values computed from stock's own expression — `max(2.25, NUM_SYM_CAD + 0.5) * symbolTime +
    /// 7.6`, truncated into an integer. They are literals here rather than a re-derivation so the
    /// test fails if either side's formula moves. Rounding up instead put MR one millisecond
    /// longer than stock at every one of them.
    #[test]
    fn slot_time_matches_stock_at_every_preset() {
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
            // Takes the LONG_FAST default, so the same slot time.
            (MODEM_VERY_LONG_SLOW, 28),
        ];
        for &(preset, slot) in expected {
            let cfg = eu868_config_for_preset(preset);
            assert_eq!(
                slot_time_ms(&cfg),
                slot,
                "slot time for preset {preset} must match stock"
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
        // Faster airtime at SF7 — soft-reinit must pick up the new SF.
        assert!(
            crate::packet_time::packet_time_ms(&fast, 32, false)
                < crate::packet_time::packet_time_ms(&slow, 32, false)
        );
        assert_eq!(contention_window_ms(MODEM_SHORT_FAST), 1500);
        assert_eq!(contention_window_ms(MODEM_SHORT_SLOW), 2000);
    }
}
