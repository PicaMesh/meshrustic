use mesh_radio::modem_preset_params;

pub type EtxFixed = u16;

pub const ETX_MIN_FIXED: EtxFixed = 100;
pub const ETX_MAX_FIXED: EtxFixed = 10_000;

const SF7_SNR_THRESHOLD_DB: f32 = -7.5;
const SNR_THRESHOLD_STEP_DB_PER_SF: f32 = -2.5;

fn spreading_factor_snr_threshold_db(spreading_factor: u8) -> f32 {
    SF7_SNR_THRESHOLD_DB + SNR_THRESHOLD_STEP_DB_PER_SF * (spreading_factor as f32 - 7.0)
}

fn preset_snr_threshold_db(modem_preset: u8) -> f32 {
    spreading_factor_snr_threshold_db(modem_preset_params(modem_preset, false).spreading_factor)
}

const MARGIN_BREAK_DB: [f32; 7] = [-10.0, -5.0, -2.0, 0.0, 6.0, 12.0, 17.0];
// Be conservative near/below the decoder threshold: zero margin must exceed the strong-hop ceiling.
const MARGIN_PROB: [f32; 7] = [0.025, 0.035, 0.065, 0.10, 0.40, 0.62, 0.95];
const MARGIN_LAST: usize = MARGIN_BREAK_DB.len() - 1;

const RSSI_FACTOR_BREAK_DBM: [i32; 2] = [-120, -60];
const RSSI_FACTOR: [f32; 2] = [0.90, 1.00];

/// NaN comparisons can otherwise fall through to the best ETX price and reward corrupt signal readings.
const NON_FINITE_SNR_FALLBACK_DB: f32 = -100.0;

pub const SATURATED_RX_RSSI_DBM: i16 = -30;

pub fn normalize_rx_signal(rssi: i16, snr: i8) -> Option<(i16, i8)> {
    if rssi == 0 && snr == 0 {
        None
    } else if rssi == 0 {
        Some((SATURATED_RX_RSSI_DBM, snr))
    } else {
        Some((rssi, snr))
    }
}

fn margin_delivery_probability(margin_db: f32) -> f32 {
    if margin_db <= MARGIN_BREAK_DB[0] {
        MARGIN_PROB[0]
    } else if margin_db >= MARGIN_BREAK_DB[MARGIN_LAST] {
        MARGIN_PROB[MARGIN_LAST]
    } else {
        let seg = MARGIN_BREAK_DB
            .iter()
            .skip(1)
            .position(|&brk| margin_db < brk)
            .unwrap_or(0);
        let t =
            (margin_db - MARGIN_BREAK_DB[seg]) / (MARGIN_BREAK_DB[seg + 1] - MARGIN_BREAK_DB[seg]);
        MARGIN_PROB[seg] + t * (MARGIN_PROB[seg + 1] - MARGIN_PROB[seg])
    }
}

fn rssi_quality_factor(rssi: i32) -> f32 {
    if rssi <= RSSI_FACTOR_BREAK_DBM[0] {
        RSSI_FACTOR[0]
    } else if rssi >= RSSI_FACTOR_BREAK_DBM[1] {
        RSSI_FACTOR[1]
    } else {
        let t = (rssi - RSSI_FACTOR_BREAK_DBM[0]) as f32
            / (RSSI_FACTOR_BREAK_DBM[1] - RSSI_FACTOR_BREAK_DBM[0]) as f32;
        RSSI_FACTOR[0] + t * (RSSI_FACTOR[1] - RSSI_FACTOR[0])
    }
}

pub fn calculate_etx(rssi: i32, snr: f32, modem_preset: u8) -> f32 {
    let snr = if snr.is_finite() {
        snr
    } else {
        NON_FINITE_SNR_FALLBACK_DB
    };
    let margin = snr - preset_snr_threshold_db(modem_preset);
    let prob = margin_delivery_probability(margin) * rssi_quality_factor(rssi);
    if prob > 0.0 {
        1.0 / prob
    } else {
        100.0
    }
}

pub fn etx_to_fixed(etx: f32) -> EtxFixed {
    if !etx.is_finite() {
        return u16::MAX;
    }
    let scaled = (etx * 100.0).clamp(1.0, 65535.0) as u16;
    scaled.max(ETX_MIN_FIXED)
}

pub fn fixed_to_etx(fixed: EtxFixed) -> f32 {
    fixed as f32 / 100.0
}

/// ETX cannot uniquely recover RSSI and margin, so this diagnostic reconstruction assumes the strongest
/// RSSI quality factor.
pub fn etx_to_signal(etx: f32, modem_preset: u8) -> (i8, i8) {
    let target_prob = (1.0 / etx.max(1.0)).clamp(MARGIN_PROB[0], MARGIN_PROB[MARGIN_LAST]);

    let margin = if target_prob <= MARGIN_PROB[0] {
        MARGIN_BREAK_DB[0]
    } else if target_prob >= MARGIN_PROB[MARGIN_LAST] {
        MARGIN_BREAK_DB[MARGIN_LAST]
    } else {
        let seg = MARGIN_PROB
            .iter()
            .skip(1)
            .position(|&p| target_prob < p)
            .unwrap_or(0);
        let t = (target_prob - MARGIN_PROB[seg]) / (MARGIN_PROB[seg + 1] - MARGIN_PROB[seg]);
        MARGIN_BREAK_DB[seg] + t * (MARGIN_BREAK_DB[seg + 1] - MARGIN_BREAK_DB[seg])
    };

    let snr = preset_snr_threshold_db(modem_preset) + margin;
    (
        RSSI_FACTOR_BREAK_DBM[1] as i8,
        snr.clamp(-128.0, 127.0) as i8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_radio::{MODEM_LONG_SLOW, MODEM_MEDIUM_SLOW, MODEM_SHORT_FAST, MODEM_SHORT_SLOW};

    #[test]
    fn strong_signal_low_etx() {
        let etx = calculate_etx(-60, 10.0, MODEM_SHORT_SLOW);
        assert!(etx < 2.0);
    }

    #[test]
    fn normalize_rx_signal_remaps_clipped_rssi() {
        assert_eq!(normalize_rx_signal(0, 0), None);
        assert_eq!(
            normalize_rx_signal(0, 14),
            Some((SATURATED_RX_RSSI_DBM, 14))
        );
        assert_eq!(normalize_rx_signal(-70, 8), Some((-70, 8)));
        assert_eq!(normalize_rx_signal(-70, 0), Some((-70, 0)));
    }

    #[test]
    fn round_trip_signal_is_reasonable() {
        let etx = calculate_etx(-75, 8.0, MODEM_SHORT_SLOW);
        let (rssi, snr) = etx_to_signal(etx, MODEM_SHORT_SLOW);
        let recomputed = calculate_etx(rssi as i32, snr as f32, MODEM_SHORT_SLOW);
        let rel_diff = (recomputed - etx).abs() / etx;
        assert!(
            rel_diff < 0.10,
            "round trip drifted more than 10%: {etx} -> ({rssi}, {snr}) -> {recomputed}"
        );
        assert_eq!(rssi, RSSI_FACTOR_BREAK_DBM[1] as i8);
    }

    #[test]
    fn round_trip_worst_case_is_bounded() {
        for preset in [MODEM_SHORT_SLOW, MODEM_MEDIUM_SLOW, MODEM_LONG_SLOW] {
            let mut worst: f32 = 0.0;
            let mut hundredths_of_etx = 100u32;
            while hundredths_of_etx <= 5000 {
                let etx = hundredths_of_etx as f32 / 100.0;
                let (rssi, snr) = etx_to_signal(etx, preset);
                let recomputed = calculate_etx(rssi as i32, snr as f32, preset);
                let rel_diff = (recomputed - etx).abs() / etx;
                if rel_diff > worst {
                    worst = rel_diff;
                }
                hundredths_of_etx += 1;
            }
            assert!(
                worst < 0.45,
                "round-trip worst case exceeded the documented ~43.7% bound at preset {preset}: {worst}"
            );
        }
    }

    #[test]
    fn below_threshold_link_prices_above_the_coverage_ceiling_at_short_slow() {
        let etx = calculate_etx(-104, -12.0, MODEM_SHORT_SLOW);
        assert!(etx > 7.0, "expected an uncoverable link, got ETX {etx}");
    }

    #[test]
    fn above_threshold_link_clears_the_coverage_ceiling_at_short_slow() {
        let etx = calculate_etx(-106, -5.0, MODEM_SHORT_SLOW);
        assert!(etx <= 7.0, "expected a coverable link, got ETX {etx}");
    }

    #[test]
    fn both_links_are_usable_at_long_slow() {
        let below_short_slow = calculate_etx(-104, -12.0, MODEM_LONG_SLOW);
        let above_short_slow = calculate_etx(-106, -5.0, MODEM_LONG_SLOW);
        assert!(below_short_slow <= 7.0, "got ETX {below_short_slow}");
        assert!(above_short_slow <= 7.0, "got ETX {above_short_slow}");
    }

    #[test]
    fn margin_saturates_at_the_top_regardless_of_preset() {
        let at_cap = calculate_etx(-60, -7.5 + 17.0, MODEM_SHORT_FAST);
        let past_cap = calculate_etx(-60, 20.0, MODEM_SHORT_FAST);
        assert_eq!(at_cap, past_cap);

        let at_cap_slow = calculate_etx(-60, -20.0 + 17.0, MODEM_LONG_SLOW);
        let past_cap_slow = calculate_etx(-60, 20.0, MODEM_LONG_SLOW);
        assert_eq!(at_cap_slow, past_cap_slow);
    }

    #[test]
    fn deep_below_threshold_hits_the_curves_floor() {
        let strong_rssi = calculate_etx(-60, -100.0, MODEM_SHORT_SLOW);
        let weak_rssi = calculate_etx(-130, -100.0, MODEM_SHORT_SLOW);
        assert!((strong_rssi - 40.0).abs() < 0.05, "got {strong_rssi}");
        assert!(weak_rssi > strong_rssi);
        assert!(weak_rssi < 45.0);
    }

    #[test]
    fn non_finite_snr_prices_as_hopeless_not_perfect() {
        let etx = calculate_etx(-60, f32::NAN, MODEM_SHORT_SLOW);
        assert!(
            etx > 7.0,
            "a corrupted SNR must never price as a good link, got ETX {etx}"
        );
        let etx_inf = calculate_etx(-60, f32::INFINITY, MODEM_SHORT_SLOW);
        assert!(etx_inf > 7.0, "got ETX {etx_inf}");
    }

    #[test]
    fn curve_is_monotonic_in_rssi_and_snr() {
        for preset in [MODEM_SHORT_FAST, MODEM_SHORT_SLOW, MODEM_LONG_SLOW] {
            let mut previous = f32::INFINITY;
            let mut rssi = -140;
            while rssi <= -20 {
                let etx = calculate_etx(rssi, 5.0, preset);
                assert!(
                    etx <= previous + 1e-4,
                    "ETX rose as RSSI improved to {rssi} at preset {preset}: {previous} -> {etx}"
                );
                previous = etx;
                rssi += 1;
            }

            let mut previous = f32::INFINITY;
            let mut tenths_of_db = -300i32;
            while tenths_of_db <= 300 {
                let snr = tenths_of_db as f32 / 10.0;
                let etx = calculate_etx(-90, snr, preset);
                assert!(
                    etx <= previous + 1e-4,
                    "ETX rose as SNR improved to {snr} at preset {preset}: {previous} -> {etx}"
                );
                previous = etx;
                tenths_of_db += 5;
            }
        }
    }

    #[test]
    fn margin_at_threshold_pins_the_zero_margin_probability() {
        let etx = calculate_etx(-60, -10.0, MODEM_SHORT_SLOW);
        assert!(
            (etx - 10.0).abs() < 0.001,
            "zero-margin ETX drifted off its pinned value: got {etx}"
        );
    }

    #[test]
    fn margin_one_db_below_threshold_pins_the_zero_margin_breakpoint() {
        let etx = calculate_etx(-60, -11.0, MODEM_SHORT_SLOW);
        assert!(
            (etx - 12.1212).abs() < 0.001,
            "-1 dB margin ETX drifted off its pinned value: got {etx}"
        );
    }

    #[test]
    fn margin_five_db_below_threshold_pins_the_low_breakpoint_probability() {
        let etx = calculate_etx(-60, -15.0, MODEM_SHORT_SLOW);
        assert!(
            (etx - 28.5714).abs() < 0.001,
            "-5 dB margin ETX drifted off its pinned value: got {etx}"
        );
    }

    #[test]
    fn weak_rssi_at_saturated_margin_pins_the_rssi_floor_breakpoint() {
        let etx = calculate_etx(-110, 7.0, MODEM_SHORT_SLOW);
        assert!(
            (etx - 1.14833).abs() < 0.0005,
            "saturated-margin, mid-range-RSSI ETX drifted off its pinned value: got {etx}"
        );
    }

    fn ranking_bucket(etx: f32) -> u16 {
        (etx * 100.0) as u16 / 50
    }

    #[test]
    fn a_weaker_link_toward_the_same_node_takes_a_later_bucket() {
        let czar_hears = calculate_etx(-95, 7.0, MODEM_SHORT_SLOW);
        let angl_hears = calculate_etx(-106, 2.0, MODEM_SHORT_SLOW);
        assert!(
            ranking_bucket(angl_hears) > ranking_bucket(czar_hears),
            "Czar {czar_hears} angl {angl_hears}"
        );
        let fcm6_hears_czar = calculate_etx(-88, -5.0, MODEM_SHORT_SLOW);
        let fcm6_hears_angl = calculate_etx(-95, -6.0, MODEM_SHORT_SLOW);
        assert!(
            ranking_bucket(fcm6_hears_angl) > ranking_bucket(fcm6_hears_czar),
            "FCM6 hears Czar {fcm6_hears_czar} angl {fcm6_hears_angl}"
        );
    }
}
