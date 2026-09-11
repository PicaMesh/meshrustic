//! Expected transmission count (ETX) from RSSI/SNR observations.
//!
//! LoRa link viability is governed by SNR clearing the demodulator's threshold for the spreading
//! factor in use — that threshold is what the datasheet calls the minimum SNR, and it runs from
//! about -7.5 dB at SF7 to about -20 dB at SF12, well below the noise floor. Absolute RSSI mainly
//! sets the noise floor; alone it predicts little. So the curve is built around *decode margin* —
//! reported SNR minus the current preset's spreading-factor threshold — with RSSI kept only as a
//! mild secondary term, never a veto.

use mesh_radio::modem_preset_params;

/// ETX stored as fixed-point (value × 100).
pub type EtxFixed = u16;

pub const ETX_MIN_FIXED: EtxFixed = 100;
pub const ETX_MAX_FIXED: EtxFixed = 10_000;

/// SX126x/SX127x datasheet demodulator SNR limit at SF7, dB, and the per-spreading-factor step: the
/// published table (-7.5 dB at SF7 down to -20 dB at SF12) falls on a straight line, 2.5 dB per SF.
const SF7_SNR_THRESHOLD_DB: f32 = -7.5;
const SNR_THRESHOLD_STEP_DB_PER_SF: f32 = -2.5;

/// Datasheet-derived demodulator SNR threshold for a spreading factor: total for any spreading
/// factor value (not just the 7..=12 range every known preset selects), by extrapolating the same
/// line rather than gating on it.
fn spreading_factor_snr_threshold_db(spreading_factor: u8) -> f32 {
    SF7_SNR_THRESHOLD_DB + SNR_THRESHOLD_STEP_DB_PER_SF * (spreading_factor as f32 - 7.0)
}

/// The current modem preset's demodulator SNR threshold. `modem_preset_params` already has a total
/// default arm for any preset value outside the known set, so this is total for any `u8`.
fn preset_snr_threshold_db(modem_preset: u8) -> f32 {
    spreading_factor_snr_threshold_db(modem_preset_params(modem_preset, false).spreading_factor)
}

/// Decode-margin breakpoints (dB above the preset's demodulator threshold) and the delivery
/// probability at each: steep across a narrow band around zero margin, because a LoRa demodulator
/// is close to a step function at its threshold, not a gradual slope over tens of dB the way path
/// loss is over distance. Flat below the first point and above the last.
const MARGIN_BREAK_DB: [f32; 6] = [-10.0, -5.0, -2.0, 0.0, 3.0, 8.0];
const MARGIN_PROB: [f32; 6] = [0.025, 0.05, 0.10, 0.15, 0.50, 0.95];

/// RSSI quality factor breakpoints (dBm) and the multiplier at each: a mild, monotonic secondary
/// term — capture effect, interference margin, estimate confidence — never large enough to be a
/// veto the way the old curve's RSSI term was. Flat below the first point and above the last.
const RSSI_FACTOR_BREAK_DBM: [i32; 2] = [-120, -60];
const RSSI_FACTOR: [f32; 2] = [0.90, 1.00];

/// A reported SNR that fails `is_finite()` (a corrupted register read; the clamp upstream of this
/// module is not something to rely on, per design) is priced as though it were this value — far
/// enough below every preset's threshold that decode margin is deeply negative regardless of
/// preset. Without this, every comparison in the margin/RSSI curves against a NaN SNR is false,
/// which falls through to the interpolation branch and produces a NaN delivery probability; packed
/// to fixed point that becomes `ETX_MIN_FIXED` — the *best* possible price for a corrupted reading,
/// exactly backwards.
const NON_FINITE_SNR_FALLBACK_DB: f32 = -100.0;

/// Delivery probability contributed by decode margin: a six-point piecewise-linear map, total over
/// any `f32` margin including non-finite ones after the caller's non-finite guard has run.
fn margin_delivery_probability(margin_db: f32) -> f32 {
    if margin_db <= MARGIN_BREAK_DB[0] {
        MARGIN_PROB[0]
    } else if margin_db >= MARGIN_BREAK_DB[5] {
        MARGIN_PROB[5]
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

/// The RSSI quality factor: total over any `i32` RSSI, including absurd inputs.
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

/// Compute ETX from an on-air observation at the given modem preset (matches the reference
/// `NeighborGraph` curve). Total for every `(modem_preset, rssi, snr)`, including non-finite `snr`
/// and preset values outside the known set.
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
    let scaled = (etx * 100.0).clamp(1.0, 65535.0) as u16;
    scaled.max(ETX_MIN_FIXED)
}

pub fn fixed_to_etx(fixed: EtxFixed) -> f32 {
    fixed as f32 / 100.0
}

/// Inverse mapping for topology wire packing (approximate RSSI/SNR from ETX at a modem preset). An
/// ETX alone cannot say how much of it was RSSI and how much was decode margin, so RSSI is fixed at
/// the top of the RSSI quality factor's domain (factor 1.0) and margin is recovered against that;
/// SNR is then the preset's threshold plus the recovered margin. Total for every `etx`, including
/// the fixed-point extremes: recovered margin always lands inside `MARGIN_BREAK_DB`'s own domain.
/// No production caller depends on this function's output.
pub fn etx_to_signal(etx: f32, modem_preset: u8) -> (i8, i8) {
    let target_prob = (1.0 / etx.max(1.0)).clamp(MARGIN_PROB[0], MARGIN_PROB[5]);

    let margin = if target_prob <= MARGIN_PROB[0] {
        MARGIN_BREAK_DB[0]
    } else if target_prob >= MARGIN_PROB[5] {
        MARGIN_BREAK_DB[5]
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
    fn round_trip_signal_is_reasonable() {
        // This particular sample round-trips to within 2.5% — a sanity check that the inverse is
        // wired up at all, not a claim about the function's worst case. See
        // `round_trip_worst_case_is_bounded` below for the real bound.
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

    // `etx_to_signal` reports SNR as an integer (the wire format's own type), so recovering it
    // from a continuous margin loses up to 1 dB to truncation. Near the curve's steep transition
    // that dB can swing the recomputed ETX far from the original — the sample above (2.5% drift)
    // is not representative. Swept over ETX 1.0-50.0 in 0.01 steps at every preset whose threshold
    // falls on a whole number of dB (SF8/10/12: SHORT_SLOW, MEDIUM_SLOW, LONG_SLOW), the true worst
    // case is ~43.7% at ETX ~6.666. Pinned here, with headroom, so the 10% figure above is never
    // mistaken for a universal bound.
    #[test]
    fn round_trip_worst_case_is_bounded() {
        for preset in [MODEM_SHORT_SLOW, MODEM_MEDIUM_SLOW, MODEM_LONG_SLOW] {
            let mut worst: f32 = 0.0;
            let mut hundredths_of_etx = 100u32; // ETX 1.00, stepping by 0.01 via an integer counter
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

    // The ranking inversion the recalibration exists to fix: at SHORT_SLOW (SF8, threshold -10 dB),
    // a link heard at -104 dBm/-12 dB (margin -2, below threshold) must price above the ETX 7
    // coverage ceiling, while a link heard at -106 dBm/-5 dB (margin +5, above threshold) must
    // clear it — even though the first has 2 dB more RSSI. Field capture:
    // tmp/meshrustic_bdacce55_20260908_2244.txt (!046b553a and !ee594922's views of !94d4a83a).
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

    // The same pair at LONG_SLOW (SF12, threshold -20 dB), where both clear the threshold, are both
    // usable — the recalibration should admit wrongly-excluded links, not just flip one comparison.
    #[test]
    fn both_links_are_usable_at_long_slow() {
        let below_short_slow = calculate_etx(-104, -12.0, MODEM_LONG_SLOW);
        let above_short_slow = calculate_etx(-106, -5.0, MODEM_LONG_SLOW);
        assert!(below_short_slow <= 7.0, "got ETX {below_short_slow}");
        assert!(above_short_slow <= 7.0, "got ETX {above_short_slow}");
    }

    #[test]
    fn margin_saturates_at_the_top_regardless_of_preset() {
        // +8 dB of margin or more is the saturation point; going further must not lower the ETX
        // any more, at a fast preset (SF7, threshold -7.5) or a slow one (SF12, threshold -20).
        let at_cap = calculate_etx(-60, -7.5 + 8.0, MODEM_SHORT_FAST);
        let past_cap = calculate_etx(-60, 20.0, MODEM_SHORT_FAST);
        assert_eq!(at_cap, past_cap);

        let at_cap_slow = calculate_etx(-60, -20.0 + 8.0, MODEM_LONG_SLOW);
        let past_cap_slow = calculate_etx(-60, 20.0, MODEM_LONG_SLOW);
        assert_eq!(at_cap_slow, past_cap_slow);
    }

    #[test]
    fn deep_below_threshold_hits_the_curves_floor() {
        // Deepest negative margin at the strongest RSSI reproduces the old curve's sentinel value;
        // at the weakest RSSI it is a little higher, because RSSI is now a mild factor, not a veto.
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
        // A two-point sample (weak vs. strong) cannot see a kink between the endpoints — sweep the
        // whole domain in both dimensions instead.
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
            let mut tenths_of_db = -300i32; // -30.0 dB, stepping by 0.5 dB via an integer counter
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

    // Mutation-tested pins. A reviewer mutated four single constants in the fork's copy of this
    // curve and found the existing suite (42/42) let every one through undetected. Each test below
    // is designed, and was verified by hand, to fail under one specific mutation: apply it, run the
    // suite, confirm the failure, then revert. Expected values are computed independently in
    // dB/probability arithmetic (see the accompanying comment on each), not by re-deriving them
    // from this module's own interpolation code — restating the implementation would not catch a
    // wrong constant.

    #[test]
    fn margin_at_threshold_pins_the_zero_margin_probability() {
        // SHORT_SLOW's threshold is -10 dB; SNR == -10 dB is exactly zero margin — the single most
        // consequential point on the curve, because it is exactly where ETX crosses the 7.0
        // coverage ceiling. RSSI is pinned at the RSSI factor's saturating end (-60, >= the
        // breakpoint) so the RSSI term is exactly 1.0 and cannot mask a change in the margin term.
        // Expected: 1 / (MARGIN_PROB[3] * 1.0) = 1 / 0.15 = 6.6667.
        let etx = calculate_etx(-60, -10.0, MODEM_SHORT_SLOW);
        assert!(
            (etx - 6.6667).abs() < 0.001,
            "zero-margin ETX drifted off its pinned value: got {etx}"
        );
    }

    #[test]
    fn margin_one_db_below_threshold_pins_the_zero_margin_breakpoint() {
        // 1 dB below SHORT_SLOW's threshold (SNR -11.0, margin -1.0) interpolates between
        // MARGIN_BREAK_DB[2] = -2 (prob 0.10) and MARGIN_BREAK_DB[3] = 0 (prob 0.15): prob =
        // 0.10 + 0.5*(0.15-0.10) = 0.125, ETX = 8.0 exactly. Moving MARGIN_BREAK_DB[3] to -1.0 puts
        // this same margin exactly on the (moved) breakpoint, collapsing the result to
        // MARGIN_PROB[3] = 0.15 and ETX 6.6667 instead — a large, easily-detected swing that the
        // zero-margin test above cannot distinguish from a marginProb[3] mutation on its own.
        let etx = calculate_etx(-60, -11.0, MODEM_SHORT_SLOW);
        assert!(
            (etx - 8.0).abs() < 0.001,
            "-1 dB margin ETX drifted off its pinned value: got {etx}"
        );
    }

    #[test]
    fn margin_five_db_below_threshold_pins_the_low_breakpoint_probability() {
        // SNR -15.0 at SHORT_SLOW is margin -5.0, exactly MARGIN_BREAK_DB[1]: prob = MARGIN_PROB[1]
        // = 0.05, ETX = 20.0 exactly. Isolated from the other three mutations above (touches only
        // index 1).
        let etx = calculate_etx(-60, -15.0, MODEM_SHORT_SLOW);
        assert!(
            (etx - 20.0).abs() < 0.001,
            "-5 dB margin ETX drifted off its pinned value: got {etx}"
        );
    }

    #[test]
    fn weak_rssi_at_saturated_margin_pins_the_rssi_floor_breakpoint() {
        // Margin pinned at the saturation point (SNR -2.0 at SHORT_SLOW is margin +8.0, so
        // delivery probability is flat at MARGIN_PROB[5] = 0.95) isolates the RSSI term. At RSSI
        // -110 dBm, strictly between RSSI_FACTOR_BREAK_DBM's -120 and -60:
        // t = (-110 - (-120)) / 60 = 1/6, rssiFactor = 0.90 + (1/6)*0.10 = 0.91667,
        // prob = 0.95 * 0.91667 = 0.87083, ETX = 1/0.87083 = 1.14833. Moving
        // RSSI_FACTOR_BREAK_DBM[0] from -120 to -100 puts -110 at-or-below the new breakpoint, so
        // the RSSI factor collapses to the flat 0.90 and ETX becomes 1.16959 instead.
        let etx = calculate_etx(-110, -2.0, MODEM_SHORT_SLOW);
        assert!(
            (etx - 1.14833).abs() < 0.0005,
            "saturated-margin, mid-range-RSSI ETX drifted off its pinned value: got {etx}"
        );
    }
}
