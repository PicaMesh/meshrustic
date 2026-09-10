//! SNR-weighted coordinated relay slot timing (ROUTER role).
//!
//! Higher SNR → larger contention window → longer delay, so edge/weak nodes relay first.

pub const CW_MIN: u8 = 3;
pub const CW_MAX: u8 = 8;
pub const SNR_MIN: i32 = -20;
pub const SNR_MAX: i32 = 10;

/// Fallback slot time when preset airtime is unavailable (SHORT_SLOW CAD slot ≈10 ms).
pub const DEFAULT_SLOT_MS: u32 = 20;

/// Minimum spacing between two relay rungs, whatever the airtime says.
///
/// Absolute, in an otherwise preset-derived geometry, and it binds about half the time: at
/// SHORT_SLOW it applies to every frame up to 54 bytes, which was 354 of 703 and 305 of 628 relays
/// across two 12 h captures. Expressing it in slot times was tried and withdrawn — the jitter range
/// below is derived from the *floored* half, so a slot-time floor would shrink two colocated nodes'
/// rung-0 separation from a measured 6.55 ms mean to a modelled 4.3–5.7 ms, through the band at
/// which they demonstrably stop hearing each other.
///
/// So it stays, with a stated purpose rather than an inherited number: 50 ms is the smallest
/// separation at which two colocated nodes reliably hear one another. Revisiting it needs a
/// measurement of the separation at which a cancel actually fires, not a substitution of one
/// constant for another.
pub const MIN_RUNG_SPACING_MS: u32 = 50;

/// Minimum de-correlation between two nodes that computed the same rung.
///
/// Absolute for the same reason, and coupled to [`MIN_RUNG_SPACING_MS`]: the range must stay
/// strictly below the spacing or two adjacent rungs can swap order. See
/// [`slot_tie_break_ms`].
pub const MIN_TIE_BREAK_RANGE_MS: u32 = 20;

/// Broadcast relay slot spacing: half of packet airtime, floored at [`MIN_RUNG_SPACING_MS`].
///
/// The one place the floor is applied. Three sites used to re-apply it independently, one of them
/// inside the relay-commit path where it feeds both the fallback spacing *and* the jitter — so
/// changing the obvious one would have left the others disagreeing, and at the short presets that
/// inverts rung order.
pub fn half_airtime_ms(packet_airtime_ms: u32) -> u32 {
    (packet_airtime_ms / 2).max(MIN_RUNG_SPACING_MS)
}

/// LoRa CAD slot time for a modem preset (EU_868 narrow band).
pub fn slot_time_for_preset(modem_preset: u8) -> u32 {
    mesh_radio::slot_time_ms(&mesh_radio::eu868_config_for_preset(modem_preset)).max(1)
}

fn map_range(value: i32, in_min: i32, in_max: i32, out_min: u8, out_max: u8) -> u8 {
    if in_max <= in_min {
        return out_min;
    }
    let clamped = value.clamp(in_min, in_max);
    let numer = (clamped - in_min) as u32 * (out_max - out_min) as u32;
    let denom = (in_max - in_min) as u32;
    (out_min as u32 + numer / denom) as u8
}

pub fn cw_size_from_snr(snr: i8) -> u8 {
    map_range(snr as i32, SNR_MIN, SNR_MAX, CW_MIN, CW_MAX)
}

/// Deterministic jitter in place of `random()` for no_std ROUTER rebroadcast delay.
fn jitter_slots(from: u32, id: u32, node_num: u32, slot_span: u32) -> u32 {
    if slot_span == 0 {
        return 0;
    }
    (from ^ id ^ node_num) % slot_span
}

/// Meshtastic ROUTER early rebroadcast: `random(0, 2 * CWsize) * slotTimeMsec`.
pub fn tx_delay_ms_router(snr: i8, slot_ms: u32, from: u32, id: u32, node_num: u32) -> u32 {
    let cw = cw_size_from_snr(snr) as u32;
    let span = 2 * cw;
    jitter_slots(from, id, node_num, span) * slot_ms
}

/// Range of the rung tie-break: a quarter of the rung spacing either side, floored.
///
/// Named so the invariant it must satisfy can be stated and tested in one place: strictly below the
/// rung spacing, or two adjacent rungs can swap and the earlier-ranked node transmits second —
/// which voids the coverage absorption the ranking performed on its behalf.
pub fn tie_break_range_ms(half_airtime_ms: u32) -> u32 {
    (half_airtime_ms / 2).max(MIN_TIE_BREAK_RANGE_MS)
}

/// Tie-breaker added to an SR relay slot: deterministic per (packet, node), within
/// ±¼ half-airtime. Small enough that two candidates in adjacent slots
/// can never swap order, large enough that two nodes computing the same slot do not key up in
/// the same instant. Returns the signed offset in ms.
pub fn slot_tie_break_ms(half_airtime_ms: u32, id: u32, node_num: u32) -> i32 {
    let range = tie_break_range_ms(half_airtime_ms);
    ((node_num ^ id) % range) as i32 - (range / 2) as i32
}

/// Meshtastic `getTxDelayMsec`: `random(0, 2^CWsize) * slotTime`, CWsize from channel
/// utilization. Used for module replies (NodeInfo answers, dirty topology broadcasts) that
/// several nodes may fire in response to the same packet. Deterministic per (seeds, node) so
/// colocated nodes draw different slots without an RNG.
pub fn tx_delay_ms_contention(
    channel_util_pct: f32,
    slot_ms: u32,
    seed_a: u32,
    seed_b: u32,
    node_num: u32,
) -> u32 {
    let cw = crate::routing_ack::contention_window_size(channel_util_pct) as u32;
    jitter_slots(seed_a, seed_b, node_num, 1u32 << cw) * slot_ms
}

/// Upper bound of [`tx_delay_ms_contention`] at the given channel utilization.
pub fn tx_delay_ms_contention_max_at(channel_util_pct: f32, slot_ms: u32) -> u32 {
    (1u32 << crate::routing_ack::contention_window_size(channel_util_pct)) * slot_ms
}

/// Upper bound of [`tx_delay_ms_contention`] at any channel utilization.
pub fn tx_delay_ms_contention_max(slot_ms: u32) -> u32 {
    (1u32 << crate::routing_ack::RETX_CW_MAX) * slot_ms
}

/// Worst-case ROUTER_LATE relay window at strong SNR (T1 insurance timer base).
pub fn tx_delay_ms_worst(cw_slot_ms: u32) -> u32 {
    let cw_max = CW_MAX as u32;
    let pow2 = 1u32 << cw_max;
    (2 * cw_max * cw_slot_ms).saturating_add(pow2 * cw_slot_ms)
}

/// `has_node_transmitted` retention: contention window or worst-case T1 delay, whichever is longer.
pub fn transmission_record_window_ms(modem_preset: u8) -> u32 {
    let preset_window = mesh_radio::contention_window_ms(modem_preset);
    let slot = slot_time_for_preset(modem_preset);
    let cfg = mesh_radio::eu868_config_for_preset(modem_preset);
    let max_airtime = mesh_radio::packet_time_ms(&cfg, mesh_radio::MAX_LORA_PAYLOAD, false);
    let t1_window = tx_delay_ms_worst(slot).saturating_add(max_airtime);
    preset_window.max(t1_window)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tie-break range must stay strictly below the rung spacing, at every preset and frame
    /// size — not only at the three values the older test happened to try.
    ///
    /// If it ever reaches the spacing, two adjacent rungs can swap: the earlier-ranked node
    /// transmits second, and the coverage the ranking absorbed on its behalf is never carried. The
    /// two floors are what make this non-obvious — the range is derived from the *floored* half, so
    /// changing either constant alone can break it, which is why both are named and pinned here.
    #[test]
    fn tie_break_range_stays_below_rung_spacing_everywhere() {
        // Every preset, and frame sizes from a bare header to the maximum payload.
        for preset in 0u8..=9 {
            let cfg = mesh_radio::eu868_config_for_preset(preset);
            for len in [16usize, 29, 48, 55, 106, 200, 237, 253] {
                let airtime = mesh_radio::packet_time_ms(&cfg, len, false);
                let half = half_airtime_ms(airtime);
                let range = tie_break_range_ms(half);
                assert!(
                    range < half,
                    "preset {preset} len {len}: tie-break range {range} must stay under the rung \
                     spacing {half}, or adjacent rungs can swap"
                );
                // And the offset it produces must fit inside that range on both sides.
                for id in [0x1u32, 0x1234_5678, 0xffff_ffff] {
                    for node in [0xbdac_ce55u32, 0x046b_553a] {
                        let j = slot_tie_break_ms(half, id, node);
                        assert!(
                            j >= -((range / 2) as i32) && j < (range - range / 2) as i32,
                            "preset {preset} len {len}: offset {j} outside ±{range}/2"
                        );
                        // The earlier rung, however late, still precedes the next however early.
                        let latest_this = (range - range / 2 - 1) as i32;
                        let earliest_next = half as i32 - (range / 2) as i32;
                        assert!(
                            earliest_next > latest_this,
                            "preset {preset} len {len}: rungs overlap"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn slot_tie_break_never_reorders_adjacent_slots() {
        for half in [50u32, 81, 150] {
            let range = (half / 2).max(20) as i32;
            for id in [0x1u32, 0x1234_5678, 0xe23d_7d52, 0xffff_ffff] {
                for node in [0xbdac_ce55u32, 0x046b_553a, 0x63dc_8f8c] {
                    let j = slot_tie_break_ms(half, id, node);
                    assert!(
                        j >= -(range / 2) && j < range - range / 2,
                        "jitter {j} outside ±{range}/2"
                    );
                    // Worst case: earlier slot maximally late, next slot maximally early.
                    let earliest_next = half as i32 - range / 2;
                    let latest_this = range - range / 2 - 1;
                    assert!(
                        earliest_next > latest_this,
                        "adjacent slots overlap at half={half}"
                    );
                }
            }
        }
    }
    use mesh_radio::{RadioConfig, MODEM_SHORT_SLOW};

    #[test]
    fn higher_snr_yields_longer_router_delay() {
        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let node = 0x677a_1caf;
        let from = 0x1234_5678;
        let id = 42;
        let weak = tx_delay_ms_router(-5, slot, from, id, node);
        let strong = tx_delay_ms_router(12, slot, from, id, node);
        assert!(strong >= weak);
    }

    #[test]
    fn cw_size_increases_with_snr() {
        assert!(cw_size_from_snr(12) >= cw_size_from_snr(-10));
    }

    #[test]
    fn tx_delay_uses_preset_slot() {
        let cfg = RadioConfig::eu868_short_slow();
        let preset_slot = mesh_radio::slot_time_ms(&cfg);
        let from = 0x1234_5678;
        let id = 42;
        let node = 0x677a_1caf;
        let with_fallback = tx_delay_ms_router(8, DEFAULT_SLOT_MS, from, id, node);
        let with_preset = tx_delay_ms_router(8, preset_slot, from, id, node);
        assert!(tx_delay_ms_worst(preset_slot) < tx_delay_ms_worst(DEFAULT_SLOT_MS));
        if preset_slot != DEFAULT_SLOT_MS {
            assert!(with_preset <= with_fallback);
        }
    }

    #[test]
    fn half_airtime_minimum_fifty_ms() {
        assert_eq!(half_airtime_ms(40), 50);
        assert_eq!(half_airtime_ms(200), 100);
    }

    #[test]
    fn slot_time_for_preset_matches_short_slow() {
        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let cfg = RadioConfig::eu868_short_slow();
        assert_eq!(slot, mesh_radio::slot_time_ms(&cfg));
    }

    #[test]
    fn transmission_record_window_covers_t1_worst_case() {
        let preset = MODEM_SHORT_SLOW;
        let slot = slot_time_for_preset(preset);
        let cfg = mesh_radio::eu868_config_for_preset(preset);
        let max_airtime = mesh_radio::packet_time_ms(&cfg, mesh_radio::MAX_LORA_PAYLOAD, false);
        let t1_delay = tx_delay_ms_worst(slot).saturating_add(max_airtime);
        let window = transmission_record_window_ms(preset);
        assert!(window >= t1_delay);
        assert!(window > mesh_radio::contention_window_ms(preset));
    }
}
