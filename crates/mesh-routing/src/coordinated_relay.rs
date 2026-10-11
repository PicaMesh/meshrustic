pub const CW_MIN: u8 = 3;
pub const CW_MAX: u8 = 8;
pub const SNR_MIN: i32 = -20;
pub const SNR_MAX: i32 = 10;

pub const DEFAULT_SLOT_MS: u32 = 20;

/// An absolute spacing floor preserves enough separation for colocated relayers to hear and cancel each
/// other.
pub const MIN_RUNG_SPACING_MS: u32 = 50;

pub const MIN_TIE_BREAK_RANGE_MS: u32 = 20;

pub fn relay_floor_ms(slot_time_ms: u32) -> u32 {
    2 * CW_MAX as u32 * slot_time_ms
}

pub fn half_airtime_ms(packet_airtime_ms: u32) -> u32 {
    (packet_airtime_ms / 2).max(MIN_RUNG_SPACING_MS)
}

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

fn jitter_slots(from: u32, id: u32, node_num: u32, slot_span: u32) -> u32 {
    if slot_span == 0 {
        return 0;
    }
    (from ^ id ^ node_num) % slot_span
}

pub fn tie_break_range_ms(half_airtime_ms: u32) -> u32 {
    (half_airtime_ms / 2).max(MIN_TIE_BREAK_RANGE_MS)
}

/// A positive tie-break separates equal first-rung choices while keeping every send outside the reserved
/// window.
pub fn slot_tie_break_ms(half_airtime_ms: u32, id: u32, node_num: u32) -> u32 {
    let range = tie_break_range_ms(half_airtime_ms);
    ((node_num ^ id) % range) + 1
}

/// Per-node seeds decorrelate replies without requiring an RNG in the routing core.
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

pub fn tx_delay_ms_contention_max_at(channel_util_pct: f32, slot_ms: u32) -> u32 {
    (1u32 << crate::routing_ack::contention_window_size(channel_util_pct)) * slot_ms
}

pub fn tx_delay_ms_contention_max(slot_ms: u32) -> u32 {
    (1u32 << crate::routing_ack::RETX_CW_MAX) * slot_ms
}

pub fn tx_delay_ms_worst(cw_slot_ms: u32) -> u32 {
    let cw_max = CW_MAX as u32;
    let pow2 = 1u32 << cw_max;
    (2 * cw_max * cw_slot_ms).saturating_add(pow2 * cw_slot_ms)
}

pub fn transmission_record_window_ms(modem_preset: u8) -> u32 {
    let preset_window = mesh_radio::contention_window_ms(modem_preset);
    let slot = slot_time_for_preset(modem_preset);
    let cfg = mesh_radio::eu868_config_for_preset(modem_preset);
    let max_airtime = mesh_radio::packet_time_ms(&cfg, mesh_radio::MAX_LORA_PAYLOAD, false);
    let ladder =
        half_airtime_ms(max_airtime).saturating_mul(crate::graph::MAX_EDGES_PER_NODE as u32);
    let t1_window = tx_delay_ms_worst(slot)
        .max(ladder)
        .saturating_add(max_airtime)
        .saturating_add(ladder);
    preset_window.max(t1_window)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tie_break_range_stays_below_rung_spacing_everywhere() {
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
                for id in [0x1u32, 0x1234_5678, 0xffff_ffff] {
                    for node in [0xbdac_ce55u32, 0x046b_553a] {
                        let j = slot_tie_break_ms(half, id, node);
                        assert!(
                            j >= 1 && j <= range,
                            "preset {preset} len {len}: offset {j} outside 1..={range}"
                        );
                        assert!(half + 1 > range, "preset {preset} len {len}: rungs overlap");
                    }
                }
            }
        }
    }

    use mesh_radio::{RadioConfig, MODEM_SHORT_SLOW};

    #[test]
    fn cw_size_increases_with_snr() {
        assert!(cw_size_from_snr(12) >= cw_size_from_snr(-10));
    }

    #[test]
    fn the_router_band_stays_below_the_non_router_floor_at_every_snr() {
        for slot_ms in [8u32, 10, 17, 28, 48, 89] {
            let floor = relay_floor_ms(slot_ms);
            for snr in i8::MIN..=i8::MAX {
                let cw = cw_size_from_snr(snr);
                assert!(
                    (CW_MIN..=CW_MAX).contains(&cw),
                    "snr {snr} mapped outside [{CW_MIN}, {CW_MAX}]: {cw}"
                );
                let worst_early = (2 * cw as u32 - 1) * slot_ms;
                assert!(
                    worst_early < floor,
                    "snr {snr} at slot {slot_ms}ms: early band reaches {worst_early}ms, \
                     non-router floor is {floor}ms"
                );
            }
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
