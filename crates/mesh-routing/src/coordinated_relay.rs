//! SNR-weighted coordinated relay slot timing (ROUTER role).
//!
//! Higher SNR → larger contention window → longer delay, so edge/weak nodes relay first.

pub const CW_MIN: u8 = 3;
pub const CW_MAX: u8 = 8;
pub const SNR_MIN: i32 = -20;
pub const SNR_MAX: i32 = 10;

/// Default slot time when airtime is not supplied (SHORT_SLOW ~200 ms packet → ~20 ms slot).
pub const DEFAULT_SLOT_MS: u32 = 20;

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
pub fn tx_delay_ms_router(
    snr: i8,
    slot_ms: u32,
    from: u32,
    id: u32,
    node_num: u32,
) -> u32 {
    let cw = cw_size_from_snr(snr) as u32;
    let span = 2 * cw;
    jitter_slots(from, id, node_num, span) * slot_ms
}

/// Worst-case ROUTER_LATE relay window at strong SNR (T1 insurance timer base).
pub fn tx_delay_ms_worst(cw_slot_ms: u32) -> u32 {
    let cw_max = CW_MAX as u32;
    let pow2 = 1u32 << cw_max;
    (2 * cw_max * cw_slot_ms).saturating_add(pow2 * cw_slot_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_snr_yields_longer_router_delay() {
        let slot = DEFAULT_SLOT_MS;
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
}
