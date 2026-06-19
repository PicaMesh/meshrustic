//! LoRa time-on-air estimation (Semtech datasheet formula).

use crate::config::RadioConfig;

/// Estimate packet airtime in milliseconds for a given payload length.
///
/// Uses the standard LoRa time-on-air formula with explicit header and CRC enabled.
pub fn packet_time_ms(config: &RadioConfig, payload_len: usize, received: bool) -> u32 {
    let _ = received;
    let sf = config.spreading_factor as u32;
    let bw_hz = (config.bandwidth_khz * 1000.0) as u32;
    let cr = (config.coding_rate as u32).saturating_sub(4);
    let preamble = config.preamble_length as u32;

    let t_sym_us = ((1u64 << sf) * 1_000_000) / bw_hz as u64;
    let de = 0u32;
    let h = 0u32; // explicit header
    let crc = 1u32;

    let mut numerator =
        8 * payload_len as i32 - 4 * sf as i32 + 28 + 16 * crc as i32 - 20 * h as i32;
    if numerator < 0 {
        numerator = 0;
    }
    let denom = 4 * (sf - 2 * de);
    let payload_symbols = if denom == 0 {
        0
    } else {
        ((numerator + denom as i32 - 1) / denom as i32).max(0) as u32 * (cr + 4)
    };

    let n_symbols = preamble + 12 + payload_symbols;
    let time_us = n_symbols as u64 * t_sym_us;
    time_us.div_ceil(1000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RadioConfig;

    #[test]
    fn short_slow_max_packet_is_reasonable() {
        let cfg = RadioConfig::eu868_short_slow();
        let ms = packet_time_ms(&cfg, 255, false);
        assert!(ms > 100);
        assert!(ms < 5_000);
    }
}
