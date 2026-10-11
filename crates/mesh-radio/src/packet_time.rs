use crate::config::RadioConfig;

pub fn packet_time_ms(config: &RadioConfig, payload_len: usize, received: bool) -> u32 {
    let _ = received;
    if !(5..=12).contains(&config.spreading_factor)
        || !(5..=8).contains(&config.coding_rate)
        || !config.bandwidth_khz.is_finite()
        || config.bandwidth_khz < 1.0
        || payload_len > 255
    {
        return u32::MAX;
    }
    let sf = config.spreading_factor as u32;
    let bw_hz = (config.bandwidth_khz * 1000.0) as u32;
    let cr = (config.coding_rate as u32).saturating_sub(4);
    let preamble = config.preamble_length as u32;

    let de = 0u32;
    let h = 0u32;
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

    let quarter_symbols = 4 * (preamble + 12 + payload_symbols) + 1;
    let time_us = (quarter_symbols as u64 * (1u64 << sf) * 1_000_000).div_ceil(4 * bw_hz as u64);
    time_us.div_ceil(1000).min(u32::MAX as u64) as u32
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
    #[test]
    fn preamble_quarter_symbol_is_included() {
        let mut config = RadioConfig::eu868_default();
        config.spreading_factor = 12;
        config.bandwidth_khz = 125.0;
        config.preamble_length = 8;
        assert_eq!(packet_time_ms(&config, 0, false), 664);
    }
    #[test]
    fn malformed_modem_parameters_fail_closed() {
        let mut config = RadioConfig::eu868_default();
        for bandwidth in [0.0, -1.0, f32::NAN, f32::INFINITY] {
            config.bandwidth_khz = bandwidth;
            assert_eq!(packet_time_ms(&config, 1, false), u32::MAX);
            assert_eq!(crate::timing::slot_time_ms(&config), u32::MAX);
        }
    }
}
