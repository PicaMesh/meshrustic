//! Expected transmission count (ETX) from RSSI/SNR observations.

/// ETX stored as fixed-point (value × 100).
pub type EtxFixed = u16;

pub const ETX_MIN_FIXED: EtxFixed = 100;
pub const ETX_MAX_FIXED: EtxFixed = 10_000;

const RSSI_BREAK: [i32; 6] = [-110, -100, -90, -80, -70, -60];
const PROB_BREAK: [f32; 6] = [0.05, 0.15, 0.40, 0.65, 0.85, 0.95];

/// Compute ETX from an on-air observation (matches reference NeighborGraph curve).
pub fn calculate_etx(rssi: i32, snr: f32) -> f32 {
    let delivery_prob = if rssi <= RSSI_BREAK[0] {
        PROB_BREAK[0]
    } else if rssi >= RSSI_BREAK[5] {
        PROB_BREAK[5]
    } else {
        let seg = RSSI_BREAK
            .iter()
            .skip(1)
            .position(|&brk| rssi < brk)
            .unwrap_or(0);
        let t = (rssi - RSSI_BREAK[seg]) as f32 / (RSSI_BREAK[seg + 1] - RSSI_BREAK[seg]) as f32;
        PROB_BREAK[seg] + t * (PROB_BREAK[seg + 1] - PROB_BREAK[seg])
    };

    let snr_factor = if snr <= 0.0 {
        0.5
    } else if snr >= 10.0 {
        1.0
    } else {
        0.5 + snr * 0.05
    };

    let prob = delivery_prob * snr_factor;
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

/// Inverse mapping for topology wire packing (approximate RSSI/SNR from ETX).
pub fn etx_to_signal(etx: f32) -> (i8, i8) {
    let prob = 1.0 / etx.max(1.0);

    let rssi = if prob <= PROB_BREAK[0] {
        RSSI_BREAK[0]
    } else if prob >= PROB_BREAK[5] {
        RSSI_BREAK[5]
    } else {
        let seg = PROB_BREAK
            .iter()
            .skip(1)
            .position(|&brk| prob < brk)
            .unwrap_or(0);
        let t = (prob - PROB_BREAK[seg]) / (PROB_BREAK[seg + 1] - PROB_BREAK[seg]);
        RSSI_BREAK[seg] + (t * (RSSI_BREAK[seg + 1] - RSSI_BREAK[seg]) as f32) as i32
    };

    let etx_at_snr10 = calculate_etx(rssi, 10.0);
    let snr = if etx <= etx_at_snr10 * 1.05 {
        10
    } else {
        let mut snr_factor = etx_at_snr10 / etx;
        if snr_factor < 0.5 {
            snr_factor = 0.5;
        }
        let snr_f = (snr_factor - 0.5) / 0.05;
        snr_f.clamp(-5.0, 10.0) as i32
    };

    (rssi as i8, snr as i8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_signal_low_etx() {
        let etx = calculate_etx(-60, 10.0);
        assert!(etx < 2.0);
    }

    #[test]
    fn round_trip_signal_is_reasonable() {
        let (rssi, snr) = etx_to_signal(calculate_etx(-75, 8.0));
        assert!(rssi <= -60);
        assert!(snr >= 0);
    }
}
