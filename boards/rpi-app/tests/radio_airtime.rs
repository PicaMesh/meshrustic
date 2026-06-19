//! AirTime duty-cycle and packet-time tests (host).

use mesh_radio::{packet_time_ms, AirTime, RadioConfig, EU_868, MODEM_SHORT_SLOW, REGION_EU_868};

#[test]
fn packet_time_short_slow_nonzero() {
    let cfg = RadioConfig::eu868_short_slow();
    let ms = packet_time_ms(&cfg, 64, false);
    assert!(ms > 50);
}

#[test]
fn duty_cycle_blocks_sustained_transmit() {
    let mut air = AirTime::new(EU_868);
    let cfg = RadioConfig::eu868_short_slow();

    for _ in 0..3600 {
        air.tick_second();
        air.log_tx_packet(&cfg, 64);
    }

    assert!(!air.is_tx_allowed_duty_cycle());
}

#[test]
fn fresh_airtime_allows_transmit() {
    let air = AirTime::new(EU_868);
    assert!(air.is_tx_allowed_duty_cycle());
}

#[test]
fn eu868_region_constants() {
    assert_eq!(EU_868.code, REGION_EU_868);
    assert_eq!(
        RadioConfig::eu868_short_slow().modem_preset,
        MODEM_SHORT_SLOW
    );
}
