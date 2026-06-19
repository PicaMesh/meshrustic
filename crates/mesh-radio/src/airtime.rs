//! Rolling TX duty cycle and channel utilization tracking.

use crate::config::RadioConfig;
use crate::config::RegionInfo;
use crate::packet_time::packet_time_ms;

pub const CHANNEL_UTILIZATION_PERIODS: usize = 6;
pub const MINUTES_IN_HOUR: usize = 60;
pub const MS_IN_HOUR: u32 = 3_600_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AirtimeLog {
    Tx,
    Rx,
    RxAll,
}

/// Tracks hourly TX duty cycle and ~10 s channel utilization windows.
#[derive(Clone, Debug)]
pub struct AirTime {
    region: RegionInfo,
    seconds_since_boot: u32,
    channel_utilization: [u32; CHANNEL_UTILIZATION_PERIODS],
    utilization_tx: [u32; MINUTES_IN_HOUR],
    last_util_period: u8,
    last_util_period_tx: u8,
    max_channel_util_percent: u8,
    polite_channel_util_percent: u8,
    polite_duty_cycle_percent: u8,
}

impl AirTime {
    pub fn new(region: RegionInfo) -> Self {
        Self {
            region,
            seconds_since_boot: 0,
            channel_utilization: [0; CHANNEL_UTILIZATION_PERIODS],
            utilization_tx: [0; MINUTES_IN_HOUR],
            last_util_period: 0,
            last_util_period_tx: 0,
            max_channel_util_percent: 40,
            polite_channel_util_percent: 25,
            polite_duty_cycle_percent: 50,
        }
    }

    pub fn tick_second(&mut self) {
        self.seconds_since_boot = self.seconds_since_boot.saturating_add(1);

        let util_period = self.period_util_minute();
        let util_period_tx = self.period_util_hour();

        if self.last_util_period != util_period {
            self.last_util_period = util_period;
            self.channel_utilization[util_period as usize] = 0;
        }
        if self.last_util_period_tx != util_period_tx {
            self.last_util_period_tx = util_period_tx;
            self.utilization_tx[util_period_tx as usize] = 0;
        }
    }

    pub fn log_airtime(&mut self, kind: AirtimeLog, airtime_ms: u32) {
        self.channel_utilization[self.period_util_minute() as usize] =
            self.channel_utilization[self.period_util_minute() as usize].saturating_add(airtime_ms);

        if kind == AirtimeLog::Tx {
            self.utilization_tx[self.period_util_hour() as usize] =
                self.utilization_tx[self.period_util_hour() as usize].saturating_add(airtime_ms);
        }
    }

    pub fn log_tx_packet(&mut self, config: &RadioConfig, payload_len: usize) {
        let ms = packet_time_ms(config, payload_len, false);
        self.log_airtime(AirtimeLog::Tx, ms);
    }

    pub fn channel_utilization_percent(&self) -> f32 {
        let sum: u32 = self.channel_utilization.iter().sum();
        (sum as f32 / (CHANNEL_UTILIZATION_PERIODS as f32 * 10.0 * 1000.0)) * 100.0
    }

    pub fn utilization_tx_percent(&self) -> f32 {
        let sum: u32 = self.utilization_tx.iter().sum();
        (sum as f32 / MS_IN_HOUR as f32) * 100.0
    }

    /// Effective hourly TX cap (polite fraction of regulatory duty cycle).
    pub fn duty_cycle_limit_percent(&self) -> f32 {
        if self.region.duty_cycle_percent >= 100 {
            return 100.0;
        }
        self.region.duty_cycle_percent as f32 * self.polite_duty_cycle_percent as f32 / 100.0
    }

    /// Whether TX is allowed under EU_868 duty cycle (polite half of cap).
    pub fn is_tx_allowed_duty_cycle(&self) -> bool {
        if self.region.duty_cycle_percent >= 100 {
            return true;
        }
        self.utilization_tx_percent() < self.duty_cycle_limit_percent()
    }

    pub fn is_tx_allowed_channel_util(&self, polite: bool) -> bool {
        let pct = if polite {
            self.polite_channel_util_percent
        } else {
            self.max_channel_util_percent
        };
        self.channel_utilization_percent() < pct as f32
    }

    fn period_util_minute(&self) -> u8 {
        ((self.seconds_since_boot / 10) as usize % CHANNEL_UTILIZATION_PERIODS) as u8
    }

    fn period_util_hour(&self) -> u8 {
        ((self.seconds_since_boot / 60) as usize % MINUTES_IN_HOUR) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RadioConfig, EU_868};

    #[test]
    fn duty_cycle_blocks_after_hour_of_continuous_tx() {
        let mut air = AirTime::new(EU_868);
        let cfg = RadioConfig::eu868_short_slow();
        let packet_ms = packet_time_ms(&cfg, 64, false);

        for _ in 0..3600 {
            air.tick_second();
            air.log_tx_packet(&cfg, 64);
        }

        let used = air.utilization_tx_percent();
        assert!(used > EU_868.duty_cycle_percent as f32 / 2.0);
        assert!(!air.is_tx_allowed_duty_cycle());
    }

    #[test]
    fn duty_cycle_limit_is_polite_half_of_region() {
        let air = AirTime::new(EU_868);
        assert!((air.duty_cycle_limit_percent() - 5.0).abs() < 0.01);
    }

    #[test]
    fn fresh_tracker_allows_tx() {
        let air = AirTime::new(EU_868);
        assert!(air.is_tx_allowed_duty_cycle());
        assert!(air.is_tx_allowed_channel_util(false));
    }
}
