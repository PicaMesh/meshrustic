//! EU_868 + modem preset constants, radio HAL traits, and AirTime tracking.

#![no_std]

mod airtime;
mod bus;
mod channel;
mod config;
mod frame;
mod interface;
mod packet_time;
mod queue;
mod slot;

pub use airtime::{AirTime, AirtimeLog, CHANNEL_UTILIZATION_PERIODS, MINUTES_IN_HOUR, MS_IN_HOUR};
pub use bus::SpiLoRaBus;
pub use channel::primary_channel_hash;
pub use config::{
    modem_preset_channel_name, modem_preset_params, RadioConfig, RegionInfo, EU_868,
    EU_868_DEFAULT_FREQ_MHZ, MODEM_LONG_FAST, MODEM_LONG_MODERATE, MODEM_LONG_SLOW,
    MODEM_LONG_TURBO, MODEM_MEDIUM_FAST, MODEM_MEDIUM_SLOW, MODEM_SHORT_FAST, MODEM_SHORT_SLOW,
    MODEM_SHORT_TURBO, MODEM_VERY_LONG_SLOW, PACKET_HEADER_LEN, PREAMBLE_LENGTH, REGION_EU_868,
    SYNC_WORD, SX126X_SYNC_CONTROL_BITS, sync_word_sx126x,
};
pub use frame::{RadioId, RxFrame, TxFrame, MAX_BRIDGE_TARGETS, MAX_LORA_PAYLOAD, MAX_RADIOS};
pub use interface::{RadioError, RadioInterface};
pub use packet_time::packet_time_ms;
pub use queue::{QueueError, RxQueue, TxQueue, DEFAULT_RX_QUEUE, DEFAULT_TX_QUEUE};
pub use slot::{RadioSlot, ServiceReport};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_sync_word_sx126x_register() {
        assert_eq!(sync_word_sx126x(SYNC_WORD), 0x24B4);
        assert_eq!(sync_word_sx126x(0x12), 0x1424);
    }

    #[test]
    fn eu868_short_slow_defaults() {
        let params = modem_preset_params(MODEM_SHORT_SLOW, false);
        assert_eq!(params.bandwidth_khz, 250.0);
        assert_eq!(params.spreading_factor, 8);
        assert_eq!(EU_868.duty_cycle_percent, 10);
        assert!(EU_868_DEFAULT_FREQ_MHZ >= EU_868.freq_start_mhz);
        assert!(EU_868_DEFAULT_FREQ_MHZ <= EU_868.freq_end_mhz);
    }
}
