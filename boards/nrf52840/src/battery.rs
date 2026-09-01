//! Battery voltage via SAADC on P0.31 (1M + 1M divider to GND).

use core::cell::RefCell;

use critical_section::Mutex;
use embassy_nrf::saadc::Saadc;
use embassy_time::{Duration, Timer};
use mesh_routing::interpret_battery_reading;

/// VBAT → 1M → tap (P0.31) → 1M → GND: V_tap = VBAT / 2.
pub const ADC_MULTIPLIER: f32 = 2.0;
/// Full-scale input of the SAADC channel configured in `main.rs`: internal 0.6 V
/// reference with gain 1/6 ⇒ 0.6 / (1/6) = 3.6 V, not the 3.0 V rail voltage.
pub const AREF_VOLTAGE: f32 = 3.6;
pub const BATTERY_SENSE_BITS: u32 = 12;
pub const BATTERY_SENSE_SAMPLES: u32 = 15;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BatteryReading {
    pub voltage_mv: u32,
    pub battery_level: u32,
    pub valid: bool,
    /// Averaged raw SAADC counts behind this reading (kept for field diagnosis:
    /// `voltage_mv` is zeroed whenever the reading is rejected as implausible).
    pub raw_adc: u32,
    pub usb_powered: bool,
}

static BATTERY: Mutex<RefCell<BatteryReading>> = Mutex::new(RefCell::new(BatteryReading {
    voltage_mv: 0,
    battery_level: 0,
    valid: false,
    raw_adc: 0,
    usb_powered: false,
}));

pub fn latest() -> BatteryReading {
    critical_section::with(|cs| *BATTERY.borrow(cs).borrow())
}

#[embassy_executor::task]
pub async fn battery_task(mut saadc: Saadc<'static, 1>) {
    saadc.calibrate().await;
    loop {
        let reading = sample_battery(&mut saadc).await;
        critical_section::with(|cs| *BATTERY.borrow(cs).borrow_mut() = reading);
        defmt::info!(
            "[Battery] {} mV level={} raw={} vbus={}",
            reading.voltage_mv,
            reading.battery_level,
            reading.raw_adc,
            reading.usb_powered
        );
        crate::usb_log::log::battery::reading(
            reading.voltage_mv,
            reading.battery_level,
            reading.raw_adc,
        );
        Timer::after(Duration::from_secs(60)).await;
    }
}

async fn sample_battery(saadc: &mut Saadc<'static, 1>) -> BatteryReading {
    let mut sum = 0u32;
    for _ in 0..BATTERY_SENSE_SAMPLES {
        let mut buf = [0i16; 1];
        saadc.sample(&mut buf).await;
        sum += buf[0].max(0) as u32;
    }
    let raw_avg = sum / BATTERY_SENSE_SAMPLES;
    let mv_per_lsb = ADC_MULTIPLIER * (1000.0 * AREF_VOLTAGE / (1u32 << BATTERY_SENSE_BITS) as f32);
    let measured_mv = (mv_per_lsb * raw_avg as f32) as u32;
    let usb = crate::usb_log::is_usb_powered();
    let (voltage_mv, battery_level, valid) = interpret_battery_reading(measured_mv, raw_avg, usb);
    BatteryReading {
        voltage_mv,
        battery_level,
        valid,
        raw_adc: raw_avg,
        usb_powered: usb,
    }
}
