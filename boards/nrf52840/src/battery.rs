use core::cell::RefCell;

use critical_section::Mutex;
use embassy_nrf::saadc::Saadc;
use embassy_time::{Duration, Timer};
use mesh_routing::interpret_battery_reading;

/// The internal reference of the nRF52840 analog converter. The converter
/// measures the difference between the input pin and this reference, so the
/// pin voltage is the reference plus the measured difference.
pub const SAADC_REFERENCE_MV: i32 = 600;
/// The configured gain spans six times the reference, and the twelve-bit
/// result maps that range onto 4096 counts.
pub const SAADC_MV_PER_COUNT: f32 = 6.0 * 600.0 / 4096.0;
/// The board divides the battery in half before the sense pin.
pub const BATTERY_DIVIDER: f32 = 2.0;
pub const BATTERY_SENSE_SAMPLES: u32 = 15;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BatteryReading {
    pub voltage_mv: u32,
    pub battery_level: u32,
    pub valid: bool,
    /// The converter count the reading came from. It is signed: a pin below
    /// the reference reads negative.
    pub raw_adc: i32,
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
    let mut sum: i32 = 0;
    for _ in 0..BATTERY_SENSE_SAMPLES {
        let mut buf = [0i16; 1];
        saadc.sample(&mut buf).await;
        // The converter is signed: a pin below the reference reads negative.
        // Clamping the sign away would throw the reading out and would bias
        // the average of the samples that surround it.
        sum += i32::from(buf[0]);
    }
    let raw_avg = sum / BATTERY_SENSE_SAMPLES as i32;
    let measured_mv = mesh_routing::battery_voltage_mv(
        raw_avg,
        SAADC_REFERENCE_MV,
        SAADC_MV_PER_COUNT,
        BATTERY_DIVIDER,
    );
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
