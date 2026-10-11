use embassy_nrf::gpio::{Input, Level, Output, Pin, Pull};

pub struct LoRaPins {
    pub reset: Output<'static>,
    pub busy: Input<'static>,
    pub ant_en: Output<'static>,
    pub dio1: Input<'static>,
}

impl LoRaPins {
    pub fn power_on(pwr_en: impl Pin, reset: impl Pin, busy: impl Pin, dio1: impl Pin) -> Self {
        let mut ant_en = Output::new(
            pwr_en,
            Level::High,
            embassy_nrf::gpio::OutputDrive::Standard,
        );
        ant_en.set_high();
        Self {
            reset: Output::new(reset, Level::High, embassy_nrf::gpio::OutputDrive::Standard),
            busy: Input::new(busy, Pull::None),
            ant_en,
            dio1: Input::new(dio1, Pull::None),
        }
    }
}
