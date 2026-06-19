//! Embassy task: USB CDC ACM device + log drain.

use crate::Irqs;
use embassy_futures::join::join;
use embassy_nrf::peripherals;
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_nrf::usb::Driver;
use embassy_time::Timer;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config};
use static_cell::StaticCell;

use super::log;

static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
static MSOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
static CDC_STATE: StaticCell<State> = StaticCell::new();

#[embassy_executor::task]
pub async fn usb_task(usb: peripherals::USBD) {
    let driver = Driver::new(usb, Irqs, HardwareVbusDetect::new(Irqs));

    let mut config = Config::new(0x1209, 0x0001);
    config.manufacturer = Some("PicaMesh");
    config.product = Some("meshrustic");
    config.serial_number = Some("0001");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        MSOS_DESCRIPTOR.init([0; 256]),
        CONTROL_BUF.init([0; 64]),
    );

    let mut class = CdcAcmClass::new(&mut builder, CDC_STATE.init(State::new()), 64);
    let mut usb_dev = builder.build();

    let usb_run = usb_dev.run();
    let log_run = async {
        loop {
            class.wait_connection().await;
            crate::usb_log::set_usb_connected(true);
            defmt::info!("USB CDC connected");
            log::push_line("[meshrustic] USB log ready");

            loop {
                let mut buf = [0u8; 64];
                let n = log::read_chunk(&mut buf);
                if n > 0 {
                    if class.write_packet(&buf[..n]).await.is_err() {
                        crate::usb_log::set_usb_connected(false);
                        break;
                    }
                } else {
                    Timer::after_millis(5).await;
                }
            }
            crate::usb_log::set_usb_connected(false);
        }
    };

    join(usb_run, log_run).await;
}
