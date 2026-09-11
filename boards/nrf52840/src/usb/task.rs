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
static SERIAL_NUMBER: StaticCell<[u8; 8]> = StaticCell::new();

/// The USB serial-number string, as this node's id in lowercase hex.
///
/// Every board used to report `0001`, so two of them attached at once were indistinguishable:
/// udev builds `/dev/serial/by-id/` from the serial, could only create one link for the pair, and
/// the second board appeared under no stable name at all. Logging tools then silently captured one
/// node and missed the other. The id is already known here — it is derived from the chip's factory
/// DEVICEID and may be overridden from flash — so it costs nothing to publish and makes the by-id
/// link name the node.
fn serial_number_str(node_num: u32) -> &'static str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let buf = SERIAL_NUMBER.init([0u8; 8]);
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = HEX[((node_num >> (28 - i * 4)) & 0xF) as usize];
    }
    // Always ASCII hex by construction; the fallback keeps this total rather than panicking in a
    // task that runs before anything can report the panic.
    core::str::from_utf8(buf).unwrap_or("meshrustic")
}

#[embassy_executor::task]
pub async fn usb_task(usb: peripherals::USBD, node_num: u32, device_role: u32) {
    let driver = Driver::new(usb, Irqs, HardwareVbusDetect::new(Irqs));

    let mut config = Config::new(0x1209, 0x0001);
    config.manufacturer = Some("PicaMesh");
    config.product = Some("meshrustic");
    config.serial_number = Some(serial_number_str(node_num));
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
            // Identity and firmware on every connection, not once at boot. Lines pushed before
            // this task runs are written into a 16 KB ring that the node fills long before a host
            // attaches, so a boot-time stamp is evicted and never seen — which is exactly what
            // happened to the first attempt. Re-stating it here also answers "what is this node
            // running?" for a capture started at any time, not only one that caught a reboot.
            log::mesh::node_id(node_num);
            log::mesh::device_role(device_role);
            log::push_line(concat!("[meshrustic] build ", env!("MR_BUILD")));

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
