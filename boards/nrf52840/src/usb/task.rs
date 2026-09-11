//! Embassy task: USB CDC ACM device + log drain + host command input.
//!
//! The command read side is Part C of the H1 controlled-node experiment harness (see
//! `tmp/controlled-node-harness-plan-20260911.md` in the MeshRustic repo): it lets an operator
//! make this node originate a frame, which is otherwise impossible to arrange over the write-only
//! link this task used to be. A line is parsed here and handed to the radio task over a small
//! channel; nothing here talks to the radio directly.

use crate::Irqs;
use embassy_futures::join::join3;
use embassy_nrf::peripherals;
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_nrf::usb::Driver;
use embassy_time::Timer;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config};
use mesh_routing::{CommandError, LineAccumulator, MAX_COMMAND_LINE};
use static_cell::StaticCell;

use super::log;
use super::HostCommandChannel;

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
pub async fn usb_task(
    usb: peripherals::USBD,
    node_num: u32,
    device_role: u32,
    host_cmd: &'static HostCommandChannel,
) {
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

    let class = CdcAcmClass::new(&mut builder, CDC_STATE.init(State::new()), 64);
    let (mut sender, mut receiver) = class.split();
    let mut usb_dev = builder.build();

    let usb_run = usb_dev.run();
    let log_run = async {
        loop {
            sender.wait_connection().await;
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
                    if sender.write_packet(&buf[..n]).await.is_err() {
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

    // Part C: host command input. A fixed-capacity line accumulator, reset on every new
    // connection so a line left partial by a disconnect can never be silently completed by
    // bytes from the next session. A complete, parsed line is handed to the radio task through
    // `host_cmd`; a rejected or dropped one is logged with its specific reason, never silent.
    let cmd_run = async {
        let mut acc: LineAccumulator<MAX_COMMAND_LINE> = LineAccumulator::new();
        loop {
            receiver.wait_connection().await;
            acc.reset();
            loop {
                let mut buf = [0u8; 64];
                let n = match receiver.read_packet(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => break, // disconnected: outer loop waits for the next connection
                };
                for &b in &buf[..n] {
                    let Some(line_result) = acc.push_byte(b) else {
                        continue;
                    };
                    match line_result {
                        // The accumulator itself only ever reports LineTooLong; a line that fit
                        // is parsed, which is where the rest of `CommandError`'s variants come
                        // from -- `reason_for` covers both.
                        Err(err) => log::mesh::host_command_rejected(reason_for(err)),
                        Ok(line) => match mesh_routing::parse_line(&line) {
                            Ok(cmd) => {
                                if host_cmd.try_send(cmd).is_err() {
                                    log::mesh::host_command_dropped();
                                }
                            }
                            Err(err) => log::mesh::host_command_rejected(reason_for(err)),
                        },
                    }
                }
            }
        }
    };

    join3(usb_run, log_run, cmd_run).await;
}

/// Which check failed, for the log line -- never a silent drop.
fn reason_for(err: CommandError) -> &'static [u8] {
    match err {
        CommandError::LineTooLong => b"line too long",
        CommandError::UnknownKeyword => b"unknown keyword (expected BCAST or UNI)",
        CommandError::MissingNodeId => b"UNI: missing node id",
        CommandError::MalformedNodeId => b"UNI: node id is not valid hex",
        CommandError::EmptyMessage => b"empty message text",
    }
}
