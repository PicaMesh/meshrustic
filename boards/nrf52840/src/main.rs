#![no_std]
#![no_main]

mod battery;
mod lora;
mod node;

#[path = "usb/mod.rs"]
mod usb_log;

use embassy_executor::Spawner;
use embassy_nrf::bind_interrupts;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::saadc;
use embassy_nrf::spim;
use lora::{create_radio, radio_task, LoRaPins, Sx1262ModuleProfile};
use mesh_radio::RadioSlot;
use mesh_routing::Router;
use node::NodeIdentity;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    SPIM3 => spim::InterruptHandler<embassy_nrf::peripherals::SPI3>;
    USBD => embassy_nrf::usb::InterruptHandler<embassy_nrf::peripherals::USBD>;
    CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
    SAADC => saadc::InterruptHandler;
});

static RADIO_SLOT: StaticCell<RadioSlot<lora::Sx1262Driver>> = StaticCell::new();
static ROUTER: StaticCell<Router> = StaticCell::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());

    let node = NodeIdentity::from_hardware();
    defmt::info!("[meshrustic] nodeId !{:08x}", node.node_num);
    usb_log::log::mesh::node_id(node.node_num);

    defmt::info!("meshrustic nrf52840");
    let _ = lora::dual_radio::SECOND_RADIO_ID;
    let _ = lora::dual_radio::bridge_target_capacity();

    let mut spi_cfg = spim::Config::default();
    spi_cfg.frequency = spim::Frequency::M4;
    let spim = spim::Spim::new(p.SPI3, Irqs, p.P1_11, p.P0_02, p.P1_15, spi_cfg);

    let cs = Output::new(p.P1_13, Level::High, OutputDrive::Standard);
    let lora_pins = LoRaPins::power_on(p.P0_13, p.P0_09, p.P0_29, p.P0_10);
    let driver = create_radio(spim, cs, lora_pins, Sx1262ModuleProfile::default_board());
    let slot = RADIO_SLOT.init(RadioSlot::new(0, driver));
    let router = ROUTER.init(Router::new(node.node_num));
    router.set_node_identity(node.nodeinfo_identity());

    spawner.spawn(usb_log::usb_task(p.USBD)).unwrap();
    let saadc_config = saadc::Config::default();
    let saadc_channel = saadc::ChannelConfig::single_ended(p.P0_31);
    let saadc = saadc::Saadc::new(p.SAADC, Irqs, saadc_config, [saadc_channel]);
    spawner.spawn(battery::battery_task(saadc)).unwrap();
    spawner
        .spawn(radio_task::radio_task(slot, router, node.node_num))
        .unwrap();

    core::future::pending().await
}
