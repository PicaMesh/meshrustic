#![no_std]
#![no_main]

mod battery;
mod lora;
mod node;
mod store;

#[path = "usb/mod.rs"]
mod usb_log;

use embassy_executor::Spawner;
use embassy_nrf::bind_interrupts;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::nvmc::Nvmc;
use embassy_nrf::saadc;
use embassy_nrf::spim;
use lora::{create_radio, radio_task, LoRaPins, Sx1262ModuleProfile};
use mesh_radio::{eu868_config_for_preset, RadioSlot};
use mesh_routing::Router;
use mesh_store::EMPTY_ADMIN_KEY;
use node::NodeIdentity;
use static_cell::StaticCell;
use store::{ConfigLoadSource, NvmcConfigStore};
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    SPIM3 => spim::InterruptHandler<embassy_nrf::peripherals::SPI3>;
    USBD => embassy_nrf::usb::InterruptHandler<embassy_nrf::peripherals::USBD>;
    CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
    SAADC => saadc::InterruptHandler;
});

static RADIO_SLOT: StaticCell<RadioSlot<lora::Sx1262Driver>> = StaticCell::new();
static ROUTER: StaticCell<Router> = StaticCell::new();
static CONFIG_STORE: StaticCell<NvmcConfigStore> = StaticCell::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());
    // Adafruit UF2 bootloader leaves RESETREAS set; clear so a later soft-reset
    // is not mistaken for a pin double-reset into upload mode.
    clear_resetreas();

    let hw = NodeIdentity::from_hardware();
    let defaults = hw.first_boot_config();
    let store = CONFIG_STORE.init(NvmcConfigStore::new(Nvmc::new(p.NVMC), defaults));
    let (config, load_src) = store.load_with_source();
    let admin_keys = config
        .admin_public_keys
        .iter()
        .filter(|k| *k != &EMPTY_ADMIN_KEY)
        .count() as u32;

    defmt::info!("[meshrustic] nodeId !{:08x}", config.node_num);
    usb_log::log::mesh::node_id(config.node_num);
    usb_log::log::mesh::config_boot(load_src == ConfigLoadSource::Flash, admin_keys);

    defmt::info!("meshrustic nrf52840");
    let _ = lora::dual_radio::SECOND_RADIO_ID;
    let _ = lora::dual_radio::bridge_target_capacity();

    let mut spi_cfg = spim::Config::default();
    spi_cfg.frequency = spim::Frequency::M4;
    let spim = spim::Spim::new(p.SPI3, Irqs, p.P1_11, p.P0_02, p.P1_15, spi_cfg);

    let cs = Output::new(p.P1_13, Level::High, OutputDrive::Standard);
    let lora_pins = LoRaPins::power_on(p.P0_13, p.P0_09, p.P0_29, p.P0_10);
    let mut driver = create_radio(spim, cs, lora_pins, Sx1262ModuleProfile::default_board());
    driver.set_radio_config(eu868_config_for_preset(config.lora.modem_preset));
    let slot = RADIO_SLOT.init(RadioSlot::new(0, driver));

    let router = ROUTER.init(Router::new(config.node_num));
    router.load_node_config(&config);
    router.set_node_identity(mesh_routing::NodeInfoIdentity::for_node(
        config.node_num,
        config.public_key,
    ));

    spawner.spawn(usb_log::usb_task(p.USBD)).unwrap();
    let saadc_config = saadc::Config::default();
    let saadc_channel = saadc::ChannelConfig::single_ended(p.P0_31);
    let saadc = saadc::Saadc::new(p.SAADC, Irqs, saadc_config, [saadc_channel]);
    spawner.spawn(battery::battery_task(saadc)).unwrap();
    spawner
        .spawn(radio_task::radio_task(slot, router, store, config.node_num))
        .unwrap();

    core::future::pending().await
}

fn clear_resetreas() {
    // nRF52840 POWER.RESETREAS — write 1 to clear sticky bits.
    const NRF_POWER_RESETREAS: *mut u32 = 0x4000_0400 as *mut u32;
    unsafe {
        let v = core::ptr::read_volatile(NRF_POWER_RESETREAS);
        core::ptr::write_volatile(NRF_POWER_RESETREAS, v);
    }
}
