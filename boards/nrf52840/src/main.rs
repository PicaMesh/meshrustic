#![no_std]
#![no_main]

mod battery;
mod dfu;
mod lora;
mod node;
mod store;

#[path = "usb/mod.rs"]
mod usb_log;

use core::sync::atomic::{AtomicBool, Ordering};
use cortex_m_rt::{exception, ExceptionFrame};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_nrf::bind_interrupts;
use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
use embassy_nrf::nvmc::Nvmc;
use embassy_nrf::rng;
use embassy_nrf::saadc;
use embassy_nrf::spim;
use embassy_nrf::wdt;
use lora::{create_radio, radio_task, LoRaPins, Sx1262ModuleProfile};
use mesh_radio::{eu868_config_for_preset, RadioSlot};
use mesh_routing::Router;
use mesh_store::{ConfigStore, EMPTY_ADMIN_KEY};
use node::NodeIdentity;
use static_cell::{ConstStaticCell, StaticCell};
use store::{ConfigLoadSource, NvmcConfigStore};

/// Resetting after a fault restores service; the retained reset reason preserves diagnostic evidence.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Re-entering defmt during a logging panic would recurse into another panic.
    static PANICKING: AtomicBool = AtomicBool::new(false);
    if !PANICKING.swap(true, Ordering::SeqCst) {
        defmt::error!("panic: {}", defmt::Display2Format(info));
    }
    cortex_m::peripheral::SCB::sys_reset()
}

/// Faults bypass the Rust panic handler; resetting avoids leaving a permanently dead node.
#[exception]
unsafe fn HardFault(_frame: &ExceptionFrame) -> ! {
    cortex_m::peripheral::SCB::sys_reset()
}

bind_interrupts!(struct Irqs {
    RNG => rng::InterruptHandler<embassy_nrf::peripherals::RNG>;
    SPIM3 => spim::InterruptHandler<embassy_nrf::peripherals::SPI3>;
    USBD => embassy_nrf::usb::InterruptHandler<embassy_nrf::peripherals::USBD>;
    CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
    SAADC => saadc::InterruptHandler;
});

const WATCHDOG_TIMEOUT_SECS: u32 = 30;

static RADIO_SLOT: StaticCell<RadioSlot<lora::Sx1262Driver>> = StaticCell::new();
static ROUTER: ConstStaticCell<Router> = ConstStaticCell::new(Router::unconfigured());
static CONFIG_STORE: StaticCell<NvmcConfigStore> = StaticCell::new();
static HOST_CMD_CHANNEL: StaticCell<usb_log::HostCommandChannel> = StaticCell::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    dfu::clear_stale_ota_request();
    let mut hw_config = embassy_nrf::config::Config::default();
    hw_config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let p = embassy_nrf::init(hw_config);
    let mut wdt_config = wdt::Config::default();
    wdt_config.timeout_ticks = 32768 * WATCHDOG_TIMEOUT_SECS;
    wdt_config.action_during_sleep = wdt::SleepConfig::RUN;
    wdt_config.action_during_debug_halt = wdt::HaltConfig::PAUSE;
    let radio_wdt = match wdt::Watchdog::try_new::<1>(p.WDT, wdt_config) {
        Ok((_wdt, [handle])) => Some(handle),
        // An inherited watchdog configuration cannot be safely claimed by this firmware; recovery
        // requires a power cycle.
        Err(_) => None,
    };
    // Clearing stale reset reasons prevents an ordinary reset from being mistaken for the bootloader’s
    // double-reset trigger.
    let reset_reason = clear_resetreas();

    let mut rng = rng::Rng::new(p.RNG, Irqs);
    let mut identity_seed = [0; 32];
    rng.blocking_fill_bytes(&mut identity_seed);
    let hw = NodeIdentity::from_hardware(identity_seed);
    let defaults = hw.first_boot_config();
    let store = CONFIG_STORE.init(NvmcConfigStore::new(Nvmc::new(p.NVMC), defaults));
    let (mut config, load_src) = store.load_with_source();
    let upgraded_identity = hw.replace_predictable_key(&mut config);
    if (load_src == ConfigLoadSource::Defaults || upgraded_identity) && store.save(&config).is_err()
    {
        defmt::error!("failed to persist secure identity");
        usb_log::log::push_line("[store] secure identity save failed");
    }
    let admin_keys = config
        .admin_public_keys
        .iter()
        .filter(|k| *k != &EMPTY_ADMIN_KEY)
        .count() as u32;

    defmt::info!("[meshrustic] nodeId !{:08x}", config.node_num);
    usb_log::log::mesh::reset_reason(reset_reason);
    usb_log::log::push_line(if radio_wdt.is_some() {
        "[meshrustic] watchdog armed: 30 s, pet by the radio task"
    } else {
        "[meshrustic] watchdog NOT armed: earlier firmware left the WDT running; resets until power-cycled"
    });
    usb_log::log::mesh::config_boot(load_src == ConfigLoadSource::Flash, admin_keys);
    defmt::info!(
        "[store] boot preset={} from_flash={}",
        config.lora.modem_preset,
        load_src == ConfigLoadSource::Flash
    );

    defmt::info!("meshrustic nrf52840");
    let _ = lora::dual_radio::SECOND_RADIO_ID;
    let _ = lora::dual_radio::bridge_target_capacity();

    let mut spi_cfg = spim::Config::default();
    spi_cfg.frequency = spim::Frequency::M4;
    let spim = spim::Spim::new(p.SPI3, Irqs, p.P1_11, p.P0_02, p.P1_15, spi_cfg);

    let cs = Output::new(p.P1_13, Level::High, OutputDrive::Standard);
    // SAFETY: both DIO1 handles are identical inputs and never drive the line; only the wake handle
    // allocates a GPIOTE channel. The driver must retain its input for blocking transmission.
    let dio1_wake = Input::new(
        unsafe { embassy_nrf::Peripheral::clone_unchecked(&p.P0_10) },
        Pull::None,
    );
    let lora_pins = LoRaPins::power_on(p.P0_13, p.P0_09, p.P0_29, p.P0_10);
    let mut driver = create_radio(spim, cs, lora_pins, Sx1262ModuleProfile::default_board());
    let mut radio_config =
        eu868_config_for_preset(mesh_radio::normalize_modem_preset(config.lora.modem_preset));
    radio_config.hop_limit = config.lora.hop_limit;
    radio_config.tx_power_dbm = config.lora.tx_power_dbm.min(mesh_radio::MAX_TX_POWER_DBM) as i8;
    driver.set_radio_config(radio_config);
    let slot = RADIO_SLOT.init(RadioSlot::new(0, driver));

    let router = ROUTER.take();
    let mut seed = [0u8; 4];
    rng.blocking_fill_bytes(&mut seed);
    router.seed_tx_ids(u32::from_le_bytes(seed));
    router.load_node_config(&config);
    router.set_bridge_enabled(false);
    router.set_node_identity(mesh_routing::NodeInfoIdentity::for_node(
        config.node_num,
        config.public_key,
    ));
    // Boot-time identity and role logs can be evicted before a host connects, so connection-time logs
    // must carry them.
    let own_role = router.device_role();
    usb_log::publish_device_role(own_role);
    usb_log::log::mesh::device_role(own_role);

    let host_cmd_channel = HOST_CMD_CHANNEL.init(usb_log::HostCommandChannel::new());
    spawner
        .spawn(usb_log::usb_task(p.USBD, config.node_num, host_cmd_channel))
        .unwrap();
    let saadc_config = saadc::Config::default();
    let mut saadc_channel = saadc::ChannelConfig::single_ended(p.P0_31);
    // The software conversion reference must agree with the configured ADC gain and reference.
    saadc_channel.reference = saadc::Reference::INTERNAL;
    saadc_channel.gain = saadc::Gain::GAIN1_6;
    // The high-impedance battery divider needs a longer acquisition time to charge the ADC sample
    // capacitor accurately.
    saadc_channel.time = saadc::Time::_40US;
    let saadc = saadc::Saadc::new(p.SAADC, Irqs, saadc_config, [saadc_channel]);
    spawner.spawn(battery::battery_task(saadc)).unwrap();
    spawner
        .spawn(radio_task::radio_task(
            slot,
            router,
            store,
            config.node_num,
            radio_wdt,
            host_cmd_channel,
            dio1_wake,
        ))
        .unwrap();

    core::future::pending().await
}

fn clear_resetreas() -> u32 {
    const NRF_POWER_RESETREAS: *mut u32 = 0x4000_0400 as *mut u32;
    unsafe {
        let v = core::ptr::read_volatile(NRF_POWER_RESETREAS);
        core::ptr::write_volatile(NRF_POWER_RESETREAS, v);
        v
    }
}
