#![no_std]
#![no_main]

mod battery;
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
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::nvmc::Nvmc;
use embassy_nrf::rng;
use embassy_nrf::saadc;
use embassy_nrf::spim;
use embassy_nrf::wdt;
use lora::{create_radio, radio_task, LoRaPins, Sx1262ModuleProfile};
use mesh_radio::{eu868_config_for_preset, RadioSlot};
use mesh_routing::Router;
use mesh_store::EMPTY_ADMIN_KEY;
use node::NodeIdentity;
use static_cell::{ConstStaticCell, StaticCell};
use store::{ConfigLoadSource, NvmcConfigStore};

/// Reset instead of halting. `panic_probe` parks the core, which in the field is a dead node
/// until someone power-cycles it: both nicenanos sat silent for two hours after a log line
/// overran its buffer. Nobody reads the defmt message without a probe, so a restart loses
/// nothing; the boot log shows `reset reason` SREQ so a panic reboot stays visible.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // defmt-rtt panics when acquired re-entrantly, so a panic raised while a log line was being
    // written would recurse through here into a stack overflow. Log once, then reset regardless.
    static PANICKING: AtomicBool = AtomicBool::new(false);
    if !PANICKING.swap(true, Ordering::SeqCst) {
        defmt::error!("panic: {}", defmt::Display2Format(info));
    }
    cortex_m::peripheral::SCB::sys_reset()
}

/// Faults (stack overflow, bus fault, unaligned access) do not reach the panic handler. The
/// cortex-m-rt default HardFault handler spins forever, the same dead-node outcome, so reset.
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
// Const-initialised so the ~70 KB router is placed by the linker, never built on the stack
// (see `Router::unconfigured`). `load_node_config` below gives it its node id and channel.
static ROUTER: ConstStaticCell<Router> = ConstStaticCell::new(Router::unconfigured());
static CONFIG_STORE: StaticCell<NvmcConfigStore> = StaticCell::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut hw_config = embassy_nrf::config::Config::default();
    // The nRF52840 USBD needs HFCLK from the external 32 MHz crystal: full-speed USB
    // tolerates 0.25 % clock error and the internal RC is only good to ~1.5 %, so on the
    // RC some units enumerate and others never show up on the host.
    hw_config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let p = embassy_nrf::init(hw_config);
    // Hardware watchdog: the panic and HardFault handlers cover crashes, this covers hangs (a task
    // that never yields stalls the whole cooperative executor). The radio task pets it on every
    // pass of its loop, which sleeps at most 100 ms; 30 s leaves room for a full-length TX and
    // an NVMC page erase. It keeps counting in sleep and pauses under a debugger. A WDT reset
    // shows up as `reset reason ... DOG` in the boot log.
    let mut wdt_config = wdt::Config::default();
    wdt_config.timeout_ticks = 32768 * WATCHDOG_TIMEOUT_SECS;
    wdt_config.action_during_sleep = wdt::SleepConfig::RUN;
    wdt_config.action_during_debug_halt = wdt::HaltConfig::PAUSE;
    let radio_wdt = match wdt::Watchdog::try_new::<1>(p.WDT, wdt_config) {
        Ok((_wdt, [handle])) => Some(handle),
        // Already running with a different setup (nothing we ship does this): we cannot pet an
        // unknown configuration, so run without and say so.
        Err(_) => None,
    };
    // Adafruit UF2 bootloader leaves RESETREAS set; clear so a later soft-reset
    // is not mistaken for a pin double-reset into upload mode. Keep the value for the boot log:
    // bit 0 RESETPIN, bit 1 DOG, bit 2 SREQ (panic handler / soft reset), bit 3 LOCKUP.
    let reset_reason = clear_resetreas();

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
    usb_log::log::mesh::reset_reason(reset_reason);
    usb_log::log::push_line(if radio_wdt.is_some() {
        "[meshrustic] watchdog armed: 30 s, pet by the radio task"
    } else {
        "[meshrustic] watchdog NOT armed: WDT already running with another configuration"
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
    let lora_pins = LoRaPins::power_on(p.P0_13, p.P0_09, p.P0_29, p.P0_10);
    let mut driver = create_radio(spim, cs, lora_pins, Sx1262ModuleProfile::default_board());
    driver.set_radio_config(eu868_config_for_preset(config.lora.modem_preset));
    let slot = RADIO_SLOT.init(RadioSlot::new(0, driver));

    let router = ROUTER.take();
    // Packet ids must differ between boots and between nodes: seed them from the RNG peripheral
    // before the config load queues the first frames (the boot broadcast and nodeinfo).
    let mut seed = [0u8; 4];
    rng::Rng::new(p.RNG, Irqs).blocking_fill_bytes(&mut seed);
    router.seed_tx_ids(u32::from_le_bytes(seed));
    router.load_node_config(&config);
    router.set_node_identity(mesh_routing::NodeInfoIdentity::for_node(
        config.node_num,
        config.public_key,
    ));

    spawner.spawn(usb_log::usb_task(p.USBD)).unwrap();
    let saadc_config = saadc::Config::default();
    let mut saadc_channel = saadc::ChannelConfig::single_ended(p.P0_31);
    // Internal 0.6 V reference with gain 1/6 -> 3.6 V full scale; keep it explicit so
    // battery::AREF_VOLTAGE cannot drift away from the hardware setting.
    saadc_channel.reference = saadc::Reference::INTERNAL;
    saadc_channel.gain = saadc::Gain::GAIN1_6;
    // The 1M + 1M VBAT divider is a ~500 kOhm source; the nRF52840 needs 40 us of
    // acquisition above 400 kOhm. At the 10 us default the sample-and-hold cap never
    // charges and the reading droops below MIN_BATTERY_MV, which makes the node fall
    // back to the "USB powered" (101) telemetry level.
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
        ))
        .unwrap();

    core::future::pending().await
}

/// Clear nRF52840 POWER.RESETREAS (write 1 to clear sticky bits) and return what it held.
fn clear_resetreas() -> u32 {
    const NRF_POWER_RESETREAS: *mut u32 = 0x4000_0400 as *mut u32;
    unsafe {
        let v = core::ptr::read_volatile(NRF_POWER_RESETREAS);
        core::ptr::write_volatile(NRF_POWER_RESETREAS, v);
        v
    }
}
