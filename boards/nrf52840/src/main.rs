#![no_std]
#![no_main]

mod battery;
mod dfu;
mod lora;
mod node;
mod store;

#[path = "usb/mod.rs"]
mod usb_log;

use core::cell::RefCell;
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

/// The watchdog handle lives in a critical section so that the boot path and
/// the radio task can both feed it. The radio task is spawned late, and a
/// watchdog that was adopted from an earlier image can have a short period:
/// nothing may let it expire while the node is still booting.
static WATCHDOG: critical_section::Mutex<RefCell<Option<embassy_nrf::wdt::WatchdogHandle>>> =
    critical_section::Mutex::new(RefCell::new(None));

/// Feed the watchdog, if one is armed.
fn pet_watchdog() {
    critical_section::with(|cs| {
        if let Some(handle) = WATCHDOG.borrow_ref_mut(cs).as_mut() {
            handle.pet();
        }
    });
}

/// Whether a watchdog is armed. The DFU park needs to know: it waits for the
/// watchdog to reset the node into the bootloader.
pub fn watchdog_armed() -> bool {
    critical_section::with(|cs| WATCHDOG.borrow_ref(cs).is_some())
}

/// The counter the watchdog runs with, in 32.768 kHz ticks.
///
/// The register is read back rather than taken from the configuration: the
/// value that was asked for is not necessarily the value the register can
/// hold, and the effective period is what the boot path has to live with.
fn watchdog_counter() -> u32 {
    const NRF_WDT_CRV: *const u32 = 0x4001_0504 as *const u32;
    // SAFETY: the watchdog counter register is always readable, and the
    // address is the one the nRF52840 reference manual gives for it.
    unsafe { core::ptr::read_volatile(NRF_WDT_CRV) }
}

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
    // A watchdog left running by an earlier image cannot be reconfigured while
    // it runs, and the peripheral refuses a configuration that differs from the
    // running one. Adopting the running configuration keeps the node
    // self-healing instead of leaving it without any watchdog at all.
    if let Some(running) = wdt::Config::try_new(&p.WDT) {
        wdt_config = running;
    }
    let radio_wdt = match wdt::Watchdog::try_new::<1>(p.WDT, wdt_config) {
        Ok((_wdt, [handle])) => Some(handle),
        // The running configuration uses a different channel count, so it cannot
        // be adopted and the peripheral cannot be reprogrammed while it runs.
        Err(_) => None,
    };
    let watchdog_armed = radio_wdt.is_some();
    if let Some(handle) = radio_wdt {
        critical_section::with(|cs| *WATCHDOG.borrow_ref_mut(cs) = Some(handle));
    }
    // The counter the peripheral really runs with, read back rather than
    // assumed: the value that was asked for is not necessarily the value the
    // register can hold, and the effective period is what decides whether the
    // boot path has to hurry.
    let watchdog_secs = if watchdog_armed {
        watchdog_counter() / 32768
    } else {
        0
    };
    // Clearing stale reset reasons prevents an ordinary reset from being mistaken for the bootloader’s
    // double-reset trigger.
    let reset_reason = clear_resetreas();

    let mut rng = rng::Rng::new(p.RNG, Irqs);
    // A degenerate random draw would give the node a predictable identity, so
    // it is drawn again rather than used. The three draws are independent:
    // the identity seed, the packet-id seed (which is the channel-encryption
    // nonce) and the direct-message nonce seed.
    let mut identity_seed = [0; 32];
    let identity_ok = draw_random(&mut rng, &mut identity_seed).await;
    pet_watchdog();
    let mut tx_seed_bytes = [0u8; 4];
    let tx_seed_ok = draw_random(&mut rng, &mut tx_seed_bytes).await;
    pet_watchdog();
    let mut pki_secret = [0u8; 32];
    let pki_ok = draw_random(&mut rng, &mut pki_secret).await;
    pet_watchdog();
    let randomness_ok = identity_ok && tx_seed_ok && pki_ok;
    if !randomness_ok {
        defmt::error!("[meshrustic] the random source did not answer");
        usb_log::log::push_line(
            "[meshrustic] random source unavailable: the node stays off the mesh",
        );
    }
    let hw = NodeIdentity::from_hardware(identity_seed);

    let defaults = hw.first_boot_config();
    let store = CONFIG_STORE.init(NvmcConfigStore::new(Nvmc::new(p.NVMC), defaults));
    let (mut config, load_src) = store.load_with_source();
    // A node whose identity could not be drawn must not persist the guessable
    // key it would otherwise fall back to.
    let upgraded_identity = identity_ok && hw.replace_predictable_key(&mut config);
    if randomness_ok
        && (load_src == ConfigLoadSource::Defaults || upgraded_identity)
        && store.save(&config).is_err()
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
    usb_log::log::push_line(if watchdog_armed {
        "[meshrustic] watchdog armed, pet by the radio task"
    } else {
        "[meshrustic] watchdog NOT armed: the peripheral refused this configuration"
    });
    usb_log::log::mesh::watchdog_state(watchdog_secs);
    usb_log::log::mesh::config_boot(load_src == ConfigLoadSource::Flash, admin_keys);
    defmt::info!(
        "[store] boot preset={} from_flash={}",
        config.lora.modem_preset,
        load_src == ConfigLoadSource::Flash
    );

    defmt::info!("meshrustic nrf52840");
    let _ = lora::dual_radio::SECOND_RADIO_ID;
    let _ = lora::dual_radio::bridge_target_capacity();

    // The console comes up first: a node that cannot run has to be able to
    // say why.
    let host_cmd_channel = HOST_CMD_CHANNEL.init(usb_log::HostCommandChannel::new());
    spawner
        .spawn(usb_log::usb_task(p.USBD, config.node_num, host_cmd_channel))
        .unwrap();
    pet_watchdog();

    if !randomness_ok {
        // Without usable randomness the node has either a guessable identity
        // or a channel-encryption nonce that repeats after every reboot. Both
        // are worse than being off the mesh, so the node stays off it: it
        // keeps the console and the watchdog alive and reports the fault.
        loop {
            pet_watchdog();
            usb_log::log::push_line(
                "[meshrustic] the node is off the mesh: no usable random source",
            );
            embassy_time::Timer::after_secs(5).await;
        }
    }

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
    // A second handle on the busy and interrupt lines, so the driver can
    // observe them. They are inputs that never drive the line.
    //
    // SAFETY: the probe handles read the same pins as the chip driver. Both
    // are inputs with no pull, so they agree on the level and neither of them
    // drives the line. The invariant this relies on is that the chip driver
    // never reconfigures those two pins: it only reads them.
    let busy_probe = Input::new(
        unsafe { embassy_nrf::Peripheral::clone_unchecked(&p.P0_29) },
        Pull::None,
    );
    let dio1_probe = Input::new(
        unsafe { embassy_nrf::Peripheral::clone_unchecked(&p.P0_10) },
        Pull::None,
    );
    let lora_pins = LoRaPins::power_on(p.P0_13, p.P0_09, p.P0_29, p.P0_10, busy_probe, dio1_probe);
    let mut driver = create_radio(spim, cs, lora_pins, Sx1262ModuleProfile::default_board());
    let mut radio_config =
        eu868_config_for_preset(mesh_radio::normalize_modem_preset(config.lora.modem_preset));
    radio_config.hop_limit = config.lora.effective_hop_limit();
    radio_config.tx_power_dbm = config.lora.tx_power_dbm.min(mesh_radio::MAX_TX_POWER_DBM) as i8;
    driver.set_radio_config(radio_config);
    let slot = RADIO_SLOT.init(RadioSlot::new(0, driver));

    let router = ROUTER.take();
    // The packet ids are the channel-encryption nonce, so a counter that always
    // restarts at the same value would repeat the nonce after every reboot.
    let mut tx_seed = u32::from_le_bytes(tx_seed_bytes);
    if tx_seed == 0 {
        tx_seed = 1; // packet id zero is reserved
    }
    router.seed_tx_ids(tx_seed);
    // An independent draw seeds the direct-message nonce.
    router.seed_pki_secret(pki_secret);
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

/// Draw random bytes with a deadline.
///
/// The random source is a peripheral, and waiting for it without a bound would
/// hang the node before the watchdog exists. A draw that times out or comes
/// back all zero is retried, because a degenerate value would make the node
/// identity predictable and would restart the packet-id counter, which repeats
/// the channel-encryption nonce.
async fn draw_random(
    rng: &mut rng::Rng<'static, embassy_nrf::peripherals::RNG>,
    out: &mut [u8],
) -> bool {
    const DRAW_TIMEOUT: embassy_time::Duration = embassy_time::Duration::from_millis(200);
    for _ in 0..4 {
        if embassy_time::with_timeout(DRAW_TIMEOUT, rng.fill_bytes(out))
            .await
            .is_ok()
            && out.iter().any(|&b| b != 0)
        {
            return true;
        }
    }
    false
}
