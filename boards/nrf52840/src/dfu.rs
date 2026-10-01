//! Adafruit nRF52 bootloader entry.
//!
//! `GPREGRET = 0xA8` is what the bootloader treats as BLE OTA, on any reset that
//! leaves the register intact. A running watchdog cannot be stopped, and it keeps
//! counting through a software reset, so that reset would kick the bootloader back
//! out before a phone can connect. A watchdog timeout does stop it. The register
//! is armed first and the core waits for that timeout; the timeout itself is the
//! bootloader entry.
//!
//! Do not stash the request in application RAM. The nicenano bootloader uses the
//! same RAM as this image and puts its stack at the top, which is where `.uninit`
//! lands. A flag there is gone by the time the application runs again.
//!
//! Entry goes through `dfu_init`, which arms the bootloader's inactivity timer
//! (six minutes, restarted by each transfer packet). When that timer fires and
//! nobody is connected, the bootloader starts this application. Nothing in this
//! image may request DFU again on that boot.

use cortex_m::peripheral::SCB;

/// `DFU_MAGIC_SKIP` — boot the app, including past the double-reset window.
pub const DFU_MAGIC_SKIP: u32 = 0x6d;
/// `DFU_MAGIC_OTA_RESET` — BLE OTA, SoftDevice not yet started.
pub const DFU_MAGIC_OTA_RESET: u32 = 0xA8;

const NRF_POWER_GPREGRET: *mut u32 = 0x4000_051C as *mut u32;
/// Bootloader double-reset word. Cleared so a later pin reset is not a second tap.
const DFU_DBL_RESET_MEM: *mut u32 = 0x2000_7F7C as *mut u32;
/// `WDT.INTENCLR`. Embassy enables the TIMEOUT interrupt and nothing handles it.
const NRF_WDT_INTENCLR: *mut u32 = 0x4001_0308 as *mut u32;
const WDT_INTEN_TIMEOUT: u32 = 1;

/// Drop a BLE-OTA request if this image is running.
///
/// The bootloader clears `GPREGRET` on the way into DFU, then starts the
/// application again after the inactivity timeout. A value left behind would
/// turn the next soft reset into another DFU session.
pub fn clear_stale_ota_request() {
    unsafe {
        if core::ptr::read_volatile(NRF_POWER_GPREGRET) == DFU_MAGIC_OTA_RESET {
            core::ptr::write_volatile(NRF_POWER_GPREGRET, 0);
        }
    }
}

pub fn write_gpregret(magic: u32) {
    unsafe {
        core::ptr::write_volatile(NRF_POWER_GPREGRET, magic);
        core::ptr::write_volatile(DFU_DBL_RESET_MEM, 0);
    }
}

/// Drop the TIMEOUT interrupt so the expiry is a watchdog reset, not an
/// unhandled IRQ into the default handler. The counter keeps running.
fn silence_watchdog_irq() {
    unsafe {
        core::ptr::write_volatile(NRF_WDT_INTENCLR, WDT_INTEN_TIMEOUT);
    }
}

/// Arm BLE OTA, then wait until the watchdog resets the chip into the bootloader.
pub fn park_for_watchdog_reset() -> ! {
    write_gpregret(DFU_MAGIC_OTA_RESET);
    silence_watchdog_irq();
    loop {
        cortex_m::asm::wfi();
    }
}

/// Software reset into BLE OTA. Only safe when the watchdog is not running.
pub fn reset_into_ota_now() -> ! {
    write_gpregret(DFU_MAGIC_OTA_RESET);
    SCB::sys_reset();
}
