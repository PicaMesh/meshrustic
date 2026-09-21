//! Adafruit nRF52 bootloader entry.
//!
//! `GPREGRET = 0xA8` on a software reset is what the bootloader treats as BLE OTA.
//! A running watchdog cannot be stopped, and it keeps counting through that software
//! reset, so the bootloader would be reset again before a phone can connect. Waiting
//! for the watchdog to time out does stop it, but that reset comes back into this
//! application (seen on Mesh Lab: the app was running again one watchdog period
//! later, with no DFU session). The request is stored in `.uninit` RAM, which
//! survives that reset. The following boot, before the watchdog is armed, performs
//! the software reset the bootloader actually stays in.

use cortex_m::peripheral::SCB;

/// `DFU_MAGIC_SKIP` — boot the app, including past the double-reset window.
pub const DFU_MAGIC_SKIP: u32 = 0x6d;
/// `DFU_MAGIC_OTA_RESET` — BLE OTA, SoftDevice not yet started.
pub const DFU_MAGIC_OTA_RESET: u32 = 0xA8;

const NRF_POWER_GPREGRET: *mut u32 = 0x4000_051C as *mut u32;
const NRF_POWER_RESETREAS: *mut u32 = 0x4000_0400 as *mut u32;
/// Bootloader double-reset word. Cleared so a later pin reset is not a second tap.
const DFU_DBL_RESET_MEM: *mut u32 = 0x2000_7F7C as *mut u32;
/// `POWER.RESETREAS` bit 1, watchdog.
const RESETREAS_DOG: u32 = 1 << 1;
const OTA_STICKY_MAGIC: u32 = 0x0DF0_07A1;

#[used]
#[link_section = ".uninit"]
static mut OTA_STICKY: u32 = 0;

fn sticky_ptr() -> *mut u32 {
    core::ptr::addr_of_mut!(OTA_STICKY)
}

pub fn write_gpregret(magic: u32) {
    unsafe {
        core::ptr::write_volatile(NRF_POWER_GPREGRET, magic);
        core::ptr::write_volatile(DFU_DBL_RESET_MEM, 0);
    }
}

fn arm_sticky() {
    unsafe {
        core::ptr::write_volatile(sticky_ptr(), OTA_STICKY_MAGIC);
    }
}

fn take_sticky() -> bool {
    unsafe {
        let value = core::ptr::read_volatile(sticky_ptr());
        core::ptr::write_volatile(sticky_ptr(), 0);
        value == OTA_STICKY_MAGIC
    }
}

fn resetreas() -> u32 {
    unsafe { core::ptr::read_volatile(NRF_POWER_RESETREAS) }
}

fn clear_resetreas(value: u32) {
    unsafe {
        core::ptr::write_volatile(NRF_POWER_RESETREAS, value);
    }
}

/// First instruction of `main`, before the watchdog starts.
///
/// A watchdog timeout leaves this flag set and `RESETREAS.DOG` set, and leaves
/// the watchdog stopped. Soft-reset into OTA from there.
pub fn finish_ota_if_watchdog_reset() {
    let pending = take_sticky();
    let reason = resetreas();
    if !pending || reason & RESETREAS_DOG == 0 {
        return;
    }
    clear_resetreas(reason);
    write_gpregret(DFU_MAGIC_OTA_RESET);
    SCB::sys_reset();
}

/// Park until the watchdog resets the chip. `finish_ota_if_watchdog_reset`
/// completes the bootloader entry on the next boot.
pub fn park_for_watchdog_reset() -> ! {
    arm_sticky();
    loop {
        cortex_m::asm::wfi();
    }
}

/// Software reset into BLE OTA. Only safe when the watchdog is not running.
pub fn reset_into_ota_now() -> ! {
    let _ = take_sticky();
    write_gpregret(DFU_MAGIC_OTA_RESET);
    SCB::sys_reset();
}
