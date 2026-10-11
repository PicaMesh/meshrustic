//! A running watchdog survives software reset and would eject the bootloader before a phone can connect.

use cortex_m::peripheral::SCB;

pub const DFU_MAGIC_SKIP: u32 = 0x6d;
pub const DFU_MAGIC_OTA_RESET: u32 = 0xA8;

const NRF_POWER_GPREGRET: *mut u32 = 0x4000_051C as *mut u32;
const DFU_DBL_RESET_MEM: *mut u32 = 0x2000_7F7C as *mut u32;
const NRF_WDT_INTENCLR: *mut u32 = 0x4001_0308 as *mut u32;
const WDT_INTEN_TIMEOUT: u32 = 1;

/// A stale DFU request would send the next ordinary reset back into the bootloader.
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

fn silence_watchdog_irq() {
    unsafe {
        core::ptr::write_volatile(NRF_WDT_INTENCLR, WDT_INTEN_TIMEOUT);
    }
}

pub fn park_for_watchdog_reset() -> ! {
    write_gpregret(DFU_MAGIC_OTA_RESET);
    silence_watchdog_irq();
    loop {
        cortex_m::asm::wfi();
    }
}

pub fn reset_into_ota_now() -> ! {
    write_gpregret(DFU_MAGIC_OTA_RESET);
    SCB::sys_reset();
}
