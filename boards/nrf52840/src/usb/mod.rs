//! USB CDC logging for field debug (Phase 4), plus host command input (Part C of H1).

use core::sync::atomic::{AtomicBool, Ordering};

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::channel::Channel;
use mesh_routing::HostCommand;

pub(crate) mod log;
mod task;

pub use task::usb_task;

/// A host-typed command, from the USB task to the radio task. Capacity 2, never unbounded, so
/// a flood of input cannot grow memory in this `no_std` binary; the radio task drains it with a
/// non-blocking receive (see `lora::radio_task`), so a full queue only drops and logs the
/// newest command rather than stalling anything. Both tasks run on the same single executor
/// with nothing in an interrupt handler touching this channel, so `ThreadModeRawMutex` is
/// enough -- no need for the heavier `CriticalSectionRawMutex`.
pub type HostCommandChannel = Channel<ThreadModeRawMutex, HostCommand, 2>;

static USB_CONNECTED: AtomicBool = AtomicBool::new(false);

pub fn set_usb_connected(connected: bool) {
    USB_CONNECTED.store(connected, Ordering::Relaxed);
}

/// True while a host has an open CDC session (used for power policy in `radio_task`).
pub fn is_usb_connected() -> bool {
    USB_CONNECTED.load(Ordering::Relaxed)
}

/// True while VBUS is present, whether or not a host opened the CDC port.
///
/// Battery reporting must key off bus power, not the log session: a node on a USB
/// charger or a host with the port closed is still externally powered.
pub fn is_usb_powered() -> bool {
    // nRF52840 POWER.USBREGSTATUS.VBUSDETECT (read-only).
    const NRF_POWER_USBREGSTATUS: *const u32 = 0x4000_0438 as *const u32;
    unsafe { core::ptr::read_volatile(NRF_POWER_USBREGSTATUS) & 1 != 0 }
}
