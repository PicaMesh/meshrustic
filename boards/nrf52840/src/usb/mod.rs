use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::channel::Channel;
use mesh_routing::HostCommand;

pub(crate) mod log;
mod task;

pub use task::usb_task;

/// A bounded command channel prevents USB input floods from exhausting RAM or blocking the radio task.
pub type HostCommandChannel = Channel<ThreadModeRawMutex, HostCommand, 2>;

static USB_CONNECTED: AtomicBool = AtomicBool::new(false);
/// The USB task cannot borrow the router owned by the radio task.
static PUBLISHED_DEVICE_ROLE: AtomicU32 = AtomicU32::new(0);

pub fn set_usb_connected(connected: bool) {
    USB_CONNECTED.store(connected, Ordering::Relaxed);
}

pub fn is_usb_connected() -> bool {
    USB_CONNECTED.load(Ordering::Relaxed)
}

pub fn publish_device_role(role: u32) {
    PUBLISHED_DEVICE_ROLE.store(role, Ordering::Relaxed);
}

pub(crate) fn published_device_role() -> u32 {
    PUBLISHED_DEVICE_ROLE.load(Ordering::Relaxed)
}

pub fn is_usb_powered() -> bool {
    const NRF_POWER_USBREGSTATUS: *const u32 = 0x4000_0438 as *const u32;
    unsafe { core::ptr::read_volatile(NRF_POWER_USBREGSTATUS) & 1 != 0 }
}
