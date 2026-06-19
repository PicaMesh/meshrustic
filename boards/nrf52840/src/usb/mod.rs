//! USB CDC logging for field debug (Phase 4).

use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) mod log;
mod task;

pub use task::usb_task;

static USB_CONNECTED: AtomicBool = AtomicBool::new(false);

pub fn set_usb_connected(connected: bool) {
    USB_CONNECTED.store(connected, Ordering::Relaxed);
}

/// True while a host has an open CDC session (used for power policy in `radio_task`).
pub fn is_usb_connected() -> bool {
    USB_CONNECTED.load(Ordering::Relaxed)
}
