//! Radio driver trait for LoRa modules.

use crate::config::RadioConfig;
use crate::frame::{RadioId, RxFrame, TxFrame};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadioError {
    InitFailed,
    Busy,
    Timeout,
    InvalidLength,
    Hardware,
}

/// Chip-level radio operations implemented by each board backend.
pub trait RadioInterface {
    fn radio_id(&self) -> RadioId;

    fn config(&self) -> &RadioConfig;

    fn init(&mut self) -> Result<(), RadioError>;

    /// Non-blocking poll for a received frame.
    fn poll_recv(&mut self) -> Result<Option<RxFrame>, RadioError>;

    /// Transmit a frame. Caller must enforce duty cycle via [`crate::AirTime`].
    fn send(&mut self, frame: &TxFrame) -> Result<(), RadioError>;

    /// Return to continuous RX after TX.
    fn start_rx(&mut self) -> Result<(), RadioError>;

    /// True while a frame is being received (preamble seen, payload not yet complete).
    /// Transmitting now would destroy that frame and the copy we send. Backends that cannot
    /// tell report `false`.
    fn rx_in_progress(&mut self) -> Result<bool, RadioError> {
        Ok(false)
    }
}
