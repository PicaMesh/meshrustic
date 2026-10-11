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

pub trait RadioInterface {
    fn radio_id(&self) -> RadioId;

    fn config(&self) -> &RadioConfig;

    fn init(&mut self) -> Result<(), RadioError>;

    fn poll_recv(&mut self) -> Result<Option<RxFrame>, RadioError>;

    fn send(&mut self, frame: &TxFrame) -> Result<(), RadioError>;

    fn start_rx(&mut self) -> Result<(), RadioError>;

    /// Transmitting during reception would corrupt both the incoming frame and our copy.
    fn rx_in_progress(&mut self) -> Result<bool, RadioError> {
        Ok(false)
    }
}
