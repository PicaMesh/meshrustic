use crate::config::RadioConfig;
use crate::frame::{RadioId, RxFrame, TxFrame};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadioError {
    InitFailed,
    Busy,
    Timeout,
    InvalidLength,
    InvalidConfig,
    TxNotStarted,
    TxOutcomeUnknown,
    Hardware,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    Complete,
    OutcomeUnknown,
}

pub trait RadioInterface {
    fn radio_id(&self) -> RadioId;

    fn config(&self) -> &RadioConfig;

    fn init(&mut self) -> Result<(), RadioError>;

    fn poll_recv(&mut self) -> Result<Option<RxFrame>, RadioError>;

    fn start_send(&mut self, frame: &TxFrame) -> Result<(), RadioError>;

    fn poll_tx(&mut self) -> Result<Option<TxStatus>, RadioError> {
        Ok(Some(TxStatus::Complete))
    }

    fn start_rx(&mut self) -> Result<(), RadioError>;

    /// Transmitting during reception would corrupt both the incoming frame and our copy.
    fn rx_in_progress(&mut self) -> Result<bool, RadioError> {
        Ok(false)
    }
}
