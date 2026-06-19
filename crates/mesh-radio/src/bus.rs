//! SPI bus abstraction for LoRa transceivers.

/// Minimal SPI bus used by SX1262 drivers (CS managed externally).
pub trait SpiLoRaBus {
    type Error;

    fn transfer(&mut self, write: &[u8], read: &mut [u8]) -> Result<(), Self::Error>;
}
