pub trait SpiLoRaBus {
    type Error;

    fn transfer(&mut self, write: &[u8], read: &mut [u8]) -> Result<(), Self::Error>;
}
