/// Channel AES key (128- or 256-bit). `length == 0` means no encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoKey {
    pub bytes: [u8; 32],
    pub length: i8,
}

impl CryptoKey {
    pub const fn none() -> Self {
        Self {
            bytes: [0; 32],
            length: 0,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut key = Self::none();
        let len = bytes.len();
        if len == 16 || len == 32 {
            key.bytes[..len].copy_from_slice(bytes);
            key.length = len as i8;
        }
        key
    }

    pub fn is_enabled(&self) -> bool {
        self.length > 0
    }
}
