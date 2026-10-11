#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoKey {
    pub bytes: [u8; 32],
    pub(crate) length: i8,
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

    pub const fn len(&self) -> usize {
        self.length as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn is_enabled(&self) -> bool {
        self.length > 0
    }
}
