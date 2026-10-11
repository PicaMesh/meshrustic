use crate::config::PACKET_HEADER_LEN;

pub type RadioId = u8;

pub const MAX_RADIOS: usize = 2;

pub const MAX_BRIDGE_TARGETS: usize = MAX_RADIOS.saturating_sub(1);

pub const MAX_LORA_PAYLOAD: usize = 255;

#[derive(Clone, Copy)]
pub struct RxFrame {
    pub radio_id: RadioId,
    pub rssi: i16,
    pub snr: i8,
    pub len: u8,
    pub bytes: [u8; MAX_LORA_PAYLOAD],
}

impl RxFrame {
    pub const fn empty(radio_id: RadioId) -> Self {
        Self {
            radio_id,
            rssi: 0,
            snr: 0,
            len: 0,
            bytes: [0; MAX_LORA_PAYLOAD],
        }
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn header(&self) -> Option<&[u8; PACKET_HEADER_LEN]> {
        if self.len as usize >= PACKET_HEADER_LEN {
            Some(self.bytes[..PACKET_HEADER_LEN].try_into().ok()?)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
pub struct TxFrame {
    pub radio_id: RadioId,
    pub len: u8,
    pub bytes: [u8; MAX_LORA_PAYLOAD],
}

impl TxFrame {
    pub fn new(radio_id: RadioId, data: &[u8]) -> Option<Self> {
        if data.len() > MAX_LORA_PAYLOAD {
            return None;
        }
        let mut frame = Self {
            radio_id,
            len: data.len() as u8,
            bytes: [0; MAX_LORA_PAYLOAD],
        };
        frame.bytes[..data.len()].copy_from_slice(data);
        Some(frame)
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}
