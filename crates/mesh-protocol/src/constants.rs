//! Public mesh air-interface constants.

pub const PACKET_HEADER_LEN: usize = 16;
pub const MAX_LORA_PAYLOAD_LEN: usize = 255;
pub const MAX_LORA_FRAME_LEN: usize = MAX_LORA_PAYLOAD_LEN;

pub const PACKET_FLAGS_HOP_LIMIT_MASK: u8 = 0x07;
pub const PACKET_FLAGS_WANT_ACK_MASK: u8 = 0x08;
pub const PACKET_FLAGS_VIA_MQTT_MASK: u8 = 0x10;
pub const PACKET_FLAGS_HOP_START_MASK: u8 = 0xE0;
pub const PACKET_FLAGS_HOP_START_SHIFT: u8 = 5;

pub const HOP_MAX: u8 = 7;
pub const HOP_RELIABLE: u8 = 3;
pub const NODENUM_BROADCAST: u32 = 0xFFFF_FFFF;
pub const NO_NEXT_HOP_PREFERENCE: u8 = 0;
pub const NO_RELAY_NODE: u8 = 0;
