use crate::constants::{
    NO_NEXT_HOP_PREFERENCE, NO_RELAY_NODE, PACKET_FLAGS_HOP_LIMIT_MASK,
    PACKET_FLAGS_HOP_START_MASK, PACKET_FLAGS_HOP_START_SHIFT, PACKET_FLAGS_VIA_MQTT_MASK,
    PACKET_FLAGS_WANT_ACK_MASK, PACKET_HEADER_LEN,
};

/// On-air LoRa packet header (16 bytes, little-endian).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    pub to: u32,
    pub from: u32,
    pub id: u32,
    pub flags: u8,
    pub channel: u8,
    pub next_hop: u8,
    pub relay_node: u8,
}

/// Logical packet fields after decoding the 16-byte LoRa header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedPacket {
    pub to: u32,
    pub from: u32,
    pub id: u32,
    pub channel: u8,
    pub hop_limit: u8,
    pub hop_start: u8,
    pub want_ack: bool,
    pub via_mqtt: bool,
    pub next_hop: u8,
    pub relay_node: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
}

impl PacketHeader {
    pub const LEN: usize = PACKET_HEADER_LEN;

    pub fn encode_flags(hop_limit: u8, hop_start: u8, want_ack: bool, via_mqtt: bool) -> u8 {
        let hop_limit = hop_limit & PACKET_FLAGS_HOP_LIMIT_MASK;
        let hop_start = (hop_start << PACKET_FLAGS_HOP_START_SHIFT) & PACKET_FLAGS_HOP_START_MASK;
        let want_ack = if want_ack {
            PACKET_FLAGS_WANT_ACK_MASK
        } else {
            0
        };
        let via_mqtt = if via_mqtt {
            PACKET_FLAGS_VIA_MQTT_MASK
        } else {
            0
        };
        hop_limit | hop_start | want_ack | via_mqtt
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_fields(
        to: u32,
        from: u32,
        id: u32,
        channel: u8,
        hop_limit: u8,
        hop_start: u8,
        want_ack: bool,
        via_mqtt: bool,
        next_hop: u8,
        relay_node: u8,
    ) -> Self {
        Self {
            to,
            from,
            id,
            flags: Self::encode_flags(hop_limit, hop_start, want_ack, via_mqtt),
            channel,
            next_hop,
            relay_node,
        }
    }

    pub fn hop_limit(&self) -> u8 {
        self.flags & PACKET_FLAGS_HOP_LIMIT_MASK
    }

    pub fn hop_start(&self) -> u8 {
        (self.flags & PACKET_FLAGS_HOP_START_MASK) >> PACKET_FLAGS_HOP_START_SHIFT
    }

    pub fn want_ack(&self) -> bool {
        self.flags & PACKET_FLAGS_WANT_ACK_MASK != 0
    }

    pub fn via_mqtt(&self) -> bool {
        self.flags & PACKET_FLAGS_VIA_MQTT_MASK != 0
    }

    pub fn encode_to(&self, out: &mut [u8; Self::LEN]) {
        out[0..4].copy_from_slice(&self.to.to_le_bytes());
        out[4..8].copy_from_slice(&self.from.to_le_bytes());
        out[8..12].copy_from_slice(&self.id.to_le_bytes());
        out[12] = self.flags;
        out[13] = self.channel;
        out[14] = self.next_hop;
        out[15] = self.relay_node;
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < Self::LEN {
            return Err(DecodeError::TooShort);
        }
        Ok(Self {
            to: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            from: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            id: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            flags: buf[12],
            channel: buf[13],
            next_hop: buf[14],
            relay_node: buf[15],
        })
    }

    /// Decode header into logical fields for routing and crypto.
    pub fn parse(&self) -> ParsedPacket {
        let hop_start = self.hop_start();
        ParsedPacket {
            to: self.to,
            from: self.from,
            id: self.id,
            channel: self.channel,
            hop_limit: self.hop_limit(),
            hop_start,
            want_ack: self.want_ack(),
            via_mqtt: self.via_mqtt(),
            next_hop: if hop_start == 0 {
                NO_NEXT_HOP_PREFERENCE
            } else {
                self.next_hop
            },
            relay_node: if hop_start == 0 {
                NO_RELAY_NODE
            } else {
                self.relay_node
            },
        }
    }
}

/// Header plus trailing encrypted payload bytes.
pub struct EncodedPacket<'a> {
    pub header: PacketHeader,
    pub payload: &'a [u8],
}

impl EncodedPacket<'_> {
    pub fn decode_frame(buf: &[u8]) -> Result<(ParsedPacket, &[u8]), DecodeError> {
        let header = PacketHeader::decode(buf)?;
        let payload = &buf[PacketHeader::LEN..];
        Ok((header.parse(), payload))
    }
}
