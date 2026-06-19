//! ROUTING_APP ACK/NAK wire frames and hop-limit policy for reliable delivery.

use mesh_crypto::CryptoKey;
use mesh_protocol::ParsedPacket;

use crate::router::MAX_WIRE_LEN;
use crate::topology::{build_app_wire_frame, DataEncodeOpts};

pub const ROUTING_APP: u32 = 5;

pub const ROUTING_ERROR_NONE: u32 = 0;
pub const ROUTING_ERROR_MAX_RETRANSMIT: u32 = 5;
pub const ROUTING_ERROR_NO_CHANNEL: u32 = 6;

pub const NUM_RELIABLE_RETX: u8 = 3;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoutingDecode {
    pub error_reason: Option<u32>,
}

/// Delay before the next reliable retransmit (simplified contention-window model).
pub fn retransmission_delay_ms(packet_airtime_ms: u32, slot_ms: u32) -> u32 {
    packet_airtime_ms
        .saturating_mul(2)
        .saturating_add(slot_ms.saturating_mul(4))
}

/// Hop limit for an ACK/NAK routed back toward the original sender.
pub fn hop_limit_for_response(parsed: &ParsedPacket, configured_hop_limit: u8) -> u8 {
    if parsed.hop_start == 0 {
        return 0;
    }
    let hops_used = parsed.hop_start.saturating_sub(parsed.hop_limit);
    if hops_used > configured_hop_limit {
        return hops_used;
    }
    let with_margin = hops_used.saturating_add(2);
    if with_margin < configured_hop_limit {
        with_margin
    } else {
        configured_hop_limit
    }
}

pub fn encode_routing_error(reason: u32) -> heapless::Vec<u8, 16> {
    let mut out = heapless::Vec::new();
    let _ = out.push((3 << 3) | 0);
    push_varint(&mut out, reason);
    out
}

pub fn decode_routing_payload(payload: &[u8]) -> Option<RoutingDecode> {
    let mut error_reason = None;
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        if field == 3 && wire == 0 {
            let (v, ni) = read_varint(payload, i)?;
            error_reason = Some(v);
            i = ni;
        } else {
            i = skip_field(payload, i, wire)?;
        }
        idx = i;
    }
    Some(RoutingDecode { error_reason })
}

pub fn build_ack_nak_frame(
    to: u32,
    from: u32,
    packet_id: u32,
    acking_id: u32,
    channel_hash: u8,
    hop_limit: u8,
    error_reason: u32,
    key: &CryptoKey,
) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
    let routing = encode_routing_error(error_reason);
    build_app_wire_frame(
        to,
        from,
        packet_id,
        channel_hash,
        hop_limit,
        hop_limit,
        false,
        key,
        ROUTING_APP,
        &routing,
        DataEncodeOpts {
            request_id: acking_id,
            ..Default::default()
        },
    )
}

fn push_varint(out: &mut heapless::Vec<u8, 16>, mut v: u32) {
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        let _ = out.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn read_varint(data: &[u8], mut idx: usize) -> Option<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        if idx >= data.len() {
            return None;
        }
        let byte = data[idx];
        idx += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some((result, idx));
        }
        shift += 7;
    }
    None
}

fn skip_field(data: &[u8], idx: usize, wire: u8) -> Option<usize> {
    match wire {
        0 => {
            let (_, i) = read_varint(data, idx)?;
            Some(i)
        }
        2 => {
            let (len, mut i) = read_varint(data, idx)?;
            i += len as usize;
            if i > data.len() {
                None
            } else {
                Some(i)
            }
        }
        1 | 5 => Some(idx + if wire == 1 { 8 } else { 4 }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_crypto::DEFAULT_PSK;
    use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};

    #[test]
    fn routing_error_round_trip() {
        let encoded = encode_routing_error(ROUTING_ERROR_NONE);
        let decoded = decode_routing_payload(&encoded).unwrap();
        assert_eq!(decoded.error_reason, Some(ROUTING_ERROR_NONE));
    }

    #[test]
    fn hop_limit_for_response_uses_margin() {
        let parsed = PacketHeader::from_fields(0xAA, 0xBB, 1, 0, 1, 3, false, false, 0, 0).parse();
        assert_eq!(hop_limit_for_response(&parsed, 3), 3);
        let direct = PacketHeader::from_fields(0xAA, 0xBB, 1, 0, 3, 0, false, false, 0, 0).parse();
        assert_eq!(hop_limit_for_response(&direct, 3), 0);
    }

    #[test]
    fn ack_frame_has_request_id() {
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let (_, frame) = build_ack_nak_frame(
            0xBB,
            0xAA,
            0x1234,
            0x5678,
            0x77,
            2,
            ROUTING_ERROR_NONE,
            &key,
        )
        .unwrap();
        let header = PacketHeader::decode(&frame[..PACKET_HEADER_LEN]).unwrap();
        assert_eq!(header.parse().to, 0xBB);
    }
}
