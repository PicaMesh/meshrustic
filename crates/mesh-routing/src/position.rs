//! POSITION_APP (port 3) fixed-position broadcasts.
//!
//! Cadence and coordinates come from remote admin, the same messages the phone
//! sends a node it administers: `Config.PositionConfig` and `AdminMessage.set_fixed_position`.
//! MeshRustic's USB link is a log plus text host commands, not the phone `ToRadio` API,
//! so that local client path is not implemented.
//!
//! Only a stored lat/lon is broadcast, on `position_broadcast_secs`. Position requests
//! are not answered. Smart broadcast, position flags, and GPS are not implemented.

use mesh_crypto::{encrypt_packet, CryptoKey};
use mesh_protocol::{PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};

use crate::nodeinfo::{DEVICE_ROLE_ROUTER, DEVICE_ROLE_ROUTER_LATE};
use crate::pool::MAX_PACKET_PAYLOAD;
use crate::router::MAX_WIRE_LEN;
use crate::topology::{
    encode_data_payload_opts, DataBitfield, DataEncodeOpts, SR_BROADCAST_MAX_HOPS,
};

pub const POSITION_APP: u32 = mesh_protocol::num::POSITION_APP;

/// `Position.LocSource.LOC_MANUAL`.
pub const LOC_MANUAL: u32 = 1;

/// Full lat/lon precision. The MT+SR fork quantizes with the channel's
/// `position_precision` (13 on a fresh primary channel); MeshRustic has no
/// channel module settings, so the configured coordinates go out unchanged.
pub const POSITION_PRECISION_BITS: u32 = 32;

/// `Default.h` `default_broadcast_interval_secs` / `min_default_broadcast_interval_secs`
/// for every role other than ROUTER and ROUTER_LATE.
pub const POSITION_BROADCAST_SECS_CLIENT: u32 = 60 * 60;

/// Same defaults for ROUTER and ROUTER_LATE (`ONE_DAY / 2`).
pub const POSITION_BROADCAST_SECS_ROUTER: u32 = 12 * 60 * 60;

/// `Default.h` `MAX_INTERVAL` (`INT32_MAX`): larger values overflow Apple clients.
pub const POSITION_BROADCAST_SECS_MAX: u32 = i32::MAX as u32;

/// Role-aware floor and default. Zero stays "unset" and resolves to this at send time.
pub fn position_interval_floor_secs(role: u32) -> u32 {
    if role == DEVICE_ROLE_ROUTER || role == DEVICE_ROLE_ROUTER_LATE {
        POSITION_BROADCAST_SECS_ROUTER
    } else {
        POSITION_BROADCAST_SECS_CLIENT
    }
}

/// Raise a configured interval to the default-channel floor. Zero is left as zero.
pub fn coerce_position_broadcast_secs(configured: u32, role: u32) -> u32 {
    if configured == 0 {
        return 0;
    }
    let capped = configured.min(POSITION_BROADCAST_SECS_MAX);
    let floor = position_interval_floor_secs(role);
    if capped < floor {
        floor
    } else {
        capped
    }
}

/// Effective broadcast period. Stored 0 uses the role default.
pub fn position_broadcast_interval_ms(stored_secs: u32, role: u32) -> u32 {
    let secs = if stored_secs == 0 {
        position_interval_floor_secs(role)
    } else {
        coerce_position_broadcast_secs(stored_secs, role)
    };
    secs.saturating_mul(1_000)
}

/// Encode `Position` with lat/lon, `LOC_MANUAL`, and full precision. No time, altitude, or flags.
pub fn encode_fixed_position(
    latitude_i: i32,
    longitude_i: i32,
    out: &mut heapless::Vec<u8, 32>,
) -> bool {
    push_sfixed32(out, 1, latitude_i)
        && push_sfixed32(out, 2, longitude_i)
        && push_varint_field(out, 5, LOC_MANUAL)
        && push_varint_field(out, 23, POSITION_PRECISION_BITS)
}

/// Broadcast the fixed position on the primary channel. `want_response` stays clear:
/// this node does not solicit position replies.
pub fn build_fixed_position_wire_frame(
    node_num: u32,
    packet_id: u32,
    channel_hash: u8,
    hop_limit: u8,
    key: &CryptoKey,
    latitude_i: i32,
    longitude_i: i32,
    ok_to_mqtt: bool,
) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
    // 0,0 is the unset sentinel. Do not put an undefined position on the air.
    if latitude_i == 0 && longitude_i == 0 {
        return None;
    }
    let mut position = heapless::Vec::<u8, 32>::new();
    if !encode_fixed_position(latitude_i, longitude_i, &mut position) {
        return None;
    }
    let plaintext = encode_data_payload_opts(
        POSITION_APP,
        &position,
        DataEncodeOpts {
            bitfield: DataBitfield::Ours { ok_to_mqtt },
            ..Default::default()
        },
    );
    if plaintext.len() > MAX_PACKET_PAYLOAD {
        return None;
    }
    let mut cipher = [0u8; MAX_PACKET_PAYLOAD];
    cipher[..plaintext.len()].copy_from_slice(&plaintext);
    encrypt_packet(
        key,
        node_num,
        packet_id as u64,
        &mut cipher[..plaintext.len()],
    );

    let hop = hop_limit.min(SR_BROADCAST_MAX_HOPS);
    let header = PacketHeader::from_fields(
        NODENUM_BROADCAST,
        node_num,
        packet_id,
        channel_hash,
        hop,
        hop,
        false,
        false,
        0,
        (node_num & 0xFF) as u8,
    );
    let mut bytes = [0u8; MAX_WIRE_LEN];
    header.encode_to((&mut bytes[..PACKET_HEADER_LEN]).try_into().ok()?);
    let len = PACKET_HEADER_LEN + plaintext.len();
    bytes[PACKET_HEADER_LEN..len].copy_from_slice(&cipher[..plaintext.len()]);
    Some((len as u8, bytes))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DecodedFixedPosition {
    pub latitude_i: i32,
    pub longitude_i: i32,
    pub has_latitude_i: bool,
    pub has_longitude_i: bool,
    pub location_source: u32,
    pub precision_bits: u32,
}

/// Decode the fields we send. Other `Position` fields are skipped.
pub fn decode_fixed_position(payload: &[u8]) -> Option<DecodedFixedPosition> {
    let mut out = DecodedFixedPosition::default();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 5) if i + 4 <= payload.len() => {
                out.latitude_i = i32::from_le_bytes(payload[i..i + 4].try_into().ok()?);
                out.has_latitude_i = true;
                i += 4;
            }
            (2, 5) if i + 4 <= payload.len() => {
                out.longitude_i = i32::from_le_bytes(payload[i..i + 4].try_into().ok()?);
                out.has_longitude_i = true;
                i += 4;
            }
            (5, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                out.location_source = v;
                i = ni;
            }
            (23, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                out.precision_bits = v;
                i = ni;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(out)
}

fn push_sfixed32(out: &mut heapless::Vec<u8, 32>, field: u32, value: i32) -> bool {
    push_tag(out, field, 5) && out.extend_from_slice(&value.to_le_bytes()).is_ok()
}

fn push_varint_field(out: &mut heapless::Vec<u8, 32>, field: u32, value: u32) -> bool {
    push_tag(out, field, 0) && push_varint(out, value)
}

fn push_tag(out: &mut heapless::Vec<u8, 32>, field: u32, wire: u8) -> bool {
    push_varint(out, (field << 3) | u32::from(wire))
}

fn push_varint(out: &mut heapless::Vec<u8, 32>, mut v: u32) -> bool {
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        if out.push(byte).is_err() {
            return false;
        }
        if v == 0 {
            return true;
        }
    }
}

fn read_varint(data: &[u8], mut idx: usize) -> Option<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0;
    while idx < data.len() && shift < 32 {
        let byte = data[idx];
        idx += 1;
        result |= u32::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((result, idx));
        }
        shift += 7;
    }
    None
}

fn skip_field(data: &[u8], idx: usize, wire: u8) -> Option<usize> {
    match wire {
        0 => read_varint(data, idx).map(|(_, i)| i),
        1 => (idx + 8 <= data.len()).then_some(idx + 8),
        2 => {
            let (len, ni) = read_varint(data, idx)?;
            let end = ni + len as usize;
            (end <= data.len()).then_some(end)
        }
        5 => (idx + 4 <= data.len()).then_some(idx + 4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodeinfo::DEVICE_ROLE_CLIENT;

    #[test]
    fn unset_interval_follows_role() {
        assert_eq!(
            position_broadcast_interval_ms(0, DEVICE_ROLE_CLIENT),
            POSITION_BROADCAST_SECS_CLIENT * 1_000
        );
        assert_eq!(
            position_broadcast_interval_ms(0, DEVICE_ROLE_ROUTER),
            POSITION_BROADCAST_SECS_ROUTER * 1_000
        );
        assert_eq!(
            position_broadcast_interval_ms(0, DEVICE_ROLE_ROUTER_LATE),
            POSITION_BROADCAST_SECS_ROUTER * 1_000
        );
    }

    #[test]
    fn short_interval_is_raised_to_the_floor() {
        assert_eq!(
            coerce_position_broadcast_secs(60, DEVICE_ROLE_CLIENT),
            POSITION_BROADCAST_SECS_CLIENT
        );
        assert_eq!(coerce_position_broadcast_secs(0, DEVICE_ROLE_CLIENT), 0);
        assert_eq!(
            coerce_position_broadcast_secs(POSITION_BROADCAST_SECS_MAX + 5, DEVICE_ROLE_CLIENT),
            POSITION_BROADCAST_SECS_MAX
        );
    }

    #[test]
    fn fixed_position_round_trip() {
        let mut buf = heapless::Vec::new();
        assert!(encode_fixed_position(-12_345_678, 98_765_432, &mut buf));
        let decoded = decode_fixed_position(&buf).unwrap();
        assert_eq!(decoded.latitude_i, -12_345_678);
        assert_eq!(decoded.longitude_i, 98_765_432);
        assert!(decoded.has_latitude_i && decoded.has_longitude_i);
        assert_eq!(decoded.location_source, LOC_MANUAL);
        assert_eq!(decoded.precision_bits, POSITION_PRECISION_BITS);
    }
}
