//! TRACEROUTE_APP (port 70) — append node id + SNR on rebroadcast.

use mesh_protocol::{NODENUM_BROADCAST, ParsedPacket};

pub const TRACEROUTE_APP: u32 = 70;
pub const ROUTE_SIZE: usize = 8;
/// Unknown hop SNR marker on the wire (Meshtastic-compatible).
pub const SNR_UNKNOWN: i32 = i8::MIN as i32;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteDiscovery {
    pub route: heapless::Vec<u32, ROUTE_SIZE>,
    pub snr_towards: heapless::Vec<i32, ROUTE_SIZE>,
    pub route_back: heapless::Vec<u32, ROUTE_SIZE>,
    pub snr_back: heapless::Vec<i32, ROUTE_SIZE>,
}

pub fn decode_route_discovery(data: &[u8]) -> Option<RouteDiscovery> {
    let mut out = RouteDiscovery::default();
    let mut idx = 0usize;
    while idx < data.len() {
        let (tag, mut i) = read_varint(data, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 5) if i + 4 <= data.len() => {
                push_u32(&mut out.route, u32::from_le_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                ]))?;
                i += 4;
            }
            (1, 2) => {
                let (len, ni) = read_varint(data, i)?;
                i = parse_fixed32_packed(&data[ni..ni + len as usize], &mut out.route, ni + len as usize)
                    .unwrap_or(ni + len as usize);
            }
            (2, 0) => {
                let (v, ni) = read_signed_varint(data, i)?;
                push_i32(&mut out.snr_towards, v)?;
                i = ni;
            }
            (2, 2) => {
                let (len, ni) = read_varint(data, i)?;
                i = parse_int32_packed(&data[ni..ni + len as usize], &mut out.snr_towards, ni + len as usize)
                    .unwrap_or(ni + len as usize);
            }
            (3, 5) if i + 4 <= data.len() => {
                push_u32(&mut out.route_back, u32::from_le_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                ]))?;
                i += 4;
            }
            (3, 2) => {
                let (len, ni) = read_varint(data, i)?;
                i = parse_fixed32_packed(
                    &data[ni..ni + len as usize],
                    &mut out.route_back,
                    ni + len as usize,
                )
                .unwrap_or(ni + len as usize);
            }
            (4, 0) => {
                let (v, ni) = read_signed_varint(data, i)?;
                push_i32(&mut out.snr_back, v)?;
                i = ni;
            }
            (4, 2) => {
                let (len, ni) = read_varint(data, i)?;
                i = parse_int32_packed(&data[ni..ni + len as usize], &mut out.snr_back, ni + len as usize)
                    .unwrap_or(ni + len as usize);
            }
            _ => {
                i = skip_field(data, i, wire)?;
            }
        }
        idx = i;
    }
    Some(out)
}

pub fn encode_route_discovery(rd: &RouteDiscovery, out: &mut heapless::Vec<u8, 128>) -> bool {
    out.clear();
    for &node in rd.route.iter() {
        push_fixed32_field(out, 1, node);
    }
    for &snr in rd.snr_towards.iter() {
        push_signed_varint_field(out, 2, snr);
    }
    for &node in rd.route_back.iter() {
        push_fixed32_field(out, 3, node);
    }
    for &snr in rd.snr_back.iter() {
        push_signed_varint_field(out, 4, snr);
    }
    true
}

/// Update RouteDiscovery before rebroadcast (Meshtastic TraceRouteModule-compatible).
pub fn alter_on_relay(
    rd: &mut RouteDiscovery,
    parsed: &ParsedPacket,
    node_num: u32,
    snr: i8,
    request_id: u32,
) {
    let towards_destination = request_id == 0;
    insert_unknown_hops(rd, parsed, towards_destination);
    let snr_only = parsed.to == node_num;
    append_id_and_snr(rd, node_num, snr, towards_destination, snr_only);
}

fn hops_away(parsed: &ParsedPacket) -> Option<u8> {
    if parsed.hop_start == 0 {
        return None;
    }
    Some(parsed.hop_start.saturating_sub(parsed.hop_limit))
}

fn insert_unknown_hops(rd: &mut RouteDiscovery, parsed: &ParsedPacket, towards_destination: bool) {
    let Some(hops_taken) = hops_away(parsed) else {
        return;
    };
    let (route, snr_list) = if towards_destination {
        (&mut rd.route, &mut rd.snr_towards)
    } else {
        (&mut rd.route_back, &mut rd.snr_back)
    };

    let route_len = route.len() as u8;
    if hops_taken > route_len {
        for _ in route_len..hops_taken {
            if route.len() >= ROUTE_SIZE {
                break;
            }
            let _ = route.push(NODENUM_BROADCAST);
        }
    }
    while snr_list.len() < route.len() && snr_list.len() < ROUTE_SIZE {
        let _ = snr_list.push(SNR_UNKNOWN);
    }
}

fn append_id_and_snr(
    rd: &mut RouteDiscovery,
    node_num: u32,
    snr: i8,
    towards_destination: bool,
    snr_only: bool,
) {
    let (route, snr_list) = if towards_destination {
        (&mut rd.route, &mut rd.snr_towards)
    } else {
        (&mut rd.route_back, &mut rd.snr_back)
    };

    if snr_list.len() < ROUTE_SIZE {
        let scaled = (i32::from(snr)).saturating_mul(4);
        let _ = snr_list.push(scaled);
    }
    if snr_only {
        return;
    }
    if route.len() < ROUTE_SIZE {
        let _ = route.push(node_num);
    }
}

/// Decrypt, append our hop, re-encrypt for relay.
pub fn rebuild_relay_ciphertext(
    parsed: &ParsedPacket,
    decoded: &crate::topology::DecodedData,
    cipher: &mut [u8],
    cipher_len: usize,
    node_num: u32,
    snr: i8,
    key: &mesh_crypto::CryptoKey,
) -> Option<(heapless::Vec<u8, 240>, u8)> {
    use mesh_crypto::decrypt_packet;

    if cipher_len == 0 || cipher_len > cipher.len() {
        return None;
    }
    decrypt_packet(key, parsed.from, parsed.id as u64, &mut cipher[..cipher_len]);
    let (data, inner) = crate::topology::decode_data_payload_full(&cipher[..cipher_len])?;
    if data.portnum != TRACEROUTE_APP {
        return None;
    }
    let mut rd = decode_route_discovery(&inner)?;
    let towards = decoded.request_id == 0;
    alter_on_relay(&mut rd, parsed, node_num, snr, decoded.request_id);
    let route_len = if towards {
        rd.route.len()
    } else {
        rd.route_back.len()
    };
    let mut route_wire = heapless::Vec::<u8, 128>::new();
    encode_route_discovery(&rd, &mut route_wire);
    let plaintext = crate::topology::encode_data_payload_opts(
        TRACEROUTE_APP,
        &route_wire,
        crate::topology::DataEncodeOpts {
            want_response: decoded.want_response,
            request_id: decoded.request_id,
            reply_id: decoded.reply_id,
        },
    );
    if plaintext.len() > cipher.len() {
        return None;
    }
    let mut out = heapless::Vec::<u8, 240>::new();
    let _ = out.extend_from_slice(&plaintext);
    mesh_crypto::encrypt_packet(key, parsed.from, parsed.id as u64, &mut out[..plaintext.len()]);
    out.truncate(plaintext.len());
    Some((out, route_len.min(u8::MAX as usize) as u8))
}

fn push_u32(out: &mut heapless::Vec<u32, ROUTE_SIZE>, v: u32) -> Option<()> {
    if out.len() >= ROUTE_SIZE {
        None
    } else {
        let _ = out.push(v);
        Some(())
    }
}

fn push_i32(out: &mut heapless::Vec<i32, ROUTE_SIZE>, v: i32) -> Option<()> {
    if out.len() >= ROUTE_SIZE {
        None
    } else {
        let _ = out.push(v);
        Some(())
    }
}

fn parse_fixed32_packed(
    data: &[u8],
    out: &mut heapless::Vec<u32, ROUTE_SIZE>,
    end: usize,
) -> Option<usize> {
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let _ = push_u32(
            out,
            u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]),
        )?;
        i += 4;
    }
    Some(end)
}

fn parse_int32_packed(
    data: &[u8],
    out: &mut heapless::Vec<i32, ROUTE_SIZE>,
    end: usize,
) -> Option<usize> {
    let mut idx = 0usize;
    while idx < data.len() {
        let (v, ni) = read_signed_varint(data, idx)?;
        push_i32(out, v)?;
        idx = ni;
    }
    Some(end)
}

fn push_fixed32_field(out: &mut heapless::Vec<u8, 128>, field: u32, value: u32) {
    let _ = out.push(((field << 3) | 5) as u8);
    let bytes = value.to_le_bytes();
    let _ = out.extend_from_slice(&bytes);
}

fn push_signed_varint_field(out: &mut heapless::Vec<u8, 128>, field: u32, v: i32) {
    let _ = out.push(((field << 3) | 0) as u8);
    push_varint_u32(out, v as u32);
}

fn push_varint_u32(out: &mut heapless::Vec<u8, 128>, mut v: u32) {
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

fn read_signed_varint(data: &[u8], idx: usize) -> Option<(i32, usize)> {
    let (uv, ni) = read_varint(data, idx)?;
    Some((uv as i32, ni))
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
    use mesh_protocol::PacketHeader;

    #[test]
    fn append_id_and_snr_on_request_path() {
        let mut rd = RouteDiscovery::default();
        let parsed = PacketHeader::from_fields(0xAA, 0xBB, 1, 0x77, 3, 3, false, false, 0, 0).parse();
        alter_on_relay(&mut rd, &parsed, 0xCC, 10, 0);
        assert_eq!(rd.route.as_slice(), &[0xCC]);
        assert_eq!(rd.snr_towards.as_slice(), &[40]);
    }

    #[test]
    fn snr_only_when_packet_to_us() {
        let mut rd = RouteDiscovery::default();
        let parsed = PacketHeader::from_fields(0xAA, 0xCC, 1, 0x77, 2, 3, false, false, 0, 0).parse();
        alter_on_relay(&mut rd, &parsed, 0xCC, 8, 0);
        assert!(rd.route.is_empty());
        assert_eq!(rd.snr_towards.as_slice(), &[32]);
    }

    #[test]
    fn reply_path_uses_route_back() {
        let mut rd = RouteDiscovery::default();
        let parsed = PacketHeader::from_fields(0xBB, 0xAA, 1, 0x77, 3, 3, false, false, 0, 0).parse();
        alter_on_relay(&mut rd, &parsed, 0xCC, 6, 0x1234);
        assert_eq!(rd.route_back.as_slice(), &[0xCC]);
        assert_eq!(rd.snr_back.as_slice(), &[24]);
        assert!(rd.route.is_empty());
    }

    #[test]
    fn encode_decode_round_trip() {
        let mut rd = RouteDiscovery::default();
        let _ = rd.route.push(0x1111_1111);
        let _ = rd.snr_towards.push(40);
        let _ = rd.route_back.push(0x2222_2222);
        let _ = rd.snr_back.push(-32);
        let mut wire = heapless::Vec::<u8, 128>::new();
        encode_route_discovery(&rd, &mut wire);
        let decoded = decode_route_discovery(&wire).unwrap();
        assert_eq!(decoded, rd);
    }
}
