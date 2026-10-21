use crate::protobuf::{read_varint, skip_field};
use mesh_protocol::{ParsedPacket, NODENUM_BROADCAST};

use crate::routing_ack::hops_away;

pub const TRACEROUTE_APP: u32 = 70;
pub const ROUTE_SIZE: usize = 8;
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
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 5) if i + 4 <= data.len() => {
                push_u32(
                    &mut out.route,
                    u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]),
                )?;
                i += 4;
            }
            (1, 2) => {
                let (len, ni) = read_varint(data, i)?;
                i = parse_fixed32_packed(
                    data.get(ni..ni.checked_add(len as usize)?)?,
                    &mut out.route,
                    ni.checked_add(len as usize)?,
                )?;
            }
            (2, 0) => {
                let (v, ni) = read_signed_varint(data, i)?;
                push_i32(&mut out.snr_towards, v)?;
                i = ni;
            }
            (2, 2) => {
                let (len, ni) = read_varint(data, i)?;
                i = parse_int32_packed(
                    data.get(ni..ni.checked_add(len as usize)?)?,
                    &mut out.snr_towards,
                    ni.checked_add(len as usize)?,
                )?;
            }
            (3, 5) if i + 4 <= data.len() => {
                push_u32(
                    &mut out.route_back,
                    u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]),
                )?;
                i += 4;
            }
            (3, 2) => {
                let (len, ni) = read_varint(data, i)?;
                i = parse_fixed32_packed(
                    data.get(ni..ni.checked_add(len as usize)?)?,
                    &mut out.route_back,
                    ni.checked_add(len as usize)?,
                )?;
            }
            (4, 0) => {
                let (v, ni) = read_signed_varint(data, i)?;
                push_i32(&mut out.snr_back, v)?;
                i = ni;
            }
            (4, 2) => {
                let (len, ni) = read_varint(data, i)?;
                i = parse_int32_packed(
                    data.get(ni..ni.checked_add(len as usize)?)?,
                    &mut out.snr_back,
                    ni.checked_add(len as usize)?,
                )?;
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
    // A repeated numeric field is carried packed: one length-delimited run per
    // field instead of one tag per element. It is the canonical form and it costs
    // fewer bytes on the air.
    let snr_len = |snr: &i32| {
        if *snr < 0 {
            10
        } else {
            let mut value = *snr as u32;
            let mut len = 1;
            while value >= 128 {
                value >>= 7;
                len += 1;
            }
            len
        }
    };
    let snr_bytes =
        |values: &heapless::Vec<i32, ROUTE_SIZE>| -> usize { values.iter().map(snr_len).sum() };
    // An empty repeated field is left out entirely rather than written as an empty
    // run, so the size estimate has to skip it too.
    let field_len = |count: usize, payload: usize| -> usize {
        if count == 0 {
            0
        } else {
            1 + varint_len(payload) + payload
        }
    };
    let needed = field_len(rd.route.len(), 4 * rd.route.len())
        + field_len(rd.snr_towards.len(), snr_bytes(&rd.snr_towards))
        + field_len(rd.route_back.len(), 4 * rd.route_back.len())
        + field_len(rd.snr_back.len(), snr_bytes(&rd.snr_back));
    if needed > out.capacity() {
        return false;
    }
    push_packed_fixed32(out, 1, &rd.route);
    push_packed_int32(out, 2, &rd.snr_towards, snr_len);
    push_packed_fixed32(out, 3, &rd.route_back);
    push_packed_int32(out, 4, &rd.snr_back, snr_len);
    true
}

pub fn alter_on_relay(
    rd: &mut RouteDiscovery,
    parsed: &ParsedPacket,
    hop_start_known: bool,
    node_num: u32,
    snr: i8,
    request_id: u32,
) {
    let towards_destination = request_id == 0;
    insert_unknown_hops(rd, parsed, hop_start_known, towards_destination);
    let snr_only = parsed.to == node_num;
    append_id_and_snr(rd, node_num, snr, towards_destination, snr_only);
}

fn insert_unknown_hops(
    rd: &mut RouteDiscovery,
    parsed: &ParsedPacket,
    hop_start_known: bool,
    towards_destination: bool,
) {
    let Some(hops_taken) = hops_away(parsed.hop_start, parsed.hop_limit, hop_start_known) else {
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
    decrypt_packet(
        key,
        parsed.from,
        parsed.id as u64,
        &mut cipher[..cipher_len],
    );
    let (data, inner) = crate::topology::decode_data_payload_full(&cipher[..cipher_len])?;
    if data.portnum != TRACEROUTE_APP {
        return None;
    }
    let mut rd = decode_route_discovery(&inner)?;
    let towards = decoded.request_id == 0;
    alter_on_relay(
        &mut rd,
        parsed,
        data.has_bitfield,
        node_num,
        snr,
        decoded.request_id,
    );
    let route_len = if towards {
        rd.route.len()
    } else {
        rd.route_back.len()
    };
    let mut route_wire = heapless::Vec::<u8, 128>::new();
    if !encode_route_discovery(&rd, &mut route_wire) {
        return None;
    }
    let plaintext = replace_data_payload(&cipher[..cipher_len], &route_wire)?;
    if plaintext.is_empty() || plaintext.len() > cipher.len() {
        return None;
    }
    let mut out = heapless::Vec::<u8, 240>::new();
    let _ = out.extend_from_slice(&plaintext);
    mesh_crypto::encrypt_packet(
        key,
        parsed.from,
        parsed.id as u64,
        &mut out[..plaintext.len()],
    );
    out.truncate(plaintext.len());
    Some((out, route_len.min(u8::MAX as usize) as u8))
}

// Relays must preserve addressing metadata and extensions they do not interpret.
fn replace_data_payload(data: &[u8], payload: &[u8]) -> Option<heapless::Vec<u8, 240>> {
    let mut out = heapless::Vec::new();
    let mut i = 0;
    let mut replaced = false;
    while i < data.len() {
        let start = i;
        let (tag, next) = read_varint(data, i)?;
        i = skip_field(data, next, (tag & 7) as u8)?;
        if tag == (2 << 3) | 2 {
            if replaced {
                continue;
            }
            out.push(tag as u8).ok()?;
            let mut length = payload.len() as u32;
            loop {
                out.push((length as u8 & 0x7f) | if length >= 128 { 0x80 } else { 0 })
                    .ok()?;
                length >>= 7;
                if length == 0 {
                    break;
                }
            }
            out.extend_from_slice(payload).ok()?;
            replaced = true;
        } else {
            out.extend_from_slice(&data[start..i]).ok()?;
        }
    }
    if !replaced || out.len() > crate::pool::MAX_PACKET_PAYLOAD {
        return None;
    }
    Some(out)
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
    if !data.len().is_multiple_of(4) {
        return None;
    }
    let mut i = 0usize;
    while i + 4 <= data.len() {
        push_u32(
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

fn varint_len(mut v: usize) -> usize {
    let mut len = 1;
    while v >= 128 {
        v >>= 7;
        len += 1;
    }
    len
}

fn push_packed_fixed32(out: &mut heapless::Vec<u8, 128>, field: u32, values: &[u32]) {
    if values.is_empty() {
        return;
    }
    let _ = out.push(((field << 3) | 2) as u8);
    push_varint(out, values.len() * 4);
    for &v in values {
        let _ = out.extend_from_slice(&v.to_le_bytes());
    }
}

fn push_packed_int32(
    out: &mut heapless::Vec<u8, 128>,
    field: u32,
    values: &[i32],
    len_of: impl Fn(&i32) -> usize,
) {
    if values.is_empty() {
        return;
    }
    let _ = out.push(((field << 3) | 2) as u8);
    push_varint(out, values.iter().map(len_of).sum::<usize>());
    for &v in values {
        push_signed_varint(out, v);
    }
}

fn push_varint(out: &mut heapless::Vec<u8, 128>, mut v: usize) {
    loop {
        let mut byte = (v & 0x7f) as u8;
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

fn push_signed_varint(out: &mut heapless::Vec<u8, 128>, v: i32) {
    let mut value = v as i64 as u64;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let _ = out.push(byte | if value != 0 { 0x80 } else { 0 });
        if value == 0 {
            break;
        }
    }
}

fn read_signed_varint(data: &[u8], idx: usize) -> Option<(i32, usize)> {
    let (uv, ni) = crate::protobuf::read_varint64(data, idx)?;
    Some((uv as i32, ni))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_protocol::PacketHeader;

    #[test]
    fn append_id_and_snr_on_request_path() {
        let mut rd = RouteDiscovery::default();
        let parsed =
            PacketHeader::from_fields(0xAA, 0xBB, 1, 0x77, 3, 3, false, false, 0, 0).parse();
        alter_on_relay(&mut rd, &parsed, true, 0xCC, 10, 0);
        assert_eq!(rd.route.as_slice(), &[0xCC]);
        assert_eq!(rd.snr_towards.as_slice(), &[40]);
    }

    #[test]
    fn snr_only_when_packet_to_us() {
        let mut rd = RouteDiscovery::default();
        let parsed =
            PacketHeader::from_fields(0xCC, 0xAA, 1, 0x77, 3, 3, false, false, 0, 0).parse();
        alter_on_relay(&mut rd, &parsed, true, 0xCC, 8, 0);
        assert!(rd.route.is_empty());
        assert_eq!(rd.snr_towards.as_slice(), &[32]);
    }

    #[test]
    fn reply_path_uses_route_back() {
        let mut rd = RouteDiscovery::default();
        let parsed =
            PacketHeader::from_fields(0xBB, 0xAA, 1, 0x77, 3, 3, false, false, 0, 0).parse();
        alter_on_relay(&mut rd, &parsed, true, 0xCC, 6, 0x1234);
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

    #[test]
    fn signed_snr_roundtrips_and_oversized_trace_fails_atomically() {
        let mut route = RouteDiscovery::default();
        route.snr_towards.push(-128).unwrap();
        let mut wire = heapless::Vec::new();
        assert!(encode_route_discovery(&route, &mut wire));
        assert_eq!(wire.len(), 12);
        assert_eq!(decode_route_discovery(&wire), Some(route.clone()));
        for _ in 1..ROUTE_SIZE {
            route.snr_towards.push(-128).unwrap();
        }
        for _ in 0..ROUTE_SIZE {
            route.snr_back.push(-128).unwrap();
        }
        assert!(!encode_route_discovery(&route, &mut wire));
        assert!(wire.is_empty());
    }

    #[test]
    fn repeated_fields_are_encoded_packed() {
        let mut rd = RouteDiscovery::default();
        rd.route.push(0x1111_1111).unwrap();
        rd.route.push(0x2222_2222).unwrap();
        rd.snr_towards.push(40).unwrap();
        rd.snr_towards.push(-32).unwrap();
        let mut wire = heapless::Vec::<u8, 128>::new();
        assert!(encode_route_discovery(&rd, &mut wire));

        // One length-delimited run per repeated field, not one tag per element.
        assert_eq!(wire[0], (1 << 3) | 2);
        assert_eq!(wire[1], 8, "two fixed32 elements");
        assert_eq!(&wire[2..6], &0x1111_1111u32.to_le_bytes()[..]);
        assert_eq!(&wire[6..10], &0x2222_2222u32.to_le_bytes()[..]);

        let decoded = decode_route_discovery(&wire).unwrap();
        assert_eq!(decoded.route.as_slice(), rd.route.as_slice());
        assert_eq!(decoded.snr_towards.as_slice(), rd.snr_towards.as_slice());
    }

    #[test]
    fn the_unpacked_form_is_still_accepted() {
        // A repeated field written one element at a time must still decode.
        let mut wire = heapless::Vec::<u8, 128>::new();
        wire.push((1 << 3) | 5).unwrap();
        wire.extend_from_slice(&0x1111_1111u32.to_le_bytes())
            .unwrap();
        wire.push((1 << 3) | 5).unwrap();
        wire.extend_from_slice(&0x2222_2222u32.to_le_bytes())
            .unwrap();
        wire.push((2 << 3) as u8).unwrap();
        wire.push(40).unwrap();

        let decoded = decode_route_discovery(&wire).unwrap();
        assert_eq!(decoded.route.as_slice(), &[0x1111_1111, 0x2222_2222]);
        assert_eq!(decoded.snr_towards.as_slice(), &[40]);
    }

    #[test]
    fn malformed_packed_routes_are_rejected() {
        for input in [
            &[0x0a, 1, 0][..],
            &[0x12, 1, 0x80][..],
            &[0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f][..],
        ] {
            assert!(decode_route_discovery(input).is_none());
        }
    }
    #[test]
    fn replacing_trace_preserves_all_other_envelope_fields() {
        let original = [
            8, 70, 18, 1, 0, 37, 1, 2, 3, 4, 48, 5, 72, 128, 2, 82, 2, 6, 7,
        ];
        let replacement = replace_data_payload(&original, &[10, 11]).unwrap();
        assert_eq!(
            replacement.as_slice(),
            &[8, 70, 18, 2, 10, 11, 37, 1, 2, 3, 4, 48, 5, 72, 128, 2, 82, 2, 6, 7]
        );
    }
}
