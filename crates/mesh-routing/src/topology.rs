//! Signal-routing topology wire format (V3 `packed_neighbors` on protobuf field 3).

use mesh_crypto::{decrypt_packet, encrypt_packet, CryptoKey};
use mesh_protocol::{PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};

use crate::pool::MAX_PACKET_PAYLOAD;
use crate::router::MAX_WIRE_LEN;
pub const SIGNAL_ROUTING_VERSION: u8 = 3;
pub const PACKED_NEIGHBOR_FORMAT_VERSION: u8 = 1;
pub const PACKED_NEIGHBOR_ENTRY_SIZE: usize = 8;
pub const PACKED_NEIGHBOR_HEADER_SIZE: usize = 5;
pub const PACKED_NEIGHBOR_FLAG_SR_ACTIVE: u8 = 0x01;
pub const PACKED_NEIGHBOR_FLAG_HEARS_US: u8 = 0x02;
pub const PACKED_HEADER_FLAG_SR_ACTIVE: u8 = 0x01;
/// Max neighbors per topology protobuf chunk (11 on wire; 28 entries fit in the 229-byte limit).
pub const MAX_NEIGHBORS_PER_PACKET: usize = 28;
pub const SR_BROADCAST_MAX_HOPS: u8 = 5;
pub const SIGNAL_ROUTING_APP: u32 = 88;

pub const MAX_TOPOLOGY_PACKETS: usize = 4;

/// Parsed `Data` protobuf fields (portnum + routing metadata).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DecodedData {
    pub portnum: u32,
    pub want_response: bool,
    pub dest: u32,
    pub request_id: u32,
    pub reply_id: u32,
}

/// Optional fields when encoding a `Data` protobuf payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataEncodeOpts {
    pub want_response: bool,
    pub reply_id: u32,
    pub request_id: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PackedHeader {
    pub format_version: u8,
    pub entry_size: u8,
    pub routing_version: u8,
    pub topology_version: u8,
    pub signal_routing_active: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PackedNeighbor {
    pub node_id: u32,
    pub rssi: i8,
    pub snr: i8,
    pub signal_routing_active: bool,
    pub hears_us: bool,
    pub etx_variance: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TopologyChunk {
    pub packed_len: u8,
    pub packed: [u8; PACKED_NEIGHBOR_HEADER_SIZE + MAX_NEIGHBORS_PER_PACKET * PACKED_NEIGHBOR_ENTRY_SIZE],
}

pub fn write_packed_header(out: &mut [u8], topology_version: u8, signal_routing_active: bool) {
    out[0] = PACKED_NEIGHBOR_FORMAT_VERSION;
    out[1] = PACKED_NEIGHBOR_ENTRY_SIZE as u8;
    out[2] = SIGNAL_ROUTING_VERSION;
    out[3] = topology_version;
    out[4] = if signal_routing_active {
        PACKED_HEADER_FLAG_SR_ACTIVE
    } else {
        0
    };
}

pub fn decode_packed_header(data: &[u8]) -> Option<PackedHeader> {
    if data.len() < PACKED_NEIGHBOR_HEADER_SIZE {
        return None;
    }
    Some(PackedHeader {
        format_version: data[0],
        entry_size: data[1],
        routing_version: data[2],
        topology_version: data[3],
        signal_routing_active: data[4] & PACKED_HEADER_FLAG_SR_ACTIVE != 0,
    })
}

pub fn decode_packed_neighbors(data: &[u8], max_entries: usize) -> Option<(PackedHeader, heapless::Vec<PackedNeighbor, 32>)> {
    let header = decode_packed_header(data)?;
    if header.format_version != PACKED_NEIGHBOR_FORMAT_VERSION {
        return None;
    }
    if header.entry_size < PACKED_NEIGHBOR_ENTRY_SIZE as u8 || header.entry_size == 0 {
        return None;
    }
    let payload_len = data.len().saturating_sub(PACKED_NEIGHBOR_HEADER_SIZE);
    let mut count = payload_len / header.entry_size as usize;
    if count > max_entries {
        count = max_entries;
    }
    let mut out = heapless::Vec::new();
    for i in 0..count {
        let base = PACKED_NEIGHBOR_HEADER_SIZE + i * header.entry_size as usize;
        if base + PACKED_NEIGHBOR_ENTRY_SIZE > data.len() {
            break;
        }
        let e = &data[base..base + PACKED_NEIGHBOR_ENTRY_SIZE];
        let node_id = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let flags = e[6];
        let rssi = e[4] as i8;
        let snr = e[5] as i8;
        let neighbor = PackedNeighbor {
            node_id,
            rssi,
            snr,
            signal_routing_active: flags & PACKED_NEIGHBOR_FLAG_SR_ACTIVE != 0,
            hears_us: flags & PACKED_NEIGHBOR_FLAG_HEARS_US != 0,
            etx_variance: e[7],
        };
        let _ = out.push(neighbor);
    }
    Some((header, out))
}

pub fn encode_packed_neighbor_entry(
    out: &mut [u8],
    node_id: u32,
    rssi: i8,
    snr: i8,
    flags: u8,
    etx_variance: u8,
) {
    out[0..4].copy_from_slice(&node_id.to_le_bytes());
    out[4] = rssi as u8;
    out[5] = snr as u8;
    out[6] = flags;
    out[7] = etx_variance;
}

pub fn encode_signal_routing_info(packed: &[u8]) -> heapless::Vec<u8, 240> {
    let mut out = heapless::Vec::new();
    let _ = out.push((3 << 3) | 2);
    push_varint(&mut out, packed.len() as u32);
    let _ = out.extend_from_slice(packed);
    out
}

pub fn encode_data_payload(portnum: u32, inner: &[u8]) -> heapless::Vec<u8, 240> {
    encode_data_payload_opts(portnum, inner, DataEncodeOpts::default())
}

pub fn encode_data_payload_opts(
    portnum: u32,
    inner: &[u8],
    opts: DataEncodeOpts,
) -> heapless::Vec<u8, 240> {
    let mut out = heapless::Vec::new();
    let _ = out.push((1 << 3) | 0);
    push_varint(&mut out, portnum);
    let _ = out.push((2 << 3) | 2);
    push_varint(&mut out, inner.len() as u32);
    let _ = out.extend_from_slice(inner);
    if opts.want_response {
        push_varint_field(&mut out, 3, 1);
    }
    if opts.request_id != 0 {
        push_fixed32_field(&mut out, 6, opts.request_id);
    }
    if opts.reply_id != 0 {
        push_fixed32_field(&mut out, 7, opts.reply_id);
    }
    out
}

/// Build an encrypted on-air frame for an app port (unicast or broadcast).
pub fn build_app_wire_frame(
    to: u32,
    from: u32,
    packet_id: u32,
    channel_hash: u8,
    hop_limit: u8,
    hop_start: u8,
    want_ack: bool,
    key: &CryptoKey,
    portnum: u32,
    inner: &[u8],
    opts: DataEncodeOpts,
) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
    let plaintext = encode_data_payload_opts(portnum, inner, opts);
    if plaintext.len() > MAX_PACKET_PAYLOAD {
        return None;
    }
    let mut cipher = [0u8; MAX_PACKET_PAYLOAD];
    cipher[..plaintext.len()].copy_from_slice(&plaintext);
    encrypt_packet(key, from, packet_id as u64, &mut cipher[..plaintext.len()]);

    let hop = hop_limit.min(SR_BROADCAST_MAX_HOPS);
    let start = hop_start.min(SR_BROADCAST_MAX_HOPS);
    let header = PacketHeader::from_fields(
        to,
        from,
        packet_id,
        channel_hash,
        hop,
        start,
        want_ack,
        false,
        0,
        0,
    );
    let mut bytes = [0u8; MAX_WIRE_LEN];
    header.encode_to((&mut bytes[..PACKET_HEADER_LEN]).try_into().ok()?);
    let len = PACKET_HEADER_LEN + plaintext.len();
    bytes[PACKET_HEADER_LEN..len].copy_from_slice(&cipher[..plaintext.len()]);
    Some((len as u8, bytes))
}

pub fn decode_data_payload(data: &[u8]) -> Option<(u32, heapless::Vec<u8, 240>)> {
    let (decoded, payload) = decode_data_payload_full(data)?;
    Some((decoded.portnum, payload))
}

pub fn decode_data_payload_full(data: &[u8]) -> Option<(DecodedData, heapless::Vec<u8, 240>)> {
    let mut decoded = DecodedData::default();
    let mut payload = heapless::Vec::new();
    let mut have_portnum = false;
    let mut idx = 0usize;
    while idx < data.len() {
        let (tag, mut i) = read_varint(data, idx)?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 0) => {
                let (v, ni) = read_varint(data, i)?;
                decoded.portnum = v;
                have_portnum = true;
                i = ni;
            }
            (2, 2) => {
                let (len, ni) = read_varint(data, i)?;
                let end = ni + len as usize;
                if end > data.len() {
                    return None;
                }
                payload.clear();
                let _ = payload.extend_from_slice(&data[ni..end]);
                i = end;
            }
            (3, 0) => {
                let (v, ni) = read_varint(data, i)?;
                decoded.want_response = v != 0;
                i = ni;
            }
            (4, 5) if i + 4 <= data.len() => {
                decoded.dest = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                i += 4;
            }
            (6, 5) if i + 4 <= data.len() => {
                decoded.request_id = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                i += 4;
            }
            (7, 5) if i + 4 <= data.len() => {
                decoded.reply_id = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                i += 4;
            }
            _ => {
                i = skip_field(data, i, wire)?;
            }
        }
        idx = i;
    }
    if !have_portnum {
        return None;
    }
    Some((decoded, payload))
}

pub fn build_topology_wire_frame(
    node_num: u32,
    packet_id: u32,
    channel_hash: u8,
    hop_limit: u8,
    key: &CryptoKey,
    packed: &[u8],
) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
    if packed.len() > PACKED_NEIGHBOR_HEADER_SIZE + MAX_NEIGHBORS_PER_PACKET * PACKED_NEIGHBOR_ENTRY_SIZE {
        return None;
    }
    let sr_info = encode_signal_routing_info(packed);
    let plaintext = encode_data_payload(SIGNAL_ROUTING_APP, &sr_info);
    if plaintext.len() > MAX_PACKET_PAYLOAD {
        return None;
    }
    let mut cipher = [0u8; MAX_PACKET_PAYLOAD];
    cipher[..plaintext.len()].copy_from_slice(&plaintext);
    encrypt_packet(key, node_num, packet_id as u64, &mut cipher[..plaintext.len()]);

    let header = PacketHeader::from_fields(
        NODENUM_BROADCAST,
        node_num,
        packet_id,
        channel_hash,
        hop_limit.min(SR_BROADCAST_MAX_HOPS),
        hop_limit.min(SR_BROADCAST_MAX_HOPS),
        false,
        false,
        0,
        0,
    );
    let mut bytes = [0u8; MAX_WIRE_LEN];
    header.encode_to((&mut bytes[..PACKET_HEADER_LEN]).try_into().ok()?);
    let len = PACKET_HEADER_LEN + plaintext.len();
    bytes[PACKET_HEADER_LEN..len].copy_from_slice(&cipher[..plaintext.len()]);
    Some((len as u8, bytes))
}

pub fn try_decrypt_data(
    key: &CryptoKey,
    from: u32,
    packet_id: u32,
    channel_hash: u8,
    header_channel: u8,
    cipher: &mut [u8],
) -> Option<(u32, heapless::Vec<u8, 240>)> {
    let (decoded, payload) = try_decrypt_data_full(key, from, packet_id, channel_hash, header_channel, cipher)?;
    Some((decoded.portnum, payload))
}

pub fn try_decrypt_data_full(
    key: &CryptoKey,
    from: u32,
    packet_id: u32,
    channel_hash: u8,
    header_channel: u8,
    cipher: &mut [u8],
) -> Option<(DecodedData, heapless::Vec<u8, 240>)> {
    if header_channel != channel_hash {
        return None;
    }
    decrypt_packet(key, from, packet_id as u64, cipher);
    let (decoded, payload) = decode_data_payload_full(cipher)?;
    Some((decoded, payload))
}

pub fn extract_packed_neighbors(payload: &[u8]) -> Option<(PackedHeader, heapless::Vec<PackedNeighbor, 32>)> {
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        if field == 3 && wire == 2 {
            let (len, ni) = read_varint(payload, i)?;
            let end = ni + len as usize;
            if end > payload.len() {
                return None;
            }
            return decode_packed_neighbors(&payload[ni..end], MAX_NEIGHBORS_PER_PACKET);
        }
        i = skip_field(payload, i, wire)?;
        idx = i;
    }
    None
}

fn push_varint_field(out: &mut heapless::Vec<u8, 240>, field: u32, value: u32) {
    let _ = out.push(((field << 3) | 0) as u8);
    push_varint(out, value);
}

fn push_fixed32_field(out: &mut heapless::Vec<u8, 240>, field: u32, value: u32) {
    let _ = out.push(((field << 3) | 5) as u8);
    let bytes = value.to_le_bytes();
    let _ = out.extend_from_slice(&bytes);
}

fn push_varint(out: &mut heapless::Vec<u8, 240>, mut v: u32) {
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
    use mesh_crypto::{CryptoKey, DEFAULT_PSK};
    use mesh_radio::{primary_channel_hash, MODEM_SHORT_SLOW};

    #[test]
    fn decode_nodeinfo_request_want_response() {
        let data = encode_data_payload_opts(
            SIGNAL_ROUTING_APP,
            &[],
            DataEncodeOpts {
                want_response: true,
                reply_id: 0,
                request_id: 0,
            },
        );
        let (decoded, payload) = decode_data_payload_full(&data).unwrap();
        assert_eq!(decoded.portnum, SIGNAL_ROUTING_APP);
        assert!(decoded.want_response);
        assert!(payload.is_empty());
    }

    #[test]
    fn packed_round_trip() {
        let mut packed = [0u8; 13];
        write_packed_header(&mut packed, 7, true);
        encode_packed_neighbor_entry(
            &mut packed[5..13],
            0x1122_3344,
            -75,
            8,
            PACKED_NEIGHBOR_FLAG_SR_ACTIVE | PACKED_NEIGHBOR_FLAG_HEARS_US,
            0,
        );

        let (hdr, neighbors) = decode_packed_neighbors(&packed, 8).unwrap();
        assert_eq!(hdr.topology_version, 7);
        assert!(hdr.signal_routing_active);
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].node_id, 0x1122_3344);
        assert_eq!(neighbors[0].rssi, -75);
        assert_eq!(neighbors[0].snr, 8);
    }

    #[test]
    fn rejects_format_version_two() {
        let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE + PACKED_NEIGHBOR_ENTRY_SIZE];
        packed[0] = 2;
        packed[1] = PACKED_NEIGHBOR_ENTRY_SIZE as u8;
        packed[2] = SIGNAL_ROUTING_VERSION;
        packed[3] = 1;
        packed[4] = PACKED_HEADER_FLAG_SR_ACTIVE;
        encode_packed_neighbor_entry(
            &mut packed[PACKED_NEIGHBOR_HEADER_SIZE..],
            0x1122_3344,
            -80,
            10,
            0,
            0,
        );
        assert!(decode_packed_neighbors(&packed, 8).is_none());
    }

    #[test]
    fn v3_signal_routing_info_is_field3_bytes_only() {
        let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE];
        write_packed_header(&mut packed, 1, true);
        let encoded = encode_signal_routing_info(&packed);
        assert_eq!(encoded[0], (3 << 3) | 2);
        assert!(encoded.len() >= PACKED_NEIGHBOR_HEADER_SIZE + 2);
    }

    #[test]
    fn topology_wire_encrypt_round_trip() {
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
        let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE];
        write_packed_header(&mut packed, 3, true);
        let (len, frame) = build_topology_wire_frame(
            0x1234_5678,
            99,
            channel_hash,
            3,
            &key,
            &packed,
        )
        .unwrap();
        let mut cipher = frame[PACKET_HEADER_LEN..len as usize].to_vec();
        let (portnum, payload) = try_decrypt_data(
            &key,
            0x1234_5678,
            99,
            channel_hash,
            channel_hash,
            &mut cipher,
        )
        .unwrap();
        assert_eq!(portnum, SIGNAL_ROUTING_APP);
        let (hdr, neighbors) = extract_packed_neighbors(&payload).unwrap();
        assert_eq!(hdr.topology_version, 3);
        assert_eq!(neighbors.len(), 0);
    }
}
