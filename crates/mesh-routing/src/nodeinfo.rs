//! NODEINFO_APP (port 4) wire encode for discovery broadcasts and unicast replies.

use mesh_crypto::{encrypt_packet, CryptoKey};
use mesh_protocol::{PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};

use crate::pool::MAX_PACKET_PAYLOAD;
use crate::router::MAX_WIRE_LEN;
use crate::topology::{encode_data_payload_opts, DataEncodeOpts, SR_BROADCAST_MAX_HOPS};

pub const NODEINFO_APP: u32 = 4;
/// `Config.DeviceConfig.Role.CLIENT` on the wire.
pub const DEVICE_ROLE_CLIENT: u32 = 0;
pub const DEVICE_ROLE_CLIENT_MUTE: u32 = 1;
/// `Config.DeviceConfig.Role.ROUTER` on the wire.
pub const DEVICE_ROLE_ROUTER: u32 = 2;
pub const DEVICE_ROLE_ROUTER_CLIENT: u32 = 3;
pub const DEVICE_ROLE_REPEATER: u32 = 4;
pub const DEVICE_ROLE_ROUTER_LATE: u32 = 5;
pub const DEVICE_ROLE_CLIENT_HIDDEN: u32 = 9;
pub const DEVICE_ROLE_LOST_AND_FOUND: u32 = 10;
/// Pro Micro DIY + TCXO board (`NRF52_PROMICRO_DIY` in mesh.proto).
pub const HW_MODEL_NRF52_PROMICRO_DIY: u32 = 63;
/// Generic private / DIY hardware model id on the wire.
pub const HW_MODEL_PRIVATE: u32 = 255;
/// Periodic nodeinfo broadcast interval (15 min).
pub const NODEINFO_BROADCAST_MS: u32 = 900_000;
/// Minimum gap between unicast nodeinfo replies to the same requester.
pub const NODEINFO_REPLY_COOLDOWN_MS: u32 = 5_000;
/// Max cached peer nodeinfo entries.
pub const MAX_NODEINFO_PEERS: usize = 16;

/// Max `User.long_name` length on the wire.
pub const NODEINFO_LONG_NAME_MAX: usize = 40;
/// Max `User.short_name` length on the wire.
pub const NODEINFO_SHORT_NAME_MAX: usize = 5;

const OWNER_LONG_BASE: &str = "MeshRustic";
const OWNER_SHORT_BASE: &str = "MR";

/// Human-readable fields advertised in the `User` protobuf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeInfoAdvert {
    pub long_name: [u8; NODEINFO_LONG_NAME_MAX],
    pub long_name_len: u8,
    pub short_name: [u8; NODEINFO_SHORT_NAME_MAX],
    pub short_name_len: u8,
    pub hw_model: u32,
    pub role: u32,
    pub is_licensed: bool,
}

impl Default for NodeInfoAdvert {
    fn default() -> Self {
        Self {
            long_name: [0; NODEINFO_LONG_NAME_MAX],
            long_name_len: 0,
            short_name: [0; NODEINFO_SHORT_NAME_MAX],
            short_name_len: 0,
            hw_model: HW_MODEL_NRF52_PROMICRO_DIY,
            role: DEVICE_ROLE_CLIENT,
            is_licensed: false,
        }
    }
}

impl NodeInfoAdvert {
    /// Fill owner names from node id (MT-style: long gets low 16 bits, short gets low byte).
    pub fn populate_owner_names(node_num: u32, advert: &mut Self) {
        advert.hw_model = HW_MODEL_NRF52_PROMICRO_DIY;
        advert.role = DEVICE_ROLE_CLIENT;
        advert.is_licensed = false;

        let mut long_len = 0usize;
        for &b in OWNER_LONG_BASE.as_bytes() {
            advert.long_name[long_len] = b;
            long_len += 1;
        }
        advert.long_name[long_len] = b' ';
        long_len += 1;
        push_hex_u16(&mut advert.long_name[long_len..long_len + 4], (node_num & 0xffff) as u16);
        long_len += 4;
        advert.long_name_len = long_len as u8;

        let mut short_len = 0usize;
        for &b in OWNER_SHORT_BASE.as_bytes() {
            advert.short_name[short_len] = b;
            short_len += 1;
        }
        push_hex_u8(&mut advert.short_name[short_len..short_len + 2], (node_num & 0xff) as u8);
        short_len += 2;
        advert.short_name_len = short_len as u8;
    }
}

/// Full on-air node identity (User protobuf + Curve25519 public key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeInfoIdentity {
    pub advert: NodeInfoAdvert,
    pub public_key: [u8; 32],
}

impl NodeInfoIdentity {
    pub fn new(advert: NodeInfoAdvert, public_key: [u8; 32]) -> Self {
        Self { advert, public_key }
    }

    pub fn for_node(node_num: u32, public_key: [u8; 32]) -> Self {
        let mut advert = NodeInfoAdvert::default();
        NodeInfoAdvert::populate_owner_names(node_num, &mut advert);
        Self { advert, public_key }
    }

    pub fn with_default_advert(public_key: [u8; 32]) -> Self {
        Self::for_node(0, public_key)
    }
}

/// Format mesh node id as `!xxxxxxxx` (9 bytes, no NUL).
pub fn format_node_id(out: &mut [u8; 9], node_num: u32) -> usize {
    out[0] = b'!';
    push_hex_u32(&mut out[1..], node_num);
    9
}

/// Hand-rolled `User` protobuf (id, names, hw_model, is_licensed, role, public_key).
pub fn encode_user(node_num: u32, identity: &NodeInfoIdentity) -> heapless::Vec<u8, 240> {
    let advert = &identity.advert;
    let mut id = [0u8; 9];
    let id_len = format_node_id(&mut id, node_num);
    let mut out = heapless::Vec::new();
    push_string_field(&mut out, 1, &id[..id_len]);
    push_string_field(
        &mut out,
        2,
        &advert.long_name[..advert.long_name_len as usize],
    );
    push_string_field(
        &mut out,
        3,
        &advert.short_name[..advert.short_name_len as usize],
    );
    push_varint_field(&mut out, 5, advert.hw_model);
    if advert.is_licensed {
        push_varint_field(&mut out, 6, 1);
    }
    if advert.role != DEVICE_ROLE_CLIENT {
        push_varint_field(&mut out, 7, advert.role);
    }
    if identity.public_key.iter().any(|&b| b != 0) {
        push_bytes_field(&mut out, 8, &identity.public_key);
    }
    out
}

/// Decode a hand-encoded `User` protobuf payload from NODEINFO_APP.
pub fn decode_user(payload: &[u8]) -> Option<NodeInfoIdentity> {
    let mut advert = NodeInfoAdvert::default();
    let mut public_key = [0u8; 32];
    let mut has_short = false;
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (2, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                let copy_len = slice.len().min(NODEINFO_LONG_NAME_MAX);
                advert.long_name[..copy_len].copy_from_slice(&slice[..copy_len]);
                advert.long_name_len = copy_len as u8;
                i = end;
            }
            (3, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                let copy_len = slice.len().min(NODEINFO_SHORT_NAME_MAX);
                advert.short_name[..copy_len].copy_from_slice(&slice[..copy_len]);
                advert.short_name_len = copy_len as u8;
                has_short = true;
                i = end;
            }
            (5, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                advert.hw_model = v;
                i = ni;
            }
            (6, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                advert.is_licensed = v != 0;
                i = ni;
            }
            (7, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                advert.role = v;
                i = ni;
            }
            (8, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                let copy_len = slice.len().min(32);
                public_key[..copy_len].copy_from_slice(&slice[..copy_len]);
                i = end;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    if !has_short {
        return None;
    }
    Some(NodeInfoIdentity { advert, public_key })
}

/// Cached peer nodeinfo from on-air NODEINFO_APP packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeInfoPeerEntry {
    pub node_num: u32,
    pub identity: NodeInfoIdentity,
    pub last_seen_ms: u32,
}

pub struct NodeInfoCache {
    entries: [NodeInfoPeerEntry; MAX_NODEINFO_PEERS],
    count: u8,
}

impl NodeInfoCache {
    pub const fn new() -> Self {
        Self {
            entries: [NodeInfoPeerEntry {
                node_num: 0,
                identity: NodeInfoIdentity {
                    advert: NodeInfoAdvert {
                        long_name: [0; NODEINFO_LONG_NAME_MAX],
                        long_name_len: 0,
                        short_name: [0; NODEINFO_SHORT_NAME_MAX],
                        short_name_len: 0,
                        hw_model: HW_MODEL_NRF52_PROMICRO_DIY,
                        role: DEVICE_ROLE_CLIENT,
                        is_licensed: false,
                    },
                    public_key: [0; 32],
                },
                last_seen_ms: 0,
            }; MAX_NODEINFO_PEERS],
            count: 0,
        }
    }

    pub fn count(&self) -> u8 {
        self.count
    }

    pub fn get(&self, node_num: u32) -> Option<&NodeInfoPeerEntry> {
        (0..self.count as usize)
            .find(|&i| self.entries[i].node_num == node_num)
            .map(|i| &self.entries[i])
    }

    pub fn upsert(&mut self, node_num: u32, identity: NodeInfoIdentity, now_ms: u32) -> bool {
        if node_num == 0 {
            return false;
        }
        for i in 0..self.count as usize {
            if self.entries[i].node_num == node_num {
                self.entries[i].identity = identity;
                self.entries[i].last_seen_ms = now_ms;
                return false;
            }
        }
        if (self.count as usize) < MAX_NODEINFO_PEERS {
            let idx = self.count as usize;
            self.entries[idx] = NodeInfoPeerEntry {
                node_num,
                identity,
                last_seen_ms: now_ms,
            };
            self.count += 1;
            return true;
        }
        let mut oldest_idx = 0usize;
        let mut oldest = self.entries[0].last_seen_ms;
        for i in 1..self.count as usize {
            if self.entries[i].last_seen_ms < oldest {
                oldest = self.entries[i].last_seen_ms;
                oldest_idx = i;
            }
        }
        self.entries[oldest_idx] = NodeInfoPeerEntry {
            node_num,
            identity,
            last_seen_ms: now_ms,
        };
        true
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

/// Broadcast nodeinfo to `NODENUM_BROADCAST` (periodic discovery).
pub fn build_nodeinfo_wire_frame(
    node_num: u32,
    packet_id: u32,
    channel_hash: u8,
    hop_limit: u8,
    key: &CryptoKey,
    identity: &NodeInfoIdentity,
) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
    build_nodeinfo_frame(
        NODENUM_BROADCAST,
        node_num,
        packet_id,
        channel_hash,
        hop_limit,
        key,
        identity,
        DataEncodeOpts::default(),
    )
}

/// Unicast nodeinfo reply to a requester (`reply_id` links to the request packet id).
pub fn build_nodeinfo_reply_frame(
    to: u32,
    from: u32,
    packet_id: u32,
    reply_id: u32,
    channel_hash: u8,
    hop_limit: u8,
    key: &CryptoKey,
    identity: &NodeInfoIdentity,
) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
    build_nodeinfo_frame(
        to,
        from,
        packet_id,
        channel_hash,
        hop_limit,
        key,
        identity,
        DataEncodeOpts {
            want_response: false,
            reply_id,
            request_id: 0,
        },
    )
}

fn build_nodeinfo_frame(
    to: u32,
    from: u32,
    packet_id: u32,
    channel_hash: u8,
    hop_limit: u8,
    key: &CryptoKey,
    identity: &NodeInfoIdentity,
    data_opts: DataEncodeOpts,
) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
    let user = encode_user(from, identity);
    let plaintext = encode_data_payload_opts(NODEINFO_APP, &user, data_opts);
    if plaintext.len() > MAX_PACKET_PAYLOAD {
        return None;
    }
    let mut cipher = [0u8; MAX_PACKET_PAYLOAD];
    cipher[..plaintext.len()].copy_from_slice(&plaintext);
    encrypt_packet(key, from, packet_id as u64, &mut cipher[..plaintext.len()]);

    let hop = hop_limit.min(SR_BROADCAST_MAX_HOPS);
    let header = PacketHeader::from_fields(
        to,
        from,
        packet_id,
        channel_hash,
        hop,
        hop,
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

fn push_string_field(out: &mut heapless::Vec<u8, 240>, field: u32, data: &[u8]) {
    let _ = out.push(((field << 3) | 2) as u8);
    push_varint(out, data.len() as u32);
    let _ = out.extend_from_slice(data);
}

fn push_bytes_field(out: &mut heapless::Vec<u8, 240>, field: u32, data: &[u8]) {
    let _ = out.push(((field << 3) | 2) as u8);
    push_varint(out, data.len() as u32);
    let _ = out.extend_from_slice(data);
}

fn push_varint_field(out: &mut heapless::Vec<u8, 240>, field: u32, value: u32) {
    let _ = out.push(((field << 3) | 0) as u8);
    push_varint(out, value);
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

fn push_hex_u32(out: &mut [u8], value: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in (0..8).rev() {
        let nibble = ((value >> (i * 4)) & 0xF) as usize;
        out[7 - i] = HEX[nibble];
    }
}

fn push_hex_u16(out: &mut [u8], value: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in (0..4).rev() {
        let nibble = ((value >> (i * 4)) & 0xF) as usize;
        out[3 - i] = HEX[nibble];
    }
}

fn push_hex_u8(out: &mut [u8], value: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out[0] = HEX[(value >> 4) as usize];
    out[1] = HEX[(value & 0xF) as usize];
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_crypto::{CryptoKey, DEFAULT_PSK};
    use mesh_radio::{primary_channel_hash, MODEM_SHORT_SLOW};
    use crate::topology::try_decrypt_data_full;

    const TEST_PUBKEY: [u8; 32] = [0xAB; 32];

    #[test]
    fn node_id_format() {
        let mut id = [0u8; 9];
        format_node_id(&mut id, 0x677a_1caf);
        assert_eq!(&id, b"!677a1caf");
    }

    #[test]
    fn owner_names_follow_mt_suffix_rules() {
        let identity = NodeInfoIdentity::for_node(0x677a_1caf, TEST_PUBKEY);
        assert_eq!(
            &identity.advert.long_name[..identity.advert.long_name_len as usize],
            b"MeshRustic 1caf"
        );
        assert_eq!(
            &identity.advert.short_name[..identity.advert.short_name_len as usize],
            b"MRaf"
        );
    }

    #[test]
    fn user_payload_has_core_fields() {
        let identity = NodeInfoIdentity::for_node(0x1234_5678, TEST_PUBKEY);
        let user = encode_user(0x1234_5678, &identity);
        assert!(user.windows(9).any(|w| w == b"!12345678"));
        assert!(user.windows(15).any(|w| w == b"MeshRustic 5678"));
        assert!(user.windows(4).any(|w| w == b"MR78"));
        assert!(user.windows(32).any(|w| w == TEST_PUBKEY));
    }

    #[test]
    fn nodeinfo_wire_encrypt_round_trip() {
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
        let identity = NodeInfoIdentity::for_node(0x677a_1caf, TEST_PUBKEY);
        let (len, frame) = build_nodeinfo_wire_frame(
            0x677a_1caf,
            42,
            channel_hash,
            3,
            &key,
            &identity,
        )
        .unwrap();
        let mut cipher = frame[PACKET_HEADER_LEN..len as usize].to_vec();
        let (decoded, payload) = try_decrypt_data_full(
            &key,
            0x677a_1caf,
            42,
            channel_hash,
            channel_hash,
            &mut cipher,
        )
        .unwrap();
        assert_eq!(decoded.portnum, NODEINFO_APP);
        assert!(!decoded.want_response);
        assert_eq!(payload.as_slice(), encode_user(0x677a_1caf, &identity).as_slice());
    }

    #[test]
    fn decode_user_round_trip() {
        let identity = NodeInfoIdentity::for_node(0x677a_1caf, TEST_PUBKEY);
        let encoded = encode_user(0x677a_1caf, &identity);
        let decoded = decode_user(&encoded).expect("decode");
        assert_eq!(decoded.advert.short_name_len, identity.advert.short_name_len);
        assert_eq!(
            &decoded.advert.short_name[..decoded.advert.short_name_len as usize],
            &identity.advert.short_name[..identity.advert.short_name_len as usize]
        );
        assert_eq!(decoded.advert.role, identity.advert.role);
        assert_eq!(decoded.public_key, identity.public_key);
    }

    #[test]
    fn nodeinfo_cache_upsert_and_lookup() {
        let mut cache = NodeInfoCache::new();
        let identity = NodeInfoIdentity::for_node(0x1234_5678, TEST_PUBKEY);
        assert!(cache.upsert(0x1234_5678, identity, 100));
        assert_eq!(cache.count(), 1);
        assert!(cache.get(0x1234_5678).is_some());
        assert!(!cache.upsert(0x1234_5678, identity, 200));
        assert_eq!(cache.get(0x1234_5678).unwrap().last_seen_ms, 200);
    }

    #[test]
    fn nodeinfo_reply_sets_reply_id_on_data_layer() {
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
        let identity = NodeInfoIdentity::for_node(0x677a_1caf, TEST_PUBKEY);
        let request_id = 0xBEEF_0001;
        let (len, frame) = build_nodeinfo_reply_frame(
            0xAABB_CCDD,
            0x677a_1caf,
            99,
            request_id,
            channel_hash,
            3,
            &key,
            &identity,
        )
        .unwrap();
        let header = PacketHeader::decode(&frame[..PACKET_HEADER_LEN]).unwrap();
        assert_eq!(header.to, 0xAABB_CCDD);
        assert_eq!(header.from, 0x677a_1caf);
        let mut cipher = frame[PACKET_HEADER_LEN..len as usize].to_vec();
        let (decoded, _payload) = try_decrypt_data_full(
            &key,
            0x677a_1caf,
            99,
            channel_hash,
            channel_hash,
            &mut cipher,
        )
        .unwrap();
        assert_eq!(decoded.reply_id, request_id);
    }
}
