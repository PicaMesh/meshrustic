//! Decrypted payload summaries for RX logging.

use mesh_protocol::portnum::num;

use crate::telemetry::{decode_device_metrics, extract_device_metrics, TELEMETRY_APP};
use crate::topology::{extract_packed_neighbors, SIGNAL_ROUTING_APP};
use crate::traceroute::{decode_route_discovery, TRACEROUTE_APP};

pub const RX_TEXT_PREVIEW: usize = 48;
pub const RX_HEX_PREVIEW: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RxPayloadSummary {
    #[default]
    Encrypted,
    UnknownPort {
        portnum: u32,
        len: u16,
    },
    Text {
        len: u16,
        preview: [u8; RX_TEXT_PREVIEW],
        preview_len: u8,
    },
    Topology {
        neighbors: u8,
        topo_v: u8,
        sr_active: bool,
    },
    Position {
        latitude_i: i32,
        longitude_i: i32,
    },
    Routing {
        error_reason: u32,
    },
    NodeInfo {
        short_name: [u8; 4],
        short_len: u8,
        role: u32,
    },
    Traceroute {
        route: u8,
        snr: u8,
        route_back: u8,
        snr_back: u8,
    },
    DeviceTelemetry {
        battery_level: u32,
        voltage_mv: u32,
    },
    Raw {
        portnum: u32,
        len: u16,
        hex: [u8; RX_HEX_PREVIEW],
        hex_len: u8,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxDecodeInfo {
    pub portnum: Option<u32>,
    pub payload_len: u16,
    pub summary: RxPayloadSummary,
}

impl RxDecodeInfo {
    pub const fn encrypted(payload_len: u16) -> Self {
        Self {
            portnum: None,
            payload_len,
            summary: RxPayloadSummary::Encrypted,
        }
    }
}

pub fn summarize_decrypted(portnum: u32, payload: &[u8]) -> RxPayloadSummary {
    match portnum {
        num::TEXT_MESSAGE_APP | num::TEXT_MESSAGE_COMPRESSED_APP => {
            let (preview, preview_len) = text_preview(payload);
            RxPayloadSummary::Text {
                len: payload.len().min(u16::MAX as usize) as u16,
                preview,
                preview_len,
            }
        }
        num::POSITION_APP => decode_position(payload).unwrap_or(RxPayloadSummary::Raw {
            portnum,
            len: payload.len().min(u16::MAX as usize) as u16,
            hex: hex_preview(payload),
            hex_len: payload.len().min(RX_HEX_PREVIEW) as u8,
        }),
        num::ROUTING_APP => decode_routing(payload).unwrap_or(RxPayloadSummary::Raw {
            portnum,
            len: payload.len().min(u16::MAX as usize) as u16,
            hex: hex_preview(payload),
            hex_len: payload.len().min(RX_HEX_PREVIEW) as u8,
        }),
        num::NODEINFO_APP => decode_nodeinfo(payload).unwrap_or(RxPayloadSummary::Raw {
            portnum,
            len: payload.len().min(u16::MAX as usize) as u16,
            hex: hex_preview(payload),
            hex_len: payload.len().min(RX_HEX_PREVIEW) as u8,
        }),
        TRACEROUTE_APP => decode_traceroute(payload).unwrap_or(RxPayloadSummary::Raw {
            portnum,
            len: payload.len().min(u16::MAX as usize) as u16,
            hex: hex_preview(payload),
            hex_len: payload.len().min(RX_HEX_PREVIEW) as u8,
        }),
        TELEMETRY_APP => decode_device_telemetry(payload).unwrap_or(RxPayloadSummary::Raw {
            portnum,
            len: payload.len().min(u16::MAX as usize) as u16,
            hex: hex_preview(payload),
            hex_len: payload.len().min(RX_HEX_PREVIEW) as u8,
        }),
        SIGNAL_ROUTING_APP => {
            if let Some((hdr, neighbors)) = extract_packed_neighbors(payload) {
                RxPayloadSummary::Topology {
                    neighbors: neighbors.len().min(u8::MAX as usize) as u8,
                    topo_v: hdr.topology_version,
                    sr_active: hdr.signal_routing_active,
                }
            } else if payload.is_empty() {
                RxPayloadSummary::Topology {
                    neighbors: 0,
                    topo_v: 0,
                    sr_active: false,
                }
            } else {
                RxPayloadSummary::Raw {
                    portnum,
                    len: payload.len().min(u16::MAX as usize) as u16,
                    hex: hex_preview(payload),
                    hex_len: payload.len().min(RX_HEX_PREVIEW) as u8,
                }
            }
        }
        _ => RxPayloadSummary::Raw {
            portnum,
            len: payload.len().min(u16::MAX as usize) as u16,
            hex: hex_preview(payload),
            hex_len: payload.len().min(RX_HEX_PREVIEW) as u8,
        },
    }
}

fn text_preview(payload: &[u8]) -> ([u8; RX_TEXT_PREVIEW], u8) {
    let mut preview = [0u8; RX_TEXT_PREVIEW];
    let mut len = 0u8;
    for (i, &byte) in payload.iter().take(RX_TEXT_PREVIEW).enumerate() {
        preview[i] = if byte >= 0x20 && byte <= 0x7E {
            byte
        } else if byte == b'\n' || byte == b'\r' || byte == b'\t' {
            byte
        } else {
            b'.'
        };
        len += 1;
    }
    (preview, len)
}

fn hex_preview(payload: &[u8]) -> [u8; RX_HEX_PREVIEW] {
    let mut out = [0u8; RX_HEX_PREVIEW];
    let n = payload.len().min(RX_HEX_PREVIEW);
    out[..n].copy_from_slice(&payload[..n]);
    out
}

fn decode_position(payload: &[u8]) -> Option<RxPayloadSummary> {
    let mut latitude_i = None;
    let mut longitude_i = None;
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 5) if i + 4 <= payload.len() => {
                latitude_i = Some(i32::from_le_bytes([
                    payload[i],
                    payload[i + 1],
                    payload[i + 2],
                    payload[i + 3],
                ]));
                i += 4;
            }
            (2, 5) if i + 4 <= payload.len() => {
                longitude_i = Some(i32::from_le_bytes([
                    payload[i],
                    payload[i + 1],
                    payload[i + 2],
                    payload[i + 3],
                ]));
                i += 4;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(RxPayloadSummary::Position {
        latitude_i: latitude_i?,
        longitude_i: longitude_i?,
    })
}

fn decode_nodeinfo(payload: &[u8]) -> Option<RxPayloadSummary> {
    let mut short_name = [0u8; 4];
    let mut short_len = 0u8;
    let mut role = 0u32;
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (3, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                short_len = slice.len().min(4) as u8;
                short_name[..short_len as usize].copy_from_slice(&slice[..short_len as usize]);
                i = end;
            }
            (7, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                role = v;
                i = ni;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(RxPayloadSummary::NodeInfo {
        short_name,
        short_len,
        role,
    })
}

fn decode_traceroute(payload: &[u8]) -> Option<RxPayloadSummary> {
    let rd = decode_route_discovery(payload)?;
    Some(RxPayloadSummary::Traceroute {
        route: rd.route.len().min(u8::MAX as usize) as u8,
        snr: rd.snr_towards.len().min(u8::MAX as usize) as u8,
        route_back: rd.route_back.len().min(u8::MAX as usize) as u8,
        snr_back: rd.snr_back.len().min(u8::MAX as usize) as u8,
    })
}

fn decode_device_telemetry(payload: &[u8]) -> Option<RxPayloadSummary> {
    let nested = extract_device_metrics(payload)?;
    let dm = decode_device_metrics(nested)?;
    let voltage_v = dm.voltage_v?;
    let battery_level = dm.battery_level.unwrap_or(0);
    Some(RxPayloadSummary::DeviceTelemetry {
        battery_level,
        voltage_mv: (voltage_v * 1000.0) as u32,
    })
}

fn decode_routing(payload: &[u8]) -> Option<RxPayloadSummary> {
    let mut error_reason = None;
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        if field == 1 && wire == 0 {
            let (v, ni) = read_varint(payload, i)?;
            error_reason = Some(v);
            i = ni;
        } else {
            i = skip_field(payload, i, wire)?;
        }
        idx = i;
    }
    Some(RxPayloadSummary::Routing {
        error_reason: error_reason?,
    })
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
    use crate::nodeinfo::{encode_user, NodeInfoAdvert, NodeInfoIdentity};

    const TEST_PUBKEY: [u8; 32] = [0xAB; 32];

    #[test]
    fn text_summary_preview() {
        let summary = summarize_decrypted(num::TEXT_MESSAGE_APP, b"hello mesh");
        match summary {
            RxPayloadSummary::Text {
                len,
                preview,
                preview_len,
            } => {
                assert_eq!(len, 10);
                assert_eq!(preview_len, 10);
                assert_eq!(&preview[..preview_len as usize], b"hello mesh");
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn routing_error_reason() {
        let mut payload = heapless::Vec::<u8, 8>::new();
        payload.push((1 << 3) | 0).unwrap();
        payload.push(3).unwrap(); // NONE or similar enum value
        match summarize_decrypted(num::ROUTING_APP, &payload) {
            RxPayloadSummary::Routing { error_reason } => assert_eq!(error_reason, 3),
            _ => panic!("expected routing"),
        }
    }

    #[test]
    fn nodeinfo_summary() {
        let mut advert = NodeInfoAdvert::default();
        advert.long_name[..8].copy_from_slice(b"TestNode");
        advert.long_name_len = 8;
        advert.short_name[..2].copy_from_slice(b"TN");
        advert.short_name_len = 2;
        advert.hw_model = 255;
        advert.role = 2;
        let identity = NodeInfoIdentity::new(advert, TEST_PUBKEY);
        let user = encode_user(0xAABB_CCDD, &identity);
        match summarize_decrypted(num::NODEINFO_APP, &user) {
            RxPayloadSummary::NodeInfo {
                short_name,
                short_len,
                role,
            } => {
                assert_eq!(short_len, 2);
                assert_eq!(&short_name[..2], b"TN");
                assert_eq!(role, 2);
            }
            _ => panic!("expected nodeinfo"),
        }
    }

    #[test]
    fn traceroute_summary() {
        let mut rd = crate::traceroute::RouteDiscovery::default();
        let _ = rd.route.push(0x1111_1111);
        let _ = rd.snr_towards.push(40);
        let mut wire = heapless::Vec::<u8, 128>::new();
        crate::traceroute::encode_route_discovery(&rd, &mut wire);
        match summarize_decrypted(num::TRACEROUTE_APP, &wire) {
            RxPayloadSummary::Traceroute {
                route,
                snr,
                route_back,
                snr_back,
            } => {
                assert_eq!(route, 1);
                assert_eq!(snr, 1);
                assert_eq!(route_back, 0);
                assert_eq!(snr_back, 0);
            }
            _ => panic!("expected traceroute"),
        }
    }
}
