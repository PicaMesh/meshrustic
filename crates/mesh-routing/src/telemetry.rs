//! TELEMETRY_APP (port 67) wire encode for periodic device metrics broadcasts.

use mesh_crypto::{encrypt_packet, CryptoKey};
use mesh_protocol::{PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};

use crate::pool::MAX_PACKET_PAYLOAD;
use crate::router::MAX_WIRE_LEN;
use crate::topology::{encode_data_payload_opts, DataEncodeOpts, SR_BROADCAST_MAX_HOPS};

pub const TELEMETRY_APP: u32 = 67;
/// Periodic device telemetry broadcast interval (20 min; config later).
pub const DEVICE_TELEMETRY_BROADCAST_MS: u32 = 1_200_000;
/// Wire value when USB-powered (no battery percent).
pub const MAGIC_USB_BATTERY_LEVEL: u32 = 101;
/// Plausible single-cell LiPo range and SAADC saturation threshold.
pub const MIN_BATTERY_MV: u32 = 2500;
pub const MAX_BATTERY_MV: u32 = 4350;
pub const ADC_SATURATED_RAW: u32 = 3950;

/// Fields advertised in `Telemetry.device_metrics` (port 67).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DeviceMetricsSnapshot {
    pub battery_level: u32,
    pub voltage_v: f32,
    pub channel_utilization: f32,
    pub air_util_tx: f32,
    pub uptime_seconds: u32,
}

/// Encode `Telemetry { device_metrics { ... } }` (time=0 when RTC unset).
pub fn encode_device_telemetry(
    metrics: &DeviceMetricsSnapshot,
    out: &mut heapless::Vec<u8, 128>,
) -> bool {
    let mut device_metrics = heapless::Vec::<u8, 64>::new();
    push_varint_field(&mut device_metrics, 1, metrics.battery_level);
    push_f32_field(&mut device_metrics, 2, metrics.voltage_v);
    push_f32_field(&mut device_metrics, 3, metrics.channel_utilization);
    push_f32_field(&mut device_metrics, 4, metrics.air_util_tx);
    push_varint_field(&mut device_metrics, 5, metrics.uptime_seconds);

    let _ = out.push(((1 << 3) | 5) as u8);
    let _ = out.extend_from_slice(&0u32.to_le_bytes());

    let _ = out.push(((2 << 3) | 2) as u8);
    push_varint(out, device_metrics.len() as u32);
    out.extend_from_slice(&device_metrics).is_ok()
}

/// Broadcast device telemetry to `NODENUM_BROADCAST`.
pub fn build_device_telemetry_wire_frame(
    node_num: u32,
    packet_id: u32,
    channel_hash: u8,
    hop_limit: u8,
    key: &CryptoKey,
    metrics: &DeviceMetricsSnapshot,
) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
    let mut telemetry = heapless::Vec::<u8, 128>::new();
    if !encode_device_telemetry(metrics, &mut telemetry) {
        return None;
    }
    let plaintext = encode_data_payload_opts(TELEMETRY_APP, &telemetry, DataEncodeOpts::default());
    if plaintext.len() > MAX_PACKET_PAYLOAD {
        return None;
    }
    let mut cipher = [0u8; MAX_PACKET_PAYLOAD];
    cipher[..plaintext.len()].copy_from_slice(&plaintext);
    encrypt_packet(key, node_num, packet_id as u64, &mut cipher[..plaintext.len()]);

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
        0,
    );
    let mut bytes = [0u8; MAX_WIRE_LEN];
    header.encode_to((&mut bytes[..PACKET_HEADER_LEN]).try_into().ok()?);
    let len = PACKET_HEADER_LEN + plaintext.len();
    bytes[PACKET_HEADER_LEN..len].copy_from_slice(&cipher[..plaintext.len()]);
    Some((len as u8, bytes))
}

/// LiPo percent from voltage (single cell, same OCV endpoints as common mesh nodes).
pub fn battery_level_from_mv(voltage_mv: u32) -> u32 {
    const EMPTY_MV: u32 = 3100;
    const FULL_MV: u32 = 4190;
    if voltage_mv <= EMPTY_MV {
        0
    } else if voltage_mv >= FULL_MV {
        100
    } else {
        ((voltage_mv - EMPTY_MV) * 100 / (FULL_MV - EMPTY_MV)).min(100)
    }
}

/// Reject floating divider / ADC rail readings when no pack is connected.
pub fn is_plausible_battery_reading(voltage_mv: u32, raw_adc: u32) -> bool {
    raw_adc < ADC_SATURATED_RAW && voltage_mv >= MIN_BATTERY_MV && voltage_mv <= MAX_BATTERY_MV
}

/// Map raw SAADC average to reported mV, level, and whether telemetry should run.
pub fn interpret_battery_reading(
    voltage_mv: u32,
    raw_adc: u32,
    usb_powered: bool,
) -> (u32, u32, bool) {
    if is_plausible_battery_reading(voltage_mv, raw_adc) {
        return (voltage_mv, battery_level_from_mv(voltage_mv), true);
    }
    if usb_powered {
        return (0, MAGIC_USB_BATTERY_LEVEL, true);
    }
    (0, 0, false)
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DecodedDeviceMetrics {
    pub battery_level: Option<u32>,
    pub voltage_v: Option<f32>,
    pub channel_utilization: Option<f32>,
    pub air_util_tx: Option<f32>,
    pub uptime_seconds: Option<u32>,
}

/// Decode `Telemetry.device_metrics` payload (for tests and RX logging).
pub fn decode_device_metrics(payload: &[u8]) -> Option<DecodedDeviceMetrics> {
    let mut out = DecodedDeviceMetrics::default();
    let mut i = 0usize;
    while i < payload.len() {
        let (tag, tag_len) = read_varint(payload, i)?;
        i += tag_len;
        let field = tag >> 3;
        let wire = tag & 7;
        match (field, wire) {
            (1, 0) => {
                let (val, n) = read_varint(payload, i)?;
                i += n;
                out.battery_level = Some(val);
            }
            (2, 5) if i + 4 <= payload.len() => {
                let bits = u32::from_le_bytes(payload[i..i + 4].try_into().ok()?);
                i += 4;
                out.voltage_v = Some(f32::from_bits(bits));
            }
            (3, 5) if i + 4 <= payload.len() => {
                let bits = u32::from_le_bytes(payload[i..i + 4].try_into().ok()?);
                i += 4;
                out.channel_utilization = Some(f32::from_bits(bits));
            }
            (4, 5) if i + 4 <= payload.len() => {
                let bits = u32::from_le_bytes(payload[i..i + 4].try_into().ok()?);
                i += 4;
                out.air_util_tx = Some(f32::from_bits(bits));
            }
            (5, 0) => {
                let (val, n) = read_varint(payload, i)?;
                i += n;
                out.uptime_seconds = Some(val);
            }
            (_, 0) => {
                let (_, n) = read_varint(payload, i)?;
                i += n;
            }
            (_, 5) if i + 4 <= payload.len() => {
                i += 4;
            }
            (_, 2) => {
                let (len, n) = read_varint(payload, i)?;
                i += n;
                i += len as usize;
            }
            (_, 1) if i + 8 <= payload.len() => {
                i += 8;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Skip `Telemetry.time` and return nested `device_metrics` bytes.
pub fn extract_device_metrics(payload: &[u8]) -> Option<&[u8]> {
    let mut i = 0usize;
    while i < payload.len() {
        let (tag, _) = read_varint(payload, i)?;
        let field = tag >> 3;
        let wire = tag & 7;
        i += varint_len(tag);
        match (field, wire) {
            (1, 5) if i + 4 <= payload.len() => {
                i += 4;
            }
            (2, 2) => {
                let (len, n) = read_varint(payload, i)?;
                i += n;
                let end = i + len as usize;
                if end <= payload.len() {
                    return Some(&payload[i..end]);
                }
                return None;
            }
            (_, 0) => {
                let (_, n) = read_varint(payload, i)?;
                i += n;
            }
            (_, 5) if i + 4 <= payload.len() => {
                i += 4;
            }
            (_, 2) => {
                let (len, n) = read_varint(payload, i)?;
                i += n + len as usize;
            }
            _ => return None,
        }
    }
    None
}

fn push_varint_field<const N: usize>(out: &mut heapless::Vec<u8, N>, field: u32, value: u32) {
    let _ = out.push(((field << 3) | 0) as u8);
    push_varint(out, value);
}

fn push_f32_field<const N: usize>(out: &mut heapless::Vec<u8, N>, field: u32, value: f32) {
    let _ = out.push(((field << 3) | 5) as u8);
    let _ = out.extend_from_slice(&value.to_bits().to_le_bytes());
}

fn push_varint<const N: usize>(out: &mut heapless::Vec<u8, N>, mut v: u32) {
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

fn read_varint(data: &[u8], mut i: usize) -> Option<(u32, usize)> {
    let start = i;
    let mut val = 0u32;
    let mut shift = 0u32;
    while i < data.len() {
        let byte = data[i];
        i += 1;
        val |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some((val, i - start));
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
    None
}

fn varint_len(mut v: u32) -> usize {
    let mut n = 1usize;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_crypto::{CryptoKey, DEFAULT_PSK};
    use mesh_radio::{primary_channel_hash, MODEM_SHORT_SLOW};
    use crate::topology::try_decrypt_data_full;

    #[test]
    fn saturated_adc_is_not_plausible() {
        assert!(!is_plausible_battery_reading(5997, 4093));
        assert!(!is_plausible_battery_reading(4200, 4000));
    }

    #[test]
    fn usb_without_battery_reports_zero_volts_and_101() {
        let (mv, level, valid) = interpret_battery_reading(5997, 4093, true);
        assert_eq!(mv, 0);
        assert_eq!(level, MAGIC_USB_BATTERY_LEVEL);
        assert!(valid);
    }

    #[test]
    fn battery_level_from_mv_endpoints() {
        assert_eq!(battery_level_from_mv(3100), 0);
        assert_eq!(battery_level_from_mv(4190), 100);
        assert!(battery_level_from_mv(3650) > 40 && battery_level_from_mv(3650) < 60);
    }

    #[test]
    fn encode_decode_device_metrics_round_trip() {
        let metrics = DeviceMetricsSnapshot {
            battery_level: 72,
            voltage_v: 3.85,
            channel_utilization: 12.5,
            air_util_tx: 4.0,
            uptime_seconds: 3600,
        };
        let mut wire = heapless::Vec::<u8, 128>::new();
        assert!(encode_device_telemetry(&metrics, &mut wire));
        let nested = extract_device_metrics(&wire).expect("device_metrics nested");
        let decoded = decode_device_metrics(nested).expect("decode");
        assert_eq!(decoded.battery_level, Some(72));
        assert!((decoded.voltage_v.unwrap() - 3.85).abs() < 0.001);
        assert!((decoded.channel_utilization.unwrap() - 12.5).abs() < 0.001);
        assert!((decoded.air_util_tx.unwrap() - 4.0).abs() < 0.001);
        assert_eq!(decoded.uptime_seconds, Some(3600));
    }

    #[test]
    fn telemetry_wire_decrypt_round_trip() {
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
        let metrics = DeviceMetricsSnapshot {
            battery_level: 101,
            voltage_v: 4.12,
            channel_utilization: 0.0,
            air_util_tx: 1.5,
            uptime_seconds: 42,
        };
        let (len, mut frame) = build_device_telemetry_wire_frame(
            0x677a_1caf,
            88,
            channel_hash,
            3,
            &key,
            &metrics,
        )
        .unwrap();
        let mut cipher = frame[mesh_protocol::PACKET_HEADER_LEN..len as usize].to_vec();
        let (portnum, payload) = crate::topology::try_decrypt_data(
            &key,
            0x677a_1caf,
            88,
            channel_hash,
            channel_hash,
            &mut cipher,
        )
        .unwrap();
        assert_eq!(portnum, TELEMETRY_APP);
        let nested = extract_device_metrics(&payload).expect("nested metrics");
        let decoded = decode_device_metrics(nested).unwrap();
        assert_eq!(decoded.battery_level, Some(101));
        assert!((decoded.voltage_v.unwrap() - 4.12).abs() < 0.001);

        let (decoded_data, _) = try_decrypt_data_full(
            &key,
            0x677a_1caf,
            88,
            channel_hash,
            channel_hash,
            &mut frame[mesh_protocol::PACKET_HEADER_LEN..len as usize],
        )
        .unwrap();
        assert_eq!(decoded_data.portnum, TELEMETRY_APP);
    }
}
