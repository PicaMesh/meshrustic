use mesh_crypto::{encrypt_packet, CryptoKey};
use mesh_protocol::{PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};

use crate::pool::MAX_PACKET_PAYLOAD;
use crate::router::MAX_WIRE_LEN;
use crate::topology::{encode_data_payload_opts, DataBitfield, DataEncodeOpts};

pub const TELEMETRY_APP: u32 = 67;
pub const DEFAULT_DEVICE_UPDATE_INTERVAL_SECS: u32 = 1_200;
pub const DEVICE_TELEMETRY_BROADCAST_MS: u32 = DEFAULT_DEVICE_UPDATE_INTERVAL_SECS * 1_000;
pub const MAGIC_USB_BATTERY_LEVEL: u32 = 101;
pub const MIN_BATTERY_MV: u32 = 2500;
pub const MAX_BATTERY_MV: u32 = 4350;
/// The count at which the converter saturates. A count at or above it means
/// the input was outside the measurable range and the reading means nothing.
pub const ADC_SATURATED_RAW: i32 = 3950;

pub fn device_telemetry_interval_ms(stored_secs: u32) -> u32 {
    let secs = if stored_secs == 0 {
        DEFAULT_DEVICE_UPDATE_INTERVAL_SECS
    } else {
        stored_secs
    };
    secs.saturating_mul(1_000).min(i32::MAX as u32)
}

/// The minimum interval prevents one telemetry stream from consuming the entire polite duty-cycle
/// budget.
pub fn min_device_update_interval_secs(radio: &mesh_radio::RadioConfig) -> u32 {
    let airtime_ms = mesh_radio::packet_time_ms(radio, 255, false).max(1);
    let polite_pct = (u32::from(radio.region.duty_cycle_percent) * 50 / 100).max(1);
    let interval_ms = airtime_ms.saturating_mul(100).div_ceil(polite_pct);
    interval_ms.div_ceil(1_000).max(1)
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DeviceMetricsSnapshot {
    pub battery_level: Option<u32>,
    pub voltage_v: Option<f32>,
    pub channel_utilization: f32,
    pub air_util_tx: f32,
    pub uptime_seconds: u32,
}

impl DeviceMetricsSnapshot {
    pub const EMPTY: Self = Self {
        battery_level: None,
        voltage_v: None,
        channel_utilization: 0.0,
        air_util_tx: 0.0,
        uptime_seconds: 0,
    };
}

pub fn encode_device_telemetry(
    metrics: &DeviceMetricsSnapshot,
    out: &mut heapless::Vec<u8, 128>,
) -> bool {
    out.clear();
    let mut device_metrics = heapless::Vec::<u8, 64>::new();
    if let Some(level) = metrics.battery_level {
        push_varint_field(&mut device_metrics, 1, level);
    }
    if let Some(voltage_v) = metrics.voltage_v {
        push_f32_field(&mut device_metrics, 2, voltage_v);
    }
    push_f32_field(&mut device_metrics, 3, metrics.channel_utilization);
    push_f32_field(&mut device_metrics, 4, metrics.air_util_tx);
    push_varint_field(&mut device_metrics, 5, metrics.uptime_seconds);

    let _ = out.push(((1 << 3) | 5) as u8);
    let _ = out.extend_from_slice(&0u32.to_le_bytes());

    let _ = out.push(((2 << 3) | 2) as u8);
    push_varint(out, device_metrics.len() as u32);
    out.extend_from_slice(&device_metrics).is_ok()
}

pub fn build_device_telemetry_wire_frame(
    node_num: u32,
    packet_id: u32,
    channel_hash: u8,
    hop_limit: u8,
    key: &CryptoKey,
    metrics: &DeviceMetricsSnapshot,
    ok_to_mqtt: bool,
) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
    let mut telemetry = heapless::Vec::<u8, 128>::new();
    if !encode_device_telemetry(metrics, &mut telemetry) {
        return None;
    }
    let plaintext = encode_data_payload_opts(
        TELEMETRY_APP,
        &telemetry,
        DataEncodeOpts {
            bitfield: DataBitfield::Ours { ok_to_mqtt },
            ..Default::default()
        },
    );
    if plaintext.is_empty() || plaintext.len() > MAX_PACKET_PAYLOAD {
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

    let header = PacketHeader::from_fields(
        NODENUM_BROADCAST,
        node_num,
        packet_id,
        channel_hash,
        hop_limit,
        hop_limit,
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

/// The battery voltage a sense network reports for a converter count.
///
/// The converter measures the **difference** between the input pin and its
/// reference, so the pin voltage is the reference *plus* the measured
/// difference, and the battery voltage is the pin voltage times the divider
/// of the sense network.
///
/// Leaving the reference out loses twice the reference in the reported
/// voltage: a converter that reports a 1.5 V difference for a pin that sits
/// on 2.1 V reports 1.5 V for a battery that is really at 4.2 V. The error
/// grows as the battery empties, and a reading that falls out of the
/// plausible window is thrown away instead of being reported — which is how
/// a node ends up sending telemetry with no battery level in it at all.
pub fn battery_voltage_mv(count: i32, reference_mv: i32, mv_per_count: f32, divider: f32) -> u32 {
    let pin_mv = reference_mv as f32 + count as f32 * mv_per_count;
    (pin_mv * divider).max(0.0) as u32
}

pub fn is_plausible_battery_reading(voltage_mv: u32, raw_adc: i32) -> bool {
    raw_adc.abs() < ADC_SATURATED_RAW && (MIN_BATTERY_MV..=MAX_BATTERY_MV).contains(&voltage_mv)
}

pub fn interpret_battery_reading(
    voltage_mv: u32,
    raw_adc: i32,
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

pub fn decode_device_metrics(payload: &[u8]) -> Option<DecodedDeviceMetrics> {
    let mut out = DecodedDeviceMetrics::default();
    let mut i = 0usize;
    while i < payload.len() {
        let (tag, tag_len) = read_varint(payload, i)?;
        i += tag_len;
        let field = tag >> 3;
        if field == 0 {
            return None;
        }
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
            _ => {
                i = crate::protobuf::skip_field(payload, i, wire as u8)?;
            }
        }
    }
    Some(out)
}

/// Whether the payload is a telemetry frame that carries no device metrics.
///
/// The public schema puts the device metrics in field 2 and the other
/// telemetry sub-messages — the local stats, the health, the air quality — in
/// the fields around it. A node that sends only those has no battery level to
/// report, and that is not a fault. The log has to be able to say so, because
/// "this node sent no battery level" and "this payload cannot be read" look
/// the same otherwise, and the first is the answer to "why does this node not
/// report a battery".
pub fn telemetry_without_device_metrics(payload: &[u8]) -> bool {
    let mut i = 0usize;
    let mut has_time = false;
    while i < payload.len() {
        let Some((tag, next)) = crate::protobuf::read_varint(payload, i) else {
            return false;
        };
        if tag >> 3 == 0 {
            return false;
        }
        if tag == (2 << 3) | 2 {
            // It does carry the device metrics.
            return false;
        }
        if tag >> 3 == 1 {
            has_time = true;
        }
        let Some(end) = crate::protobuf::skip_field(payload, next, (tag & 7) as u8) else {
            return false;
        };
        i = end;
    }
    has_time
}

pub fn extract_device_metrics(payload: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    let mut metrics = None;
    while i < payload.len() {
        let (tag, next) = crate::protobuf::read_varint(payload, i)?;
        if tag >> 3 == 0 {
            return None;
        }
        i = crate::protobuf::skip_field(payload, next, (tag & 7) as u8)?;
        if tag == (2 << 3) | 2 {
            let (len, start) = crate::protobuf::read_varint(payload, next)?;
            metrics = Some(payload.get(start..start.checked_add(len as usize)?)?);
        }
    }
    metrics
}

fn push_varint_field<const N: usize>(out: &mut heapless::Vec<u8, N>, field: u32, value: u32) {
    let _ = out.push((field << 3) as u8);
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

fn read_varint(data: &[u8], i: usize) -> Option<(u32, usize)> {
    let (value, end) = crate::protobuf::read_varint(data, i)?;
    Some((value, end - i))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::try_decrypt_data_full;
    use mesh_crypto::{CryptoKey, DEFAULT_PSK};
    use mesh_radio::{primary_channel_hash, MODEM_SHORT_SLOW};

    #[test]
    fn saturated_adc_is_not_plausible() {
        assert!(!is_plausible_battery_reading(5997, 4093));
        assert!(!is_plausible_battery_reading(4200, 4000));
    }

    #[test]
    fn a_negative_count_is_not_plausible() {
        // A pin below the reference reads negative, and the voltage it stands
        // for is below the reference as well: there is no battery there.
        let mv = battery_voltage_mv(-12, 600, 6.0 * 600.0 / 4096.0, 2.0);
        assert!(mv < MIN_BATTERY_MV);
        assert!(!is_plausible_battery_reading(mv, -12));
    }

    /// The converter measures the difference between the pin and its
    /// reference, so the reference has to be added back before the divider is
    /// applied. Leaving it out loses twice the reference in the reported
    /// voltage, and a reading that falls out of the plausible window is
    /// thrown away: that is how a node ends up with no battery level in its
    /// telemetry at all.
    #[test]
    fn the_reference_offset_is_part_of_the_voltage() {
        // The nRF52840 numbers: a 600 mV internal reference, a gain that
        // spans six times the reference over 4096 counts, and a divider of two.
        const REFERENCE_MV: i32 = 600;
        const MV_PER_COUNT: f32 = 6.0 * 600.0 / 4096.0;
        const DIVIDER: f32 = 2.0;

        // A full cell: 4.2 V at the battery, 2.1 V at the pin, 1.5 V above
        // the reference.
        let count = ((2100 - 600) as f32 / MV_PER_COUNT) as i32;
        let mv = battery_voltage_mv(count, REFERENCE_MV, MV_PER_COUNT, DIVIDER);
        assert!(
            (4190..=4210).contains(&mv),
            "a full cell must read about 4200 mV, got {mv}"
        );
        let (reported, level, valid) = interpret_battery_reading(mv, count, false);
        assert!(valid);
        assert_eq!(reported, mv);
        assert_eq!(level, 100);

        // A cell that has run down: 3.5 V at the battery. Without the
        // reference the reading would be 2.3 V, which is outside the
        // plausible window, and the node would report no battery level.
        let count = ((1750 - 600) as f32 / MV_PER_COUNT) as i32;
        let mv = battery_voltage_mv(count, REFERENCE_MV, MV_PER_COUNT, DIVIDER);
        assert!(
            (3490..=3510).contains(&mv),
            "a half-empty cell must read about 3500 mV, got {mv}"
        );
        let (reported, level, valid) = interpret_battery_reading(mv, count, false);
        assert!(valid, "a half-empty cell must still report a level");
        assert_eq!(reported, mv);
        assert!(level > 30 && level < 45, "level was {level}");
    }

    #[test]
    fn a_count_below_the_reference_reads_as_no_battery() {
        // A disconnected or flat battery pulls the pin below the reference.
        let mv = battery_voltage_mv(-100, 600, 6.0 * 600.0 / 4096.0, 2.0);
        let (_, _, valid) = interpret_battery_reading(mv, -100, false);
        assert!(!valid);
    }

    #[test]
    fn device_telemetry_interval_zero_is_default() {
        assert_eq!(
            device_telemetry_interval_ms(0),
            DEVICE_TELEMETRY_BROADCAST_MS
        );
        assert_eq!(device_telemetry_interval_ms(600), 600_000);
    }

    #[test]
    fn min_interval_floor_is_airtime_derived() {
        let radio = mesh_radio::eu868_config_for_preset(mesh_radio::MODEM_DEFAULT_PRESET);
        let floor = min_device_update_interval_secs(&radio);
        assert!(floor > 1);
        let airtime = mesh_radio::packet_time_ms(&radio, 255, false).max(1);
        let polite = (u32::from(radio.region.duty_cycle_percent) * 50 / 100).max(1);
        let expected = airtime
            .saturating_mul(100)
            .div_ceil(polite)
            .div_ceil(1_000)
            .max(1);
        assert_eq!(floor, expected);
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
            battery_level: Some(72),
            voltage_v: Some(3.85),
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

    /// The whole chain: a converter count becomes a battery voltage, the
    /// voltage becomes a level, and the level reaches the air in the
    /// telemetry frame. A node whose battery has run down must still be
    /// reported — that is the case that used to be thrown away.
    #[test]
    fn a_reading_reaches_the_air_as_a_battery_level() {
        const REFERENCE_MV: i32 = 600;
        const MV_PER_COUNT: f32 = 6.0 * 600.0 / 4096.0;
        const DIVIDER: f32 = 2.0;

        // A cell at 3.7 V: the pin sits on 1.85 V, 1.25 V above the reference.
        let count = ((1850 - 600) as f32 / MV_PER_COUNT) as i32;
        let mv = battery_voltage_mv(count, REFERENCE_MV, MV_PER_COUNT, DIVIDER);
        let (_, level, valid) = interpret_battery_reading(mv, count, false);
        assert!(valid, "a cell at 3.7 V must be reported");
        assert!(
            level > 50 && level < 60,
            "3.7 V is about half a cell, got {level}"
        );

        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
        let metrics = DeviceMetricsSnapshot {
            battery_level: Some(level),
            voltage_v: Some(mv as f32 / 1000.0),
            channel_utilization: 0.0,
            air_util_tx: 0.0,
            uptime_seconds: 600,
        };
        let (len, frame) = build_device_telemetry_wire_frame(
            0x677a_1caf,
            89,
            channel_hash,
            3,
            &key,
            &metrics,
            false,
        )
        .unwrap();
        let mut cipher = frame[mesh_protocol::PACKET_HEADER_LEN..len as usize].to_vec();
        let (portnum, payload) = crate::topology::try_decrypt_data(
            &key,
            0x677a_1caf,
            89,
            channel_hash,
            channel_hash,
            &mut cipher,
        )
        .unwrap();
        assert_eq!(portnum, TELEMETRY_APP);
        let nested = extract_device_metrics(&payload).expect("nested metrics");
        let decoded = decode_device_metrics(nested).unwrap();
        assert_eq!(decoded.battery_level, Some(level));
        assert!((decoded.voltage_v.unwrap() - mv as f32 / 1000.0).abs() < 0.001);
    }

    #[test]
    fn telemetry_wire_decrypt_round_trip() {
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
        let metrics = DeviceMetricsSnapshot {
            battery_level: Some(MAGIC_USB_BATTERY_LEVEL),
            voltage_v: Some(4.12),
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
            false,
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
