//! Device telemetry wire-format tests (port 67).

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::PacketHeader;
use mesh_radio::{primary_channel_hash, MODEM_SHORT_SLOW};
use mesh_routing::{
    build_device_telemetry_wire_frame, decode_device_metrics, extract_device_metrics,
    summarize_decrypted, try_decrypt_data, DeviceMetricsSnapshot, Router, RxPayloadSummary,
    DEVICE_TELEMETRY_BROADCAST_MS, MAGIC_USB_BATTERY_LEVEL, TELEMETRY_APP,
};
use static_cell::StaticCell;

#[test]
fn telemetry_wire_decrypt_and_summary() {
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
    let metrics = DeviceMetricsSnapshot {
        battery_level: 85,
        voltage_v: 3.92,
        channel_utilization: 6.0,
        air_util_tx: 2.0,
        uptime_seconds: 120,
    };
    let (len, frame) = build_device_telemetry_wire_frame(
        0x677a_1caf,
        42,
        channel_hash,
        3,
        &key,
        &metrics,
    )
    .unwrap();
    let mut cipher = frame[mesh_protocol::PACKET_HEADER_LEN..len as usize].to_vec();
    let (portnum, payload) = try_decrypt_data(
        &key,
        0x677a_1caf,
        42,
        channel_hash,
        channel_hash,
        &mut cipher,
    )
    .unwrap();
    assert_eq!(portnum, TELEMETRY_APP);
    match summarize_decrypted(portnum, &payload) {
        RxPayloadSummary::DeviceTelemetry {
            battery_level,
            voltage_mv,
        } => {
            assert_eq!(battery_level, 85);
            assert!((voltage_mv as i32 - 3920).abs() <= 1);
        }
        other => panic!("expected device telemetry summary, got {other:?}"),
    }
}

#[test]
fn router_schedules_periodic_device_telemetry() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let router = ROUTER.init(Router::with_modem_preset(
        0x677a_1caf,
        "",
        MODEM_SHORT_SLOW,
        true,
        key,
        3,
    ));
    router.update_device_metrics(DeviceMetricsSnapshot {
        battery_level: MAGIC_USB_BATTERY_LEVEL,
        voltage_v: 0.0,
        channel_utilization: 0.0,
        air_util_tx: 0.0,
        uptime_seconds: 0,
    });

    router.run_maintenance(1_000, 100);
    let first = router.poll_telemetry_tx(1_000).expect("first telemetry queued");
    let header = PacketHeader::decode(&first.bytes[..first.len as usize]).unwrap();
    assert_eq!(header.from, 0x677a_1caf);
    assert_eq!(header.to, mesh_protocol::NODENUM_BROADCAST);

    router.run_maintenance(1_000 + DEVICE_TELEMETRY_BROADCAST_MS - 1, 100);
    assert!(router.poll_telemetry_tx(1_000 + DEVICE_TELEMETRY_BROADCAST_MS - 1).is_none());

    router.run_maintenance(1_000 + DEVICE_TELEMETRY_BROADCAST_MS, 100);
    let second = router
        .poll_telemetry_tx(1_000 + DEVICE_TELEMETRY_BROADCAST_MS)
        .expect("second telemetry queued");
    let mut cipher = second.bytes[mesh_protocol::PACKET_HEADER_LEN..second.len as usize].to_vec();
    let (portnum, payload) = try_decrypt_data(
        &key,
        0x677a_1caf,
        PacketHeader::decode(&second.bytes[..second.len as usize])
            .unwrap()
            .id,
        router.channel_hash(),
        router.channel_hash(),
        &mut cipher,
    )
    .unwrap();
    assert_eq!(portnum, TELEMETRY_APP);
    let nested = extract_device_metrics(&payload).unwrap();
    let decoded = decode_device_metrics(nested).unwrap();
    assert_eq!(decoded.battery_level, Some(MAGIC_USB_BATTERY_LEVEL));
    assert!((decoded.voltage_v.unwrap()).abs() < 0.001);
}
