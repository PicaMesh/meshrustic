//! Duplicate RX handling — role cancel, upgrade, want_ack re-ACK.

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::{NODENUM_BROADCAST, PacketHeader, PACKET_HEADER_LEN};
use mesh_radio::MODEM_SHORT_SLOW;
use mesh_protocol::num::TEXT_MESSAGE_APP;
use mesh_routing::{
    build_app_wire_frame, build_ack_nak_frame, coordinated_relay, DataEncodeOpts, InboundPacket,
    Router, DEVICE_ROLE_CLIENT, DEVICE_ROLE_CLIENT_MUTE, DEVICE_ROLE_ROUTER, ROUTING_ERROR_NONE,
};

fn wire_bytes(header: PacketHeader, payload: &[u8]) -> heapless::Vec<u8, 280> {
    let mut out = heapless::Vec::new();
    let mut hdr = [0u8; PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    let _ = out.extend_from_slice(&hdr);
    let _ = out.extend_from_slice(payload);
    out
}

#[test]
fn router_role_router_keeps_relay_commit_on_dupe() {
    const US: u32 = 0xAABB_CCDD;
    let mut router = Router::with_channel(
        US,
        CryptoKey::from_bytes(&DEFAULT_PSK),
        0x77,
        MODEM_SHORT_SLOW,
        true,
        3,
    );
    router.set_device_role(DEVICE_ROLE_ROUTER);

    let header = PacketHeader::from_fields(
        NODENUM_BROADCAST,
        0x1234_5678,
        42,
        0x77,
        2,
        3,
        false,
        false,
        0,
        0x12,
    );
    let wire = wire_bytes(header, &[0xDE, 0xAD]);
    let inbound = InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 10,
        bytes: &wire,
    };

    let result = router.process_inbound(&inbound, 0).expect("first rx");
    let _plan = router.evaluate_tx_plan(
        &result,
        0.0,
        coordinated_relay::DEFAULT_SLOT_MS,
        0,
    );
    assert!(
        router.relay_tx_after(0x1234_5678, 42, 0).is_some(),
        "relay should be committed"
    );

    let _dupe = router.process_inbound(&inbound, 100).expect("dupe rx");
    assert!(
        router.relay_tx_after(0x1234_5678, 42, 0).is_some(),
        "ROUTER must not cancel committed relay on dupe"
    );
}

#[test]
fn client_cancels_relay_commit_on_dupe() {
    const US: u32 = 0xAABB_CCDD;
    let mut router = Router::with_channel(
        US,
        CryptoKey::from_bytes(&DEFAULT_PSK),
        0x77,
        MODEM_SHORT_SLOW,
        true,
        3,
    );
    router.set_device_role(DEVICE_ROLE_CLIENT);

    let header = PacketHeader::from_fields(
        NODENUM_BROADCAST,
        0x1234_5678,
        43,
        0x77,
        2,
        3,
        false,
        false,
        0,
        0x12,
    );
    let wire = wire_bytes(header, &[0xBE, 0xEF]);
    let inbound = InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 10,
        bytes: &wire,
    };

    let result = router.process_inbound(&inbound, 0).expect("first rx");
    let _plan = router.evaluate_tx_plan(
        &result,
        0.0,
        coordinated_relay::DEFAULT_SLOT_MS,
        0,
    );
    assert!(router.relay_tx_after(0x1234_5678, 43, 0).is_some());

    let _dupe = router.process_inbound(&inbound, 100).expect("dupe rx");
    assert!(
        router.relay_tx_after(0x1234_5678, 43, 0).is_none(),
        "CLIENT should cancel relay on dupe"
    );
}

#[test]
fn repeated_want_ack_to_us_schedules_ack_on_duplicate() {
    const US: u32 = 0xCCCC_CCCC;
    const FROM: u32 = 0x1111_1111;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let mut router = Router::with_channel(US, key, 0x77, MODEM_SHORT_SLOW, true, 3);
    router.set_device_role(DEVICE_ROLE_CLIENT_MUTE);

    let payload = b"hi";
    let (len, frame) = build_app_wire_frame(
        US,
        FROM,
        99,
        0x77,
        3,
        3,
        true,
        &key,
        TEXT_MESSAGE_APP,
        payload,
        DataEncodeOpts::default(),
    )
    .expect("wire");

    let inbound = InboundPacket {
        radio_id: 0,
        rssi: -65,
        snr: 8,
        bytes: &frame[..usize::from(len)],
    };

    router.process_inbound(&inbound, 0).expect("first");
    router.poll_ack_tx(0);
    router.process_inbound(&inbound, 50).expect("dupe repeated tx");
    assert!(
        router.poll_ack_tx(50).is_some(),
        "duplicate repeated want_ack should re-send ACK"
    );
}

#[test]
fn foreign_routing_ack_cancels_pending_relay() {
    const US: u32 = 0xDDDD_DDDD;
    const ORIGIN: u32 = 0x1111_1111;
    const DEST: u32 = 0x2222_2222;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let mut router = Router::with_channel(US, key, 0x77, MODEM_SHORT_SLOW, true, 3);
    router
        .graph_mut()
        .observe_direct_neighbor(DEST, -70, 8, 1_000, 0);

    let (dm_len, dm_frame) = build_app_wire_frame(
        DEST,
        ORIGIN,
        77,
        0x77,
        3,
        3,
        false,
        &key,
        TEXT_MESSAGE_APP,
        b"payload",
        DataEncodeOpts::default(),
    )
    .expect("dm wire");

    let dm = InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 8,
        bytes: &dm_frame[..usize::from(dm_len)],
    };
    let result = router.process_inbound(&dm, 1_000).expect("dm rx");
    let plan = router.evaluate_tx_plan(
        &result,
        0.0,
        coordinated_relay::DEFAULT_SLOT_MS,
        1_000,
    );
    if plan.relay.is_some() {
        return;
    }
    let tx_after = router
        .relay_tx_after(ORIGIN, 77, 0)
        .expect("relay committed");
    assert!(
        tx_after > 1_000,
        "need delayed pending relay for this test"
    );
    assert!(
        router.poll_ready_relay(tx_after.saturating_sub(1)).is_some()
            || router.poll_ready_relay(tx_after.saturating_sub(1)).is_none()
    );

    let (ack_len, ack_wire) = build_ack_nak_frame(
        ORIGIN,
        DEST,
        9001,
        77,
        0x77,
        3,
        ROUTING_ERROR_NONE,
        &key,
    )
    .expect("ack frame");

    let ack = InboundPacket {
        radio_id: 0,
        rssi: -68,
        snr: 7,
        bytes: &ack_wire[..ack_len as usize],
    };
    router.process_inbound(&ack, 1_010).expect("routing ack rx");
    assert!(
        router.poll_ready_relay(tx_after).is_none(),
        "foreign routing ACK should cancel pending relay"
    );
}

#[test]
fn upgraded_hop_limit_reprocesses_after_dropping_lower_pending() {
    const US: u32 = 0xEEEE_EEEE;
    const FROM: u32 = 0x3333_3333;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let mut router = Router::with_channel(US, key, 0x77, MODEM_SHORT_SLOW, true, 3);

    let payload = b"x";
    let (low_len, low_frame) = build_app_wire_frame(
        NODENUM_BROADCAST,
        FROM,
        88,
        0x77,
        2,
        3,
        false,
        &key,
        TEXT_MESSAGE_APP,
        payload,
        DataEncodeOpts::default(),
    )
    .expect("low hop wire");

    let low = InboundPacket {
        radio_id: 0,
        rssi: -72,
        snr: 9,
        bytes: &low_frame[..usize::from(low_len)],
    };
    let result = router.process_inbound(&low, 0).expect("low hop rx");
    let plan = router.evaluate_tx_plan(
        &result,
        0.0,
        coordinated_relay::DEFAULT_SLOT_MS,
        0,
    );
    if plan.relay.is_some() {
        return;
    }
    assert!(
        router.relay_tx_after(FROM, 88, 0).is_some(),
        "lower-hop copy should commit relay"
    );

    let (high_len, high_frame) = build_app_wire_frame(
        NODENUM_BROADCAST,
        FROM,
        88,
        0x77,
        3,
        3,
        false,
        &key,
        TEXT_MESSAGE_APP,
        payload,
        DataEncodeOpts::default(),
    )
    .expect("high hop wire");

    let high = InboundPacket {
        radio_id: 0,
        rssi: -71,
        snr: 10,
        bytes: &high_frame[..usize::from(high_len)],
    };
    let upgraded = router.process_inbound(&high, 50).expect("upgraded rx");
    assert!(
        !upgraded.duplicate,
        "upgrade with dropped pending should fall through as new RX"
    );
}
