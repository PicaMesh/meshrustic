//! Phase 9 bridge policy — host checks for cross-preset forwarding.

use mesh_protocol::{PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};
use mesh_routing::{
    coordinated_relay, evaluate_bridge_targets, BridgeDedupCache, BridgeEval, ChannelQoS,
    InboundPacket, NeighborGraph, RelayPlan, Router, TxPlan, MAX_WIRE_LEN,
};
use static_cell::StaticCell;

#[test]
fn evaluate_bridge_targets_empty_with_one_radio() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(0x677a_1caf));

    let header =
        PacketHeader::from_fields(NODENUM_BROADCAST, 0x979e_d146, 7, 0x77, 3, 3, false, false, 0, 0);
    let mut wire = heapless::Vec::<u8, 64>::new();
    let mut hdr = [0u8; PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    wire.extend_from_slice(&hdr).unwrap();
    wire.extend_from_slice(&[1, 2, 3]).unwrap();

    let result = router
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 10,
                bytes: &wire,
            },
            0,
        )
        .expect("accepted");

    let plan = router.evaluate_tx_plan(
        &result,
        0.0,
        coordinated_relay::DEFAULT_SLOT_MS,
        0,
    );
    assert_eq!(plan.bridge_count, 0);
}

#[test]
fn bridge_stub_direct_call_returns_zero() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0x677a_1caf);
    let parsed = PacketHeader::from_fields(
        NODENUM_BROADCAST,
        0x979e_d146,
        1,
        0x77,
        3,
        3,
        false,
        false,
        0,
        0,
    )
    .parse();
    let relay = RelayPlan {
        len: PACKET_HEADER_LEN as u8 + 3,
        bytes: [0u8; MAX_WIRE_LEN],
        delay_ms: 0,
    };
    let eval = BridgeEval {
        rx_radio: 0,
        parsed: &parsed,
        route: Default::default(),
        decoded_portnum: None,
        chutil_pct: 0.0,
        now_ms: 0,
        from_us: false,
        to_us: false,
    };
    let mut dedup = BridgeDedupCache::new();
    let mut sr_log = mesh_routing::SrLog::new();
    let qos = ChannelQoS::new();
    let mut plan = TxPlan::default();
    assert!(!evaluate_bridge_targets(
        &eval,
        &relay,
        &mut graph,
        &mut dedup,
        &qos,
        &mut sr_log,
        0x677a_1caf,
        10,
        coordinated_relay::DEFAULT_SLOT_MS,
        coordinated_relay::slot_time_for_preset(mesh_radio::MODEM_SHORT_SLOW),
        &mut plan,
    ));
    assert_eq!(plan.bridge_count, 0);
}

#[test]
fn cross_preset_unicast_bridges_to_long_fast_segment() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(0x677a_1caf));
    let dest = 0x5889_1234u32;
    {
        let graph = router.graph_mut();
        graph.observe_direct_neighbor(0x979e_d146, -70, 8, 0, 0);
        graph.observe_direct_neighbor(dest, -70, 8, 0, 1);
    }

    let header = PacketHeader::from_fields(dest, 0x979e_d146, 9, 0x77, 3, 3, false, false, 0, 0);
    let mut wire = heapless::Vec::<u8, 64>::new();
    let mut hdr = [0u8; PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    wire.extend_from_slice(&hdr).unwrap();
    wire.extend_from_slice(&[0xAA, 0xBB, 0xCC]).unwrap();

    let result = router
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 10,
                bytes: &wire,
            },
            100,
        )
        .expect("accepted");

    let plan = router.evaluate_tx_plan(
        &result,
        0.0,
        coordinated_relay::DEFAULT_SLOT_MS,
        100,
    );

    assert_eq!(plan.bridge_count, 1);
    assert_eq!(plan.bridge[0].target_radio, 1);
    assert!(plan.relay.is_none());
    assert_eq!(plan.bridge[0].len as usize, wire.len());
}

#[test]
fn bridge_dedup_suppresses_second_bridge_to_same_target() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA00_00AA);
    graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 0, 0);
    graph.observe_direct_neighbor(0xCC00_00CC, -70, 8, 0, 1);
    let route = graph.route_to(0xCC00_00CC, 100);
    let parsed =
        PacketHeader::from_fields(0xCC00_00CC, 0xBB00_00BB, 2, 0x77, 3, 3, false, false, 0, 0)
            .parse();
    let relay = RelayPlan {
        len: PACKET_HEADER_LEN as u8 + 1,
        bytes: [0u8; MAX_WIRE_LEN],
        delay_ms: 0,
    };
    let eval = BridgeEval {
        rx_radio: 0,
        parsed: &parsed,
        route,
        decoded_portnum: None,
        chutil_pct: 0.0,
        now_ms: 100,
        from_us: false,
        to_us: false,
    };
    let mut dedup = BridgeDedupCache::new();
    let mut sr_log = mesh_routing::SrLog::new();
    let qos = ChannelQoS::new();
    let mut plan = TxPlan::default();
    assert!(evaluate_bridge_targets(
        &eval,
        &relay,
        &mut graph,
        &mut dedup,
        &qos,
        &mut sr_log,
        0xAA00_00AA,
        10,
        coordinated_relay::DEFAULT_SLOT_MS,
        coordinated_relay::slot_time_for_preset(mesh_radio::MODEM_SHORT_SLOW),
        &mut plan,
    ));
    assert_eq!(plan.bridge_count, 1);
    plan = TxPlan::default();
    assert!(!evaluate_bridge_targets(
        &eval,
        &relay,
        &mut graph,
        &mut dedup,
        &qos,
        &mut sr_log,
        0xAA00_00AA,
        10,
        coordinated_relay::DEFAULT_SLOT_MS,
        coordinated_relay::slot_time_for_preset(mesh_radio::MODEM_SHORT_SLOW),
        &mut plan,
    ));
    assert_eq!(plan.bridge_count, 0);
}
