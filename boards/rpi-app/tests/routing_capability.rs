//! Capability cache, stock relay slots, passive topology roles, and T1 originated broadcasts.

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::{portnum::num, PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};
use mesh_routing::{
    calculate_etx, coordinated_relay, etx_to_fixed, write_packed_header, CapabilityStatus,
    InboundPacket, NeighborGraph, Router, TopologyMergeResult, CAPABILITY_TTL_MS,
    DEVICE_ROLE_CLIENT_MUTE, DEVICE_ROLE_REPEATER, MAX_CAPABILITY_RECORDS,
};

#[test]
fn client_mute_may_send_topology() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.set_device_role(DEVICE_ROLE_CLIENT_MUTE);
    assert!(graph.can_send_topology());
}

#[test]
fn passive_node_tracks_relayed_topology_capability() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.set_device_role(DEVICE_ROLE_CLIENT_MUTE);
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 2, true);
    let (header, _) = mesh_routing::decode_packed_neighbors(&packed, 8).unwrap();
    let result = graph.merge_topology(0xBB, &header, &[], false, 100, 0);
    assert!(matches!(result, TopologyMergeResult::IgnoredFormat));
    assert_eq!(graph.capability_status(0xBB), CapabilityStatus::SrActive);
}

#[test]
fn stock_router_gets_earlier_slot_than_sr_self() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 0, 0);
    graph.track_node_role(0xBB, DEVICE_ROLE_REPEATER, 0);

    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 1, false);
    let (header, _) = mesh_routing::decode_packed_neighbors(&packed, 8).unwrap();
    let remote = mesh_routing::PackedNeighbor {
        node_id: 0xDD,
        etx_fixed: etx_to_fixed(calculate_etx(-75, 8.0)),
        signal_routing_active: false,
        hears_us: false,
        etx_variance: 0,
    };
    graph.merge_topology(0xBB, &header, &[remote], true, 0, 0);

    let (idx_self_only, count_alone) = graph.relay_slot_index(99, 0, 0);
    assert_eq!(count_alone, 1);
    assert_eq!(idx_self_only, 0);

    let (idx_with_stock, count) = graph.relay_slot_index(99, 0xDD, 0);
    assert_eq!(count, 2);
    assert_eq!(idx_with_stock, 1);
}

#[test]
fn send_local_broadcast_schedules_t1() {
    let mut router = Router::with_channel(
        0xAA,
        CryptoKey::from_bytes(&DEFAULT_PSK),
        0x77,
        mesh_radio::MODEM_SHORT_SLOW,
        true,
        3,
    );

    let header = PacketHeader::from_fields(NODENUM_BROADCAST, 0xBB, 1, 0x77, 3, 3, false, false, 0, 0);
    let mut hdr = [0u8; PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    let wire = [hdr.as_slice(), &[0x01u8]].concat();
    router
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 8,
                bytes: &wire,
            },
            0,
        )
        .unwrap();
    router.confirm_direct_neighbor_hears_us(0xBB);

    let airtime = 200;
    let slot_ms = coordinated_relay::slot_time_for_preset(mesh_radio::MODEM_SHORT_SLOW);
    let plan = router
        .send_local(
            NODENUM_BROADCAST,
            num::TEXT_MESSAGE_APP,
            b"hello mesh",
            false,
            3,
            1_000,
            airtime,
            slot_ms,
        )
        .expect("send");
    assert!(usize::from(plan.len) > PACKET_HEADER_LEN);

    let fire_ms = coordinated_relay::tx_delay_ms_worst(slot_ms).saturating_add(airtime);
    assert!(router.poll_t1_retransmit(1_000 + fire_ms - 1).is_none());
    assert!(router.poll_t1_retransmit(1_000 + fire_ms).is_some());
}

#[test]
fn three_node_topology_versions_converge() {
    let mut a = NeighborGraph::new();
    a.set_my_node(0xA000_0001);
    a.observe_direct_neighbor(0xB000_0002, -70, 8, 0, 0);

    let mut b = NeighborGraph::new();
    b.set_my_node(0xB000_0002);
    b.observe_direct_neighbor(0xA000_0001, -70, 8, 0, 0);

    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 3, true);
    let (header, _) = mesh_routing::decode_packed_neighbors(&packed, 8).unwrap();
    let neighbor = mesh_routing::PackedNeighbor {
        node_id: 0xC000_0003,
        etx_fixed: etx_to_fixed(calculate_etx(-75, 8.0)),
        signal_routing_active: true,
        hears_us: false,
        etx_variance: 0,
    };

    let r1 = b.merge_topology(0xA000_0001, &header, &[neighbor], true, 100, 0);
    assert!(matches!(r1, TopologyMergeResult::Applied { .. }));

    write_packed_header(&mut packed, 4, true);
    let (header2, _) = mesh_routing::decode_packed_neighbors(&packed, 8).unwrap();
    let r2 = a.merge_topology(0xB000_0002, &header2, &[neighbor], false, 200, 0);
    assert!(matches!(r2, TopologyMergeResult::Applied { .. }));
}

#[test]
fn capability_expires_at_1810s() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.track_node_role(0xBB, DEVICE_ROLE_REPEATER, 0);
    graph.capability_mut().track_topology(0xBB, true, 0);
    assert_eq!(
        graph.capability_status_at(0xBB, CAPABILITY_TTL_MS),
        CapabilityStatus::SrActive
    );
    assert_eq!(
        graph.capability_status_at(0xBB, CAPABILITY_TTL_MS + 1),
        CapabilityStatus::Unknown
    );
}

#[test]
fn capability_cache_holds_64() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    for i in 1..=MAX_CAPABILITY_RECORDS as u32 {
        graph.capability_mut().track_topology(i, true, 0);
    }
    assert_eq!(
        graph.capability_mut().record_count(),
        MAX_CAPABILITY_RECORDS as u8
    );
    graph
        .capability_mut()
        .track_topology(MAX_CAPABILITY_RECORDS as u32 + 1, true, 0);
    assert_eq!(
        graph.capability_mut().record_count(),
        MAX_CAPABILITY_RECORDS as u8
    );
}

#[test]
fn sr_capability_expiry_clears_hears_us() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 0, 0);
    graph.confirm_direct_neighbor_hears_us(0xBB);
    assert!(graph.has_any_hears_us_neighbor());
    graph.capability_mut().track_topology(0xBB, true, 0);
    graph.run_maintenance(CAPABILITY_TTL_MS + 1);
    assert!(!graph.has_any_hears_us_neighbor());
}

#[test]
fn local_node_capability_from_role() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.set_device_role(DEVICE_ROLE_REPEATER);
    assert_eq!(
        graph.capability_status(0xAA),
        CapabilityStatus::SrActive
    );
    graph.set_device_role(DEVICE_ROLE_CLIENT_MUTE);
    assert_eq!(
        graph.capability_status(0xAA),
        CapabilityStatus::Passive
    );
}
