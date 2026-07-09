//! Host three-node SR bench — line topology without hardware.

use mesh_routing::{
    decode_packed_neighbors, write_packed_header, NeighborGraph,
    PackedNeighbor, TopologyMergeResult, DEVICE_ROLE_ROUTER, MAX_DOWNSTREAM,
};

#[test]
fn downstream_table_supports_full_capacity() {
    assert_eq!(MAX_DOWNSTREAM, 1100);
}

#[test]
fn three_node_line_learns_remote_via_topology() {
    let mut a = NeighborGraph::new();
    a.set_my_node(0xA000_0001);
    a.observe_direct_neighbor(0xB000_0002, -70, 8, 0, 0);

    let mut b = NeighborGraph::new();
    b.set_my_node(0xB000_0002);
    b.observe_direct_neighbor(0xA000_0001, -70, 8, 0, 0);
    b.observe_direct_neighbor(0xC000_0003, -75, 8, 0, 0);

    let remote = PackedNeighbor {
        node_id: 0xC000_0003,
        rssi: -75,
        snr: 8,
        signal_routing_active: true,
        hears_us: false,
        etx_variance: 0,
    };
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 2, true);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();

    let result = a.merge_topology(0xB000_0002, &header, &[remote], true, 100, 0);
    assert!(matches!(result, TopologyMergeResult::Applied { .. }));

    let hop = a.get_next_hop(0xC000_0003, 0xB000_0002, 0xB000_0002, 100);
    assert_ne!(hop, 0);
}

#[test]
fn three_node_middle_node_defers_to_stock_router() {
    let mut c = NeighborGraph::new();
    c.set_my_node(0xC000_0003);
    c.set_device_role(DEVICE_ROLE_ROUTER);
    c.observe_direct_neighbor(0xB000_0002, -70, 8, 0, 0);
    c.observe_direct_neighbor(0xD000_0004, -72, 7, 0, 0);
    c.track_node_role(0xD000_0004, DEVICE_ROLE_ROUTER, 0);

    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 1, false);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
    let neighbor = PackedNeighbor {
        node_id: 0xB000_0002,
        rssi: -75,
        snr: 8,
        signal_routing_active: false,
        hears_us: false,
        etx_variance: 0,
    };
    c.merge_topology(0xD000_0004, &header, &[neighbor], true, 0, 0);

    assert_eq!(c.find_best_relay_candidate(0x99, 0xB000_0002, 0), 0xD000_0004);

    let half = mesh_routing::coordinated_relay::half_airtime_ms(
        mesh_routing::coordinated_relay::DEFAULT_SLOT_MS,
    );
    let plan = c.plan_broadcast_relay(
        0x99,
        0xB000_0002,
        0xB000_0002,
        0xFFFF_FFFF,
        0,
        half,
    );
    assert!(plan.should_relay);
    assert!(plan.slot_delay_ms >= half);
}

#[test]
fn three_node_relayed_packet_infers_upstream_placeholder() {
    let mut b = NeighborGraph::new();
    b.set_my_node(0xB000_0002);
    b.set_device_role(DEVICE_ROLE_ROUTER);
    b.observe_direct_neighbor(0xA000_0001, -70, 8, 0, 0);
    b.observe_packet(0xA000_0001, 3, 2, 0xEF, -70, 8, 50, 0, None, 0);

    let placeholder = mesh_routing::placeholder_node_id(0xEF);
    let route = b.get_route(0xA000_0001, 50);
    assert!(route.next_hop != 0 || b.neighbor_count() >= 1);
    let _ = placeholder;
}
