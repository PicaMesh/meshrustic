//! Graph topology merge, ETX, and downstream tests.

use mesh_routing::{
    calculate_etx, etx_to_fixed, etx_to_signal, decode_packed_neighbors, write_packed_header,
    NeighborGraph, PackedNeighbor, SrLog, SrLogEvent, TopologyMergeResult, MAX_EDGES_PER_NODE,
    NeighborEntry, PACKED_NEIGHBOR_HEADER_SIZE,
};

#[test]
fn etx_monotonic_with_signal_strength() {
    let weak = calculate_etx(-110, 0.0);
    let strong = calculate_etx(-60, 10.0);
    assert!(strong < weak);
}

#[test]
fn downstream_created_for_hears_us_remote_neighbor() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 100, 0);

    let neighbor = PackedNeighbor {
        node_id: 0xCC,
        etx_fixed: etx_to_fixed(calculate_etx(-75, 8.0)),
        signal_routing_active: true,
        hears_us: true,
        etx_variance: 0,
    };
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 1, true);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
    let result = graph.merge_topology(0xBB, &header, &[neighbor], true, 200, 0);
    assert!(matches!(result, TopologyMergeResult::Applied { .. }));
}

#[test]
fn reported_edges_sort_before_mirrored_in_topology_pack() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0x11, -80, 5, 100, 0);
    graph.observe_direct_neighbor(0x22, -60, 10, 100, 0);

    let neighbor = PackedNeighbor {
        node_id: 0x33,
        etx_fixed: etx_to_fixed(calculate_etx(-70, 8.0)),
        signal_routing_active: true,
        hears_us: false,
        etx_variance: 0,
    };
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 1, true);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
    graph.merge_topology(0x22, &header, &[neighbor], true, 200, 0);

    let mut entries = [NeighborEntry::default(); MAX_EDGES_PER_NODE];
    let count = graph.topology_neighbors_for_pack(&mut entries);
    assert!(count >= 2);
    assert_eq!(entries[0].node_id, 0x22);
}

#[test]
fn topology_pack_round_trips_etx_fixed() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0x1234_5678, -80, 10, 0, 0);
    let expected_etx_fixed = etx_to_fixed(calculate_etx(-80, 10.0));

    let mut packed = [0u8; 64];
    let len = graph
        .build_topology_chunk(0, 1, &mut packed)
        .expect("chunk");
    assert!(len > PACKED_NEIGHBOR_HEADER_SIZE);
    let (_, neighbors) = decode_packed_neighbors(&packed[..len], len).unwrap();
    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0].node_id, 0x1234_5678);
    assert_eq!(neighbors[0].etx_fixed, expected_etx_fixed);
}

#[test]
fn relay_slot_index_increases_with_more_candidates() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0x11, -70, 8, 0, 0);
    graph.observe_direct_neighbor(0x22, -70, 8, 0, 0);
    let (_, count) = graph.relay_slot_index(42, 0, 0);
    assert_eq!(count, 3);
    let (idx_self, _) = graph.relay_slot_index(42, 0, 0);
    graph.record_node_transmission(0x11, 42, 0);
    let (idx_after, count_after) = graph.relay_slot_index(42, 0, 0);
    assert_eq!(count_after, 2);
    assert!(idx_after <= idx_self || count_after < count);
}

#[test]
fn etx_to_signal_round_trip_is_stable() {
    let etx = calculate_etx(-75, 8.0);
    let (rssi, snr) = etx_to_signal(etx);
    let again = calculate_etx(rssi as i32, snr as f32);
    assert!((again - etx).abs() < 5.0);
}

#[test]
fn merge_topology_accepts_high_version_on_first_contact() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 100, 0);

    let neighbor = PackedNeighbor {
        node_id: 0xCC,
        etx_fixed: etx_to_fixed(calculate_etx(-75, 8.0)),
        signal_routing_active: true,
        hears_us: true,
        etx_variance: 0,
    };
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 160, true);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
    let result = graph.merge_topology(0xBB, &header, &[neighbor], true, 200, 0);
    assert!(matches!(
        result,
        TopologyMergeResult::Applied {
            neighbors: 1,
            topo_v: 160
        }
    ));
}

#[test]
fn direct_neighbor_survives_maintenance_before_topology_merge() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 1_000, 0);
    assert_eq!(graph.neighbor_count(), 1);

    let report = graph.run_maintenance(61_000);
    assert_eq!(graph.neighbor_count(), 1);
    assert!(report.graph_log_due);
}

#[test]
fn relayed_packet_creates_placeholder_edge_to_transmitter() {
    use mesh_routing::{DEVICE_ROLE_CLIENT, placeholder_node_id};

    let mut graph = NeighborGraph::new();
    graph.set_my_node(0x677a_1caf);
    graph.set_device_role(DEVICE_ROLE_CLIENT);
    graph.observe_packet(0x108a_ef6c, 2, 1, 0x8f, -75, 11, 1_000, 0, None);
    let placeholder = placeholder_node_id(0x8f);
    assert!(graph.has_graph_node(placeholder));
}

#[test]
fn relayed_topology_adds_sender_edges_and_downstream_without_destination_node() {
    use mesh_routing::DEVICE_ROLE_CLIENT;

    let mut graph = NeighborGraph::new();
    graph.set_my_node(0x677a_1caf);
    graph.set_device_role(DEVICE_ROLE_CLIENT);
    graph.observe_packet(0x108a_ef6c, 2, 1, 0x8f, -75, 11, 1_000, 0, None);

    let neighbor = PackedNeighbor {
        node_id: 0xd6c2_3e3e,
        etx_fixed: etx_to_fixed(calculate_etx(-80, 8.0)),
        signal_routing_active: true,
        hears_us: true,
        etx_variance: 0,
    };
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 197, true);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
    let result = graph.merge_topology(0x108a_ef6c, &header, &[neighbor], false, 2_000, 0);
    assert!(matches!(result, TopologyMergeResult::Applied { .. }));
    assert!(graph.has_graph_node(0x108a_ef6c));
    assert!(!graph.has_graph_node(0xd6c2_3e3e));
    assert!(graph.get_downstream_relay(0xd6c2_3e3e, 2_000).is_some());
}

#[test]
fn maintenance_removes_activity_only_nodes() {
    use mesh_routing::DEVICE_ROLE_CLIENT;

    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.set_device_role(DEVICE_ROLE_CLIENT);
    graph.update_node_activity(0xBB, 1_000);
    assert!(graph.has_graph_node(0xBB));
    graph.run_maintenance(61_000);
    assert!(!graph.has_graph_node(0xBB));
}

#[test]
fn topology_log_header_includes_graph_and_downstream_counts() {
    use mesh_routing::DEVICE_ROLE_CLIENT;

    let mut graph = NeighborGraph::new();
    graph.set_my_node(0x677a_1caf);
    graph.set_device_role(DEVICE_ROLE_CLIENT);
    graph.observe_packet(0x108a_ef6c, 2, 1, 0x8f, -75, 11, 1_000, 0, None);

    let neighbor = PackedNeighbor {
        node_id: 0xd6c2_3e3e,
        etx_fixed: etx_to_fixed(calculate_etx(-80, 8.0)),
        signal_routing_active: true,
        hears_us: true,
        etx_variance: 0,
    };
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 197, true);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
    graph.merge_topology(0x108a_ef6c, &header, &[neighbor], false, 2_000, 0);

    let mut log = SrLog::new();
    graph.emit_topology_log(0x677a_1caf, &mut log);
    let mut events = heapless::Vec::<SrLogEvent, { mesh_routing::MAX_SR_LOG }>::new();
    log.take(&mut events);

    assert!(events.iter().any(|event| matches!(
        event,
        SrLogEvent::NetworkTopologyHeader {
            direct_neighbors: 0,
            graph_nodes,
            downstream_routes: 2,
        } if *graph_nodes >= 1
    )));
}

#[test]
fn emit_topology_log_lists_mirrored_and_downstream_nodes() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 100, 0);

    let neighbor = PackedNeighbor {
        node_id: 0xCC,
        etx_fixed: etx_to_fixed(calculate_etx(-75, 8.0)),
        signal_routing_active: true,
        hears_us: true,
        etx_variance: 0,
    };
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 1, true);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
    graph.merge_topology(0xBB, &header, &[neighbor], true, 200, 0);

    let mut log = SrLog::new();
    graph.emit_topology_log(0xAA, &mut log);
    let mut events = heapless::Vec::<SrLogEvent, { mesh_routing::MAX_SR_LOG }>::new();
    log.take(&mut events);

    assert!(events.iter().any(|event| matches!(
        event,
        SrLogEvent::NetworkTopologyMirrored {
            node_id: 0xCC,
            hears_us: true,
            ..
        }
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        SrLogEvent::NetworkTopologyDownstreamRoute {
            destination: 0xCC,
            relay: 0xBB,
            ..
        }
    )));
}

#[test]
fn topology_log_omits_self_as_neighbor() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 100, 0);

    let mut log = SrLog::new();
    graph.emit_topology_log(0xAA, &mut log);
    let mut events = heapless::Vec::<SrLogEvent, { mesh_routing::MAX_SR_LOG }>::new();
    log.take(&mut events);

    assert!(!events.iter().any(|event| matches!(
        event,
        SrLogEvent::NetworkTopologyNeighbor { node_id: 0xAA, .. }
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        SrLogEvent::NetworkTopologyNeighbor { node_id: 0xBB, .. }
    )));
}

#[test]
fn direct_neighbor_count_uses_reported_to_us() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.update_node_activity(0xBB, 100);
    graph.edges_mut().update_edge(
        0xAA,
        0xBB,
        0xAA,
        2.0,
        100,
        mesh_routing::EdgeSource::Reported,
        true,
        0,
    );
    assert_eq!(graph.neighbor_count(), 1);
    assert_eq!(graph.fill_neighbor_entries(&mut [NeighborEntry::default(); MAX_EDGES_PER_NODE]), 0);
}

#[test]
fn is_our_direct_neighbor_any_edge() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.update_node_activity(0xBB, 100);
    graph.edges_mut().update_edge(
        0xAA,
        0xAA,
        0xBB,
        2.0,
        100,
        mesh_routing::EdgeSource::Mirrored,
        true,
        0,
    );
    assert!(graph.is_our_direct_neighbor(0xBB));
    assert!(!graph.edges().has_direct_reported_edge_to(0xAA, 0xBB));
}
