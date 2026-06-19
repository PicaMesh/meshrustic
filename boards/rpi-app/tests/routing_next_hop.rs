//! getNextHop Dijkstra routing tests.

use mesh_protocol::PacketHeader;
use mesh_routing::{relay_header_with_next_hop, NeighborGraph};

#[test]
fn get_next_hop_returns_direct_neighbor() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 0, 0);
    assert_eq!(graph.get_next_hop(0xBB, 0xCC, 0), 0xBB);
}

#[test]
fn get_next_hop_two_hop_via_intermediate() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 0, 0);
    let mut packed = [0u8; 16];
    mesh_routing::write_packed_header(&mut packed, 1, true);
    let (header, _) = mesh_routing::decode_packed_neighbors(&packed, 8).unwrap();
    let neighbor = mesh_routing::PackedNeighbor {
        node_id: 0xCC,
        rssi: -75,
        snr: 8,
        signal_routing_active: true,
        hears_us: false,
        etx_variance: 0,
    };
    graph.merge_topology(0xBB, &header, &[neighbor], true, 100, 0);
    assert_eq!(graph.get_next_hop(0xCC, 0xDD, 200), 0xBB);
}

#[test]
fn unicast_relay_sets_next_hop_byte() {
    let header = PacketHeader::from_fields(0x1234_5678, 0xAABB_CCDD, 1, 0, 3, 3, false, false, 0, 0);
    let parsed = header.parse();
    let relay = relay_header_with_next_hop(&parsed, 0xDEAD_BEEF, 0xBB).unwrap();
    assert_eq!(relay.next_hop, 0xBB);
}

#[test]
fn downstream_fallback_when_no_graph_path() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 0, 0);
    let mut packed = [0u8; 16];
    mesh_routing::write_packed_header(&mut packed, 1, true);
    let (header, _) = mesh_routing::decode_packed_neighbors(&packed, 8).unwrap();
    let remote = mesh_routing::PackedNeighbor {
        node_id: 0xCC,
        rssi: -75,
        snr: 8,
        signal_routing_active: true,
        hears_us: true,
        etx_variance: 0,
    };
    graph.merge_topology(0xBB, &header, &[remote], true, 100, 0);
    assert_eq!(graph.get_next_hop(0xCC, 0xDD, 200), 0xBB);
}
