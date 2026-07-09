//! getNextHop Dijkstra routing tests.

use mesh_protocol::PacketHeader;
use mesh_routing::{
    decode_packed_neighbors, relay_header_with_next_hop,
    write_packed_header, DEVICE_ROLE_CLIENT_MUTE, NeighborGraph, PackedNeighbor,
    TopologyMergeResult,
};

fn merge_remote(graph: &mut NeighborGraph, reporter: u32, neighbor: u32, now_ms: u32) {
    let remote = PackedNeighbor {
        node_id: neighbor,
        rssi: -75,
        snr: 8,
        signal_routing_active: true,
        hears_us: false,
        etx_variance: 0,
    };
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 1, true);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
    let result = graph.merge_topology(reporter, &header, &[remote], true, now_ms, 0);
    assert!(matches!(result, TopologyMergeResult::Applied { .. }));
}

#[test]
fn get_next_hop_returns_direct_neighbor() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 0, 0);
    assert_eq!(graph.get_next_hop(0xBB, 0, 0, 0), 0xBB);
}

#[test]
fn get_next_hop_two_hop_via_intermediate() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    graph.observe_direct_neighbor(0xBB, -70, 8, 0, 0);
    merge_remote(&mut graph, 0xBB, 0xCC, 100);
    assert_eq!(graph.get_next_hop(0xCC, 0, 0, 200), 0xBB);
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
    merge_remote(&mut graph, 0xBB, 0xCC, 100);
    assert_eq!(graph.get_next_hop(0xCC, 0, 0, 200), 0xBB);
}

#[test]
fn next_hop_requires_verified_connectivity() {
    const AA: u32 = 0xAA00_00AA;
    const BB: u32 = 0xBB00_00BB;
    const CC: u32 = 0xCC00_00CC;
    const DD: u32 = 0xDD00_00DD;

    let mut graph = NeighborGraph::new();
    graph.set_my_node(AA);
    graph.observe_direct_neighbor(BB, -70, 8, 0, 0);
    merge_remote(&mut graph, BB, CC, 100);

    assert_eq!(graph.get_next_hop(CC, 0, DD, 200), AA);
    assert_ne!(graph.get_next_hop(CC, 0, DD, 200), BB);
}

#[test]
fn dijkstra_skips_non_routable_node() {
    const AA: u32 = 0xAA00_00AA;
    const MUTE: u32 = 0x0100_0001;
    const BB: u32 = 0xBB00_00BB;
    const CC: u32 = 0xCC00_00CC;

    let mut graph = NeighborGraph::new();
    graph.set_my_node(AA);
    graph.observe_direct_neighbor(MUTE, -70, 8, 0, 0);
    graph.track_node_role(MUTE, DEVICE_ROLE_CLIENT_MUTE, 0);
    graph.observe_direct_neighbor(BB, -72, 8, 0, 0);
    merge_remote(&mut graph, BB, CC, 100);

    assert_eq!(graph.get_next_hop(CC, 0, 0, 200), BB);
}

#[test]
fn opportunistic_skips_source_and_heard_from() {
    use mesh_routing::find_better_positioned_neighbor;

    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA00_00AA);
    graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 0, 0);
    graph.observe_direct_neighbor(0xCC00_00CC, -72, 8, 0, 0);
    merge_remote(&mut graph, 0xBB00_00BB, 0xDD00_00DD, 100);
    merge_remote(&mut graph, 0xCC00_00CC, 0xDD00_00DD, 100);

    let hop = find_better_positioned_neighbor(
        graph.edges(),
        &mesh_routing::CapabilityCache::new(),
        0xAA00_00AA,
        mesh_routing::DEVICE_ROLE_CLIENT,
        0xDD00_00DD,
        0xBB00_00BB,
        0,
        8.0,
    );
    assert_eq!(hop, 0xCC00_00CC);
}

#[test]
fn next_hop_fallback_order() {
    const AA: u32 = 0xAA00_00AA;
    const RELAY: u32 = 0xBB00_00BB;
    const DEST: u32 = 0xCC00_00CC;

    let mut graph = NeighborGraph::new();
    graph.set_my_node(AA);
    graph.observe_direct_neighbor(RELAY, -70, 8, 0, 0);
    graph.downstream_mut().update(AA, DEST, RELAY, 3.0, 100, false, 0);

    assert_eq!(graph.get_next_hop(DEST, 0, 0, 200), RELAY);
}

#[test]
fn relayed_unicast_delivers_to_direct_neighbor_with_hears_us() {
    const AA: u32 = 0xAA00_00AA;
    const SOURCE: u32 = 0xEE00_00EE;
    const DEST: u32 = 0xDD00_00DD;

    let mut graph = NeighborGraph::new();
    graph.set_my_node(AA);
    graph.observe_direct_neighbor(DEST, -70, 8, 0, 0);
    graph.confirm_direct_neighbor_hears_us(DEST);

    assert_eq!(graph.get_next_hop(DEST, SOURCE, SOURCE, 100), DEST);
}
