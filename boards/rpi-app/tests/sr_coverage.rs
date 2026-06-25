//! Broadcast dupe coverage via accumulated transmitters + unique coverage.

use mesh_routing::{
    decode_packed_neighbors, write_packed_header, NeighborGraph, PackedNeighbor,
    TopologyMergeResult, DEFAULT_SLOT_MS,
};

const ME: u32 = 0x1000_0001;
const NEIGHBOR_A: u32 = 0xA000_000A;
const NEIGHBOR_B: u32 = 0xB000_000B;
const NEIGHBOR_C: u32 = 0xC000_000C;
const NEIGHBOR_D: u32 = 0xD000_000D;
const NEIGHBOR_E: u32 = 0xE000_000E;
const SOURCE: u32 = 0x5000_00EE;
const PACKET_ID: u32 = 0xDEAD_BEEF;

fn hears_us_neighbors(graph: &mut NeighborGraph, neighbors: &[u32]) {
    for &neighbor in neighbors {
        graph.observe_direct_neighbor(neighbor, -70, 8, 0, 0);
        graph.confirm_direct_neighbor_hears_us(neighbor);
    }
}

fn merge_remote_neighbor(graph: &mut NeighborGraph, reporter: u32, neighbor: u32, now_ms: u32) {
    let remote = PackedNeighbor {
        node_id: neighbor,
        rssi: -72,
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

fn commit_broadcast_relay(graph: &mut NeighborGraph, heard_from: u32) {
    graph.commit_relay(
        SOURCE,
        PACKET_ID,
        0,
        8,
        heard_from,
        1_000,
        50,
        DEFAULT_SLOT_MS,
        ME,
    );
}

#[test]
fn unique_coverage_keeps_relay() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(ME);
    hears_us_neighbors(&mut graph, &[NEIGHBOR_A, NEIGHBOR_B]);
    commit_broadcast_relay(&mut graph, NEIGHBOR_A);

    assert!(
        !graph.all_neighbors_covered(SOURCE, PACKET_ID, NEIGHBOR_A),
        "B is not in A's edge set — relay should stay"
    );
}

#[test]
fn all_covered_cancels_relay() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(ME);
    hears_us_neighbors(&mut graph, &[NEIGHBOR_A, NEIGHBOR_B]);
    merge_remote_neighbor(&mut graph, NEIGHBOR_A, NEIGHBOR_B, 100);
    commit_broadcast_relay(&mut graph, NEIGHBOR_A);

    assert!(
        graph.all_neighbors_covered(SOURCE, PACKET_ID, NEIGHBOR_A),
        "A covers B — dupe cancel should proceed"
    );
}

#[test]
fn heard_transmitters_accumulate_distinct() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(ME);
    hears_us_neighbors(&mut graph, &[NEIGHBOR_A, NEIGHBOR_B, NEIGHBOR_D, NEIGHBOR_C]);
    graph.observe_direct_neighbor(NEIGHBOR_E, -70, 8, 0, 0);
    merge_remote_neighbor(&mut graph, NEIGHBOR_A, NEIGHBOR_B, 100);
    merge_remote_neighbor(&mut graph, NEIGHBOR_E, NEIGHBOR_D, 100);
    commit_broadcast_relay(&mut graph, NEIGHBOR_A);

    assert_eq!(graph.relay_heard_transmitter_count(SOURCE, PACKET_ID), 0);
    assert!(!graph.all_neighbors_covered(SOURCE, PACKET_ID, NEIGHBOR_C));
    assert_eq!(graph.relay_heard_transmitter_count(SOURCE, PACKET_ID), 1);

    assert!(!graph.all_neighbors_covered(SOURCE, PACKET_ID, NEIGHBOR_C));
    assert_eq!(graph.relay_heard_transmitter_count(SOURCE, PACKET_ID), 1);

    assert!(graph.all_neighbors_covered(SOURCE, PACKET_ID, NEIGHBOR_E));
    assert_eq!(graph.relay_heard_transmitter_count(SOURCE, PACKET_ID), 2);
}
