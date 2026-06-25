//! Downstream relay lookup: TTL, lowest cost, transfer helpers.

use mesh_routing::{DownstreamTable, NeighborGraph, NEIGHBOR_TTL_MS};

#[test]
fn downstream_relay_picks_lowest_cost() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA00_00AA);
    graph.downstream_mut().update(0xAA00_00AA, 0xDD00_00DD, 0xBB00_00BB, 4.0, 1_000, false, 0);
    graph
        .downstream_mut()
        .update(0xAA00_00AA, 0xDD00_00DD, 0xCC00_00CC, 2.5, 1_000, false, 0);
    assert_eq!(
        graph.get_downstream_relay(0xDD00_00DD, 1_500),
        Some(0xCC00_00CC)
    );
}

#[test]
fn downstream_relay_skips_stale_ttl() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA00_00AA);
    graph.downstream_mut().update(0xAA00_00AA, 0xDD00_00DD, 0xBB00_00BB, 2.0, 1_000, false, 0);
    graph
        .downstream_mut()
        .update(0xAA00_00AA, 0xDD00_00DD, 0xCC00_00CC, 1.5, 1_000, false, 0);
    let stale_at = 1_000 + NEIGHBOR_TTL_MS;
    assert_eq!(graph.get_downstream_relay(0xDD00_00DD, stale_at), None);
}

#[test]
fn transfer_downstream_moves_entries() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA00_00AA);
    graph.downstream_mut().update(0xAA00_00AA, 0xD100_0001, 0x0100_0001, 2.0, 1_000, false, 0);
    graph.downstream_mut().update(0xAA00_00AA, 0xD200_0002, 0x0100_0001, 3.0, 1_000, false, 0);
    assert_eq!(graph.transfer_downstream(0x0100_0001, 0x0200_0002, 2_000), 2);
    assert_eq!(graph.downstream_count_for_relay(0x0100_0001, 2_000), 0);
    assert_eq!(graph.downstream_count_for_relay(0x0200_0002, 2_000), 2);
    assert!(graph.is_downstream_relay_for(0x0200_0002, 0xD100_0001, 2_000));
}

#[test]
fn table_helpers_match_graph_wrappers() {
    let mut table = DownstreamTable::new();
    const RELAY: u32 = 0x0000_00A1;
    table.update(0xAA, 0xD1, RELAY, 2.0, 1_000, false, 0);
    assert!(table.is_relay_for(RELAY, 0xD1, 1_500, 10_000));
    assert_eq!(table.count_for_relay(RELAY, 1_500, 10_000), 1);
    let mut out = [0u32; 2];
    assert_eq!(table.nodes_for_relay(RELAY, &mut out, 1_500, 10_000), 1);
    assert_eq!(out[0], 0xD1);
}
