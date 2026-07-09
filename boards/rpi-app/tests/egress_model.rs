//! Egress vs inbound model — coverage and relay candidacy use `hears_us` only.

use mesh_routing::{
    decode_packed_neighbors, plan_broadcast_relay, write_packed_header, BroadcastRelayContext,
    NeighborGraph, PackedNeighbor, TopologyMergeResult, DEVICE_ROLE_ROUTER,
};

const ME: u32 = 0x1000_0001;
const EGRESS: u32 = 0xA000_000A;
const INBOUND: u32 = 0xB000_000B;
const SOURCE: u32 = 0x5000_00EE;
const PACKET_ID: u32 = 0xABCD_1234;

const EGRESS2: u32 = 0xC000_000C;
const HEARD_FROM: u32 = 0xD000_000D;

#[test]
fn field_egress_coverage_ignores_inbound_only_neighbor() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(ME);
    graph.observe_direct_neighbor(EGRESS, -70, 8, 0, 0);
    graph.observe_direct_neighbor(EGRESS2, -71, 8, 0, 0);
    graph.observe_direct_neighbor(INBOUND, -72, 7, 0, 0);
    graph.confirm_direct_neighbor_hears_us(EGRESS);
    graph.confirm_direct_neighbor_hears_us(EGRESS2);

    assert!(graph.has_unique_coverage(&[EGRESS]));
    graph.confirm_direct_neighbor_hears_us(INBOUND);
    assert!(graph.has_unique_coverage(&[EGRESS]));
    assert!(!graph.has_unique_coverage(&[EGRESS, EGRESS2, INBOUND]));
}

#[test]
fn field_merge_asymmetric_downstream_is_observable() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(ME);
    graph.set_device_role(DEVICE_ROLE_ROUTER);
    graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 0, 0);

    let remote = PackedNeighbor {
        node_id: 0xCC00_00CC,
        rssi: -72,
        snr: 8,
        signal_routing_active: true,
        hears_us: false,
        etx_variance: 0,
    };
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 1, true);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
    let result = graph.merge_topology(0xBB00_00BB, &header, &[remote], true, 200, 0);
    assert!(matches!(result, TopologyMergeResult::Applied { .. }));
    let skips: heapless::Vec<_, 4> = graph.drain_merge_asymmetric_skips().collect();
    assert_eq!(skips.as_slice(), &[(0xBB00_00BB, 0xCC00_00CC)]);
}

#[test]
fn field_relay_plan_counts_only_hears_us_sr_candidates() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(ME);
    graph.observe_direct_neighbor(HEARD_FROM, -70, 8, 0, 0);
    graph.observe_direct_neighbor(EGRESS, -70, 8, 0, 0);
    graph.confirm_direct_neighbor_hears_us(EGRESS);
    graph.observe_direct_neighbor(INBOUND, -72, 7, 0, 0);
    graph.capability_mut().track_topology(INBOUND, true, 0);
    graph.capability_mut().track_topology(EGRESS, true, 0);

    let ctx = BroadcastRelayContext {
        my_node: ME,
        edges: graph.edges(),
        capability: graph.capability(),
        downstream: graph.downstream(),
    };
    let plan_without = plan_broadcast_relay(
        &ctx,
        PACKET_ID,
        SOURCE,
        HEARD_FROM,
        0xFFFF_FFFF,
        0,
        100,
        |_| false,
    );
    assert_eq!(plan_without.candidate_count, 2);

    graph.confirm_direct_neighbor_hears_us(INBOUND);
    let ctx = BroadcastRelayContext {
        my_node: ME,
        edges: graph.edges(),
        capability: graph.capability(),
        downstream: graph.downstream(),
    };
    let plan_with = plan_broadcast_relay(
        &ctx,
        PACKET_ID,
        SOURCE,
        HEARD_FROM,
        0xFFFF_FFFF,
        0,
        100,
        |_| false,
    );
    assert_eq!(plan_with.candidate_count, 3);
}
