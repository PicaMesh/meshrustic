//! Phase 9 multi-radio graph metadata (heard_on / egress_radio).

use mesh_routing::{NeighborGraph, Route};

#[test]
fn direct_neighbor_edge_records_heard_on_radio() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA00_00AA);
    graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 100, 1);
    assert_eq!(graph.edge_heard_on(0xBB00_00BB), 1);
}

#[test]
fn route_to_sets_egress_radio_from_first_hop_edge() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA00_00AA);
    graph.observe_direct_neighbor(0xCC00_00CC, -70, 8, 0, 1);
    let Route {
        next_hop,
        egress_radio,
        ..
    } = graph.route_to(0xCC00_00CC, 0);
    assert_eq!(next_hop, 0xCC00_00CC);
    assert_eq!(egress_radio, 1);
}

#[test]
fn merge_topology_downstream_stores_via_radio() {
    use mesh_routing::{PackedHeader, PackedNeighbor};

    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA00_00AA);
    graph.observe_direct_neighbor(0xDD00_00DD, -70, 8, 0, 1);
    let header = PackedHeader {
        format_version: 1,
        entry_size: 8,
        routing_version: 3,
        topology_version: 1,
        signal_routing_active: true,
    };
    let neighbor = PackedNeighbor {
        node_id: 0xEE00_00EE,
        rssi: -70,
        snr: 8,
        signal_routing_active: true,
        hears_us: true,
        etx_variance: 0,
    };
    graph.merge_topology(0xDD00_00DD, &header, &[neighbor], true, 100, 1);
    let route = graph.route_to(0xEE00_00EE, 200);
    assert_eq!(route.next_hop, 0xDD00_00DD);
    assert_eq!(route.egress_radio, 1);
}
