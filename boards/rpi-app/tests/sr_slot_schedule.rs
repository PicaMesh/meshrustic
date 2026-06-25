//! Broadcast relay slot scheduling (phased stock → SR → downstream → coverage).

use mesh_routing::{
    NeighborGraph, EdgeSource, DEVICE_ROLE_REPEATER, DEVICE_ROLE_ROUTER,
    POOR_LINK_ETX_THRESHOLD,
};

const ME: u32 = 0xCC00_00CC;
const BB: u32 = 0xBB00_00BB;
const DD: u32 = 0xDD00_00DD;
const EE: u32 = 0xEE00_00EE;
const HALF: u32 = 100;

fn setup_stock_graph(graph: &mut NeighborGraph) {
    graph.set_my_node(ME);
    graph.set_device_role(DEVICE_ROLE_ROUTER);
    graph.observe_direct_neighbor(BB, -70, 8, 0, 0);
    graph.observe_direct_neighbor(DD, -72, 7, 0, 0);
    graph.track_node_role(DD, DEVICE_ROLE_REPEATER, 0);
    graph.edges_mut().update_edge(ME, DD, BB, 2.0, 0, EdgeSource::Reported, true, 0);
    graph.edges_mut().update_edge(ME, BB, DD, 2.0, 0, EdgeSource::Reported, true, 0);
}

#[test]
fn stock_router_gets_first_slot() {
    let mut graph = NeighborGraph::new();
    setup_stock_graph(&mut graph);
    let plan = graph.plan_broadcast_relay(0x99, BB, BB, 0xFFFF_FFFF, 0, HALF);
    assert!(!plan.should_relay);
    assert_eq!(plan.slot_delay_ms, 0);
}

#[test]
fn best_candidate_assigned_earlier_slot() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(ME);
    graph.set_device_role(DEVICE_ROLE_ROUTER);
    graph.edges_mut().ensure_local_node(ME, 0);
    graph.edges_mut().update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
    graph.edges_mut().update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
    graph.capability_mut().track_topology(EE, true, 0);
    graph.capability_mut().track_topology(ME, true, 0);
    graph.edges_mut().update_edge(ME, EE, BB, 1.5, 0, EdgeSource::Reported, true, 0);
    graph.edges_mut().update_edge(ME, EE, ME, 2.0, 0, EdgeSource::Reported, true, 0);
    graph
        .edges_mut()
        .update_edge(ME, EE, 0xFF00_00FF, 1.5, 0, EdgeSource::Reported, true, 0);
    graph
        .edges_mut()
        .update_edge(ME, ME, 0xFF00_00FF, 2.0, 0, EdgeSource::Reported, true, 0);

    let plan = graph.plan_broadcast_relay(0x99, BB, BB, 0xFFFF_FFFF, 0, HALF);
    assert!(plan.should_relay);
    assert_eq!(plan.slot_delay_ms, HALF);
    assert_eq!(plan.slot_index, 1);
}

#[test]
fn poor_etx_neighbor_not_precovered() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(ME);
    graph.set_device_role(DEVICE_ROLE_ROUTER);
    graph.observe_direct_neighbor(BB, -70, 8, 0, 0);
    graph.observe_direct_neighbor(DD, -72, 7, 0, 0);
    graph.track_node_role(DD, DEVICE_ROLE_REPEATER, 0);
    graph.edges_mut().update_edge(ME, DD, BB, 2.0, 0, EdgeSource::Reported, true, 0);
    graph.edges_mut().update_edge(
        ME,
        BB,
        ME,
        POOR_LINK_ETX_THRESHOLD + 1.0,
        0,
        EdgeSource::Reported,
        true,
        0,
    );
    let plan = graph.plan_broadcast_relay(0x99, BB, BB, 0xFFFF_FFFF, 0, HALF);
    assert!(plan.should_relay);
}

#[test]
fn we_relay_when_downstream_relay_for_source() {
    let mut graph = NeighborGraph::new();
    setup_stock_graph(&mut graph);
    graph
        .downstream_mut()
        .update(ME, BB, ME, 1.0, 0, false, 0);
    let plan = graph.plan_broadcast_relay(0x99, BB, BB, 0xFFFF_FFFF, 0, HALF);
    assert!(plan.should_relay);
}
