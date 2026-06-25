//! Placeholder → real node resolution and gateway transfer.

use mesh_routing::{
    get_placeholder_for_relay, is_placeholder_node, NeighborGraph, DEVICE_ROLE_ROUTER,
};

const ME: u32 = 0xAA00_00AA;
const SOURCE: u32 = 0xBEEF_00AB;
const DEST: u32 = 0xCC00_00CC;
const RELAY_BYTE: u8 = 0xCD;

fn relayed_placeholder(graph: &mut NeighborGraph) -> u32 {
    graph.set_my_node(ME);
    graph.set_device_role(DEVICE_ROLE_ROUTER);
    graph.observe_packet(SOURCE, 3, 2, RELAY_BYTE, -70, 8, 100, 0);
    let placeholder = get_placeholder_for_relay(RELAY_BYTE);
    assert!(graph.has_graph_node(placeholder));
    placeholder
}

#[test]
fn placeholder_replaced_when_real_node_learned() {
    let mut graph = NeighborGraph::new();
    let placeholder = relayed_placeholder(&mut graph);

    assert!(graph.resolve_placeholder(placeholder, SOURCE, 200));
    assert!(!graph.has_graph_node(placeholder));
    assert!(!graph.resolve_placeholder(placeholder, SOURCE, 300));
}

#[test]
fn downstream_transferred_on_resolution() {
    let mut graph = NeighborGraph::new();
    let placeholder = relayed_placeholder(&mut graph);
    graph
        .downstream_mut()
        .update(ME, DEST, placeholder, 2.0, 100, false, 0);

    assert!(graph.resolve_placeholder(placeholder, SOURCE, 200));
    assert_eq!(graph.get_downstream_relay(DEST, 200), Some(SOURCE));
    assert!(graph.is_downstream_relay_for(SOURCE, DEST, 200));
    assert!(!is_placeholder_node(
        graph.get_downstream_relay(DEST, 200).unwrap_or(0)
    ));
}

#[test]
fn no_duplicate_edges_after_resolution() {
    let mut graph = NeighborGraph::new();
    let placeholder = relayed_placeholder(&mut graph);
    graph.observe_direct_neighbor(SOURCE, -72, 9, 150, 0);

    assert!(graph.resolve_placeholder(placeholder, SOURCE, 200));
    assert!(!graph.has_graph_node(placeholder));

    let Some(my_edges) = graph.edges().find_node(ME) else {
        panic!("missing local node");
    };
    let mut to_source = 0u8;
    for i in 0..my_edges.edge_count as usize {
        if my_edges.edges[i].to == SOURCE {
            to_source += 1;
        }
        assert_ne!(my_edges.edges[i].to, placeholder);
    }
    assert_eq!(to_source, 1);
}
