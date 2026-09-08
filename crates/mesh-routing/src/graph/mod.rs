//! Full topology graph (edges + downstream) ported from reference NeighborGraph.

pub mod downstream;
pub mod edge;
pub mod etx;
pub mod placeholder;
pub mod route;

pub use downstream::{DownstreamEntry, DownstreamTable, MAX_DOWNSTREAM};
pub use edge::{
    Edge, EdgeSource, EdgeStore, NodeEdges, EDGE_NEW, EDGE_NO_CHANGE, EDGE_SIGNIFICANT_CHANGE,
    MAX_EDGES_PER_NODE,
};
pub use etx::{calculate_etx, etx_to_fixed, etx_to_signal, fixed_to_etx, EtxFixed};
pub use placeholder::{
    get_placeholder_for_relay, is_placeholder_node, placeholder_node_id, PLACEHOLDER_NODE_PREFIX,
};
pub use route::{
    calculate_route, can_deliver, coverage_owner, covers, delivery_hop_cost_fixed,
    find_better_positioned_neighbor, hop_cost_fixed, is_node_routable, is_silent_publisher,
    known_to_hear, publishes_topology, verified_connectivity, witness_owner, RoutableFilter, Route,
    RouteCache, COVERAGE_ETX_CEILING_FIXED, MAX_CACHED_ROUTES, OWNER_COST_BUCKET_FIXED,
    ROUTE_CACHE_TIMEOUT_MS, UNVERIFIED_HOP_COST_FACTOR,
};

pub const MAX_GRAPH_NODES: usize = 40;
