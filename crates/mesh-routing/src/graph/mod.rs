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
pub use placeholder::{is_placeholder_node, placeholder_node_id, PLACEHOLDER_NODE_PREFIX};
pub use route::{
    calculate_route, find_better_positioned_neighbor, Route, RouteCache, MAX_CACHED_ROUTES,
    ROUTE_CACHE_TIMEOUT_MS,
};

pub const MAX_GRAPH_NODES: usize = 24;
