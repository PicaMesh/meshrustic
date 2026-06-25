//! Dijkstra routing and route cache over the edge graph.

use mesh_radio::RadioId;

use super::{DownstreamTable, EdgeStore, MAX_GRAPH_NODES};
use super::is_placeholder_node;
use crate::capability::{CapabilityCache, CapabilityStatus};
use crate::nodeinfo::DEVICE_ROLE_CLIENT_MUTE;

pub const MAX_CACHED_ROUTES: usize = 32;
pub const ROUTE_CACHE_TIMEOUT_MS: u32 = 300_000;
pub const ROUTE_COST_UNKNOWN: u16 = 0xFFFF;

/// Inputs for Dijkstra hop filtering (`is_node_routable`).
pub struct RoutableFilter<'a> {
    pub capability: &'a CapabilityCache,
    pub my_node: u32,
    pub device_role: u32,
}

pub fn is_node_routable(filter: &RoutableFilter<'_>, node_id: u32) -> bool {
    if node_id == 0 {
        return false;
    }
    if filter.device_role == DEVICE_ROLE_CLIENT_MUTE && node_id == filter.my_node {
        return false;
    }
    match filter.capability.status(node_id) {
        CapabilityStatus::Legacy => filter.capability.is_legacy_router(node_id),
        _ => true,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Route {
    pub destination: u32,
    pub next_hop: u32,
    pub egress_radio: RadioId,
    pub cost_fixed: u16,
    pub timestamp_ms: u32,
}

impl Route {
    pub fn cost(&self) -> f32 {
        self.cost_fixed as f32 / 100.0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RouteCacheEntry {
    route: Route,
}

pub struct RouteCache {
    entries: [RouteCacheEntry; MAX_CACHED_ROUTES],
    count: u8,
}

impl RouteCache {
    pub const fn new() -> Self {
        Self {
            entries: [RouteCacheEntry {
                route: Route {
                    destination: 0,
                    next_hop: 0,
                    egress_radio: 0,
                    cost_fixed: 0,
                    timestamp_ms: 0,
                },
            }; MAX_CACHED_ROUTES],
            count: 0,
        }
    }

    pub fn clear(&mut self) {
        self.count = 0;
    }

    pub fn get(&self, destination: u32, now_ms: u32) -> Option<Route> {
        for i in 0..self.count as usize {
            let route = self.entries[i].route;
            if route.destination == destination
                && now_ms.wrapping_sub(route.timestamp_ms) < ROUTE_CACHE_TIMEOUT_MS
                && route.next_hop != 0
            {
                return Some(route);
            }
        }
        None
    }

    pub fn insert(&mut self, route: Route) {
        if route.next_hop == 0 {
            return;
        }
        for i in 0..self.count as usize {
            if self.entries[i].route.destination == route.destination {
                self.entries[i].route = route;
                return;
            }
        }
        if (self.count as usize) < MAX_CACHED_ROUTES {
            let idx = self.count as usize;
            self.entries[idx].route = route;
            self.count += 1;
            return;
        }
        self.entries[0].route = route;
    }
}

#[derive(Clone, Copy)]
struct DNode {
    id: u32,
    cost: u16,
    prev: u32,
    visited: bool,
}

fn find_or_add_node(
    id: u32,
    nodes: &mut [DNode; MAX_GRAPH_NODES],
    node_count: &mut usize,
) -> Option<usize> {
    for i in 0..*node_count {
        if nodes[i].id == id {
            return Some(i);
        }
    }
    if *node_count >= MAX_GRAPH_NODES {
        return None;
    }
    nodes[*node_count] = DNode {
        id,
        cost: ROUTE_COST_UNKNOWN,
        prev: 0,
        visited: false,
    };
    *node_count += 1;
    Some(*node_count - 1)
}

fn prev_of(nodes: &[DNode; MAX_GRAPH_NODES], node_count: usize, id: u32) -> u32 {
    for i in 0..node_count {
        if nodes[i].id == id {
            return nodes[i].prev;
        }
    }
    0
}

pub fn calculate_route(
    edges: &EdgeStore,
    downstream: &DownstreamTable,
    my_node: u32,
    destination: u32,
    now_ms: u32,
    routable: Option<&RoutableFilter<'_>>,
) -> Route {
    let mut result = Route {
        destination,
        next_hop: 0,
        egress_radio: 0,
        cost_fixed: ROUTE_COST_UNKNOWN,
        timestamp_ms: now_ms,
    };
    if my_node == 0 || destination == 0 || destination == my_node {
        return result;
    }

    if let Some(edge) = edges
        .find_node(my_node)
        .and_then(|n| n.find_edge(destination))
    {
        result.next_hop = destination;
        result.cost_fixed = edge.etx_fixed;
        result.egress_radio = edge.heard_on;
        return result;
    }

    let mut nodes = [DNode {
        id: 0,
        cost: ROUTE_COST_UNKNOWN,
        prev: 0,
        visited: false,
    }; MAX_GRAPH_NODES];
    let mut node_count = 0usize;

    let Some(src_idx) = find_or_add_node(my_node, &mut nodes, &mut node_count) else {
        return result;
    };
    nodes[src_idx].cost = 0;
    let _ = find_or_add_node(destination, &mut nodes, &mut node_count);
    for i in 0..edges.node_count() {
        if let Some(id) = edges.node_id_at(i) {
            let _ = find_or_add_node(id, &mut nodes, &mut node_count);
        }
    }

    loop {
        let mut u_idx = None;
        let mut u_cost = ROUTE_COST_UNKNOWN;
        for i in 0..node_count {
            if !nodes[i].visited && nodes[i].cost < u_cost {
                u_cost = nodes[i].cost;
                u_idx = Some(i);
            }
        }
        let Some(u_idx) = u_idx else {
            break;
        };
        if u_cost == ROUTE_COST_UNKNOWN {
            break;
        }

        let u = nodes[u_idx].id;
        nodes[u_idx].visited = true;
        if u == destination {
            break;
        }

        if u != my_node {
            if let Some(filter) = routable {
                if !is_node_routable(filter, u) {
                    continue;
                }
            }
        }

        let Some(u_edges) = edges.find_node(u) else {
            continue;
        };
        for e in 0..u_edges.edge_count as usize {
            let edge = u_edges.edges[e];
            let v = edge.to;
            let Some(v_idx) = find_or_add_node(v, &mut nodes, &mut node_count) else {
                continue;
            };
            if nodes[v_idx].visited {
                continue;
            }
            let new_cost = u_cost.saturating_add(edge.etx_fixed).min(0xFFFE);
            if new_cost < nodes[v_idx].cost {
                nodes[v_idx].cost = new_cost;
                nodes[v_idx].prev = u;
            }
        }
    }

    for i in 0..node_count {
        if nodes[i].id == destination && nodes[i].cost < ROUTE_COST_UNKNOWN {
            result.cost_fixed = nodes[i].cost;
            let mut cur = destination;
            let mut prev = nodes[i].prev;
            while prev != my_node && prev != 0 {
                cur = prev;
                prev = prev_of(&nodes, node_count, cur);
            }
            result.next_hop = cur;
            break;
        }
    }

    if result.next_hop != 0 {
        result.egress_radio = edges
            .find_node(my_node)
            .and_then(|n| n.find_edge(result.next_hop))
            .map(|e| e.heard_on)
            .unwrap_or(0);
    }

    if result.next_hop == 0 {
        let my_edges = edges.find_node(my_node);
        let mut best_cost = ROUTE_COST_UNKNOWN;
        let mut best_relay = 0u32;
        for i in 0..downstream.count() {
            let Some(entry) = downstream.entry(i) else {
                break;
            };
            if entry.destination != destination {
                continue;
            }
            if edges.find_node(entry.relay).is_none() {
                continue;
            }
            let cost_to_relay = my_edges
                .and_then(|n| n.find_edge(entry.relay))
                .map(|e| e.etx_fixed)
                .unwrap_or(ROUTE_COST_UNKNOWN);
            if cost_to_relay >= 0xFFF0 || entry.cost_fixed >= 0xFFF0 {
                continue;
            }
            let total = cost_to_relay.saturating_add(entry.cost_fixed);
            if total < best_cost {
                best_cost = total;
                best_relay = entry.relay;
            }
        }
        if best_relay != 0 {
            result.next_hop = best_relay;
            result.cost_fixed = best_cost;
            result.egress_radio = my_edges
                .and_then(|n| n.find_edge(best_relay))
                .map(|e| e.heard_on)
                .unwrap_or(0);
            if result.egress_radio == 0 {
                for i in 0..downstream.count() {
                    if let Some(entry) = downstream.entry(i) {
                        if entry.destination == destination && entry.relay == best_relay {
                            result.egress_radio = entry.via_radio;
                            break;
                        }
                    }
                }
            }
        }
    }

    result
}

/// Returns `(verified, unknown)` for whether `transmitter` can reach `receiver`.
pub fn verified_connectivity(
    edges: &EdgeStore,
    capability: &CapabilityCache,
    transmitter: u32,
    receiver: u32,
) -> (bool, bool) {
    let tx_stock = is_stock_for_connectivity(capability, transmitter);
    let rx_stock = is_stock_for_connectivity(capability, receiver);
    if tx_stock && rx_stock {
        return (false, true);
    }
    if !tx_stock && edges.has_direct_reported_edge_to(transmitter, receiver) {
        return (true, false);
    }
    if !rx_stock && edges.has_direct_reported_edge_to(receiver, transmitter) {
        return (true, false);
    }
    if tx_stock || rx_stock {
        (false, true)
    } else {
        (false, false)
    }
}

fn is_stock_for_connectivity(capability: &CapabilityCache, node: u32) -> bool {
    is_placeholder_node(node)
        || matches!(
            capability.status(node),
            CapabilityStatus::Legacy | CapabilityStatus::Unknown
        )
}

/// Opportunistic next hop: neighbor with a direct edge to `destination` significantly better than our route.
pub fn find_better_positioned_neighbor(
    edges: &EdgeStore,
    capability: &CapabilityCache,
    my_node: u32,
    device_role: u32,
    destination: u32,
    source_node: u32,
    heard_from: u32,
    our_route_cost: f32,
) -> u32 {
    let filter = RoutableFilter {
        capability,
        my_node,
        device_role,
    };
    let mut best_neighbor = 0u32;
    let mut best_cost = our_route_cost;
    let Some(my_edges) = edges.find_node(my_node) else {
        return 0;
    };
    for i in 0..my_edges.edge_count as usize {
        let neighbor = my_edges.edges[i].to;
        if neighbor == 0 || neighbor == source_node || neighbor == heard_from {
            continue;
        }
        if !is_node_routable(&filter, neighbor) {
            continue;
        }
        if heard_from != 0 {
            let (verified, unknown) =
                verified_connectivity(edges, capability, heard_from, neighbor);
            if !verified || unknown {
                continue;
            }
        }
        let Some(neighbor_edges) = edges.find_node(neighbor) else {
            continue;
        };
        for j in 0..neighbor_edges.edge_count as usize {
            if neighbor_edges.edges[j].to != destination {
                continue;
            }
            let direct_etx = neighbor_edges.edges[j].etx();
            if direct_etx + 1.0 < best_cost {
                best_neighbor = neighbor;
                best_cost = direct_etx;
            }
            break;
        }
    }
    best_neighbor
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityCache;
    use crate::nodeinfo::{DEVICE_ROLE_CLIENT, DEVICE_ROLE_CLIENT_MUTE};
    use crate::graph::{EdgeSource, EdgeStore, DownstreamTable};

    #[test]
    fn direct_neighbor_is_next_hop() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 0);
        edges.update_edge_from_observation(0xAA, 0xAA, 0xBB, -70, 8, 0, EdgeSource::Reported, 1);
        let downstream = DownstreamTable::new();
        let route = calculate_route(&edges, &downstream, 0xAA, 0xBB, 0, None);
        assert_eq!(route.next_hop, 0xBB);
        assert_eq!(route.egress_radio, 1);
    }

    #[test]
    fn two_hop_route_via_intermediate() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 0);
        edges.update_edge(0xAA, 0xAA, 0xBB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(0xAA, 0xBB, 0xCC, 2.0, 0, EdgeSource::Mirrored, true, 0);
        let downstream = DownstreamTable::new();
        let route = calculate_route(&edges, &downstream, 0xAA, 0xCC, 0, None);
        assert_eq!(route.next_hop, 0xBB);
    }

    #[test]
    fn better_neighbor_beats_expensive_route() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 0);
        edges.update_edge(0xAA, 0xAA, 0xBB, 4.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(0xAA, 0xBB, 0xDD, 4.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(0xAA, 0xAA, 0xCC, 2.0, 0, EdgeSource::Reported, true, 1);
        edges.update_edge(0xAA, 0xCC, 0xDD, 2.0, 0, EdgeSource::Mirrored, true, 1);
        assert_eq!(
            find_better_positioned_neighbor(
                &edges,
                &CapabilityCache::new(),
                0xAA,
                DEVICE_ROLE_CLIENT,
                0xDD,
                0,
                0,
                8.0,
            ),
            0xCC
        );
    }

    #[test]
    fn better_neighbor_skips_source_and_heard_from() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 0);
        edges.update_edge(0xAA, 0xAA, 0xBB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(0xAA, 0xAA, 0xCC, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(0xAA, 0xBB, 0xDD, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(0xAA, 0xCC, 0xDD, 2.0, 0, EdgeSource::Mirrored, true, 0);
        assert_eq!(
            find_better_positioned_neighbor(
                &edges,
                &CapabilityCache::new(),
                0xAA,
                DEVICE_ROLE_CLIENT,
                0xDD,
                0xBB,
                0,
                8.0,
            ),
            0xCC
        );
    }

    #[test]
    fn dijkstra_skips_non_routable_intermediate() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 0);
        const M1: u32 = 0x0100_0001;
        edges.update_edge(0xAA, 0xAA, M1, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(0xAA, M1, 0xCC, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(0xAA, 0xAA, 0xBB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(0xAA, 0xBB, 0xCC, 2.0, 0, EdgeSource::Mirrored, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_role(M1, DEVICE_ROLE_CLIENT_MUTE, 0);
        let filter = RoutableFilter {
            capability: &capability,
            my_node: 0xAA,
            device_role: DEVICE_ROLE_CLIENT,
        };
        let downstream = DownstreamTable::new();
        let route = calculate_route(&edges, &downstream, 0xAA, 0xCC, 0, Some(&filter));
        assert_eq!(route.next_hop, 0xBB);
    }
}
