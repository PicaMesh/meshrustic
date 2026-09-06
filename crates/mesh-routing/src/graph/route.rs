//! Dijkstra routing and route cache over the edge graph.

use mesh_radio::RadioId;

use super::is_placeholder_node;
use super::{DownstreamTable, EdgeStore, MAX_GRAPH_NODES};
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
        // SR-passive nodes broadcast topology but never relay: routing through one is a dead end.
        CapabilityStatus::Passive => false,
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
    /// Hops on the path, 1 for a direct neighbour; 0 when the route came from the downstream
    /// table (length unknown) or there is none.
    pub hops: u8,
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

impl Default for RouteCache {
    fn default() -> Self {
        Self::new()
    }
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
                    hops: 0,
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
    if let Some(i) = nodes[..*node_count].iter().position(|n| n.id == id) {
        return Some(i);
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
    nodes[..node_count]
        .iter()
        .find(|n| n.id == id)
        .map_or(0, |n| n.prev)
}

/// Can a frame transmitted by `from` be received by `to`? An edge records hearing: `from`
/// listing `to` says `from` hears `to`. The reverse is known only when that edge carries
/// `hears_us` (`to` confirmed it hears `from`) or `to` itself lists `from`. A node that
/// publishes topology and confirms neither does not hear `from`; a node that publishes none
/// (stock, or not yet classified) cannot be ruled out.
pub fn can_deliver(
    edges: &EdgeStore,
    capability: Option<&CapabilityCache>,
    from: u32,
    to: u32,
) -> bool {
    if edges
        .find_node(from)
        .and_then(|n| n.find_edge(to))
        .is_some_and(|e| e.hears_us)
    {
        return true;
    }
    if edges
        .find_node(to)
        .and_then(|n| n.find_edge(from))
        .is_some()
    {
        return true;
    }
    !publishes_topology(capability, to)
}

/// Does `node` broadcast neighbour lists (SR active or passive)? Then its list is the
/// authoritative set of nodes that can deliver to it, and a missing entry means "does not hear".
pub fn publishes_topology(capability: Option<&CapabilityCache>, node: u32) -> bool {
    matches!(
        capability.map(|c| c.status(node)),
        Some(CapabilityStatus::SrActive) | Some(CapabilityStatus::Passive)
    )
}

/// Lower `cost[m]` to `cost + edge_cost` with `via` as the next hop toward the destination.
fn relax(
    nodes: &mut [DNode; MAX_GRAPH_NODES],
    node_count: &mut usize,
    m: u32,
    via: u32,
    cost: u16,
    edge_cost: u16,
) {
    let Some(m_idx) = find_or_add_node(m, nodes, node_count) else {
        return;
    };
    if nodes[m_idx].visited {
        return;
    }
    let new_cost = cost.saturating_add(edge_cost).min(0xFFFE);
    if new_cost < nodes[m_idx].cost {
        nodes[m_idx].cost = new_cost;
        nodes[m_idx].prev = via;
    }
}

/// Route from `my_node` to `destination`: a Dijkstra search run backwards from the
/// destination over "who hears whom". A settled node N is reached by the nodes that can deliver
/// to it: the nodes N lists (N hears them, priced at the cost N measured on their signal), the
/// nodes whose edge to N carries `hears_us` (N confirmed it hears them), and, when N publishes
/// no topology, anyone who hears N (assumed symmetric, since nothing better is known). An edge
/// alone is therefore never used against its direction, and every hop is priced at its receiver.
/// Intermediate hops must pass `is_node_routable`; the destination and we ourselves need not.
pub fn calculate_route(
    edges: &EdgeStore,
    downstream: &DownstreamTable,
    my_node: u32,
    destination: u32,
    now_ms: u32,
    routable: Option<&RoutableFilter<'_>>,
) -> Route {
    let capability = routable.map(|f| f.capability);
    let mut result = Route {
        destination,
        next_hop: 0,
        egress_radio: 0,
        cost_fixed: ROUTE_COST_UNKNOWN,
        timestamp_ms: now_ms,
        hops: 0,
    };
    if my_node == 0 || destination == 0 || destination == my_node {
        return result;
    }

    // `cost` is the cost of the path from a node to the destination; `prev` is the node after it
    // on that path.
    let mut nodes = [DNode {
        id: 0,
        cost: ROUTE_COST_UNKNOWN,
        prev: 0,
        visited: false,
    }; MAX_GRAPH_NODES];
    let mut node_count = 0usize;
    let Some(dst_idx) = find_or_add_node(destination, &mut nodes, &mut node_count) else {
        return result;
    };
    nodes[dst_idx].cost = 0;

    loop {
        let mut u_idx = None;
        let mut u_cost = ROUTE_COST_UNKNOWN;
        for (i, node) in nodes[..node_count].iter().enumerate() {
            if !node.visited && node.cost < u_cost {
                u_cost = node.cost;
                u_idx = Some(i);
            }
        }
        let Some(u_idx) = u_idx else {
            break;
        };
        if u_cost == ROUTE_COST_UNKNOWN {
            break;
        }
        let n = nodes[u_idx].id;
        nodes[u_idx].visited = true;
        if n == my_node {
            break;
        }
        // Every settled node other than the destination would relay on this path.
        if n != destination {
            if let Some(filter) = routable {
                if !is_node_routable(filter, n) {
                    continue;
                }
            }
        }

        // The nodes N hears, at the cost N measured on their signal: the true cost of M -> N.
        if let Some(n_edges) = edges.find_node(n) {
            for e in 0..n_edges.edge_count as usize {
                let edge = n_edges.edges[e];
                relax(
                    &mut nodes,
                    &mut node_count,
                    edge.to,
                    n,
                    u_cost,
                    edge.etx_fixed,
                );
            }
        }
        // Nodes N confirmed hearing (`hears_us` on their edge to N), and, for a node without
        // lists, anyone hearing N. Priced at the sender's measurement of N, the best available.
        let n_publishes = publishes_topology(capability, n);
        for i in 0..edges.node_count() {
            let Some(m) = edges.node_id_at(i) else {
                continue;
            };
            if m == n {
                continue;
            }
            let listed_by_n = edges.find_node(n).and_then(|ne| ne.find_edge(m)).is_some();
            if listed_by_n {
                continue;
            }
            let Some(edge) = edges.find_node(m).and_then(|me| me.find_edge(n)) else {
                continue;
            };
            if edge.hears_us || !n_publishes {
                relax(&mut nodes, &mut node_count, m, n, u_cost, edge.etx_fixed);
            }
        }
    }

    if let Some(me) = nodes[..node_count].iter().find(|x| x.id == my_node) {
        if me.cost < ROUTE_COST_UNKNOWN && me.prev != 0 {
            result.cost_fixed = me.cost;
            result.next_hop = me.prev;
            let mut cur = me.prev;
            let mut hops = 1u8;
            while cur != destination && cur != 0 && (hops as usize) < MAX_GRAPH_NODES {
                cur = prev_of(&nodes, node_count, cur);
                hops = hops.saturating_add(1);
            }
            result.hops = hops;
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
            if neighbor_edges.edges[j].to != destination
                || !can_deliver(edges, Some(capability), neighbor, destination)
            {
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
    use crate::graph::{DownstreamTable, EdgeSource, EdgeStore};
    use crate::nodeinfo::{DEVICE_ROLE_CLIENT, DEVICE_ROLE_CLIENT_MUTE};

    #[test]
    fn direct_neighbor_is_next_hop() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 0);
        edges.update_edge_from_observation(0xAA, 0xAA, 0xBB, -70, 8, 0, EdgeSource::Reported, 1);
        let downstream = DownstreamTable::new();
        let route = calculate_route(&edges, &downstream, 0xAA, 0xBB, 0, None);
        assert_eq!(route.next_hop, 0xBB);
        assert_eq!(route.egress_radio, 1);
        assert_eq!(route.hops, 1);
    }

    /// 2026-09-06 17:31: MR22 hears FCM6 at -108 dBm and lists it without hearsUs; FCM6's own
    /// list has no MR22. Both nicenanos still routed "to FCM6 via MR22". An edge says who hears
    /// whom in one direction only; forwarding needs the other one.
    #[test]
    fn one_way_edge_is_not_a_route() {
        const ME: u32 = 0xAA;
        const RELAY: u32 = 0xBB;
        const DEST: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, RELAY, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, RELAY, true);
        // The relay hears the destination; nothing says the destination hears the relay.
        edges.update_edge(ME, RELAY, DEST, 4.0, 0, EdgeSource::Mirrored, true, 0);
        let downstream = DownstreamTable::new();
        let mut capability = CapabilityCache::new();
        capability.track_topology(RELAY, true, 0);
        capability.track_topology(DEST, true, 0);
        let filter = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
        };
        assert_eq!(
            calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter)).next_hop,
            0,
            "a topology-publishing destination that never confirmed the relay is unreachable"
        );
        // A destination that publishes no topology cannot be ruled out.
        let mut stock = CapabilityCache::new();
        stock.track_topology(RELAY, true, 0);
        let stock_filter = RoutableFilter {
            capability: &stock,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
        };
        assert_eq!(
            calculate_route(&edges, &downstream, ME, DEST, 0, Some(&stock_filter)).next_hop,
            RELAY
        );
        // The destination confirms it hears the relay: the route is back.
        edges.set_edge_hears_us(RELAY, DEST, true);
        assert_eq!(
            calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter)).next_hop,
            RELAY
        );
        // The same for our own direct link: a neighbour that does not hear us is no next hop.
        edges.update_edge(ME, ME, DEST, 1.0, 0, EdgeSource::Reported, true, 0);
        assert_eq!(
            calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter)).next_hop,
            RELAY,
            "heard but not hearing us: go through the relay it confirmed"
        );
        edges.set_edge_hears_us(ME, DEST, true);
        assert_eq!(
            calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter)).next_hop,
            DEST
        );
    }

    /// Costs are what the receiver of each hop measured: R hears us at ETX 3 and the destination
    /// hears R at ETX 2, however good R's signal looks to us.
    #[test]
    fn route_cost_is_measured_at_the_receiver() {
        const ME: u32 = 0xAA;
        const RELAY: u32 = 0xBB;
        const DEST: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, RELAY, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, RELAY, ME, 3.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, RELAY, DEST, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, DEST, RELAY, 2.0, 0, EdgeSource::Mirrored, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(RELAY, true, 0);
        capability.track_topology(DEST, true, 0);
        let filter = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
        };
        let route = calculate_route(&edges, &DownstreamTable::new(), ME, DEST, 0, Some(&filter));
        assert_eq!(route.next_hop, RELAY);
        assert_eq!(
            route.cost_fixed, 500,
            "3.0 into the relay plus 2.0 into the destination"
        );
        assert_eq!(route.hops, 2);
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
    fn passive_sr_node_is_not_routable_but_stays_reachable_as_destination() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 0);
        const P: u32 = 0x0200_0002;
        edges.update_edge(0xAA, 0xAA, P, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(0xAA, P, 0xCC, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(0xAA, 0xAA, 0xBB, 3.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(0xAA, 0xBB, 0xCC, 3.0, 0, EdgeSource::Mirrored, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(P, false, 0); // passive: sends topology, never relays
        edges.set_edge_hears_us(0xAA, P, true); // its list names us: it hears us
        let filter = RoutableFilter {
            capability: &capability,
            my_node: 0xAA,
            device_role: DEVICE_ROLE_CLIENT,
        };
        assert!(!is_node_routable(&filter, P));
        let downstream = DownstreamTable::new();
        // Cheaper path via the passive node must be rejected in favour of the relaying one.
        let route = calculate_route(&edges, &downstream, 0xAA, 0xCC, 0, Some(&filter));
        assert_eq!(route.next_hop, 0xBB);
        // The passive node itself is still a valid destination.
        let to_p = calculate_route(&edges, &downstream, 0xAA, P, 0, Some(&filter));
        assert_eq!(to_p.next_hop, P);
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
