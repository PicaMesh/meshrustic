use mesh_radio::RadioId;

use super::edge::{effective_variance_byte, Edge, EdgeSource};
use super::is_placeholder_node;
use super::{DownstreamTable, EdgeStore, MAX_GRAPH_NODES};
use crate::capability::{CapabilityCache, CapabilityStatus};
use crate::neighbor_graph::TOPOLOGY_BROADCAST_MS;
use crate::nodeinfo::DEVICE_ROLE_CLIENT_MUTE;

pub const MAX_CACHED_ROUTES: usize = 32;
pub const ROUTE_CACHE_TIMEOUT_MS: u32 = 300_000;
pub const ROUTE_COST_UNKNOWN: u16 = 0xFFFF;

pub struct RoutableFilter<'a> {
    pub capability: &'a CapabilityCache,
    pub my_node: u32,
    pub device_role: u32,
    pub excluded: &'a [u32],
}

pub fn is_node_routable(filter: &RoutableFilter<'_>, node_id: u32) -> bool {
    if node_id == 0 {
        return false;
    }
    if filter.excluded.contains(&node_id) {
        return false;
    }
    if filter.device_role == DEVICE_ROLE_CLIENT_MUTE && node_id == filter.my_node {
        return false;
    }
    match filter.capability.status(node_id) {
        CapabilityStatus::Legacy => filter.capability.is_legacy_router(node_id),
        CapabilityStatus::Passive => false,
        _ => true,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RouteMode {
    #[default]
    Ball = 0,
    ListDownstream = 1,
    OrphanGateway = 2,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Route {
    pub destination: u32,
    pub next_hop: u32,
    pub egress_radio: RadioId,
    pub cost_fixed: u16,
    pub timestamp_ms: u32,
    pub hops: u8,
    pub verified: bool,
    pub mode: RouteMode,
}

pub const UNVERIFIED_HOP_COST_FACTOR: u16 = 4;

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
                    verified: true,
                    mode: RouteMode::Ball,
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
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .max_by_key(|(_, entry)| route.timestamp_ms.wrapping_sub(entry.route.timestamp_ms))
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.entries[oldest].route = route;
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

/// Silence proves a missing link only when the peer promises to publish its neighbours.
pub fn can_deliver(
    edges: &EdgeStore,
    capability: Option<&CapabilityCache>,
    from: u32,
    to: u32,
) -> bool {
    if known_to_hear(edges, from, to) {
        return true;
    }
    !publishes_topology(capability, to)
}

pub fn known_to_hear(edges: &EdgeStore, from: u32, to: u32) -> bool {
    if edges
        .find_node(from)
        .and_then(|n| n.find_edge(to))
        .is_some_and(|e| e.hears_us)
    {
        return true;
    }
    edges
        .find_node(to)
        .and_then(|n| n.find_edge(from))
        .is_some()
}

pub fn publishes_topology(capability: Option<&CapabilityCache>, node: u32) -> bool {
    matches!(
        capability.map(|c| c.status(node)),
        Some(CapabilityStatus::SrActive) | Some(CapabilityStatus::Passive)
    )
}

fn measured_etx(edges: &EdgeStore, node: u32, peer: u32) -> Option<u16> {
    measured_edge(edges, node, peer).map(|e| e.etx_fixed)
}

fn measured_edge(edges: &EdgeStore, node: u32, peer: u32) -> Option<&Edge> {
    edges
        .find_node(node)
        .and_then(|n| n.find_edge(peer))
        .filter(|e| e.source.is_measured())
}

/// An inferred crossing proves a path exists, but its nominal price is not a link measurement.
pub fn hop_cost_fixed(edges: &EdgeStore, from: u32, to: u32) -> Option<u16> {
    if let Some(cost) = measured_etx(edges, to, from) {
        return Some(cost);
    }
    measured_etx(edges, from, to)
}

pub fn priced_hop_cost_fixed(
    edge: &Edge,
    list_owner: u32,
    my_node: u32,
    now_ms: u32,
    unverified: bool,
) -> u16 {
    let etx = if unverified {
        edge.etx_fixed.saturating_mul(UNVERIFIED_HOP_COST_FACTOR)
    } else {
        edge.etx_fixed
    };
    let our_rx = list_owner == my_node && edge.source == EdgeSource::Reported;
    let var_byte = effective_variance_byte(edge, now_ms, TOPOLOGY_BROADCAST_MS, our_rx);
    let weight = if our_rx { 10u16 } else { 5u16 };
    etx.saturating_add(var_byte as u16 * weight).min(0xFFFE)
}

fn relax_priced(
    edges: &EdgeStore,
    my_node: u32,
    now_ms: u32,
    nodes: &mut [DNode; MAX_GRAPH_NODES],
    node_count: &mut usize,
    m: u32,
    via: u32,
    u_cost: u16,
    list_owner: u32,
    edge: &Edge,
    unverified: bool,
) {
    let mut edge_cost = priced_hop_cost_fixed(edge, list_owner, my_node, now_ms, unverified);
    if m == my_node {
        if let Some(rx) = edges
            .find_node(my_node)
            .and_then(|n| n.find_edge(via))
            .filter(|e| e.source == EdgeSource::Reported && e.last_heard_ms != 0)
        {
            edge_cost = edge_cost.max(priced_hop_cost_fixed(rx, my_node, my_node, now_ms, false));
        }
    }
    relax(nodes, node_count, m, via, u_cost, edge_cost);
}

pub fn delivery_direction_cost_fixed(
    edges: &EdgeStore,
    capability: Option<&CapabilityCache>,
    from: u32,
    to: u32,
    now_ms: u32,
    my_node: u32,
) -> Option<u16> {
    if let Some(edge) = measured_edge(edges, to, from) {
        return Some(priced_hop_cost_fixed(edge, to, my_node, now_ms, false));
    }
    let edge = measured_edge(edges, from, to)?;
    let unverified = publishes_topology(capability, to);
    Some(priced_hop_cost_fixed(
        edge, from, my_node, now_ms, unverified,
    ))
}

pub fn delivery_hop_cost_fixed(
    edges: &EdgeStore,
    capability: Option<&CapabilityCache>,
    from: u32,
    to: u32,
    now_ms: u32,
    my_node: u32,
) -> Option<u16> {
    if !can_deliver(edges, capability, from, to) {
        return None;
    }
    delivery_direction_cost_fixed(edges, capability, from, to, now_ms, my_node)
}

pub fn has_strong_hop_to(
    edges: &EdgeStore,
    capability: Option<&CapabilityCache>,
    from: u32,
    peer: u32,
    now_ms: u32,
    my_node: u32,
) -> bool {
    if peer == 0 {
        return false;
    }
    delivery_direction_cost_fixed(edges, capability, from, peer, now_ms, my_node)
        .is_some_and(|cost| cost <= COVERAGE_ETX_CEILING_FIXED)
}

pub fn has_strong_delivery_hop(
    edges: &EdgeStore,
    capability: Option<&CapabilityCache>,
    from: u32,
    dest: u32,
    now_ms: u32,
    my_node: u32,
) -> bool {
    delivery_hop_cost_fixed(edges, capability, from, dest, now_ms, my_node)
        .is_some_and(|cost| cost <= COVERAGE_ETX_CEILING_FIXED)
}

/// Cost buckets prevent tiny differences in local measurements from assigning different owners on
/// different nodes.
pub const OWNER_COST_BUCKET_FIXED: u16 = 50;

/// Only a return link the originator can hear can stop its retry ladder.
pub fn acknowledgement_price_fixed(edges: &EdgeStore, candidate: u32, source: u32) -> Option<u16> {
    if source == 0 || candidate == 0 || candidate == source {
        return None;
    }
    if is_placeholder_node(source) || is_placeholder_node(candidate) {
        return None;
    }
    let edge = edges
        .find_node(candidate)
        .and_then(|n| n.find_edge(source))
        .filter(|e| e.source.is_measured())?;
    if !edge.hears_us {
        return None;
    }
    let cost = hop_cost_fixed(edges, candidate, source).unwrap_or(edge.etx_fixed);
    if cost > COVERAGE_ETX_CEILING_FIXED {
        return None;
    }
    Some(cost)
}

/// A peer’s explicit omission is evidence against reachability; ownership must not contradict it.
pub fn coverage_owner(
    edges: &EdgeStore,
    capability: &CapabilityCache,
    me: u32,
    me_relays: bool,
    target: u32,
) -> u32 {
    if target == 0 || is_placeholder_node(target) {
        return 0;
    }
    if publishes_topology(Some(capability), target) {
        return 0;
    }
    let mut owner = 0u32;
    let mut best = (u8::MAX, u16::MAX);
    for i in 0..edges.node_count() {
        let Some(candidate) = edges.node_id_at(i) else {
            continue;
        };
        if candidate == target
            || is_placeholder_node(candidate)
            || capability
                .role(candidate)
                .is_some_and(crate::sr_role::role_is_mute)
        {
            continue;
        }
        if candidate != me && !edges.has_direct_reported_edge_to(me, candidate) {
            continue;
        }
        let Some(edge) = edges
            .find_node(candidate)
            .and_then(|n| n.find_edge(target))
            .filter(|e| e.source.is_measured())
        else {
            continue;
        };
        // Crediting an unusable link with coverage would defer delivery to a relay that cannot arrive.
        if edge.etx_fixed > COVERAGE_ETX_CEILING_FIXED {
            continue;
        }
        let tier = if candidate == me {
            if !me_relays {
                continue;
            }
            1
        } else if capability.is_immediate_relay_router(candidate) {
            0
        } else if capability.status(candidate) == CapabilityStatus::SrActive {
            1
        } else {
            continue;
        };
        let bucket = edge.etx_fixed / OWNER_COST_BUCKET_FIXED;
        let key = (tier, bucket);
        if key < best || (key == best && candidate < owner) {
            best = key;
            owner = candidate;
        }
    }
    owner
}

pub const COVERAGE_ETX_CEILING_FIXED: u16 = 700;

/// A peer’s old published edge may outlive our silence timeout; it must not resurrect coverage for a
/// vanished publisher.
pub fn is_silent_publisher(
    edges: &EdgeStore,
    capability: Option<&CapabilityCache>,
    node: u32,
    now_ms: u32,
) -> bool {
    if !publishes_topology(capability, node) {
        return false;
    }
    let Some(entry) = edges.find_node(node) else {
        return false;
    };
    let silent = now_ms.wrapping_sub(entry.last_full_update_ms);
    silent > crate::neighbor_graph::PUBLISHER_SILENCE_MS && silent < 0x8000_0000
}

/// A topology publisher’s silence about the sender is itself evidence that it does not hear that sender.
pub fn covers(edges: &EdgeStore, capability: Option<&CapabilityCache>, from: u32, to: u32) -> bool {
    let evidenced = if publishes_topology(capability, to) {
        known_to_hear(edges, from, to)
    } else {
        known_to_hear(edges, from, to)
            || edges
                .find_node(from)
                .and_then(|n| n.find_edge(to))
                .is_some()
    };
    evidenced && hop_cost_fixed(edges, from, to).is_some_and(|c| c <= COVERAGE_ETX_CEILING_FIXED)
}

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

fn backward_search(
    edges: &EdgeStore,
    my_node: u32,
    destination: u32,
    now_ms: u32,
    routable: Option<&RoutableFilter<'_>>,
    allow_unverified: bool,
) -> Option<(u16, u32, u8)> {
    let capability = routable.map(|f| f.capability);
    let mut nodes = [DNode {
        id: 0,
        cost: ROUTE_COST_UNKNOWN,
        prev: 0,
        visited: false,
    }; MAX_GRAPH_NODES];
    let mut node_count = 0usize;
    let dst_idx = find_or_add_node(destination, &mut nodes, &mut node_count)?;
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
        if n != destination {
            if let Some(filter) = routable {
                if !is_node_routable(filter, n) {
                    continue;
                }
            }
        }

        if let Some(n_edges) = edges.find_node(n) {
            for e in 0..n_edges.edge_count as usize {
                let edge = n_edges.edges[e];
                relax_priced(
                    edges,
                    my_node,
                    now_ms,
                    &mut nodes,
                    &mut node_count,
                    edge.to,
                    n,
                    u_cost,
                    n,
                    &edge,
                    false,
                );
            }
        }
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
            if !n_publishes {
                relax_priced(
                    edges,
                    my_node,
                    now_ms,
                    &mut nodes,
                    &mut node_count,
                    m,
                    n,
                    u_cost,
                    m,
                    edge,
                    false,
                );
            } else if allow_unverified {
                relax_priced(
                    edges,
                    my_node,
                    now_ms,
                    &mut nodes,
                    &mut node_count,
                    m,
                    n,
                    u_cost,
                    m,
                    edge,
                    true,
                );
            }
        }
    }

    let me = nodes[..node_count].iter().find(|x| x.id == my_node)?;
    if me.cost == ROUTE_COST_UNKNOWN || me.prev == 0 {
        return None;
    }
    let mut cur = me.prev;
    let mut hops = 1u8;
    while cur != destination && cur != 0 && (hops as usize) < MAX_GRAPH_NODES {
        cur = prev_of(&nodes, node_count, cur);
        hops = hops.saturating_add(1);
    }
    Some((me.cost, me.prev, hops))
}

fn try_compose_via_parent(
    edges: &EdgeStore,
    my_node: u32,
    parent: u32,
    hop_cost: u16,
    now_ms: u32,
    routable: Option<&RoutableFilter<'_>>,
    verified: bool,
    result: &mut Route,
) -> bool {
    if edges.find_node(parent).is_none() {
        return false;
    }
    let Some((cost_to_m, next_hop, hops)) =
        backward_search(edges, my_node, parent, now_ms, routable, false)
    else {
        return false;
    };
    if next_hop == 0 || cost_to_m >= 0xFFF0 {
        return false;
    }
    result.next_hop = next_hop;
    result.cost_fixed = cost_to_m.saturating_add(hop_cost);
    result.hops = hops.saturating_add(1);
    result.verified = verified;
    result.mode = RouteMode::ListDownstream;
    result.egress_radio = edges
        .find_node(my_node)
        .and_then(|n| n.find_edge(next_hop))
        .map(|e| e.heard_on)
        .unwrap_or(0);
    true
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
        hops: 0,
        verified: false,
        mode: RouteMode::Ball,
    };
    if my_node == 0 || destination == 0 || destination == my_node {
        return result;
    }

    let dest_in_ball = edges.find_node(destination).is_some();
    let list_ds = downstream.list_downstream(destination, now_ms, u32::MAX);
    let ds_relay = downstream.get_relay(destination, now_ms, u32::MAX);
    let skip_dijkstra_to_dest = list_ds
        .map(|(m, _)| m)
        .or(ds_relay)
        .is_some_and(|m| edges.find_node(m).is_some());

    if dest_in_ball || !skip_dijkstra_to_dest {
        if let Some((cost, next_hop, hops)) =
            backward_search(edges, my_node, destination, now_ms, routable, false)
        {
            result.cost_fixed = cost;
            result.next_hop = next_hop;
            result.hops = hops;
            result.verified = true;
            result.mode = RouteMode::Ball;
        }
    }

    if result.next_hop != 0 {
        result.egress_radio = edges
            .find_node(my_node)
            .and_then(|n| n.find_edge(result.next_hop))
            .map(|e| e.heard_on)
            .unwrap_or(0);
        return result;
    }

    if let Some((m, hop_cost)) = list_ds {
        if try_compose_via_parent(
            edges,
            my_node,
            m,
            hop_cost,
            now_ms,
            routable,
            true,
            &mut result,
        ) {
            return result;
        }
    }

    if result.next_hop == 0 {
        let parent_hint = edges
            .find_node(destination)
            .map(|n| n.parent_hint)
            .unwrap_or(0);
        if parent_hint != 0 && parent_hint != destination && parent_hint != my_node {
            if let Some(edge) = edges
                .find_node(parent_hint)
                .and_then(|n| n.find_edge(destination))
                .filter(|e| e.source.is_measured())
            {
                if try_compose_via_parent(
                    edges,
                    my_node,
                    parent_hint,
                    edge.etx_fixed,
                    now_ms,
                    routable,
                    edge.hears_us,
                    &mut result,
                ) {
                    return result;
                }
            }
        }
    }

    if result.next_hop == 0 {
        let my_edges = edges.find_node(my_node);
        let is_egress = |n: u32| {
            n != 0
                && n != my_node
                && my_edges.is_some_and(|me| me.find_edge(n).is_some())
                && !routable.is_some_and(|f| f.excluded.contains(&n))
        };
        if let Some(chain) = downstream.chain_egress(destination, now_ms, u32::MAX, is_egress) {
            let cost_to_egress = my_edges
                .and_then(|n| n.find_edge(chain.node))
                .map(|e| e.etx_fixed)
                .unwrap_or(ROUTE_COST_UNKNOWN);
            if cost_to_egress < 0xFFF0 && chain.cost_fixed < 0xFFF0 {
                result.next_hop = chain.node;
                result.cost_fixed = cost_to_egress.saturating_add(chain.cost_fixed);
                result.verified = false;
                result.mode = RouteMode::OrphanGateway;
                result.hops = chain.hops;
                result.egress_radio = my_edges
                    .and_then(|n| n.find_edge(chain.node))
                    .map(|e| e.heard_on)
                    .unwrap_or(0);
                return result;
            }
        }
    }

    if result.next_hop == 0 {
        if let Some((cost, next_hop, hops)) =
            backward_search(edges, my_node, destination, now_ms, routable, true)
        {
            result.cost_fixed = cost;
            result.next_hop = next_hop;
            result.hops = hops;
            result.verified = false;
            result.mode = RouteMode::Ball;
            result.egress_radio = edges
                .find_node(my_node)
                .and_then(|n| n.find_edge(next_hop))
                .map(|e| e.heard_on)
                .unwrap_or(0);
        }
    }

    result
}

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
        excluded: &[],
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
    use crate::graph::{DownstreamTable, EdgeSource, EdgeStore, NodeClass};
    use crate::nodeinfo::{DEVICE_ROLE_CLIENT, DEVICE_ROLE_CLIENT_MUTE};

    #[test]
    fn strong_hop_gate_uses_variance_aware_delivery_score() {
        const ME: u32 = 0xAA;
        const PEER: u32 = 0xBB;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, PEER, 5.2, 0, EdgeSource::Reported, true, 0);
        edges.find_node_mut(ME).unwrap().find_edge_mut(PEER).unwrap().etx_variance = 43;

        let scored = delivery_direction_cost_fixed(&edges, None, ME, PEER, 0, ME).unwrap();
        assert_eq!(scored, 950, "ETX 5.2 plus variance penalty 4.3");
        assert!(!has_strong_hop_to(&edges, None, ME, PEER, 0, ME));
    }

    #[test]
    fn direct_neighbor_is_next_hop() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 0);
        edges.update_edge_from_observation(
            0xAA,
            0xAA,
            0xBB,
            -70,
            8,
            0,
            EdgeSource::Reported,
            1,
            mesh_radio::MODEM_DEFAULT_PRESET,
        );
        let downstream = DownstreamTable::new();
        let route = calculate_route(&edges, &downstream, 0xAA, 0xBB, 0, None);
        assert_eq!(route.next_hop, 0xBB);
        assert_eq!(route.egress_radio, 1);
        assert_eq!(route.hops, 1);
    }

    #[test]
    fn one_way_edge_is_not_a_route() {
        const ME: u32 = 0xAA;
        const RELAY: u32 = 0xBB;
        const DEST: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, RELAY, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, RELAY, true);
        edges.update_edge(ME, RELAY, DEST, 4.0, 0, EdgeSource::Mirrored, true, 0);
        let downstream = DownstreamTable::new();
        let mut capability = CapabilityCache::new();
        capability.track_topology(RELAY, true, 0);
        capability.track_topology(DEST, true, 0);
        let filter = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &[],
        };
        let fallback = calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter));
        assert!(
            !fallback.verified,
            "a publisher that has not measured the relay has no verified route"
        );
        assert_eq!(fallback.next_hop, RELAY, "the inbound gateway still tries");
        assert_eq!(
            fallback.cost_fixed,
            (100 + 400) * UNVERIFIED_HOP_COST_FACTOR
        );
        let mut stock = CapabilityCache::new();
        stock.track_topology(RELAY, true, 0);
        let stock_filter = RoutableFilter {
            capability: &stock,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &[],
        };
        assert_eq!(
            calculate_route(&edges, &downstream, ME, DEST, 0, Some(&stock_filter)).next_hop,
            RELAY
        );
        edges.set_edge_hears_us(RELAY, DEST, true);
        let claimed = calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter));
        assert_eq!((claimed.next_hop, claimed.verified), (RELAY, false));
        assert_eq!(claimed.cost_fixed, (100 + 400) * UNVERIFIED_HOP_COST_FACTOR);
        edges.update_edge(ME, RELAY, ME, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, DEST, RELAY, 2.5, 0, EdgeSource::Mirrored, true, 0);
        let verified = calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter));
        assert_eq!((verified.next_hop, verified.verified), (RELAY, true));
        assert_eq!(verified.cost_fixed, 100 + 250);
        edges.update_edge(ME, ME, DEST, 1.0, 0, EdgeSource::Reported, true, 0);
        assert_eq!(
            calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter)).next_hop,
            RELAY,
            "heard but not measured by the destination: stay on the verified relay"
        );
        edges.set_edge_hears_us(ME, DEST, true);
        assert_eq!(
            calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter)).next_hop,
            RELAY,
            "hears_us without the destination's measurement does not beat the verified relay"
        );
        edges.update_edge(ME, DEST, ME, 1.0, 0, EdgeSource::Mirrored, true, 0);
        assert_eq!(
            calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter)).next_hop,
            DEST
        );
    }

    #[test]
    fn asymmetric_l1_routes_via_l2_hearer_not_our_rx() {
        const ME: u32 = 0xAA00_00AA;
        const A: u32 = 0xA100_00A1;
        const B: u32 = 0xB200_00B2;
        const C: u32 = 0xC300_00C3;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, A, 1.5, 0, EdgeSource::Reported, true, 0);
        assert!(
            !edges
                .find_node(ME)
                .and_then(|n| n.find_edge(A))
                .is_some_and(|e| e.hears_us),
            "premise: A does not hear us"
        );
        edges.update_edge(ME, ME, C, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, C, true);
        edges.update_edge(ME, C, ME, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, C, B, 1.5, 0, EdgeSource::Mirrored, true, 0);
        edges.set_edge_hears_us(C, B, true);
        assert!(edges.ensure_publisher(B, NodeClass::L2, C, 0, ME, &mut DownstreamTable::new(),));
        edges.update_edge(ME, B, C, 1.2, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, A, B, 2.0, 0, EdgeSource::Mirrored, true, 0);

        let mut capability = CapabilityCache::new();
        capability.track_topology(A, true, 0);
        capability.track_topology(B, true, 0);
        capability.track_topology(C, true, 0);
        let filter = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &[],
        };
        let downstream = DownstreamTable::new();

        assert!(
            edges.find_node(ME).and_then(|n| n.find_edge(A)).is_some(),
            "graph stores our RX of A"
        );
        assert!(
            edges.find_node(A).and_then(|n| n.find_edge(B)).is_some(),
            "graph stores A hearing B"
        );
        assert_eq!(
            edges.node_class(B),
            Some(NodeClass::L2),
            "B sits in the L2 ball via C"
        );
        assert!(
            !can_deliver(&edges, Some(&capability), ME, A),
            "one-way RX is not a delivery hop into a publishing A"
        );
        assert!(can_deliver(&edges, Some(&capability), B, A));
        assert!(can_deliver(&edges, Some(&capability), C, B));

        let route = calculate_route(&edges, &downstream, ME, A, 0, Some(&filter));
        assert_eq!(route.next_hop, C, "leave toward C, not A");
        assert!(route.verified, "receiver-priced path C→B→A is verified");
        assert_eq!(route.hops, 3);
        assert_eq!(route.cost_fixed, 100 + 120 + 200);
        assert_ne!(
            route.cost_fixed,
            150 * UNVERIFIED_HOP_COST_FACTOR,
            "must not be the inbound-gateway guess from our RX of A"
        );
    }

    #[test]
    fn inbound_gateway_is_the_fallback_only_without_a_confirmed_path() {
        const ME: u32 = 0xAA;
        const GATEWAY: u32 = 0xBB;
        const PASSIVE: u32 = 0x0200_0002;
        const HUB: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, GATEWAY, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, GATEWAY, true);
        edges.update_edge(ME, ME, PASSIVE, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, PASSIVE, true);
        edges.update_edge(ME, GATEWAY, HUB, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, PASSIVE, HUB, 1.0, 0, EdgeSource::Mirrored, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(GATEWAY, true, 0);
        capability.track_topology(PASSIVE, false, 0);
        capability.track_topology(HUB, true, 0);
        let filter = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &[],
        };
        let downstream = DownstreamTable::new();
        let route = calculate_route(&edges, &downstream, ME, HUB, 0, Some(&filter));
        assert_eq!(
            route.next_hop, GATEWAY,
            "the passive node never relays, the gateway tries"
        );
        assert!(!route.verified);
        assert_eq!(route.cost_fixed, (100 + 200) * UNVERIFIED_HOP_COST_FACTOR);
        assert_eq!(route.hops, 2);

        const FAR: u32 = 0xDD;
        edges.update_edge(ME, GATEWAY, ME, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, GATEWAY, FAR, 3.0, 0, EdgeSource::Mirrored, true, 0);
        edges.set_edge_hears_us(GATEWAY, FAR, true);
        edges.update_edge(ME, FAR, GATEWAY, 3.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, HUB, FAR, 3.0, 0, EdgeSource::Mirrored, true, 0);
        capability.track_topology(FAR, true, 0);
        let filter = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &[],
        };
        let route = calculate_route(&edges, &downstream, ME, HUB, 0, Some(&filter));
        assert!(route.verified);
        assert_eq!((route.next_hop, route.hops), (GATEWAY, 3));
        assert_eq!(route.cost_fixed, 100 + 300 + 300);
    }

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
            excluded: &[],
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
    fn the_destinations_measurement_beats_a_cheaper_reverse_snr() {
        const ME: u32 = 0xAA;
        const CHEAP_REVERSE: u32 = 0xBB;
        const MEASURED: u32 = 0xCC;
        const DEST: u32 = 0xDD;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, CHEAP_REVERSE, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, CHEAP_REVERSE, ME, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, ME, MEASURED, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, MEASURED, ME, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(
            ME,
            CHEAP_REVERSE,
            DEST,
            1.2,
            0,
            EdgeSource::Mirrored,
            true,
            0,
        );
        edges.set_edge_hears_us(CHEAP_REVERSE, DEST, true);
        edges.update_edge(ME, DEST, MEASURED, 2.4, 0, EdgeSource::Mirrored, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(CHEAP_REVERSE, true, 0);
        capability.track_topology(MEASURED, true, 0);
        capability.track_topology(DEST, true, 0);
        let filter = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &[],
        };
        let route = calculate_route(&edges, &DownstreamTable::new(), ME, DEST, 0, Some(&filter));
        assert_eq!(route.next_hop, MEASURED);
        assert!(route.verified);
        assert_eq!(route.cost_fixed, 100 + 240);
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
        edges.update_edge(0xAA, P, 0xAA, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(0xAA, 0xAA, 0xBB, 3.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(0xAA, 0xBB, 0xCC, 3.0, 0, EdgeSource::Mirrored, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(P, false, 0);
        edges.set_edge_hears_us(0xAA, P, true);
        let filter = RoutableFilter {
            capability: &capability,
            my_node: 0xAA,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &[],
        };
        assert!(!is_node_routable(&filter, P));
        let downstream = DownstreamTable::new();
        let route = calculate_route(&edges, &downstream, 0xAA, 0xCC, 0, Some(&filter));
        assert_eq!(route.next_hop, 0xBB);
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
            excluded: &[],
        };
        let downstream = DownstreamTable::new();
        let route = calculate_route(&edges, &downstream, 0xAA, 0xCC, 0, Some(&filter));
        assert_eq!(route.next_hop, 0xBB);
    }

    #[test]
    fn can_deliver_requires_confirmation_when_receiver_publishes_topology() {
        const TX: u32 = 0xAA;
        const RX: u32 = 0xBB;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(TX, 0);
        edges.update_edge(TX, TX, RX, 2.0, 0, EdgeSource::Reported, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(RX, true, 0);
        assert!(!can_deliver(&edges, Some(&capability), TX, RX));
        edges.set_edge_hears_us(TX, RX, true);
        assert!(can_deliver(&edges, Some(&capability), TX, RX));
        assert_eq!(
            delivery_hop_cost_fixed(&edges, Some(&capability), TX, RX, 0, TX),
            Some(200 * UNVERIFIED_HOP_COST_FACTOR),
            "the receiver publishes and has not measured this hop, so the reverse SNR is penalised"
        );
    }

    #[test]
    fn can_deliver_from_receiver_listing_and_prefers_receiver_cost() {
        const TX: u32 = 0xAA;
        const RX: u32 = 0xBB;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(TX, 0);
        edges.update_edge(TX, TX, RX, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(TX, RX, TX, 3.0, 0, EdgeSource::Mirrored, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(RX, true, 0);
        assert!(can_deliver(&edges, Some(&capability), TX, RX));
        assert_eq!(
            delivery_hop_cost_fixed(&edges, Some(&capability), TX, RX, 0, TX),
            Some(300)
        );
    }

    #[test]
    fn can_deliver_assumes_stock_receiver_hears_when_unclear() {
        const TX: u32 = 0xAA;
        const STOCK: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(TX, 0);
        edges.update_edge(TX, TX, STOCK, 2.5, 0, EdgeSource::Reported, true, 0);
        assert!(can_deliver(&edges, None, TX, STOCK));
        assert_eq!(
            delivery_hop_cost_fixed(&edges, None, TX, STOCK, 0, TX),
            Some(250)
        );
    }

    #[test]
    fn covers_requires_a_link_that_is_not_hopeless() {
        const TX: u32 = 0xAA;
        const RX: u32 = 0xBB;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        capability.track_topology(RX, true, 0);
        edges.ensure_local_node(TX, 0);
        edges.update_edge(TX, TX, RX, 40.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(TX, RX, true);
        assert!(known_to_hear(&edges, TX, RX));
        assert!(
            !covers(&edges, Some(&capability), TX, RX),
            "confirmed but hopeless is not coverage"
        );
        edges.update_edge(TX, TX, RX, 1.5, 0, EdgeSource::Reported, true, 0);
        assert!(covers(&edges, Some(&capability), TX, RX));
    }

    #[test]
    fn covers_a_silent_node_on_the_senders_own_edge() {
        const TX: u32 = 0xAA;
        const SILENT: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(TX, 0);
        edges.update_edge(TX, TX, SILENT, 2.0, 0, EdgeSource::Reported, true, 0);
        assert!(!known_to_hear(&edges, TX, SILENT));
        assert!(covers(&edges, None, TX, SILENT));
        let mut capability = CapabilityCache::new();
        capability.track_topology(SILENT, true, 0);
        assert!(
            !covers(&edges, Some(&capability), TX, SILENT),
            "a reporting node's silence about the sender counts against coverage"
        );
    }

    #[test]
    fn a_publisher_has_no_owner() {
        const ME: u32 = 0xAA;
        const PEER: u32 = 0xBB;
        const TARGET: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, PEER, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, TARGET, 2.0, 0, EdgeSource::Reported, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(PEER, true, 0);
        assert_eq!(coverage_owner(&edges, &capability, ME, true, TARGET), ME);
        capability.track_topology(TARGET, true, 0);
        assert_eq!(coverage_owner(&edges, &capability, ME, true, TARGET), 0);
    }

    #[test]
    fn only_the_confirmed_search_reports_a_verified_route() {
        const ME: u32 = 0xAA;
        const DEST: u32 = 0xCC;
        let edges = EdgeStore::new();
        let downstream = DownstreamTable::new();
        let empty = calculate_route(&edges, &downstream, ME, DEST, 0, None);
        assert_eq!(empty.next_hop, 0);
        assert!(!empty.verified, "no route at all is not a confirmed route");
    }

    #[test]
    fn a_hopeless_link_owns_nothing() {
        const ME: u32 = 0xAA;
        const PEER: u32 = 0xBB;
        const SILENT: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(PEER, true, 0);
        edges.update_edge(ME, ME, PEER, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, PEER, SILENT, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, ME, SILENT, 40.0, 0, EdgeSource::Reported, true, 0);
        assert_eq!(
            coverage_owner(&edges, &capability, ME, true, SILENT),
            PEER,
            "the sound link owns it"
        );
        edges.update_edge(ME, PEER, SILENT, 40.0, 0, EdgeSource::Mirrored, true, 0);
        assert_eq!(
            coverage_owner(&edges, &capability, ME, true, SILENT),
            0,
            "a link past the ceiling delivers nothing, so it owns nothing"
        );
    }

    #[test]
    fn known_to_hear_ignores_stock_optimism() {
        const TX: u32 = 0xAA;
        const STOCK: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(TX, 0);
        edges.update_edge(TX, TX, STOCK, 2.0, 0, EdgeSource::Reported, true, 0);
        assert!(!known_to_hear(&edges, TX, STOCK));
        assert!(can_deliver(&edges, None, TX, STOCK));
        edges.set_edge_hears_us(TX, STOCK, true);
        assert!(known_to_hear(&edges, TX, STOCK));
    }
    #[test]
    fn coverage_is_not_priced_on_a_guess() {
        const ME: u32 = 0xAA;
        const GW: u32 = 0xBB;
        const FAR: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, GW, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, GW, FAR, 1.57, 0, EdgeSource::Inferred, true, 0);
        let capability = CapabilityCache::new();

        assert_eq!(hop_cost_fixed(&edges, GW, FAR), None);
        assert!(!covers(&edges, Some(&capability), GW, FAR));
        assert_eq!(coverage_owner(&edges, &capability, ME, true, FAR), 0);

        edges.update_edge(ME, GW, FAR, 2.0, 0, EdgeSource::Mirrored, true, 0);
        assert_eq!(hop_cost_fixed(&edges, GW, FAR), Some(200));
        assert!(covers(&edges, Some(&capability), GW, FAR));
    }

    #[test]
    fn a_route_still_travels_over_a_guess() {
        const ME: u32 = 0xAA;
        const GW: u32 = 0xBB;
        const FAR: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, GW, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, GW, ME, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, GW, FAR, 1.57, 0, EdgeSource::Inferred, true, 0);
        edges.update_edge(ME, FAR, GW, 1.57, 0, EdgeSource::Inferred, true, 0);
        let downstream = DownstreamTable::new();

        let route = calculate_route(&edges, &downstream, ME, FAR, 0, None);
        assert_eq!(route.next_hop, GW, "the guessed hop still routes");
    }

    #[test]
    fn downstream_chain_appoints_the_neighbour_we_hear() {
        const ME: u32 = 0xAA;
        const HUB: u32 = 0xF6;
        const PARENT: u32 = 0x11;
        const DEST: u32 = 0x22;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, HUB, 1.2, 0, EdgeSource::Reported, true, 0);
        edges.ensure_local_node(HUB, 0);
        edges.update_edge(HUB, HUB, PARENT, 1.4, 0, EdgeSource::Reported, true, 0);
        let mut downstream = DownstreamTable::new();
        downstream.update_listed(ME, DEST, PARENT, 2.0, 0, false, 0);
        downstream.update(ME, PARENT, HUB, 2.0, 0, false, 0);
        downstream.update_listed(HUB, DEST, PARENT, 2.0, 0, false, 0);
        let route = calculate_route(&edges, &downstream, ME, DEST, 0, None);
        assert_eq!(route.next_hop, HUB);
        assert!(route.verified);
        assert_eq!(route.mode, RouteMode::ListDownstream);
        let hub = calculate_route(&edges, &downstream, HUB, DEST, 0, None);
        assert_eq!(hub.next_hop, PARENT);
    }

    #[test]
    fn orphan_via_l1_is_unverified_gateway_handoff() {
        const ME: u32 = 0xAA;
        const GW: u32 = 0xBB;
        const FAR: u32 = 0xCC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, GW, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_l1(GW);
        let mut downstream = DownstreamTable::new();
        downstream.update(ME, FAR, GW, 2.0, 0, false, 0);
        assert!(edges.find_node(FAR).is_none());
        let route = calculate_route(&edges, &downstream, ME, FAR, 0, None);
        assert_eq!(route.next_hop, GW);
        assert!(!route.verified);
        assert_eq!(route.mode, RouteMode::OrphanGateway);
    }

    #[test]
    fn l2_publisher_does_not_own_a_local_silent_neighbour() {
        const ME: u32 = 0xAA;
        const L1: u32 = 0xBB;
        const L2: u32 = 0xCC;
        const SILENT: u32 = 0xDD;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, L1, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, SILENT, 3.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, L1, L2, 1.5, 0, EdgeSource::Mirrored, true, 0);
        edges.set_edge_hears_us(L1, L2, true);
        let mut ds = DownstreamTable::new();
        edges.ensure_publisher(L2, NodeClass::L2, L1, 0, ME, &mut ds);
        edges.update_edge(ME, L2, SILENT, 1.0, 0, EdgeSource::Mirrored, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(L1, true, 0);
        capability.track_topology(L2, true, 0);
        assert_eq!(
            coverage_owner(&edges, &capability, ME, true, SILENT),
            ME,
            "an L2 list must not own a silent neighbour of ours"
        );
    }

    #[test]
    fn parent_hint_composes_when_dest_omits_parent_from_its_list() {
        const ME: u32 = 0xAA00_00AA;
        const PARENT: u32 = 0xBB00_00BB;
        const DEST: u32 = 0xCC00_00CC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, PARENT, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_l1(PARENT);
        edges.update_edge(ME, PARENT, DEST, 1.5, 0, EdgeSource::Mirrored, true, 0);
        edges.set_edge_hears_us(PARENT, DEST, true);
        assert!(edges.ensure_publisher(
            DEST,
            NodeClass::L2,
            PARENT,
            0,
            ME,
            &mut DownstreamTable::new(),
        ));
        edges.update_edge(ME, DEST, 0xDD00_00DD, 1.2, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, PARENT, ME, 1.0, 0, EdgeSource::Mirrored, true, 0);

        let mut capability = CapabilityCache::new();
        capability.track_topology(DEST, true, 0);
        capability.track_topology(PARENT, true, 0);
        let filter = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: 0,
            excluded: &[],
        };
        let downstream = DownstreamTable::new();
        assert!(downstream.get_relay(DEST, 0, u32::MAX).is_none());
        let route = calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter));
        assert_eq!(route.next_hop, PARENT);
        assert!(route.verified);
        assert_eq!(route.mode, RouteMode::ListDownstream);
        assert_eq!(route.hops, 2);
        assert_eq!(route.cost_fixed, 250);
    }

    #[test]
    fn variance_outranks_a_slightly_better_mean_when_a_neighbour_is_silent() {
        const ME: u32 = 0xAA00_00AA;
        const QUIET: u32 = 0xBB00_00BB;
        const NOISY: u32 = 0xCC00_00CC;
        const DEST: u32 = 0xDD00_00DD;
        const T: u32 = TOPOLOGY_BROADCAST_MS;
        let t0 = 10_000_000u32;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, t0);
        edges.update_edge(ME, ME, QUIET, 1.8, t0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, NOISY, 2.0, t0, EdgeSource::Reported, true, 0);
        edges
            .find_node_mut(ME)
            .unwrap()
            .find_edge_mut(QUIET)
            .unwrap()
            .last_heard_ms = t0;
        edges
            .find_node_mut(ME)
            .unwrap()
            .find_edge_mut(NOISY)
            .unwrap()
            .last_heard_ms = t0 + T;
        edges.update_edge(ME, QUIET, DEST, 1.0, t0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, NOISY, DEST, 1.2, t0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, DEST, QUIET, 1.0, t0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, DEST, NOISY, 1.2, t0, EdgeSource::Mirrored, true, 0);
        let downstream = DownstreamTable::new();
        let now = t0 + 2 * T + 1;
        let route = calculate_route(&edges, &downstream, ME, DEST, now, None);
        assert_eq!(route.next_hop, NOISY);
    }

    #[test]
    fn delivery_cost_rises_with_silence_on_our_rx_edge() {
        const ME: u32 = 0xAA00_00AA;
        const PEER: u32 = 0xBB00_00BB;
        const T: u32 = TOPOLOGY_BROADCAST_MS;
        let t0 = 5_000_000u32;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, t0);
        edges.update_edge(ME, ME, PEER, 2.0, t0, EdgeSource::Reported, true, 0);
        edges
            .find_node_mut(ME)
            .unwrap()
            .find_edge_mut(PEER)
            .unwrap()
            .last_heard_ms = t0;
        let inside = delivery_hop_cost_fixed(&edges, None, PEER, ME, t0 + T / 4, ME).unwrap();
        assert_eq!(inside, 200);
        let loud = delivery_hop_cost_fixed(&edges, None, PEER, ME, t0 + T + 1_000, ME).unwrap();
        assert!(loud > inside);
        let saturated = delivery_hop_cost_fixed(&edges, None, PEER, ME, t0 + 2 * T, ME).unwrap();
        assert!(saturated > loud);
    }

    #[test]
    fn silence_fold_keeps_scar_after_a_long_gap_packet() {
        const ME: u32 = 0xAA00_00AA;
        const PEER: u32 = 0xBB00_00BB;
        const T: u32 = TOPOLOGY_BROADCAST_MS;
        let mut graph = crate::neighbor_graph::NeighborGraph::new();
        graph.set_my_node(ME);
        let t0 = 1_000_000u32;
        graph.observe_direct_neighbor(PEER, -70, 8, t0, 0);
        let fresh = delivery_hop_cost_fixed(graph.edges(), None, PEER, ME, t0, ME).unwrap();
        graph.observe_direct_neighbor(PEER, -70, 8, t0 + 2 * T + 1, 0);
        let after =
            delivery_hop_cost_fixed(graph.edges(), None, PEER, ME, t0 + 2 * T + 1, ME).unwrap();
        assert!(after > fresh);
    }

    #[test]
    fn unverified_priced_hop_saturates_instead_of_wrapping() {
        const ME: u32 = 0xAA00_00AA;
        let edge = Edge {
            to: 0xBB00_00BB,
            etx_fixed: 20_000,
            last_update_ms: 0,
            etx_variance: 0,
            source: EdgeSource::Mirrored,
            hears_us: false,
            heard_on: 0,
            last_heard_ms: 0,
        };
        assert_eq!(
            priced_hop_cost_fixed(&edge, edge.to, ME, 0, true),
            0xFFFE,
            "etx*4 must saturate, not wrap a uint16"
        );
    }

    #[test]
    fn egress_silence_applies_only_after_we_have_heard_them() {
        const ME: u32 = 0xAA00_00AA;
        const HUB: u32 = 0xBB00_00BB;
        const DEST: u32 = 0xCC00_00CC;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, HUB, 5.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, HUB, ME, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, HUB, DEST, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, DEST, HUB, 1.0, 0, EdgeSource::Mirrored, true, 0);
        let downstream = DownstreamTable::new();
        let unheard = calculate_route(&edges, &downstream, ME, DEST, 0, None);
        assert_eq!(unheard.next_hop, HUB);
        assert_eq!(
            unheard.cost_fixed, 200,
            "a Reported edge we have never RF-heard must not replace their list of us"
        );
        edges
            .find_node_mut(ME)
            .unwrap()
            .find_edge_mut(HUB)
            .unwrap()
            .last_heard_ms = 1;
        let heard = calculate_route(&edges, &downstream, ME, DEST, 1, None);
        assert_eq!(heard.next_hop, HUB);
        assert!(heard.cost_fixed > unheard.cost_fixed);
    }

    #[test]
    fn excluded_first_hop_yields_alternate_and_skips_only_path() {
        const ME: u32 = 0xAA00_00AA;
        const HOP_A: u32 = 0xBB00_00BB;
        const HOP_B: u32 = 0xCC00_00CC;
        const DEST: u32 = 0xDD00_00DD;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, HOP_A, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, HOP_B, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, HOP_A, DEST, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, HOP_B, DEST, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, DEST, HOP_A, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, DEST, HOP_B, 1.0, 0, EdgeSource::Mirrored, true, 0);
        let mut capability = CapabilityCache::new();
        capability.track_topology(HOP_A, true, 0);
        capability.track_topology(HOP_B, true, 0);
        capability.track_topology(DEST, true, 0);
        let downstream = DownstreamTable::new();
        let filter = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &[],
        };
        let primary = calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter));
        assert_eq!(primary.next_hop, HOP_A);
        let excl = [HOP_A];
        let filter_ex = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &excl,
        };
        let alt = calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter_ex));
        assert_eq!(alt.next_hop, HOP_B);
        let excl_both = [HOP_A, HOP_B];
        let filter_none = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &excl_both,
        };
        let none = calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter_none));
        assert_eq!(none.next_hop, 0);
        let excl_dest = [DEST];
        let filter_dest = RoutableFilter {
            capability: &capability,
            my_node: ME,
            device_role: DEVICE_ROLE_CLIENT,
            excluded: &excl_dest,
        };
        let still = calculate_route(&edges, &downstream, ME, DEST, 0, Some(&filter_dest));
        assert_eq!(still.next_hop, HOP_A);
    }
}
