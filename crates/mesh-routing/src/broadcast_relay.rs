//! Phased broadcast relay slot scheduling (stock → SR ranked → downstream → stock coverage).

use crate::capability::{CapabilityCache, CapabilityStatus};
use crate::graph::{is_placeholder_node, DownstreamTable, EdgeStore, MAX_EDGES_PER_NODE};
use crate::nodeinfo::{
    DEVICE_ROLE_CLIENT_HIDDEN, DEVICE_ROLE_CLIENT_MUTE, DEVICE_ROLE_LOST_AND_FOUND,
};

/// ETX above this threshold is not treated as good pre-coverage from `heard_from`.
pub const POOR_LINK_ETX_THRESHOLD: f32 = 7.0;
const BIDI_ETX_CEILING: f32 = 20.0;
const DOWNSTREAM_TTL_MS: u32 = 7_200_000;
const MAX_COVERED: usize = MAX_EDGES_PER_NODE + 8;
const MAX_CANDIDATES: usize = MAX_EDGES_PER_NODE + 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayCandidate {
    pub node_id: u32,
    pub coverage_count: u8,
    pub avg_cost_fixed: u16,
    pub tier: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BroadcastRelayPlan {
    pub should_relay: bool,
    pub slot_delay_ms: u32,
    pub slot_index: u8,
    pub candidate_count: u8,
}

struct NodeSet {
    ids: [u32; MAX_CANDIDATES],
    count: u8,
}

impl NodeSet {
    const fn new() -> Self {
        Self {
            ids: [0; MAX_CANDIDATES],
            count: 0,
        }
    }

    fn contains(&self, node: u32) -> bool {
        self.ids[..self.count as usize].contains(&node)
    }

    fn insert(&mut self, node: u32) -> bool {
        if node == 0 || self.contains(node) {
            return false;
        }
        if (self.count as usize) >= MAX_CANDIDATES {
            return false;
        }
        self.ids[self.count as usize] = node;
        self.count += 1;
        true
    }

    fn erase(&mut self, node: u32) {
        for i in 0..self.count as usize {
            if self.ids[i] == node {
                self.ids[i] = self.ids[(self.count - 1) as usize];
                self.count -= 1;
                return;
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }
}

struct CoveredSet {
    ids: [u32; MAX_COVERED],
    count: u8,
}

impl CoveredSet {
    const fn new() -> Self {
        Self {
            ids: [0; MAX_COVERED],
            count: 0,
        }
    }

    fn contains(&self, node: u32) -> bool {
        self.ids[..self.count as usize].contains(&node)
    }

    fn insert(&mut self, node: u32) {
        if node == 0 || self.contains(node) {
            return;
        }
        if (self.count as usize) >= MAX_COVERED {
            return;
        }
        self.ids[self.count as usize] = node;
        self.count += 1;
    }
}

pub struct BroadcastRelayContext<'a> {
    pub my_node: u32,
    pub edges: &'a EdgeStore,
    pub capability: &'a CapabilityCache,
    pub downstream: &'a DownstreamTable,
}

fn is_non_relaying_legacy(capability: &CapabilityCache, node_id: u32) -> bool {
    let Some(role) = capability.role(node_id) else {
        return false;
    };
    matches!(
        role,
        DEVICE_ROLE_CLIENT_MUTE | DEVICE_ROLE_CLIENT_HIDDEN | DEVICE_ROLE_LOST_AND_FOUND
    )
}

fn we_egress_to(edges: &EdgeStore, my_node: u32, target: u32) -> bool {
    edges
        .find_node(my_node)
        .and_then(|node| node.find_edge(target))
        .map(|edge| edge.hears_us)
        .unwrap_or(false)
}

fn get_coverage_if_relays(
    edges: &EdgeStore,
    my_node: u32,
    relay: u32,
    out: &mut [u32; MAX_EDGES_PER_NODE],
) -> u8 {
    let Some(relay_edges) = edges.find_node(relay) else {
        return 0;
    };
    let mut count = 0u8;
    for i in 0..relay_edges.edge_count as usize {
        let target = relay_edges.edges[i].to;
        if target == 0 || is_placeholder_node(target) {
            continue;
        }
        if !we_egress_to(edges, my_node, target) {
            continue;
        }
        if (count as usize) < MAX_EDGES_PER_NODE {
            out[count as usize] = target;
            count += 1;
        }
    }
    count
}

fn absorb_relay_coverage(edges: &EdgeStore, covered: &mut CoveredSet, relay: u32) {
    covered.insert(relay);
    let Some(relay_edges) = edges.find_node(relay) else {
        return;
    };
    for i in 0..relay_edges.edge_count as usize {
        covered.insert(relay_edges.edges[i].to);
    }
}

fn find_best_relay_candidate<F>(
    ctx: &BroadcastRelayContext<'_>,
    candidates: &NodeSet,
    already_covered: &CoveredSet,
    prefer_high_node_id: bool,
    source_node: u32,
    has_transmitted: F,
) -> RelayCandidate
where
    F: Fn(u32) -> bool,
{
    let mut best = RelayCandidate::default();

    for i in 0..candidates.count as usize {
        let candidate = candidates.ids[i];
        if has_transmitted(candidate) {
            continue;
        }

        let mut coverage_buf = [0u32; MAX_EDGES_PER_NODE];
        let coverage_n = get_coverage_if_relays(ctx.edges, ctx.my_node, candidate, &mut coverage_buf);
        let mut unique = [0u32; MAX_EDGES_PER_NODE];
        let mut unique_count = 0u8;
        for j in 0..coverage_n as usize {
            let node = coverage_buf[j];
            if !already_covered.contains(node) {
                unique[unique_count as usize] = node;
                unique_count += 1;
            }
        }
        if unique_count == 0 && candidate != ctx.my_node {
            continue;
        }

        let Some(candidate_edges) = ctx.edges.find_node(candidate) else {
            continue;
        };

        let mut total_cost = 0f32;
        let mut valid_costs = 0u8;
        for j in 0..unique_count as usize {
            let target = unique[j as usize];
            if let Some(edge) = candidate_edges.find_edge(target) {
                total_cost += edge.etx();
                valid_costs += 1;
            }
        }
        if unique_count > 0 && valid_costs == 0 {
            continue;
        }

        let avg_cost_fixed = if valid_costs > 0 {
            (total_cost / valid_costs as f32 * 100.0) as u16
        } else {
            0
        };
        let mut tier = 0u8;
        if source_node != 0 {
            if let Some(edge) = candidate_edges.find_edge(source_node) {
                if edge.hears_us && edge.etx() < BIDI_ETX_CEILING {
                    tier = 1;
                }
            }
        }

        let mut is_better = tier > best.tier
            || (tier == best.tier && unique_count > best.coverage_count)
            || (tier == best.tier
                && unique_count == best.coverage_count
                && avg_cost_fixed < best.avg_cost_fixed);
        if !is_better
            && best.node_id != 0
            && tier == best.tier
            && unique_count == best.coverage_count
            && avg_cost_fixed == best.avg_cost_fixed
        {
            is_better = if prefer_high_node_id {
                candidate > best.node_id
            } else {
                candidate < best.node_id
            };
        }
        if is_better {
            best = RelayCandidate {
                node_id: candidate,
                coverage_count: unique_count,
                avg_cost_fixed,
                tier,
            };
        }
    }

    best
}

fn build_already_covered(
    edges: &EdgeStore,
    source: u32,
    heard_from: u32,
) -> CoveredSet {
    let mut covered = CoveredSet::new();
    covered.insert(source);
    covered.insert(heard_from);
    if let Some(heard_edges) = edges.find_node(heard_from) {
        for i in 0..heard_edges.edge_count as usize {
            let edge = heard_edges.edges[i];
            if edge.to != 0 && edge.etx() < POOR_LINK_ETX_THRESHOLD {
                covered.insert(edge.to);
            }
        }
    }
    covered
}

fn build_candidates(
    ctx: &BroadcastRelayContext<'_>,
    source: u32,
    heard_from: u32,
) -> NodeSet {
    let mut candidates = NodeSet::new();
    candidates.insert(ctx.my_node);

    let Some(my_edges) = ctx.edges.find_node(ctx.my_node) else {
        return candidates;
    };

    for i in 0..my_edges.edge_count as usize {
        let edge = my_edges.edges[i];
        let neighbor = edge.to;
        if neighbor == 0 || neighbor == heard_from || neighbor == source || !edge.hears_us {
            continue;
        }
        let status = ctx.capability.status(neighbor);
        if status == CapabilityStatus::SrActive || ctx.capability.is_immediate_relay_router(neighbor) {
            candidates.insert(neighbor);
        }
    }

    for i in 0..my_edges.edge_count as usize {
        let edge = my_edges.edges[i];
        let neighbor = edge.to;
        if neighbor == 0 || neighbor == heard_from || neighbor == source || !edge.hears_us {
            continue;
        }
        if ctx.capability.status(neighbor) != CapabilityStatus::SrActive {
            continue;
        }
        let Some(neighbor_edges) = ctx.edges.find_node(neighbor) else {
            continue;
        };
        for j in 0..neighbor_edges.edge_count as usize {
            if neighbor_edges.edges[j].to == heard_from {
                candidates.insert(neighbor);
                break;
            }
        }
    }

    candidates
}

fn stock_can_hear_transmitter(edges: &EdgeStore, stock: u32, heard_from: u32) -> bool {
    edges
        .find_node(stock)
        .and_then(|node| node.find_edge(heard_from))
        .is_some()
}

fn should_relay_for_stock_neighbors(
    ctx: &BroadcastRelayContext<'_>,
    source: u32,
    heard_from: u32,
) -> bool {
    let mut stock = [0u32; MAX_EDGES_PER_NODE];
    let mut stock_count = 0u8;
    let Some(my_edges) = ctx.edges.find_node(ctx.my_node) else {
        return false;
    };
    for i in 0..my_edges.edge_count as usize {
        let neighbor = my_edges.edges[i].to;
        if ctx.capability.status(neighbor) != CapabilityStatus::Legacy {
            continue;
        }
        if is_non_relaying_legacy(ctx.capability, neighbor) {
            stock[stock_count as usize] = neighbor;
            stock_count += 1;
        } else if my_edges.edges[i].hears_us {
            stock[stock_count as usize] = neighbor;
            stock_count += 1;
        }
    }
    if stock_count == 0 {
        return false;
    }

    let mut has_uncovered = false;
    let mut best_neighbor = 0u32;
    let mut best_cost = f32::MAX;

    for i in 0..stock_count as usize {
        let stock_neighbor = stock[i as usize];
        if stock_neighbor == heard_from || stock_neighbor == source {
            continue;
        }
        let mut heard_directly = false;
        if let Some(source_edges) = ctx.edges.find_node(source) {
            for j in 0..source_edges.edge_count as usize {
                if source_edges.edges[j].to == stock_neighbor {
                    heard_directly = true;
                    break;
                }
            }
        }
        if !heard_directly {
            if let Some(heard_edges) = ctx.edges.find_node(heard_from) {
                for j in 0..heard_edges.edge_count as usize {
                    if heard_edges.edges[j].to == stock_neighbor {
                        heard_directly = true;
                        break;
                    }
                }
            }
        }
        if heard_directly {
            continue;
        }
        has_uncovered = true;
        if let Some(edge) = my_edges.find_edge(stock_neighbor) {
            let cost = edge.etx();
            if cost < best_cost {
                best_cost = cost;
                best_neighbor = stock_neighbor;
            }
        }
    }

    has_uncovered && best_neighbor != 0
}

pub fn plan_broadcast_relay<F>(
    ctx: &BroadcastRelayContext<'_>,
    packet_id: u32,
    source: u32,
    heard_from: u32,
    broadcast_dest: u32,
    now_ms: u32,
    half_airtime_ms: u32,
    has_transmitted: F,
) -> BroadcastRelayPlan
where
    F: Fn(u32) -> bool,
{
    let half = half_airtime_ms.max(50);
    let prefer_high = (packet_id & 1) != 0;
    let mut already_covered = build_already_covered(ctx.edges, source, heard_from);
    let mut candidates = build_candidates(ctx, source, heard_from);
    let initial_candidates = candidates.count;
    let mut slot_delay = 0u32;
    let mut should_relay = false;
    let mut my_delay = 0u32;

    if let Some(my_edges) = ctx.edges.find_node(ctx.my_node) {
        for i in 0..my_edges.edge_count as usize {
            let neighbor = my_edges.edges[i].to;
            if neighbor == 0 || neighbor == heard_from || neighbor == source {
                continue;
            }
            if !ctx.capability.is_immediate_relay_router(neighbor) {
                continue;
            }
            if !stock_can_hear_transmitter(ctx.edges, neighbor, heard_from) {
                candidates.erase(neighbor);
                continue;
            }
            candidates.erase(neighbor);
            if has_transmitted(neighbor) {
                absorb_relay_coverage(ctx.edges, &mut already_covered, neighbor);
            }
            slot_delay = slot_delay.saturating_add(half);
        }
    }

    while !candidates.is_empty() {
        let best = find_best_relay_candidate(
            ctx,
            &candidates,
            &already_covered,
            prefer_high,
            source,
            &has_transmitted,
        );
        if best.node_id == 0 {
            break;
        }
        candidates.erase(best.node_id);

        if has_transmitted(best.node_id) {
            absorb_relay_coverage(ctx.edges, &mut already_covered, best.node_id);
            continue;
        }

        if best.node_id == ctx.my_node {
            should_relay = true;
            my_delay = slot_delay;
            break;
        }

        slot_delay = slot_delay.saturating_add(half);
    }

    if !should_relay {
        let relay_for_source = ctx.downstream.get_relay(source, now_ms, DOWNSTREAM_TTL_MS);
        let relay_for_dest = ctx.downstream.get_relay(broadcast_dest, now_ms, DOWNSTREAM_TTL_MS);
        if relay_for_source == Some(ctx.my_node) || relay_for_dest == Some(ctx.my_node) {
            should_relay = true;
            my_delay = slot_delay;
        }
    }

    if !should_relay
        && should_relay_for_stock_neighbors(ctx, source, heard_from)
    {
        should_relay = true;
        my_delay = slot_delay;
    }

    let slot_index = if half > 0 {
        (my_delay / half).min(u8::MAX as u32) as u8
    } else {
        0
    };

    BroadcastRelayPlan {
        should_relay,
        slot_delay_ms: my_delay,
        slot_index,
        candidate_count: initial_candidates.max(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityCache;
    use crate::graph::{DownstreamTable, EdgeSource, EdgeStore};
    use crate::nodeinfo::DEVICE_ROLE_REPEATER;

    const ME: u32 = 0xCC00_00CC;
    const BB: u32 = 0xBB00_00BB;
    const DD: u32 = 0xDD00_00DD;
    const EE: u32 = 0xEE00_00EE;

    fn never_transmitted(_node: u32) -> bool {
        false
    }

    fn setup_stock_topology(edges: &mut EdgeStore, capability: &mut CapabilityCache) {
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, DD, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, DD, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, BB, DD, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, DD, true);
        capability.track_role(DD, DEVICE_ROLE_REPEATER, 0);
    }

    fn ctx<'a>(
        edges: &'a EdgeStore,
        capability: &'a CapabilityCache,
        downstream: &'a DownstreamTable,
    ) -> BroadcastRelayContext<'a> {
        BroadcastRelayContext {
            my_node: ME,
            edges,
            capability,
            downstream,
        }
    }

    #[test]
    fn relay_when_sole_candidate_without_egress_neighbors() {
        const A: u32 = 0xA000_0001;
        let mut edges = EdgeStore::new();
        let capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, A, 2.0, 0, EdgeSource::Reported, true, 0);
        let ctx = ctx(&edges, &capability, &downstream);
        let plan = plan_broadcast_relay(
            &ctx,
            0x77,
            A,
            A,
            0xFFFF_FFFF,
            0,
            100,
            |_| false,
        );
        assert!(plan.should_relay);
    }

    #[test]
    fn relay_candidates_require_hears_us() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        capability.track_topology(EE, true, 0);
        let relay_ctx = ctx(&edges, &capability, &downstream);
        let candidates = build_candidates(&relay_ctx, 0x99, BB);
        assert!(!candidates.contains(EE));
        edges.set_edge_hears_us(ME, EE, true);
        let relay_ctx = ctx(&edges, &capability, &downstream);
        let candidates = build_candidates(&relay_ctx, 0x99, BB);
        assert!(candidates.contains(EE));
    }

    #[test]
    fn stock_router_gets_first_slot() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        setup_stock_topology(&mut edges, &mut capability);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            never_transmitted,
        );
        assert!(!plan.should_relay);
        assert_eq!(plan.slot_delay_ms, 0);
    }

    #[test]
    fn poor_etx_neighbor_not_precovered() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let _downstream = DownstreamTable::new();
        setup_stock_topology(&mut edges, &mut capability);
        edges.update_edge(ME, BB, ME, 10.0, 0, EdgeSource::Reported, true, 0);
        let covered = build_already_covered(&edges, BB, BB);
        assert!(!covered.contains(ME));
    }

    #[test]
    fn we_relay_when_downstream_relay_for_source() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let mut downstream = DownstreamTable::new();
        setup_stock_topology(&mut edges, &mut capability);
        downstream.update(ME, BB, ME, 1.0, 0, false, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            never_transmitted,
        );
        assert!(plan.should_relay);
    }

    #[test]
    fn best_candidate_assigned_earlier_slot() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, EE, true);
        edges.update_edge(ME, EE, BB, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, ME, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, 0xFF00_00FF, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, 0xFF00_00FF, 2.0, 0, EdgeSource::Reported, true, 0);
        capability.track_topology(EE, true, 0);
        capability.track_topology(ME, true, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            never_transmitted,
        );
        assert!(plan.should_relay);
        assert_eq!(plan.slot_delay_ms, 100);
        assert_eq!(plan.slot_index, 1);
    }
}
