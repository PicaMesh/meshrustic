//! Phased broadcast relay slot scheduling (stock → SR ranked → downstream → stock coverage).

use crate::capability::{CapabilityCache, CapabilityStatus};
use crate::graph::{
    is_placeholder_node, DownstreamTable, EdgeSource, EdgeStore, MAX_EDGES_PER_NODE,
};
use crate::sr_role::role_is_mute;

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
    /// Slot holders in slot order (first `ranked_len` entries), for the log: lets two nodes'
    /// views of the same packet be compared side by side.
    pub ranked: [u32; RANKED_LOG],
    pub ranked_len: u8,
    pub reason: RelayReason,
}

/// How many slot holders the plan records for logging.
pub const RANKED_LOG: usize = 4;

/// Why the plan decided we relay (for the log; `None` when we defer).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RelayReason {
    #[default]
    None,
    /// We won a slot in the coverage ranking.
    Ranked,
    /// We are the known downstream relay for the source or destination.
    Downstream,
    /// A stock (mute or legacy) neighbour of ours is not covered by anyone ranked ahead.
    StockCoverage,
    /// Sparse mesh: we were the only candidate.
    Sparse,
    /// Unicast: we hold a slot in the cost-to-destination ranking.
    UnicastCost,
}

fn push_ranked(plan_ranked: &mut [u32; RANKED_LOG], len: &mut u8, node: u32) {
    if (*len as usize) < RANKED_LOG {
        plan_ranked[*len as usize] = node;
        *len += 1;
    }
}

#[derive(Clone, Copy)]
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
    capability.role(node_id).map(role_is_mute).unwrap_or(false)
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
        let edge = relay_edges.edges[i];
        let target = edge.to;
        if target == 0 || is_placeholder_node(target) {
            continue;
        }
        // Rank ourselves from the edges peers can see, i.e. what our topology broadcast
        // carries (Reported edges). Mirrored edges learned from relayed packets are real
        // but invisible to peers; counting them made every node rate its own coverage
        // above the others' and two nodes then both settled on the same slot.
        if relay == my_node && edge.source != EdgeSource::Reported {
            continue;
        }
        // Count nodes that can hear this relay (not our own egress set — that
        // under-counted SR peers that cover remote topology we do not hear).
        if !edge.hears_us {
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
        let coverage_n =
            get_coverage_if_relays(ctx.edges, ctx.my_node, candidate, &mut coverage_buf);
        let mut unique = [0u32; MAX_EDGES_PER_NODE];
        let mut unique_count = 0u8;
        for &node in &coverage_buf[..coverage_n as usize] {
            if !already_covered.contains(node) {
                unique[unique_count as usize] = node;
                unique_count += 1;
            }
        }
        // Zero unique coverage never wins a slot (including self). Sparse sole-candidate
        // flood and stock-trailing slots are handled after the ranking loop.
        if unique_count == 0 {
            continue;
        }

        let Some(candidate_edges) = ctx.edges.find_node(candidate) else {
            continue;
        };

        let mut total_cost = 0f32;
        let mut valid_costs = 0u8;
        for &target in &unique[..unique_count as usize] {
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

        let mut is_better = best.node_id == 0
            || tier > best.tier
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

fn build_already_covered(edges: &EdgeStore, source: u32, heard_from: u32) -> CoveredSet {
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

fn build_candidates(ctx: &BroadcastRelayContext<'_>, source: u32, heard_from: u32) -> NodeSet {
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
        if status == CapabilityStatus::SrActive
            || ctx.capability.is_immediate_relay_router(neighbor)
        {
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

/// True when a stock neighbour of ours still needs this broadcast and we are the SR candidate
/// that should provide it.
///
/// A stock node is covered if the source, the relayer we heard, or any candidate ranked ahead
/// of us (`already_covered` holds their edges) reaches it. For the rest, exactly one SR
/// candidate must relay: the one with the lowest node id among those that have an edge to it,
/// a rule every peer can evaluate identically from the reported topology. Before this, every
/// SR node next to a mute neighbour relayed every broadcast for it, in the same slot.
fn should_relay_for_stock_neighbors(
    ctx: &BroadcastRelayContext<'_>,
    source: u32,
    heard_from: u32,
    already_covered: &CoveredSet,
    peers: &NodeSet,
) -> bool {
    let mut stock = [0u32; MAX_EDGES_PER_NODE];
    let mut stock_count = 0u8;
    let Some(my_edges) = ctx.edges.find_node(ctx.my_node) else {
        return false;
    };
    for i in 0..my_edges.edge_count as usize {
        let neighbor = my_edges.edges[i].to;
        if ctx.capability.is_immediate_relay_router(neighbor) {
            // Immediate routers take their own early slot — not our coverage burden.
            continue;
        }
        if ctx.capability.status(neighbor) != CapabilityStatus::Legacy {
            continue;
        }
        // Mute legacy nodes count regardless (they never relay, so hears_us can never be
        // confirmed); relaying legacy nodes only once they proved they hear us.
        if is_non_relaying_legacy(ctx.capability, neighbor) || my_edges.edges[i].hears_us {
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

    for &stock_neighbor in &stock[..stock_count as usize] {
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
        if heard_directly || already_covered.contains(stock_neighbor) {
            continue;
        }
        if stock_owner(ctx, peers, stock_neighbor) != ctx.my_node {
            continue; // a lower-id SR peer that also reaches it takes this one
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

/// Lowest node id among us and the SR candidates that have an edge to `stock_neighbor`.
fn stock_owner(ctx: &BroadcastRelayContext<'_>, peers: &NodeSet, stock_neighbor: u32) -> u32 {
    let mut owner = ctx.my_node;
    for &peer in &peers.ids[..peers.count as usize] {
        if peer == ctx.my_node || peer >= owner {
            continue;
        }
        let reaches = ctx
            .edges
            .find_node(peer)
            .map(|n| n.find_edge(stock_neighbor).is_some())
            .unwrap_or(false);
        if reaches {
            owner = peer;
        }
    }
    owner
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
    let peers = candidates; // every SR candidate, kept for the stock-coverage tie-break
    let initial_candidates = candidates.count;
    let mut reason = RelayReason::None;
    let mut slot_delay = 0u32;
    let mut should_relay = false;
    let mut my_delay = 0u32;
    let mut ranked = [0u32; RANKED_LOG];
    let mut ranked_len = 0u8;

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
            // Stock takes the early slot — count their coverage now so we only
            // trail if we still have unique nodes after they relay.
            absorb_relay_coverage(ctx.edges, &mut already_covered, neighbor);
            push_ranked(&mut ranked, &mut ranked_len, neighbor);
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

        push_ranked(&mut ranked, &mut ranked_len, best.node_id);
        if best.node_id == ctx.my_node {
            should_relay = true;
            reason = RelayReason::Ranked;
            my_delay = slot_delay;
            break;
        }

        // Earlier-ranked peer is assumed to relay — subtract their coverage so we
        // only take a later slot when we still have unique nodes to reach.
        absorb_relay_coverage(ctx.edges, &mut already_covered, best.node_id);
        slot_delay = slot_delay.saturating_add(half);
    }

    if !should_relay {
        let relay_for_source = ctx.downstream.get_relay(source, now_ms, DOWNSTREAM_TTL_MS);
        let relay_for_dest = ctx
            .downstream
            .get_relay(broadcast_dest, now_ms, DOWNSTREAM_TTL_MS);
        if relay_for_source == Some(ctx.my_node) || relay_for_dest == Some(ctx.my_node) {
            should_relay = true;
            reason = RelayReason::Downstream;
            my_delay = slot_delay;
        }
    }

    if !should_relay
        && should_relay_for_stock_neighbors(ctx, source, heard_from, &already_covered, &peers)
    {
        should_relay = true;
        reason = RelayReason::StockCoverage;
        my_delay = slot_delay;
    }

    // Sparse mesh: only we were a candidate and ranking found no unique coverage.
    if !should_relay && initial_candidates <= 1 {
        should_relay = true;
        reason = RelayReason::Sparse;
        my_delay = slot_delay;
    }

    let slot_index = my_delay
        .checked_div(half)
        .map_or(0, |slots| slots.min(u8::MAX as u32) as u8);

    BroadcastRelayPlan {
        should_relay,
        slot_delay_ms: my_delay,
        slot_index,
        candidate_count: initial_candidates.max(1),
        ranked,
        ranked_len,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityCache;
    use crate::graph::{DownstreamTable, EdgeSource, EdgeStore};
    use crate::nodeinfo::{DEVICE_ROLE_REPEATER, DEVICE_ROLE_TRACKER};

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
    fn mute_roles_count_as_non_relaying_legacy() {
        let mut capability = CapabilityCache::new();
        capability.track_role(BB, DEVICE_ROLE_TRACKER, 0);
        assert!(is_non_relaying_legacy(&capability, BB));
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
        let plan = plan_broadcast_relay(&ctx, 0x77, A, A, 0xFFFF_FFFF, 0, 100, |_| false);
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
        // Immediate REPEATER takes the early slot; with no remaining unique coverage we defer.
        assert!(!plan.should_relay);
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
    fn repeater_neighbor_defers_like_field() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        const C: u32 = 0xC000_0003;
        const B: u32 = 0xB000_0002;
        const D: u32 = 0xD000_0004;
        edges.ensure_local_node(C, 0);
        edges.update_edge(C, C, B, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(C, C, D, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(C, B, true);
        edges.set_edge_hears_us(C, D, true);
        edges.update_edge(C, D, B, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(D, B, true);
        capability.track_role(D, DEVICE_ROLE_REPEATER, 0);
        let ctx = BroadcastRelayContext {
            my_node: C,
            edges: &edges,
            capability: &capability,
            downstream: &downstream,
        };
        let plan = plan_broadcast_relay(&ctx, 0x99, B, B, 0xFFFF_FFFF, 0, 100, |_| false);
        assert!(
            !plan.should_relay,
            "got should_relay delay={} cands={}",
            plan.slot_delay_ms, plan.candidate_count
        );
    }

    #[test]
    fn better_peer_with_unique_coverage_suppresses_us() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        const FF: u32 = 0xAA00_00FF;
        edges.ensure_local_node(ME, 0);
        // Direct: ME ↔ BB (heard_from), ME ↔ EE (SR peer).
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, EE, true);
        // Transmitter BB already covers ME's only other neighbor EE.
        edges.update_edge(ME, BB, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(BB, EE, true);
        // EE uniquely covers remote FF (we do not hear FF).
        edges.update_edge(ME, EE, BB, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, ME, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, FF, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(EE, BB, true);
        edges.set_edge_hears_us(EE, ME, true);
        edges.set_edge_hears_us(EE, FF, true);
        capability.track_topology(EE, true, 0);
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
        assert!(
            !plan.should_relay,
            "must defer when an SR peer has unique coverage and we have none"
        );
        assert!(plan.candidate_count >= 2);
    }

    #[test]
    fn self_coverage_counts_only_reported_edges_so_peers_agree_on_order() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        const FF: u32 = 0xAA00_00FF;
        const GG: u32 = 0xAA00_0011;
        const JJ: u32 = 0xAA00_0022;
        const KK: u32 = 0xAA00_0033;
        const HH1: u32 = 0xAA00_0044;
        const HH2: u32 = 0xAA00_0055;
        edges.ensure_local_node(ME, 0);
        // Direct neighbours: BB is the transmitter, EE an SR peer that hears us.
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, EE, true);
        // Our reported coverage beyond the transmitter: EE and KK.
        edges.update_edge(ME, ME, KK, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, KK, true);
        // Two mirrored edges learned from relayed packets: real, but never in our broadcast.
        edges.update_edge(ME, ME, HH1, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, ME, HH2, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.set_edge_hears_us(ME, HH1, true);
        edges.set_edge_hears_us(ME, HH2, true);
        // EE hears the transmitter too, so both candidates sit in the same bidi tier and
        // only coverage decides the order.
        edges.update_edge(ME, EE, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(EE, BB, true);
        // EE reports three neighbours that hear it.
        for n in [FF, GG, JJ] {
            edges.update_edge(ME, EE, n, 1.5, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(EE, n, true);
        }
        edges.update_edge(ME, EE, ME, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(EE, ME, true);
        capability.track_topology(EE, true, 0);
        capability.track_topology(ME, true, 0);

        // Even id: on a tie the lower id (ME) would win, so only the coverage counts decide.
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x98,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            never_transmitted,
        );
        // Counting the mirrored edges we would claim 4 unique nodes and take slot 0 while EE,
        // seeing only our 2 reported ones, ranks itself first: both in slot 0. Reported-only
        // gives us 2 against EE's 3, so EE leads and we trail in slot 1 with KK still unique.
        assert!(plan.should_relay);
        assert_eq!(plan.slot_index, 1);
        assert_eq!(plan.ranked_len, 2);
        assert_eq!(plan.ranked[0], EE);
        assert_eq!(plan.ranked[1], ME);
    }

    /// ME and a peer both neighbour a mute stock node SS that nobody upstream reaches.
    fn stock_fixture(peer: u32) -> (EdgeStore, CapabilityCache) {
        const SS: u32 = 0xDD00_00DD;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, peer, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, SS, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, peer, true);
        // BB reaches the peer directly, so neither of us has unique hears_us coverage and the
        // ranking assigns no slot: only the stock fallback can decide.
        edges.update_edge(ME, BB, peer, 2.0, 0, EdgeSource::Reported, true, 0);
        // The peer reports BB and SS as its neighbours too.
        edges.update_edge(ME, peer, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, peer, SS, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(peer, BB, true);
        capability.track_topology(peer, true, 0);
        capability.track_topology(ME, true, 0);
        capability.track_role(SS, DEVICE_ROLE_TRACKER, 0); // mute legacy
        (edges, capability)
    }

    #[test]
    fn stock_coverage_goes_to_the_lowest_id_candidate_only() {
        let downstream = DownstreamTable::new();
        // Peer id above ours: we own SS and relay.
        let (edges, capability) = stock_fixture(0xEE00_00EE);
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
        assert_eq!(plan.reason, RelayReason::StockCoverage);
        // Peer id below ours: the peer owns SS and we stay silent.
        let (edges, capability) = stock_fixture(0xAA00_00AA);
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
        assert!(
            !plan.should_relay,
            "lower-id peer that also reaches SS must take it"
        );
        assert_eq!(plan.reason, RelayReason::None);
    }

    #[test]
    fn stock_neighbour_covered_by_transmitter_needs_no_relay() {
        let downstream = DownstreamTable::new();
        let (mut edges, capability) = stock_fixture(0xEE00_00EE);
        // BB itself reaches SS.
        edges.update_edge(ME, BB, 0xDD00_00DD, 2.0, 0, EdgeSource::Reported, true, 0);
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
    }

    #[test]
    fn best_candidate_assigned_earlier_slot() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        // Not a placeholder id (0xFF00_xxxx are reserved).
        const FF: u32 = 0xAA00_00FF;
        const GG: u32 = 0xAA00_0011;
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, EE, true);
        // Transmitter already covers EE, so ME's unique coverage is only GG.
        edges.update_edge(ME, BB, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(BB, EE, true);
        edges.update_edge(ME, EE, BB, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, ME, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, FF, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(EE, BB, true);
        edges.set_edge_hears_us(EE, ME, true);
        edges.set_edge_hears_us(EE, FF, true);
        // ME also uniquely reaches GG (EE does not).
        edges.update_edge(ME, ME, GG, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, GG, true);
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
