use crate::capability::{CapabilityCache, CapabilityStatus};
use crate::graph::{
    coverage_owner, covers, delivery_hop_cost_fixed, is_placeholder_node, is_silent_publisher,
    DownstreamTable, EdgeSource, EdgeStore, MAX_EDGES_PER_NODE,
};
use crate::rate_limit::YoungCoverageGate;

const BIDI_ETX_CEILING: f32 = 20.0;
const DOWNSTREAM_TTL_MS: u32 = crate::neighbor_graph::NEIGHBOR_TTL_MS;
const MAX_COVERED: usize = MAX_EDGES_PER_NODE + 8;
const MAX_CANDIDATES: usize = MAX_EDGES_PER_NODE + 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayCandidate {
    pub node_id: u32,
    pub coverage_count: u8,
    pub avg_cost_fixed: u16,
    pub tier: u8,
    pub role_rank: u8,
    pub coverage_for: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BroadcastRelayPlan {
    pub should_relay: bool,
    pub slot_delay_ms: u32,
    pub slot_index: u8,
    pub candidate_count: u8,
    pub ranked: [u32; RANKED_LOG],
    pub ranked_len: u8,
    pub reason: RelayReason,
    pub evaluated: [(u32, u8, u8, u16); RANKED_LOG],
    pub evaluated_len: u8,
    pub pre_covered: u8,
    pub uncovered: [u32; UNCOVERED_LOG],
    pub uncovered_len: u8,
    pub slots_given: u8,
    /// Captures need to distinguish reserved, uncoordinated routers from peers with deterministic relay
    /// slots.
    pub reserved_slots: u8,
    pub reserved_ranked: u8,
    pub absorbed: [(u32, u8); RANKED_LOG],
    pub absorbed_len: u8,
    pub coverage_for: u32,
    pub last_hop_backup: bool,
    pub nonfinal_flood: bool,
    pub has_nonfinal_flood_slot: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EvaluatedList {
    pub items: [(u32, u8, u8, u16); RANKED_LOG],
    pub len: u8,
}

pub fn push_evaluated(
    out: &mut [(u32, u8, u8, u16); RANKED_LOG],
    len: &mut u8,
    node: u32,
    coverage: u8,
    total: u8,
    cost: u16,
) {
    if (*len as usize) < RANKED_LOG {
        out[*len as usize] = (node, coverage, total, cost);
        *len += 1;
    }
}

pub const RANKED_LOG: usize = 4;
pub const UNCOVERED_LOG: usize = 6;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RelayReason {
    #[default]
    None,
    Ranked,
    Downstream,
    Sparse,
    UnicastCost,
    /// An originator awaiting delivery confirmation may retry unless it hears a rebroadcast, even when
    /// no onward coverage remains.
    Acknowledgement,
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
    pub my_node_relays: bool,
    pub edges: &'a EdgeStore,
    pub capability: &'a CapabilityCache,
    pub downstream: &'a DownstreamTable,
    pub dropped_coverage: YoungCoverageGate,
}

fn get_coverage_if_relays(
    ctx: &BroadcastRelayContext<'_>,
    relay: u32,
    now_ms: u32,
    out: &mut [u32; MAX_EDGES_PER_NODE],
) -> u8 {
    let edges = ctx.edges;
    let my_node = ctx.my_node;
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
        if relay == my_node && edge.source != EdgeSource::Reported {
            continue;
        }
        if !edge.source.is_measured() {
            continue;
        }
        if !admits_coverage(ctx, relay, target, now_ms) {
            continue;
        }
        if (count as usize) < MAX_EDGES_PER_NODE {
            out[count as usize] = target;
            count += 1;
        }
    }
    count
}

fn absorb_relay_coverage(
    ctx: &BroadcastRelayContext<'_>,
    covered: &mut CoveredSet,
    relay: u32,
    now_ms: u32,
) -> u8 {
    let before = covered.count;
    covered.insert(relay);
    let Some(relay_edges) = ctx.edges.find_node(relay) else {
        return covered.count.saturating_sub(before);
    };
    for i in 0..relay_edges.edge_count as usize {
        let edge = relay_edges.edges[i];
        if !edge.source.is_measured() {
            continue;
        }
        if admits_coverage(ctx, relay, edge.to, now_ms) {
            covered.insert(edge.to);
        }
    }
    covered.count.saturating_sub(before)
}

fn admits_coverage(ctx: &BroadcastRelayContext<'_>, relay: u32, target: u32, now_ms: u32) -> bool {
    if is_silent_publisher(ctx.edges, Some(ctx.capability), target, now_ms) {
        return false;
    }
    if ctx.dropped_coverage.blocks(target) {
        return false;
    }
    covers(ctx.edges, Some(ctx.capability), relay, target)
        || coverage_owner(
            ctx.edges,
            ctx.capability,
            ctx.my_node,
            ctx.my_node_relays,
            target,
        ) == relay
}

struct AcknowledgementPlan {
    should_relay: bool,
    my_delay: u32,
    slots_given: u8,
    ranked: [u32; RANKED_LOG],
    ranked_len: u8,
}

/// Acknowledgement ranking needs the return direction: a relay the originator cannot hear does not stop
/// retries.
fn plan_acknowledgement(
    ctx: &BroadcastRelayContext<'_>,
    packet_id: u32,
    source: u32,
    heard_from: u32,
    half: u32,
    slot_time_ms: u32,
) -> Option<AcknowledgementPlan> {
    if !ctx.my_node_relays {
        return None;
    }
    let my_edges = ctx.edges.find_node(ctx.my_node)?;

    // An unconditional relayer already supplies the acknowledgement; our copy would only duplicate it.
    for i in 0..my_edges.edge_count as usize {
        let neighbor = my_edges.edges[i].to;
        if neighbor == 0 || neighbor == source {
            continue;
        }
        if !ctx.capability.will_not_cancel_for_us(neighbor) {
            continue;
        }
        if stock_can_hear_transmitter(ctx.edges, neighbor, heard_from) {
            return None;
        }
    }

    let mut entries = [(0u32, 0u16); MAX_CANDIDATES];
    let mut count = 0usize;
    let consider = |node: u32, entries: &mut [(u32, u16); MAX_CANDIDATES], count: &mut usize| {
        if *count >= MAX_CANDIDATES || node == 0 || node == source {
            return;
        }
        if node != ctx.my_node {
            let usable = ctx.capability.status(node) == CapabilityStatus::SrActive
                || ctx.capability.is_immediate_relay_router(node);
            if !usable {
                return;
            }
        }
        if let Some(price) = crate::graph::acknowledgement_price_fixed(ctx.edges, node, source) {
            entries[*count] = (node, price);
            *count += 1;
        }
    };
    consider(ctx.my_node, &mut entries, &mut count);
    for i in 0..my_edges.edge_count as usize {
        consider(my_edges.edges[i].to, &mut entries, &mut count);
    }
    if count == 0 {
        return None;
    }

    let prefer_high = (packet_id & 1) != 0;
    let bucket = |cost: u16| cost / crate::unicast_relay::COST_BUCKET_FIXED;
    let better = |a: (u32, u16), b: (u32, u16)| {
        let (ba, bb) = (bucket(a.1), bucket(b.1));
        if ba != bb {
            return ba < bb;
        }
        if prefer_high {
            a.0 > b.0
        } else {
            a.0 < b.0
        }
    };
    for i in 1..count {
        let mut j = i;
        while j > 0 && better(entries[j], entries[j - 1]) {
            entries.swap(j, j - 1);
            j -= 1;
        }
    }

    let mut plan = AcknowledgementPlan {
        should_relay: false,
        my_delay: 0,
        slots_given: 0,
        ranked: [0; RANKED_LOG],
        ranked_len: 0,
    };
    let mut delay = crate::coordinated_relay::relay_floor_ms(slot_time_ms);
    for &(node, _) in entries.iter().take(count) {
        if (plan.ranked_len as usize) < RANKED_LOG {
            plan.ranked[plan.ranked_len as usize] = node;
            plan.ranked_len += 1;
        }
        if node == ctx.my_node {
            plan.should_relay = true;
            plan.my_delay = delay;
            break;
        }
        plan.slots_given = plan.slots_given.saturating_add(1);
        delay = delay.saturating_add(half);
    }
    if !plan.should_relay {
        return None;
    }
    Some(plan)
}

fn push_absorbed(list: &mut [(u32, u8); RANKED_LOG], len: &mut u8, relay: u32, credit: u8) {
    if (*len as usize) < RANKED_LOG {
        list[*len as usize] = (relay, credit);
        *len += 1;
    }
}

/// The ROUTER role expresses an operator preference that link cost cannot capture. Promoting ROUTER_LATE
/// would defeat its deliberate late-relay policy.
fn role_rank(ctx: &BroadcastRelayContext<'_>, candidate: u32) -> u8 {
    u8::from(may_take_early_window(ctx, candidate))
}

fn may_take_early_window(ctx: &BroadcastRelayContext<'_>, candidate: u32) -> bool {
    ctx.capability.role(candidate) == Some(crate::nodeinfo::DEVICE_ROLE_ROUTER)
}

fn find_best_relay_candidate<F>(
    ctx: &BroadcastRelayContext<'_>,
    candidates: &NodeSet,
    already_covered: &CoveredSet,
    prefer_high_node_id: bool,
    source_node: u32,
    now_ms: u32,
    has_transmitted: F,
    mut evaluated: Option<&mut EvaluatedList>,
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
        let coverage_n = get_coverage_if_relays(ctx, candidate, now_ms, &mut coverage_buf);
        let mut unique = [0u32; MAX_EDGES_PER_NODE];
        let mut unique_count = 0u8;
        for &node in &coverage_buf[..coverage_n as usize] {
            if !already_covered.contains(node) {
                unique[unique_count as usize] = node;
                unique_count += 1;
            }
        }
        if let Some(ev) = evaluated.as_deref_mut() {
            push_evaluated(
                &mut ev.items,
                &mut ev.len,
                candidate,
                unique_count,
                coverage_n,
                0,
            );
        }
        if unique_count == 0 {
            continue;
        }

        let mut total_cost = 0f32;
        let mut valid_costs = 0u8;
        for &target in &unique[..unique_count as usize] {
            if let Some(fixed) = delivery_hop_cost_fixed(
                ctx.edges,
                Some(ctx.capability),
                candidate,
                target,
                now_ms,
                ctx.my_node,
            ) {
                total_cost += fixed as f32 / 100.0;
                valid_costs += 1;
            }
        }
        debug_assert!(
            unique_count == 0 || valid_costs > 0,
            "an admitted target always has a delivery price"
        );

        let avg_cost_fixed = if valid_costs > 0 {
            let fixed = (total_cost / valid_costs as f32 * 100.0) as u16;
            fixed / crate::unicast_relay::COST_BUCKET_FIXED
                * crate::unicast_relay::COST_BUCKET_FIXED
        } else {
            0
        };
        if let Some(ev) = evaluated.as_deref_mut() {
            let n = ev.len as usize;
            if n > 0 && ev.items[n - 1].0 == candidate {
                ev.items[n - 1].3 = avg_cost_fixed;
            }
        }
        let mut tier = 0u8;
        if source_node != 0 {
            if let Some(edge) = ctx
                .edges
                .find_node(candidate)
                .and_then(|n| n.find_edge(source_node))
            {
                if edge.hears_us && edge.etx() < BIDI_ETX_CEILING {
                    tier = 1;
                }
            }
        }

        let rank = role_rank(ctx, candidate);
        let mut is_better = best.node_id == 0
            || rank > best.role_rank
            || (rank == best.role_rank && tier > best.tier)
            || (rank == best.role_rank && tier == best.tier && unique_count > best.coverage_count)
            || (rank == best.role_rank
                && tier == best.tier
                && unique_count == best.coverage_count
                && avg_cost_fixed < best.avg_cost_fixed);
        if !is_better
            && best.node_id != 0
            && rank == best.role_rank
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
                role_rank: rank,
                coverage_for: unique[0],
            };
        }
    }

    best
}

fn build_already_covered(
    edges: &EdgeStore,
    capability: &CapabilityCache,
    source: u32,
    heard_from: u32,
) -> CoveredSet {
    let mut covered = CoveredSet::new();
    covered.insert(source);
    covered.insert(heard_from);
    if let Some(heard_edges) = edges.find_node(heard_from) {
        for i in 0..heard_edges.edge_count as usize {
            let target = heard_edges.edges[i].to;
            if target != 0 && covers(edges, Some(capability), heard_from, target) {
                covered.insert(target);
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

    candidates
}

fn stock_can_hear_transmitter(edges: &EdgeStore, stock: u32, heard_from: u32) -> bool {
    edges
        .find_node(stock)
        .and_then(|node| node.find_edge(heard_from))
        .is_some()
}

pub fn plan_broadcast_relay<F>(
    ctx: &BroadcastRelayContext<'_>,
    packet_id: u32,
    source: u32,
    heard_from: u32,
    broadcast_dest: u32,
    now_ms: u32,
    half_airtime_ms: u32,
    slot_time_ms: u32,
    has_transmitted: F,
    ack_eligible: bool,
) -> BroadcastRelayPlan
where
    F: Fn(u32) -> bool,
{
    // Applying the spacing floor twice would make this schedule diverge from the shared timing
    // calculation.
    let half = half_airtime_ms.max(crate::coordinated_relay::MIN_RUNG_SPACING_MS);
    let prefer_high = (packet_id & 1) != 0;
    let mut already_covered = build_already_covered(ctx.edges, ctx.capability, source, heard_from);
    let pre_covered_count = already_covered.count;
    let mut uncovered = [0u32; UNCOVERED_LOG];
    let mut uncovered_len = 0u8;
    {
        let mut mine = [0u32; MAX_EDGES_PER_NODE];
        let n = get_coverage_if_relays(ctx, ctx.my_node, now_ms, &mut mine);
        for &target in &mine[..n as usize] {
            if !already_covered.contains(target) && (uncovered_len as usize) < UNCOVERED_LOG {
                uncovered[uncovered_len as usize] = target;
                uncovered_len += 1;
            }
        }
    }
    let mut candidates = build_candidates(ctx, source, heard_from);
    let initial_candidates = candidates.count;
    let mut reason = RelayReason::None;
    // Reservations describe an uncertain transmission; ranked rungs describe our actual send times, so
    // they require different spacing.
    let mut positions = crate::relay_window::PositionAllocator::new(slot_time_ms, half);
    let mut should_relay = false;
    let mut my_delay = 0u32;
    let mut my_slot_index = 0u8;
    let mut coverage_for = 0u32;
    let mut slots_given = 0u8;
    let mut reserved_slots = 0u8;
    let mut reserved_ranked = 0u8;
    let mut absorbed = [(0u32, 0u8); RANKED_LOG];
    let mut absorbed_len = 0u8;
    let mut ranked = [0u32; RANKED_LOG];
    let mut ranked_len = 0u8;
    let mut evaluated = EvaluatedList::default();
    let mut first_pick = true;

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
            push_ranked(&mut ranked, &mut ranked_len, neighbor);
            reserved_ranked = reserved_ranked.saturating_add(1);
            // A reservation is an expectation rather than proof of delivery; subtracting its coverage
            // before hearing it could leave the packet uncarried.
            if has_transmitted(neighbor) {
                let credit = absorb_relay_coverage(ctx, &mut already_covered, neighbor, now_ms);
                push_absorbed(&mut absorbed, &mut absorbed_len, neighbor, credit);
            } else {
                slots_given = slots_given.saturating_add(1);
                reserved_slots = reserved_slots.saturating_add(1);
            }
            positions.take_reserved();
        }
    }

    let mut late_candidates = NodeSet::new();
    {
        let mut i = 0u8;
        while i < candidates.count {
            let id = candidates.ids[i as usize];
            if may_take_early_window(ctx, id) {
                i = i.saturating_add(1);
            } else {
                candidates.erase(id);
                let _ = late_candidates.insert(id);
            }
        }
    }

    for early in [true, false] {
        if should_relay {
            break;
        }
        let pool = if early {
            &mut candidates
        } else {
            &mut late_candidates
        };
        while !pool.is_empty() {
            let best = find_best_relay_candidate(
                ctx,
                pool,
                &already_covered,
                prefer_high,
                source,
                now_ms,
                &has_transmitted,
                if first_pick {
                    Some(&mut evaluated)
                } else {
                    None
                },
            );
            first_pick = false;
            if best.node_id == 0 {
                break;
            }
            pool.erase(best.node_id);

            if has_transmitted(best.node_id) {
                let credit = absorb_relay_coverage(ctx, &mut already_covered, best.node_id, now_ms);
                push_absorbed(&mut absorbed, &mut absorbed_len, best.node_id, credit);
                continue;
            }

            push_ranked(&mut ranked, &mut ranked_len, best.node_id);
            let assigned_index = positions.next_index();
            let delay = if early {
                positions.take_rung()
            } else {
                positions.take_late_rung()
            };
            if best.node_id == ctx.my_node {
                should_relay = true;
                reason = RelayReason::Ranked;
                my_slot_index = assigned_index;
                my_delay = delay;
                coverage_for = best.coverage_for;
                break;
            }

            slots_given = slots_given.saturating_add(1);
        }
    }

    if !should_relay {
        let relay_for_source = ctx.downstream.get_relay(source, now_ms, DOWNSTREAM_TTL_MS);
        let relay_for_dest = ctx
            .downstream
            .get_relay(broadcast_dest, now_ms, DOWNSTREAM_TTL_MS);
        if relay_for_source == Some(ctx.my_node) || relay_for_dest == Some(ctx.my_node) {
            should_relay = true;
            reason = RelayReason::Downstream;
            my_slot_index = positions.next_index();
            my_delay = positions.first_free_ms();
        }
    }

    if !should_relay && initial_candidates <= 1 {
        should_relay = true;
        reason = RelayReason::Sparse;
        my_slot_index = positions.next_index();
        my_delay = positions.first_free_ms();
    }

    // Coverage ranking cannot select an acknowledgement relay when no unique target remains to price.
    if !should_relay && slots_given == 0 && ack_eligible {
        if let Some(ack) =
            plan_acknowledgement(ctx, packet_id, source, heard_from, half, slot_time_ms)
        {
            should_relay = ack.should_relay;
            reason = RelayReason::Acknowledgement;
            my_delay = ack.my_delay;
            my_slot_index = ack.slots_given;
            slots_given = ack.slots_given;
            for i in 0..ack.ranked_len {
                push_ranked(&mut ranked, &mut ranked_len, ack.ranked[i as usize]);
            }
        }
    }

    let slot_index = my_slot_index;

    BroadcastRelayPlan {
        should_relay,
        slot_delay_ms: my_delay,
        slot_index,
        candidate_count: initial_candidates.max(1),
        ranked,
        ranked_len,
        reason,
        evaluated: evaluated.items,
        evaluated_len: evaluated.len,
        pre_covered: pre_covered_count,
        uncovered,
        uncovered_len,
        coverage_for,
        slots_given,
        reserved_slots,
        reserved_ranked,
        absorbed,
        absorbed_len,
        last_hop_backup: false,
        nonfinal_flood: false,
        has_nonfinal_flood_slot: false,
    }
}

#[cfg(test)]
mod tests {
    const TEST_SLOT_MS: u32 = 10;

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
            my_node_relays: true,
            edges,
            capability,
            downstream,
            dropped_coverage: YoungCoverageGate::empty(),
        }
    }

    #[test]
    fn reservation_and_rung_are_counted_apart() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        setup_stock_topology(&mut edges, &mut capability);
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, EE, true);
        capability.track_topology(EE, true, 0);
        let ctx = ctx(&edges, &capability, &downstream);

        let plan = plan_broadcast_relay(
            &ctx,
            1,
            BB,
            BB,
            u32::MAX,
            0,
            50,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(
            plan.reserved_slots > 0,
            "the stock repeater that hears the transmitter holds a reserved position"
        );
        assert!(
            plan.slots_given >= plan.reserved_slots,
            "reservations are a subset of the transmissions we expect"
        );
        assert_eq!(
            plan.reserved_ranked as usize, 1,
            "exactly the leading order entry is the reservation"
        );
        assert_eq!(plan.ranked[0], DD, "reservations are listed before rungs");

        let plan = plan_broadcast_relay(
            &ctx,
            1,
            BB,
            BB,
            u32::MAX,
            0,
            50,
            TEST_SLOT_MS,
            |node| node == DD,
            false,
        );
        assert_eq!(
            plan.reserved_slots, 0,
            "a copy already on the air is not a transmission we are waiting for"
        );
        assert_eq!(
            plan.reserved_ranked as usize, 1,
            "but it still occupies its position in the order"
        );
    }

    #[test]
    fn somebody_answers_when_the_ladder_is_empty() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        let t0 = 1_000u32;
        edges.ensure_local_node(ME, t0);
        edges.update_edge(ME, ME, BB, 1.0, t0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 1.0, t0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, EE, true);
        edges.update_edge(ME, EE, BB, 1.0, t0, EdgeSource::Mirrored, true, 0);
        capability.track_topology(BB, true, t0);
        capability.track_topology(EE, true, t0);
        edges.update_edge(ME, BB, ME, 1.0, t0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, BB, EE, 1.0, t0, EdgeSource::Mirrored, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(EE, BB, true);

        let ctx = ctx(&edges, &capability, &downstream);

        let plan = plan_broadcast_relay(
            &ctx,
            1,
            BB,
            BB,
            u32::MAX,
            t0,
            50,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(
            !plan.should_relay,
            "with nothing unique to carry and no acknowledgement owed, we stay quiet"
        );

        let plan = plan_broadcast_relay(
            &ctx,
            1,
            BB,
            BB,
            u32::MAX,
            t0,
            50,
            TEST_SLOT_MS,
            never_transmitted,
            true,
        );
        assert_eq!(plan.reason, RelayReason::Acknowledgement);
        assert_eq!(
            plan.ranked_len, 2,
            "both candidates the source hears are ranked"
        );
        assert!(
            plan.should_relay,
            "we are one of them, so we answer at our own rung"
        );
    }

    #[test]
    fn the_source_hears_the_first_answerer_best() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        let t0 = 1_000u32;
        edges.ensure_local_node(ME, t0);
        edges.update_edge(ME, ME, BB, 6.0, t0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 1.0, t0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, EE, true);
        edges.update_edge(ME, EE, BB, 1.0, t0, EdgeSource::Mirrored, true, 0);
        capability.track_topology(BB, true, t0);
        capability.track_topology(EE, true, t0);
        edges.update_edge(ME, BB, ME, 6.0, t0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, BB, EE, 1.0, t0, EdgeSource::Mirrored, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(EE, BB, true);

        let ctx = ctx(&edges, &capability, &downstream);
        let plan = plan_broadcast_relay(
            &ctx,
            2,
            BB,
            BB,
            u32::MAX,
            t0,
            50,
            TEST_SLOT_MS,
            never_transmitted,
            true,
        );
        assert_eq!(plan.reason, RelayReason::Acknowledgement);
        assert_eq!(
            plan.ranked[0], EE,
            "the source hears the peer six times better, so the peer answers first"
        );
        assert!(plan.should_relay, "we answer too, behind it");
        assert!(
            plan.slot_delay_ms > crate::coordinated_relay::relay_floor_ms(TEST_SLOT_MS),
            "our answer waits behind its rung and cancels if that answer arrives"
        );
        assert!(
            plan.slots_given > 0,
            "a rung ahead of ours is a transmission we wait on, so T1 insures it"
        );
    }

    #[test]
    fn a_publisher_we_stopped_hearing_is_nobody_s_target() {
        const GONE: u32 = 0xDEAD_0001;
        const NEAR: u32 = 0xBEEF_0002;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        let t0 = 1_000u32;
        edges.ensure_local_node(ME, t0);
        edges.update_edge(ME, ME, NEAR, 1.0, t0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, NEAR, true);
        edges.update_edge(ME, NEAR, GONE, 2.0, t0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, GONE, NEAR, 2.0, t0, EdgeSource::Mirrored, true, 0);
        capability.track_topology(NEAR, true, t0);
        capability.track_topology(GONE, true, t0);

        let c = ctx(&edges, &capability, &downstream);
        let mut buf = [0u32; MAX_EDGES_PER_NODE];

        let inside = t0 + crate::neighbor_graph::PUBLISHER_SILENCE_MS;
        let n = get_coverage_if_relays(&c, NEAR, inside, &mut buf);
        assert!(
            buf[..n as usize].contains(&GONE),
            "still heard: the peer's published link is coverage"
        );

        let past = inside + 1;
        let n = get_coverage_if_relays(&c, NEAR, past, &mut buf);
        assert!(
            !buf[..n as usize].contains(&GONE),
            "gone quiet: a peer's list outlives the node it names"
        );
        let mut covered = CoveredSet::new();
        absorb_relay_coverage(&c, &mut covered, NEAR, past);
        assert!(!covered.contains(GONE), "absorb credits the same set");

        edges.update_node_activity(GONE, past, ME);
        let c = ctx(&edges, &capability, &downstream);
        let n = get_coverage_if_relays(&c, NEAR, past, &mut buf);
        assert!(buf[..n as usize].contains(&GONE), "back on the air");
    }

    #[test]
    fn a_dropped_young_node_is_not_a_coverage_target() {
        const MUTE: u32 = 0x1100_0011;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        capability.track_topology(BB, true, 0);
        edges.update_edge(ME, ME, MUTE, 1.5, 0, EdgeSource::Reported, false, 0);
        capability.track_role(MUTE, crate::nodeinfo::DEVICE_ROLE_CLIENT_MUTE, 0);

        let mut c = ctx(&edges, &capability, &downstream);
        let mut buf = [0u32; MAX_EDGES_PER_NODE];
        let n = get_coverage_if_relays(&c, ME, 0, &mut buf);
        assert!(
            buf[..n as usize].contains(&MUTE),
            "a mute neighbour only we reach is a coverage target"
        );

        let mut gate = YoungCoverageGate::empty();
        gate.active = true;
        gate.ids[0] = MUTE;
        gate.id_count = 1;
        c.dropped_coverage = gate;
        let n = get_coverage_if_relays(&c, ME, 0, &mut buf);
        assert!(
            !buf[..n as usize].contains(&MUTE),
            "dropped traffic is nobody's to carry"
        );
        let mut covered = CoveredSet::new();
        absorb_relay_coverage(&c, &mut covered, ME, 0);
        assert!(!covered.contains(MUTE), "absorb credits the same set");
    }

    #[test]
    fn a_mute_neighbour_past_the_ceiling_is_nobody_s_relay() {
        const PEER: u32 = 0xAB00_00AB;
        const SS: u32 = 0xDD00_00DD;
        let plan_at = |our_etx: f32| {
            let mut edges = EdgeStore::new();
            let mut capability = CapabilityCache::new();
            edges.ensure_local_node(ME, 0);
            edges.update_edge(ME, ME, BB, 1.0, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(ME, BB, true);
            capability.track_topology(BB, true, 0);
            edges.update_edge(ME, ME, PEER, 1.0, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(ME, PEER, true);
            capability.track_topology(PEER, true, 0);
            edges.update_edge(ME, PEER, BB, 1.0, 0, EdgeSource::Mirrored, true, 0);
            edges.update_edge(ME, BB, PEER, 1.0, 0, EdgeSource::Mirrored, true, 0);
            edges.set_edge_hears_us(BB, PEER, true);
            capability.track_role(SS, DEVICE_ROLE_TRACKER, 0);
            for (from, to) in [(ME, SS), (SS, ME)] {
                edges.update_edge(ME, from, to, our_etx, 0, EdgeSource::Reported, true, 0);
            }
            let downstream = DownstreamTable::new();
            plan_broadcast_relay(
                &ctx(&edges, &capability, &downstream),
                0x99,
                BB,
                BB,
                0xFFFF_FFFF,
                0,
                100,
                TEST_SLOT_MS,
                never_transmitted,
                false,
            )
        };
        let inside = plan_at(6.0);
        assert!(inside.should_relay, "reachable: the ranking carries it");
        assert_eq!(inside.reason, RelayReason::Ranked);
        assert_eq!(inside.coverage_for, SS);
        let past = plan_at(8.0);
        assert!(
            !past.should_relay,
            "past the ceiling the copy does not arrive, so no slot is spent on it"
        );
    }

    #[test]
    fn an_owner_taking_a_slot_absorbs_the_neighbour_it_owns() {
        const PEER: u32 = 0xAB00_00AB;
        const SILENT: u32 = 0xDD00_00DD;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        capability.track_topology(BB, true, 0);
        edges.update_edge(ME, ME, PEER, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, PEER, true);
        capability.track_topology(PEER, true, 0);
        edges.update_edge(ME, PEER, SILENT, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, ME, SILENT, 6.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, PEER, BB, 1.0, 0, EdgeSource::Mirrored, true, 0);
        let downstream = DownstreamTable::new();
        let ctx = ctx(&edges, &capability, &downstream);
        assert_eq!(
            crate::graph::coverage_owner(&edges, &capability, ME, true, SILENT),
            PEER
        );
        let mut covered = CoveredSet::new();
        absorb_relay_coverage(&ctx, &mut covered, PEER, 0);
        assert!(
            covered.contains(SILENT),
            "the owner carries what it owns, so nobody else relays for it"
        );
    }

    #[test]
    fn mute_stock_neighbour_only_we_reach_is_carried_by_the_ranking() {
        const SS: u32 = 0xDD00_00DD;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        capability.track_topology(BB, true, 0);
        edges.update_edge(ME, ME, SS, 1.0, 0, EdgeSource::Reported, true, 0);
        capability.track_role(SS, DEVICE_ROLE_TRACKER, 0);
        let downstream = DownstreamTable::new();
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(plan.should_relay, "nobody else reaches it");
        assert_eq!(plan.reason, RelayReason::Ranked, "carried by the ranking");
        assert_eq!(plan.coverage_for, SS);
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
            TEST_SLOT_MS,
            |_| false,
            false,
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
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(!plan.should_relay);
    }

    fn edges_with_remote_transmitter(bb_to_me_etx: f32) -> EdgeStore {
        const VIA: u32 = 0xDD00_00DD;
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, VIA, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, VIA, BB, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, BB, ME, bb_to_me_etx, 0, EdgeSource::Mirrored, true, 0);
        assert!(edges.find_node(BB).and_then(|n| n.find_edge(ME)).is_some());
        assert!(edges.find_node(ME).and_then(|n| n.find_edge(BB)).is_none());
        edges
    }

    #[test]
    fn one_way_listed_neighbor_is_not_precovered() {
        let edges = edges_with_remote_transmitter(1.5);
        let mut capability = CapabilityCache::new();
        capability.track_topology(ME, true, 0);
        assert!(!build_already_covered(&edges, &capability, BB, BB).contains(ME));
        assert!(build_already_covered(&edges, &CapabilityCache::new(), BB, BB).contains(ME));
    }

    #[test]
    fn hopeless_confirmed_neighbor_is_not_precovered() {
        let mut edges = edges_with_remote_transmitter(40.0);
        edges.set_edge_hears_us(BB, ME, true);
        let mut capability = CapabilityCache::new();
        capability.track_topology(ME, true, 0);
        assert!(!build_already_covered(&edges, &capability, BB, BB).contains(ME));
        edges.update_edge(ME, BB, ME, 1.5, 0, EdgeSource::Mirrored, true, 0);
        assert!(build_already_covered(&edges, &capability, BB, BB).contains(ME));
    }

    #[test]
    fn one_way_absorb_does_not_suppress_unique_coverage_slot() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        const FF: u32 = 0xAA00_00FF;
        const PEER: u32 = 0xEE00_00EE;
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, PEER, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, FF, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, PEER, true);
        edges.set_edge_hears_us(ME, FF, true);
        edges.update_edge(ME, PEER, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, PEER, FF, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(PEER, BB, true);
        edges.update_edge(ME, BB, PEER, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(BB, PEER, true);
        capability.track_topology(PEER, true, 0);
        capability.track_topology(ME, true, 0);
        capability.track_topology(FF, true, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(
            plan.should_relay,
            "FF is not covered by the transmitter, so we take a slot"
        );
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
            TEST_SLOT_MS,
            never_transmitted,
            false,
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
        edges.update_edge(C, B, D, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(B, D, true);
        capability.track_role(D, DEVICE_ROLE_REPEATER, 0);
        let ctx = BroadcastRelayContext {
            my_node: C,
            my_node_relays: true,
            edges: &edges,
            capability: &capability,
            downstream: &downstream,
            dropped_coverage: YoungCoverageGate::empty(),
        };
        let plan = plan_broadcast_relay(
            &ctx,
            0x99,
            B,
            B,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            |_| false,
            false,
        );
        assert!(
            !plan.should_relay,
            "transmitter already reaches everyone we do; the repeater is reserved, not assumed to cover leftover neighbours: got should_relay delay={} cands={}",
            plan.slot_delay_ms, plan.candidate_count
        );
        assert_eq!(plan.reserved_slots, 1, "and it holds a reserved position");
    }

    #[test]
    fn an_sr_router_outranks_a_client_of_equal_coverage() {
        const RT: u32 = 0xAA00_0071;
        const CL: u32 = 0xAA00_0072;
        const FAR: u32 = 0xAA00_00FF;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        for peer in [BB, RT, CL] {
            edges.update_edge(ME, ME, peer, 2.0, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(ME, peer, true);
        }
        for peer in [RT, CL] {
            edges.update_edge(ME, BB, peer, 1.5, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(BB, peer, true);
        }
        for (peer, cost) in [(RT, 3.0f32), (CL, 1.2f32)] {
            edges.update_edge(ME, peer, BB, 1.5, 0, EdgeSource::Reported, true, 0);
            edges.update_edge(ME, peer, FAR, cost, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(peer, BB, true);
            edges.set_edge_hears_us(peer, FAR, true);
            capability.track_topology(peer, true, 0);
        }
        capability.track_role(RT, crate::nodeinfo::DEVICE_ROLE_ROUTER, 0);
        capability.track_role(CL, crate::nodeinfo::DEVICE_ROLE_CLIENT, 0);
        let c = ctx(&edges, &capability, &downstream);
        let best = find_best_relay_candidate(
            &c,
            &build_candidates(&c, BB, BB),
            &build_already_covered(&edges, &capability, BB, BB),
            false,
            BB,
            0,
            never_transmitted,
            None,
        );
        assert_eq!(
            best.node_id, RT,
            "the ROUTER is preferred despite the dearer link"
        );
        assert_eq!(best.role_rank, 1);
    }

    #[test]
    fn an_sr_router_with_coverage_takes_a_window_position() {
        const FAR: u32 = 0xAA00_00FF;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        capability.track_topology(ME, true, 0);
        capability.track_role(ME, crate::nodeinfo::DEVICE_ROLE_ROUTER, 0);
        edges.update_edge(ME, ME, FAR, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, FAR, true);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(plan.should_relay);
        assert_eq!(plan.reason, RelayReason::Ranked);
        assert_eq!(
            plan.reserved_slots, 0,
            "an SR ROUTER is ranked, never reserved"
        );
        assert_eq!(
            plan.slot_delay_ms, 0,
            "empty window: the first ranked position is at the window start"
        );
        assert_eq!(plan.slot_index, 0);
        assert!(!capability.is_immediate_relay_router(ME));
    }

    #[test]
    fn a_client_with_coverage_takes_a_late_rung_past_the_transition() {
        const FAR: u32 = 0xAA00_00FF;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        capability.track_topology(ME, true, 0);
        capability.track_role(ME, crate::nodeinfo::DEVICE_ROLE_CLIENT, 0);
        edges.update_edge(ME, ME, FAR, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, FAR, true);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(plan.should_relay);
        assert_eq!(plan.reason, RelayReason::Ranked);
        assert_eq!(
            plan.slot_delay_ms,
            crate::coordinated_relay::relay_floor_ms(TEST_SLOT_MS),
            "CLIENT must not take an early-window position"
        );
    }

    #[test]
    fn client_base_with_coverage_takes_a_late_rung() {
        const FAR: u32 = 0xAA00_00FE;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        capability.track_topology(ME, true, 0);
        capability.track_role(ME, crate::nodeinfo::DEVICE_ROLE_CLIENT_BASE, 0);
        edges.update_edge(ME, ME, FAR, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, FAR, true);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x9a,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(plan.should_relay);
        assert!(
            plan.slot_delay_ms >= crate::coordinated_relay::relay_floor_ms(TEST_SLOT_MS),
            "CLIENT_BASE delay {} must be at or past the preset floor",
            plan.slot_delay_ms
        );
    }

    #[test]
    fn client_outranking_router_on_coverage_still_waits_past_early_window() {
        const RT: u32 = 0xAA00_0071;
        const FAR: u32 = 0xAA00_00FF;
        const FAR2: u32 = 0xAA00_00FE;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        for peer in [BB, RT] {
            edges.update_edge(ME, ME, peer, 2.0, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(ME, peer, true);
        }
        capability.track_topology(ME, true, 0);
        capability.track_role(ME, crate::nodeinfo::DEVICE_ROLE_CLIENT, 0);
        capability.track_topology(RT, true, 0);
        capability.track_role(RT, crate::nodeinfo::DEVICE_ROLE_ROUTER, 0);
        for (who, target) in [(RT, FAR), (ME, FAR), (ME, FAR2)] {
            edges.update_edge(ME, who, target, 1.5, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(who, target, true);
        }
        edges.update_edge(ME, RT, BB, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(RT, BB, true);
        edges.update_edge(ME, ME, BB, 1.5, 0, EdgeSource::Reported, true, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x9b,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(plan.should_relay);
        assert_eq!(
            plan.slots_given, 1,
            "the SR ROUTER still takes an early slot ahead of us"
        );
        assert_eq!(plan.ranked[0], RT);
        assert_eq!(plan.ranked[1], ME);
        assert!(
            plan.slot_delay_ms >= crate::coordinated_relay::relay_floor_ms(TEST_SLOT_MS),
            "CLIENT delay {} must wait past the early window",
            plan.slot_delay_ms
        );
    }

    #[test]
    fn router_with_unique_beats_a_client_with_more_coverage() {
        const RT: u32 = 0xAA00_0071;
        const CL: u32 = 0xAA00_0072;
        const FAR: u32 = 0xAA00_00FF;
        const FAR2: u32 = 0xAA00_00FE;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        for peer in [BB, RT, CL] {
            edges.update_edge(ME, ME, peer, 2.0, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(ME, peer, true);
        }
        for peer in [RT, CL] {
            edges.update_edge(ME, peer, BB, 1.5, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(peer, BB, true);
            edges.update_edge(ME, peer, FAR, 1.5, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(peer, FAR, true);
            capability.track_topology(peer, true, 0);
        }
        edges.update_edge(ME, CL, FAR2, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(CL, FAR2, true);
        capability.track_role(RT, crate::nodeinfo::DEVICE_ROLE_ROUTER, 0);
        capability.track_role(CL, crate::nodeinfo::DEVICE_ROLE_CLIENT, 0);
        let c = ctx(&edges, &capability, &downstream);
        let best = find_best_relay_candidate(
            &c,
            &build_candidates(&c, BB, BB),
            &build_already_covered(&edges, &capability, BB, BB),
            false,
            BB,
            0,
            never_transmitted,
            None,
        );
        assert_eq!(
            best.node_id, RT,
            "a ROUTER with unique coverage ranks before a CLIENT with more unique"
        );
    }

    #[test]
    fn router_late_earns_no_ranking_promotion() {
        const RL: u32 = 0xAA00_0073;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, RL, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, RL, true);
        capability.track_topology(RL, true, 0);
        capability.track_role(RL, crate::nodeinfo::DEVICE_ROLE_ROUTER_LATE, 0);
        let c = ctx(&edges, &capability, &downstream);
        assert_eq!(role_rank(&c, RL), 0);
    }

    #[test]
    fn better_peer_with_unique_coverage_suppresses_us() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        const FF: u32 = 0xAA00_00FF;
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, EE, true);
        edges.update_edge(ME, BB, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(BB, EE, true);
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
            TEST_SLOT_MS,
            never_transmitted,
            false,
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
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, EE, true);
        edges.update_edge(ME, ME, KK, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, KK, true);
        edges.update_edge(ME, ME, HH1, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, ME, HH2, 2.0, 0, EdgeSource::Mirrored, true, 0);
        edges.set_edge_hears_us(ME, HH1, true);
        edges.set_edge_hears_us(ME, HH2, true);
        edges.update_edge(ME, EE, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(EE, BB, true);
        for n in [FF, GG, JJ] {
            edges.update_edge(ME, EE, n, 1.5, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(EE, n, true);
        }
        edges.update_edge(ME, EE, ME, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(EE, ME, true);
        capability.track_topology(EE, true, 0);
        capability.track_topology(ME, true, 0);

        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x98,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(plan.should_relay);
        assert_eq!(plan.slot_index, 1);
        assert_eq!(plan.ranked_len, 2);
        assert_eq!(plan.ranked[0], EE);
        assert_eq!(plan.ranked[1], ME);
    }

    #[test]
    fn overlapping_unique_vs_transmitter_both_take_slots() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        const FF: u32 = 0xAA00_00FF;
        const GG: u32 = 0xAA00_0011;
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, FF, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, EE, true);
        edges.set_edge_hears_us(ME, FF, true);
        edges.update_edge(ME, BB, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(BB, EE, true);
        edges.update_edge(ME, EE, BB, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, ME, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, FF, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, GG, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(EE, BB, true);
        edges.set_edge_hears_us(EE, ME, true);
        edges.set_edge_hears_us(EE, FF, true);
        edges.set_edge_hears_us(EE, GG, true);
        capability.track_topology(EE, true, 0);
        capability.track_topology(ME, true, 0);
        capability.track_topology(FF, true, 0);
        capability.track_topology(GG, true, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(
            plan.should_relay,
            "FF is not covered by the transmitter, so we keep a later slot even though EE also reaches it"
        );
        assert_eq!(plan.ranked[0], EE);
        assert_eq!(plan.ranked[1], ME);
        assert_eq!(plan.slot_index, 1);
        assert_eq!(plan.absorbed_len, 0, "planned peers do not absorb");
    }

    #[test]
    fn stock_reservation_does_not_absorb_unheard_coverage() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        setup_stock_topology(&mut edges, &mut capability);
        const FF: u32 = 0xAA00_00FF;
        edges.update_edge(ME, ME, FF, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, FF, true);
        edges.update_edge(ME, DD, FF, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(DD, FF, true);
        capability.track_topology(ME, true, 0);
        capability.track_topology(FF, true, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(
            plan.should_relay,
            "FF is not covered by the transmitter, so a stock reservation does not silence us"
        );
        assert!(plan.reserved_slots > 0);
        assert_eq!(plan.absorbed_len, 0);

        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            |node| node == DD,
            false,
        );
        assert!(
            !plan.should_relay,
            "once the stock copy is on the air, FF is covered and we take no slot"
        );
        assert!(plan.absorbed_len > 0);
    }

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
        edges.update_edge(ME, BB, peer, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, peer, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, peer, SS, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(peer, BB, true);
        capability.track_topology(peer, true, 0);
        capability.track_topology(ME, true, 0);
        capability.track_role(SS, DEVICE_ROLE_TRACKER, 0);
        (edges, capability)
    }

    #[test]
    fn silent_neighbour_is_relayed_for_by_the_best_link_only() {
        const SS: u32 = 0xDD00_00DD;
        const PEER: u32 = 0xEE00_00EE;
        let downstream = DownstreamTable::new();
        let relay_for = |ours: f32, theirs: f32| {
            let (mut edges, capability) = stock_fixture(PEER);
            edges.update_edge(ME, ME, SS, ours, 0, EdgeSource::Reported, true, 0);
            edges.update_edge(ME, PEER, SS, theirs, 0, EdgeSource::Reported, true, 0);
            plan_broadcast_relay(
                &ctx(&edges, &capability, &downstream),
                0x99,
                BB,
                BB,
                0xFFFF_FFFF,
                0,
                100,
                TEST_SLOT_MS,
                never_transmitted,
                false,
            )
            .should_relay
        };
        assert!(relay_for(1.0, 4.0), "our link to it is the best: we relay");
        assert!(
            relay_for(4.0, 1.0),
            "the peer hears it better and ranks first; we still take a later slot until we hear them"
        );
    }

    #[test]
    fn plan_names_the_neighbour_the_relay_is_for() {
        const SS: u32 = 0xDD00_00DD;
        const PEER: u32 = 0xEE00_00EE;
        let downstream = DownstreamTable::new();
        let (mut edges, capability) = stock_fixture(PEER);
        edges.update_edge(ME, ME, SS, 1.0, 0, EdgeSource::Reported, true, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(plan.should_relay);
        assert_eq!(plan.coverage_for, SS);
        assert_eq!(&plan.uncovered[..plan.uncovered_len as usize], &[SS]);
    }

    #[test]
    fn plan_names_nothing_when_the_transmitter_covered_it_all() {
        const SS: u32 = 0xDD00_00DD;
        const PEER: u32 = 0xEE00_00EE;
        let downstream = DownstreamTable::new();
        let (mut edges, capability) = stock_fixture(PEER);
        edges.update_edge(ME, ME, SS, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, BB, SS, 2.0, 0, EdgeSource::Reported, true, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert_eq!(plan.uncovered_len, 0);
    }

    #[test]
    fn stock_neighbour_covered_by_transmitter_needs_no_relay() {
        let downstream = DownstreamTable::new();
        let (mut edges, capability) = stock_fixture(0xEE00_00EE);
        edges.update_edge(ME, BB, 0xDD00_00DD, 2.0, 0, EdgeSource::Reported, true, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(!plan.should_relay);
    }

    #[test]
    fn best_candidate_assigned_earlier_slot() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        const FF: u32 = 0xAA00_00FF;
        const GG: u32 = 0xAA00_0011;
        edges.ensure_local_node(ME, 0);
        edges.update_edge(ME, ME, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(ME, EE, true);
        edges.update_edge(ME, BB, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(BB, EE, true);
        edges.update_edge(ME, EE, BB, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, ME, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, FF, 1.5, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(EE, BB, true);
        edges.set_edge_hears_us(EE, ME, true);
        edges.set_edge_hears_us(EE, FF, true);
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
            TEST_SLOT_MS,
            never_transmitted,
            false,
        );
        assert!(plan.should_relay);
        assert_eq!(plan.slot_index, 1);
        assert!(
            plan.slot_delay_ms >= crate::coordinated_relay::relay_floor_ms(TEST_SLOT_MS),
            "second late rung sits past the early window, got {}",
            plan.slot_delay_ms
        );
    }
}
