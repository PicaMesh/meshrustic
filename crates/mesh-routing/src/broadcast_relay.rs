//! Phased broadcast relay slot scheduling (stock early slots → SR ranked → downstream).

use crate::capability::{CapabilityCache, CapabilityStatus};
use crate::graph::{
    coverage_owner, covers, delivery_hop_cost_fixed, is_placeholder_node, is_silent_publisher,
    DownstreamTable, EdgeSource, EdgeStore, MAX_EDGES_PER_NODE,
};

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
    /// One neighbour this candidate covers that the transmitter did not reach: the reason the
    /// relay is worth its airtime, named in the log rather than left to be guessed at.
    pub coverage_for: u32,
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
    /// Ranking inputs of the first candidates evaluated: (node, unique coverage, total coverage,
    /// cost bucket). Lets two nodes' views of the same packet be compared when their orders
    /// disagree: unique < total shows how much pre-coverage took away.
    pub evaluated: [(u32, u8, u8, u16); RANKED_LOG],
    pub evaluated_len: u8,
    /// Nodes counted as already covered before ranking (source, heard-from and its good links).
    pub pre_covered: u8,
    /// Our own neighbours this transmission did *not* cover, first `uncovered_len` valid. This is
    /// exactly what earns us a slot and what T1 insures, so two nodes that disagree about a
    /// packet can be compared by name rather than by the `pre_covered` count alone.
    pub uncovered: [u32; UNCOVERED_LOG],
    pub uncovered_len: u8,
    /// Transmissions we expect ahead of ours: stock relay routers that have not transmitted
    /// this packet yet, plus the ranked SR peers whose coverage we absorbed. Zero means nothing
    /// is expected, so there is nothing for a late copy to stand in for.
    pub slots_given: u8,
    /// How many of `slots_given` are reserved positions held by stock relay routers rather than
    /// rungs held by ranked SR peers. The two are different reasons to stay quiet — one expects a
    /// node we do not coordinate with, the other a node we do — and a log that merges them cannot
    /// say which. Needed to check that removing the reservation does not silently drop the
    /// insurance arm it used to earn.
    pub reserved_slots: u8,
    /// How many of the leading `ranked` entries came from the reservation pre-pass rather than
    /// the ranking loop. Not the same as `reserved_slots`: a router that already transmitted this
    /// packet is still listed, and still consumed the accumulator, but is no longer a
    /// transmission we are waiting for. Lets the order line say which entries are reservations.
    pub reserved_ranked: u8,
    /// Who absorbed coverage before we were ranked, and how many nodes each newly covered:
    /// `(relay, credit)`. This is why a later candidate finds nothing unique and stays quiet, and
    /// it was computed at three sites and logged at none — so a capture could not say whether a
    /// reservation earned the suppression it caused.
    pub absorbed: [(u32, u8); RANKED_LOG],
    pub absorbed_len: u8,
    /// A neighbour our relay reaches that the transmitter did not (0 when the relay was taken
    /// for another reason: sole candidate or downstream).
    pub coverage_for: u32,
}

/// Ranking inputs collected during the first pick, for the log.
#[derive(Clone, Copy, Debug, Default)]
pub struct EvaluatedList {
    pub items: [(u32, u8, u8, u16); RANKED_LOG],
    pub len: u8,
}

/// Record one candidate's ranking inputs for the log (first RANKED_LOG only).
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

/// How many slot holders the plan records for logging.
pub const RANKED_LOG: usize = 4;
/// Uncovered neighbours named in the log line. Six, not three: with a shorter list each node
/// prints a *prefix* of its own edge order, so two nodes comparing a packet cannot tell a real
/// disagreement from two different truncations of the same set — which cost a wrong lead on
/// 2026-09-09. Six covers the whole neighbourhood this fits in one line.
pub const UNCOVERED_LOG: usize = 6;

/// Why the plan decided we relay (for the log; `None` when we defer).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RelayReason {
    #[default]
    None,
    /// We won a slot in the coverage ranking.
    Ranked,
    /// We are the known downstream relay for the source or destination.
    Downstream,
    /// Sparse mesh: we were the only candidate.
    Sparse,
    /// Unicast: we hold a slot in the cost-to-destination ranking.
    UnicastCost,
    /// Nobody had coverage to offer for a message its originator is waiting on, so we answer it:
    /// stock turns a heard rebroadcast into its delivery confirmation and otherwise retransmits.
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
    /// Our role rebroadcasts: needed to decide whether we may own an unconfirmed neighbour.
    pub my_node_relays: bool,
    pub edges: &'a EdgeStore,
    pub capability: &'a CapabilityCache,
    pub downstream: &'a DownstreamTable,
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
        // A candidate's coverage set is what it published, and for ourselves what we publish.
        // Mirrored edges are invisible to peers; counting them made colocated nodes disagree on
        // slot order. An edge we invented from a relayed frame is invisible to everyone,
        // including the candidate it is attributed to, so it belongs in nobody's set.
        if relay == my_node && edge.source != EdgeSource::Reported {
            continue;
        }
        if !edge.source.is_measured() {
            continue;
        }
        // A neighbour nobody can be shown to reach is still worth one relay, but only from its
        // owner: counting it everywhere made every node on the branch relay every frame for the
        // same unconfirmed node (an Alert node that publishes nothing, 2026-09-07).
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

/// Credit a relay we expect to transmit with everything it carries — by exactly the rule that
/// admitted it in [`get_coverage_if_relays`]. Crediting only `covers` while admission also
/// accepted ownership left an owned neighbour uncovered after its owner took a slot, so a later
/// phase relayed for it a second time.
/// Credit `relay` with everything it carries, and report how many nodes that newly covered.
///
/// The count is what makes absorption visible: it is the reason a later candidate finds nothing
/// unique and stays quiet, and until now it was computed at three call sites and logged at none —
/// so a capture could not say whether a reservation actually earned its suppression.
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

/// Does `relay` carry `target` if it transmits: it can be shown to deliver, or `target` is a
/// neighbour nobody can be shown to reach and `relay` is the one node that owns it.
fn admits_coverage(ctx: &BroadcastRelayContext<'_>, relay: u32, target: u32, now_ms: u32) -> bool {
    // A publisher that has gone quiet is nobody's target, however good the link a peer published
    // to it: our own link to it is already retracted, and crediting peers with reaching it hands
    // them a slot they will decline.
    if is_silent_publisher(ctx.edges, Some(ctx.capability), target, now_ms) {
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

/// Outcome of the acknowledgement pass: who answers, in what order, and whether we are one.
struct AcknowledgementPlan {
    should_relay: bool,
    my_delay: u32,
    slots_given: u8,
    ranked: [u32; RANKED_LOG],
    ranked_len: u8,
}

/// Answer a message its originator is waiting on, when the coverage ranking had nothing to offer.
///
/// Ordered by how well *the source* hears each candidate, best first — the opposite of stock's
/// reverse-ETX flood order, which puts the worst-heard node first because it is optimising
/// propagation. Here the purpose is that the originator hears the answer, so a copy it cannot hear
/// achieves nothing.
///
/// The candidate set is the intersection of two conditions, and both are needed. We must be able to
/// hear the candidate, or its copy cannot cancel our own rung and every candidate transmits. And
/// there must be positive evidence that the source hears it, or the answer does not arrive. Two
/// nodes with disjoint neighbourhoods may therefore each answer; that is bounded, and still far
/// fewer copies than every node that heard the frame.
fn plan_acknowledgement(
    ctx: &BroadcastRelayContext<'_>,
    packet_id: u32,
    source: u32,
    heard_from: u32,
    half: u32,
) -> Option<AcknowledgementPlan> {
    if !ctx.my_node_relays {
        return None;
    }
    let my_edges = ctx.edges.find_node(ctx.my_node)?;

    // Stand down for a neighbour that will rebroadcast regardless and will not cancel for us: its
    // copy is the acknowledgement and ours would only add to it. A stock CLIENT is not such a
    // node — it floods later than our rung and cancels on hearing us, so answering first removes
    // its copy rather than adding to ours.
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

    // Rank the candidates we can hear that the source can be shown to hear, ourselves included.
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

    // Bucketed price first, then the ladder's own tie-break so the work rotates across packets
    // rather than always falling to the same node.
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
    let mut delay = crate::channel_access::SLOT_ORIGIN_MS;
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
        // A rung ahead of ours we are waiting on, so T1 insures the answer if it never comes.
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
        // Sparse sole-candidate and stock-trailing slots are handled after ranking.
        if unique_count == 0 {
            continue;
        }

        let mut total_cost = 0f32;
        let mut valid_costs = 0u8;
        for &target in &unique[..unique_count as usize] {
            if let Some(fixed) =
                delivery_hop_cost_fixed(ctx.edges, Some(ctx.capability), candidate, target)
            {
                total_cost += fixed as f32 / 100.0;
                valid_costs += 1;
            }
        }
        // Admission guarantees a price: `covers` needs an edge in one direction or the other,
        // ownership needs the candidate's own edge, and neither admits a target `can_deliver`
        // would refuse — a publisher that never confirmed the candidate fails `covers`, and
        // ownership skips publishers entirely.
        debug_assert!(
            unique_count == 0 || valid_costs > 0,
            "an admitted target always has a delivery price"
        );

        // Own vs peer-reported ETX differ by hundredths; exact compare inverted colocated ranks.
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

pub fn plan_broadcast_relay<F>(
    ctx: &BroadcastRelayContext<'_>,
    packet_id: u32,
    source: u32,
    heard_from: u32,
    broadcast_dest: u32,
    now_ms: u32,
    half_airtime_ms: u32,
    has_transmitted: F,
    ack_eligible: bool,
) -> BroadcastRelayPlan
where
    F: Fn(u32) -> bool,
{
    // Floored once, in coordinated_relay: a second application here would drift from it.
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
    // Slot k fires at SLOT_ORIGIN_MS + k * half: nobody keys up inside the peers' turnaround.
    let mut slot_delay = crate::channel_access::SLOT_ORIGIN_MS;
    let mut should_relay = false;
    let mut my_delay = 0u32;
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
            // Stock takes the early slot — count their coverage now so we only
            // trail if we still have unique nodes after they relay.
            let credit = absorb_relay_coverage(ctx, &mut already_covered, neighbor, now_ms);
            push_absorbed(&mut absorbed, &mut absorbed_len, neighbor, credit);
            push_ranked(&mut ranked, &mut ranked_len, neighbor);
            reserved_ranked = reserved_ranked.saturating_add(1);
            // Its slot is still spent — a stock router transmits on its own schedule — but a
            // copy already on the air is not a transmission we are still waiting for.
            if !has_transmitted(neighbor) {
                slots_given = slots_given.saturating_add(1);
                reserved_slots = reserved_slots.saturating_add(1);
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
        candidates.erase(best.node_id);

        if has_transmitted(best.node_id) {
            let credit = absorb_relay_coverage(ctx, &mut already_covered, best.node_id, now_ms);
            push_absorbed(&mut absorbed, &mut absorbed_len, best.node_id, credit);
            continue;
        }

        push_ranked(&mut ranked, &mut ranked_len, best.node_id);
        if best.node_id == ctx.my_node {
            should_relay = true;
            reason = RelayReason::Ranked;
            my_delay = slot_delay;
            coverage_for = best.coverage_for;
            break;
        }

        // Earlier-ranked peer is assumed to relay — subtract their coverage so we
        // only take a later slot when we still have unique nodes to reach.
        let credit = absorb_relay_coverage(ctx, &mut already_covered, best.node_id, now_ms);
        push_absorbed(&mut absorbed, &mut absorbed_len, best.node_id, credit);
        slots_given = slots_given.saturating_add(1);
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

    // Sparse mesh: only we were a candidate and ranking found no unique coverage.
    if !should_relay && initial_candidates <= 1 {
        should_relay = true;
        reason = RelayReason::Sparse;
        my_delay = slot_delay;
    }

    // Nobody had coverage to offer, and the originator is waiting to be told its message reached
    // the mesh. Stock's only delivery confirmation for a broadcast is hearing somebody rebroadcast
    // it, so suppressing every copy removes the signal it depends on and it retransmits into
    // silence — the phone reports a failure for a message that in fact arrived everywhere.
    //
    // The ranking cannot answer this: it drops a candidate with no unique coverage, because the
    // cost it ranks on is the mean delivery cost over the unique targets and there is nothing to
    // price. So this is a second pass with its own price, run only when the ladder came out empty.
    if !should_relay && slots_given == 0 && ack_eligible {
        if let Some(ack) = plan_acknowledgement(ctx, packet_id, source, heard_from, half) {
            should_relay = ack.should_relay;
            reason = RelayReason::Acknowledgement;
            my_delay = ack.my_delay;
            slots_given = ack.slots_given;
            for i in 0..ack.ranked_len {
                push_ranked(&mut ranked, &mut ranked_len, ack.ranked[i as usize]);
            }
        }
    }

    let slot_index = my_delay
        .saturating_sub(crate::channel_access::SLOT_ORIGIN_MS)
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
            my_node_relays: true,
            edges,
            capability,
            downstream,
        }
    }

    /// A reservation and a rung are different reasons to stay quiet, and the plan must say which.
    ///
    /// Both raise `slots_given`, so a log that carries only that total cannot tell a stock router
    /// we cannot coordinate with from an SR peer we can — and it is the reservation whose removal
    /// would silently drop the insurance arm it used to earn. `reserved_ranked` additionally
    /// counts the leading order entries that are reservations, which is not the same number: a
    /// router that already transmitted still holds its place in the order but is no longer a
    /// transmission we are waiting for.
    #[test]
    fn reservation_and_rung_are_counted_apart() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        setup_stock_topology(&mut edges, &mut capability);
        // A second neighbour of the transmitter, SR-active, so the ranking has something to rank
        // besides the reserved router.
        edges.update_edge(ME, ME, EE, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, EE, BB, 2.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, EE, true);
        capability.track_topology(EE, true, 0);
        let ctx = ctx(&edges, &capability, &downstream);

        let plan = plan_broadcast_relay(&ctx, 1, BB, BB, u32::MAX, 0, 50, never_transmitted, false);
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

        // The same topology with the router's copy already on the air: it keeps its place in the
        // order, so the marker still applies, but it is no longer awaited.
        let plan = plan_broadcast_relay(&ctx, 1, BB, BB, u32::MAX, 0, 50, |node| node == DD, false);
        assert_eq!(
            plan.reserved_slots, 0,
            "a copy already on the air is not a transmission we are waiting for"
        );
        assert_eq!(
            plan.reserved_ranked as usize, 1,
            "but it still occupies its position in the order"
        );
    }

    /// When nobody has coverage to offer, somebody still answers a message its sender awaits.
    ///
    /// The ranking cannot do this: it drops a candidate with no unique coverage because the cost it
    /// ranks on is the mean delivery cost over the unique targets, and there is nothing to price.
    /// Without a second pass every node stays quiet, the originator never hears a rebroadcast —
    /// stock's only delivery confirmation for a broadcast — and it reports a failure for a message
    /// that arrived everywhere. Field 2026-09-09: four copies of one channel message and "Failed to
    /// deliver to mesh" on the phone.
    ///
    /// The topology below is the one that produces an empty ladder: the source lists both of its
    /// neighbours, so pre-coverage accounts for both and neither has anything unique left, and
    /// there are two candidates so the sole-candidate rule does not fire either.
    #[test]
    fn somebody_answers_when_the_ladder_is_empty() {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        let t0 = 1_000u32;
        edges.ensure_local_node(ME, t0);
        // We hear the source and the peer; the peer hears the source.
        edges.update_edge(ME, ME, BB, 1.0, t0, EdgeSource::Reported, true, 0);
        edges.update_edge(ME, ME, EE, 1.0, t0, EdgeSource::Reported, true, 0);
        // The peer must be a candidate, or the sole-candidate rule relays before this pass is
        // reached and the test proves nothing.
        edges.set_edge_hears_us(ME, EE, true);
        edges.update_edge(ME, EE, BB, 1.0, t0, EdgeSource::Mirrored, true, 0);
        capability.track_topology(BB, true, t0);
        capability.track_topology(EE, true, t0);
        // The source published both of us, and that it hears us both: pre-coverage takes both off
        // the table, and the answer has the evidence it needs.
        edges.update_edge(ME, BB, ME, 1.0, t0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, BB, EE, 1.0, t0, EdgeSource::Mirrored, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        edges.set_edge_hears_us(EE, BB, true);

        let ctx = ctx(&edges, &capability, &downstream);

        // Not eligible: nothing unique, nothing owed, so nobody speaks.
        let plan =
            plan_broadcast_relay(&ctx, 1, BB, BB, u32::MAX, t0, 50, never_transmitted, false);
        assert!(
            !plan.should_relay,
            "with nothing unique to carry and no acknowledgement owed, we stay quiet"
        );

        // Eligible: the same frame is answered, and the ladder names both answerers in order.
        let plan = plan_broadcast_relay(&ctx, 1, BB, BB, u32::MAX, t0, 50, never_transmitted, true);
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

    /// The answer is ordered by how well the *source* hears each candidate, not by coverage.
    ///
    /// Coverage asks whether a relay reaches a target; an acknowledgement asks whether the
    /// originator hears the relay. A copy the originator cannot hear tells it nothing and its retry
    /// ladder runs regardless, so the candidate the source hears best answers first and the others
    /// fall in behind — standing down when they hear that answer.
    #[test]
    fn the_source_hears_the_first_answerer_best() {
        // Same topology as above, but the source hears the peer far better than us.
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
        // The packet id is even, so the tie-break would prefer the *lower* node id — us. Price
        // must override it, or the ordering is not the one the design claims.
        let plan = plan_broadcast_relay(&ctx, 2, BB, BB, u32::MAX, t0, 50, never_transmitted, true);
        assert_eq!(plan.reason, RelayReason::Acknowledgement);
        assert_eq!(
            plan.ranked[0], EE,
            "the source hears the peer six times better, so the peer answers first"
        );
        assert!(plan.should_relay, "we answer too, behind it");
        assert!(
            plan.slot_delay_ms > crate::channel_access::SLOT_ORIGIN_MS,
            "our answer waits behind its rung and cancels if that answer arrives"
        );
        assert!(
            plan.slots_given > 0,
            "a rung ahead of ours is a transmission we wait on, so T1 insures it"
        );
    }

    /// A publisher we have stopped hearing is nobody's target, however good the edge a peer
    /// published to it. Field 2026-09-08: the branch gateway died, maintenance retracted our own
    /// link at the silence horizon, and the peers' lists kept naming it for another interval —
    /// so every node credited its peers with covering it and handed them a slot each declined.
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
        // The peer published a healthy link to the node, and the node itself once published too.
        edges.update_edge(ME, NEAR, GONE, 2.0, t0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, GONE, NEAR, 2.0, t0, EdgeSource::Mirrored, true, 0);
        capability.track_topology(NEAR, true, t0);
        capability.track_topology(GONE, true, t0);

        let c = ctx(&edges, &capability, &downstream);
        let mut buf = [0u32; MAX_EDGES_PER_NODE];

        // Inside the horizon the peer covers it.
        let inside = t0 + crate::neighbor_graph::PUBLISHER_SILENCE_MS;
        let n = get_coverage_if_relays(&c, NEAR, inside, &mut buf);
        assert!(
            buf[..n as usize].contains(&GONE),
            "still heard: the peer's published link is coverage"
        );

        // Past it, no peer covers it, so nobody is handed a slot for it.
        let past = inside + 1;
        let n = get_coverage_if_relays(&c, NEAR, past, &mut buf);
        assert!(
            !buf[..n as usize].contains(&GONE),
            "gone quiet: a peer's list outlives the node it names"
        );
        let mut covered = CoveredSet::new();
        absorb_relay_coverage(&c, &mut covered, NEAR, past);
        assert!(!covered.contains(GONE), "absorb credits the same set");

        // Hearing it again restores it: the entry's own timestamp is the evidence.
        edges.update_node_activity(GONE, past, ME);
        let c = ctx(&edges, &capability, &downstream);
        let n = get_coverage_if_relays(&c, NEAR, past, &mut buf);
        assert!(buf[..n as usize].contains(&GONE), "back on the air");
    }

    /// With a second candidate present — so the sole-candidate rule cannot fire — a mute stock
    /// neighbour only we reach is carried by the ranking while our link is inside the coverage
    /// ceiling, and not at all once it is past it. The deleted stock-coverage phase relayed in
    /// both cases, which is the behaviour the ceiling exists to stop: over an ETX-8 link a copy
    /// arrives about one time in eight, and the ranking would have spent a slot on it.
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
            // A second SR candidate that heard the transmitter, covered by it already.
            edges.update_edge(ME, ME, PEER, 1.0, 0, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(ME, PEER, true);
            capability.track_topology(PEER, true, 0);
            edges.update_edge(ME, PEER, BB, 1.0, 0, EdgeSource::Mirrored, true, 0);
            edges.update_edge(ME, BB, PEER, 1.0, 0, EdgeSource::Mirrored, true, 0);
            edges.set_edge_hears_us(BB, PEER, true);
            // The mute stock neighbour: only our own edge reaches it.
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

    /// A peer that takes a slot because it *owns* a silent neighbour must be credited with it
    /// when its coverage is absorbed, exactly as the admission credited it. Crediting only
    /// `covers` left the neighbour looking uncovered after its owner was ranked, so a later
    /// phase relayed for it a second time.
    #[test]
    fn an_owner_taking_a_slot_absorbs_the_neighbour_it_owns() {
        const PEER: u32 = 0xAB00_00AB;
        const SILENT: u32 = 0xDD00_00DD;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        edges.ensure_local_node(ME, 0);
        // The transmitter BB, an SR peer, and a silent node only the peer hears well.
        edges.update_edge(ME, ME, BB, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, BB, true);
        capability.track_topology(BB, true, 0);
        edges.update_edge(ME, ME, PEER, 1.0, 0, EdgeSource::Reported, true, 0);
        edges.set_edge_hears_us(ME, PEER, true);
        capability.track_topology(PEER, true, 0);
        edges.update_edge(ME, PEER, SILENT, 1.0, 0, EdgeSource::Mirrored, true, 0);
        edges.update_edge(ME, ME, SILENT, 6.0, 0, EdgeSource::Reported, true, 0);
        // The peer hears BB, so it is a candidate for this packet.
        edges.update_edge(ME, PEER, BB, 1.0, 0, EdgeSource::Mirrored, true, 0);
        let downstream = DownstreamTable::new();
        let ctx = ctx(&edges, &capability, &downstream);
        // The peer owns SILENT on the better link, so absorbing its coverage must cover SILENT.
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

    /// A mute stock neighbour only we reach is carried by the ranking itself: coverage admits a
    /// silent node on our own edge, so we take a ranked slot for it, and the separate fallback
    /// that used to do this is gone — it applied no ETX ceiling, so it also relayed over links
    /// the model calls undeliverable.
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
        let plan = plan_broadcast_relay(&ctx, 0x77, A, A, 0xFFFF_FFFF, 0, 100, |_| false, false);
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
            false,
        );
        // Immediate REPEATER takes the early slot; with no remaining unique coverage we defer.
        assert!(!plan.should_relay);
    }

    /// Reachable-but-not-heard transmitter: we learned BB's list through a neighbour and have no
    /// edge of our own to BB. `update_edge` only accepts a report about a node it can reach, so
    /// the relaying neighbour has to exist or the fixture proves nothing.
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

    /// A one-way listing is not pre-coverage: BB hearing us says nothing about us hearing BB.
    #[test]
    fn one_way_listed_neighbor_is_not_precovered() {
        let edges = edges_with_remote_transmitter(1.5);
        // We publish topology, so our silence about BB counts: BB listing us is not coverage.
        let mut capability = CapabilityCache::new();
        capability.track_topology(ME, true, 0);
        assert!(!build_already_covered(&edges, &capability, BB, BB).contains(ME));
        // A node that publishes nothing could never confirm anything, so the listing is all the
        // evidence there is and it does count.
        assert!(build_already_covered(&edges, &CapabilityCache::new(), BB, BB).contains(ME));
    }

    /// The transmitter's own list is pre-coverage only for the neighbours it actually reaches:
    /// a hop confirmed once but priced hopeless leaves us responsible for relaying.
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
        // Peer lists FF one-way (peer hears FF; FF does not hear peer). Ranking must not
        // treat FF as covered after the peer is assumed to relay.
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
            never_transmitted,
            false,
        );
        assert!(
            plan.should_relay,
            "FF still unique to us after one-way absorb of the peer"
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
        capability.track_role(D, DEVICE_ROLE_REPEATER, 0);
        let ctx = BroadcastRelayContext {
            my_node: C,
            my_node_relays: true,
            edges: &edges,
            capability: &capability,
            downstream: &downstream,
        };
        let plan = plan_broadcast_relay(&ctx, 0x99, B, B, 0xFFFF_FFFF, 0, 100, |_| false, false);
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
            false,
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

    /// A silent neighbour (mute, publishes nothing) is relayed for by exactly one node: the one
    /// whose link to it is best, since its receive path is all anyone can measure. Before this,
    /// every neighbour claimed it and the whole branch relayed every frame.
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
                never_transmitted,
                false,
            )
            .should_relay
        };
        assert!(relay_for(1.0, 4.0), "our link to it is the best: we relay");
        assert!(
            !relay_for(4.0, 1.0),
            "the peer hears it better: it relays and we stay silent"
        );
    }

    /// The plan names the neighbour that earned the relay. The log used to recompute it against
    /// the transmitter alone, which named a node a ranked peer does reach.
    #[test]
    fn plan_names_the_neighbour_the_relay_is_for() {
        const SS: u32 = 0xDD00_00DD;
        const PEER: u32 = 0xEE00_00EE;
        let downstream = DownstreamTable::new();
        let (mut edges, capability) = stock_fixture(PEER);
        // Only our link reaches SS, so ranking picks us and SS is what we relay for.
        edges.update_edge(ME, ME, SS, 1.0, 0, EdgeSource::Reported, true, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            never_transmitted,
            false,
        );
        assert!(plan.should_relay);
        assert_eq!(plan.coverage_for, SS);
        // The log names what the transmission missed, so two nodes that disagree about a packet
        // can be compared by name instead of by the pre-covered count alone.
        assert_eq!(&plan.uncovered[..plan.uncovered_len as usize], &[SS]);
    }

    /// A transmission that reached everything of ours leaves nothing to name.
    #[test]
    fn plan_names_nothing_when_the_transmitter_covered_it_all() {
        const SS: u32 = 0xDD00_00DD;
        const PEER: u32 = 0xEE00_00EE;
        let downstream = DownstreamTable::new();
        let (mut edges, capability) = stock_fixture(PEER);
        edges.update_edge(ME, ME, SS, 1.0, 0, EdgeSource::Reported, true, 0);
        // The transmitter reaches SS too, so it is pre-covered.
        edges.update_edge(ME, BB, SS, 2.0, 0, EdgeSource::Reported, true, 0);
        let plan = plan_broadcast_relay(
            &ctx(&edges, &capability, &downstream),
            0x99,
            BB,
            BB,
            0xFFFF_FFFF,
            0,
            100,
            never_transmitted,
            false,
        );
        assert_eq!(plan.uncovered_len, 0);
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
            false,
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
            false,
        );
        assert!(plan.should_relay);
        assert_eq!(
            plan.slot_delay_ms,
            crate::channel_access::SLOT_ORIGIN_MS + 100
        );
        assert_eq!(plan.slot_index, 1);
    }
}
