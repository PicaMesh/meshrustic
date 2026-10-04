//! Cost-ranked relay coordination for unicasts.
//!
//! Every SR node that overhears a unicast computes the same candidate ordering from its graph,
//! so the node best placed to deliver the packet keys up first and everybody else cancels on
//! its copy. Candidates are ourselves (we overheard the frame) plus SR-active direct neighbours
//! that are known to hear this copy's transmitter, ranked by cost to the destination:
//!
//! - deliverable hop to the destination ([`can_deliver`]), priced at the receiver when known;
//! - known downstream relay of the destination: [`DOWNSTREAM_TIER_COST`];
//! - deliverable hop to the shared next hop only: receiver-priced ETX with [`INDIRECT_TIER`].
//!
//! Costs are compared in buckets of [`COST_BUCKET_FIXED`] (half an ETX). Within a bucket, ties
//! break by node id (packet-id parity). Before ranking, suppress only when a coverer is known to
//! hold this copy (heard from them, or they already transmitted this id). A heard copy cancels a
//! later slot when that transmitter can finish delivery, is ranked ahead of us with a path, or
//! (for a named backup) is the designated hop / shows hop-limit progress on that designation —
//! even when the graph cannot yet prove finish. We keep the slot if we can finish and they
//! cannot. Finishing is a priced hop to the destination, or being its downstream gateway — not
//! stock optimism without a link.
//!
//! Last hop (a priced hop to the destination): at most two such links if dest is SR, otherwise
//! one. The second waits for dest's ACK. Indirect candidates still take later slots. Non-final
//! hops: the last ranked non-direct slot floods (`next_hop` cleared) after the named next hop
//! has had its chance, so stock neighbours may pick up.

use crate::broadcast_relay::{BroadcastRelayPlan, RelayReason, RANKED_LOG};
use crate::capability::{CapabilityCache, CapabilityStatus};
use crate::graph::{
    can_deliver, delivery_hop_cost_fixed, hop_cost_fixed, is_placeholder_node, known_to_hear,
    DownstreamTable, EdgeStore, MAX_EDGES_PER_NODE,
};
use crate::sr_log::SrSkipReason;

pub const MAX_UNICAST_CANDIDATES: usize = MAX_EDGES_PER_NODE + 1;
/// Cost of a candidate that is the destination's downstream relay without a reported edge.
pub const DOWNSTREAM_TIER_COST: u16 = 0x7FFF;
/// Set on the cost of candidates that only reach the shared next hop.
pub const INDIRECT_TIER: u16 = 0x8000;
/// Cost we give ourselves when the route picker said "relay it yourself" and no edge backs it.
pub const BEST_EFFORT_SELF_COST: u16 = 0xFFFE;
/// ETX costs are compared in buckets this wide (fixed-point, ETX × 100): half an ETX.
pub const COST_BUCKET_FIXED: u16 = 50;
const NO_PATH: u16 = u16::MAX;

fn bucket(etx_fixed: u16) -> u16 {
    etx_fixed / COST_BUCKET_FIXED * COST_BUCKET_FIXED
}

pub struct UnicastRelayContext<'a> {
    pub my_node: u32,
    pub edges: &'a EdgeStore,
    pub capability: &'a CapabilityCache,
    pub downstream: &'a DownstreamTable,
    pub downstream_ttl_ms: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnicastCandidate {
    pub node_id: u32,
    pub cost: u16,
}

/// How a committed unicast slot should treat a heard copy and whether it floods.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnicastSlotFlags {
    pub last_hop_backup: bool,
    pub nonfinal_flood: bool,
    pub nominated_next_hop: u32,
    /// Incoming `next_hop` byte when we armed as a named backup (0 = undesignated / not a backup).
    /// Hearing that hop's copy cancels us even when the graph cannot yet prove it finishes.
    pub designated_next_hop: u8,
    /// `hop_limit` on the copy we armed from; a later copy that still names `designated_next_hop`
    /// with a strictly lower hop_limit means that hop progressed the frame.
    pub armed_hop_limit: u8,
}

impl UnicastSlotFlags {
    pub const EMPTY: Self = Self {
        last_hop_backup: false,
        nonfinal_flood: false,
        nominated_next_hop: 0,
        designated_next_hop: 0,
        armed_hop_limit: 0,
    };
}

/// `a` is placed earlier than `b` in the unicast ranking for `packet_id`.
fn ranked_ahead(a: UnicastCandidate, b: UnicastCandidate, packet_id: u32) -> bool {
    let prefer_high_id = packet_id & 1 != 0;
    a.cost < b.cost
        || (a.cost == b.cost
            && if prefer_high_id {
                a.node_id > b.node_id
            } else {
                a.node_id < b.node_id
            })
}

impl UnicastRelayContext<'_> {
    fn downstream_relay(&self, destination: u32, now_ms: u32) -> Option<u32> {
        self.downstream
            .get_relay(destination, now_ms, self.downstream_ttl_ms)
    }

    fn chain_egress(&self, destination: u32, now_ms: u32) -> Option<u32> {
        self.downstream
            .chain_egress(destination, now_ms, self.downstream_ttl_ms, |n| {
                n != 0
                    && n != self.my_node
                    && self
                        .edges
                        .find_node(self.my_node)
                        .and_then(|e| e.find_edge(n))
                        .is_some()
            })
            .map(|c| c.node)
    }

    fn reaches(&self, node: u32, destination: u32, now_ms: u32) -> bool {
        self.can_finish(node, destination, now_ms)
    }

    /// A neighbour only gets a unicast slot if it is known to hear this copy's transmitter.
    /// We ourselves always count: we are ranking because we received the frame.
    fn heard_this_copy(&self, heard_from: u32, node: u32) -> bool {
        heard_from == 0 || node == self.my_node || known_to_hear(self.edges, heard_from, node)
    }

    /// Last-hop delivery: a priced hop to the destination, or we are its immediate
    /// downstream parent. `can_deliver` alone is not enough — it is true for every unpublished dest.
    /// Being the first SR hop we would appoint (chain egress) is not last-hop finish.
    fn can_finish(&self, node: u32, destination: u32, now_ms: u32) -> bool {
        delivery_hop_cost_fixed(
            self.edges,
            Some(self.capability),
            node,
            destination,
            now_ms,
            self.my_node,
        )
        .is_some()
            || self.downstream_relay(destination, now_ms) == Some(node)
    }

    fn candidate_cost(&self, node: u32, destination: u32, my_next_hop: u32, now_ms: u32) -> u16 {
        if let Some(cost) =
            delivery_hop_cost_fixed(
                self.edges,
                Some(self.capability),
                node,
                destination,
                now_ms,
                self.my_node,
            )
        {
            return bucket(cost.min(DOWNSTREAM_TIER_COST - 1));
        }
        if self.downstream_relay(destination, now_ms) == Some(node) {
            return DOWNSTREAM_TIER_COST;
        }
        if self.chain_egress(destination, now_ms) == Some(node) {
            return DOWNSTREAM_TIER_COST;
        }
        // Shared next hop must be a real forwarder (not us / dest) and reachable from `node`.
        if my_next_hop != 0
            && my_next_hop != destination
            && my_next_hop != node
            && my_next_hop != self.my_node
        {
            // Raw price: this hop is into the shared relay, and two neighbours a few hundredths
            // apart must stay in one bucket. The penalty for a reverse-only arrival applies to
            // the hop into the destination, above.
            if can_deliver(self.edges, Some(self.capability), node, my_next_hop) {
                if let Some(cost) = hop_cost_fixed(self.edges, node, my_next_hop) {
                    return bucket(cost.min(INDIRECT_TIER - 1)) | INDIRECT_TIER;
                }
            }
        }
        NO_PATH
    }

    /// Neighbour that already transmitted this id, heard `heard_from`, and can finish delivery.
    fn better_positioned_neighbor(
        &self,
        heard_from: u32,
        destination: u32,
        now_ms: u32,
        has_transmitted: &impl Fn(u32) -> bool,
    ) -> bool {
        let Some(mine) = self.edges.find_node(self.my_node) else {
            return false;
        };
        mine.edges[..mine.edge_count as usize].iter().any(|e| {
            let n = e.to;
            n != heard_from
                && n != self.my_node
                && !is_placeholder_node(n)
                && self.capability.status(n) == CapabilityStatus::SrActive
                && has_transmitted(n)
                && can_deliver(self.edges, Some(self.capability), heard_from, n)
                && self.reaches(n, destination, now_ms)
        })
    }
}

/// Rank the relay candidates for a unicast we overheard.
///
/// `my_next_hop` is what our route picker answered for `destination` (0 = no route, our own
/// id = "relay it ourselves"). A neighbour that does not hear `heard_from` is not a candidate:
/// a path to the destination is not evidence they received this copy. Returns the plan with our
/// slot, or the reason we stay silent.
///
/// A priced hop to the destination is a last hop: at most two such links if dest is SR, else
/// one. The extra directs return [`SrSkipReason::LastHopReserved`]. Indirect candidates still
/// get slots. When two or more non-direct candidates remain, the last of them is the flood
/// slot (`BroadcastRelayPlan::nonfinal_flood`).
pub fn plan_unicast_relay(
    ctx: &UnicastRelayContext<'_>,
    packet_id: u32,
    source: u32,
    heard_from: u32,
    destination: u32,
    my_next_hop: u32,
    now_ms: u32,
    has_transmitted: impl Fn(u32) -> bool,
) -> Result<BroadcastRelayPlan, SrSkipReason> {
    let me = ctx.my_node;

    let source_relay = ctx.downstream_relay(source, now_ms);
    if let Some(relay) = source_relay {
        if source_relay == ctx.downstream_relay(destination, now_ms) && relay != me {
            // Only if that gateway already holds this copy — otherwise we may be the sole hearer.
            if relay == heard_from || has_transmitted(relay) {
                return Err(SrSkipReason::UnicastCovered);
            }
        }
    }

    if heard_from != 0 && heard_from != me && heard_from != source {
        if ctx.reaches(heard_from, destination, now_ms) {
            return Err(SrSkipReason::UnicastCovered);
        }
        if ctx.better_positioned_neighbor(heard_from, destination, now_ms, &has_transmitted) {
            return Err(SrSkipReason::UnicastCovered);
        }
    }

    let mut candidates = [UnicastCandidate::default(); MAX_UNICAST_CANDIDATES];
    let mut count = 0usize;

    let mut my_cost = ctx.candidate_cost(me, destination, my_next_hop, now_ms);
    if my_cost == NO_PATH && (my_next_hop == me || my_next_hop == 0) {
        // The route picker fell back to us (or has no coordinated hop at all): stay in the
        // ranking as the last resort so the packet is not dropped when nobody else qualifies.
        my_cost = BEST_EFFORT_SELF_COST;
    }
    if my_cost != NO_PATH {
        candidates[count] = UnicastCandidate {
            node_id: me,
            cost: my_cost,
        };
        count += 1;
    }

    if let Some(mine) = ctx.edges.find_node(me) {
        for edge in &mine.edges[..mine.edge_count as usize] {
            let n = edge.to;
            if n == heard_from || n == source || n == me || is_placeholder_node(n) {
                continue;
            }
            if ctx.capability.is_legacy_router(n)
                || ctx.capability.status(n) != CapabilityStatus::SrActive
            {
                continue;
            }
            if !ctx.heard_this_copy(heard_from, n) {
                continue;
            }
            let cost = ctx.candidate_cost(n, destination, my_next_hop, now_ms);
            if cost != NO_PATH && count < MAX_UNICAST_CANDIDATES {
                candidates[count] = UnicastCandidate { node_id: n, cost };
                count += 1;
            }
        }
    }

    // Ascending cost; equal costs ordered by node id, direction chosen by packet-id parity so
    // no node is favoured across packets.
    for i in 1..count {
        let mut j = i;
        while j > 0 && ranked_ahead(candidates[j], candidates[j - 1], packet_id) {
            candidates.swap(j, j - 1);
            j -= 1;
        }
    }

    // Last hop: at most two priced links if dest is SR (early + dest-ACK backup), otherwise
    // one. Indirect candidates stay so the packet can still reach that link.
    let dest_sr = ctx.capability.status(destination).is_signal_routing();
    let i_am_direct = candidates[..count]
        .iter()
        .any(|c| c.node_id == me && c.cost < DOWNSTREAM_TIER_COST);
    if count > 0 && candidates[0].cost < DOWNSTREAM_TIER_COST {
        let max_directs = if dest_sr { 2usize } else { 1 };
        let mut kept = 0usize;
        let mut kept_directs = 0usize;
        for i in 0..count {
            let direct = candidates[i].cost < DOWNSTREAM_TIER_COST;
            if direct {
                if kept_directs >= max_directs {
                    continue;
                }
                kept_directs += 1;
            }
            candidates[kept] = candidates[i];
            kept += 1;
        }
        count = kept;
        if i_am_direct && !candidates[..count].iter().any(|c| c.node_id == me) {
            return Err(SrSkipReason::LastHopReserved);
        }
    }

    let mut plan = BroadcastRelayPlan {
        reason: RelayReason::UnicastCost,
        ..Default::default()
    };
    for candidate in &candidates[..count] {
        crate::broadcast_relay::push_evaluated(
            &mut plan.evaluated,
            &mut plan.evaluated_len,
            candidate.node_id,
            0,
            0,
            candidate.cost,
        );
    }
    let mut slot = 0u8;
    let mut my_slot = None;
    let mut my_direct = false;
    let mut last_non_direct_slot = None;
    let mut non_direct_slots = 0u8;
    for candidate in &candidates[..count] {
        if has_transmitted(candidate.node_id) {
            continue;
        }
        let direct = candidate.cost < DOWNSTREAM_TIER_COST;
        if !direct {
            last_non_direct_slot = Some(slot);
            non_direct_slots = non_direct_slots.saturating_add(1);
        }
        if (plan.ranked_len as usize) < RANKED_LOG {
            plan.ranked[plan.ranked_len as usize] = candidate.node_id;
            plan.ranked_len += 1;
        }
        if candidate.node_id == me {
            my_slot = Some(slot);
            my_direct = direct;
        }
        slot = slot.saturating_add(1);
    }
    let Some(my_slot) = my_slot else {
        return Err(SrSkipReason::NoRelayPath);
    };
    plan.should_relay = true;
    plan.slot_index = my_slot;
    plan.candidate_count = slot.max(1);
    plan.last_hop_backup = my_direct && dest_sr && my_slot == 1;
    plan.has_nonfinal_flood_slot = non_direct_slots >= 2;
    plan.nonfinal_flood =
        !my_direct && non_direct_slots >= 2 && last_non_direct_slot == Some(my_slot);
    Ok(plan)
}

pub fn unicast_dupe_cancels(
    ctx: &UnicastRelayContext<'_>,
    packet_id: u32,
    destination: u32,
    my_next_hop: u32,
    now_ms: u32,
    dupe_relayer: Option<u32>,
) -> bool {
    unicast_dupe_cancels_for(
        ctx,
        packet_id,
        destination,
        my_next_hop,
        now_ms,
        dupe_relayer,
        UnicastSlotFlags::default(),
        0,
        0,
        0,
    )
}

/// Whether a heard unicast copy should pull back our pending relay.
///
/// Cancel when the transmitter can finish (priced hop / dest's downstream) or is ranked ahead of
/// us with a path. Keep when we can finish and they cannot. An unresolved relay byte is treated
/// as a designated/stock hop we were waiting for only if we cannot finish ourselves.
///
/// Last-hop backup: only dest's own copy (or dest ACK, handled elsewhere) cancels. A flood slot
/// stays for a same-hop named SR copy that cannot finish, and cancels when the nominated hop,
/// dest, a finisher, or another flood copy is heard.
///
/// Named backup: hearing the designated `next_hop` byte (or a lower hop_limit still naming it)
/// cancels even when `can_finish` is unknown — boot graphs must not keep the backup.
pub fn unicast_dupe_cancels_for(
    ctx: &UnicastRelayContext<'_>,
    packet_id: u32,
    destination: u32,
    my_next_hop: u32,
    now_ms: u32,
    dupe_relayer: Option<u32>,
    flags: UnicastSlotFlags,
    dupe_next_hop: u8,
    dupe_relay_byte: u8,
    dupe_hop_limit: u8,
) -> bool {
    // Named-backup cancel that does not need a complete graph: the byte on the wire is enough.
    if flags.designated_next_hop != 0 {
        if dupe_relay_byte == flags.designated_next_hop {
            return true;
        }
        if let Some(relayer) = dupe_relayer {
            if relayer != 0
                && !is_placeholder_node(relayer)
                && (relayer & 0xFF) as u8 == flags.designated_next_hop
            {
                return true;
            }
        }
        // Designation progressed: same next_hop byte, strictly fewer hops remaining.
        if dupe_next_hop == flags.designated_next_hop
            && flags.armed_hop_limit != 0
            && dupe_hop_limit < flags.armed_hop_limit
        {
            return true;
        }
    }

    let me = ctx.my_node;
    let we_finish = ctx.can_finish(me, destination, now_ms);
    let Some(relayer) = dupe_relayer.filter(|&n| n != 0 && n != me && !is_placeholder_node(n)) else {
        return !we_finish;
    };
    if flags.last_hop_backup {
        return relayer == destination;
    }
    if flags.nonfinal_flood {
        if relayer == destination {
            return true;
        }
        if ctx.can_finish(relayer, destination, now_ms) {
            return true;
        }
        let nominated = flags.nominated_next_hop;
        if nominated != 0
            && (relayer == nominated || (nominated & 0xFF) as u8 == (relayer & 0xFF) as u8)
        {
            return true;
        }
        if dupe_next_hop == 0 {
            return true;
        }
        return false;
    }
    if ctx.can_finish(relayer, destination, now_ms) {
        return true;
    }
    if we_finish {
        return false;
    }
    let their_cost = ctx.candidate_cost(relayer, destination, my_next_hop, now_ms);
    if their_cost == NO_PATH {
        return false;
    }
    let mut my_cost = ctx.candidate_cost(me, destination, my_next_hop, now_ms);
    if my_cost == NO_PATH {
        my_cost = BEST_EFFORT_SELF_COST;
    }
    ranked_ahead(
        UnicastCandidate {
            node_id: relayer,
            cost: their_cost,
        },
        UnicastCandidate {
            node_id: me,
            cost: my_cost,
        },
        packet_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::EdgeSource;

    const ME: u32 = 0x046b_553a;
    const PEER: u32 = 0xbdac_ce55;
    const GW: u32 = 0x63dc_8f8c;
    const PHONE: u32 = 0x979e_d146;
    const DEST: u32 = 0x32ac_a541;
    const NOW: u32 = 846_000;
    const TTL: u32 = 7_200_000;

    struct Fixture {
        edges: EdgeStore,
        capability: CapabilityCache,
        downstream: DownstreamTable,
    }

    impl Fixture {
        fn ctx(&self) -> UnicastRelayContext<'_> {
            UnicastRelayContext {
                my_node: ME,
                edges: &self.edges,
                capability: &self.capability,
                downstream: &self.downstream,
                downstream_ttl_ms: TTL,
            }
        }
    }

    /// The 2026-09-03 17:12 field case: the phone (SR-passive) sends a traceroute to a node
    /// downstream of the gateway. We, our SR peer and the gateway all hear the phone directly.
    /// Nobody has received the gateway's topology yet; the destination is only known from the
    /// downstream table.
    fn field_fixture() -> Fixture {
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let mut downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, NOW);
        for (n, etx) in [(GW, 1.5), (PEER, 1.0), (PHONE, 1.1)] {
            edges.update_edge(ME, ME, n, etx, NOW, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(ME, n, true);
        }
        // The phone lists all three of us and reports that we hear it; the peer lists us and the phone.
        for n in [ME, PEER, GW] {
            edges.update_edge(ME, PHONE, n, 1.2, NOW, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(PHONE, n, true);
        }
        for n in [ME, PHONE] {
            edges.update_edge(ME, PEER, n, 1.2, NOW, EdgeSource::Reported, true, 0);
        }
        capability.track_topology(GW, true, NOW);
        capability.track_topology(PEER, true, NOW);
        capability.track_topology(PHONE, false, NOW);
        downstream.update(ME, DEST, GW, 2.0, NOW, false, 0);
        Fixture {
            edges,
            capability,
            downstream,
        }
    }

    #[test]
    fn gateway_holding_the_destination_downstream_outranks_us() {
        let f = field_fixture();
        let plan = plan_unicast_relay(&f.ctx(), 0xe0c9_25e5, PHONE, PHONE, DEST, GW, NOW, |_| {
            false
        })
        .expect("we are a candidate");
        assert!(plan.should_relay);
        assert_eq!(plan.slot_index, 1, "gateway takes slot 0, we follow");
        assert_eq!(
            plan.candidate_count, 2,
            "the peer has no path and is not a candidate"
        );
        assert_eq!(&plan.ranked[..2], &[GW, ME]);
        assert_eq!(plan.reason, RelayReason::UnicastCost);
    }

    #[test]
    fn chained_downstream_gateway_outranks_us() {
        const PARENT: u32 = 0x1100_0011;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let mut downstream = DownstreamTable::new();
        edges.ensure_local_node(ME, NOW);
        for n in [GW, PEER] {
            edges.update_edge(ME, ME, n, 1.5, NOW, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(ME, n, true);
        }
        capability.track_topology(GW, true, NOW);
        capability.track_topology(PEER, true, NOW);
        downstream.update(ME, DEST, PARENT, 2.0, NOW, false, 0);
        downstream.update(ME, PARENT, GW, 2.0, NOW, false, 0);
        edges.update_edge(ME, GW, PHONE, 1.5, NOW, EdgeSource::Reported, true, 0);
        let ctx = UnicastRelayContext {
            my_node: ME,
            edges: &edges,
            capability: &capability,
            downstream: &downstream,
            downstream_ttl_ms: TTL,
        };
        let plan = plan_unicast_relay(&ctx, 0x20, PHONE, PHONE, DEST, GW, NOW, |_| false)
            .expect("we are a candidate");
        assert_eq!(plan.ranked[0], GW);
        assert!(plan.slot_index >= 1);
    }

    #[test]
    fn node_id_no_longer_decides_the_order() {
        // Same graph, but swap which node is us: the peer (high id) sees the same ordering.
        let mut f = field_fixture();
        // The peer's own edges: it hears the gateway too, so it is an indirect candidate.
        f.edges
            .update_edge(PEER, PEER, GW, 1.6, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(PEER, GW, true);
        f.edges
            .update_edge(PEER, PEER, ME, 1.0, NOW, EdgeSource::Reported, true, 0);
        let mut ctx = f.ctx();
        ctx.my_node = PEER;
        let plan = plan_unicast_relay(&ctx, 0xe0c9_25e5, PHONE, PHONE, DEST, GW, NOW, |_| false)
            .expect("candidate");
        assert_eq!(plan.ranked[0], GW);
        assert!(plan.slot_index >= 1);
    }

    #[test]
    fn gateway_that_already_transmitted_frees_slot_zero() {
        let f = field_fixture();
        let plan = plan_unicast_relay(&f.ctx(), 0xe0c9_25e5, PHONE, PHONE, DEST, GW, NOW, |n| {
            n == GW
        })
        .expect("candidate");
        assert_eq!(plan.slot_index, 0);
        assert_eq!(plan.candidate_count, 1);
    }

    #[test]
    fn direct_edge_beats_downstream_beats_indirect() {
        let mut f = field_fixture();
        // The peer now reports a direct edge to the destination.
        f.edges
            .update_edge(ME, PEER, DEST, 3.0, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(PEER, DEST, true);
        let plan = plan_unicast_relay(&f.ctx(), 0xe0c9_25e5, PHONE, PHONE, DEST, GW, NOW, |_| {
            false
        })
        .expect("candidate");
        assert_eq!(&plan.ranked[..3], &[PEER, GW, ME]);
        assert_eq!(plan.slot_index, 2);
    }

    /// Field case of 2026-09-03 23:18 (cfd2d4da): A and B were both indirect-tier candidates whose
    /// costs differed by a few hundredths in opposite directions on each node, so each ranked the
    /// other first, both took slot 3 and collided. Half-ETX buckets make them tie, and the
    /// packet-id parity picks the same node on both.
    #[test]
    fn near_equal_costs_fall_to_the_node_id_tie_break() {
        let mut f = field_fixture();
        // Our own link to the gateway prices at 1.31, the peer's reported one at 1.18.
        f.edges
            .update_edge(ME, ME, GW, 1.31, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(ME, GW, true);
        f.edges
            .update_edge(ME, PEER, GW, 1.18, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(PEER, GW, true);
        // Even id: lower node id first, although our own link is the dearer one.
        let even = plan_unicast_relay(&f.ctx(), 0xcfd2_d4da, PHONE, PHONE, DEST, GW, NOW, |_| {
            false
        })
        .unwrap();
        assert_eq!(&even.ranked[..3], &[GW, ME, PEER]);
        assert!(even.has_nonfinal_flood_slot);
        assert!(
            !even.nonfinal_flood,
            "a named slot is not itself the flood slot"
        );
        // Odd id: higher node id first.
        let odd = plan_unicast_relay(&f.ctx(), 0xcfd2_d4db, PHONE, PHONE, DEST, GW, NOW, |_| {
            false
        })
        .unwrap();
        assert_eq!(&odd.ranked[..3], &[GW, PEER, ME]);
        // A genuinely worse own link (a full bucket apart, ETX cannot go below 1.0) loses
        // regardless of parity.
        f.edges
            .update_edge(ME, ME, GW, 1.6, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(ME, GW, true);
        let better = plan_unicast_relay(&f.ctx(), 0xcfd2_d4da, PHONE, PHONE, DEST, GW, NOW, |_| {
            false
        })
        .unwrap();
        assert_eq!(&better.ranked[..3], &[GW, PEER, ME]);
    }

    #[test]
    fn equal_costs_alternate_on_packet_id_parity() {
        let mut f = field_fixture();
        f.edges
            .update_edge(ME, PEER, DEST, 2.0, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(PEER, DEST, true);
        f.edges
            .update_edge(ME, ME, DEST, 2.0, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(ME, DEST, true);
        // DEST is not SR: only the cheapest direct gets a slot.
        let even =
            plan_unicast_relay(&f.ctx(), 0x10, PHONE, PHONE, DEST, DEST, NOW, |_| false).unwrap();
        assert_eq!(even.ranked[0], ME, "even id: low node id first");
        assert!(
            !even.ranked[..even.ranked_len as usize].contains(&PEER),
            "the other direct link does not get a slot"
        );
        let odd =
            plan_unicast_relay(&f.ctx(), 0x11, PHONE, PHONE, DEST, DEST, NOW, |_| false)
                .unwrap_err();
        assert_eq!(odd, SrSkipReason::LastHopReserved);
    }

    #[test]
    fn sr_dest_gives_two_last_hop_slots() {
        let mut f = field_fixture();
        f.capability.track_topology(DEST, true, NOW);
        f.edges
            .update_edge(ME, PEER, DEST, 2.0, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(PEER, DEST, true);
        f.edges
            .update_edge(ME, ME, DEST, 2.0, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(ME, DEST, true);
        let even =
            plan_unicast_relay(&f.ctx(), 0x10, PHONE, PHONE, DEST, DEST, NOW, |_| false).unwrap();
        assert_eq!(even.ranked[0], ME);
        assert!(
            even.ranked[..even.ranked_len as usize].contains(&PEER),
            "next-best last hop still gets a dest-ACK slot"
        );
        assert!(!even.last_hop_backup);
        let odd =
            plan_unicast_relay(&f.ctx(), 0x11, PHONE, PHONE, DEST, DEST, NOW, |_| false).unwrap();
        assert_eq!(odd.ranked[0], PEER);
        assert!(odd.last_hop_backup);
    }

    #[test]
    fn last_non_direct_of_two_is_the_flood_slot() {
        let f = field_fixture();
        let plan = plan_unicast_relay(&f.ctx(), 0xe0c9_25e5, PHONE, PHONE, DEST, GW, NOW, |_| {
            false
        })
        .expect("we are a candidate");
        assert_eq!(plan.slot_index, 1);
        assert!(plan.has_nonfinal_flood_slot);
        assert!(plan.nonfinal_flood, "last ranked non-direct floods");
    }

    #[test]
    fn flood_slot_stays_for_named_sr_that_cannot_finish() {
        let f = field_fixture();
        let flags = UnicastSlotFlags {
            nonfinal_flood: true,
            nominated_next_hop: GW,
            ..Default::default()
        };
        assert!(
            !unicast_dupe_cancels_for(
                &f.ctx(),
                0x40,
                DEST,
                GW,
                NOW,
                Some(PEER),
                flags,
                (PEER & 0xFF) as u8,
                0,
                0,
            ),
            "a named same-hop SR that cannot finish is not dest's ACK"
        );
        assert!(unicast_dupe_cancels_for(
            &f.ctx(),
            0x40,
            DEST,
            GW,
            NOW,
            Some(GW),
            flags,
            0,
            0,
            0,
        ));
        assert!(unicast_dupe_cancels_for(
            &f.ctx(),
            0x40,
            DEST,
            GW,
            NOW,
            Some(DEST),
            flags,
            0,
            0,
            0,
        ));
        assert!(
            unicast_dupe_cancels_for(&f.ctx(), 0x40, DEST, GW, NOW, Some(PEER), flags, 0, 0, 0),
            "another flood copy cancels"
        );
    }

    #[test]
    fn named_backup_cancels_on_designated_hop_without_finish_proof() {
        // Empty graph: cannot can_finish anyone toward DEST. Hearing the designated byte must
        // still cancel — the field failure when a thin boot graph kept the backup after Czar.
        let edges = EdgeStore::new();
        let capability = CapabilityCache::new();
        let downstream = DownstreamTable::new();
        let ctx = UnicastRelayContext {
            my_node: ME,
            edges: &edges,
            capability: &capability,
            downstream: &downstream,
            downstream_ttl_ms: TTL,
        };
        let gw_byte = (GW & 0xFF) as u8;
        let peer_byte = (PEER & 0xFF) as u8;
        let flags = UnicastSlotFlags {
            designated_next_hop: gw_byte,
            armed_hop_limit: 7,
            ..Default::default()
        };
        assert!(!ctx.can_finish(GW, DEST, NOW));
        assert!(
            unicast_dupe_cancels_for(&ctx, 0x50, DEST, 0, NOW, None, flags, 0, gw_byte, 6),
            "relay byte matching designated next_hop cancels even when identity is unresolved"
        );
        assert!(
            unicast_dupe_cancels_for(&ctx, 0x51, DEST, 0, NOW, Some(GW), flags, 0, 0, 6),
            "resolved designated hop cancels without finish proof"
        );
        assert!(
            unicast_dupe_cancels_for(
                &ctx,
                0x52,
                DEST,
                0,
                NOW,
                Some(PEER),
                flags,
                gw_byte,
                peer_byte,
                5,
            ),
            "lower hop_limit still naming the designation means that hop progressed"
        );
        assert!(
            !unicast_dupe_cancels_for(
                &ctx,
                0x53,
                DEST,
                0,
                NOW,
                Some(PEER),
                flags,
                0,
                peer_byte,
                6,
            ),
            "an unrelated peer copy does not cancel on designation alone when finish/rank are unknown"
        );
    }

    #[test]
    fn last_hop_backup_does_not_cancel_on_the_other_direct() {
        let mut f = field_fixture();
        f.capability.track_topology(DEST, true, NOW);
        f.edges
            .update_edge(ME, ME, DEST, 1.2, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(ME, DEST, true);
        let flags = UnicastSlotFlags {
            last_hop_backup: true,
            ..Default::default()
        };
        assert!(
            !unicast_dupe_cancels_for(&f.ctx(), 0x40, DEST, DEST, NOW, Some(PEER), flags, 0, 0, 0),
            "another last hop is not dest's ACK"
        );
        assert!(unicast_dupe_cancels_for(
            &f.ctx(),
            0x40,
            DEST,
            DEST,
            NOW,
            Some(DEST),
            flags,
            0,
            0,
            0,
        ));
    }

    #[test]
    fn relayer_that_reaches_the_destination_suppresses_us() {
        let f = field_fixture();
        // Heard from the gateway itself, which holds the destination downstream.
        let err =
            plan_unicast_relay(&f.ctx(), 0x20, PHONE, GW, DEST, GW, NOW, |_| false).unwrap_err();
        assert_eq!(err, SrSkipReason::UnicastCovered);
    }

    #[test]
    fn sr_neighbour_must_have_transmitted_to_suppress_us() {
        let mut f = field_fixture();
        // DEST publishes: PEER does not reach it without confirmation. GW hears PEER and holds
        // DEST downstream — but must have transmitted this id before we stand down.
        f.capability.track_topology(DEST, true, NOW);
        f.edges
            .update_edge(ME, GW, PEER, 1.3, NOW, EdgeSource::Reported, true, 0);
        assert!(
            plan_unicast_relay(&f.ctx(), 0x21, PHONE, PEER, DEST, GW, NOW, |_| false).is_ok(),
            "possible coverer without a heard copy must not suppress"
        );
        let err = plan_unicast_relay(&f.ctx(), 0x21, PHONE, PEER, DEST, GW, NOW, |n| n == GW)
            .unwrap_err();
        assert_eq!(err, SrSkipReason::UnicastCovered);
    }

    #[test]
    fn shared_downstream_suppresses_only_when_gateway_holds_copy() {
        let mut f = field_fixture();
        f.downstream.update(ME, PHONE, GW, 2.0, NOW, false, 0);
        assert!(
            plan_unicast_relay(&f.ctx(), 0x22, PHONE, PHONE, DEST, GW, NOW, |_| false).is_ok(),
            "shared GW not known to hold this copy must not suppress"
        );
        let from_gw =
            plan_unicast_relay(&f.ctx(), 0x22, PHONE, GW, DEST, GW, NOW, |_| false).unwrap_err();
        assert_eq!(from_gw, SrSkipReason::UnicastCovered);
        let tx_gw = plan_unicast_relay(&f.ctx(), 0x22, PHONE, PHONE, DEST, GW, NOW, |n| n == GW)
            .unwrap_err();
        assert_eq!(tx_gw, SrSkipReason::UnicastCovered);
    }

    #[test]
    fn best_effort_self_when_route_picker_falls_back_to_us() {
        let f = field_fixture();
        let plan = plan_unicast_relay(&f.ctx(), 0x23, PHONE, PHONE, 0x1111_1111, ME, NOW, |_| {
            false
        })
        .expect("sole candidate");
        assert_eq!(plan.slot_index, 0);
        assert_eq!(plan.candidate_count, 1);
    }

    #[test]
    fn one_way_list_to_publishing_dest_is_not_a_direct_path() {
        let mut f = field_fixture();
        f.capability.track_topology(DEST, true, NOW);
        f.edges
            .update_edge(ME, ME, DEST, 1.0, NOW, EdgeSource::Reported, true, 0);
        let plan = plan_unicast_relay(&f.ctx(), 0x30, PHONE, PHONE, DEST, GW, NOW, |_| false)
            .expect("still an indirect/downstream candidate");
        assert_eq!(
            plan.ranked[0], GW,
            "listing DEST without DEST hearing us must not win slot 0"
        );
    }

    #[test]
    fn no_path_and_a_real_next_hop_means_no_slot() {
        let mut f = field_fixture();
        // We lost our edge to the gateway and the route names a node we have no edge to:
        // no direct, downstream or indirect path for anyone.
        f.edges.remove_edges_to(GW);
        let err = plan_unicast_relay(&f.ctx(), 0x24, PHONE, PHONE, DEST, 0x5555_5555, NOW, |_| {
            false
        })
        .unwrap_err();
        assert_eq!(err, SrSkipReason::NoRelayPath);
    }

    #[test]
    fn neighbour_that_does_not_hear_the_transmitter_gets_no_slot() {
        const OURS: u32 = 0xAA00_00AA;
        const HUB: u32 = 0xBB00_00BB;
        const TX: u32 = 0x1100_0011;
        const FAR: u32 = 0x2200_0022;
        let mut edges = EdgeStore::new();
        let mut capability = CapabilityCache::new();
        let mut downstream = DownstreamTable::new();
        edges.ensure_local_node(OURS, NOW);
        for n in [HUB, TX] {
            edges.update_edge(OURS, OURS, n, 1.5, NOW, EdgeSource::Reported, true, 0);
            edges.set_edge_hears_us(OURS, n, true);
        }
        capability.track_topology(HUB, true, NOW);
        downstream.update(OURS, FAR, HUB, 2.0, NOW, false, 0);
        let ctx = UnicastRelayContext {
            my_node: OURS,
            edges: &edges,
            capability: &capability,
            downstream: &downstream,
            downstream_ttl_ms: TTL,
        };
        let plan = plan_unicast_relay(&ctx, 0x40, TX, TX, FAR, HUB, NOW, |_| false)
            .expect("we overheard the copy");
        assert_eq!(plan.slot_index, 0);
        assert_eq!(plan.candidate_count, 1);
        assert_eq!(plan.ranked[0], OURS);
        assert!(
            !plan.ranked[..plan.ranked_len as usize].contains(&HUB),
            "a path to dest is not evidence HUB received this copy"
        );
    }

    #[test]
    fn dupe_cancels_when_the_relayer_can_finish() {
        let f = field_fixture();
        assert!(unicast_dupe_cancels(
            &f.ctx(),
            0x30,
            DEST,
            GW,
            NOW,
            Some(GW)
        ));
    }

    #[test]
    fn dupe_kept_when_we_can_finish_and_they_cannot() {
        let mut f = field_fixture();
        f.edges
            .update_edge(ME, ME, DEST, 1.2, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(ME, DEST, true);
        f.capability.track_topology(DEST, true, NOW);
        assert!(
            !unicast_dupe_cancels(&f.ctx(), 0x31, DEST, GW, NOW, Some(PEER)),
            "PEER cannot finish; we can"
        );
        assert!(
            !unicast_dupe_cancels(&f.ctx(), 0x31, DEST, GW, NOW, None),
            "unresolved copy must not kill a last hop we can finish"
        );
    }

    #[test]
    fn dupe_cancels_when_relayer_is_ranked_ahead_with_a_path() {
        let mut f = field_fixture();
        f.edges
            .update_edge(ME, PEER, GW, 1.5, NOW, EdgeSource::Reported, true, 0);
        f.edges.set_edge_hears_us(PEER, GW, true);
        f.capability.track_topology(PEER, true, NOW);
        // Neither finishes (DEST is GW's downstream). Equal indirect costs: even id ranks
        // the lower id (ME) first, so PEER is behind us and we keep.
        assert!(!unicast_dupe_cancels(
            &f.ctx(),
            0x32,
            DEST,
            GW,
            NOW,
            Some(PEER)
        ));
        // Odd id: higher id first, PEER is ahead.
        assert!(unicast_dupe_cancels(
            &f.ctx(),
            0x33,
            DEST,
            GW,
            NOW,
            Some(PEER)
        ));
    }

    #[test]
    fn dupe_kept_when_relayer_has_no_path() {
        let f = field_fixture();
        assert!(
            !unicast_dupe_cancels(&f.ctx(), 0x35, DEST, GW, NOW, Some(PEER)),
            "a copy from a node with no path must not kill our slot"
        );
    }

    #[test]
    fn unresolved_dupe_cancels_when_we_cannot_finish() {
        let f = field_fixture();
        assert!(unicast_dupe_cancels(&f.ctx(), 0x34, DEST, GW, NOW, None));
        assert!(
            unicast_dupe_cancels(&f.ctx(), 0x34, DEST, GW, NOW, Some(0xFF00_0099)),
            "a placeholder relay byte is the designated hop we were waiting for"
        );
    }
}
