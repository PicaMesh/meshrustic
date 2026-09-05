//! Cost-ranked relay coordination for unicasts.
//!
//! Mirrors the fork's `shouldRelayUnicastForCoordination`: every SR node that overhears a
//! unicast computes the same candidate ordering from its graph, so the node best placed to
//! deliver the packet keys up first and everybody else cancels on its copy. Candidates are
//! ourselves plus our SR-active direct neighbours, ranked by cost to the destination:
//!
//! - direct edge to the destination: the edge's ETX (`0x0064..0x7FFE`);
//! - known downstream relay of the destination: [`DOWNSTREAM_TIER_COST`], after any direct
//!   edge but ahead of every indirect candidate (the fork has no downstream tier; MeshRustic
//!   adds it because the downstream table is often the only knowledge we have of a gateway's
//!   branch before its topology report arrives);
//! - edge to the shared next hop only: the edge's ETX with [`INDIRECT_TIER`] set.
//!
//! Costs are compared in buckets of [`COST_BUCKET_FIXED`] (half an ETX). Each node prices its own
//! link from its own measurements and a peer's link from the peer's packed report, so two
//! near-equal costs differ by a few hundredths on every node, in a direction that varies. Exact
//! comparison then ranked the two colocated nicenanos in opposite orders (each behind the other),
//! both took the same slot and keyed up together. Within a bucket, ties are broken by node id, low
//! first on even packet ids and high first on odd ones, as the fork does. Before ranking, the
//! packet is suppressed outright when the transmitter or an SR neighbour that covers the
//! transmitter can already deliver it.

use crate::broadcast_relay::{BroadcastRelayPlan, RelayReason, RANKED_LOG};
use crate::capability::{CapabilityCache, CapabilityStatus};
use crate::graph::{is_placeholder_node, DownstreamTable, EdgeStore, MAX_EDGES_PER_NODE};
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

impl UnicastRelayContext<'_> {
    fn has_edge(&self, from: u32, to: u32) -> bool {
        self.edges
            .find_node(from)
            .and_then(|n| n.find_edge(to))
            .is_some()
    }

    fn edge_cost(&self, from: u32, to: u32) -> Option<u16> {
        self.edges
            .find_node(from)
            .and_then(|n| n.find_edge(to))
            .map(|e| e.etx_fixed)
    }

    fn downstream_relay(&self, destination: u32, now_ms: u32) -> Option<u32> {
        self.downstream
            .get_relay(destination, now_ms, self.downstream_ttl_ms)
    }

    /// `node` can hand the packet to `destination` without another SR hop.
    fn reaches(&self, node: u32, destination: u32, now_ms: u32) -> bool {
        self.has_edge(node, destination) || self.downstream_relay(destination, now_ms) == Some(node)
    }

    fn candidate_cost(&self, node: u32, destination: u32, my_next_hop: u32, now_ms: u32) -> u16 {
        if let Some(cost) = self.edge_cost(node, destination) {
            return bucket(cost.min(DOWNSTREAM_TIER_COST - 1));
        }
        if self.downstream_relay(destination, now_ms) == Some(node) {
            return DOWNSTREAM_TIER_COST;
        }
        // An edge to the shared next hop is a path only when that hop is a real forwarder:
        // when the route picker fell back to us, a neighbour reaching us gets nowhere.
        if my_next_hop != 0
            && my_next_hop != destination
            && my_next_hop != node
            && my_next_hop != self.my_node
        {
            if let Some(cost) = self.edge_cost(node, my_next_hop) {
                return bucket(cost.min(INDIRECT_TIER - 1)) | INDIRECT_TIER;
            }
        }
        NO_PATH
    }

    /// An SR-active neighbour of ours that hears `heard_from` and can deliver to `destination`
    /// is better placed than we are: it holds the packet already and needs no extra hop.
    fn better_positioned_neighbor(&self, heard_from: u32, destination: u32, now_ms: u32) -> bool {
        let Some(mine) = self.edges.find_node(self.my_node) else {
            return false;
        };
        mine.edges[..mine.edge_count as usize].iter().any(|e| {
            let n = e.to;
            n != heard_from
                && n != self.my_node
                && !is_placeholder_node(n)
                && self.capability.status(n) == CapabilityStatus::SrActive
                && self.has_edge(n, heard_from)
                && self.reaches(n, destination, now_ms)
        })
    }
}

/// Rank the relay candidates for a unicast we overheard.
///
/// `my_next_hop` is what our route picker answered for `destination` (0 = no route, our own
/// id = "relay it ourselves"). Returns the plan with our slot, or the reason we stay silent.
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

    // Source and destination hang off the same relay: that relay delivers on its own.
    let source_relay = ctx.downstream_relay(source, now_ms);
    if source_relay.is_some()
        && source_relay == ctx.downstream_relay(destination, now_ms)
        && source_relay != Some(me)
    {
        return Err(SrSkipReason::UnicastCovered);
    }

    if heard_from != 0 && heard_from != me && heard_from != source {
        // The relayer we heard already reaches the destination; handing it back is a dupe.
        if ctx.reaches(heard_from, destination, now_ms) {
            return Err(SrSkipReason::UnicastCovered);
        }
        if ctx.better_positioned_neighbor(heard_from, destination, now_ms) {
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
            let cost = ctx.candidate_cost(n, destination, my_next_hop, now_ms);
            if cost != NO_PATH && count < MAX_UNICAST_CANDIDATES {
                candidates[count] = UnicastCandidate { node_id: n, cost };
                count += 1;
            }
        }
    }

    // Ascending cost; equal costs ordered by node id, direction chosen by packet-id parity so
    // no node is favoured across packets (same rule as the fork).
    let prefer_high_id = packet_id & 1 != 0;
    let ahead = |a: &UnicastCandidate, b: &UnicastCandidate| {
        a.cost < b.cost
            || (a.cost == b.cost
                && if prefer_high_id {
                    a.node_id > b.node_id
                } else {
                    a.node_id < b.node_id
                })
    };
    for i in 1..count {
        let mut j = i;
        while j > 0 && ahead(&candidates[j], &candidates[j - 1]) {
            candidates.swap(j, j - 1);
            j -= 1;
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
            candidate.cost,
        );
    }
    let mut slot = 0u8;
    let mut my_slot = None;
    for candidate in &candidates[..count] {
        if has_transmitted(candidate.node_id) {
            continue;
        }
        if (plan.ranked_len as usize) < RANKED_LOG {
            plan.ranked[plan.ranked_len as usize] = candidate.node_id;
            plan.ranked_len += 1;
        }
        if candidate.node_id == me {
            my_slot = Some(slot);
        }
        slot = slot.saturating_add(1);
    }
    let Some(my_slot) = my_slot else {
        return Err(SrSkipReason::NoRelayPath);
    };
    plan.should_relay = true;
    plan.slot_index = my_slot;
    plan.candidate_count = slot.max(1);
    Ok(plan)
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
        }
        // The phone lists all three of us; the peer lists us and the phone.
        for n in [ME, PEER, GW] {
            edges.update_edge(ME, PHONE, n, 1.2, NOW, EdgeSource::Reported, true, 0);
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
    fn node_id_no_longer_decides_the_order() {
        // Same graph, but swap which node is us: the peer (high id) sees the same ordering.
        let mut f = field_fixture();
        // The peer's own edges: it hears the gateway too, so it is an indirect candidate.
        f.edges
            .update_edge(PEER, PEER, GW, 1.6, NOW, EdgeSource::Reported, true, 0);
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
        f.edges
            .update_edge(ME, PEER, GW, 1.18, NOW, EdgeSource::Reported, true, 0);
        // Even id: lower node id first, although our own link is the dearer one.
        let even = plan_unicast_relay(&f.ctx(), 0xcfd2_d4da, PHONE, PHONE, DEST, GW, NOW, |_| {
            false
        })
        .unwrap();
        assert_eq!(&even.ranked[..3], &[GW, ME, PEER]);
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
        f.edges
            .update_edge(ME, ME, DEST, 2.0, NOW, EdgeSource::Reported, true, 0);
        let even =
            plan_unicast_relay(&f.ctx(), 0x10, PHONE, PHONE, DEST, DEST, NOW, |_| false).unwrap();
        let odd =
            plan_unicast_relay(&f.ctx(), 0x11, PHONE, PHONE, DEST, DEST, NOW, |_| false).unwrap();
        assert_eq!(even.ranked[0], ME, "even id: low node id first");
        assert_eq!(odd.ranked[0], PEER, "odd id: high node id first");
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
    fn sr_neighbour_covering_the_relayer_suppresses_us() {
        let mut f = field_fixture();
        // Heard from the peer; the gateway hears the peer and reaches the destination.
        f.edges
            .update_edge(ME, GW, PEER, 1.3, NOW, EdgeSource::Reported, true, 0);
        let err =
            plan_unicast_relay(&f.ctx(), 0x21, PHONE, PEER, DEST, GW, NOW, |_| false).unwrap_err();
        assert_eq!(err, SrSkipReason::UnicastCovered);
    }

    #[test]
    fn shared_downstream_relay_suppresses_us() {
        let mut f = field_fixture();
        f.downstream.update(ME, PHONE, GW, 2.0, NOW, false, 0);
        let err =
            plan_unicast_relay(&f.ctx(), 0x22, PHONE, PHONE, DEST, GW, NOW, |_| false).unwrap_err();
        assert_eq!(err, SrSkipReason::UnicastCovered);
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
}
