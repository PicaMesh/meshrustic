//! Cross-preset bridge decisions (Phase 9).

use mesh_protocol::{NODENUM_BROADCAST, ParsedPacket};
use mesh_radio::{RadioId, MAX_BRIDGE_TARGETS, MAX_RADIOS};

use crate::graph::Route;
use crate::neighbor_graph::NeighborGraph;
use crate::qos::ChannelQoS;
use crate::relay::wire_may_relay;
use crate::router::{RelayPlan, TxPlan, MAX_WIRE_LEN};
use crate::sr_log::{SrLog, SrLogEvent};

const BRIDGE_DEDUP_SIZE: usize = 32;

#[derive(Clone, Copy, Default)]
struct BridgeDedupEntry {
    from: u32,
    id: u32,
    target_radio: RadioId,
}

/// Tracks recent `(from, id, target_radio)` bridge forwards (separate from RX dedup).
#[derive(Clone, Copy, Default)]
pub struct BridgeDedupCache {
    entries: [BridgeDedupEntry; BRIDGE_DEDUP_SIZE],
    head: usize,
}

impl BridgeDedupCache {
    pub const fn new() -> Self {
        Self {
            entries: [BridgeDedupEntry {
                from: 0,
                id: 0,
                target_radio: 0,
            }; BRIDGE_DEDUP_SIZE],
            head: 0,
        }
    }

    pub fn seen(&self, from: u32, id: u32, target_radio: RadioId) -> bool {
        if from == 0 || id == 0 {
            return false;
        }
        self.entries
            .iter()
            .any(|e| e.from == from && e.id == id && e.target_radio == target_radio)
    }

    pub fn remember(&mut self, from: u32, id: u32, target_radio: RadioId) {
        if from == 0 || id == 0 {
            return;
        }
        if self.seen(from, id, target_radio) {
            return;
        }
        self.entries[self.head] = BridgeDedupEntry {
            from,
            id,
            target_radio,
        };
        self.head = (self.head + 1) % BRIDGE_DEDUP_SIZE;
    }
}

/// Cross-preset forward leg queued on a target radio's TX queue.
#[derive(Clone, Copy)]
pub struct BridgeLeg {
    pub target_radio: RadioId,
    pub len: u8,
    pub bytes: [u8; MAX_WIRE_LEN],
}

impl Default for BridgeLeg {
    fn default() -> Self {
        Self {
            target_radio: 0,
            len: 0,
            bytes: [0; MAX_WIRE_LEN],
        }
    }
}

impl BridgeLeg {
    pub const MAX: usize = MAX_BRIDGE_TARGETS;
}

/// Inputs for bridge policy (read-only graph snapshot).
pub struct BridgeEval<'a> {
    pub rx_radio: RadioId,
    pub parsed: &'a ParsedPacket,
    pub route: Route,
    pub decoded_portnum: Option<u32>,
    pub chutil_pct: f32,
    pub now_ms: u32,
    pub from_us: bool,
    pub to_us: bool,
}

/// Whether a copy of `frame` should be forwarded on `dst_radio` instead of relaying on `rx_radio`.
pub fn should_bridge_to(
    eval: &BridgeEval<'_>,
    dst_radio: RadioId,
    graph: &NeighborGraph,
    dedup: &BridgeDedupCache,
    qos: &ChannelQoS,
) -> bool {
    if eval.parsed.id == 0 {
        return false;
    }
    if dst_radio == eval.rx_radio {
        return false;
    }
    if dst_radio as usize >= MAX_RADIOS {
        return false;
    }
    if dedup.seen(eval.parsed.from, eval.parsed.id, dst_radio) {
        return false;
    }
    if !wire_may_relay(eval.parsed, eval.from_us, eval.to_us) {
        return false;
    }
    if !qos.can_relay(
        eval.decoded_portnum,
        eval.parsed.channel,
        eval.chutil_pct,
    ) {
        return false;
    }
    routing_need(eval, dst_radio, graph)
}

fn routing_need(eval: &BridgeEval<'_>, dst_radio: RadioId, graph: &NeighborGraph) -> bool {
    if eval.parsed.to == NODENUM_BROADCAST {
        return graph.segment_has_uncovered_hears_us_neighbors(
            dst_radio,
            eval.parsed.id,
            eval.parsed.from,
            eval.now_ms,
        );
    }
    if eval.route.next_hop == 0 {
        return false;
    }
    if eval.route.egress_radio != dst_radio {
        return false;
    }
    eval.route.egress_radio != eval.rx_radio
}

/// Fill `plan.bridge` when another preset segment should carry this frame.
///
/// Returns `true` when a cross-preset bridge leg was queued (same-radio relay should be skipped).
pub fn evaluate_bridge_targets(
    eval: &BridgeEval<'_>,
    relay: &RelayPlan,
    graph: &mut NeighborGraph,
    dedup: &mut BridgeDedupCache,
    qos: &ChannelQoS,
    sr_log: &mut SrLog,
    node_num: u32,
    snr: i8,
    slot_ms: u32,
    plan: &mut TxPlan,
) -> bool {
    plan.bridge_count = 0;
    for leg in plan.bridge.iter_mut() {
        *leg = BridgeLeg::default();
    }

    if eval.parsed.to != NODENUM_BROADCAST
        && eval.route.next_hop != 0
        && eval.route.egress_radio != eval.rx_radio
    {
        let dst = eval.route.egress_radio;
        if should_bridge_to(eval, dst, graph, dedup, qos) {
            return enqueue_bridge_leg(
                eval,
                relay,
                dst,
                graph,
                dedup,
                sr_log,
                node_num,
                snr,
                slot_ms,
                plan,
            );
        }
        return false;
    }

    for dst in 0..MAX_RADIOS as RadioId {
        if dst == eval.rx_radio {
            continue;
        }
        if !should_bridge_to(eval, dst, graph, dedup, qos) {
            continue;
        }
        if enqueue_bridge_leg(
            eval,
            relay,
            dst,
            graph,
            dedup,
            sr_log,
            node_num,
            snr,
            slot_ms,
            plan,
        ) {
            return true;
        }
    }
    false
}

fn enqueue_bridge_leg(
    eval: &BridgeEval<'_>,
    relay: &RelayPlan,
    dst_radio: RadioId,
    graph: &mut NeighborGraph,
    dedup: &mut BridgeDedupCache,
    sr_log: &mut SrLog,
    node_num: u32,
    snr: i8,
    slot_ms: u32,
    plan: &mut TxPlan,
) -> bool {
    if plan.bridge_count as usize >= MAX_BRIDGE_TARGETS {
        return false;
    }
    let half_airtime = (slot_ms / 2).max(50);
    let (tx_after_ms, _, _) = graph.commit_relay(
        eval.parsed.from,
        eval.parsed.id,
        dst_radio,
        snr,
        eval.parsed.from,
        eval.now_ms,
        half_airtime,
        crate::coordinated_relay::DEFAULT_SLOT_MS,
        node_num,
    );
    let delay_ms = tx_after_ms.wrapping_sub(eval.now_ms);

    let idx = plan.bridge_count as usize;
    plan.bridge[idx] = BridgeLeg {
        target_radio: dst_radio,
        len: relay.len,
        bytes: relay.bytes,
    };
    plan.bridge_count += 1;
    dedup.remember(eval.parsed.from, eval.parsed.id, dst_radio);
    sr_log.push(SrLogEvent::BridgeForward {
        id: eval.parsed.id,
        from: eval.parsed.from,
        dest: eval.parsed.to,
        src_radio: eval.rx_radio,
        dst_radio,
        delay_ms,
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_protocol::PacketHeader;

    fn parsed_broadcast(from: u32) -> ParsedPacket {
        PacketHeader::from_fields(
            NODENUM_BROADCAST,
            from,
            1,
            0x77,
            3,
            3,
            false,
            false,
            0,
            0,
        )
        .parse()
    }

    fn parsed_unicast(from: u32, to: u32) -> ParsedPacket {
        PacketHeader::from_fields(to, from, 2, 0x77, 3, 3, false, false, 0, 0).parse()
    }

    #[test]
    fn dedup_suppresses_repeat_bridge() {
        let mut dedup = BridgeDedupCache::new();
        assert!(!dedup.seen(0xAA, 1, 1));
        dedup.remember(0xAA, 1, 1);
        assert!(dedup.seen(0xAA, 1, 1));
        assert!(!dedup.seen(0xAA, 2, 1));
    }

    #[test]
    fn unicast_bridges_when_egress_on_other_radio() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA00_00AA);
        graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 0, 0);
        graph.observe_direct_neighbor(0xCC00_00CC, -70, 8, 0, 1);
        let route = graph.route_to(0xCC00_00CC, 100);
        assert_eq!(route.egress_radio, 1);

        let parsed = parsed_unicast(0xBB00_00BB, 0xCC00_00CC);
        let eval = BridgeEval {
            rx_radio: 0,
            parsed: &parsed,
            route,
            decoded_portnum: None,
            chutil_pct: 0.0,
            now_ms: 100,
            from_us: false,
            to_us: false,
        };
        let dedup = BridgeDedupCache::new();
        let qos = ChannelQoS::new();
        assert!(should_bridge_to(&eval, 1, &graph, &dedup, &qos));
        assert!(!should_bridge_to(&eval, 0, &graph, &dedup, &qos));
    }
}
