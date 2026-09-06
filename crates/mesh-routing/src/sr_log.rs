//! SR routing decision log events (`[SR]` USB prefix).

pub const MAX_SR_LOG: usize = 64;
/// Destinations per downstream log line. Twelve ids fit a 256-byte USB line with room to
/// spare; the array also sets the size of every `SrLogEvent`, so it is not made larger.
pub const DOWNSTREAM_LOG_GROUP: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrLogEvent {
    ModuleInitialized {
        version: u8,
    },
    UsingNeighborGraph,
    Config {
        broadcast_secs: u16,
        dirty_secs: u16,
        node_ttl_secs: u32,
        max_hops: u8,
    },
    DirectNeighbor {
        node_id: u32,
        rssi: i16,
        snr: i8,
        is_new: bool,
    },
    PacketFrom {
        from: u32,
        relay_node: u8,
        hop_start: u8,
        hop_limit: u8,
        direct: bool,
    },
    /// A peer's topology report was accepted outside the forward version window: `last` was
    /// stored, `received` arrived after the peer's boot broadcast or two silent intervals.
    TopologyVersionResync {
        from: u32,
        received: u8,
        last: u8,
    },
    SlotScheduling {
        id: u32,
        half_airtime_ms: u32,
        candidates: u8,
        slot_index: u8,
        /// Slot holders in order (first `ranked_len` valid); empty for unicast slots.
        ranked: [u32; crate::broadcast_relay::RANKED_LOG],
        ranked_len: u8,
        reason: crate::broadcast_relay::RelayReason,
        /// Ranking inputs of the first candidates evaluated: (node, unique coverage, total
        /// coverage, cost bucket). Unicast plans carry the tiered cost with coverage 0.
        evaluated: [(u32, u8, u8, u16); crate::broadcast_relay::RANKED_LOG],
        evaluated_len: u8,
        /// Nodes counted as already covered before ranking.
        pre_covered: u8,
    },
    RelayCommitted {
        id: u32,
        heard_from: u32,
        delay_ms: u32,
    },
    BroadcastDupeCancel {
        id: u32,
        from: u32,
    },
    RelaySkip {
        from: u32,
        reason: SrSkipReason,
    },
    TopologySending {
        node_id: u32,
        neighbors: u8,
        packets: u8,
        topo_v: u8,
    },
    TopologyDirtySending {
        delay_ms: u32,
    },
    /// A NodeInfo reply was queued behind a contention-window delay.
    NodeInfoReplyDelayed {
        delay_ms: u32,
    },
    EmptyBootBroadcast,
    TopologyProcessing {
        from: u32,
        neighbors: u8,
        topo_v: u8,
        sr_active: bool,
        relay_node: u8,
    },
    TopologyReceived {
        from: u32,
        neighbors: u8,
        routing_version: u8,
        sr_active: bool,
    },
    TopologyStale {
        from: u32,
        received: u8,
        last: u8,
    },
    TopologyDirtyFromNeighbor {
        from: u32,
    },
    NetworkTopologyHeader {
        direct_neighbors: u8,
        graph_nodes: u8,
        downstream_routes: u16,
    },
    NetworkTopologyUs {
        node_id: u32,
    },
    NetworkTopologyEmpty,
    NetworkTopologyNeighbor {
        node_id: u32,
        rssi: i16,
        snr: i8,
        hears_us: bool,
        last: bool,
    },
    NetworkTopologyMirrored {
        continue_pipe: bool,
        node_id: u32,
        hears_us: bool,
        last_mirrored: bool,
    },
    NetworkTopologyDownstreamHeader {
        count: u16,
    },
    /// One line of the downstream dump: `relay: dest dest ...`. A relay with more than
    /// [`DOWNSTREAM_LOG_GROUP`] destinations continues on further events for the same relay.
    NetworkTopologyDownstreamGroup {
        relay: u32,
        destinations: [u32; DOWNSTREAM_LOG_GROUP],
        len: u8,
        last: bool,
    },
    TopologyDownstreamSkippedAsymmetric {
        sender: u32,
        destination: u32,
    },
    TopologyLoggingComplete,
    /// An empty bootstrap broadcast arrived inside the bootstrap-reply cooldown; no list sent.
    BootstrapReplyRateLimited,
    /// The destination of this unicast hears its source directly (per the source's topology):
    /// our relay waits `wait_ms` for the destination's ACK or reply before it may go out.
    UnicastDestHeardDirect {
        id: u32,
        wait_ms: u32,
    },
    /// The destination answered the source: our queued relay of the request was cancelled.
    UnicastReplyCancel {
        id: u32,
    },
    /// The radio was re-initialised for a new preset; queued transmissions timed for the old
    /// air parameters (and addressed to nodes still on them) were dropped.
    RadioReconfigured {
        dropped: u8,
    },
    GraphAged {
        before: u8,
        after: u8,
    },
    TopologyChangedNewNeighbor {
        node_id: u32,
        total: u8,
    },
    RelayConfirmedHearsUs {
        node_id: u32,
    },
    DirectNeighborLostDirty,
    NodeInfoReceived {
        from: u32,
        short_len: u8,
        short_name: [u8; 5],
        role: u32,
        is_new: bool,
    },
    RouteNextHop {
        destination: u32,
        next_hop: u32,
        cost_x100: u16,
        hops: u8,
    },
    T1Scheduled {
        id: u32,
        delay_ms: u32,
    },
    T1Fired {
        id: u32,
    },
    T1Canceled {
        id: u32,
        reason: T1CancelReason,
    },
    /// Unicast carrying a designated next hop: that byte owns slot 0, we take rank+1.
    UnicastDesignated {
        next_hop: u8,
        is_us: bool,
        sr_active: bool,
        slot: u8,
        slot_delay_ms: u32,
    },
    /// A copy of a unicast we were about to relay was heard: our copy is redundant.
    UnicastDupeCancel {
        id: u32,
        from: u32,
    },
    /// We forwarded a want_ack unicast with a designated next hop and will retry it.
    RelayRetxArmed {
        id: u32,
        next_hop: u8,
    },
    /// A retry went out; `fallback` marks the last one, sent with next_hop cleared.
    RelayRetxFired {
        id: u32,
        fallback: bool,
    },
    RelayRetxCanceled {
        id: u32,
        reason: RelayRetxCancelReason,
    },
    TracerouteAppended {
        towards: bool,
        route_len: u8,
        snr_only: bool,
    },
    BridgeForward {
        id: u32,
        from: u32,
        dest: u32,
        src_radio: u8,
        dst_radio: u8,
        delay_ms: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayRetxCancelReason {
    /// Someone relayed the packet on: the designated hop or a later slot.
    CopyHeard,
    /// The destination answered (ACK, NAK or application reply).
    ReplyHeard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T1CancelReason {
    RelayHeard,
    AllHearsUsHeard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrSkipReason {
    WireGate,
    Qos,
    Duplicate,
    RateLimited,
    OwnRebroadcast,
    UnknownDestination,
    BetterNeighbor,
    /// Unicast whose next hop is the node we just heard it from.
    NextHopIsRelayer,
    /// Unicast that would leave us with hop_limit 0 without a direct link to the target.
    DeadEndHop,
    /// Unicast the transmitter, or an SR neighbour covering it, can already deliver.
    UnicastCovered,
    /// Unicast we have no direct, downstream or next-hop path for.
    NoRelayPath,
    /// Routing ACK toward a node its sender heard directly: it retraces the request's link and
    /// a lost ACK is covered by the sender's own retransmission.
    ReplyRetracesLink,
}

/// Sink for periodic topology graph dumps (may emit many lines).
pub trait TopologyLogSink {
    fn emit(&mut self, event: SrLogEvent);
}

pub struct SrLog {
    pending: heapless::Vec<SrLogEvent, MAX_SR_LOG>,
}

impl TopologyLogSink for SrLog {
    fn emit(&mut self, event: SrLogEvent) {
        self.push(event);
    }
}

impl Default for SrLog {
    fn default() -> Self {
        Self::new()
    }
}

impl SrLog {
    pub const fn new() -> Self {
        Self {
            pending: heapless::Vec::new(),
        }
    }

    pub fn push(&mut self, event: SrLogEvent) {
        if self.pending.len() >= MAX_SR_LOG {
            let _ = self.pending.remove(0);
        }
        let _ = self.pending.push(event);
    }

    pub fn take(&mut self, out: &mut heapless::Vec<SrLogEvent, MAX_SR_LOG>) {
        out.clear();
        for event in self.pending.iter() {
            let _ = out.push(*event);
        }
        self.pending.clear();
    }
}
