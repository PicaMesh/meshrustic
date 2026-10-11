pub const MAX_SR_LOG: usize = 64;
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
        ranked: [u32; crate::broadcast_relay::RANKED_LOG],
        ranked_len: u8,
        reason: crate::broadcast_relay::RelayReason,
        evaluated: [(u32, u8, u8, u16); crate::broadcast_relay::RANKED_LOG],
        evaluated_len: u8,
        pre_covered: u8,
        uncovered: [u32; crate::broadcast_relay::UNCOVERED_LOG],
        uncovered_len: u8,
        slots_given: u8,
        reserved_slots: u8,
        reserved_ranked: u8,
        absorbed: [(u32, u8); crate::broadcast_relay::RANKED_LOG],
        absorbed_len: u8,
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
    RateLimitTrip {
        node_id: u32,
        kind: u8,
    },
    RateLimitClear {
        node_id: u32,
        kind: u8,
    },
    RateLimitYoungAnnounce {
        ids: [u32; 4],
        count: u8,
    },
    RateLimitDestDrop {
        from: u32,
        to: u32,
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
        more_chunks: bool,
        continuation: bool,
    },
    TopologyListedNeighbor {
        from: u32,
        node_id: u32,
        rssi: i8,
        snr: i8,
        hears_us: bool,
        sr_active: bool,
        etx_variance: u8,
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
        l1: u8,
        l2: u8,
        l3: u8,
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
        class: crate::graph::NodeClass,
    },
    NetworkTopologyMirrored {
        continue_pipe: bool,
        node_id: u32,
        hears_us: bool,
        last_mirrored: bool,
        etx_fixed: u16,
        measured: bool,
        class: crate::graph::NodeClass,
    },
    NetworkTopologyDownstreamHeader {
        count: u16,
    },
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
    BootstrapReplyRateLimited,
    BootstrapReplyAlreadyAnswered,
    UnicastDestHeardDirect {
        id: u32,
        wait_ms: u32,
    },
    UnicastReplyCancel {
        id: u32,
    },
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
    BroadcastUnrankedThinGraph {
        from: u32,
        direct_neighbors: u8,
    },
    DirectNeighborLostDirty,
    NodeInfoReceived {
        from: u32,
        short_len: u8,
        short_name: [u8; 5],
        role: u32,
        is_new: bool,
    },
    CoverageFor {
        neighbor: u32,
    },
    RouteNextHop {
        destination: u32,
        next_hop: u32,
        cost_x100: u16,
        hops: u8,
        verified: bool,
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
    UnicastDesignated {
        next_hop: u8,
        is_us: bool,
        sr_active: bool,
        slot: u8,
        slot_delay_ms: u32,
    },
    UnicastDupeCancel {
        id: u32,
        from: u32,
    },
    RelayRetxArmed {
        id: u32,
        next_hop: u8,
    },
    RelayRetxRepeat {
        id: u32,
    },
    RelayRetxRedirect {
        id: u32,
        next_hop: u8,
    },
    RelayRetxNoAlternate {
        id: u32,
    },
    RelayRetxCanceled {
        id: u32,
        reason: RelayRetxCancelReason,
    },
    OriginatorRetryReplanned {
        id: u32,
    },
    NextHopSuspect {
        next_hop: u32,
        destination: u32,
        misses: u8,
    },
    NextHopHealthy {
        next_hop: u32,
        destination: u32,
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
    CopyHeard,
    ReplyHeard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T1CancelReason {
    Policy,
    RelayHeard,
    OwnTransmission,
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
    RouterExpected,
    NextHopIsRelayer,
    DeadEndHop,
    UnicastCovered,
    NoRelayPath,
    ReplyRetracesLink,
    AlreadyCovered,
    UnverifiedBacktrack,
    LastHopReserved,
}

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
