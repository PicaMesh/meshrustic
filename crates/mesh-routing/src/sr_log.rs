//! SR routing decision log events (`[SR]` USB prefix).

pub const MAX_SR_LOG: usize = 64;

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
    SlotScheduling {
        id: u32,
        half_airtime_ms: u32,
        candidates: u8,
        slot_index: u8,
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
    NetworkTopologyDownstreamRoute {
        destination: u32,
        relay: u32,
        last: bool,
    },
    TopologyDownstreamSkippedAsymmetric {
        sender: u32,
        destination: u32,
    },
    TopologyLoggingComplete,
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
