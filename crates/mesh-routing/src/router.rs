//! Unified routing core — RX pipeline, graph maintenance, coordinated relay (Phase 6).

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::{is_direct_packet, PacketHeader, ParsedPacket, PACKET_HEADER_LEN, NODENUM_BROADCAST};
use mesh_radio::{primary_channel_hash, MODEM_SHORT_SLOW};

use crate::coordinated_relay::{half_airtime_ms, slot_time_for_preset, tx_delay_ms_worst};
use crate::neighbor_graph::{
    MaintenanceReport, NeighborGraph, TopologyMergeResult, NEIGHBOR_TTL_MS,
    TOPOLOGY_BROADCAST_MS, TOPOLOGY_DIRTY_MIN_MS,
};
use crate::nodeinfo::{
    build_nodeinfo_reply_frame, build_nodeinfo_wire_frame, decode_user, NodeInfoCache,
    NodeInfoIdentity, NODEINFO_APP, NODEINFO_BROADCAST_MS, NODEINFO_REPLY_COOLDOWN_MS,
    NODEINFO_SHORT_NAME_MAX,
};
use crate::packet_history::{ObserveResult, PacketHistory};
use crate::pool::{PacketHandle, PacketPool, PacketSlot, MAX_PACKET_PAYLOAD};
use crate::qos::ChannelQoS;
use crate::rate_limit::NodeRateLimiter;
use crate::relay_identity::RelayIdentityCache;
use crate::relay::{copy_opaque_payload, relay_header_with_next_hop_opts, wire_may_relay};
use crate::reliable::{
    bump_reliable_delays, due_retransmit, schedule_reliable, stop_reliable, PendingReliable,
    MAX_PENDING_RELIABLE,
};
use crate::routing_ack::{
    build_ack_nak_frame, decode_routing_payload, hop_limit_for_response, ROUTING_APP,
    ROUTING_ERROR_NONE, ROUTING_ERROR_NO_CHANNEL,
};
use crate::rx_decode::{summarize_decrypted, RxDecodeInfo};
use crate::sr_log::{SrLog, SrLogEvent, SrSkipReason, T1CancelReason, MAX_SR_LOG};
use crate::telemetry::{
    build_device_telemetry_wire_frame, DeviceMetricsSnapshot, DEVICE_TELEMETRY_BROADCAST_MS,
    MAGIC_USB_BATTERY_LEVEL,
};
use crate::topology::{
    build_app_wire_frame, build_topology_wire_frame, extract_packed_neighbors, try_decrypt_data_full,
    DecodedData, DataEncodeOpts, MAX_TOPOLOGY_PACKETS, SIGNAL_ROUTING_APP, SIGNAL_ROUTING_VERSION,
    SR_BROADCAST_MAX_HOPS,
};
use crate::traceroute::{
    alter_on_relay, decode_route_discovery, encode_route_discovery, rebuild_relay_ciphertext,
    TRACEROUTE_APP,
};

pub const MAX_WIRE_LEN: usize = PACKET_HEADER_LEN + MAX_PACKET_PAYLOAD;
const MAX_PENDING_RELAYS: usize = 8;

fn psk_bytes(key: &CryptoKey) -> &[u8] {
    let len = key.length.max(0) as usize;
    &key.bytes[..len]
}

/// Raw RX frame passed in from a radio driver task.
pub struct InboundPacket<'a> {
    pub radio_id: u8,
    pub rssi: i16,
    pub snr: i8,
    pub bytes: &'a [u8],
}

/// Outcome of `Router::process_inbound`.
#[derive(Clone, Copy)]
pub struct ProcessResult {
    pub parsed: ParsedPacket,
    pub duplicate: bool,
    pub rate_limited: bool,
    pub handle: Option<PacketHandle>,
    pub radio_id: u8,
    pub rssi: i16,
    pub snr: i8,
    pub decoded_portnum: Option<u32>,
    pub decode: RxDecodeInfo,
    pub decoded_data: Option<DecodedData>,
}

/// Built relay frame ready for the radio TX queue.
#[derive(Clone, Copy)]
pub struct RelayPlan {
    pub len: u8,
    pub bytes: [u8; MAX_WIRE_LEN],
    pub delay_ms: u32,
}

/// TX decisions for one received frame (same-radio relay + optional cross-preset bridge).
#[derive(Clone, Copy)]
pub struct TxPlan {
    pub relay: Option<RelayPlan>,
    pub bridge_count: u8,
    pub bridge: [crate::bridge::BridgeLeg; crate::bridge::BridgeLeg::MAX],
}

impl Default for TxPlan {
    fn default() -> Self {
        Self {
            relay: None,
            bridge_count: 0,
            bridge: [crate::bridge::BridgeLeg::default(); crate::bridge::BridgeLeg::MAX],
        }
    }
}

#[derive(Clone, Copy)]
struct PendingRelay {
    active: bool,
    from: u32,
    id: u32,
    _radio_id: u8,
    tx_after_ms: u32,
    len: u8,
    bytes: [u8; MAX_WIRE_LEN],
}

#[derive(Clone, Copy)]
struct PendingTopology {
    active: bool,
    count: u8,
    next_idx: u8,
    next_tx_ms: u32,
    spacing_ms: u32,
    lens: [u8; MAX_TOPOLOGY_PACKETS],
    frames: [[u8; MAX_WIRE_LEN]; MAX_TOPOLOGY_PACKETS],
}

const MAX_PENDING_RETRANSMITS: usize = 4;

#[derive(Clone, Copy)]
struct PendingRetransmit {
    active: bool,
    canceled: bool,
    packet_id: u32,
    heard_from: u32,
    fire_after_ms: u32,
    len: u8,
    bytes: [u8; MAX_WIRE_LEN],
}

#[derive(Clone, Copy)]
struct PendingNodeInfo {
    active: bool,
    next_tx_ms: u32,
    len: u8,
    bytes: [u8; MAX_WIRE_LEN],
}

#[derive(Clone, Copy)]
struct PendingTelemetry {
    active: bool,
    next_tx_ms: u32,
    len: u8,
    bytes: [u8; MAX_WIRE_LEN],
}

#[derive(Clone, Copy)]
struct PendingTraceroute {
    active: bool,
    next_tx_ms: u32,
    len: u8,
    bytes: [u8; MAX_WIRE_LEN],
}

#[derive(Clone, Copy)]
struct PendingAck {
    active: bool,
    next_tx_ms: u32,
    len: u8,
    bytes: [u8; MAX_WIRE_LEN],
}

/// Shared static router state.
pub struct Router {
    node_num: u32,
    pool: PacketPool,
    history: PacketHistory,
    rate_limit: NodeRateLimiter,
    relay_identity: RelayIdentityCache,
    qos: ChannelQoS,
    graph: NeighborGraph,
    pending: [PendingRelay; MAX_PENDING_RELAYS],
    pending_topology: PendingTopology,
    pending_nodeinfo: PendingNodeInfo,
    pending_telemetry: PendingTelemetry,
    pending_traceroute: PendingTraceroute,
    pending_retransmits: [PendingRetransmit; MAX_PENDING_RETRANSMITS],
    pending_reliable: [PendingReliable; MAX_PENDING_RELIABLE],
    pending_ack: PendingAck,
    nodeinfo_identity: NodeInfoIdentity,
    nodeinfo_cache: NodeInfoCache,
    last_nodeinfo_ms: u32,
    last_nodeinfo_reply_to: u32,
    last_nodeinfo_reply_ms: u32,
    last_telemetry_ms: u32,
    device_metrics: DeviceMetricsSnapshot,
    channel_key: CryptoKey,
    channel_hash: u8,
    modem_preset: u8,
    use_preset: bool,
    hop_limit: u8,
    next_tx_id: u32,
    sr_log: SrLog,
    bridge_dedup: crate::bridge::BridgeDedupCache,
}

impl Router {
    pub fn new(node_num: u32) -> Self {
        Self::with_modem_preset(
            node_num,
            "",
            MODEM_SHORT_SLOW,
            true,
            CryptoKey::from_bytes(&DEFAULT_PSK),
            3,
        )
    }

    /// Primary channel hash from stored name + modem preset.
    pub fn with_modem_preset(
        node_num: u32,
        stored_channel_name: &str,
        modem_preset: u8,
        use_preset: bool,
        channel_key: CryptoKey,
        hop_limit: u8,
    ) -> Self {
        let psk = psk_bytes(&channel_key);
        Self::with_channel(
            node_num,
            channel_key,
            primary_channel_hash(stored_channel_name, modem_preset, use_preset, psk),
            modem_preset,
            use_preset,
            hop_limit,
        )
    }

    pub fn with_primary_channel(
        node_num: u32,
        channel_name: &str,
        channel_key: CryptoKey,
        hop_limit: u8,
    ) -> Self {
        let psk = psk_bytes(&channel_key);
        Self::with_channel(
            node_num,
            channel_key,
            mesh_crypto::channel_hash(channel_name, psk),
            MODEM_SHORT_SLOW,
            true,
            hop_limit,
        )
    }

    pub fn with_channel(
        node_num: u32,
        channel_key: CryptoKey,
        channel_hash: u8,
        modem_preset: u8,
        use_preset: bool,
        hop_limit: u8,
    ) -> Self {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(node_num);
        graph.set_modem_preset(modem_preset);
        Self {
            node_num,
            pool: PacketPool::new(),
            history: PacketHistory::new(),
            rate_limit: NodeRateLimiter::with_node_num(node_num),
            relay_identity: RelayIdentityCache::new(),
            qos: ChannelQoS::new(),
            graph,
            pending: [PendingRelay {
                active: false,
                from: 0,
                id: 0,
                _radio_id: 0,
                tx_after_ms: 0,
                len: 0,
                bytes: [0; MAX_WIRE_LEN],
            }; MAX_PENDING_RELAYS],
            pending_topology: PendingTopology {
                active: false,
                count: 0,
                next_idx: 0,
                next_tx_ms: 0,
                spacing_ms: 0,
                lens: [0; MAX_TOPOLOGY_PACKETS],
                frames: [[0; MAX_WIRE_LEN]; MAX_TOPOLOGY_PACKETS],
            },
            pending_nodeinfo: PendingNodeInfo {
                active: false,
                next_tx_ms: 0,
                len: 0,
                bytes: [0; MAX_WIRE_LEN],
            },
            pending_telemetry: PendingTelemetry {
                active: false,
                next_tx_ms: 0,
                len: 0,
                bytes: [0; MAX_WIRE_LEN],
            },
            pending_traceroute: PendingTraceroute {
                active: false,
                next_tx_ms: 0,
                len: 0,
                bytes: [0; MAX_WIRE_LEN],
            },
            pending_retransmits: [PendingRetransmit {
                active: false,
                canceled: false,
                packet_id: 0,
                heard_from: 0,
                fire_after_ms: 0,
                len: 0,
                bytes: [0; MAX_WIRE_LEN],
            }; MAX_PENDING_RETRANSMITS],
            pending_reliable: [PendingReliable::inactive(); MAX_PENDING_RELIABLE],
            pending_ack: PendingAck {
                active: false,
                next_tx_ms: 0,
                len: 0,
                bytes: [0; MAX_WIRE_LEN],
            },
            nodeinfo_identity: NodeInfoIdentity::with_default_advert([0; 32]),
            nodeinfo_cache: NodeInfoCache::new(),
            last_nodeinfo_ms: 0,
            last_nodeinfo_reply_to: 0,
            last_nodeinfo_reply_ms: 0,
            last_telemetry_ms: 0,
            device_metrics: DeviceMetricsSnapshot::default(),
            channel_key,
            channel_hash,
            modem_preset,
            use_preset,
            hop_limit,
            next_tx_id: 1,
            sr_log: SrLog::new(),
            bridge_dedup: crate::bridge::BridgeDedupCache::new(),
        }
    }

    /// Graph access for host integration tests (`rpi-app`).
    #[doc(hidden)]
    pub fn graph_mut(&mut self) -> &mut NeighborGraph {
        &mut self.graph
    }

    pub fn set_node_identity(&mut self, identity: NodeInfoIdentity) {
        self.graph.set_device_role(identity.advert.role);
        self.nodeinfo_identity = identity;
    }

    /// Update cached device metrics before periodic telemetry broadcast.
    pub fn update_device_metrics(&mut self, metrics: DeviceMetricsSnapshot) {
        self.device_metrics = metrics;
    }

    /// Recompute channel hash when LoRa preset or channel settings change.
    pub fn set_modem_preset(
        &mut self,
        stored_channel_name: &str,
        modem_preset: u8,
        use_preset: bool,
        channel_key: CryptoKey,
    ) {
        self.channel_key = channel_key;
        self.modem_preset = modem_preset;
        self.use_preset = use_preset;
        self.graph.set_modem_preset(modem_preset);
        self.channel_hash =
            primary_channel_hash(stored_channel_name, modem_preset, use_preset, psk_bytes(&channel_key));
    }

    pub fn channel_hash(&self) -> u8 {
        self.channel_hash
    }

    pub fn route_to(&mut self, destination: u32, now_ms: u32) -> crate::graph::Route {
        self.graph.route_to(destination, now_ms)
    }

    pub fn edge_heard_on(&self, peer: u32) -> u8 {
        self.graph.edge_heard_on(peer)
    }

    pub fn modem_preset(&self) -> u8 {
        self.modem_preset
    }

    fn cw_slot_ms(&self) -> u32 {
        slot_time_for_preset(self.modem_preset)
    }

    /// Call when a frame is actually queued for TX (own-rebroadcast detection).
    pub fn record_tx_on_air(&mut self, packet_id: u32, now_ms: u32) {
        if packet_id != 0 {
            self.graph.record_our_transmission(packet_id, now_ms);
            self.graph.notify_originated_packet_sent(now_ms);
        }
    }

    pub fn node_num(&self) -> u32 {
        self.node_num
    }

    pub fn neighbor_count(&self) -> u8 {
        self.graph.neighbor_count()
    }

    pub fn relay_tx_after(&self, from: u32, id: u32, radio_id: u8) -> Option<u32> {
        self.graph.relay_tx_after(from, id, radio_id)
    }

    pub fn nodeinfo_peer_count(&self) -> u8 {
        self.nodeinfo_cache.count()
    }

    pub fn nodeinfo_peer(&self, node_num: u32) -> Option<&NodeInfoIdentity> {
        self.nodeinfo_cache.get(node_num).map(|e| &e.identity)
    }

    pub fn topology_version(&self) -> u8 {
        self.graph.topology_version()
    }

    pub fn confirm_direct_neighbor_hears_us(&mut self, neighbor: u32) {
        self.graph.confirm_direct_neighbor_hears_us(neighbor);
    }

    pub fn get_next_hop(
        &mut self,
        destination: u32,
        source_node: u32,
        heard_from: u32,
        now_ms: u32,
    ) -> u32 {
        self.graph
            .get_next_hop(destination, source_node, heard_from, now_ms)
    }

    pub fn drain_sr_logs(&mut self, out: &mut heapless::Vec<SrLogEvent, MAX_SR_LOG>) {
        self.sr_log.take(out);
    }

    pub fn ensure_boot_broadcasts(&mut self, now_ms: u32, slot_ms: u32) {
        if self.graph.can_send_topology()
            && self.graph.last_topology_ms() == 0
            && !self.pending_topology.active
        {
            if self.schedule_topology_broadcast(now_ms, slot_ms, false) {
                self.graph.commit_topology_broadcast(now_ms, false);
            }
        }
        if self.last_nodeinfo_ms == 0 && !self.pending_nodeinfo.active {
            self.schedule_nodeinfo_broadcast(now_ms);
        }
    }

    pub fn set_device_role(&mut self, role: u32) {
        self.graph.set_device_role(role);
    }

    /// One-time startup logs for SR / graph init.
    pub fn emit_startup_logs(&mut self) {
        self.sr_log.push(SrLogEvent::UsingNeighborGraph);
        self.sr_log.push(SrLogEvent::ModuleInitialized {
            version: SIGNAL_ROUTING_VERSION,
        });
        self.sr_log.push(SrLogEvent::Config {
            broadcast_secs: (TOPOLOGY_BROADCAST_MS / 1000) as u16,
            dirty_secs: (TOPOLOGY_DIRTY_MIN_MS / 1000) as u16,
            node_ttl_secs: NEIGHBOR_TTL_MS / 1000,
            max_hops: SR_BROADCAST_MAX_HOPS,
        });
    }

    /// RX pipeline: parse, dedup, rate-limit, graph update, stash opaque payload.
    pub fn process_inbound(
        &mut self,
        packet: &InboundPacket<'_>,
        now_ms: u32,
    ) -> Option<ProcessResult> {
        let header = PacketHeader::decode(packet.bytes).ok()?;
        let parsed = header.parse();
        let payload_len = packet.bytes.len().saturating_sub(PACKET_HEADER_LEN);
        if payload_len > MAX_PACKET_PAYLOAD {
            return None;
        }
        let (decode, inner, decoded_data) = self.decode_payload(&parsed, packet.bytes, payload_len);

        match self
            .history
            .observe(parsed.from, parsed.id, parsed.hop_limit)
        {
            ObserveResult::Upgraded => {
                if !self.try_handle_upgraded_packet(&parsed) {
                    self.handle_duplicate_rx(
                        &parsed,
                        decoded_data.as_ref(),
                        packet,
                        now_ms,
                    );
                    return Some(ProcessResult {
                        parsed,
                        duplicate: true,
                        rate_limited: false,
                        handle: None,
                        radio_id: packet.radio_id,
                        rssi: packet.rssi,
                        snr: packet.snr,
                        decoded_portnum: decode.portnum,
                        decode,
                        decoded_data,
                    });
                }
            }
            ObserveResult::Duplicate => {
                self.handle_duplicate_rx(
                    &parsed,
                    decoded_data.as_ref(),
                    packet,
                    now_ms,
                );
                return Some(ProcessResult {
                    parsed,
                    duplicate: true,
                    rate_limited: false,
                    handle: None,
                    radio_id: packet.radio_id,
                    rssi: packet.rssi,
                    snr: packet.snr,
                    decoded_portnum: decode.portnum,
                    decode,
                    decoded_data,
                });
            }
            ObserveResult::New => {}
        }

        let direct = is_direct_packet(
            parsed.from,
            parsed.hop_start,
            parsed.hop_limit,
            parsed.relay_node,
        );
        self.sr_log.push(SrLogEvent::PacketFrom {
            from: parsed.from,
            relay_node: parsed.relay_node,
            hop_start: parsed.hop_start,
            hop_limit: parsed.hop_limit,
            direct,
        });

        if let Some((node_id, rssi, snr, is_new)) = self.graph.observe_packet(
            parsed.from,
            parsed.hop_start,
            parsed.hop_limit,
            parsed.relay_node,
            packet.rssi,
            packet.snr,
            now_ms,
            packet.radio_id,
        ) {
            if is_new {
                self.sr_log.push(SrLogEvent::DirectNeighbor {
                    node_id,
                    rssi,
                    snr,
                    is_new: true,
                });
                self.sr_log.push(SrLogEvent::TopologyChangedNewNeighbor {
                    node_id,
                    total: self.graph.neighbor_count(),
                });
                // Immediate dirty topology when a new direct neighbor appears.
                if !self.pending_topology.active {
                    if self.schedule_topology_broadcast(
                        now_ms,
                        crate::coordinated_relay::DEFAULT_SLOT_MS,
                        true,
                    ) {
                        self.graph.commit_topology_broadcast(now_ms, true);
                    }
                }
            }
        }

        if self.graph.is_active_routing_role() || direct {
            self.graph.update_node_activity(parsed.from, now_ms);
            if !direct && parsed.relay_node != 0 {
                let from_low = (parsed.from & 0xFF) as u8;
                if parsed.relay_node != from_low {
                    let relay = crate::graph::placeholder_node_id(parsed.relay_node);
                    if relay != parsed.from && relay != self.node_num {
                        self.graph.update_node_activity(relay, now_ms);
                    }
                }
            }
        }

        if direct {
            let relay_byte = (parsed.from & 0xFF) as u8;
            if relay_byte != 0 {
                self.try_resolve_placeholder(relay_byte, parsed.from, now_ms);
                self.relay_identity
                    .remember_relay_identity(parsed.from, relay_byte, now_ms);
            }
        }

        let decoded_portnum = decode.portnum;
        if self
            .rate_limit
            .should_drop(
                parsed.from,
                decoded_portnum,
                parsed.hop_start,
                parsed.hop_limit,
                now_ms,
            )
        {
            self.sr_log.push(SrLogEvent::RelaySkip {
                from: parsed.from,
                reason: SrSkipReason::RateLimited,
            });
            return Some(ProcessResult {
                parsed,
                duplicate: false,
                rate_limited: true,
                handle: None,
                radio_id: packet.radio_id,
                rssi: packet.rssi,
                snr: packet.snr,
                decoded_portnum,
                decode,
                decoded_data,
            });
        }

        if let Some(data) = decoded_data.as_ref() {
            self.maybe_cancel_relay_for_foreign_ack(&parsed, data);
        }

        if let Some(data) = decoded_data {
            if data.portnum == SIGNAL_ROUTING_APP {
                if let Some(ref inner) = inner {
                    self.process_topology_rx(&parsed, inner, now_ms, packet.radio_id);
                }
            } else if data.portnum == NODEINFO_APP {
                if Self::is_nodeinfo_request_for_us(&parsed, &data, self.node_num) {
                    self.maybe_schedule_nodeinfo_reply(parsed.from, parsed.id, now_ms);
                } else if let Some(ref inner) = inner {
                    if !inner.is_empty() {
                        self.process_nodeinfo_rx(&parsed, inner, now_ms);
                    }
                }
            } else if data.portnum == TRACEROUTE_APP {
                if let Some(ref inner) = inner {
                    self.maybe_schedule_traceroute_response(
                        &parsed,
                        &data,
                        inner,
                        packet.snr,
                        now_ms,
                    );
                }
            }
        }

        self.process_reliable_rx(&parsed, decoded_data.as_ref(), inner.as_deref(), now_ms);

        let handle = self.pool.alloc()?;
        {
            let slot = self.pool.get_mut(handle).unwrap();
            slot.header = header;
            slot.payload[..payload_len].copy_from_slice(&packet.bytes[PACKET_HEADER_LEN..]);
            slot.payload_len = payload_len as u16;
        }

        Some(ProcessResult {
            parsed,
            duplicate: false,
            rate_limited: false,
            handle: Some(handle),
            radio_id: packet.radio_id,
            rssi: packet.rssi,
            snr: packet.snr,
            decoded_portnum,
            decode,
            decoded_data,
        })
    }

    fn decode_payload(
        &self,
        parsed: &ParsedPacket,
        wire: &[u8],
        payload_len: usize,
    ) -> (
        RxDecodeInfo,
        Option<heapless::Vec<u8, 240>>,
        Option<DecodedData>,
    ) {
        let mut cipher = [0u8; MAX_PACKET_PAYLOAD];
        cipher[..payload_len].copy_from_slice(&wire[PACKET_HEADER_LEN..]);
        if let Some((data, inner)) = try_decrypt_data_full(
            &self.channel_key,
            parsed.from,
            parsed.id,
            self.channel_hash,
            parsed.channel,
            &mut cipher[..payload_len],
        ) {
            (
                RxDecodeInfo {
                    portnum: Some(data.portnum),
                    payload_len: inner.len().min(u16::MAX as usize) as u16,
                    summary: summarize_decrypted(data.portnum, &inner),
                },
                Some(inner),
                Some(data),
            )
        } else {
            (
                RxDecodeInfo::encrypted(payload_len.min(u16::MAX as usize) as u16),
                None,
                None,
            )
        }
    }

    fn is_nodeinfo_request_for_us(
        parsed: &ParsedPacket,
        data: &DecodedData,
        our_node: u32,
    ) -> bool {
        parsed.from != our_node
            && data.portnum == NODEINFO_APP
            && data.want_response
            && (parsed.to == our_node
                || parsed.to == NODENUM_BROADCAST
                || data.dest == our_node)
    }

    fn maybe_schedule_nodeinfo_reply(&mut self, to: u32, request_id: u32, now_ms: u32) {
        if self.last_nodeinfo_reply_to == to
            && now_ms.wrapping_sub(self.last_nodeinfo_reply_ms) < NODEINFO_REPLY_COOLDOWN_MS
        {
            return;
        }
        self.schedule_nodeinfo_unicast(to, request_id, now_ms);
        self.last_nodeinfo_reply_to = to;
        self.last_nodeinfo_reply_ms = now_ms;
    }

    fn process_topology_rx(
        &mut self,
        parsed: &ParsedPacket,
        payload: &[u8],
        now_ms: u32,
        heard_on: u8,
    ) {
        if parsed.from == 0 || parsed.from == self.node_num {
            return;
        }
        if self.graph.has_our_transmission(parsed.id) {
            return;
        }
        let Some((header, neighbor_list)) = extract_packed_neighbors(payload) else {
            return;
        };
        let is_direct = is_direct_packet(
            parsed.from,
            parsed.hop_start,
            parsed.hop_limit,
            parsed.relay_node,
        );
        match self.graph.merge_topology(
            parsed.from,
            &header,
            &neighbor_list,
            is_direct,
            now_ms,
            heard_on,
        ) {
            TopologyMergeResult::Applied { neighbors, topo_v } => {
                self.graph
                    .apply_topology_hears_us(parsed.from, self.node_num, &neighbor_list);
                self.sr_log.push(SrLogEvent::TopologyProcessing {
                    from: parsed.from,
                    neighbors,
                    topo_v,
                    sr_active: header.signal_routing_active,
                    relay_node: parsed.relay_node,
                });
                self.sr_log.push(SrLogEvent::TopologyReceived {
                    from: parsed.from,
                    neighbors,
                    routing_version: header.routing_version,
                    sr_active: header.signal_routing_active,
                });
            }
            TopologyMergeResult::Stale { received, last } => {
                self.sr_log.push(SrLogEvent::TopologyStale {
                    from: parsed.from,
                    received,
                    last,
                });
            }
            TopologyMergeResult::IgnoredFormat => {}
        }
        if neighbor_list.is_empty() && is_direct && header.signal_routing_active {
            self.sr_log.push(SrLogEvent::TopologyDirtyFromNeighbor {
                from: parsed.from,
            });
            if !self.pending_topology.active {
                if self.schedule_topology_broadcast(now_ms, crate::coordinated_relay::DEFAULT_SLOT_MS, true)
                {
                    self.graph.commit_topology_broadcast(now_ms, true);
                }
            }
        }
    }

    /// Decide whether to relay on the receiving radio (coordinated flooding path).
    pub fn evaluate_tx_plan(
        &mut self,
        result: &ProcessResult,
        chutil_pct: f32,
        slot_ms: u32,
        now_ms: u32,
    ) -> TxPlan {
        let mut plan = TxPlan::default();

        if result.duplicate || result.rate_limited {
            return plan;
        }

        let Some(handle) = result.handle else {
            return plan;
        };

        let parsed = result.parsed;
        let from_us = parsed.from == self.node_num;
        let to_us = parsed.to == self.node_num;

        if self.graph.has_our_transmission(parsed.id) {
            self.pool.release(handle);
            self.sr_log.push(SrLogEvent::RelaySkip {
                from: parsed.from,
                reason: SrSkipReason::OwnRebroadcast,
            });
            return plan;
        }

        if !wire_may_relay(&parsed, from_us, to_us) {
            self.pool.release(handle);
            self.sr_log.push(SrLogEvent::RelaySkip {
                from: parsed.from,
                reason: SrSkipReason::WireGate,
            });
            return plan;
        }

        if !self
            .qos
            .can_relay(result.decoded_portnum, parsed.channel, chutil_pct)
        {
            self.pool.release(handle);
            self.sr_log.push(SrLogEvent::RelaySkip {
                from: parsed.from,
                reason: SrSkipReason::Qos,
            });
            return plan;
        }

        if mesh_protocol::is_direct_packet(
            parsed.from,
            parsed.hop_start,
            parsed.hop_limit,
            parsed.relay_node,
        ) && parsed.relay_node != 0
        {
            self.try_resolve_placeholder(parsed.relay_node, parsed.from, now_ms);
        }

        let heard_from = self.resolve_heard_from_node(
            parsed.relay_node,
            parsed.from,
            result.rssi,
            result.snr,
            now_ms,
        );

        let half_airtime = half_airtime_ms(slot_ms);
        let broadcast_plan = if parsed.to == NODENUM_BROADCAST
            && self.graph.signal_routing_active()
            && parsed.from != self.node_num
            && self.graph.topology_healthy_for_broadcast()
        {
            Some(self.graph.plan_broadcast_relay(
                parsed.id,
                parsed.from,
                heard_from,
                parsed.to,
                now_ms,
                half_airtime,
            ))
        } else {
            None
        };

        if let Some(ref relay_plan) = broadcast_plan {
            if !relay_plan.should_relay {
                self.pool.release(handle);
                self.sr_log.push(SrLogEvent::RelaySkip {
                    from: parsed.from,
                    reason: SrSkipReason::BetterNeighbor,
                });
                return plan;
            }
            self.graph
                .record_node_transmission(self.node_num, parsed.id, now_ms);
        }

        if parsed.to != NODENUM_BROADCAST
            && parsed.to != self.node_num
            && !self.graph.topology_healthy_for_unicast(parsed.to, now_ms)
            && !self.graph.is_known_relay_target(parsed.to, now_ms)
        {
            self.pool.release(handle);
            self.sr_log.push(SrLogEvent::RelaySkip {
                from: parsed.from,
                reason: SrSkipReason::UnknownDestination,
            });
            return plan;
        }

        let next_hop = if parsed.to != NODENUM_BROADCAST {
            let hop = self.graph.get_next_hop(parsed.to, parsed.from, heard_from, now_ms);
            if hop != 0 {
                let route = self.graph.get_route(parsed.to, now_ms);
                self.sr_log.push(SrLogEvent::RouteNextHop {
                    destination: parsed.to,
                    next_hop: hop,
                    cost_x100: route.cost_fixed,
                });
            }
            hop
        } else {
            0
        };

        let direct_hop_limit = if parsed.to != NODENUM_BROADCAST {
            self.graph.unicast_hop_limit_for_direct_neighbor(parsed.to)
        } else {
            None
        };
        let relay_hdr = match relay_header_with_next_hop_opts(
            &parsed,
            self.node_num,
            next_hop,
            direct_hop_limit,
        ) {
            Some(h) => h,
            None => {
                self.pool.release(handle);
                self.sr_log.push(SrLogEvent::RelaySkip {
                    from: parsed.from,
                    reason: SrSkipReason::WireGate,
                });
                return plan;
            }
        };

        let mut staging = PacketSlot::empty();
        {
            let rx = self.pool.get(handle).unwrap();
            copy_opaque_payload(&mut staging, rx);
        }
        self.pool.release(handle);

        let mut bytes = [0u8; MAX_WIRE_LEN];
        relay_hdr.encode_to(
            (&mut bytes[..PACKET_HEADER_LEN])
                .try_into()
                .expect("header slice"),
        );
        let plen = staging.payload_len as usize;
        let payload_len = if result.decoded_portnum == Some(TRACEROUTE_APP) {
            if let Some(decoded) = result.decoded_data {
                let mut cipher = [0u8; MAX_PACKET_PAYLOAD];
                cipher[..plen].copy_from_slice(&staging.payload[..plen]);
                if let Some((new_cipher, route_len)) = rebuild_relay_ciphertext(
                    &parsed,
                    &decoded,
                    &mut cipher,
                    plen,
                    self.node_num,
                    result.snr,
                    &self.channel_key,
                ) {
                    let n = new_cipher.len();
                    bytes[PACKET_HEADER_LEN..PACKET_HEADER_LEN + n]
                        .copy_from_slice(&new_cipher);
                    let towards = decoded.request_id == 0;
                    self.sr_log.push(SrLogEvent::TracerouteAppended {
                        towards,
                        route_len,
                        snr_only: parsed.to == self.node_num,
                    });
                    n
                } else {
                    bytes[PACKET_HEADER_LEN..PACKET_HEADER_LEN + plen]
                        .copy_from_slice(&staging.payload[..plen]);
                    plen
                }
            } else {
                bytes[PACKET_HEADER_LEN..PACKET_HEADER_LEN + plen]
                    .copy_from_slice(&staging.payload[..plen]);
                plen
            }
        } else {
            bytes[PACKET_HEADER_LEN..PACKET_HEADER_LEN + plen]
                .copy_from_slice(&staging.payload[..plen]);
            plen
        };
        let len = (PACKET_HEADER_LEN + payload_len) as u8;

        let route = if parsed.to != NODENUM_BROADCAST {
            self.graph.get_route(parsed.to, now_ms)
        } else {
            crate::graph::Route::default()
        };

        let bridge_eval = crate::bridge::BridgeEval {
            rx_radio: result.radio_id,
            parsed: &parsed,
            route,
            decoded_portnum: result.decoded_portnum,
            chutil_pct,
            now_ms,
            from_us,
            to_us,
        };

        let relay_preview = RelayPlan {
            len,
            bytes,
            delay_ms: 0,
        };

        let cw_slot = self.cw_slot_ms();

        if parsed.to != NODENUM_BROADCAST
            && route.next_hop != 0
            && route.egress_radio != result.radio_id
        {
            let mut bridged = TxPlan::default();
            if crate::bridge::evaluate_bridge_targets(
                &bridge_eval,
                &relay_preview,
                &mut self.graph,
                &mut self.bridge_dedup,
                &self.qos,
                &mut self.sr_log,
                self.node_num,
                result.snr,
                slot_ms,
                cw_slot,
                &mut bridged,
            ) {
                return bridged;
            }
        }

        let (tx_after_ms, slot_index, candidates) = self.graph.commit_relay(
            parsed.from,
            parsed.id,
            result.radio_id,
            result.snr,
            heard_from,
            now_ms,
            half_airtime,
            cw_slot,
            self.node_num,
            broadcast_plan.as_ref(),
        );
        let delay_ms = tx_after_ms.wrapping_sub(now_ms);
        self.sr_log.push(SrLogEvent::SlotScheduling {
            id: parsed.id,
            half_airtime_ms: half_airtime,
            candidates,
            slot_index,
        });
        self.sr_log.push(SrLogEvent::RelayCommitted {
            id: parsed.id,
            heard_from,
            delay_ms,
        });

        self.maybe_schedule_t1_retransmit(
            &parsed,
            len,
            bytes,
            result.decoded_portnum,
            slot_ms,
            now_ms,
            true,
        );

        if delay_ms == 0 {
            let relay = RelayPlan {
                len,
                bytes,
                delay_ms: 0,
            };
            plan.relay = Some(relay);
            let _ = crate::bridge::evaluate_bridge_targets(
                &bridge_eval,
                &relay,
                &mut self.graph,
                &mut self.bridge_dedup,
                &self.qos,
                &mut self.sr_log,
                self.node_num,
                result.snr,
                slot_ms,
                cw_slot,
                &mut plan,
            );
            return plan;
        }

        if self.store_pending(
            parsed.from,
            parsed.id,
            result.radio_id,
            tx_after_ms,
            len,
            bytes,
        ) {
            return plan;
        }

        let relay = RelayPlan {
            len,
            bytes,
            delay_ms: 0,
        };
        plan.relay = Some(relay);
        let _ = crate::bridge::evaluate_bridge_targets(
            &bridge_eval,
            &relay,
            &mut self.graph,
            &mut self.bridge_dedup,
            &self.qos,
            &mut self.sr_log,
            self.node_num,
            result.snr,
            slot_ms,
            cw_slot,
            &mut plan,
        );
        plan
    }

    /// Return the next pending relay whose slot time has elapsed.
    pub fn poll_ready_relay(&mut self, now_ms: u32) -> Option<RelayPlan> {
        let mut best_idx = None;
        let mut best_after = u32::MAX;
        for (idx, pending) in self.pending.iter().enumerate() {
            if !pending.active {
                continue;
            }
            if now_ms.wrapping_sub(pending.tx_after_ms) >= 0x8000_0000 {
                continue;
            }
            if pending.tx_after_ms < best_after {
                best_after = pending.tx_after_ms;
                best_idx = Some(idx);
            }
        }
        let idx = best_idx?;
        let pending = self.pending[idx];
        self.pending[idx].active = false;
        self.graph.cancel_relay(pending.from, pending.id);
        Some(RelayPlan {
            len: pending.len,
            bytes: pending.bytes,
            delay_ms: 0,
        })
    }

    pub fn run_maintenance(&mut self, now_ms: u32, slot_ms: u32) -> MaintenanceReport {
        self.relay_identity.prune_relay_identity_cache(now_ms);
        let report = self.graph.run_maintenance(now_ms);
        if let Some((before, after)) = report.graph_aged {
            self.sr_log.push(SrLogEvent::GraphAged { before, after });
            if after < before {
                self.sr_log.push(SrLogEvent::DirectNeighborLostDirty);
            }
        }
        if report.topology_due
            && self.graph.can_send_topology()
            && !self.pending_topology.active
        {
            if self.schedule_topology_broadcast(now_ms, slot_ms, report.topology_dirty_send) {
                self.graph
                    .commit_topology_broadcast(now_ms, report.topology_dirty_send);
            }
        }
        if self.last_nodeinfo_ms == 0
            || now_ms.wrapping_sub(self.last_nodeinfo_ms) >= NODEINFO_BROADCAST_MS
        {
            if !self.pending_nodeinfo.active {
                self.schedule_nodeinfo_broadcast(now_ms);
            }
        }
        if self.device_metrics.voltage_v > 0.0
            || self.device_metrics.battery_level == MAGIC_USB_BATTERY_LEVEL
        {
            if self.last_telemetry_ms == 0
                || now_ms.wrapping_sub(self.last_telemetry_ms) >= DEVICE_TELEMETRY_BROADCAST_MS
            {
                if !self.pending_telemetry.active {
                    self.schedule_telemetry_broadcast(now_ms);
                }
            }
        }
        report
    }

    /// Stream the full topology graph dump to `sink` (bypasses the SR log ring buffer).
    pub fn emit_topology_log<S: crate::sr_log::TopologyLogSink>(&self, sink: &mut S) {
        self.graph.emit_topology_log(self.node_num, sink);
    }

    /// Receiving radio index for a captured inbound frame (v1: single radio).
    pub fn received_on_radio(packet: &InboundPacket<'_>) -> u8 {
        packet.radio_id
    }

    /// Resolve the NodeNum of the relaying neighbor for SR flooding decisions.
    pub fn resolve_heard_from_node(
        &mut self,
        relay_node: u8,
        source: u32,
        rssi: i16,
        snr: i8,
        now_ms: u32,
    ) -> u32 {
        self.relay_identity.resolve_heard_from(
            relay_node,
            source,
            rssi,
            snr,
            &self.graph,
            now_ms,
        )
    }

    /// Record a relay-byte mapping (host tests and topology learning paths).
    #[doc(hidden)]
    pub fn remember_relay_identity(&mut self, node_id: u32, relay_byte: u8, now_ms: u32) {
        self.relay_identity
            .remember_relay_identity(node_id, relay_byte, now_ms);
    }

    fn try_resolve_placeholder(&mut self, relay_byte: u8, real_node_id: u32, now_ms: u32) -> bool {
        if relay_byte == 0 || crate::graph::is_placeholder_node(real_node_id) {
            return false;
        }
        let placeholder_id = crate::graph::get_placeholder_for_relay(relay_byte);
        if self.relay_identity.resolve_relay_identity(
            relay_byte,
            0,
            0,
            self.graph.edges(),
            self.node_num,
            now_ms,
        ).is_some()
        {
            return false;
        }
        if !self
            .graph
            .resolve_placeholder(placeholder_id, real_node_id, now_ms)
        {
            return false;
        }
        self.relay_identity
            .remember_relay_identity(real_node_id, relay_byte, now_ms);
        true
    }

    /// Cancel a scheduled T1 broadcast retransmit (fork: cancelBroadcastRetransmit).
    pub fn cancel_broadcast_retransmit(&mut self, packet_id: u32) {
        self.cancel_t1_retransmit(packet_id, T1CancelReason::RelayHeard);
    }

    /// True when every direct neighbor is covered by accumulated transmitters (broadcast dupe cancel).
    pub fn all_neighbors_covered(&mut self, from: u32, packet_id: u32, dupe_relayer: u32) -> bool {
        self.graph
            .all_neighbors_covered(from, packet_id, dupe_relayer)
    }

    /// True when router has scheduled TX work (relays, topology, ACKs, retransmits).
    pub fn has_pending_work(&self) -> bool {
        self.pending.iter().any(|p| p.active)
            || self.pending_topology.active
            || self.pending_nodeinfo.active
            || self.pending_telemetry.active
            || self.pending_traceroute.active
            || self.pending_ack.active
            || self.pending_retransmits.iter().any(|p| p.active && !p.canceled)
            || self.pending_reliable.iter().any(|p| p.active)
            || self.graph.has_active_relay_commits()
    }

    /// Originate an app payload on the primary channel (optionally with reliable retransmit).
    pub fn send_local(
        &mut self,
        to: u32,
        portnum: u32,
        payload: &[u8],
        want_ack: bool,
        hop_limit: u8,
        now_ms: u32,
        airtime_ms: u32,
        slot_ms: u32,
    ) -> Option<RelayPlan> {
        let packet_id = self.alloc_tx_id(now_ms);
        let hop = hop_limit.min(SR_BROADCAST_MAX_HOPS);
        let Some((len, frame)) = build_app_wire_frame(
            to,
            self.node_num,
            packet_id,
            self.channel_hash,
            hop,
            hop,
            want_ack,
            &self.channel_key,
            portnum,
            payload,
            DataEncodeOpts::default(),
        ) else {
            return None;
        };
        if want_ack {
            let _ = schedule_reliable(
                &mut self.pending_reliable,
                packet_id,
                to,
                len,
                frame,
                airtime_ms,
                slot_ms,
                now_ms,
            );
        }
        if to == NODENUM_BROADCAST && portnum != SIGNAL_ROUTING_APP {
            self.schedule_t1_broadcast(packet_id, 0, len, frame, airtime_ms, now_ms);
        }
        Some(RelayPlan {
            len,
            bytes: frame,
            delay_ms: 0,
        })
    }

    pub fn note_rx_airtime(&mut self, airtime_ms: u32) {
        bump_reliable_delays(&mut self.pending_reliable, airtime_ms);
    }

    pub fn poll_reliable_retransmit(
        &mut self,
        now_ms: u32,
        airtime_ms: u32,
        slot_ms: u32,
    ) -> Option<RelayPlan> {
        let (len, bytes) =
            due_retransmit(&mut self.pending_reliable, now_ms, airtime_ms, slot_ms)?;
        Some(RelayPlan {
            len,
            bytes,
            delay_ms: 0,
        })
    }

    pub fn poll_ack_tx(&mut self, now_ms: u32) -> Option<RelayPlan> {
        if !self.pending_ack.active {
            return None;
        }
        if now_ms.wrapping_sub(self.pending_ack.next_tx_ms) >= 0x8000_0000 {
            return None;
        }
        if now_ms < self.pending_ack.next_tx_ms {
            return None;
        }
        self.pending_ack.active = false;
        Some(RelayPlan {
            len: self.pending_ack.len,
            bytes: self.pending_ack.bytes,
            delay_ms: 0,
        })
    }

    pub fn has_pending_reliable(&self, packet_id: u32) -> bool {
        self.pending_reliable
            .iter()
            .any(|s| s.active && s.packet_id == packet_id)
    }

    pub fn poll_nodeinfo_tx(&mut self, now_ms: u32) -> Option<RelayPlan> {
        if !self.pending_nodeinfo.active {
            return None;
        }
        if now_ms.wrapping_sub(self.pending_nodeinfo.next_tx_ms) >= 0x8000_0000 {
            return None;
        }
        if now_ms < self.pending_nodeinfo.next_tx_ms {
            return None;
        }
        self.pending_nodeinfo.active = false;
        Some(RelayPlan {
            len: self.pending_nodeinfo.len,
            bytes: self.pending_nodeinfo.bytes,
            delay_ms: 0,
        })
    }

    pub fn poll_telemetry_tx(&mut self, now_ms: u32) -> Option<RelayPlan> {
        if !self.pending_telemetry.active {
            return None;
        }
        if now_ms.wrapping_sub(self.pending_telemetry.next_tx_ms) >= 0x8000_0000 {
            return None;
        }
        if now_ms < self.pending_telemetry.next_tx_ms {
            return None;
        }
        self.pending_telemetry.active = false;
        Some(RelayPlan {
            len: self.pending_telemetry.len,
            bytes: self.pending_telemetry.bytes,
            delay_ms: 0,
        })
    }

    pub fn poll_traceroute_tx(&mut self, now_ms: u32) -> Option<RelayPlan> {
        if !self.pending_traceroute.active {
            return None;
        }
        if now_ms.wrapping_sub(self.pending_traceroute.next_tx_ms) >= 0x8000_0000 {
            return None;
        }
        if now_ms < self.pending_traceroute.next_tx_ms {
            return None;
        }
        self.pending_traceroute.active = false;
        Some(RelayPlan {
            len: self.pending_traceroute.len,
            bytes: self.pending_traceroute.bytes,
            delay_ms: 0,
        })
    }

    pub fn poll_topology_tx(&mut self, now_ms: u32) -> Option<RelayPlan> {
        if !self.pending_topology.active {
            return None;
        }
        if now_ms.wrapping_sub(self.pending_topology.next_tx_ms) >= 0x8000_0000 {
            return None;
        }
        if now_ms < self.pending_topology.next_tx_ms {
            return None;
        }
        let idx = self.pending_topology.next_idx as usize;
        if idx >= self.pending_topology.count as usize {
            self.pending_topology.active = false;
            return None;
        }
        let len = self.pending_topology.lens[idx];
        let bytes = self.pending_topology.frames[idx];
        self.pending_topology.next_idx = self.pending_topology.next_idx.saturating_add(1);
        if self.pending_topology.next_idx >= self.pending_topology.count {
            self.pending_topology.active = false;
        } else {
            self.pending_topology.next_tx_ms = now_ms.wrapping_add(self.pending_topology.spacing_ms);
        }
        Some(RelayPlan {
            len,
            bytes,
            delay_ms: 0,
        })
    }

    pub fn free_pool_slots(&self) -> usize {
        self.pool.free_count()
    }

    fn process_reliable_rx(
        &mut self,
        parsed: &ParsedPacket,
        data: Option<&DecodedData>,
        inner: Option<&[u8]>,
        now_ms: u32,
    ) {
        let to_us = parsed.to == self.node_num;
        if !to_us {
            return;
        }
        if let Some(data) = data {
            if data.portnum == ROUTING_APP {
                if let Some(inner) = inner {
                    if data.request_id != 0 {
                        if decode_routing_payload(inner).is_some() {
                            let _ = stop_reliable(&mut self.pending_reliable, data.request_id);
                        }
                    }
                }
                return;
            }
            if parsed.from != self.node_num
                && parsed.from != 0
                && parsed.want_ack
                && data.request_id == 0
                && data.reply_id == 0
            {
                self.schedule_ack(parsed, parsed.channel, now_ms);
            }
        } else if parsed.from != self.node_num
            && parsed.from != 0
            && parsed.want_ack
        {
            self.schedule_nak(parsed, ROUTING_ERROR_NO_CHANNEL, now_ms);
        }
    }

    fn schedule_ack(&mut self, parsed: &ParsedPacket, channel_hash: u8, now_ms: u32) {
        if self.pending_ack.active {
            return;
        }
        let hop = hop_limit_for_response(parsed, self.hop_limit);
        let packet_id = self.alloc_tx_id(now_ms);
        let Some((len, frame)) = build_ack_nak_frame(
            parsed.from,
            self.node_num,
            packet_id,
            parsed.id,
            channel_hash,
            hop,
            ROUTING_ERROR_NONE,
            &self.channel_key,
        ) else {
            return;
        };
        self.pending_ack = PendingAck {
            active: true,
            next_tx_ms: now_ms,
            len,
            bytes: frame,
        };
    }

    fn schedule_nak(&mut self, parsed: &ParsedPacket, error: u32, now_ms: u32) {
        if self.pending_ack.active {
            return;
        }
        let hop = hop_limit_for_response(parsed, self.hop_limit);
        let packet_id = self.alloc_tx_id(now_ms);
        let Some((len, frame)) = build_ack_nak_frame(
            parsed.from,
            self.node_num,
            packet_id,
            parsed.id,
            parsed.channel,
            hop,
            error,
            &self.channel_key,
        ) else {
            return;
        };
        self.pending_ack = PendingAck {
            active: true,
            next_tx_ms: now_ms,
            len,
            bytes: frame,
        };
    }

    fn process_nodeinfo_rx(&mut self, parsed: &ParsedPacket, payload: &[u8], now_ms: u32) {
        if parsed.from == 0 || parsed.from == self.node_num {
            return;
        }
        if self.graph.has_our_transmission(parsed.id) {
            return;
        }
        let Some(identity) = decode_user(payload) else {
            return;
        };
        let advert = identity.advert;
        let mut short_name = [0u8; 5];
        let short_len = advert.short_name_len.min(NODEINFO_SHORT_NAME_MAX as u8);
        short_name[..short_len as usize]
            .copy_from_slice(&advert.short_name[..short_len as usize]);
        let role = advert.role;
        let is_new = self.nodeinfo_cache.upsert(parsed.from, identity, now_ms);
        self.graph
            .track_node_role(parsed.from, advert.role, now_ms);
        self.sr_log.push(SrLogEvent::NodeInfoReceived {
            from: parsed.from,
            short_len,
            short_name,
            role,
            is_new,
        });
    }

    fn schedule_nodeinfo_broadcast(&mut self, now_ms: u32) {
        let packet_id = self.alloc_tx_id(now_ms);
        let Some((len, frame)) = build_nodeinfo_wire_frame(
            self.node_num,
            packet_id,
            self.channel_hash,
            self.hop_limit,
            &self.channel_key,
            &self.nodeinfo_identity,
        ) else {
            return;
        };
        self.queue_nodeinfo_tx(now_ms, len, frame);
        self.last_nodeinfo_ms = now_ms;
    }

    fn schedule_nodeinfo_unicast(&mut self, to: u32, reply_id: u32, now_ms: u32) {
        let packet_id = self.alloc_tx_id(now_ms);
        let Some((len, frame)) = build_nodeinfo_reply_frame(
            to,
            self.node_num,
            packet_id,
            reply_id,
            self.channel_hash,
            self.hop_limit,
            &self.channel_key,
            &self.nodeinfo_identity,
        ) else {
            return;
        };
        self.queue_nodeinfo_tx(now_ms, len, frame);
    }

    fn queue_nodeinfo_tx(&mut self, now_ms: u32, len: u8, frame: [u8; MAX_WIRE_LEN]) {
        self.pending_nodeinfo.active = true;
        self.pending_nodeinfo.next_tx_ms = now_ms;
        self.pending_nodeinfo.len = len;
        self.pending_nodeinfo.bytes = frame;
    }

    fn schedule_telemetry_broadcast(&mut self, now_ms: u32) {
        let packet_id = self.alloc_tx_id(now_ms);
        let Some((len, frame)) = build_device_telemetry_wire_frame(
            self.node_num,
            packet_id,
            self.channel_hash,
            self.hop_limit,
            &self.channel_key,
            &self.device_metrics,
        ) else {
            return;
        };
        self.queue_telemetry_tx(now_ms, len, frame);
        self.last_telemetry_ms = now_ms;
    }

    fn queue_telemetry_tx(&mut self, now_ms: u32, len: u8, frame: [u8; MAX_WIRE_LEN]) {
        self.pending_telemetry.active = true;
        self.pending_telemetry.next_tx_ms = now_ms;
        self.pending_telemetry.len = len;
        self.pending_telemetry.bytes = frame;
    }

    fn maybe_schedule_traceroute_response(
        &mut self,
        parsed: &ParsedPacket,
        data: &DecodedData,
        inner: &[u8],
        snr: i8,
        now_ms: u32,
    ) {
        if parsed.from == self.node_num || parsed.from == 0 {
            return;
        }
        if parsed.to != self.node_num || !data.want_response {
            return;
        }
        let mut rd = match decode_route_discovery(inner) {
            Some(rd) => rd,
            None => return,
        };
        alter_on_relay(&mut rd, parsed, self.node_num, snr, data.request_id);
        let mut route_wire = heapless::Vec::<u8, 128>::new();
        if !encode_route_discovery(&rd, &mut route_wire) {
            return;
        }
        let hop = hop_limit_for_response(parsed, self.hop_limit);
        let packet_id = self.alloc_tx_id(now_ms);
        let Some((len, frame)) = build_app_wire_frame(
            parsed.from,
            self.node_num,
            packet_id,
            parsed.channel,
            hop,
            hop,
            parsed.want_ack,
            &self.channel_key,
            TRACEROUTE_APP,
            &route_wire,
            DataEncodeOpts {
                want_response: false,
                request_id: parsed.id,
                ..Default::default()
            },
        ) else {
            return;
        };
        self.pending_traceroute.active = true;
        self.pending_traceroute.next_tx_ms = now_ms;
        self.pending_traceroute.len = len;
        self.pending_traceroute.bytes = frame;
        self.sr_log.push(SrLogEvent::TracerouteAppended {
            towards: data.request_id == 0,
            route_len: rd.route.len().min(u8::MAX as usize) as u8,
            snr_only: true,
        });
    }

    fn schedule_topology_broadcast(&mut self, now_ms: u32, slot_ms: u32, dirty: bool) -> bool {
        if !self.graph.can_send_topology() {
            return false;
        }
        if dirty {
            self.sr_log.push(SrLogEvent::TopologyDirtySending);
        }
        let topo_v = self.graph.topology_version();
        let packet_count = self.graph.topology_packet_count();
        let neighbors = self.graph.neighbor_count();
        if neighbors == 0 {
            self.sr_log.push(SrLogEvent::EmptyBootBroadcast);
        }
        let mut packed_buf = [0u8; 256];
        let mut built = 0u8;
        for chunk in 0..packet_count {
            let Some(packed_len) = self.graph.build_topology_chunk(chunk, topo_v, &mut packed_buf) else {
                continue;
            };
            let packet_id = self.alloc_tx_id(now_ms);
            let Some((len, frame)) = build_topology_wire_frame(
                self.node_num,
                packet_id,
                self.channel_hash,
                self.hop_limit,
                &self.channel_key,
                &packed_buf[..packed_len],
            ) else {
                continue;
            };
            self.pending_topology.frames[built as usize] = frame;
            self.pending_topology.lens[built as usize] = len;
            built += 1;
        }
        if built == 0 {
            return false;
        }
        self.pending_topology.active = true;
        self.pending_topology.count = built;
        self.pending_topology.next_idx = 0;
        self.pending_topology.next_tx_ms = now_ms;
        self.pending_topology.spacing_ms = slot_ms.saturating_mul(2);
        self.sr_log.push(SrLogEvent::TopologySending {
            node_id: self.node_num,
            neighbors,
            packets: built,
            topo_v,
        });
        true
    }

    fn alloc_tx_id(&mut self, now_ms: u32) -> u32 {
        let id = self.next_tx_id ^ now_ms;
        self.next_tx_id = self.next_tx_id.wrapping_add(1);
        id
    }

    fn store_pending(
        &mut self,
        from: u32,
        id: u32,
        radio_id: u8,
        tx_after_ms: u32,
        len: u8,
        bytes: [u8; MAX_WIRE_LEN],
    ) -> bool {
        if let Some(idx) = self.pending.iter().position(|p| !p.active) {
            self.pending[idx] = PendingRelay {
                active: true,
                from,
                id,
                _radio_id: radio_id,
                tx_after_ms,
                len,
                bytes,
            };
            return true;
        }
        false
    }

    fn cancel_pending(&mut self, from: u32, id: u32) -> bool {
        let mut canceled = false;
        for pending in &mut self.pending {
            if pending.active && pending.from == from && pending.id == id {
                pending.active = false;
                canceled = true;
            }
        }
        canceled
    }

    fn has_pending_relay(&self, from: u32, id: u32) -> bool {
        self.pending
            .iter()
            .any(|p| p.active && p.from == from && p.id == id)
    }

    fn cancel_pending_lower_hop(&mut self, from: u32, id: u32, threshold: u8) -> bool {
        let mut canceled = false;
        for pending in &mut self.pending {
            if !pending.active || pending.from != from || pending.id != id {
                continue;
            }
            let hop = pending.bytes[12] & 0x07;
            if hop < threshold {
                pending.active = false;
                canceled = true;
            }
        }
        canceled
    }

    fn try_handle_upgraded_packet(&mut self, parsed: &ParsedPacket) -> bool {
        if !self.graph.is_rebroadcaster() || parsed.hop_limit == 0 {
            return false;
        }
        let dropped = self.cancel_pending_lower_hop(parsed.from, parsed.id, parsed.hop_limit);
        if dropped {
            self.graph.cancel_relay(parsed.from, parsed.id);
        }
        dropped
    }

    fn is_repeated_reliable_tx(parsed: &ParsedPacket, sr_active: bool) -> bool {
        if sr_active {
            return false;
        }
        parsed.hop_start > 0 && parsed.hop_start == parsed.hop_limit
    }

    fn maybe_cancel_relay_for_foreign_ack(&mut self, parsed: &ParsedPacket, data: &DecodedData) {
        if parsed.to == self.node_num || parsed.to == NODENUM_BROADCAST {
            return;
        }
        let cancel_id = if data.request_id != 0 {
            data.request_id
        } else if data.reply_id != 0 {
            data.reply_id
        } else {
            return;
        };
        let _ = self.cancel_pending(parsed.to, cancel_id);
    }

    fn handle_duplicate_rx(
        &mut self,
        parsed: &ParsedPacket,
        decoded_data: Option<&DecodedData>,
        packet: &InboundPacket<'_>,
        now_ms: u32,
    ) {
        if let Some(data) = decoded_data {
            self.maybe_cancel_relay_for_foreign_ack(parsed, data);
        }

        if Self::is_repeated_reliable_tx(parsed, self.graph.is_active_routing_role()) {
            if parsed.to == self.node_num && parsed.want_ack {
                self.schedule_ack(parsed, parsed.channel, now_ms);
            }
            return;
        }

        self.perhaps_cancel_dupe(parsed, packet, now_ms);
    }

    fn duplicate_is_rebroadcast(parsed: &ParsedPacket, our_node: u32) -> bool {
        let our_low = (our_node & 0xFF) as u8;
        parsed.hop_limit < parsed.hop_start
            || (parsed.relay_node != 0
                && parsed.relay_node != our_low
                && parsed.relay_node != (parsed.from & 0xFF) as u8)
    }

    fn perhaps_cancel_dupe(
        &mut self,
        parsed: &ParsedPacket,
        packet: &InboundPacket<'_>,
        now_ms: u32,
    ) {
        let committed = self.graph.is_committed_relay(parsed.from, parsed.id);
        let has_pending = self.has_pending_relay(parsed.from, parsed.id);
        let rebroadcast = Self::duplicate_is_rebroadcast(parsed, self.node_num);

        if committed {
            if !has_pending {
                self.cancel_t1_retransmit(parsed.id, T1CancelReason::RelayHeard);
                if self.graph.role_allows_canceling_dupe() {
                    self.graph.cancel_relay(parsed.from, parsed.id);
                    self.sr_log.push(SrLogEvent::BroadcastDupeCancel {
                        id: parsed.id,
                        from: parsed.from,
                    });
                }
                return;
            }
            if rebroadcast {
                let heard_from = self.resolve_heard_from_node(
                    parsed.relay_node,
                    parsed.from,
                    packet.rssi,
                    packet.snr,
                    now_ms,
                );
                if !self.all_neighbors_covered(parsed.from, parsed.id, heard_from) {
                    return;
                }
            }
        }

        if self.graph.role_allows_canceling_dupe() {
            if rebroadcast {
                self.graph.cancel_relay_on_rebroadcast(
                    parsed.from,
                    parsed.id,
                    parsed.hop_start,
                    parsed.hop_limit,
                    parsed.relay_node,
                    self.node_num,
                    now_ms,
                );
            } else {
                self.graph.cancel_relay(parsed.from, parsed.id);
            }
            let had_relay = self
                .graph
                .relay_tx_after(parsed.from, parsed.id, packet.radio_id)
                .is_some();
            let canceled_pending = self.cancel_pending(parsed.from, parsed.id);
            if had_relay || canceled_pending {
                self.sr_log.push(SrLogEvent::BroadcastDupeCancel {
                    id: parsed.id,
                    from: parsed.from,
                });
            }
        }

        self.cancel_t1_retransmit(parsed.id, T1CancelReason::RelayHeard);

        if parsed.from == self.node_num {
            let _ = stop_reliable(&mut self.pending_reliable, parsed.id);
        }
    }

    pub fn poll_t1_retransmit(&mut self, now_ms: u32) -> Option<RelayPlan> {
        for slot in &mut self.pending_retransmits {
            if !slot.active || slot.canceled {
                continue;
            }
            if now_ms.wrapping_sub(slot.fire_after_ms) >= 0x8000_0000 {
                continue;
            }
            if now_ms < slot.fire_after_ms {
                continue;
            }
            if self.graph.all_hears_us_neighbors_heard_packet(
                slot.packet_id,
                slot.heard_from,
                now_ms,
            ) {
                let id = slot.packet_id;
                slot.active = false;
                slot.canceled = true;
                self.sr_log.push(SrLogEvent::T1Canceled {
                    id,
                    reason: T1CancelReason::AllHearsUsHeard,
                });
                continue;
            }
            let plan = RelayPlan {
                len: slot.len,
                bytes: slot.bytes,
                delay_ms: 0,
            };
            let id = slot.packet_id;
            slot.active = false;
            self.sr_log.push(SrLogEvent::T1Fired { id });
            return Some(plan);
        }
        None
    }

    fn maybe_schedule_t1_retransmit(
        &mut self,
        parsed: &ParsedPacket,
        len: u8,
        bytes: [u8; MAX_WIRE_LEN],
        decoded_portnum: Option<u32>,
        airtime_ms: u32,
        now_ms: u32,
        require_relay_commit: bool,
    ) {
        if parsed.to != NODENUM_BROADCAST {
            return;
        }
        if decoded_portnum == Some(SIGNAL_ROUTING_APP) {
            return;
        }
        if !self.graph.has_any_hears_us_neighbor() {
            return;
        }
        if require_relay_commit && !self.graph.is_committed_relay(parsed.from, parsed.id) {
            return;
        }
        self.schedule_t1_broadcast(parsed.id, parsed.from, len, bytes, airtime_ms, now_ms);
    }

    fn schedule_t1_broadcast(
        &mut self,
        packet_id: u32,
        heard_from: u32,
        len: u8,
        bytes: [u8; MAX_WIRE_LEN],
        airtime_ms: u32,
        now_ms: u32,
    ) {
        for slot in &self.pending_retransmits {
            if slot.active && slot.packet_id == packet_id {
                return;
            }
        }
        let Some(idx) = self
            .pending_retransmits
            .iter()
            .position(|s| !s.active || s.canceled)
        else {
            return;
        };
        let fire_delay = tx_delay_ms_worst(self.cw_slot_ms()).saturating_add(airtime_ms);
        self.pending_retransmits[idx] = PendingRetransmit {
            active: true,
            canceled: false,
            packet_id,
            heard_from,
            fire_after_ms: now_ms.wrapping_add(fire_delay),
            len,
            bytes,
        };
        self.sr_log.push(SrLogEvent::T1Scheduled {
            id: packet_id,
            delay_ms: fire_delay,
        });
    }

    fn cancel_t1_retransmit(&mut self, packet_id: u32, reason: T1CancelReason) {
        for slot in &mut self.pending_retransmits {
            if slot.active && !slot.canceled && slot.packet_id == packet_id {
                slot.active = false;
                slot.canceled = true;
                self.sr_log.push(SrLogEvent::T1Canceled { id: packet_id, reason });
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinated_relay;
    use mesh_protocol::PacketHeader;
    use static_cell::StaticCell;

    fn encode_wire(header: PacketHeader, payload: &[u8]) -> heapless::Vec<u8, 128> {
        let mut out = heapless::Vec::new();
        let mut hdr = [0u8; PACKET_HEADER_LEN];
        header.encode_to(&mut hdr);
        out.extend_from_slice(&hdr).unwrap();
        out.extend_from_slice(payload).unwrap();
        out
    }

    #[test]
    fn relays_third_party_opaque_packet() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0xDEAD_BEEF));

        let header =
            PacketHeader::from_fields(0xFFFF_FFFF, 0x1234_5678, 42, 0, 3, 3, false, false, 0, 0);
        let cipher = [0xAA, 0xBB, 0xCC, 0xDD];
        let wire = encode_wire(header, &cipher);

        let inbound = InboundPacket {
            radio_id: 0,
            rssi: -80,
            snr: 8,
            bytes: &wire,
        };

        let result = router
            .process_inbound(&inbound, 0)
            .expect("process inbound");
        assert!(!result.duplicate);
        assert_eq!(router.neighbor_count(), 1);
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        assert!(plan.relay.is_some() || router.poll_ready_relay(500).is_some());
    }

    #[test]
    fn duplicate_suppresses_relay() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0x1111_1111));

        let header = PacketHeader::from_fields(1, 2, 99, 0, 2, 2, false, false, 0, 0);
        let wire = encode_wire(header, &[1, 2, 3]);

        let inbound = InboundPacket {
            radio_id: 0,
            rssi: 0,
            snr: 0,
            bytes: &wire,
        };

        assert!(router
            .process_inbound(&inbound, 0)
            .unwrap()
            .handle
            .is_some());
        let dup = router.process_inbound(&inbound, 100).unwrap();
        assert!(dup.duplicate);
        assert!(router
            .evaluate_tx_plan(&dup, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 100)
            .relay
            .is_none());
        assert!(router.poll_ready_relay(100).is_none());
    }

    #[test]
    fn delayed_relay_fires_after_slot() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0x677a_1caf));

        let header =
            PacketHeader::from_fields(0xFFFF_FFFF, 0xAABB_CCDD, 7, 0, 3, 3, false, false, 0, 0);
        let wire = encode_wire(header, &[1, 2, 3, 4]);

        let inbound = InboundPacket {
            radio_id: 0,
            rssi: -82,
            snr: 12,
            bytes: &wire,
        };

        let result = router.process_inbound(&inbound, 1_000).unwrap();
        let plan = router.evaluate_tx_plan(
            &result,
            0.0,
            coordinated_relay::DEFAULT_SLOT_MS,
            1_000,
        );
        if plan.relay.is_some() {
            return;
        }
        let tx_after = router
            .relay_tx_after(0xAABB_CCDD, 7, 0)
            .expect("commit");
        assert!(router.poll_ready_relay(tx_after.saturating_sub(1)).is_none());
        assert!(router.poll_ready_relay(tx_after).is_some());
    }

    #[test]
    fn t1_retransmit_fires_after_window() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0x677a_1caf));

        let neighbor_wire = encode_wire(
            PacketHeader::from_fields(0xFFFF_FFFF, 0x1111_1111, 1, 0, 3, 3, false, false, 0, 0),
            &[0x01],
        );
        router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -65,
                    snr: 12,
                    bytes: &neighbor_wire,
                },
                900,
            )
            .unwrap();
        router.confirm_direct_neighbor_hears_us(0x1111_1111);

        let header = PacketHeader::from_fields(
            NODENUM_BROADCAST,
            0x2222_2222,
            99,
            0,
            3,
            3,
            false,
            false,
            0,
            0,
        );
        let wire = encode_wire(header, &[0x01, 0x02]);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 10,
                    bytes: &wire,
                },
                1_000,
            )
            .unwrap();
        let airtime = coordinated_relay::DEFAULT_SLOT_MS * 10;
        let _plan = router.evaluate_tx_plan(&result, 0.0, airtime, 1_000);

        let fire_ms = coordinated_relay::tx_delay_ms_worst(coordinated_relay::DEFAULT_SLOT_MS)
            .saturating_add(airtime);
        assert!(router.poll_t1_retransmit(1_000 + fire_ms - 1).is_none());
        assert!(router.poll_t1_retransmit(1_000 + fire_ms).is_some());
    }

    #[test]
    fn has_pending_work_after_relay_commit() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0x677a_1caf));

        assert!(!router.has_pending_work());

        let header =
            PacketHeader::from_fields(0xFFFF_FFFF, 0xAABB_CCDD, 7, 0, 3, 3, false, false, 0, 0);
        let wire = encode_wire(header, &[1, 2, 3, 4]);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -82,
                    snr: 12,
                    bytes: &wire,
                },
                1_000,
            )
            .unwrap();
        let _plan = router.evaluate_tx_plan(
            &result,
            0.0,
            coordinated_relay::DEFAULT_SLOT_MS,
            1_000,
        );
        assert!(router.has_pending_work());
    }
}
