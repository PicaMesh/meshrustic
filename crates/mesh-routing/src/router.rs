//! Unified routing core — RX pipeline, graph maintenance, coordinated relay (Phase 6).

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::{
    is_direct_packet, PacketHeader, ParsedPacket, NODENUM_BROADCAST, PACKET_HEADER_LEN,
};
use mesh_radio::{
    eu868_config_for_preset, packet_time_ms, primary_channel_hash, MODEM_DEFAULT_PRESET,
};

use crate::admin::{
    encode_admin_response, encode_owner_response, handle_admin, AdminState,
    ROUTING_ERROR_ADMIN_PUBLIC_KEY_UNAUTHORIZED, ROUTING_ERROR_PKI_FAILED,
    ROUTING_ERROR_PKI_UNKNOWN_PUBKEY,
};
use crate::admin_codec::{AdminPayload, ADMIN_APP};
use crate::coordinated_relay::{
    half_airtime_ms, slot_time_for_preset, tx_delay_ms_contention, tx_delay_ms_worst,
};
use crate::neighbor_graph::LAST_HOP_BUDGET;
use crate::neighbor_graph::{
    MaintenanceReport, NeighborGraph, TopologyMergeResult, NEIGHBOR_TTL_MS, TOPOLOGY_BROADCAST_MS,
    TOPOLOGY_DIRTY_MIN_MS,
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
use crate::relay::{copy_opaque_payload, relay_header_with_next_hop_opts, wire_may_relay};
use crate::relay_identity::RelayIdentityCache;
use crate::reliable::{
    bump_reliable_delays, due_retransmit, schedule_reliable, stop_reliable, stop_reliable_for,
    PendingReliable, MAX_PENDING_RELIABLE,
};
use crate::routing_ack::{
    build_ack_nak_frame, decode_routing_payload, encode_routing_error, hop_limit_for_response,
    hops_away, retransmission_delay_ms, ROUTING_APP, ROUTING_ERROR_NONE, ROUTING_ERROR_NO_CHANNEL,
};
use crate::rx_decode::{summarize_decrypted, RxDecodeInfo};
use crate::sr_log::{
    RelayRetxCancelReason, SrLog, SrLogEvent, SrSkipReason, T1CancelReason, MAX_SR_LOG,
};
use crate::telemetry::{
    build_device_telemetry_wire_frame, DeviceMetricsSnapshot, DEVICE_TELEMETRY_BROADCAST_MS,
};
use crate::topology::{
    build_app_wire_frame, build_topology_wire_frame, extract_packed_neighbors,
    try_decrypt_data_full, DataBitfield, DataEncodeOpts, DecodedData, MAX_TOPOLOGY_PACKETS,
    SIGNAL_ROUTING_APP, SIGNAL_ROUTING_VERSION, SR_BROADCAST_MAX_HOPS,
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
    /// The frame left the router but may still be waiting behind listen-before-talk. A copy
    /// heard now must pull it back out of the radio queue, exactly as a committed relay does:
    /// without this an insurer that fired before hearing the first one put a second copy on the
    /// air 0.4 to 1.0 s later (six times in 109 min, field 2026-09-08).
    fired: bool,
    packet_id: u32,
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

const MAX_PENDING_ADMIN: usize = 4;

#[derive(Clone, Copy)]
struct PendingAdmin {
    active: bool,
    next_tx_ms: u32,
    len: u8,
    bytes: [u8; MAX_WIRE_LEN],
}

/// Minimum spacing between topology lists sent in answer to empty bootstrap broadcasts.
pub const BOOTSTRAP_REPLY_MIN_MS: u32 = 60_000;

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
    /// Uptime at which a direct SR neighbour's empty bootstrap broadcast asked for our list
    /// (0 = nothing pending). The timestamp, not a flag: a list that goes out after the
    /// request has already answered it.
    pending_topology_reply_ms: u32,
    pending_nodeinfo: PendingNodeInfo,
    pending_telemetry: PendingTelemetry,
    pending_traceroute: PendingTraceroute,
    pending_retransmits: [PendingRetransmit; MAX_PENDING_RETRANSMITS],
    pending_reliable: [PendingReliable; MAX_PENDING_RELIABLE],
    /// Latest channel utilization reported by the radio task (drives retransmit backoff).
    channel_util_pct: f32,
    pending_ack: PendingAck,
    pending_admin: [PendingAdmin; MAX_PENDING_ADMIN],
    pending_admin_count: u8,
    /// Packet ids whose relay we cancelled after it may already have been handed to the radio;
    /// the board pulls matching frames back out of the radio's TX queue.
    tx_cancels: heapless::Vec<u32, 8>,
    /// When we last answered an empty bootstrap broadcast with our topology (0 = never).
    /// Bootstrap replies are rate-limited so a burst of empty broadcasts cannot make every node
    /// flood the channel with its list.
    last_bootstrap_reply_ms: u32,
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
    admin: AdminState,
    /// Remote pubkey from last successful PKI admin decrypt (for reply encryption).
    admin_reply_remote_pk: Option<[u8; 32]>,
    /// True when last admin decrypt used PKI (vs channel).
    admin_reply_use_pki: bool,
    /// Pending PKI decrypt failure to NAK when addressed to us.
    pending_pki_error: Option<u32>,
    /// When an admin (or PKI) module reply is queued for this RX, skip a separate
    /// WantAck ACK — the reply's `Data.request_id` already stops reliable retransmit.
    module_reply_suppresses_ack: bool,
    /// LoRa preset changed; board must soft-reinit the radio (no sys_reset).
    pending_radio_reinit: bool,
    /// Packet id of a duplicate that named us as next hop and is being forwarded as a hand-off.
    designated_repeat_id: Option<u32>,
}

impl Router {
    pub fn new(node_num: u32) -> Self {
        Self::with_modem_preset(
            node_num,
            "",
            MODEM_DEFAULT_PRESET,
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
            MODEM_DEFAULT_PRESET,
            true,
            hop_limit,
        )
    }

    /// Router with no node id or channel yet. Boards place this in a `ConstStaticCell` so the
    /// ~70 KB router is laid out at link time instead of being built on the stack: the nRF52840
    /// has ~100 KB of stack above its statics and `with_channel` needs a frame larger than the
    /// router itself, which stopped the boards booting once the graph caps grew.
    /// `load_node_config` must run before the router is used.
    pub const fn unconfigured() -> Self {
        Self::with_channel(0, CryptoKey::none(), 0, MODEM_DEFAULT_PRESET, true, 3)
    }

    pub const fn with_channel(
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
            pending_topology_reply_ms: 0,
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
                fired: false,
                packet_id: 0,
                fire_after_ms: 0,
                len: 0,
                bytes: [0; MAX_WIRE_LEN],
            }; MAX_PENDING_RETRANSMITS],
            pending_reliable: [PendingReliable::inactive(); MAX_PENDING_RELIABLE],
            channel_util_pct: 0.0,
            pending_ack: PendingAck {
                active: false,
                next_tx_ms: 0,
                len: 0,
                bytes: [0; MAX_WIRE_LEN],
            },
            pending_admin: [PendingAdmin {
                active: false,
                next_tx_ms: 0,
                len: 0,
                bytes: [0; MAX_WIRE_LEN],
            }; MAX_PENDING_ADMIN],
            pending_admin_count: 0,
            tx_cancels: heapless::Vec::new(),
            last_bootstrap_reply_ms: 0,
            nodeinfo_identity: NodeInfoIdentity::unconfigured(),
            nodeinfo_cache: NodeInfoCache::new(),
            last_nodeinfo_ms: 0,
            last_nodeinfo_reply_to: 0,
            last_nodeinfo_reply_ms: 0,
            last_telemetry_ms: 0,
            device_metrics: DeviceMetricsSnapshot::EMPTY,
            channel_key,
            channel_hash,
            modem_preset,
            use_preset,
            hop_limit,
            next_tx_id: 1,
            sr_log: SrLog::new(),
            bridge_dedup: crate::bridge::BridgeDedupCache::new(),
            admin: AdminState::new(),
            admin_reply_remote_pk: None,
            admin_reply_use_pki: false,
            pending_pki_error: None,
            module_reply_suppresses_ack: false,
            pending_radio_reinit: false,
            designated_repeat_id: None,
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
        self.admin.public_key = identity.public_key;
    }

    /// Load persisted NodeConfig into admin + channel/modem state.
    pub fn load_node_config(&mut self, cfg: &mesh_store::NodeConfig) {
        self.node_num = cfg.node_num;
        self.graph.set_my_node(cfg.node_num);
        self.rate_limit.set_node_num(cfg.node_num);
        self.admin.apply_node_config(cfg);
        self.nodeinfo_identity = NodeInfoIdentity::for_node(cfg.node_num, cfg.public_key);
        self.set_modem_preset(
            "",
            cfg.lora.modem_preset,
            cfg.lora.use_preset,
            cfg.channel_key,
        );
        self.hop_limit = cfg.lora.hop_limit;
    }

    /// Export admin-managed fields into a NodeConfig for flash save.
    pub fn write_admin_into_config(&self, cfg: &mut mesh_store::NodeConfig) {
        self.admin.export_to_node_config(cfg);
        cfg.channel_key = self.channel_key;
        cfg.node_num = self.node_num;
    }

    pub fn admin_config_dirty(&self) -> bool {
        self.admin.config_dirty
    }

    pub fn clear_admin_config_dirty(&mut self) {
        self.admin.config_dirty = false;
    }

    pub fn take_pending_reboot_seconds(&mut self) -> Option<i32> {
        self.admin.pending_reboot_seconds.take()
    }

    /// True after a LoRa preset change — board should reinit SX1262 without sys_reset.
    pub fn take_pending_radio_reinit(&mut self) -> bool {
        core::mem::take(&mut self.pending_radio_reinit)
    }

    /// The board applied a new modem preset. Everything still queued was heard on, timed for
    /// and addressed to nodes on the old air parameters: relays and T1 insurance of packets
    /// nobody on the new preset saw, reliable retries and routing ACKs the requester (who
    /// stays on its preset) can no longer hear, and admin replies to that requester. Periodic
    /// topology, NodeInfo and telemetry broadcasts stay: they introduce us on the new preset.
    pub fn radio_reconfigured(&mut self) {
        let mut dropped = 0usize;
        for p in &mut self.pending {
            if p.active {
                p.active = false;
                dropped += 1;
            }
        }
        for p in &mut self.pending_retransmits {
            if p.active {
                p.active = false;
                dropped += 1;
            }
        }
        for p in &mut self.pending_reliable {
            if p.active {
                p.active = false;
                dropped += 1;
            }
        }
        if self.pending_ack.active {
            self.pending_ack.active = false;
            dropped += 1;
        }
        for p in &mut self.pending_admin {
            if p.active {
                p.active = false;
                dropped += 1;
            }
        }
        self.pending_admin_count = 0;
        if self.pending_traceroute.active {
            self.pending_traceroute.active = false;
            dropped += 1;
        }
        self.pending_topology_reply_ms = 0;
        dropped += self.graph.clear_relays();
        self.sr_log.push(SrLogEvent::RadioReconfigured {
            dropped: dropped.min(u8::MAX as usize) as u8,
        });
    }

    /// Host/unit-test only: run admin handler as if `remote_pk` completed PKI decrypt.
    ///
    /// Not compiled into firmware builds (no `std` / `test`). Prefer real PKI frames in
    /// integration tests whenever a keypair is available.
    #[cfg(any(test, feature = "std"))]
    pub fn process_admin_as_pki_peer_for_test(
        &mut self,
        remote_pk: &[u8; 32],
        from: u32,
        request_id: u32,
        inner: &[u8],
        now_ms: u32,
    ) {
        self.admin_reply_remote_pk = Some(*remote_pk);
        self.admin_reply_use_pki = true;
        let parsed = ParsedPacket {
            to: self.node_num,
            from,
            id: request_id,
            channel: 0,
            hop_limit: 3,
            hop_start: 3,
            want_ack: false,
            via_mqtt: false,
            next_hop: 0,
            relay_node: 0,
        };
        self.process_admin_rx(&parsed, inner, true, now_ms);
    }

    /// Host/unit-test only: replace Appendix A builtin pubs with a known keypair set.
    #[cfg(any(test, feature = "std"))]
    pub fn set_builtin_admin_public_keys_for_test(&mut self, keys: [[u8; 32]; 2]) {
        self.admin.set_builtin_admin_public_keys_for_test(keys);
    }

    /// Host/unit-test only: seed NODEINFO cache so PKI decrypt can try `public_key` for `node_num`.
    #[cfg(any(test, feature = "std"))]
    pub fn seed_nodeinfo_peer_for_test(
        &mut self,
        node_num: u32,
        public_key: [u8; 32],
        now_ms: u32,
    ) {
        let identity = NodeInfoIdentity::for_node(node_num, public_key);
        let _ = self.nodeinfo_cache.upsert(node_num, identity, now_ms);
    }

    pub fn admin_state(&self) -> &AdminState {
        &self.admin
    }

    pub fn admin_state_mut(&mut self) -> &mut AdminState {
        &mut self.admin
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
        self.channel_hash = primary_channel_hash(
            stored_channel_name,
            modem_preset,
            use_preset,
            psk_bytes(&channel_key),
        );
    }

    pub fn channel_hash(&self) -> u8 {
        self.channel_hash
    }

    /// Our own configured device role, as the graph holds it.
    ///
    /// The role decides which ladder positions we take and whether peers reserve air for us, so a
    /// capture that does not record it cannot be checked against the ladder it produced.
    pub fn device_role(&self) -> u32 {
        self.graph.device_role()
    }

    pub fn route_to(&mut self, destination: u32, now_ms: u32) -> crate::graph::Route {
        self.graph.route_to(destination, now_ms)
    }

    pub fn edge_heard_on(&self, peer: u32) -> u8 {
        self.graph.edge_heard_on(peer)
    }

    /// Our LoRa "OK to MQTT" setting: the MQTT bit of every Data bitfield we originate.
    pub fn ok_to_mqtt(&self) -> bool {
        self.admin.ok_to_mqtt
    }

    fn ours(&self) -> DataBitfield {
        DataBitfield::Ours {
            ok_to_mqtt: self.admin.ok_to_mqtt,
        }
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
        let _ = self.graph.confirm_direct_neighbor_hears_us(neighbor);
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
            && self.schedule_topology_broadcast(now_ms, slot_ms, false)
        {
            self.graph.commit_topology_broadcast(now_ms, false);
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
        // Per-RX: module replies (admin, traceroute) for this packet suppress a separate WantAck ACK.
        self.module_reply_suppresses_ack = false;
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
                        inner.as_deref(),
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
                // A copy that names our byte as next hop is the previous relay handing the
                // packet to us (stock: `weWereNextHop`): forward it like a fresh reception
                // instead of cancelling. B relayed a traceroute to A, A dropped it as a dupe
                // and B retried three times into silence.
                let our_byte = (self.node_num & 0xFF) as u8;
                let designated_repeat = parsed.to != NODENUM_BROADCAST
                    && parsed.to != self.node_num
                    && parsed.from != self.node_num
                    && parsed.next_hop == our_byte
                    && parsed.hop_limit > 0
                    && self.graph.is_active_routing_role()
                    && !self.graph.has_our_transmission(parsed.id);
                if designated_repeat {
                    // The first copy (naming someone else) may have left a later-slot frame, a
                    // relay commit at that slot and an armed retry: all superseded by the hand-off.
                    self.cancel_pending(parsed.from, parsed.id);
                    self.graph.cancel_relay(parsed.from, parsed.id);
                    self.cancel_relayed_retx(
                        parsed.from,
                        parsed.id,
                        RelayRetxCancelReason::CopyHeard,
                    );
                    self.designated_repeat_id = Some(parsed.id);
                } else {
                    self.handle_duplicate_rx(
                        &parsed,
                        decoded_data.as_ref(),
                        inner.as_deref(),
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

        let known_relay = if !direct && parsed.relay_node != 0 {
            Some(self.resolve_heard_from_node(
                parsed.relay_node,
                parsed.from,
                packet.rssi,
                packet.snr,
                now_ms,
            ))
        } else {
            None
        };

        if let Some((node_id, rssi, snr, is_new, hears_us)) = self.graph.observe_packet(
            parsed.from,
            parsed.hop_start,
            parsed.hop_limit,
            parsed.relay_node,
            packet.rssi,
            packet.snr,
            now_ms,
            packet.radio_id,
            known_relay,
            parsed.id,
        ) {
            if hears_us {
                self.sr_log
                    .push(SrLogEvent::RelayConfirmedHearsUs { node_id });
            }
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
                // The graph marked the topology dirty; the list goes out on the dirty schedule
                // (once TOPOLOGY_DIRTY_MIN_MS has passed since our last broadcast, jittered).
                // Sending a list the instant each neighbour appeared made peers treat every
                // partial boot-time list as authoritative and clear hears_us on their edge to
                // us; the empty boot broadcast already asks them for theirs.
            }
        }

        if self.graph.is_active_routing_role() || direct {
            self.graph.update_node_activity(parsed.from, now_ms);
            if !direct && parsed.relay_node != 0 {
                let from_low = (parsed.from & 0xFF) as u8;
                if parsed.relay_node != from_low {
                    let relay = known_relay
                        .filter(|&id| id != 0 && !crate::graph::is_placeholder_node(id))
                        .unwrap_or_else(|| crate::graph::placeholder_node_id(parsed.relay_node));
                    if relay != parsed.from && relay != self.node_num {
                        self.graph.update_node_activity(relay, now_ms);
                    }
                }
            }
        }

        if direct {
            // A frame that reached us direct and names our byte as its next hop proves the
            // sender hears us: a next hop is learned from traffic received, so it could only
            // have chosen us by hearing us. Same class of evidence as watching a peer carry our
            // frame, and the sender's own list carries it too — but the list can be an interval
            // away, and until then a reply to that neighbour cannot be framed as a last hop, so
            // it goes out with a spare hop and gets relayed (field 2026-09-08: a traceroute
            // reply to a neighbour 47 dB down was carried by two further relays because its
            // requester had not yet published a list naming us).
            let our_byte = (self.node_num & 0xFF) as u8;
            if parsed.to != NODENUM_BROADCAST
                && parsed.from != self.node_num
                && parsed.next_hop != 0
                && parsed.next_hop == our_byte
                && self.graph.confirm_direct_neighbor_hears_us(parsed.from)
            {
                self.sr_log.push(SrLogEvent::RelayConfirmedHearsUs {
                    node_id: parsed.from,
                });
            }
            self.try_resolve_placeholder(&parsed, now_ms);
            let relay_byte = (parsed.from & 0xFF) as u8;
            if relay_byte != 0 {
                self.relay_identity
                    .remember_relay_identity(parsed.from, relay_byte, now_ms);
            }
        }

        let decoded_portnum = decode.portnum;
        // Packets addressed to us are always processed (admin, DMs, requests); the
        // per-source rate limiter only guards relay and graph work for other traffic.
        if parsed.to != self.node_num
            && self.rate_limit.should_drop(
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
                        &parsed, &data, inner, packet.snr, now_ms,
                    );
                }
            } else if data.portnum == ADMIN_APP && parsed.to == self.node_num {
                if let Some(ref inner) = inner {
                    self.process_admin_rx(&parsed, inner, data.has_bitfield, now_ms);
                }
            }
        } else if parsed.to == self.node_num {
            if let Some(err) = self.pending_pki_error.take() {
                self.schedule_admin_routing_error(&parsed, false, err, now_ms);
            }
        }
        self.pending_pki_error = None;

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
        &mut self,
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
            // Channel path must not inherit a prior PKI peer for admin ACL.
            self.admin_reply_remote_pk = None;
            self.admin_reply_use_pki = false;
            self.pending_pki_error = None;
            (
                RxDecodeInfo {
                    portnum: Some(data.portnum),
                    payload_len: inner.len().min(u16::MAX as usize) as u16,
                    summary: summarize_decrypted(data.portnum, &inner),
                },
                Some(inner),
                Some(data),
            )
        } else if parsed.to == self.node_num {
            self.try_pki_decrypt(parsed, wire, payload_len)
        } else {
            self.admin_reply_remote_pk = None;
            self.admin_reply_use_pki = false;
            (
                RxDecodeInfo::encrypted(payload_len.min(u16::MAX as usize) as u16),
                None,
                None,
            )
        }
    }

    fn try_pki_decrypt(
        &mut self,
        parsed: &ParsedPacket,
        wire: &[u8],
        payload_len: usize,
    ) -> (
        RxDecodeInfo,
        Option<heapless::Vec<u8, 240>>,
        Option<DecodedData>,
    ) {
        self.admin_reply_remote_pk = None;
        self.admin_reply_use_pki = false;

        #[cfg(feature = "pki")]
        {
            use crate::topology::decode_data_payload_full;
            use mesh_crypto::CryptoEngine;

            let mut candidates: heapless::Vec<[u8; 32], 8> = heapless::Vec::new();
            for k in self.admin.candidate_pki_keys() {
                let _ = candidates.push(k);
            }
            if let Some(peer) = self.nodeinfo_cache.get(parsed.from) {
                if peer.identity.public_key.iter().any(|&b| b != 0) {
                    let pk = peer.identity.public_key;
                    if !candidates.iter().any(|c| c == &pk) {
                        let _ = candidates.push(pk);
                    }
                }
            }

            let had_candidates = !candidates.is_empty();
            let mut engine = CryptoEngine::new();
            engine.set_dh_private_key(&self.admin.private_key);
            for remote_pk in candidates {
                let mut plain = [0u8; MAX_PACKET_PAYLOAD];
                let cipher = &wire[PACKET_HEADER_LEN..PACKET_HEADER_LEN + payload_len];
                if !engine.decrypt_curve25519(
                    parsed.from,
                    &remote_pk,
                    parsed.id as u64,
                    cipher,
                    &mut plain,
                ) {
                    continue;
                }
                // PKI plaintext length is cipher_len - 12 (MIC + extra nonce).
                if payload_len < 12 {
                    continue;
                }
                let plain_len = payload_len - 12;
                if let Some((data, inner)) = decode_data_payload_full(&plain[..plain_len]) {
                    self.admin_reply_remote_pk = Some(remote_pk);
                    self.admin_reply_use_pki = true;
                    self.pending_pki_error = None;
                    return (
                        RxDecodeInfo {
                            portnum: Some(data.portnum),
                            payload_len: inner.len().min(u16::MAX as usize) as u16,
                            summary: summarize_decrypted(data.portnum, &inner),
                        },
                        Some(inner),
                        Some(data),
                    );
                }
            }
            // Addressed decrypt failed: remember error for reply when a path exists.
            self.pending_pki_error = Some(if had_candidates {
                ROUTING_ERROR_PKI_FAILED
            } else {
                ROUTING_ERROR_PKI_UNKNOWN_PUBKEY
            });
        }
        #[cfg(not(feature = "pki"))]
        {
            let _ = (parsed, wire, payload_len);
            self.pending_pki_error = Some(ROUTING_ERROR_PKI_FAILED);
        }
        (
            RxDecodeInfo::encrypted(payload_len.min(u16::MAX as usize) as u16),
            None,
            None,
        )
    }

    fn process_admin_rx(
        &mut self,
        parsed: &ParsedPacket,
        payload: &[u8],
        hop_start_known: bool,
        now_ms: u32,
    ) {
        // v1: admin is authorized only from this packet's successful PKI remote pubkey.
        let Some(remote_pk) = self
            .admin_reply_remote_pk
            .filter(|_| self.admin_reply_use_pki)
        else {
            self.schedule_admin_routing_error(
                parsed,
                hop_start_known,
                ROUTING_ERROR_ADMIN_PUBLIC_KEY_UNAUTHORIZED,
                now_ms,
            );
            return;
        };

        let outcome = handle_admin(
            &mut self.admin,
            &remote_pk,
            &self.nodeinfo_identity,
            self.node_num,
            psk_bytes(&self.channel_key),
            self.channel_hash,
            self.graph.device_role(),
            payload,
            now_ms,
        );

        if let Some(preset) = outcome.apply_modem_preset {
            self.set_modem_preset("", preset, true, self.channel_key);
            self.pending_radio_reinit = true;
        }
        if let Some(secs) = outcome.reboot_seconds {
            self.admin.pending_reboot_seconds = Some(secs);
        }

        if let Some(err) = outcome.routing_error {
            self.schedule_admin_routing_error(parsed, hop_start_known, err, now_ms);
            return;
        }

        if let Some(resp) = outcome.response {
            self.schedule_admin_response(parsed, hop_start_known, &resp, now_ms);
        } else if outcome.routing_ok {
            // Mutating admin ops complete with ROUTING_APP Error_NONE.
            // This reply also serves as the WantAck ACK (no second ROUTING NONE).
            // Always send — some clients omit Data.want_response on set.
            self.schedule_admin_routing_error(parsed, hop_start_known, ROUTING_ERROR_NONE, now_ms);
        }
    }

    fn schedule_admin_routing_error(
        &mut self,
        parsed: &ParsedPacket,
        hop_start_known: bool,
        error: u32,
        now_ms: u32,
    ) {
        let (hop, next_hop) = self.response_header(parsed, hop_start_known);
        let id = self.alloc_tx_id(now_ms);
        let routing = encode_routing_error(error);
        // Mirror setReplyTo: Data.request_id only (not reply_id), and copy WantAck so the reply
        // alone can stop reliable retransmit (no second ACK).
        let opts = DataEncodeOpts {
            request_id: parsed.id,
            want_response: false,
            bitfield: self.ours(),
            ..Default::default()
        };
        let frame = if let Some(remote_pk) = self.remote_pk_for_error_reply(parsed) {
            self.build_pki_app_frame(
                parsed.from,
                id,
                hop.max(1),
                ROUTING_APP,
                &routing,
                opts,
                &remote_pk,
                parsed.want_ack,
                next_hop,
            )
        } else {
            build_app_wire_frame(
                parsed.from,
                self.node_num,
                id,
                self.channel_hash,
                hop,
                hop,
                parsed.want_ack,
                &self.channel_key,
                ROUTING_APP,
                &routing,
                opts,
                next_hop,
            )
        };
        let Some((len, bytes)) = frame else {
            return;
        };
        self.enqueue_admin_tx(now_ms, len, bytes);
    }

    /// Prefer the current PKI peer, else NODEINFO cache for `from`.
    fn remote_pk_for_error_reply(&self, parsed: &ParsedPacket) -> Option<[u8; 32]> {
        if let Some(pk) = self.admin_reply_remote_pk {
            if pk.iter().any(|&b| b != 0) {
                return Some(pk);
            }
        }
        if let Some(peer) = self.nodeinfo_cache.get(parsed.from) {
            if peer.identity.public_key.iter().any(|&b| b != 0) {
                return Some(peer.identity.public_key);
            }
        }
        None
    }

    fn schedule_admin_response(
        &mut self,
        parsed: &ParsedPacket,
        hop_start_known: bool,
        resp: &crate::admin_codec::AdminMessage,
        now_ms: u32,
    ) {
        let inner = match &resp.payload {
            AdminPayload::GetOwnerResponse(_) if resp.has_session_passkey => encode_owner_response(
                self.node_num,
                &self.nodeinfo_identity,
                &resp.session_passkey,
            ),
            _ => encode_admin_response(resp),
        };
        let hop = hop_limit_for_response(parsed, hop_start_known, self.hop_limit).max(1);
        let next_hop = 0u8;
        let id = self.alloc_tx_id(now_ms);
        // Clients correlate admin replies via Data.request_id (setReplyTo on the wire).
        let opts = DataEncodeOpts {
            want_response: false,
            request_id: parsed.id,
            bitfield: self.ours(),
            ..Default::default()
        };
        let frame = if self.admin_reply_use_pki {
            match self.admin_reply_remote_pk {
                Some(remote_pk) => self.build_pki_app_frame(
                    parsed.from,
                    id,
                    hop,
                    ADMIN_APP,
                    &inner,
                    opts,
                    &remote_pk,
                    parsed.want_ack,
                    next_hop,
                ),
                None => None,
            }
        } else {
            build_app_wire_frame(
                parsed.from,
                self.node_num,
                id,
                self.channel_hash,
                hop,
                hop,
                parsed.want_ack,
                &self.channel_key,
                ADMIN_APP,
                &inner,
                opts,
                next_hop,
            )
        };
        let Some((len, bytes)) = frame else {
            return;
        };
        self.enqueue_admin_tx(now_ms, len, bytes);
    }

    fn enqueue_admin_tx(&mut self, now_ms: u32, len: u8, bytes: [u8; MAX_WIRE_LEN]) {
        // Module reply serves as the WantAck ACK (skip separate first ACK).
        self.module_reply_suppresses_ack = true;
        // Copy of request WantAck ⇒ reliable retx (~NUM_RELIABLE_RETX) until peer ACKs.
        if let Ok(hdr) = PacketHeader::decode(&bytes[..PACKET_HEADER_LEN]) {
            let p = hdr.parse();
            if p.want_ack {
                let delay = self.reliable_retx_delay_ms(len, self.node_num, p.id);
                let _ = schedule_reliable(
                    &mut self.pending_reliable,
                    self.node_num,
                    p.id,
                    p.to,
                    false,
                    len,
                    bytes,
                    delay,
                    now_ms,
                );
            }
        }
        for slot in &mut self.pending_admin {
            if !slot.active {
                *slot = PendingAdmin {
                    active: true,
                    next_tx_ms: now_ms,
                    len,
                    bytes,
                };
                self.pending_admin_count = self
                    .pending_admin_count
                    .saturating_add(1)
                    .min(MAX_PENDING_ADMIN as u8);
                return;
            }
        }
        // Queue full: drop the oldest slot (lowest next_tx_ms) and enqueue.
        let mut oldest = 0usize;
        for i in 1..MAX_PENDING_ADMIN {
            let a = self.pending_admin[i].next_tx_ms;
            let b = self.pending_admin[oldest].next_tx_ms;
            if a.wrapping_sub(b) < 0x8000_0000 && a < b {
                oldest = i;
            }
        }
        self.pending_admin[oldest] = PendingAdmin {
            active: true,
            next_tx_ms: now_ms,
            len,
            bytes,
        };
    }

    fn build_pki_app_frame(
        &self,
        to: u32,
        packet_id: u32,
        hop_limit: u8,
        portnum: u32,
        inner: &[u8],
        opts: DataEncodeOpts,
        remote_pk: &[u8; 32],
        want_ack: bool,
        next_hop: u8,
    ) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
        #[cfg(feature = "pki")]
        {
            use crate::topology::encode_data_payload_opts;
            use mesh_crypto::CryptoEngine;

            let plaintext = encode_data_payload_opts(portnum, inner, opts);
            if plaintext.len() + 12 > MAX_PACKET_PAYLOAD {
                return None;
            }
            let mut engine = CryptoEngine::new();
            engine.set_dh_private_key(&self.admin.private_key);
            let mut cipher = [0u8; MAX_PACKET_PAYLOAD];
            let extra_nonce = packet_id;
            if !engine.encrypt_curve25519(
                remote_pk,
                self.node_num,
                packet_id as u64,
                extra_nonce,
                &plaintext,
                &mut cipher,
            ) {
                return None;
            }
            let cipher_len = plaintext.len() + 12;
            let header = PacketHeader::from_fields(
                to,
                self.node_num,
                packet_id,
                0, // PKI frames use channel 0 on the air header
                hop_limit.min(SR_BROADCAST_MAX_HOPS),
                hop_limit.min(SR_BROADCAST_MAX_HOPS),
                want_ack,
                false,
                next_hop,
                (self.node_num & 0xFF) as u8,
            );
            let mut bytes = [0u8; MAX_WIRE_LEN];
            header.encode_to((&mut bytes[..PACKET_HEADER_LEN]).try_into().ok()?);
            let len = PACKET_HEADER_LEN + cipher_len;
            bytes[PACKET_HEADER_LEN..len].copy_from_slice(&cipher[..cipher_len]);
            Some((len as u8, bytes))
        }
        #[cfg(not(feature = "pki"))]
        {
            let _ = (
                to, packet_id, hop_limit, portnum, inner, opts, remote_pk, want_ack, next_hop,
            );
            None
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
            && (parsed.to == our_node || parsed.to == NODENUM_BROADCAST || data.dest == our_node)
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
                for (sender, destination) in self.graph.drain_merge_asymmetric_skips() {
                    self.sr_log
                        .push(SrLogEvent::TopologyDownstreamSkippedAsymmetric {
                            sender,
                            destination,
                        });
                }
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
        if let Some((from, received, last)) = self.graph.take_topology_version_resync() {
            self.sr_log.push(SrLogEvent::TopologyVersionResync {
                from,
                received,
                last,
            });
        }
        if neighbor_list.is_empty() && is_direct && header.signal_routing_active {
            self.sr_log
                .push(SrLogEvent::TopologyDirtyFromNeighbor { from: parsed.from });
            self.pending_topology_reply_ms = now_ms.max(1);
        }
    }

    fn poll_scheduled_topology_reply(&mut self, now_ms: u32, slot_ms: u32) {
        let requested_ms = self.pending_topology_reply_ms;
        if requested_ms == 0 {
            return;
        }
        self.pending_topology_reply_ms = 0;
        if self.pending_topology.active || !self.graph.can_send_topology() {
            return;
        }
        // Any list we transmitted after the request already answered it: the requester heard
        // our neighbours, and a second list carries the same 5 to 28 entries under the next
        // version number, which every receiver then accepts as a fresh report. On a mesh where
        // two nodes relay for us, one avoidable list is six frames of airtime.
        let last_list_ms = self.graph.last_topology_list_ms();
        if last_list_ms != 0 && (1..0x8000_0000).contains(&last_list_ms.wrapping_sub(requested_ms))
        {
            self.sr_log.push(SrLogEvent::BootstrapReplyAlreadyAnswered);
            return;
        }
        // At most one bootstrap-triggered list per BOOTSTRAP_REPLY_MIN_MS: a burst of empty
        // broadcasts (many nodes rebooting, or a rogue) must not make every node answer each
        // one. The requester is already in our graph and gets the next periodic list.
        if self.last_bootstrap_reply_ms != 0
            && now_ms.wrapping_sub(self.last_bootstrap_reply_ms) < BOOTSTRAP_REPLY_MIN_MS
        {
            self.sr_log.push(SrLogEvent::BootstrapReplyRateLimited);
            return;
        }
        if self.schedule_topology_broadcast(now_ms, slot_ms, false) {
            self.graph.commit_topology_broadcast(now_ms, false);
            self.last_bootstrap_reply_ms = now_ms.max(1);
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

        if !self.graph.is_rebroadcaster() {
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
        ) {
            self.try_resolve_placeholder(&parsed, now_ms);
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
            if relay_plan.should_relay {
                self.graph
                    .record_node_transmission(self.node_num, parsed.id, now_ms);
                // Name the neighbour we are spending the airtime on, taken from the ranking
                // that decided it: a relay nobody needs and a relay that saves a node look
                // identical in the log without it. Recomputing it here against the transmitter
                // alone named a neighbour that a ranked peer does reach.
                if relay_plan.coverage_for != 0 {
                    self.sr_log.push(SrLogEvent::CoverageFor {
                        neighbor: relay_plan.coverage_for,
                    });
                }
            } else {
                // Two reasons can still put a late copy on the air, and both are known now.
                // A transmission we expect: the ranking gave a slot to a stock relay router or
                // a ranked SR peer, and if their copy never comes ours is the
                // redundancy that covers the loss. Or a witness owed: the originator asked to
                // be told (`want_ack`) and heard us directly, so our copy is the rebroadcast
                // stock turns into its implicit ACK — one elected neighbour answers instead of
                // every one that heard it, and without it the sender retransmits three times.
                let witness_owed = parsed.want_ack
                    && parsed.hop_start == parsed.hop_limit
                    && self.graph.is_elected_witness(parsed.from);
                if relay_plan.slots_given > 0 || witness_owed {
                    self.arm_t1_for_deferred_broadcast(
                        &parsed,
                        handle,
                        heard_from,
                        result.decoded_portnum,
                        slot_ms,
                        half_airtime,
                        now_ms,
                    );
                    self.log_slot_scheduling(&parsed, relay_plan, half_airtime);
                    // Name which kind of transmission we are standing down for. A reserved stock
                    // router and a ranked SR peer are different expectations — one we cannot
                    // predict or coordinate with, the other we can — and merging them into one
                    // reason makes the reservation's effect invisible in a capture.
                    let reason = if relay_plan.reserved_slots > 0 {
                        SrSkipReason::RouterExpected
                    } else {
                        SrSkipReason::BetterNeighbor
                    };
                    self.sr_log.push(SrLogEvent::RelaySkip {
                        from: parsed.from,
                        reason,
                    });
                } else {
                    // Nobody was given a slot and nobody is waiting to be told: there is no
                    // expected transmission for a late copy to stand in for. Measured over
                    // 30 min on three nodes (2026-09-08): this declines ~100 copies per node
                    // and costs no delivery — the asymmetry between two colocated nodes is
                    // 3.2% with it and 2.9% without.
                    self.pool.release(handle);
                    self.log_slot_scheduling(&parsed, relay_plan, half_airtime);
                    self.sr_log.push(SrLogEvent::RelaySkip {
                        from: parsed.from,
                        reason: SrSkipReason::AlreadyCovered,
                    });
                }
                return plan;
            }
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

        // `verified` distinguishes a path whose every hop is backed by evidence that the
        // receiver hears the transmitter from the inbound-gateway fallback, which only guesses
        // that somebody past us can finish. Both may carry a packet; only the first may name a
        // next hop.
        let mut route_verified = true;
        let picked_hop = if parsed.to != NODENUM_BROADCAST {
            // The verdict belongs to the hop we were handed, not to the searched route: the
            // picker also answers with a better-positioned neighbour, the downstream table or
            // ourselves, and none of those is a confirmed path.
            let (hop, hop_verified) =
                self.graph
                    .get_next_hop_verified(parsed.to, parsed.from, heard_from, now_ms);
            if hop != 0 {
                let route = self.graph.get_route(parsed.to, now_ms);
                route_verified = hop_verified;
                self.sr_log.push(SrLogEvent::RouteNextHop {
                    destination: parsed.to,
                    next_hop: hop,
                    cost_x100: route.cost_fixed,
                    hops: route.hops,
                    verified: hop_verified,
                });
            }
            hop
        } else {
            0
        };
        // The route picker answers "relay it ourselves" when it has no verified next hop. That
        // must not go on the air as next_hop = our byte: receivers would treat us as the
        // designated forwarder and wait for a second copy that never comes. Leave it clear so
        // they coordinate by slot, and so we never arm retries waiting for ourselves.
        let mut next_hop = if picked_hop == self.node_num {
            0
        } else {
            picked_hop
        };

        // The packet names us as its next hop: the sender asked us to carry it, so no
        // "somebody else is better placed" reason applies. Without this, a designated hop whose
        // own route pointed back at the node it heard the frame from went silent and only a
        // backup carried the packet, a slot late (seen on both nicenanos, 2026-09-07).
        let we_are_designated_hop =
            parsed.to != NODENUM_BROADCAST && parsed.next_hop == (self.node_num & 0xFF) as u8;

        // Containment. A guessed route that points back at the node we heard the packet from
        // carries the packet away from its destination: onto our own branch, where the only path
        // anyone knows is the one it just arrived on. Nobody there can finish it, so the copy is
        // pure airtime and, for a want_ack unicast, an invitation for the far side to retry
        // through us again. Drop it — unless we were named as the next hop: the sender is
        // waiting on us specifically, its retries would designate us again, and one frame from
        // us costs less than three from it. That case falls through to the clear below, which is
        // also what a verified route pointing back does.
        if parsed.to != NODENUM_BROADCAST
            && !route_verified
            && !we_are_designated_hop
            && next_hop != 0
            && next_hop == heard_from
        {
            self.pool.release(handle);
            self.sr_log.push(SrLogEvent::RelaySkip {
                from: parsed.from,
                reason: SrSkipReason::UnverifiedBacktrack,
            });
            return plan;
        }

        // A guessed route may still be worth carrying in any other direction, but it must not
        // be stamped: the node it names never proved it hears the destination, and receivers
        // treat the byte as a designation, standing down and waiting for a copy from a node
        // that may have no way to send one. Cleared, we stay one candidate among the ranked
        // slots and the others keep coordinating.
        if !route_verified && next_hop != 0 {
            next_hop = 0;
            self.sr_log.push(SrLogEvent::RouteNextHop {
                destination: parsed.to,
                next_hop: 0,
                cost_x100: 0,
                hops: 0,
                verified: false,
            });
        }
        // Hand-off: the previous relay named us and our only route points back at it. Stock
        // floods here (next_hop cleared) rather than dropping the packet, and so do we.
        let designated_repeat = self.designated_repeat_id.take() == Some(parsed.id);
        if designated_repeat && parsed.to != NODENUM_BROADCAST && next_hop == heard_from {
            next_hop = 0;
            self.sr_log.push(SrLogEvent::RouteNextHop {
                destination: parsed.to,
                next_hop: 0,
                cost_x100: 0,
                hops: 0,
                verified: true,
            });
        }

        // Named as next hop while our only route runs back to the node that handed us the
        // packet: forward it, but never back the way it came. Stamping the relayer would bounce
        // it (it named us because its own route points at us), so the copy goes out with no next
        // hop, as a designated repeat of a duplicate already does.
        if we_are_designated_hop && next_hop != 0 && next_hop == heard_from {
            next_hop = 0;
            self.sr_log.push(SrLogEvent::RouteNextHop {
                destination: parsed.to,
                next_hop: 0,
                cost_x100: 0,
                hops: 0,
                verified: false,
            });
        }

        // Relayer already holds the packet and can finish: handing it back is a dupe.
        // If they cannot finish, clear next_hop and stay in the ranking as backup.
        if parsed.to != NODENUM_BROADCAST
            && !we_are_designated_hop
            && next_hop != 0
            && next_hop == heard_from
        {
            let finishes = crate::graph::can_deliver(
                self.graph.edges(),
                Some(self.graph.capability()),
                heard_from,
                parsed.to,
            ) || self.graph.get_downstream_relay(parsed.to, now_ms)
                == Some(heard_from);
            if finishes {
                self.pool.release(handle);
                self.sr_log.push(SrLogEvent::RelaySkip {
                    from: parsed.from,
                    reason: SrSkipReason::NextHopIsRelayer,
                });
                return plan;
            }
            next_hop = 0;
        }

        // Unicasts coordinate by cost to the destination: every SR node that overheard the
        // packet ranks itself and its SR neighbours the same way, the best placed one keys up
        // first and the rest cancel on its copy. Node id used to decide this order, which let
        // the lowest id in the neighbourhood pre-empt the gateway on every unicast.
        let unicast_ranking = if parsed.to != NODENUM_BROADCAST
            && parsed.to != self.node_num
            && self.graph.signal_routing_active()
        {
            Some(self.graph.plan_unicast_relay(
                parsed.id,
                parsed.from,
                heard_from,
                parsed.to,
                picked_hop,
                now_ms,
            ))
        } else {
            None
        };
        // A next hop equal to the destination's own byte names no relayer: the source expects
        // direct delivery (stock learns the destination as its own next hop from a direct
        // reply). Nobody owns slot 0 then; the cost ranking decides as for an unnamed hop.
        let relayer_named = parsed.next_hop != 0 && parsed.next_hop != (parsed.to & 0xFF) as u8;
        let unicast_plan = match unicast_ranking {
            Some(Err(reason)) if !relayer_named => {
                self.pool.release(handle);
                self.sr_log.push(SrLogEvent::RelaySkip {
                    from: parsed.from,
                    reason,
                });
                return plan;
            }
            Some(Ok(mut ranked)) if !relayer_named => {
                // Slot 0 still needs the peer turnaround; keying up at delay 0 loses every
                // receiver still reading the frame we are answering.
                ranked.slot_delay_ms = if ranked.slot_index == 0 {
                    crate::channel_access::SLOT_ORIGIN_MS
                } else {
                    self.sr_peer_relay_wait_ms(slot_ms)
                        .saturating_add((ranked.slot_index as u32 - 1).saturating_mul(half_airtime))
                };
                Some(ranked)
            }
            _ => None,
        };

        // A unicast that already names a next hop keeps SR coordination: the designated node
        // owns slot 0 and every other candidate shifts down one slot, cancelling on any heard copy.
        let designated_plan = if parsed.to != NODENUM_BROADCAST && relayer_named {
            Some(self.plan_designated_unicast(
                &parsed,
                heard_from,
                result.rssi,
                result.snr,
                half_airtime,
                slot_ms,
                now_ms,
                unicast_ranking,
            ))
        } else {
            None
        };
        let mut unicast_plan = unicast_plan.or(designated_plan);

        // Heard straight from the source, and the source's own topology says the destination
        // hears it: the destination most likely has the packet already. A routing ACK on that
        // link is never relayed (a lost ACK is covered by the sender's retransmission). Anything
        // else waits for the destination's ACK or reply, which cancels the queued relay; only
        // silence lets the relay go. Colocated receivers lose about half the frames of a very
        // strong neighbour here, so the relay must stay available, just not be first.
        if parsed.to != NODENUM_BROADCAST && heard_from == parsed.from {
            let src_edge = self
                .graph
                .edges()
                .find_node(parsed.from)
                .and_then(|n| n.find_edge(parsed.to))
                .copied();
            if let Some(edge) = src_edge {
                let is_routing_reply = result.decoded_portnum == Some(ROUTING_APP)
                    && result.decoded_data.is_some_and(|d| d.request_id != 0);
                if is_routing_reply {
                    self.pool.release(handle);
                    self.sr_log.push(SrLogEvent::RelaySkip {
                        from: parsed.from,
                        reason: SrSkipReason::ReplyRetracesLink,
                    });
                    return plan;
                }
                if edge.hears_us {
                    if let Some(p) = unicast_plan.as_mut() {
                        let wait = self.dest_ack_wait_ms(slot_ms);
                        p.slot_delay_ms = p.slot_delay_ms.saturating_add(wait);
                        self.sr_log.push(SrLogEvent::UnicastDestHeardDirect {
                            id: parsed.id,
                            wait_ms: wait,
                        });
                    }
                }
            }
        }

        let last_hop = parsed.to != NODENUM_BROADCAST && self.graph.caps_last_hop(parsed.to);
        let relay_hdr =
            match relay_header_with_next_hop_opts(&parsed, self.node_num, next_hop, last_hop) {
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

        // 2. A unicast leaving us with hop_limit 0 can only still be delivered by a node that
        // is the destination itself; without a direct link to the target it is dead airtime.
        if parsed.to != NODENUM_BROADCAST
            && relay_hdr.hop_limit() == 0
            && !self.graph.has_direct_edge(parsed.to)
        {
            self.pool.release(handle);
            self.sr_log.push(SrLogEvent::RelaySkip {
                from: parsed.from,
                reason: SrSkipReason::DeadEndHop,
            });
            return plan;
        }

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
                    bytes[PACKET_HEADER_LEN..PACKET_HEADER_LEN + n].copy_from_slice(&new_cipher);
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
            broadcast_plan.as_ref().or(unicast_plan.as_ref()),
        );
        let delay_ms = tx_after_ms.wrapping_sub(now_ms);
        let (
            ranked,
            ranked_len,
            reason,
            evaluated,
            evaluated_len,
            pre_covered,
            uncovered,
            uncovered_len,
        ) = broadcast_plan.as_ref().or(unicast_plan.as_ref()).map_or(
            (
                [0u32; crate::broadcast_relay::RANKED_LOG],
                0,
                crate::broadcast_relay::RelayReason::None,
                [(0u32, 0u8, 0u8, 0u16); crate::broadcast_relay::RANKED_LOG],
                0,
                0,
                [0u32; crate::broadcast_relay::UNCOVERED_LOG],
                0,
            ),
            |p| {
                (
                    p.ranked,
                    p.ranked_len,
                    p.reason,
                    p.evaluated,
                    p.evaluated_len,
                    p.pre_covered,
                    p.uncovered,
                    p.uncovered_len,
                )
            },
        );
        // Taken separately rather than widened into the tuple above: three more elements would
        // push it past readability for no gain.
        let plan_for_log = broadcast_plan.as_ref().or(unicast_plan.as_ref());
        let slots_given = plan_for_log.map_or(0, |p| p.slots_given);
        let reserved_slots = plan_for_log.map_or(0, |p| p.reserved_slots);
        let reserved_ranked = plan_for_log.map_or(0, |p| p.reserved_ranked);
        let absorbed = plan_for_log
            .map_or([(0u32, 0u8); crate::broadcast_relay::RANKED_LOG], |p| {
                p.absorbed
            });
        let absorbed_len = plan_for_log.map_or(0, |p| p.absorbed_len);
        self.sr_log.push(SrLogEvent::SlotScheduling {
            id: parsed.id,
            half_airtime_ms: half_airtime,
            candidates,
            slot_index,
            ranked,
            ranked_len,
            reason,
            evaluated,
            evaluated_len,
            pre_covered,
            uncovered,
            uncovered_len,
            slots_given,
            reserved_slots,
            reserved_ranked,
            absorbed,
            absorbed_len,
        });
        self.sr_log.push(SrLogEvent::RelayCommitted {
            id: parsed.id,
            heard_from,
            delay_ms,
        });

        if delay_ms == 0 {
            self.arm_relayed_unicast_retx(len, bytes, now_ms);
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

        self.arm_relayed_unicast_retx(len, bytes, now_ms);
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
        for idx in 0..self.pending.len() {
            if !self.pending[idx].active {
                continue;
            }
            // Already on the air from us (an earlier plan for the same packet): drop, do not repeat.
            if self.graph.has_our_transmission(self.pending[idx].id) {
                self.pending[idx].active = false;
                continue;
            }
            let pending = &self.pending[idx];
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
        // The committed relay stays until the radio reports the frame on the air
        // (`note_tx_done`): a copy heard while the frame waits in the radio queue still runs
        // the coverage check and can pull the frame back. Release used to forget the relay here,
        // which let the frame go out regardless of what arrived in the meantime.
        self.arm_relayed_unicast_retx(pending.len, pending.bytes, now_ms);
        Some(RelayPlan {
            len: pending.len,
            bytes: pending.bytes,
            delay_ms: 0,
        })
    }

    pub fn run_maintenance(&mut self, now_ms: u32, slot_ms: u32) -> MaintenanceReport {
        self.relay_identity.prune_relay_identity_cache(now_ms);
        self.poll_scheduled_topology_reply(now_ms, slot_ms);
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
            && self.schedule_topology_broadcast(now_ms, slot_ms, report.topology_dirty_send)
        {
            self.graph
                .commit_topology_broadcast(now_ms, report.topology_dirty_send);
        }
        if (self.last_nodeinfo_ms == 0
            || now_ms.wrapping_sub(self.last_nodeinfo_ms) >= NODEINFO_BROADCAST_MS)
            && !self.pending_nodeinfo.active
        {
            self.schedule_nodeinfo_broadcast(now_ms);
        }
        // Channel utilization, air util and uptime are always worth broadcasting, so this
        // is deliberately not gated on having a battery reading: an unknown pack voltage
        // only drops fields 1-2 from the encoded DeviceMetrics.
        if (self.last_telemetry_ms == 0
            || now_ms.wrapping_sub(self.last_telemetry_ms) >= DEVICE_TELEMETRY_BROADCAST_MS)
            && !self.pending_telemetry.active
        {
            self.schedule_telemetry_broadcast(now_ms);
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
        self.relay_identity
            .resolve_heard_from(relay_node, source, rssi, snr, &self.graph, now_ms)
    }

    /// Record a relay-byte mapping (host tests and topology learning paths).
    #[doc(hidden)]
    pub fn remember_relay_identity(&mut self, node_id: u32, relay_byte: u8, now_ms: u32) {
        self.relay_identity
            .remember_relay_identity(node_id, relay_byte, now_ms);
    }

    /// Slot plan for a unicast whose header already names a next hop.
    ///
    /// The designated node owns slot 0. If that is us we relay at once. Otherwise we keep our
    /// normal unicast rank shifted by one slot, behind a slot-0 wait sized for the designated
    /// node: one half-airtime for an SR peer (deterministic), the worst-case stock contention
    /// window plus one airtime for a stock or unknown node. Any copy heard before our slot
    /// cancels us (see `perhaps_cancel_dupe`). Bystanders therefore recover a failed designated
    /// hop within a slot instead of staying silent, and duplicates are bounded by the same
    /// cancel-on-hear rule broadcasts use.
    fn plan_designated_unicast(
        &mut self,
        parsed: &ParsedPacket,
        heard_from: u32,
        rssi: i16,
        snr: i8,
        half_airtime: u32,
        airtime_ms: u32,
        now_ms: u32,
        ranking: Option<Result<crate::broadcast_relay::BroadcastRelayPlan, SrSkipReason>>,
    ) -> crate::broadcast_relay::BroadcastRelayPlan {
        use crate::broadcast_relay::BroadcastRelayPlan;
        let our_byte = (self.node_num & 0xFF) as u8;
        if parsed.next_hop == our_byte {
            self.sr_log.push(SrLogEvent::UnicastDesignated {
                next_hop: parsed.next_hop,
                is_us: true,
                sr_active: true,
                slot: 0,
                slot_delay_ms: 0,
            });
            return BroadcastRelayPlan {
                should_relay: true,
                slot_delay_ms: crate::channel_access::SLOT_ORIGIN_MS,
                slot_index: 0,
                candidate_count: 1,
                ..Default::default()
            };
        }
        let designated = self
            .relay_identity
            .resolve_relay_identity(
                parsed.next_hop,
                rssi,
                snr,
                self.graph.edges(),
                self.node_num,
                now_ms,
            )
            .or_else(|| {
                self.graph
                    .match_relay_byte_on_outgoing_edges(parsed.next_hop)
            });
        let sr_active = designated
            .map(|n| {
                self.graph.capability_status(n) == crate::capability::CapabilityStatus::SrActive
            })
            .unwrap_or(false);
        // An SR peer queues its relay behind its own contention delay (up to 2^CW slots at
        // the current utilisation) and then needs one airtime to send it; a half-airtime
        // reservation let us pre-empt a healthy designated node by 200 ms in the field.
        let slot0_wait = if sr_active {
            self.sr_peer_relay_wait_ms(airtime_ms)
        } else {
            tx_delay_ms_worst(self.cw_slot_ms()).saturating_add(airtime_ms)
        };
        // Ranking Err → unranked backup behind the designated wait (silent designated hop).
        let (rank, count, ranked, ranked_len, reason, evaluated, evaluated_len, pre_covered) =
            match ranking {
                Some(Ok(p)) => (
                    p.slot_index,
                    p.candidate_count,
                    p.ranked,
                    p.ranked_len,
                    p.reason,
                    p.evaluated,
                    p.evaluated_len,
                    p.pre_covered,
                ),
                Some(Err(_)) => {
                    // Coverage skipped us for the ranking, but a named next hop still needs a
                    // backup. Take the unranked slot order rather than all backups sharing
                    // slot 1: a silent designated hop would otherwise be answered by every
                    // candidate at once.
                    let (rank, count) = self.graph.relay_slot_index(parsed.id, heard_from, now_ms);
                    (
                        rank,
                        count,
                        [0u32; crate::broadcast_relay::RANKED_LOG],
                        0,
                        crate::broadcast_relay::RelayReason::UnicastCost,
                        [(0u32, 0u8, 0u8, 0u16); crate::broadcast_relay::RANKED_LOG],
                        0,
                        0,
                    )
                }
                None => {
                    let (rank, count) = self.graph.relay_slot_index(parsed.id, heard_from, now_ms);
                    (
                        rank,
                        count,
                        [0u32; crate::broadcast_relay::RANKED_LOG],
                        0,
                        crate::broadcast_relay::RelayReason::None,
                        [(0u32, 0u8, 0u8, 0u16); crate::broadcast_relay::RANKED_LOG],
                        0,
                        0,
                    )
                }
            };
        let slot = rank.saturating_add(1);
        let slot_delay_ms = slot0_wait.saturating_add((rank as u32).saturating_mul(half_airtime));
        self.sr_log.push(SrLogEvent::UnicastDesignated {
            next_hop: parsed.next_hop,
            is_us: false,
            sr_active,
            slot,
            slot_delay_ms,
        });
        BroadcastRelayPlan {
            should_relay: true,
            slot_delay_ms,
            slot_index: slot,
            candidate_count: count.saturating_add(1),
            ranked,
            ranked_len,
            reason,
            evaluated,
            evaluated_len,
            pre_covered,
            // Unicast plan: coverage does not enter into it.
            uncovered: [0; crate::broadcast_relay::UNCOVERED_LOG],
            uncovered_len: 0,
            coverage_for: 0,
            slots_given: 0,
            // No reservation on a unicast ladder: the router window is a broadcast rule.
            reserved_slots: 0,
            reserved_ranked: 0,
            absorbed: [(0, 0); crate::broadcast_relay::RANKED_LOG],
            absorbed_len: 0,
        }
    }

    /// How long to give a destination that heard the packet directly to answer it: its ACK
    /// contention delay (the channel may look busier to it than to us, hence twice our
    /// contention maximum) plus the ACK's airtime.
    fn dest_ack_wait_ms(&self, airtime_ms: u32) -> u32 {
        crate::channel_access::dest_ack_wait_ms(
            airtime_ms,
            crate::coordinated_relay::tx_delay_ms_contention_max_at(
                self.channel_util_pct,
                self.cw_slot_ms(),
            ),
        )
    }

    /// Hop budget for a reply we originate. A reply to a
    /// direct neighbour that hears us goes out with hop limit 0 (1 on a marginal link) when
    /// stock neighbours are around, so nobody relays a packet we deliver ourselves. A
    /// traceroute reply from A to Dura went out with hop 2 and was relayed three times.
    /// Header fields of a response to `parsed`: hop budget and next hop. A last-hop reply (the
    /// requester hears us directly, stock nodes listen, and the request came direct) gets
    /// `LAST_HOP_BUDGET` and names the requester as next hop; anything else keeps stock's budget
    /// and no next hop.
    fn response_header(&self, parsed: &ParsedPacket, hop_start_known: bool) -> (u8, u8) {
        let base = hop_limit_for_response(parsed, hop_start_known, self.hop_limit);
        // A request that reached us through a relay says the direct link is not carrying
        // frames right now; the reply then keeps its hop budget so a relay can return it.
        let arrived_direct = is_direct_packet(
            parsed.from,
            parsed.hop_start,
            parsed.hop_limit,
            parsed.relay_node,
        );
        if arrived_direct && self.graph.caps_last_hop(parsed.from) {
            (LAST_HOP_BUDGET.min(base), (parsed.from & 0xFF) as u8)
        } else {
            (base, 0)
        }
    }

    /// How long an SR peer that owns the slot ahead of us needs before its relay has left the
    /// air: its contention delay at the current utilisation plus one airtime.
    fn sr_peer_relay_wait_ms(&self, airtime_ms: u32) -> u32 {
        crate::channel_access::peer_relay_wait_ms(
            airtime_ms,
            crate::coordinated_relay::tx_delay_ms_contention_max_at(
                self.channel_util_pct,
                self.cw_slot_ms(),
            ),
        )
    }

    fn try_resolve_placeholder(&mut self, parsed: &ParsedPacket, now_ms: u32) -> bool {
        if !is_direct_packet(
            parsed.from,
            parsed.hop_start,
            parsed.hop_limit,
            parsed.relay_node,
        ) {
            return false;
        }
        let relay_byte = (parsed.from & 0xFF) as u8;
        if relay_byte == 0 || crate::graph::is_placeholder_node(parsed.from) {
            return false;
        }
        let real_node_id = parsed.from;
        let placeholder_id = crate::graph::get_placeholder_for_relay(relay_byte);
        if self.graph.edges().find_node(placeholder_id).is_none() {
            self.relay_identity
                .remember_relay_identity(real_node_id, relay_byte, now_ms);
            return false;
        }
        if let Some(cached) = self.relay_identity.resolve_relay_identity(
            relay_byte,
            0,
            0,
            self.graph.edges(),
            self.node_num,
            now_ms,
        ) {
            if cached != real_node_id {
                return false;
            }
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

    /// Cancel a scheduled T1 broadcast retransmit.
    pub fn cancel_broadcast_retransmit(&mut self, packet_id: u32) {
        self.cancel_t1_retransmit(packet_id, T1CancelReason::RelayHeard);
    }

    /// True when every direct neighbor is covered by accumulated transmitters (broadcast dupe cancel).
    pub fn all_neighbors_covered(
        &mut self,
        from: u32,
        packet_id: u32,
        dupe_relayer: u32,
        now_ms: u32,
    ) -> bool {
        self.graph
            .all_neighbors_covered(from, packet_id, dupe_relayer, now_ms)
    }

    /// True when router has scheduled TX work (relays, topology, ACKs, retransmits).
    pub fn has_pending_work(&self) -> bool {
        self.pending.iter().any(|p| p.active)
            || self.pending_topology.active
            || self.pending_nodeinfo.active
            || self.pending_telemetry.active
            || self.pending_traceroute.active
            || self.pending_ack.active
            || self.pending_admin.iter().any(|p| p.active)
            || self
                .pending_retransmits
                .iter()
                .any(|p| p.active && !p.canceled)
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
    ) -> Option<RelayPlan> {
        let packet_id = self.alloc_tx_id(now_ms);
        let mut hop = hop_limit.min(SR_BROADCAST_MAX_HOPS);
        let mut next_hop = 0u8;
        if to != NODENUM_BROADCAST && self.graph.caps_last_hop(to) {
            hop = hop.min(LAST_HOP_BUDGET);
            next_hop = (to & 0xFF) as u8;
        }
        let (len, frame) = build_app_wire_frame(
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
            DataEncodeOpts {
                bitfield: self.ours(),
                ..Default::default()
            },
            next_hop,
        )?;
        if want_ack {
            let delay = self.reliable_retx_delay_ms(len, self.node_num, packet_id);
            let _ = schedule_reliable(
                &mut self.pending_reliable,
                self.node_num,
                packet_id,
                to,
                false,
                len,
                frame,
                delay,
                now_ms,
            );
        }
        if to == NODENUM_BROADCAST && portnum != SIGNAL_ROUTING_APP {
            self.schedule_t1_broadcast(packet_id, len, frame, airtime_ms, 0, now_ms);
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

    /// Record the radio's current channel utilization; widens the reliable retransmit backoff.
    pub fn set_channel_utilization(&mut self, pct: f32) {
        self.channel_util_pct = pct;
    }

    /// Reliable retransmit delay for a frame of `wire_len` bytes on the current preset
    /// (Meshtastic `getRetransmissionMsec`: real airtime, contention window, processing margin).
    pub fn reliable_retx_delay_ms(&self, wire_len: u8, from: u32, id: u32) -> u32 {
        Self::retx_delay_for(
            self.modem_preset,
            self.channel_util_pct,
            self.node_num,
            from,
            id,
            wire_len,
        )
    }

    /// Backoff before a retry plus a per-node contention offset. Two relayers that armed
    /// retries for the same packet at the same instant would otherwise fire in lockstep and
    /// collide on every attempt.
    fn retx_delay_for(
        preset: u8,
        util: f32,
        node_num: u32,
        from: u32,
        id: u32,
        wire_len: u8,
    ) -> u32 {
        let cfg = eu868_config_for_preset(preset);
        let airtime_ms = packet_time_ms(&cfg, wire_len as usize, false).max(1);
        let slot_ms = slot_time_for_preset(preset).max(1);
        retransmission_delay_ms(airtime_ms, slot_ms, util)
            .saturating_add(tx_delay_ms_contention(util, slot_ms, from, id, node_num))
    }

    pub fn poll_reliable_retransmit(&mut self, now_ms: u32) -> Option<RelayPlan> {
        let (preset, util, node_num) = (self.modem_preset, self.channel_util_pct, self.node_num);
        let delay_for = |from: u32, id: u32, len: u8| {
            Self::retx_delay_for(preset, util, node_num, from, id, len)
        };
        let due = due_retransmit(&mut self.pending_reliable, now_ms, delay_for)?;
        if due.relayed {
            self.sr_log.push(SrLogEvent::RelayRetxFired {
                id: due.packet_id,
                fallback: due.fallback,
            });
        }
        Some(RelayPlan {
            len: due.len,
            bytes: due.bytes,
            delay_ms: 0,
        })
    }

    /// Arm retries for a unicast we are about to forward on behalf of someone else, when the
    /// origin asked for reliability and we stamped a designated next hop. Retries stop as soon
    /// as any copy of the packet is heard or the destination answers; the last one goes out with
    /// `next_hop` cleared so the flood takes over. Fire-and-forget unicasts are never retried,
    /// which bounds the airtime a rogue origin can extract from relayers.
    fn arm_relayed_unicast_retx(&mut self, len: u8, bytes: [u8; MAX_WIRE_LEN], now_ms: u32) {
        let Ok(hdr) = PacketHeader::decode(&bytes[..PACKET_HEADER_LEN]) else {
            return;
        };
        let p = hdr.parse();
        if p.to == NODENUM_BROADCAST || p.from == self.node_num || !p.want_ack || p.next_hop == 0 {
            return;
        }
        let delay = self.reliable_retx_delay_ms(len, p.from, p.id);
        if schedule_reliable(
            &mut self.pending_reliable,
            p.from,
            p.id,
            p.to,
            true,
            len,
            bytes,
            delay,
            now_ms,
        ) {
            self.sr_log.push(SrLogEvent::RelayRetxArmed {
                id: p.id,
                next_hop: p.next_hop,
            });
        }
    }

    fn cancel_relayed_retx(&mut self, from: u32, id: u32, reason: RelayRetxCancelReason) {
        if stop_reliable_for(&mut self.pending_reliable, from, id) {
            self.sr_log
                .push(SrLogEvent::RelayRetxCanceled { id, reason });
        }
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

    pub fn poll_admin_tx(&mut self, now_ms: u32) -> Option<RelayPlan> {
        let mut best: Option<usize> = None;
        for (i, slot) in self.pending_admin.iter().enumerate() {
            if !slot.active {
                continue;
            }
            if now_ms.wrapping_sub(slot.next_tx_ms) >= 0x8000_0000 {
                continue;
            }
            if now_ms < slot.next_tx_ms {
                continue;
            }
            best = Some(match best {
                None => i,
                Some(j) => {
                    if slot
                        .next_tx_ms
                        .wrapping_sub(self.pending_admin[j].next_tx_ms)
                        < 0x8000_0000
                        && slot.next_tx_ms < self.pending_admin[j].next_tx_ms
                    {
                        i
                    } else {
                        j
                    }
                }
            });
        }
        let idx = best?;
        let slot = &mut self.pending_admin[idx];
        slot.active = false;
        self.pending_admin_count = self.pending_admin_count.saturating_sub(1);
        Some(RelayPlan {
            len: slot.len,
            bytes: slot.bytes,
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
            self.pending_topology.next_tx_ms =
                now_ms.wrapping_add(self.pending_topology.spacing_ms);
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
            // Stock: any reply carrying our request id (ACK, NAK or a module reply such as a
            // traceroute response) is the acknowledgement; module replies replace the ACK.
            if data.request_id != 0 {
                let _ = stop_reliable(&mut self.pending_reliable, data.request_id);
            }
            if data.portnum == ROUTING_APP {
                let _ = inner.map(decode_routing_payload);
                return;
            }
            if parsed.from != self.node_num
                && parsed.from != 0
                && parsed.want_ack
                && !self.module_reply_suppresses_ack
            {
                if data.request_id == 0 && data.reply_id == 0 {
                    self.schedule_ack(parsed, data.has_bitfield, parsed.channel, now_ms);
                } else if hops_away(parsed.hop_start, parsed.hop_limit, data.has_bitfield)
                    == Some(0)
                    || parsed.next_hop != 0
                {
                    // Stock: a response is acknowledged only when it reached us with zero hops
                    // or through a designated next hop, and then with a hop-0 ACK; a relayed
                    // response was already implicitly acknowledged by the relay.
                    self.schedule_ack_with_hop(parsed, parsed.channel, 0, 0, now_ms);
                }
            }
        } else if parsed.from != self.node_num
            && parsed.from != 0
            && parsed.want_ack
            && !self.module_reply_suppresses_ack
        {
            self.schedule_nak(parsed, false, ROUTING_ERROR_NO_CHANNEL, now_ms);
        }
    }

    fn schedule_ack(
        &mut self,
        parsed: &ParsedPacket,
        hop_start_known: bool,
        channel_hash: u8,
        now_ms: u32,
    ) {
        let (hop, next_hop) = self.response_header(parsed, hop_start_known);
        self.schedule_ack_with_hop(parsed, channel_hash, hop, next_hop, now_ms);
    }

    /// Original-sender WantAck retry (dupe, hopsAway==0): cheap hop_limit=0 re-ACK only.
    /// Must not re-run admin/modules — those already ran on first delivery.
    fn schedule_dupe_want_ack(&mut self, parsed: &ParsedPacket, channel_hash: u8, now_ms: u32) {
        self.schedule_ack_with_hop(parsed, channel_hash, 0, 0, now_ms);
    }

    fn schedule_ack_with_hop(
        &mut self,
        parsed: &ParsedPacket,
        channel_hash: u8,
        hop: u8,
        next_hop: u8,
        now_ms: u32,
    ) {
        if self.pending_ack.active {
            return;
        }
        let packet_id = self.alloc_tx_id(now_ms);
        let Some((len, frame)) = self.build_ack_nak_reply(
            parsed,
            packet_id,
            hop,
            next_hop,
            ROUTING_ERROR_NONE,
            channel_hash,
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

    fn schedule_nak(
        &mut self,
        parsed: &ParsedPacket,
        hop_start_known: bool,
        error: u32,
        now_ms: u32,
    ) {
        if self.pending_ack.active {
            return;
        }
        let (hop, next_hop) = self.response_header(parsed, hop_start_known);
        let packet_id = self.alloc_tx_id(now_ms);
        let Some((len, frame)) =
            self.build_ack_nak_reply(parsed, packet_id, hop, next_hop, error, parsed.channel)
        else {
            return;
        };
        self.pending_ack = PendingAck {
            active: true,
            next_tx_ms: now_ms,
            len,
            bytes: frame,
        };
    }

    /// WantAck ACK/NAK must use the same crypto as the request: PKI when the inbound
    /// packet was PKI-decrypted (Ch=0), otherwise channel PSK. Channel-encrypting a
    /// PKI WantAck makes pure-PKI clients ignore the ACK and retransmit forever.
    fn build_ack_nak_reply(
        &self,
        parsed: &ParsedPacket,
        packet_id: u32,
        hop: u8,
        next_hop: u8,
        error_reason: u32,
        channel_hash: u8,
    ) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
        let routing = encode_routing_error(error_reason);
        let opts = DataEncodeOpts {
            request_id: parsed.id,
            bitfield: self.ours(),
            ..Default::default()
        };
        if self.admin_reply_use_pki {
            if let Some(remote_pk) = self.remote_pk_for_error_reply(parsed) {
                // hop may be 0 for original-sender WantAck dupe re-ACKs.
                return self.build_pki_app_frame(
                    parsed.from,
                    packet_id,
                    hop,
                    ROUTING_APP,
                    &routing,
                    opts,
                    &remote_pk,
                    false,
                    next_hop,
                );
            }
        }
        build_ack_nak_frame(
            parsed.from,
            self.node_num,
            packet_id,
            parsed.id,
            channel_hash,
            hop,
            error_reason,
            &self.channel_key,
            self.ok_to_mqtt(),
            next_hop,
        )
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
        short_name[..short_len as usize].copy_from_slice(&advert.short_name[..short_len as usize]);
        let role = advert.role;
        let is_new = self.nodeinfo_cache.upsert(parsed.from, identity, now_ms);
        self.graph.track_node_role(parsed.from, advert.role, now_ms);
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
            self.ok_to_mqtt(),
        ) else {
            return;
        };
        self.queue_nodeinfo_tx(now_ms, len, frame);
        self.last_nodeinfo_ms = now_ms;
    }

    /// Contention-window delay for a reply several nodes may send to the same trigger
    /// (Meshtastic `getTxDelayMsec`). Without it, colocated nodes answering one request
    /// transmit inside each other's airtime.
    fn reply_tx_delay_ms(&self, seed_a: u32, seed_b: u32) -> u32 {
        tx_delay_ms_contention(
            self.channel_util_pct,
            self.cw_slot_ms(),
            seed_a,
            seed_b,
            self.node_num,
        )
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
            self.ok_to_mqtt(),
        ) else {
            return;
        };
        let delay_ms = self.reply_tx_delay_ms(to, reply_id);
        self.sr_log
            .push(SrLogEvent::NodeInfoReplyDelayed { delay_ms });
        self.queue_nodeinfo_tx(now_ms.wrapping_add(delay_ms), len, frame);
    }

    fn queue_nodeinfo_tx(&mut self, tx_at_ms: u32, len: u8, frame: [u8; MAX_WIRE_LEN]) {
        self.pending_nodeinfo.active = true;
        self.pending_nodeinfo.next_tx_ms = tx_at_ms;
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
            self.ok_to_mqtt(),
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
        alter_on_relay(
            &mut rd,
            parsed,
            data.has_bitfield,
            self.node_num,
            snr,
            data.request_id,
        );
        let mut route_wire = heapless::Vec::<u8, 128>::new();
        if !encode_route_discovery(&rd, &mut route_wire) {
            return;
        }
        let (hop, next_hop) = self.response_header(parsed, data.has_bitfield);
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
                bitfield: self.ours(),
                ..Default::default()
            },
            next_hop,
        ) else {
            return;
        };
        self.pending_traceroute.active = true;
        self.pending_traceroute.next_tx_ms = now_ms;
        self.pending_traceroute.len = len;
        self.pending_traceroute.bytes = frame;
        // The reply carries request_id and is the ACK (stock: a module reply replaces the
        // separate ACK). Sending both put two frames on the air back to back and Dura missed
        // the second one every time.
        self.module_reply_suppresses_ack = true;
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
        // A dirty broadcast reacts to something every neighbour heard too (a new node, a
        // report), so it gets a contention-window delay; periodic ones run on our own timer.
        let dirty_delay_ms = if dirty {
            self.reply_tx_delay_ms(self.graph.topology_version() as u32, now_ms)
        } else {
            0
        };
        if dirty {
            self.sr_log.push(SrLogEvent::TopologyDirtySending {
                delay_ms: dirty_delay_ms,
            });
        }
        let topo_v = self.graph.topology_version();
        let packet_count = self.graph.topology_packet_count();
        let neighbors = self.graph.neighbor_count();
        if neighbors == 0 {
            self.sr_log.push(SrLogEvent::EmptyBootBroadcast);
        }
        let mut packed_buf = [0u8; 256];
        let mut built = 0u8;
        let mut longest_frame = 0usize;
        for chunk in 0..packet_count {
            let Some(packed_len) = self
                .graph
                .build_topology_chunk(chunk, topo_v, &mut packed_buf)
            else {
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
                self.ok_to_mqtt(),
            ) else {
                continue;
            };
            self.pending_topology.frames[built as usize] = frame;
            self.pending_topology.lens[built as usize] = len;
            longest_frame = longest_frame.max(len as usize);
            built += 1;
        }
        if built == 0 {
            return false;
        }
        self.pending_topology.active = true;
        self.pending_topology.count = built;
        self.pending_topology.next_idx = 0;
        self.pending_topology.next_tx_ms = now_ms.wrapping_add(dirty_delay_ms);
        // Chunks of one list are spaced by twice the packet airtime: our peers
        // relay chunk N in the slots right after it, and our chunk N+1 must not land on top of
        // them. Two contention slots, the previous value, were far shorter than one airtime.
        let cfg = eu868_config_for_preset(self.modem_preset);
        let airtime_ms = packet_time_ms(&cfg, longest_frame, false).max(slot_ms);
        self.pending_topology.spacing_ms = airtime_ms.saturating_mul(2);
        self.sr_log.push(SrLogEvent::TopologySending {
            node_id: self.node_num,
            neighbors,
            packets: built,
            topo_v,
        });
        true
    }

    /// Seed the packet id sequence with hardware entropy. Without it every boot replays the
    /// same ids (counter mixed with uptime), and two nodes booting a minute apart collide in the
    /// low id range: B dropped A's boot broadcast because id 0x3a matched one of B's own frames.
    pub fn seed_tx_ids(&mut self, seed: u32) {
        self.next_tx_id = seed;
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
        // One pending frame per packet: a re-plan (hand-off, better slot) replaces the earlier
        // frame instead of queueing a second copy of the same packet behind it.
        let existing = self
            .pending
            .iter()
            .position(|p| p.active && p.from == from && p.id == id);
        if let Some(idx) = existing.or_else(|| self.pending.iter().position(|p| !p.active)) {
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

    /// Park an already-built relay frame as a pending relay due now, so the board releases it
    /// through the same gated path as every other frame (post-reception hold, channel quiet).
    pub fn defer_relay(&mut self, plan: RelayPlan, radio_id: u8, now_ms: u32) -> bool {
        let Ok(header) = PacketHeader::decode(&plan.bytes[..PACKET_HEADER_LEN]) else {
            return false;
        };
        let parsed = header.parse();
        self.store_pending(
            parsed.from,
            parsed.id,
            radio_id,
            now_ms.wrapping_add(plan.delay_ms),
            plan.len,
            plan.bytes,
        )
    }

    /// Remember that `id` must not go on the air from us, wherever its frame currently sits.
    fn note_tx_cancel(&mut self, id: u32) {
        if !self.tx_cancels.contains(&id) {
            let _ = self.tx_cancels.push(id);
        }
    }

    /// Packet ids whose queued relay the board must remove from the radio TX queue. A copy heard
    /// while our frame waits behind listen-before-talk is the usual case: the frame has left the
    /// router but not the node, and only the radio queue can still stop it.
    /// The radio finished sending `packet_id`: the committed relay is complete.
    pub fn note_tx_done(&mut self, packet_id: u32) {
        if packet_id != 0 {
            self.graph.cancel_relay_for_id(packet_id);
            // On the air: nothing left to pull back.
            for slot in &mut self.pending_retransmits {
                if slot.packet_id == packet_id {
                    slot.fired = false;
                }
            }
        }
    }

    pub fn take_tx_cancels(&mut self, out: &mut heapless::Vec<u32, 8>) {
        out.clear();
        for id in self.tx_cancels.iter() {
            let _ = out.push(*id);
        }
        self.tx_cancels.clear();
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
            self.note_tx_cancel(parsed.id);
        }
        dropped
    }

    /// Zero hops away: the original transmitter's own frame, not a relayed copy.
    /// Unicast WantAck retries use this to emit a hop_limit=0 re-ACK without re-running modules.
    /// To-us DMs are never SR-suppressed for this check (SR is not used for packets to us).
    fn is_repeated_reliable_tx(parsed: &ParsedPacket, data: Option<&DecodedData>) -> bool {
        let hop_start_known = data.is_some_and(|d| d.has_bitfield);
        hops_away(parsed.hop_start, parsed.hop_limit, hop_start_known) == Some(0)
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
        // The destination answered the origin: our copy is redundant wherever it sits, still
        // pending here, committed, or already handed to the radio queue (both nicenanos once
        // transmitted 80 ms after logging "reply heard" because only the retries were stopped).
        let had_pending = self.cancel_pending(parsed.to, cancel_id);
        let committed = self.graph.is_committed_relay(parsed.to, cancel_id);
        if had_pending || committed || self.graph.has_our_transmission(cancel_id) {
            self.graph.cancel_relay(parsed.to, cancel_id);
            self.note_tx_cancel(cancel_id);
            self.sr_log
                .push(SrLogEvent::UnicastReplyCancel { id: cancel_id });
        }
        self.cancel_relayed_retx(parsed.to, cancel_id, RelayRetxCancelReason::ReplyHeard);
    }

    fn handle_duplicate_rx(
        &mut self,
        parsed: &ParsedPacket,
        decoded_data: Option<&DecodedData>,
        inner: Option<&[u8]>,
        packet: &InboundPacket<'_>,
        now_ms: u32,
    ) {
        if let Some(data) = decoded_data {
            self.maybe_cancel_relay_for_foreign_ack(parsed, data);
        }

        // Any further copy of a unicast we forwarded means it is moving on: stop retrying it.
        if parsed.to != NODENUM_BROADCAST && parsed.from != self.node_num {
            self.cancel_relayed_retx(parsed.from, parsed.id, RelayRetxCancelReason::CopyHeard);
        }

        // Hearing our own frame (rebroadcast) is an implicit ACK — always cancel
        // reliable retx before any early return for WantAck re-ACK handling.
        if parsed.from == self.node_num {
            let _ = stop_reliable(&mut self.pending_reliable, parsed.id);
            self.perhaps_cancel_dupe(parsed, packet, now_ms);
            return;
        }

        // Dupe path never re-enters rate_limit / admin / modules (history short-circuit).
        // Original-sender WantAck retry: re-send idempotent admin GET replies, else hop_limit=0 re-ACK.
        if Self::is_repeated_reliable_tx(parsed, decoded_data) {
            if parsed.to == self.node_num && parsed.want_ack {
                if let (Some(data), Some(payload)) = (decoded_data, inner) {
                    if data.portnum == ADMIN_APP {
                        if let Some(msg) = crate::admin_codec::decode_admin_message(payload) {
                            if crate::admin::admin_request_is_idempotent_read(&msg.payload) {
                                self.process_admin_rx(parsed, payload, data.has_bitfield, now_ms);
                                return;
                            }
                        }
                    }
                }
                self.schedule_dupe_want_ack(parsed, parsed.channel, now_ms);
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
        let heard_relayer = if rebroadcast {
            Some(self.resolve_heard_from_node(
                parsed.relay_node,
                parsed.from,
                packet.rssi,
                packet.snr,
                now_ms,
            ))
        } else {
            None
        };

        if let Some(heard_from) = heard_relayer {
            self.graph
                .record_heard_transmissions(parsed.from, parsed.id, Some(heard_from), now_ms);
            if self
                .graph
                .maybe_confirm_hears_us_from_relay(heard_from, parsed.from, parsed.id)
            {
                self.sr_log.push(SrLogEvent::RelayConfirmedHearsUs {
                    node_id: heard_from,
                });
            }
        }

        // A unicast copy heard from anyone means the packet is moving, whether the designated
        // next hop or an earlier slot carried it: our pending copy is redundant. Broadcast
        // coverage reasoning below does not apply to unicasts. `in_flight` covers the frame
        // that already left the router for the radio queue (release forgets the relay here,
        // but the board recorded our transmission when it queued the frame).
        let in_flight = self.graph.has_our_transmission(parsed.id);
        if parsed.to != NODENUM_BROADCAST && (committed || has_pending || in_flight) {
            if self.graph.role_allows_canceling_dupe() {
                self.graph.cancel_relay(parsed.from, parsed.id);
                let canceled_pending = self.cancel_pending(parsed.from, parsed.id);
                self.note_tx_cancel(parsed.id);
                if canceled_pending || has_pending {
                    self.sr_log.push(SrLogEvent::UnicastDupeCancel {
                        id: parsed.id,
                        from: parsed.from,
                    });
                }
            }
            return;
        }

        // Set once the coverage test has decided our committed copy is no longer needed. That
        // verdict is about the packet — the nodes we would have carried have been carried by
        // somebody else, so transmitting adds a duplicate and nothing else — so it overrides the
        // role gate, which answers a different question: whether a router may fall silent for
        // reasons of its own. Without this a node configured ROUTER or ROUTER_LATE cancelled its
        // insurance and then transmitted anyway.
        let mut sr_coverage_cancel = false;

        if committed {
            if !has_pending {
                // Released to the radio (or already sent). Someone relayed, so T1 is moot.
                self.cancel_t1_retransmit(parsed.id, T1CancelReason::RelayHeard);
                // Coverage decides, not the role: the frame may still be pullable from the radio
                // queue, and a covered relay that goes out anyway is a duplicate we chose.
                if let Some(heard_from) = heard_relayer {
                    if !self.all_neighbors_covered(parsed.from, parsed.id, heard_from, now_ms) {
                        return;
                    }
                }
                self.graph.cancel_relay(parsed.from, parsed.id);
                self.note_tx_cancel(parsed.id);
                self.sr_log.push(SrLogEvent::BroadcastDupeCancel {
                    id: parsed.id,
                    from: parsed.from,
                });
                return;
            }
            if let Some(heard_from) = heard_relayer {
                if !self.all_neighbors_covered(parsed.from, parsed.id, heard_from, now_ms) {
                    return;
                }
            }
            sr_coverage_cancel = true;
        }

        // Non-SR traffic keeps stock's behaviour for our role; a committed relay the coverage test
        // has released does not.
        if sr_coverage_cancel || self.graph.role_allows_canceling_dupe() {
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
                self.note_tx_cancel(parsed.id);
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
            // Our own TX already gave the source a retransmission to hear.
            if self.graph.has_our_transmission(slot.packet_id) {
                let id = slot.packet_id;
                slot.active = false;
                slot.canceled = true;
                self.sr_log.push(SrLogEvent::T1Canceled {
                    id,
                    reason: T1CancelReason::OwnTransmission,
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
            slot.fired = true;
            self.sr_log.push(SrLogEvent::T1Fired { id });
            return Some(plan);
        }
        None
    }

    /// Build a relay frame and arm T1 after we deferred (no ranked slot).
    fn arm_t1_for_deferred_broadcast(
        &mut self,
        parsed: &ParsedPacket,
        handle: PacketHandle,
        heard_from: u32,
        decoded_portnum: Option<u32>,
        airtime_ms: u32,
        half_airtime_ms: u32,
        now_ms: u32,
    ) {
        if decoded_portnum == Some(SIGNAL_ROUTING_APP) || !self.graph.has_any_hears_us_neighbor() {
            self.pool.release(handle);
            return;
        }
        let Some(relay_hdr) = relay_header_with_next_hop_opts(parsed, self.node_num, 0, false)
        else {
            self.pool.release(handle);
            return;
        };
        let mut bytes = [0u8; MAX_WIRE_LEN];
        relay_hdr.encode_to(
            (&mut bytes[..PACKET_HEADER_LEN])
                .try_into()
                .expect("header slice"),
        );
        let plen = {
            let rx = self.pool.get(handle).unwrap();
            let n = rx.payload_len as usize;
            bytes[PACKET_HEADER_LEN..PACKET_HEADER_LEN + n].copy_from_slice(&rx.payload[..n]);
            n
        };
        self.pool.release(handle);
        let len = (PACKET_HEADER_LEN + plen) as u8;
        // Every node that deferred arms T1, so the insurers need the slot ladder too: firing
        // together would collide precisely when the ranked relay was the frame that went missing.
        // Same deterministic order as an unranked relay slot, one half-airtime apart.
        let (rank, _) = self.graph.relay_slot_index(parsed.id, heard_from, now_ms);
        let stagger = (rank as u32).saturating_mul(half_airtime_ms);
        self.schedule_t1_broadcast(parsed.id, len, bytes, airtime_ms, stagger, now_ms);
    }

    fn schedule_t1_broadcast(
        &mut self,
        packet_id: u32,
        len: u8,
        bytes: [u8; MAX_WIRE_LEN],
        airtime_ms: u32,
        stagger_ms: u32,
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
        let fire_delay = tx_delay_ms_worst(self.cw_slot_ms())
            .saturating_add(airtime_ms)
            .saturating_add(stagger_ms);
        self.pending_retransmits[idx] = PendingRetransmit {
            active: true,
            canceled: false,
            fired: false,
            packet_id,
            fire_after_ms: now_ms.wrapping_add(fire_delay),
            len,
            bytes,
        };
        self.sr_log.push(SrLogEvent::T1Scheduled {
            id: packet_id,
            delay_ms: fire_delay,
        });
    }

    /// The ranking inputs behind a deferral. Logged on the defer path as well as on the commit
    /// path: without it a field log shows that we stood down but not who we stood down for, and
    /// a slot handed to a node that cannot deliver is invisible.
    fn log_slot_scheduling(
        &mut self,
        parsed: &ParsedPacket,
        plan: &crate::broadcast_relay::BroadcastRelayPlan,
        half_airtime: u32,
    ) {
        self.sr_log.push(SrLogEvent::SlotScheduling {
            id: parsed.id,
            half_airtime_ms: half_airtime,
            candidates: plan.candidate_count,
            slot_index: plan.slot_index,
            ranked: plan.ranked,
            ranked_len: plan.ranked_len,
            reason: plan.reason,
            evaluated: plan.evaluated,
            evaluated_len: plan.evaluated_len,
            pre_covered: plan.pre_covered,
            uncovered: plan.uncovered,
            uncovered_len: plan.uncovered_len,
            slots_given: plan.slots_given,
            reserved_slots: plan.reserved_slots,
            reserved_ranked: plan.reserved_ranked,
            absorbed: plan.absorbed,
            absorbed_len: plan.absorbed_len,
        });
    }

    fn cancel_t1_retransmit(&mut self, packet_id: u32, reason: T1CancelReason) {
        let mut pull_back = false;
        let mut canceled = false;
        for slot in &mut self.pending_retransmits {
            if slot.packet_id != packet_id {
                continue;
            }
            if slot.active && !slot.canceled {
                slot.active = false;
                slot.canceled = true;
                canceled = true;
            } else if slot.fired {
                // Already handed to the radio: only the TX queue can still stop it.
                slot.fired = false;
                pull_back = true;
                canceled = true;
            }
            break;
        }
        if pull_back {
            self.note_tx_cancel(packet_id);
        }
        if canceled {
            self.sr_log.push(SrLogEvent::T1Canceled {
                id: packet_id,
                reason,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinated_relay;
    use crate::graph::EdgeSource;
    use crate::routing_ack::{build_ack_nak_frame, ROUTING_ERROR_NONE};
    use crate::sr_log::RelayRetxCancelReason;
    use crate::topology::{decode_packed_neighbors, write_packed_header, PackedNeighbor};
    use mesh_crypto::{CryptoKey, DEFAULT_PSK};
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
    fn peer_relay_wait_includes_processing_allowance() {
        let router = Router::new(0x1100_0011);
        assert!(
            router.sr_peer_relay_wait_ms(100) >= 100 + crate::channel_access::PEER_TURNAROUND_MS
        );
    }

    #[test]
    fn reply_to_direct_hearing_neighbour_is_hop_limited_when_stock_nodes_are_around() {
        const ME: u32 = 0x1100_0011;
        const DEST: u32 = 0xD000_000D;
        const STOCK: u32 = 0x5000_0005;
        let mut router = Router::new(ME);
        router
            .graph_mut()
            .observe_direct_neighbor(DEST, -40, 12, 1_000, 0);
        router.graph_mut().confirm_direct_neighbor_hears_us(DEST);
        let request = PacketHeader::from_fields(ME, DEST, 7, 0, 7, 7, true, false, 0, 0).parse();
        assert_eq!(
            router.response_header(&request, true),
            (2, 0),
            "no stock neighbour: nothing to protect, default margin applies"
        );
        router
            .graph_mut()
            .observe_direct_neighbor(STOCK, -60, 10, 1_000, 0);
        assert_eq!(
            router.response_header(&request, true),
            (LAST_HOP_BUDGET, (DEST & 0xFF) as u8),
            "last hop: one hop, the requester named as next hop"
        );
        // The same request arriving through a relay: the direct link is not carrying frames
        // right now, so the reply keeps a budget a relay can use to bring it back.
        let relayed = PacketHeader::from_fields(ME, DEST, 8, 0, 6, 7, true, false, 0, 0x99).parse();
        assert_eq!(
            router.response_header(&relayed, true),
            (hop_limit_for_response(&relayed, true, router.hop_limit), 0)
        );
        assert!(router.response_header(&relayed, true).0 >= 1);
    }

    #[test]
    fn dest_ack_wait_includes_processing_allowance() {
        let router = Router::new(0x1100_0011);
        let wait = router.dest_ack_wait_ms(100);
        assert!(
            wait >= 100 + crate::channel_access::PEER_TURNAROUND_MS,
            "got {wait}"
        );
    }

    #[test]
    fn topology_chunks_are_spaced_by_two_airtimes() {
        let mut router = Router::new(0x1100_0011);
        for i in 0..30u32 {
            router
                .graph_mut()
                .observe_direct_neighbor(0x2000_0000 + i, -60, 8, 1_000, 0);
        }
        assert!(router.schedule_topology_broadcast(10_000, 16, false));
        assert_eq!(router.pending_topology.count, 2);
        let first = router
            .poll_topology_tx(10_000)
            .expect("first chunk at once");
        let cfg = eu868_config_for_preset(router.modem_preset());
        let airtime = packet_time_ms(&cfg, first.len as usize, false);
        assert!(
            airtime > 100,
            "a 28-entry chunk is a long frame: {airtime} ms"
        );
        assert!(
            router.poll_topology_tx(10_000 + airtime).is_none(),
            "second chunk held while peers relay the first"
        );
        assert!(router.poll_topology_tx(10_000 + 2 * airtime).is_some());
        assert!(router.poll_topology_tx(10_000 + 2 * airtime + 1).is_none());
    }

    #[test]
    fn empty_peer_topology_replies_on_next_maintenance() {
        use crate::topology::{
            build_topology_wire_frame, write_packed_header, PACKED_NEIGHBOR_HEADER_SIZE,
        };
        use mesh_crypto::{CryptoKey, DEFAULT_PSK};
        use mesh_radio::MODEM_SHORT_SLOW;

        const ME: u32 = 0x677a_1caf;
        const PEER: u32 = 0x63dc_8f8c;
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let mut router = Router::with_channel(ME, key, 0x77, MODEM_SHORT_SLOW, true, 3);
        router.ensure_boot_broadcasts(0, 20);
        let _ = router.poll_topology_tx(0);

        let direct_wire = encode_wire(
            PacketHeader::from_fields(
                NODENUM_BROADCAST,
                PEER,
                1,
                0x77,
                3,
                3,
                false,
                false,
                0,
                (PEER & 0xFF) as u8,
            ),
            &[0x01],
        );
        router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &direct_wire,
                },
                500,
            )
            .unwrap();
        // The new-neighbour dirty broadcast is jittered; drain it before the empty-peer step.
        let drain_at = 500 + coordinated_relay::tx_delay_ms_contention_max(router.cw_slot_ms());
        let _ = router.poll_topology_tx(drain_at);

        let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE];
        write_packed_header(&mut packed, 1, true);
        let (len, frame) =
            build_topology_wire_frame(PEER, 99, 0x77, 3, &key, &packed, false).unwrap();
        let inbound = InboundPacket {
            radio_id: 0,
            rssi: -70,
            snr: 8,
            bytes: &frame[..len as usize],
        };
        router.process_inbound(&inbound, 1_000).unwrap();
        assert!(router.poll_topology_tx(1_000).is_none());

        router.run_maintenance(1_000, 20);
        assert!(router.poll_topology_tx(1_000).is_some());
    }

    /// A new neighbour marks the topology dirty; the list follows on the dirty schedule with
    /// jitter, not the instant the neighbour appears (partial boot-time lists made peers clear
    /// hears_us on their edge to us).
    #[test]
    fn new_neighbour_dirty_topology_broadcast_waits_for_the_dirty_window() {
        use mesh_crypto::{CryptoKey, DEFAULT_PSK};
        use mesh_radio::MODEM_SHORT_SLOW;
        const ME: u32 = 0x677a_1caf;
        const PEER: u32 = 0x63dc_8f8c;
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let mut router = Router::with_channel(ME, key, 0x77, MODEM_SHORT_SLOW, true, 3);
        router.ensure_boot_broadcasts(1_000, 20);
        assert!(router.poll_topology_tx(1_000).is_some(), "empty bootstrap");
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);

        let direct_wire = encode_wire(
            PacketHeader::from_fields(
                NODENUM_BROADCAST,
                PEER,
                7,
                0x77,
                3,
                3,
                false,
                false,
                0,
                (PEER & 0xFF) as u8,
            ),
            &[0x01],
        );
        router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &direct_wire,
                },
                1_500,
            )
            .unwrap();
        assert!(
            router.poll_topology_tx(1_600).is_none(),
            "no list the moment a neighbour appears"
        );
        router.run_maintenance(2_000, 20);
        assert!(
            router.poll_topology_tx(2_500).is_none(),
            "dirty window not yet elapsed"
        );
        router.drain_sr_logs(&mut logs);

        let due = 1_000 + crate::neighbor_graph::TOPOLOGY_DIRTY_MIN_MS;
        router.run_maintenance(due, 20);
        router.drain_sr_logs(&mut logs);
        let delay = logs
            .iter()
            .find_map(|e| match e {
                SrLogEvent::TopologyDirtySending { delay_ms } => Some(*delay_ms),
                _ => None,
            })
            .expect("dirty broadcast scheduled once the window elapsed");
        let max = coordinated_relay::tx_delay_ms_contention_max(router.cw_slot_ms());
        assert!(delay <= max, "delay {delay} exceeds contention bound {max}");
        if delay > 0 {
            assert!(
                router.poll_topology_tx(due + delay - 1).is_none(),
                "must not fire early"
            );
        }
        assert!(router.poll_topology_tx(due + delay).is_some());
    }

    /// Empty bootstrap broadcasts are answered at most once per BOOTSTRAP_REPLY_MIN_MS.
    #[test]
    fn bootstrap_replies_are_rate_limited() {
        use crate::topology::{build_topology_wire_frame, PACKED_NEIGHBOR_HEADER_SIZE};
        use mesh_radio::MODEM_SHORT_SLOW;
        const ME: u32 = 0x677a_1caf;
        const P1: u32 = 0x63dc_8f8c;
        const P2: u32 = 0x5879_fa8f;
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let mut router = Router::with_channel(ME, key, 0x77, MODEM_SHORT_SLOW, true, 3);
        router.ensure_boot_broadcasts(1_000, 20);
        let _ = router.poll_topology_tx(1_000);
        let mut logs = heapless::Vec::new();
        let bootstrap = |from: u32, id: u32| {
            let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE];
            write_packed_header(&mut packed, 1, true);
            build_topology_wire_frame(from, id, 0x77, 3, &key, &packed, false).unwrap()
        };
        let feed = |router: &mut Router, frame: &(u8, [u8; MAX_WIRE_LEN]), at: u32| {
            router
                .process_inbound(
                    &InboundPacket {
                        radio_id: 0,
                        rssi: -70,
                        snr: 8,
                        bytes: &frame.1[..frame.0 as usize],
                    },
                    at,
                )
                .unwrap();
            router.run_maintenance(at, 20);
        };
        // First bootstrap: answered.
        feed(&mut router, &bootstrap(P1, 0x91), 5_000);
        let max = coordinated_relay::tx_delay_ms_contention_max(router.cw_slot_ms());
        assert!((5_000..=5_000 + max).any(|t| router.poll_topology_tx(t).is_some()));
        // Second one shortly after, from another node: rate-limited.
        feed(&mut router, &bootstrap(P2, 0x92), 20_000);
        assert!((20_000..=20_000 + max).all(|t| router.poll_topology_tx(t).is_none()));
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::BootstrapReplyRateLimited)));
        // After the cooldown a bootstrap is answered again.
        feed(
            &mut router,
            &bootstrap(P1, 0x93),
            5_000 + BOOTSTRAP_REPLY_MIN_MS + 1,
        );
        let t3 = 5_000 + BOOTSTRAP_REPLY_MIN_MS + 1;
        assert!((t3..=t3 + max).any(|t| router.poll_topology_tx(t).is_some()));
    }

    /// A list that goes out after the bootstrap request has already answered it. Seen on a
    /// node whose periodic list and a queued bootstrap reply left 170 ms apart, doubling every
    /// relay of it downstream.
    #[test]
    fn bootstrap_reply_is_dropped_when_a_list_already_went_out() {
        use crate::topology::{build_topology_wire_frame, PACKED_NEIGHBOR_HEADER_SIZE};
        use mesh_radio::MODEM_SHORT_SLOW;
        const ME: u32 = 0x677a_1caf;
        const PEER: u32 = 0x63dc_8f8c;
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let mut router = Router::with_channel(ME, key, 0x77, MODEM_SHORT_SLOW, true, 3);
        let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE];
        write_packed_header(&mut packed, 1, true);
        let frame = build_topology_wire_frame(PEER, 0x94, 0x77, 3, &key, &packed, false).unwrap();
        // The peer asks for our list before our own first list has gone out.
        router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &frame.1[..frame.0 as usize],
                },
                1_000,
            )
            .unwrap();
        router.ensure_boot_broadcasts(2_000, 20);
        assert!(
            router.poll_topology_tx(2_000).is_some(),
            "our own list goes out after the request"
        );
        router.run_maintenance(3_000, 20);
        let max = coordinated_relay::tx_delay_ms_contention_max(router.cw_slot_ms());
        assert!(
            (3_000..=3_000 + max).all(|t| router.poll_topology_tx(t).is_none()),
            "the peer already has our list: no second one"
        );
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::BootstrapReplyAlreadyAnswered)));
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
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 1_000);
        if plan.relay.is_some() {
            return;
        }
        let tx_after = router.relay_tx_after(0xAABB_CCDD, 7, 0).expect("commit");
        assert!(router
            .poll_ready_relay(tx_after.saturating_sub(1))
            .is_none());
        assert!(router.poll_ready_relay(tx_after).is_some());
    }

    #[test]
    fn t1_retransmit_fires_after_defer_window() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0xCC00_00CC));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        let graph = router.graph_mut();
        const NEIGHBOR: u32 = 0xBB00_00BB;
        const STOCK: u32 = 0xDD00_00DD;
        graph.observe_direct_neighbor(NEIGHBOR, -70, 8, 0, 0);
        graph.observe_direct_neighbor(STOCK, -72, 7, 0, 0);
        graph.confirm_direct_neighbor_hears_us(NEIGHBOR);
        graph.confirm_direct_neighbor_hears_us(STOCK);
        graph.track_node_role(STOCK, crate::nodeinfo::DEVICE_ROLE_REPEATER, 0);
        graph.capability_mut().track_topology(NEIGHBOR, true, 0);
        graph.edges_mut().update_edge(
            0xCC00_00CC,
            STOCK,
            NEIGHBOR,
            2.0,
            0,
            EdgeSource::Reported,
            true,
            0,
        );
        graph.edges_mut().set_edge_hears_us(STOCK, NEIGHBOR, true);
        // EDGE is reachable by us and by the stock repeater, and not by the source. The
        // repeater takes the early slot and its coverage of EDGE is absorbed, so we defer with
        // nothing unique left — the deferral T1 exists for exactly this: if the repeater never
        // transmits, EDGE is still unreached when our rung comes up.
        const EDGE: u32 = 0xEE00_00EE;
        graph.observe_direct_neighbor(EDGE, -70, 8, 0, 0);
        graph.confirm_direct_neighbor_hears_us(EDGE);
        graph.edges_mut().update_edge(
            0xCC00_00CC,
            STOCK,
            EDGE,
            2.0,
            0,
            EdgeSource::Reported,
            true,
            0,
        );
        graph.edges_mut().set_edge_hears_us(STOCK, EDGE, true);

        let header =
            PacketHeader::from_fields(NODENUM_BROADCAST, NEIGHBOR, 99, 0, 3, 3, false, false, 0, 0);
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
        let plan = router.evaluate_tx_plan(&result, 0.0, airtime, 1_000);
        assert!(plan.relay.is_none());
        assert!(router.relay_tx_after(NEIGHBOR, 99, 0).is_none());

        let slot_ms = coordinated_relay::slot_time_for_preset(router.modem_preset());
        let fire_ms = coordinated_relay::tx_delay_ms_worst(slot_ms).saturating_add(airtime);
        // Never inside the defer window; our own rung of the insurance ladder follows it.
        assert!(router.poll_t1_retransmit(1_000 + fire_ms - 1).is_none());
        let ladder =
            coordinated_relay::half_airtime_ms(airtime) * crate::graph::MAX_EDGES_PER_NODE as u32;
        assert!(router
            .poll_t1_retransmit(1_000 + fire_ms + ladder)
            .is_some());
    }

    /// A copy heard after our insurance fired must still stop it: the frame has left the router
    /// but waits behind listen-before-talk, and only the radio queue can pull it back. Field
    /// 2026-09-08: six copies went out 0.4 to 1.0 s behind another insurer's for want of this.
    #[test]
    fn a_copy_heard_after_t1_fired_pulls_the_frame_back() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0xCC00_00CC));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        const NEIGHBOR: u32 = 0xBB00_00BB;
        const STOCK: u32 = 0xDD00_00DD;
        const EDGE: u32 = 0xEE00_00EE;
        {
            let graph = router.graph_mut();
            graph.observe_direct_neighbor(NEIGHBOR, -70, 8, 0, 0);
            graph.observe_direct_neighbor(STOCK, -72, 7, 0, 0);
            graph.observe_direct_neighbor(EDGE, -70, 8, 0, 0);
            graph.confirm_direct_neighbor_hears_us(NEIGHBOR);
            graph.confirm_direct_neighbor_hears_us(STOCK);
            graph.confirm_direct_neighbor_hears_us(EDGE);
            graph.track_node_role(STOCK, crate::nodeinfo::DEVICE_ROLE_REPEATER, 0);
            graph.capability_mut().track_topology(NEIGHBOR, true, 0);
            for target in [NEIGHBOR, EDGE] {
                graph.edges_mut().update_edge(
                    0xCC00_00CC,
                    STOCK,
                    target,
                    2.0,
                    0,
                    EdgeSource::Reported,
                    true,
                    0,
                );
                graph.edges_mut().set_edge_hears_us(STOCK, target, true);
            }
        }
        let wire = encode_wire(
            PacketHeader::from_fields(NODENUM_BROADCAST, NEIGHBOR, 99, 0, 3, 3, false, false, 0, 0),
            &[0x01, 0x02],
        );
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
        assert!(router
            .evaluate_tx_plan(&result, 0.0, airtime, 1_000)
            .relay
            .is_none());
        let slot_ms = coordinated_relay::slot_time_for_preset(router.modem_preset());
        let ladder =
            coordinated_relay::half_airtime_ms(airtime) * crate::graph::MAX_EDGES_PER_NODE as u32;
        let fire_at = (1_000 + coordinated_relay::tx_delay_ms_worst(slot_ms) + airtime
            ..=1_000 + coordinated_relay::tx_delay_ms_worst(slot_ms) + airtime + ladder)
            .find(|&t| router.poll_t1_retransmit(t).is_some())
            .expect("insurance fires: the repeater never relayed");
        let mut cancels = heapless::Vec::new();
        router.take_tx_cancels(&mut cancels);
        assert!(cancels.is_empty(), "nothing to pull back yet");
        // Another insurer's copy lands while ours is still queued.
        let relayed = encode_wire(
            PacketHeader::from_fields(
                NODENUM_BROADCAST,
                NEIGHBOR,
                99,
                0,
                2,
                3,
                false,
                false,
                0,
                (EDGE & 0xFF) as u8,
            ),
            &[0x01, 0x02],
        );
        let _ = router.process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 8,
                bytes: &relayed,
            },
            fire_at + 200,
        );
        router.take_tx_cancels(&mut cancels);
        assert!(
            cancels.contains(&99),
            "the queued insurance frame must be pulled out of the radio queue"
        );
        // And once the radio reports it went out, there is nothing left to cancel.
        router.note_tx_done(99);
        let _ = router.process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 8,
                bytes: &relayed,
            },
            fire_at + 400,
        );
        router.take_tx_cancels(&mut cancels);
        assert!(cancels.is_empty(), "already on the air: no pull-back");
    }

    /// The same deferral once the peer's copy is actually heard: only observation of the air
    /// cancels the insurance, never a repeat of the coverage question. Field evidence
    /// (2026-09-08): two of seven late copies carried frames the graph believed were covered
    /// but that were lost at -84 to -93 dBm, so the graph cannot answer this.
    #[test]
    fn t1_stands_down_when_the_peers_copy_is_heard() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0xCC00_00CC));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        const NEIGHBOR: u32 = 0xBB00_00BB;
        const STOCK: u32 = 0xDD00_00DD;
        const EDGE: u32 = 0xEE00_00EE;
        {
            let graph = router.graph_mut();
            graph.observe_direct_neighbor(NEIGHBOR, -70, 8, 0, 0);
            graph.observe_direct_neighbor(STOCK, -72, 7, 0, 0);
            graph.observe_direct_neighbor(EDGE, -70, 8, 0, 0);
            graph.confirm_direct_neighbor_hears_us(NEIGHBOR);
            graph.confirm_direct_neighbor_hears_us(STOCK);
            graph.confirm_direct_neighbor_hears_us(EDGE);
            graph.track_node_role(STOCK, crate::nodeinfo::DEVICE_ROLE_REPEATER, 0);
            graph.capability_mut().track_topology(NEIGHBOR, true, 0);
            for target in [NEIGHBOR, EDGE] {
                graph.edges_mut().update_edge(
                    0xCC00_00CC,
                    STOCK,
                    target,
                    2.0,
                    0,
                    EdgeSource::Reported,
                    true,
                    0,
                );
                graph.edges_mut().set_edge_hears_us(STOCK, target, true);
            }
        }
        let wire = encode_wire(
            PacketHeader::from_fields(NODENUM_BROADCAST, NEIGHBOR, 99, 0, 3, 3, false, false, 0, 0),
            &[0x01, 0x02],
        );
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
        assert!(router
            .evaluate_tx_plan(&result, 0.0, airtime, 1_000)
            .relay
            .is_none());
        // The repeater's copy arrives: the expected transmission happened after all.
        let relayed = encode_wire(
            PacketHeader::from_fields(
                NODENUM_BROADCAST,
                NEIGHBOR,
                99,
                0,
                2,
                3,
                false,
                false,
                0,
                (STOCK & 0xFF) as u8,
            ),
            &[0x01, 0x02],
        );
        let _ = router.process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -72,
                snr: 7,
                bytes: &relayed,
            },
            1_500,
        );
        let slot_ms = coordinated_relay::slot_time_for_preset(router.modem_preset());
        let fire_ms = coordinated_relay::tx_delay_ms_worst(slot_ms).saturating_add(airtime);
        let ladder =
            coordinated_relay::half_airtime_ms(airtime) * crate::graph::MAX_EDGES_PER_NODE as u32;
        for t in (1_500..=1_000 + fire_ms + ladder + 1_000).step_by(17) {
            assert!(router.poll_t1_retransmit(t).is_none(), "copy heard");
        }
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::T1Canceled {
                reason: T1CancelReason::RelayHeard,
                ..
            }
        )));
    }

    /// Two nodes and nothing else: the sender's broadcast reaches no new node if we relay it,
    /// but our copy is the only signal it can ever get that the mesh received it. The ranking
    /// has nothing to weigh here (we are the only candidate), so the sole-candidate rule
    /// relays immediately — the insurance timer never enters this case, whatever `want_ack`
    /// says. Field-proven: `candidates=1 ... via=sparse` followed by a committed relay.
    #[test]
    fn two_node_mesh_relays_and_confirms_to_the_sender() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        const ME: u32 = 0xCC00_00CC;
        const SRC: u32 = 0xBB00_00BB;
        let router = ROUTER.init(Router::new(ME));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        {
            let graph = router.graph_mut();
            graph.observe_direct_neighbor(SRC, -70, 8, 0, 0);
            graph.confirm_direct_neighbor_hears_us(SRC);
            graph.capability_mut().track_topology(SRC, true, 0);
        }
        // want_ack clear: no witness is owed, and none is needed to make us relay.
        let wire = encode_wire(
            PacketHeader::from_fields(NODENUM_BROADCAST, SRC, 0x79, 0, 3, 3, false, false, 0, 0),
            &[0x01, 0x02],
        );
        let airtime = coordinated_relay::DEFAULT_SLOT_MS * 10;
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
        let plan = router.evaluate_tx_plan(&result, 0.0, airtime, 1_000);
        let relayed = plan.relay.is_some()
            || router
                .relay_tx_after(SRC, 0x79, 0)
                .and_then(|tx| router.poll_ready_relay(tx))
                .is_some();
        assert!(
            relayed,
            "sole candidate: the sender gets its copy back, T1 not involved"
        );
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::SlotScheduling {
                reason: crate::broadcast_relay::RelayReason::Sparse,
                ..
            }
        )));
    }

    /// Nobody was given a slot and no originator is waiting to be told: no transmission is
    /// expected, so there is nothing for a late copy to stand in for. Measured over 30 min on
    /// three field nodes (2026-09-08): this declines ~100 copies per node and costs no
    /// delivery, while T1 traffic fell roughly tenfold.
    #[test]
    fn no_expected_transmission_arms_no_insurance() {
        use crate::topology::{decode_packed_neighbors, write_packed_header, PackedNeighbor};
        static ROUTER: StaticCell<Router> = StaticCell::new();
        const ME: u32 = 0xCC00_00CC;
        const SRC: u32 = 0xBB00_00BB;
        const PEER: u32 = 0xAB00_00AB;
        let router = ROUTER.init(Router::new(ME));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        {
            let graph = router.graph_mut();
            graph.observe_direct_neighbor(SRC, -70, 8, 0, 0);
            graph.observe_direct_neighbor(PEER, -70, 8, 0, 0);
            graph.confirm_direct_neighbor_hears_us(SRC);
            graph.confirm_direct_neighbor_hears_us(PEER);
            graph.capability_mut().track_topology(SRC, true, 0);
            graph.capability_mut().track_topology(PEER, true, 0);
        }
        // The source reaches PEER itself, so the ranking hands out no slot at all.
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let entry = PackedNeighbor {
            node_id: PEER,
            rssi: -70,
            snr: 8,
            signal_routing_active: true,
            hears_us: true,
            etx_variance: 0,
        };
        let us = PackedNeighbor {
            node_id: ME,
            ..entry
        };
        router
            .graph_mut()
            .merge_topology(SRC, &header, &[entry, us], true, 0, 0);

        // want_ack clear: the source asked for no acknowledgement either.
        let wire = encode_wire(
            PacketHeader::from_fields(NODENUM_BROADCAST, SRC, 0x77, 0, 3, 3, false, false, 0, 0),
            &[0x01, 0x02],
        );
        let airtime = coordinated_relay::DEFAULT_SLOT_MS * 10;
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
        let plan = router.evaluate_tx_plan(&result, 0.0, airtime, 1_000);
        assert!(plan.relay.is_none(), "nothing to reach: no immediate relay");
        let slot_ms = coordinated_relay::slot_time_for_preset(router.modem_preset());
        let ladder =
            coordinated_relay::half_airtime_ms(airtime) * crate::graph::MAX_EDGES_PER_NODE as u32;
        let horizon = 1_000
            + coordinated_relay::tx_delay_ms_worst(slot_ms)
            + airtime
            + ladder
            + half_airtime_ms(airtime);
        for t in (1_000..=horizon).step_by(17) {
            assert!(
                router.poll_t1_retransmit(t).is_none(),
                "nothing was expected"
            );
        }
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::RelaySkip {
                reason: SrSkipReason::AlreadyCovered,
                ..
            }
        )));
    }

    /// The same frame with `want_ack`: stock turns a heard rebroadcast into its implicit ACK
    /// and otherwise retransmits three times, so the elected witness answers even when the
    /// ranking gave nobody a slot.
    #[test]
    fn elected_witness_answers_when_no_slot_was_given() {
        use crate::topology::{decode_packed_neighbors, write_packed_header, PackedNeighbor};
        static ROUTER: StaticCell<Router> = StaticCell::new();
        const ME: u32 = 0xCC00_00CC;
        const SRC: u32 = 0xBB00_00BB;
        const PEER: u32 = 0xAB00_00AB;
        let router = ROUTER.init(Router::new(ME));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        {
            let graph = router.graph_mut();
            graph.observe_direct_neighbor(SRC, -70, 8, 0, 0);
            graph.observe_direct_neighbor(PEER, -70, 8, 0, 0);
            graph.confirm_direct_neighbor_hears_us(SRC);
            graph.confirm_direct_neighbor_hears_us(PEER);
            graph.capability_mut().track_topology(SRC, true, 0);
            graph.capability_mut().track_topology(PEER, true, 0);
        }
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let entry = PackedNeighbor {
            node_id: PEER,
            rssi: -90,
            snr: 2,
            signal_routing_active: true,
            hears_us: true,
            etx_variance: 0,
        };
        // The source hears us best, so the witness election falls to us.
        let us = PackedNeighbor {
            node_id: ME,
            rssi: -60,
            snr: 10,
            ..entry
        };
        router
            .graph_mut()
            .merge_topology(SRC, &header, &[entry, us], true, 0, 0);
        assert!(router.graph.is_elected_witness(SRC));

        let wire = encode_wire(
            PacketHeader::from_fields(NODENUM_BROADCAST, SRC, 0x78, 0, 3, 3, true, false, 0, 0),
            &[0x01, 0x02],
        );
        let airtime = coordinated_relay::DEFAULT_SLOT_MS * 10;
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
        assert!(router
            .evaluate_tx_plan(&result, 0.0, airtime, 1_000)
            .relay
            .is_none());
        let slot_ms = coordinated_relay::slot_time_for_preset(router.modem_preset());
        let fire_ms = coordinated_relay::tx_delay_ms_worst(slot_ms).saturating_add(airtime);
        let ladder =
            coordinated_relay::half_airtime_ms(airtime) * crate::graph::MAX_EDGES_PER_NODE as u32;
        assert!(
            (1_000 + fire_ms..=1_000 + fire_ms + ladder)
                .any(|t| router.poll_t1_retransmit(t).is_some()),
            "a want_ack originator that elected us gets its one witness"
        );
    }

    /// The witness election picks one answerer for a `want_ack` broadcast: stock turns a heard
    /// rebroadcast into its implicit ACK and otherwise retransmits three times. The evidence is
    /// the delivery direction — the originator must be able to hear the answer, so a peer we
    /// hear better than it hears us does not win on our side of the link.
    #[test]
    fn source_witness_is_the_neighbour_the_source_can_hear() {
        use crate::topology::{decode_packed_neighbors, write_packed_header, PackedNeighbor};
        static ROUTER: StaticCell<Router> = StaticCell::new();
        const ME: u32 = 0xCC00_00CC;
        const SRC: u32 = 0xBB00_00BB;
        const PEER: u32 = 0xAB00_00AB;
        let router = ROUTER.init(Router::new(ME));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        {
            let graph = router.graph_mut();
            graph.observe_direct_neighbor(SRC, -70, 8, 0, 0);
            graph.observe_direct_neighbor(PEER, -70, 8, 0, 0);
            graph.confirm_direct_neighbor_hears_us(PEER);
            graph.capability_mut().track_topology(SRC, true, 0);
            graph.capability_mut().track_topology(PEER, true, 0);
        }
        // The source publishes a list naming only PEER as a neighbour that hears it: we are not
        // in it, so our copy would acknowledge nothing however well we hear the source.
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let peer_entry = PackedNeighbor {
            node_id: PEER,
            rssi: -90,
            snr: 2,
            signal_routing_active: true,
            hears_us: true,
            etx_variance: 0,
        };
        router
            .graph_mut()
            .merge_topology(SRC, &header, &[peer_entry], true, 0, 0);
        assert!(
            !router.graph.is_elected_witness(SRC),
            "the source cannot hear us: our copy is no acknowledgement"
        );
        // Once the source lists us too, the election is between two nodes it hears, and the
        // better link in the delivery direction wins.
        let us_entry = PackedNeighbor {
            node_id: ME,
            rssi: -60,
            snr: 10,
            ..peer_entry
        };
        router
            .graph_mut()
            .merge_topology(SRC, &header, &[peer_entry, us_entry], true, 0, 0);
        assert!(
            router.graph.is_elected_witness(SRC),
            "the source hears us best: we answer for it"
        );
    }

    #[test]
    fn ranked_broadcast_slot_does_not_arm_t1() {
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
        let slot_ms = coordinated_relay::slot_time_for_preset(router.modem_preset());
        let fire_ms = coordinated_relay::tx_delay_ms_worst(slot_ms).saturating_add(airtime);
        assert!(
            router.poll_t1_retransmit(1_000 + fire_ms).is_none(),
            "a node that took a relay slot must not also arm T1"
        );
    }

    /// A covered relay is cancelled whatever our role, and the role still governs other traffic.
    ///
    /// The coverage test answers "has somebody already carried the nodes we would have carried";
    /// the role gate answers "may a router fall silent for reasons of its own". They are different
    /// questions and the first has to win, or a node configured ROUTER or ROUTER_LATE cancels its
    /// insurance on hearing a copy and then transmits anyway — one extra frame with the backstop
    /// already given up.
    #[test]
    fn coverage_cancels_a_committed_relay_whatever_our_role() {
        for role in [
            crate::nodeinfo::DEVICE_ROLE_CLIENT,
            crate::nodeinfo::DEVICE_ROLE_ROUTER,
            crate::nodeinfo::DEVICE_ROLE_ROUTER_LATE,
        ] {
            // A fresh router per role. Built as a local rather than through a StaticCell, which
            // can only be initialised once and so cannot serve a loop.
            let mut router = Router::new(0x677a_1caf);
            router.set_device_role(role);

            // One neighbour that hears us, so a broadcast from a second node gives us a rung.
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
            assert!(
                router.has_pending_work(),
                "role {role}: a rung should have been taken"
            );

            // The neighbour relays it. Its copy covers the only node we could have reached, so
            // ours is redundant whatever our own role says about falling silent.
            let dupe = encode_wire(
                PacketHeader::from_fields(
                    NODENUM_BROADCAST,
                    0x2222_2222,
                    99,
                    0,
                    3,
                    2,
                    false,
                    false,
                    0,
                    (0x1111_1111u32 & 0xFF) as u8,
                ),
                &[0x01, 0x02],
            );
            let _ = router.process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -66,
                    snr: 11,
                    bytes: &dupe,
                },
                1_050,
            );
            assert!(
                !router.has_pending_work(),
                "role {role}: a covered relay must be cancelled, role notwithstanding"
            );
        }
    }

    /// The role gate still applies where SR has not committed: stock behaviour for stock traffic.
    #[test]
    fn role_still_governs_traffic_we_did_not_commit_to() {
        let mut router = Router::new(0x677a_1caf);
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        assert!(
            !router.graph.role_allows_canceling_dupe(),
            "a ROUTER still declines to cancel on its own account"
        );
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_CLIENT);
        assert!(router.graph.role_allows_canceling_dupe());
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
        let _plan =
            router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 1_000);
        assert!(router.has_pending_work());
    }

    const LAST_HOP_ME: u32 = 0xCC00_00CC;
    const LAST_HOP_SOURCE: u32 = 0xBB00_00BB;
    const LAST_HOP_GATEWAY: u32 = 0xEE00_00EE;

    fn last_hop_broadcast_wire(
        source: u32,
        relay: u32,
        hop_limit: u8,
        hop_start: u8,
        id: u32,
    ) -> heapless::Vec<u8, 128> {
        let header = PacketHeader::from_fields(
            0xFFFF_FFFF,
            source,
            id,
            0,
            hop_limit,
            hop_start,
            false,
            false,
            0,
            (relay & 0xFF) as u8,
        );
        encode_wire(header, &[0xDE, 0xAD])
    }

    #[test]
    fn last_hop_broadcast_relayed_with_zero_hop_limit() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(LAST_HOP_ME));
        router.graph_mut().downstream_mut().update(
            LAST_HOP_ME,
            LAST_HOP_SOURCE,
            LAST_HOP_GATEWAY,
            100.0,
            0,
            false,
            0,
        );

        let wire = last_hop_broadcast_wire(LAST_HOP_SOURCE, LAST_HOP_GATEWAY, 1, 3, 42);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -80,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        // Stock Meshtastic semantics: hop_limit 1 is relayed once more with hop_limit 0.
        let relay = plan
            .relay
            .or_else(|| {
                router
                    .relay_tx_after(LAST_HOP_SOURCE, 42, 0)
                    .and_then(|tx| router.poll_ready_relay(tx))
            })
            .expect("hop_limit=1 broadcast must be relayed");
        let header = PacketHeader::decode(&relay.bytes[..PACKET_HEADER_LEN]).unwrap();
        assert_eq!(header.hop_limit(), 0);
        assert_eq!(header.hop_start(), 3);
    }

    const UNI_ME: u32 = 0xCC00_00CC;
    const UNI_RELAYER: u32 = 0xBB00_00BB;
    const UNI_SOURCE: u32 = 0xDD00_00DD;
    const UNI_DEST: u32 = 0xEE00_00EE;

    /// Graph: we hear RELAYER directly, DEST is only known as downstream of RELAYER (no
    /// verified two-hop route).
    fn setup_downstream_only_graph(router: &mut Router) {
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_RELAYER, -70, 8, 0, 0);
        router
            .graph_mut()
            .downstream_mut()
            .update(UNI_ME, UNI_DEST, UNI_RELAYER, 2.0, 0, false, 0);
    }

    /// Graph: verified route ME -> RELAYER -> DEST. RELAYER is an SR-active neighbour that
    /// hears us and reports DEST as a neighbour that hears it.
    fn setup_unicast_graph(router: &mut Router) {
        setup_downstream_only_graph(router);
        router
            .graph_mut()
            .capability_mut()
            .track_topology(UNI_RELAYER, true, 0);
        router
            .graph_mut()
            .confirm_direct_neighbor_hears_us(UNI_RELAYER);
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let dest = PackedNeighbor {
            node_id: UNI_DEST,
            rssi: -75,
            snr: 8,
            signal_routing_active: false,
            hears_us: true,
            etx_variance: 0,
        };
        // RELAYER must list us too, otherwise its report clears our hears_us flag on it.
        let us = PackedNeighbor {
            node_id: UNI_ME,
            ..dest
        };
        router
            .graph_mut()
            .merge_topology(UNI_RELAYER, &header, &[dest, us], true, 0, 0);
    }

    #[test]
    fn unverified_route_relays_with_next_hop_cleared() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_downstream_only_graph(router);
        // Route picker falls back to "relay ourselves": the frame must not carry our byte.
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x600, true);
        let (sent, _) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0);
        assert!(
            !router.has_pending_reliable(0x600),
            "no designated hop, nothing to retry"
        );
    }

    const UNI_PEER: u32 = 0xAB00_00AB;

    /// Graph: DEST is only reachable by guess. GATEWAY reports DEST as a neighbour it hears,
    /// DEST publishes topology and has never listed GATEWAY, so nothing says DEST hears it —
    /// the inbound-gateway fallback, not a verified path.
    fn setup_unverified_gateway_graph(router: &mut Router, listener: Option<u32>) {
        let graph = router.graph_mut();
        graph.observe_direct_neighbor(UNI_RELAYER, -70, 8, 0, 0);
        graph.capability_mut().track_topology(UNI_RELAYER, true, 0);
        graph.capability_mut().track_topology(UNI_DEST, true, 0);
        graph.confirm_direct_neighbor_hears_us(UNI_RELAYER);
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let us = PackedNeighbor {
            node_id: UNI_ME,
            rssi: -70,
            snr: 8,
            signal_routing_active: false,
            hears_us: true,
            etx_variance: 0,
        };
        // GATEWAY hears DEST; DEST has never confirmed the reverse.
        let dest = PackedNeighbor {
            node_id: UNI_DEST,
            hears_us: false,
            ..us
        };
        router
            .graph_mut()
            .merge_topology(UNI_RELAYER, &header, &[dest, us], true, 0, 0);
        // A second SR neighbour that reports the gateway, so a packet heard from it counts as
        // reaching the gateway and the route survives the connectivity check.
        if let Some(peer) = listener {
            let graph = router.graph_mut();
            graph.observe_direct_neighbor(peer, -70, 8, 0, 0);
            graph.capability_mut().track_topology(peer, true, 0);
            graph.confirm_direct_neighbor_hears_us(peer);
            let gw = PackedNeighbor {
                node_id: UNI_RELAYER,
                ..us
            };
            router
                .graph_mut()
                .merge_topology(peer, &header, &[gw, us], true, 0, 0);
        }
    }

    /// 2026-09-07: the branch gateway relayed unicasts for outside destinations back into the
    /// branch, where the only path known was the one the packet arrived on.
    #[test]
    fn guessed_route_back_the_way_it_came_is_dropped() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unverified_gateway_graph(router, None);
        // Heard from the gateway itself: our guess names it as next hop.
        let wire = unicast_wire(2, 3, 0, 0xBB, 0x701);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(!scheduled, "carrying it moves the packet away from DEST");
        assert_eq!(reason, Some(SrSkipReason::UnverifiedBacktrack));
    }

    /// The same frame, but the sender named us as its next hop: it is waiting on us
    /// specifically and its retries would designate us again, so one copy from us costs less
    /// than three from it. Forwarded with the next hop cleared, never dropped.
    #[test]
    fn a_frame_named_for_us_is_forwarded_even_on_a_guessed_backtrack() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unverified_gateway_graph(router, None);
        // Heard from the gateway, whose byte our guess names — but the frame names us.
        let wire = unicast_wire(2, 3, (UNI_ME & 0xFF) as u8, 0xBB, 0x703);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(scheduled, "named for us: carry it");
        assert_ne!(reason, Some(SrSkipReason::UnverifiedBacktrack));
    }

    #[test]
    fn a_direct_frame_routed_through_us_proves_the_sender_hears_us() {
        const SENDER: u32 = 0x4600_0046;
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        router
            .graph_mut()
            .set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);

        // Addressed to us, arrived direct, and the sender named our byte as its next hop: it can
        // only have learned to route through us by hearing us.
        let header = PacketHeader::from_fields(
            UNI_ME,
            SENDER,
            0x901,
            0x77,
            7,
            7,
            true,
            false,
            (UNI_ME & 0xFF) as u8,
            (SENDER & 0xFF) as u8,
        );
        let wire = encode_wire(header, &[0xDE, 0xAD]);
        let _ = router.process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -50,
                snr: 12,
                bytes: &wire,
            },
            1_000,
        );
        assert!(
            router.graph_mut().edge_hears_us_for_test(SENDER),
            "a peer that routes through us hears us"
        );
    }

    #[test]
    fn a_relayed_frame_naming_us_proves_nothing_about_its_sender() {
        const SENDER: u32 = 0x4700_0047;
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        router
            .graph_mut()
            .set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        router
            .graph_mut()
            .observe_direct_neighbor(SENDER, -50, 12, 500, 0);

        // Our byte is named, but the frame was relayed: the byte was stamped by the relayer, and
        // it says nothing about whether the originator hears us.
        let header = PacketHeader::from_fields(
            UNI_ME,
            SENDER,
            0x902,
            0x77,
            5,
            7,
            true,
            false,
            (UNI_ME & 0xFF) as u8,
            0xBB,
        );
        let wire = encode_wire(header, &[0xDE, 0xAD]);
        let _ = router.process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -50,
                snr: 12,
                bytes: &wire,
            },
            1_000,
        );
        assert!(
            !router.graph_mut().edge_hears_us_for_test(SENDER),
            "a relayed frame carries the relayer's next hop, not the sender's"
        );
    }

    #[test]
    fn guessed_route_is_never_stamped_as_next_hop() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unverified_gateway_graph(router, Some(UNI_PEER));
        // Heard from the other SR neighbour, so the guess points onward, not back.
        let wire = unicast_wire_ack(2, 3, 0, 0xAB, 0x702, true);
        let (sent, _) = forward_unicast(router, &wire, 0);
        assert_eq!(
            sent.next_hop, 0,
            "a node that never confirmed it hears DEST must not be designated"
        );
        assert!(
            !router.has_pending_reliable(0x702),
            "no designated hop, nothing to retry"
        );
    }

    fn unicast_wire(
        hop_limit: u8,
        hop_start: u8,
        next_hop: u8,
        relay: u8,
        id: u32,
    ) -> heapless::Vec<u8, 128> {
        let header = PacketHeader::from_fields(
            UNI_DEST, UNI_SOURCE, id, 0x77, hop_limit, hop_start, false, false, next_hop, relay,
        );
        encode_wire(header, &[0xDE, 0xAD, 0xBE, 0xEF])
    }

    fn unicast_skip_reason(router: &mut Router, wire: &[u8]) -> (bool, Option<SrSkipReason>) {
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: wire,
                },
                0,
            )
            .unwrap();
        let (from, id) = (result.parsed.from, result.parsed.id);
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        // Only the relay of this packet counts; a directly heard source also queues a
        // topology broadcast, which is unrelated pending work.
        let scheduled = plan.relay.is_some() || router.relay_tx_after(from, id, 0).is_some();
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        let reason = logs.iter().rev().find_map(|e| match e {
            SrLogEvent::RelaySkip { reason, .. } => Some(*reason),
            _ => None,
        });
        (scheduled, reason)
    }

    #[test]
    fn unicast_not_relayed_back_to_the_relayer() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        // Heard from RELAYER (relay byte 0xBB), and RELAYER is also our route to DEST.
        let wire = unicast_wire(2, 3, 0, 0xBB, 0x501);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(!scheduled);
        assert_eq!(reason, Some(SrSkipReason::NextHopIsRelayer));
    }

    fn unicast_wire_ack(
        hop_limit: u8,
        hop_start: u8,
        next_hop: u8,
        relay: u8,
        id: u32,
        want_ack: bool,
    ) -> heapless::Vec<u8, 128> {
        let header = PacketHeader::from_fields(
            UNI_DEST, UNI_SOURCE, id, 0x77, hop_limit, hop_start, want_ack, false, next_hop, relay,
        );
        encode_wire(header, &[0xDE, 0xAD, 0xBE, 0xEF])
    }

    /// Feed a unicast, release its relay (immediately or from the pending slot) and return the
    /// transmitted frame header.
    /// Returns the transmitted header and the time the relay left (retries are armed then).
    fn forward_unicast(router: &mut Router, wire: &[u8], now_ms: u32) -> (ParsedPacket, u32) {
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: wire,
                },
                now_ms,
            )
            .unwrap();
        let (from, id) = (result.parsed.from, result.parsed.id);
        let plan =
            router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, now_ms);
        let (relay, released_at) = match plan.relay {
            Some(r) => (r, now_ms),
            None => {
                let tx = router.relay_tx_after(from, id, 0).expect("relay committed");
                (router.poll_ready_relay(tx).expect("relay released"), tx)
            }
        };
        (
            PacketHeader::decode(&relay.bytes[..PACKET_HEADER_LEN])
                .unwrap()
                .parse(),
            released_at,
        )
    }

    #[test]
    fn forwarded_want_ack_unicast_is_retried_then_released_to_flooding() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x601, true);
        let (sent, armed_at) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0xBB, "route to DEST goes via RELAYER");
        assert!(router.has_pending_reliable(0x601), "retries armed");
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::RelayRetxArmed {
                id: 0x601,
                next_hop: 0xBB
            }
        )));

        let step = router.reliable_retx_delay_ms(sent_len(&wire), UNI_SOURCE, 0x601);
        let mut t = armed_at;
        assert!(router.poll_reliable_retransmit(t + step - 1).is_none());
        // Retries 1 and 2 keep the designated next hop.
        for _ in 0..2 {
            t += step;
            let retx = router.poll_reliable_retransmit(t + 1).expect("retry due");
            let hdr = PacketHeader::decode(&retx.bytes[..PACKET_HEADER_LEN])
                .unwrap()
                .parse();
            assert_eq!(hdr.next_hop, 0xBB);
        }
        // Retry 3 is the fallback: next hop cleared, then nothing more.
        t += step;
        let last = router
            .poll_reliable_retransmit(t + 1)
            .expect("final retry due");
        let hdr = PacketHeader::decode(&last.bytes[..PACKET_HEADER_LEN])
            .unwrap()
            .parse();
        assert_eq!(hdr.next_hop, 0, "last retry must be released to flooding");
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::RelayRetxFired {
                id: 0x601,
                fallback: true
            }
        )));
        t += step;
        assert!(router.poll_reliable_retransmit(t + 1).is_none());
        assert!(!router.has_pending_reliable(0x601));
    }

    fn sent_len(wire: &[u8]) -> u8 {
        wire.len() as u8
    }

    #[test]
    fn forwarded_unicast_without_want_ack_is_not_retried() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x602, false);
        let (sent, _) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0xBB);
        assert!(!router.has_pending_reliable(0x602));
    }

    #[test]
    fn heard_copy_cancels_forwarded_retries() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x603, true);
        let _ = forward_unicast(router, &wire, 0);
        assert!(router.has_pending_reliable(0x603));
        // RELAYER carries it on (one more hop used, its relay byte).
        let copy = unicast_wire_ack(1, 3, 0, 0xBB, 0x603, true);
        let dupe = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &copy,
                },
                500,
            )
            .unwrap();
        assert!(dupe.duplicate);
        assert!(!router.has_pending_reliable(0x603));
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::RelayRetxCanceled {
                id: 0x603,
                reason: RelayRetxCancelReason::CopyHeard
            }
        )));
    }

    #[test]
    fn reply_to_origin_cancels_forwarded_retries() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x604, true);
        let _ = forward_unicast(router, &wire, 0);
        assert!(router.has_pending_reliable(0x604));
        // DEST acks SOURCE for 0x604 on the primary channel.
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let (len, ack) = build_ack_nak_frame(
            UNI_SOURCE,
            UNI_DEST,
            0x7001,
            0x604,
            router.channel_hash(),
            3,
            ROUTING_ERROR_NONE,
            &key,
            false,
            0,
        )
        .unwrap();
        let _ = router.process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 8,
                bytes: &ack[..len as usize],
            },
            700,
        );
        assert!(!router.has_pending_reliable(0x604));
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::RelayRetxCanceled {
                id: 0x604,
                reason: RelayRetxCancelReason::ReplyHeard
            }
        )));
    }

    #[test]
    fn unicast_designated_to_us_takes_slot_zero() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        // Heard from SOURCE with our byte (0xCC) as next hop; DEST is downstream via RELAYER.
        let wire = unicast_wire(3, 3, 0xCC, 0xDD, 0x502);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(scheduled);
        assert_eq!(reason, None);
        assert!(router.relay_tx_after(UNI_SOURCE, 0x502, 0).is_some());
    }

    #[test]
    fn duplicate_naming_us_as_next_hop_is_forwarded_with_next_hop_cleared() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        // First copy names RELAYER (0xBB) as next hop: we take a later slot.
        let wire = unicast_wire(3, 3, 0xBB, 0xDD, 0x611);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        assert!(plan.relay.is_none());
        // RELAYER forwards it naming us. Our own route to DEST goes through RELAYER, so the
        // hand-off is honoured by flooding with next_hop cleared instead of being dropped.
        let copy = unicast_wire(2, 3, 0xCC, 0xBB, 0x611);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &copy,
                },
                50,
            )
            .unwrap();
        assert!(!result.duplicate, "a hand-off is not a dupe");
        let _ = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 50);
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(
            logs.iter().any(|e| matches!(
                e,
                SrLogEvent::UnicastDesignated {
                    is_us: true,
                    slot: 0,
                    ..
                }
            )),
            "hand-off takes slot 0; log: {logs:?}"
        );
        // Slot 0 still sits behind the short post-reception hold, so it is pending, not inline.
        let origin = crate::channel_access::SLOT_ORIGIN_MS;
        assert!(
            router.poll_ready_relay(50 + origin - 1).is_none(),
            "slot 0 sits at the ladder origin, inside the peers' turnaround"
        );
        let relay = router
            .poll_ready_relay(50 + origin + coordinated_relay::DEFAULT_SLOT_MS)
            .expect("hand-off relay ready at slot 0");
        let hdr = PacketHeader::decode(&relay.bytes[..PACKET_HEADER_LEN])
            .unwrap()
            .parse();
        assert_eq!(hdr.next_hop, 0, "route pointed back at the relayer: flood");
        assert_eq!(hdr.relay_node, 0xCC);
        assert_eq!(hdr.hop_limit, 1);
        router.record_tx_on_air(0x611, 50 + origin + 20);
        assert!(
            router.poll_ready_relay(50 + origin + 10_000).is_none(),
            "the first copy's later-slot frame was replaced, not queued behind the hand-off"
        );
    }

    /// 2026-09-06 17:31: Dura's request to FCM6 carried FCM6's own byte as next hop. Both
    /// nicenanos waited the worst-case stock delay for a relayer that cannot exist.
    /// 2026-09-07: a unicast named A as next hop, A's own route to the destination pointed back
    /// at the node A heard it from, and A skipped it as "next hop is relayer". The designated hop
    /// forwards; only bystanders may defer.
    #[test]
    fn designated_hop_forwards_even_when_our_route_points_back_at_the_relayer() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        // Our route to the destination runs through the node we hear the packet from.
        assert_eq!(
            router.graph_mut().route_to(UNI_DEST, 0).next_hop,
            UNI_RELAYER,
            "fixture: our route to the destination is via the relayer"
        );
        let relayer_byte = (UNI_RELAYER & 0xFF) as u8;
        let wire = unicast_wire(3, 3, (UNI_ME & 0xFF) as u8, relayer_byte, 0x705);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        let relay = plan
            .relay
            .or_else(|| {
                router
                    .relay_tx_after(UNI_SOURCE, 0x705, 0)
                    .and_then(|after| router.poll_ready_relay(after))
            })
            .expect("the designated hop must forward");
        assert!(
            relay.delay_ms <= crate::channel_access::SLOT_ORIGIN_MS,
            "designated hop owns slot 0, got {}",
            relay.delay_ms
        );
        let hdr = PacketHeader::decode(&relay.bytes[..PACKET_HEADER_LEN])
            .unwrap()
            .parse();
        assert_eq!(
            hdr.next_hop, 0,
            "must not hand the packet back to the node it came from"
        );
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(
            !logs.iter().any(|e| matches!(
                e,
                SrLogEvent::RelaySkip {
                    reason: SrSkipReason::NextHopIsRelayer,
                    ..
                }
            )),
            "must not skip a packet addressed through us: {logs:?}"
        );
    }

    #[test]
    fn next_hop_equal_to_the_destination_names_no_relayer() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire(3, 3, (UNI_DEST & 0xFF) as u8, 0xDD, 0x504);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        let slot0_wait = coordinated_relay::tx_delay_ms_worst(coordinated_relay::DEFAULT_SLOT_MS)
            + coordinated_relay::DEFAULT_SLOT_MS;
        let tx_after = plan
            .relay
            .map(|r| r.delay_ms)
            .or_else(|| router.relay_tx_after(UNI_SOURCE, 0x504, 0))
            .expect("relay planned by the cost ranking");
        assert!(
            tx_after < slot0_wait,
            "no slot-0 reservation for the destination itself: {tx_after} >= {slot0_wait}"
        );
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(
            !logs
                .iter()
                .any(|e| matches!(e, SrLogEvent::UnicastDesignated { .. })),
            "the destination byte is not a designated relayer"
        );
    }

    #[test]
    fn unicast_designated_elsewhere_takes_a_later_slot_and_cancels_on_copy() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        // next_hop 0x99 names an unknown (treated as stock) node: it owns slot 0, we wait at
        // least the worst-case stock delay plus one airtime before our own slot.
        let wire = unicast_wire(3, 3, 0x99, 0xDD, 0x503);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        assert!(plan.relay.is_none(), "must not relay immediately");
        let tx_after = router
            .relay_tx_after(UNI_SOURCE, 0x503, 0)
            .expect("relay pending in a later slot");
        let slot0_wait = coordinated_relay::tx_delay_ms_worst(coordinated_relay::DEFAULT_SLOT_MS)
            + coordinated_relay::DEFAULT_SLOT_MS;
        assert!(
            tx_after >= slot0_wait,
            "tx_after {tx_after} < slot-0 wait {slot0_wait}"
        );
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::UnicastDesignated { next_hop: 0x99, is_us: false, sr_active: false, slot, .. } if *slot >= 1
        )));

        // The designated node relays (copy with one hop used, relay byte 0x99): we stand down.
        let copy = unicast_wire(2, 3, 0, 0x99, 0x503);
        let dupe = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &copy,
                },
                100,
            )
            .unwrap();
        assert!(dupe.duplicate);
        assert!(
            router.relay_tx_after(UNI_SOURCE, 0x503, 0).is_none(),
            "pending relay must be cancelled"
        );
        assert!(router.poll_ready_relay(tx_after + 1).is_none());
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::UnicastDupeCancel { id: 0x503, .. })));
    }

    #[test]
    fn designated_hop_backup_survives_ranking_skip() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        const PEER: u32 = 0xAA00_00AA;
        router
            .graph_mut()
            .observe_direct_neighbor(PEER, -70, 8, 0, 0);
        router.graph_mut().confirm_direct_neighbor_hears_us(PEER);
        router
            .graph_mut()
            .capability_mut()
            .track_topology(PEER, true, 0);
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let dest = PackedNeighbor {
            node_id: UNI_DEST,
            rssi: -75,
            snr: 8,
            signal_routing_active: false,
            hears_us: true,
            etx_variance: 0,
        };
        let us = PackedNeighbor {
            node_id: UNI_ME,
            ..dest
        };
        router
            .graph_mut()
            .merge_topology(PEER, &header, &[dest, us], true, 0, 0);

        // Named hop owns slot 0; ranking UnicastCover because PEER already reaches DEST —
        // previously that Err aborted the whole plan. Relay byte is PEER (not our path hop).
        let wire = unicast_wire(3, 3, 0x99, 0xAA, 0x505);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        assert!(plan.relay.is_none(), "backup waits behind designated");
        let tx_after = router
            .relay_tx_after(UNI_SOURCE, 0x505, 0)
            .expect("designated backup must still schedule");
        let slot0_wait = coordinated_relay::tx_delay_ms_worst(coordinated_relay::DEFAULT_SLOT_MS)
            + coordinated_relay::DEFAULT_SLOT_MS;
        assert!(
            tx_after >= slot0_wait,
            "tx_after {tx_after} < slot-0 wait {slot0_wait}"
        );
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(
            !logs
                .iter()
                .any(|e| matches!(e, SrLogEvent::RelaySkip { .. })),
            "ranking skip must not abort designated backup; log: {logs:?}"
        );
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::UnicastDesignated {
                next_hop: 0x99,
                is_us: false,
                slot,
                ..
            } if *slot >= 1
        )));
        let relay = router
            .poll_ready_relay(tx_after + coordinated_relay::DEFAULT_SLOT_MS)
            .expect("backup TX after designated wait");
        let hdr = PacketHeader::decode(&relay.bytes[..PACKET_HEADER_LEN])
            .unwrap()
            .parse();
        assert_eq!(hdr.next_hop, 0xBB, "path next hop, not flood");
        assert_eq!(hdr.relay_node, 0xCC);
    }

    /// The relayer we heard the packet from is the first hop of a verified path, but cannot
    /// finish it alone: handing the packet back is not a dupe, so we stay in the ranking with
    /// next_hop cleared. (A guessed route pointing back is the different, contained case.)
    #[test]
    fn next_hop_is_relayer_clears_when_they_cannot_finish() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        {
            let graph = router.graph_mut();
            graph.observe_direct_neighbor(UNI_RELAYER, -70, 8, 0, 0);
            graph.confirm_direct_neighbor_hears_us(UNI_RELAYER);
            graph.capability_mut().track_topology(UNI_RELAYER, true, 0);
            graph.capability_mut().track_topology(UNI_PEER, true, 0);
            graph.capability_mut().track_topology(UNI_DEST, true, 0);
        }
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let heard = PackedNeighbor {
            node_id: UNI_ME,
            rssi: -70,
            snr: 8,
            signal_routing_active: true,
            hears_us: true,
            etx_variance: 0,
        };
        // ME -> RELAYER -> PEER -> DEST, every hop confirmed by the node that receives it.
        // RELAYER has no edge to DEST of its own, so can_deliver(RELAYER, DEST) is false and
        // there is no downstream entry either: it cannot finish in one hop.
        let via_peer = PackedNeighbor {
            node_id: UNI_PEER,
            ..heard
        };
        router
            .graph_mut()
            .merge_topology(UNI_RELAYER, &header, &[via_peer, heard], true, 0, 0);
        let to_dest = PackedNeighbor {
            node_id: UNI_DEST,
            ..heard
        };
        let gw = PackedNeighbor {
            node_id: UNI_RELAYER,
            ..heard
        };
        router
            .graph_mut()
            .merge_topology(UNI_PEER, &header, &[to_dest, gw], true, 0, 0);

        let wire = unicast_wire(2, 3, 0, 0xBB, 0x506);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(
            scheduled,
            "cannot finish at RELAYER: stay in ranking, not NextHopIsRelayer"
        );
        assert_ne!(reason, Some(SrSkipReason::NextHopIsRelayer));
        assert_ne!(reason, Some(SrSkipReason::UnverifiedBacktrack));
    }

    /// After a preset switch the requester stays on its preset: retries, T1 insurance, ACKs
    /// and committed relays timed for the old air parameters must not go out on the new one.
    #[test]
    fn preset_switch_drops_stale_retransmits_and_relays() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        // A forwarded want_ack unicast arms relayed retries once its relay leaves.
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x801, true);
        let (_, released_at) = forward_unicast(router, &wire, 0);
        assert!(router.has_pending_reliable(0x801));
        // A second unicast still sits in its relay slot.
        let wire2 = unicast_wire(3, 3, 0, 0xDD, 0x802);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire2,
                },
                released_at + 10,
            )
            .unwrap();
        let _ = router.evaluate_tx_plan(
            &result,
            0.0,
            coordinated_relay::DEFAULT_SLOT_MS,
            released_at + 10,
        );
        assert!(router.relay_tx_after(UNI_SOURCE, 0x802, 0).is_some());

        router.radio_reconfigured();

        assert!(!router.has_pending_reliable(0x801));
        assert!(router.relay_tx_after(UNI_SOURCE, 0x802, 0).is_none());
        let far = released_at + 600_000;
        assert!(router.poll_reliable_retransmit(far).is_none());
        assert!(router.poll_ready_relay(far).is_none());
        assert!(router.poll_t1_retransmit(far).is_none());
        assert!(router.poll_ack_tx(far).is_none());
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::RadioReconfigured { dropped } if *dropped >= 2
        )));
    }

    /// A copy heard after our relay left the router (it may sit in the radio queue behind
    /// listen-before-talk) must be reported so the board can pull the frame back.
    #[test]
    fn dupe_cancel_reports_the_frame_for_radio_removal() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire(3, 3, 0, 0xDD, 0x901);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let _ = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        let tx_after = router
            .relay_tx_after(UNI_SOURCE, 0x901, 0)
            .expect("later slot");
        // The slot fires: the frame leaves the router for the radio queue, and the board records
        // the transmission as it queues the frame.
        assert!(router.poll_ready_relay(tx_after).is_some());
        router.record_tx_on_air(0x901, tx_after);
        let mut cancels = heapless::Vec::new();
        router.take_tx_cancels(&mut cancels);
        assert!(cancels.is_empty());

        // RELAYER's copy arrives while our frame is still queued in the radio.
        let copy = unicast_wire(2, 3, 0, 0xBB, 0x901);
        let dupe = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &copy,
                },
                tx_after + 20,
            )
            .unwrap();
        assert!(dupe.duplicate);
        router.take_tx_cancels(&mut cancels);
        assert_eq!(cancels.as_slice(), &[0x901]);
        router.take_tx_cancels(&mut cancels);
        assert!(cancels.is_empty(), "reported once");
    }

    /// A broadcast copy heard after our relay left the router pulls the frame back only when the
    /// transmitters heard so far cover every neighbour we reach; TX done ends the relay's life.
    #[test]
    fn released_broadcast_relay_is_pulled_back_only_when_covered() {
        const ME: u32 = 0xCC00_00CC;
        const SRC: u32 = 0xDD00_00DD;
        const PEER: u32 = 0x1100_0011; // ranks ahead of us: covers three nodes
        const UNIQ: u32 = 0xEE00_00EE; // hears only us
        const OTHER: u32 = 0x9900_0099; // does not hear the source; its copy covers UNIQ
        const X: u32 = 0x7700_0077;
        const Y: u32 = 0x8800_0088;
        const Z: u32 = 0x6600_0066;
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(ME));
        {
            let g = router.graph_mut();
            for n in [SRC, PEER, UNIQ, OTHER] {
                g.observe_direct_neighbor(n, -70, 8, 0, 0);
            }
            for n in [PEER, UNIQ] {
                g.confirm_direct_neighbor_hears_us(n);
            }
            for n in [PEER, UNIQ, OTHER] {
                g.capability_mut().track_topology(n, true, 0);
            }
            let mut packed = [0u8; 16];
            write_packed_header(&mut packed, 1, true);
            let (h, _) = decode_packed_neighbors(&packed, 8).unwrap();
            let nb = |id: u32| PackedNeighbor {
                node_id: id,
                rssi: -70,
                snr: 8,
                signal_routing_active: true,
                hears_us: true,
                etx_variance: 0,
            };
            g.merge_topology(PEER, &h, &[nb(ME), nb(X), nb(Y), nb(Z)], true, 0, 0);
            g.merge_topology(OTHER, &h, &[nb(ME), nb(UNIQ)], true, 0, 0);
        }
        let wire = encode_wire(
            PacketHeader::from_fields(0xFFFF_FFFF, SRC, 0xB02, 0, 3, 3, false, false, 0, 0xDD),
            &[1, 2, 3, 4],
        );
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        // PEER covers four nodes to our three (OTHER's report lists us, so it counts for us).
        assert!(plan.relay.is_none(), "PEER covers more and takes slot 0");
        let tx_after = router
            .relay_tx_after(SRC, 0xB02, 0)
            .expect("our later slot");
        assert!(router.poll_ready_relay(tx_after).is_some());
        router.record_tx_on_air(0xB02, tx_after);
        assert!(
            router.graph_mut().is_committed_relay(SRC, 0xB02),
            "relay outlives release"
        );

        // PEER's copy: it does not reach UNIQ, so our queued frame stays.
        let mut cancels = heapless::Vec::new();
        let copy = encode_wire(
            PacketHeader::from_fields(0xFFFF_FFFF, SRC, 0xB02, 0, 2, 3, false, false, 0, 0x11),
            &[1, 2, 3, 4],
        );
        let dupe = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &copy,
                },
                tx_after + 10,
            )
            .unwrap();
        assert!(dupe.duplicate);
        router.take_tx_cancels(&mut cancels);
        assert!(cancels.is_empty(), "UNIQ is still uncovered");
        assert!(router.graph_mut().is_committed_relay(SRC, 0xB02));

        // OTHER's copy reaches UNIQ: now everyone is covered and the frame is pulled back.
        let copy2 = encode_wire(
            PacketHeader::from_fields(0xFFFF_FFFF, SRC, 0xB02, 0, 2, 3, false, false, 0, 0x99),
            &[1, 2, 3, 4],
        );
        let _ = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &copy2,
                },
                tx_after + 20,
            )
            .unwrap();
        router.take_tx_cancels(&mut cancels);
        assert_eq!(cancels.as_slice(), &[0xB02]);
        assert!(!router.graph_mut().is_committed_relay(SRC, 0xB02));
    }

    #[test]
    fn tx_done_ends_the_committed_relay() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire(3, 3, 0, 0xDD, 0x902);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let _ = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        let tx_after = router
            .relay_tx_after(UNI_SOURCE, 0x902, 0)
            .expect("later slot");
        assert!(router.poll_ready_relay(tx_after).is_some());
        assert!(router.graph_mut().is_committed_relay(UNI_SOURCE, 0x902));
        router.note_tx_done(0x902);
        assert!(!router.graph_mut().is_committed_relay(UNI_SOURCE, 0x902));
        assert!(!router.graph_mut().has_active_relay_commits());
    }

    /// The destination answered the source while our relay of the request sat in the radio
    /// queue: the frame must be reported for removal, not just the retries stopped.
    #[test]
    fn reply_heard_pulls_the_queued_relay() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x605, true);
        let (_, released_at) = forward_unicast(router, &wire, 0);
        router.record_tx_on_air(0x605, released_at);
        let mut cancels = heapless::Vec::new();
        router.take_tx_cancels(&mut cancels);
        assert!(cancels.is_empty());
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let (len, ack) = build_ack_nak_frame(
            UNI_SOURCE,
            UNI_DEST,
            0x7005,
            0x605,
            router.channel_hash(),
            3,
            ROUTING_ERROR_NONE,
            &key,
            false,
            0,
        )
        .unwrap();
        let _ = router.process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 8,
                bytes: &ack[..len as usize],
            },
            released_at + 20,
        );
        router.take_tx_cancels(&mut cancels);
        assert_eq!(cancels.as_slice(), &[0x605]);
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::UnicastReplyCancel { id: 0x605 })));
    }

    /// Graph where SRC and DST are both our direct neighbours and SRC's topology says DST hears
    /// it. Unicasts SRC -> DST heard straight from SRC reach DST without us.
    fn setup_source_reaches_destination(router: &mut Router) {
        const SRC: u32 = 0xDD00_00DD;
        const DST: u32 = 0xEE00_00EE;
        let g = router.graph_mut();
        for n in [SRC, DST] {
            g.observe_direct_neighbor(n, -70, 8, 0, 0);
            g.confirm_direct_neighbor_hears_us(n);
            g.capability_mut().track_topology(n, true, 0);
        }
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let nb = |id: u32| PackedNeighbor {
            node_id: id,
            rssi: -70,
            snr: 8,
            signal_routing_active: true,
            hears_us: true,
            etx_variance: 0,
        };
        g.merge_topology(SRC, &header, &[nb(DST), nb(UNI_ME)], true, 0, 0);
    }

    #[test]
    fn unicast_to_a_neighbour_the_source_reaches_waits_for_its_ack() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_source_reaches_destination(router);
        // Heard straight from SRC (relay byte 0xDD), addressed to DST.
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x606, true);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        assert!(plan.relay.is_none(), "must not relay at once");
        let tx_after = router
            .relay_tx_after(UNI_SOURCE, 0x606, 0)
            .expect("held relay");
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        let wait = logs
            .iter()
            .find_map(|e| match e {
                SrLogEvent::UnicastDestHeardDirect { id: 0x606, wait_ms } => Some(*wait_ms),
                _ => None,
            })
            .expect("ack wait logged");
        assert!(wait >= coordinated_relay::DEFAULT_SLOT_MS);
        // commit_relay adds a deterministic tie-break of up to half a slot either way.
        let jitter = half_airtime_ms(coordinated_relay::DEFAULT_SLOT_MS).max(50) / 2;
        assert!(
            tx_after + jitter >= wait,
            "tx_after {tx_after} < ack wait {wait}"
        );

        // DST acks SRC: the held relay is cancelled and nothing goes out.
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let (len, ack) = build_ack_nak_frame(
            UNI_SOURCE,
            UNI_DEST,
            0x7006,
            0x606,
            router.channel_hash(),
            3,
            ROUTING_ERROR_NONE,
            &key,
            false,
            0,
        )
        .unwrap();
        let _ = router.process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 8,
                bytes: &ack[..len as usize],
            },
            100,
        );
        assert!(router.relay_tx_after(UNI_SOURCE, 0x606, 0).is_none());
        assert!(router.poll_ready_relay(tx_after + 1).is_none());
    }

    #[test]
    fn routing_ack_toward_a_node_the_sender_heard_is_not_relayed() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_source_reaches_destination(router);
        // SRC acks DST for some earlier packet; SRC lists DST as a neighbour it hears.
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let (len, ack) = build_ack_nak_frame(
            UNI_DEST,
            UNI_SOURCE,
            0x7007,
            0x1234,
            router.channel_hash(),
            3,
            ROUTING_ERROR_NONE,
            &key,
            false,
            0,
        )
        .unwrap();
        let (scheduled, reason) = unicast_skip_reason(router, &ack[..len as usize]);
        assert!(!scheduled);
        assert_eq!(reason, Some(SrSkipReason::ReplyRetracesLink));
    }

    /// Field case of 2026-09-03: the relayer that actually reaches the destination must own
    /// slot 0 even when our node id is lower; we follow only after its relay would have
    /// cleared the air, and stand down when its copy arrives.
    #[test]
    fn undesignated_unicast_defers_to_the_neighbour_that_reaches_the_destination() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire(3, 3, 0, 0xDD, 0x701);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        assert!(
            plan.relay.is_none(),
            "RELAYER holds slot 0, we must not key up first"
        );
        let tx_after = router
            .relay_tx_after(UNI_SOURCE, 0x701, 0)
            .expect("we hold a later slot");
        let leader_wait = coordinated_relay::DEFAULT_SLOT_MS
            + coordinated_relay::tx_delay_ms_contention_max_at(0.0, router.cw_slot_ms());
        let half = half_airtime_ms(coordinated_relay::DEFAULT_SLOT_MS).max(50);
        assert!(
            tx_after + half / 2 >= leader_wait,
            "tx_after {tx_after} fires before the leader's relay clears ({leader_wait})"
        );
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::SlotScheduling { id: 0x701, slot_index: 1, ranked, ranked_len: 2, reason: crate::broadcast_relay::RelayReason::UnicastCost, .. }
                if ranked[0] == UNI_RELAYER && ranked[1] == UNI_ME
        )), "slot log: {logs:?}");

        // RELAYER's copy (relay byte 0xBB, one hop used) cancels our pending relay.
        let copy = unicast_wire(2, 3, 0, 0xBB, 0x701);
        let dupe = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &copy,
                },
                100,
            )
            .unwrap();
        assert!(dupe.duplicate);
        assert!(router.relay_tx_after(UNI_SOURCE, 0x701, 0).is_none());
    }

    #[test]
    fn undesignated_unicast_slot_zero_waits_for_peer_turnaround() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_DEST, -70, 8, 0, 0);
        router
            .graph_mut()
            .confirm_direct_neighbor_hears_us(UNI_DEST);
        router
            .graph_mut()
            .capability_mut()
            .track_topology(UNI_DEST, true, 0);
        // No named next hop: we are the sole cost-ranked candidate (direct to DEST).
        let wire = unicast_wire(3, 3, 0, 0xDD, 0x702);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        let origin = crate::channel_access::SLOT_ORIGIN_MS;
        let tx_after = plan
            .relay
            .map(|r| r.delay_ms)
            .or_else(|| router.relay_tx_after(UNI_SOURCE, 0x702, 0))
            .expect("slot 0 planned");
        assert!(
            tx_after >= origin,
            "undesignated slot 0 must wait peer turnaround: {tx_after} < {origin}"
        );
        assert!(
            router.poll_ready_relay(origin.saturating_sub(1)).is_none(),
            "must not release inside the turnaround"
        );
        assert!(
            router
                .poll_ready_relay(origin + coordinated_relay::DEFAULT_SLOT_MS)
                .is_some(),
            "slot 0 ready at origin"
        );
    }

    #[test]
    fn unicast_designated_sr_peer_uses_half_airtime_slot() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        // RELAYER (byte 0xBB) is a known SR-active direct neighbour and the designated next hop.
        router
            .graph_mut()
            .capability_mut()
            .track_topology(UNI_RELAYER, true, 0);
        let wire = unicast_wire(3, 3, 0xBB, 0xDD, 0x505);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let _ = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        let designated = logs.iter().find_map(|e| match e {
            SrLogEvent::UnicastDesignated {
                sr_active,
                slot_delay_ms,
                ..
            } => Some((*sr_active, *slot_delay_ms)),
            _ => None,
        });
        let (sr_active, delay) = designated.expect("designated plan logged");
        assert!(sr_active);
        let stock_wait = coordinated_relay::tx_delay_ms_worst(coordinated_relay::DEFAULT_SLOT_MS);
        assert!(
            delay < stock_wait,
            "SR peer slot-0 wait {delay} should be far below stock {stock_wait}"
        );
        // ...but not shorter than the peer's own queue delay plus one airtime.
        let min_wait = coordinated_relay::DEFAULT_SLOT_MS
            + coordinated_relay::tx_delay_ms_contention_max_at(
                0.0,
                coordinated_relay::DEFAULT_SLOT_MS,
            );
        assert!(
            delay >= min_wait,
            "SR peer slot-0 wait {delay} below {min_wait}"
        );
    }

    #[test]
    fn unicast_last_hop_needs_direct_link_to_target() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        // Heard directly from SOURCE with one hop left: relaying would leave hop_limit 0 and
        // DEST is not our direct neighbour.
        let wire = unicast_wire(1, 1, 0, 0xDD, 0x503);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(!scheduled);
        assert_eq!(reason, Some(SrSkipReason::DeadEndHop));
    }

    #[test]
    fn unicast_last_hop_relayed_when_target_is_direct_neighbour() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_DEST, -75, 6, 0, 0);
        let wire = unicast_wire(1, 1, 0, 0xDD, 0x504);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(
            scheduled,
            "hop_limit 0 is fine when the next hop is the destination"
        );
        assert_eq!(reason, None);
    }

    #[test]
    fn packets_addressed_to_us_bypass_rate_limit() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(LAST_HOP_ME));
        // Undecodable payload lands in the OTHER bucket (4 per window).
        for id in 1..=8u32 {
            let header = PacketHeader::from_fields(
                LAST_HOP_ME,
                LAST_HOP_SOURCE,
                id,
                0,
                3,
                3,
                false,
                false,
                0,
                0,
            );
            let wire = encode_wire(header, &[0xDE, 0xAD]);
            let result = router
                .process_inbound(
                    &InboundPacket {
                        radio_id: 0,
                        rssi: -80,
                        snr: 8,
                        bytes: &wire,
                    },
                    0,
                )
                .unwrap();
            assert!(
                !result.rate_limited,
                "packet {id} addressed to us must not be rate limited"
            );
        }
        // Control: the same burst addressed elsewhere is throttled by the same bucket
        // (undecodable frames count against UNKNOWN, 12 per window).
        let mut limited = false;
        for id in 100..=115u32 {
            let header = PacketHeader::from_fields(
                0xDD00_00DD,
                LAST_HOP_SOURCE,
                id,
                0,
                3,
                3,
                false,
                false,
                0,
                0,
            );
            let wire = encode_wire(header, &[0xDE, 0xAD]);
            let result = router
                .process_inbound(
                    &InboundPacket {
                        radio_id: 0,
                        rssi: -80,
                        snr: 8,
                        bytes: &wire,
                    },
                    0,
                )
                .unwrap();
            limited |= result.rate_limited;
            // Release the pool slot as the radio task would.
            let _ = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        }
        assert!(
            limited,
            "rate limiter must still apply to traffic not addressed to us"
        );
    }

    #[test]
    fn last_hop_broadcast_allowed_when_downstream_gateway() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(LAST_HOP_ME));
        router.graph_mut().downstream_mut().update(
            LAST_HOP_ME,
            LAST_HOP_SOURCE,
            LAST_HOP_ME,
            100.0,
            0,
            false,
            0,
        );

        let wire = last_hop_broadcast_wire(LAST_HOP_SOURCE, LAST_HOP_GATEWAY, 1, 3, 43);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -80,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        // `u32::MAX` looks "before" a small tx_after under wrapping subtract; poll at due time.
        let ready = plan.relay.is_some()
            || router
                .relay_tx_after(LAST_HOP_SOURCE, 43, 0)
                .and_then(|tx| router.poll_ready_relay(tx))
                .is_some();
        assert!(ready);
    }

    #[test]
    fn last_hop_guard_does_not_apply_when_hop_budget_remains() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(LAST_HOP_ME));
        router.graph_mut().downstream_mut().update(
            LAST_HOP_ME,
            LAST_HOP_SOURCE,
            LAST_HOP_GATEWAY,
            100.0,
            0,
            false,
            0,
        );

        let wire = last_hop_broadcast_wire(LAST_HOP_SOURCE, LAST_HOP_GATEWAY, 2, 3, 44);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -80,
                    snr: 8,
                    bytes: &wire,
                },
                0,
            )
            .unwrap();
        let plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        let ready = plan.relay.is_some()
            || router
                .relay_tx_after(LAST_HOP_SOURCE, 44, 0)
                .and_then(|tx| router.poll_ready_relay(tx))
                .is_some();
        assert!(ready);
    }
}
