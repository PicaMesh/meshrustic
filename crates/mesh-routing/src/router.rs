use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::{
    is_direct_packet, num::TEXT_MESSAGE_APP, PacketHeader, ParsedPacket, NODENUM_BROADCAST,
    PACKET_HEADER_LEN,
};
use mesh_radio::{
    eu868_config_for_preset, packet_time_ms, primary_channel_hash, MODEM_DEFAULT_PRESET,
};

#[cfg(feature = "pki")]
use crate::admin::ROUTING_ERROR_PKI_UNKNOWN_PUBKEY;
use crate::admin::{
    encode_admin_response, encode_owner_response, handle_admin, AdminState,
    ROUTING_ERROR_ADMIN_PUBLIC_KEY_UNAUTHORIZED, ROUTING_ERROR_PKI_FAILED,
};
use crate::admin_codec::{AdminPayload, ADMIN_APP};
use crate::coordinated_relay::{
    half_airtime_ms, slot_time_for_preset, tx_delay_ms_contention, tx_delay_ms_worst,
};
use crate::enter_dfu::{payload_is_enter_dfu, DFU_CONFIRM_TEXT, DFU_ENTER_DELAY_SECS};
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
use crate::position::{build_fixed_position_wire_frame, position_broadcast_interval_ms};
use crate::qos::ChannelQoS;
use crate::rate_limit::NodeRateLimiter;
use crate::relay::{copy_opaque_payload, relay_header_with_next_hop_opts, wire_may_relay};
use crate::relay_identity::RelayIdentityCache;
use crate::reliable::{
    bump_reliable_delays, due_retransmit, named_followup, schedule_reliable, stop_reliable_for,
    NamedFollowup, PendingReliable, MAX_PENDING_RELIABLE, NAMED_FOLLOWUP_TRIES,
};
use crate::routing_ack::{
    build_ack_nak_frame, decode_routing_payload, encode_routing_error, hop_limit_for_response,
    hops_away, retransmission_delay_ms, NUM_RELIABLE_RETX, ROUTING_APP, ROUTING_ERROR_NONE,
    ROUTING_ERROR_NO_CHANNEL, ROUTING_ERROR_NO_ROUTE,
};
use crate::rx_decode::{summarize_decrypted, RxDecodeInfo};
use crate::sr_log::{
    RelayRetxCancelReason, SrLog, SrLogEvent, SrSkipReason, T1CancelReason, MAX_SR_LOG,
};
use crate::telemetry::{
    build_device_telemetry_wire_frame, device_telemetry_interval_ms, DeviceMetricsSnapshot,
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
    let len = key.len();
    &key.bytes[..len]
}

pub struct InboundPacket<'a> {
    pub radio_id: u8,
    pub rssi: i16,
    pub snr: i8,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct ProcessResult {
    pub parsed: ParsedPacket,
    pub duplicate: bool,
    pub rate_limited: bool,
    pub dest_rate_limited: bool,
    pub handle: Option<PacketHandle>,
    pub radio_id: u8,
    pub rssi: i16,
    pub snr: i8,
    pub decoded_portnum: Option<u32>,
    pub decode: RxDecodeInfo,
    pub decoded_data: Option<DecodedData>,
}

#[derive(Clone, Copy)]
pub struct RelayPlan {
    pub len: u8,
    pub bytes: [u8; MAX_WIRE_LEN],
    pub delay_ms: u32,
}

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
    unicast_flags: crate::unicast_relay::UnicastSlotFlags,
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
    fired: bool,
    from: u32,
    resolved_relay: Option<u32>,
    packet_id: u32,
    fire_after_ms: u32,
    decoded_portnum: Option<u32>,
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

pub const BOOTSTRAP_REPLY_MIN_MS: u32 = 120_000;

pub struct Router {
    node_num: u32,
    pool: PacketPool,
    history: PacketHistory,
    rate_limit: NodeRateLimiter,
    pending_young_announce: Option<crate::rate_limit::YoungAnnounce>,
    relay_identity: RelayIdentityCache,
    qos: ChannelQoS,
    graph: NeighborGraph,
    pending: [PendingRelay; MAX_PENDING_RELAYS],
    pending_topology: PendingTopology,
    pending_topology_reply_ms: u32,
    pending_nodeinfo: PendingNodeInfo,
    pending_telemetry: PendingTelemetry,
    pending_position: PendingTelemetry,
    pending_traceroute: PendingTraceroute,
    pending_retransmits: [PendingRetransmit; MAX_PENDING_RETRANSMITS],
    pending_reliable: [PendingReliable; MAX_PENDING_RELIABLE],
    channel_util_pct: f32,
    pending_ack: PendingAck,
    pending_dfu_confirm: PendingAck,
    pending_admin: [PendingAdmin; MAX_PENDING_ADMIN],
    tx_cancels: heapless::Vec<(u32, u32), 8>,
    /// Bootstrap reply throttling prevents simultaneous restarts from making every node flood the
    /// channel.
    last_bootstrap_reply_ms: Option<u32>,
    nodeinfo_identity: NodeInfoIdentity,
    nodeinfo_cache: NodeInfoCache,
    last_nodeinfo_ms: Option<u32>,
    last_nodeinfo_reply_to: u32,
    last_nodeinfo_reply_ms: u32,
    last_telemetry_ms: Option<u32>,
    last_position_ms: Option<u32>,
    device_metrics: DeviceMetricsSnapshot,
    channel_key: CryptoKey,
    channel_hash: u8,
    modem_preset: u8,
    operating_preset: u8,
    use_preset: bool,
    hop_limit: u8,
    next_tx_id: u32,
    sr_log: SrLog,
    bridge_dedup: crate::bridge::BridgeDedupCache,
    admin: AdminState,
    admin_reply_remote_pk: Option<[u8; 32]>,
    admin_reply_use_pki: bool,
    pending_pki_error: Option<u32>,
    module_reply_suppresses_ack: bool,
    pending_radio_reinit: bool,
    designated_repeat_id: Option<(u32, u32)>,
    pending_ota_dfu_seconds: Option<i32>,
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

    /// Static initialization avoids constructing the large routing graph on the constrained firmware
    /// stack.
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
            pending_young_announce: None,
            relay_identity: RelayIdentityCache::new(),
            qos: ChannelQoS::with_primary_channel(channel_hash),
            graph,
            pending: [PendingRelay {
                active: false,
                from: 0,
                id: 0,
                _radio_id: 0,
                tx_after_ms: 0,
                len: 0,
                bytes: [0; MAX_WIRE_LEN],
                unicast_flags: crate::unicast_relay::UnicastSlotFlags::EMPTY,
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
            pending_position: PendingTelemetry {
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
                from: 0,
                resolved_relay: None,
                packet_id: 0,
                fire_after_ms: 0,
                decoded_portnum: None,
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
            pending_dfu_confirm: PendingAck {
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
            tx_cancels: heapless::Vec::new(),
            last_bootstrap_reply_ms: None,
            nodeinfo_identity: NodeInfoIdentity::unconfigured(),
            nodeinfo_cache: NodeInfoCache::new(),
            last_nodeinfo_ms: None,
            last_nodeinfo_reply_to: 0,
            last_nodeinfo_reply_ms: 0,
            last_telemetry_ms: None,
            last_position_ms: None,
            device_metrics: DeviceMetricsSnapshot::EMPTY,
            channel_key,
            channel_hash,
            modem_preset,
            operating_preset: modem_preset,
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
            pending_ota_dfu_seconds: None,
        }
    }

    #[doc(hidden)]
    pub fn graph_mut(&mut self) -> &mut NeighborGraph {
        &mut self.graph
    }

    pub fn set_node_identity(&mut self, identity: NodeInfoIdentity) {
        let role = self.graph.device_role();
        self.nodeinfo_identity = identity;
        self.nodeinfo_identity.advert.role = role;
        self.admin.public_key = self.nodeinfo_identity.public_key;
    }

    pub fn load_node_config(&mut self, cfg: &mesh_store::NodeConfig) {
        self.node_num = cfg.node_num;
        self.graph.set_my_node(cfg.node_num);
        self.rate_limit.set_node_num(cfg.node_num);
        self.admin.import_node_config(cfg);
        self.nodeinfo_identity = NodeInfoIdentity::for_node(cfg.node_num, cfg.public_key);
        self.set_device_role(u32::from(cfg.device_role));
        self.set_modem_preset(
            "",
            cfg.lora.modem_preset,
            cfg.lora.use_preset,
            cfg.channel_key,
        );
        self.operating_preset = self.modem_preset;
        self.hop_limit = cfg.lora.hop_limit;
    }

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

    pub fn take_pending_ota_dfu_seconds(&mut self) -> Option<i32> {
        self.pending_ota_dfu_seconds.take()
    }

    /// A software reset would enter the UF2 bootloader rather than simply apply radio settings.
    pub fn radio_config(&self) -> mesh_radio::RadioConfig {
        let mut config = mesh_radio::eu868_config_for_preset(self.modem_preset);
        config.hop_limit = self.hop_limit;
        config.tx_power_dbm = self.admin.tx_power_dbm.min(22) as i8;
        config
    }

    pub fn has_pending_control_tx(&self) -> bool {
        self.pending_ack.active
            || self.pending_dfu_confirm.active
            || self.pending_admin.iter().any(|slot| slot.active)
    }

    pub fn take_pending_radio_reinit(&mut self) -> bool {
        core::mem::take(&mut self.pending_radio_reinit)
    }

    pub fn take_young_announce(&mut self) -> Option<crate::rate_limit::YoungAnnounce> {
        self.pending_young_announce.take()
    }

    pub fn set_young_announce_broadcast(&mut self, enabled: bool) {
        self.rate_limit.set_announce_broadcast(enabled);
    }

    pub fn young_announce_broadcast(&self) -> bool {
        self.rate_limit.announce_broadcast()
    }

    /// Links learned on the previous RF parameters cannot establish connectivity on the new preset.
    pub fn radio_reconfigured(&mut self, now_ms: u32, slot_ms: u32) {
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
        if self.pending_traceroute.active {
            self.pending_traceroute.active = false;
            dropped += 1;
        }
        self.pending_topology_reply_ms = 0;
        dropped += self.graph.clear_relays();
        if self.modem_preset != self.operating_preset {
            if self.pending_topology.active {
                self.pending_topology.active = false;
                dropped += 1;
            }
            self.graph.purge_for_preset_change();
            self.relay_identity.clear();
            self.last_nodeinfo_ms = None;
            self.operating_preset = self.modem_preset;
            self.ensure_boot_broadcasts(now_ms, slot_ms);
        }
        self.sr_log.push(SrLogEvent::RadioReconfigured {
            dropped: dropped.min(u8::MAX as usize) as u8,
        });
    }

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

    #[cfg(any(test, feature = "std"))]
    pub fn set_builtin_admin_public_keys_for_test(&mut self, keys: [[u8; 32]; 2]) {
        self.admin.set_builtin_admin_public_keys_for_test(keys);
    }

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

    pub fn update_device_metrics(&mut self, metrics: DeviceMetricsSnapshot) {
        self.device_metrics = metrics;
    }

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
        self.qos = ChannelQoS::with_primary_channel(self.channel_hash);
    }

    pub fn channel_hash(&self) -> u8 {
        self.channel_hash
    }

    pub fn device_role(&self) -> u32 {
        self.graph.device_role()
    }

    pub fn route_to(&mut self, destination: u32, now_ms: u32) -> crate::graph::Route {
        self.graph.route_to(destination, now_ms)
    }

    pub fn edge_heard_on(&self, peer: u32) -> u8 {
        self.graph.edge_heard_on(peer)
    }

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

    pub fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    fn cw_slot_ms(&self) -> u32 {
        slot_time_for_preset(self.modem_preset)
    }

    pub fn record_tx_on_air(&mut self, from: u32, packet_id: u32, now_ms: u32) {
        if packet_id != 0 {
            self.graph.record_our_transmission(from, packet_id, now_ms);
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
            && !self.graph.has_sent_topology()
            && !self.pending_topology.active
            && self.schedule_topology_broadcast(now_ms, slot_ms, false)
        {
            self.graph.commit_topology_broadcast(now_ms, false);
        }
        if self.last_nodeinfo_ms.is_none() && !self.pending_nodeinfo.active {
            self.schedule_nodeinfo_broadcast(now_ms);
        }
    }

    pub fn set_device_role(&mut self, role: u32) {
        let role = crate::nodeinfo::sanitize_device_role(role);
        self.graph.set_device_role(role);
        self.nodeinfo_identity.advert.role = role;
        self.admin.device_role = role;
        if self.admin.coerce_position_interval() {
            self.admin.config_dirty = true;
        }
    }

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

    pub fn process_inbound(
        &mut self,
        packet: &InboundPacket<'_>,
        now_ms: u32,
    ) -> Option<ProcessResult> {
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
                        dest_rate_limited: false,
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
                let our_byte = (self.node_num & 0xFF) as u8;
                let designated_repeat = parsed.to != NODENUM_BROADCAST
                    && parsed.to != self.node_num
                    && parsed.from != self.node_num
                    && parsed.next_hop == our_byte
                    && parsed.hop_limit > 0
                    && self.graph.is_active_routing_role()
                    && !self
                        .graph
                        .has_our_transmission(parsed.from, parsed.id, now_ms);
                let originator_retry = parsed.to != NODENUM_BROADCAST
                    && parsed.to != self.node_num
                    && parsed.from != self.node_num
                    && is_direct_packet(
                        parsed.from,
                        parsed.hop_start,
                        parsed.hop_limit,
                        parsed.relay_node,
                    )
                    && (parsed.next_hop == 0 || parsed.next_hop == our_byte)
                    && parsed.hop_limit > 0
                    && !self
                        .graph
                        .has_our_transmission(parsed.from, parsed.id, now_ms)
                    && !self.has_pending_relay(parsed.from, parsed.id)
                    && !self.graph.is_committed_relay(parsed.from, parsed.id);
                if designated_repeat || originator_retry {
                    self.cancel_pending(parsed.from, parsed.id);
                    self.graph.cancel_relay(parsed.from, parsed.id);
                    self.cancel_relayed_retx(
                        parsed.from,
                        parsed.id,
                        RelayRetxCancelReason::CopyHeard,
                    );
                    if designated_repeat {
                        self.designated_repeat_id = Some((parsed.from, parsed.id));
                    }
                    if originator_retry {
                        self.sr_log
                            .push(SrLogEvent::OriginatorRetryReplanned { id: parsed.id });
                    }
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
                        dest_rate_limited: false,
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

        let decoded_portnum = decode.portnum;
        let rebroadcast_candidate = parsed.to != self.node_num
            && parsed.from != self.node_num
            && parsed.hop_limit > 0
            && self.graph.is_rebroadcaster();
        let resolved_relay = if direct {
            (parsed.from != 0 && parsed.from != self.node_num).then_some(parsed.from)
        } else {
            known_relay.filter(|&id| {
                id != 0 && !crate::graph::is_placeholder_node(id) && id != self.node_num
            })
        };
        let payload_air_len = packet.bytes.len().saturating_sub(PACKET_HEADER_LEN);
        let air_cfg = mesh_radio::eu868_config_for_preset(self.operating_preset);
        let airtime_ms = mesh_radio::packet_time_ms(&air_cfg, payload_air_len, true).max(1);
        let on_default_channel = parsed.channel == self.channel_hash
            && psk_bytes(&self.channel_key) == DEFAULT_PSK.as_slice();
        let rl_pkt = crate::rate_limit::RateLimitPacket {
            from: parsed.from,
            to: parsed.to,
            decoded_portnum,
            now_ms,
            rebroadcast_candidate,
            resolved_relay,
            airtime_ms,
            channel_util_pct: self.channel_util_pct,
            graph_established: self.graph.neighbor_count() > 0,
            on_default_channel,
        };
        let rate_limited = {
            let graph = &mut self.graph;
            self.rate_limit
                .should_drop(&rl_pkt, |nid| crate::rate_limit::GraphProximity {
                    in_graph: graph.rate_limit_node_in_graph(nid),
                    hops: graph.rate_limit_graph_hops(nid, now_ms),
                })
        };
        self.graph
            .set_dropped_coverage(self.rate_limit.coverage_gate(now_ms));
        let mut dest_rate_limited = false;
        if let Some(ev) = self.rate_limit.take_event() {
            match ev {
                crate::rate_limit::RateLimitEvent::Trip { node_id, kind } => {
                    if kind == crate::rate_limit::RateLimitKind::Dest {
                        dest_rate_limited = true;
                    }
                    self.sr_log.push(SrLogEvent::RateLimitTrip {
                        node_id,
                        kind: kind.as_u8(),
                    });
                }
                crate::rate_limit::RateLimitEvent::Clear { node_id, kind } => {
                    self.sr_log.push(SrLogEvent::RateLimitClear {
                        node_id,
                        kind: kind.as_u8(),
                    });
                }
                crate::rate_limit::RateLimitEvent::DestDrop { node_id } => {
                    dest_rate_limited = true;
                    self.sr_log.push(SrLogEvent::RateLimitDestDrop {
                        from: parsed.from,
                        to: node_id,
                    });
                }
            }
        }
        if let Some(ann) = self.rate_limit.take_announce() {
            self.sr_log.push(SrLogEvent::RateLimitYoungAnnounce {
                ids: ann.ids,
                count: ann.count,
            });
            self.pending_young_announce = Some(ann);
        }
        if rate_limited {
            // Discarding our link measurement would eventually turn a limited neighbour into an
            // apparently unserved node and manufacture extra relays.
            if direct && !parsed.via_mqtt {
                self.graph.observe_direct_neighbor(
                    parsed.from,
                    packet.rssi,
                    packet.snr,
                    now_ms,
                    packet.radio_id,
                );
            }
            if !dest_rate_limited {
                self.sr_log.push(SrLogEvent::RelaySkip {
                    from: parsed.from,
                    reason: SrSkipReason::RateLimited,
                });
            }
            return Some(ProcessResult {
                parsed,
                duplicate: false,
                rate_limited: true,
                dest_rate_limited,
                handle: None,
                radio_id: packet.radio_id,
                rssi: packet.rssi,
                snr: packet.snr,
                decoded_portnum,
                decode,
                decoded_data,
            });
        }

        self.observe_inbound_graph(&parsed, packet, now_ms, known_relay);

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

        if let Some(data) = decoded_data.as_ref() {
            self.maybe_cancel_relay_for_foreign_ack(&parsed, data, now_ms);
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
            } else if data.portnum == TEXT_MESSAGE_APP && parsed.to == self.node_num {
                if let Some(ref inner) = inner {
                    self.maybe_arm_ota_dfu(&parsed, inner, data.has_bitfield, now_ms);
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
            dest_rate_limited: false,
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

    fn maybe_arm_ota_dfu(
        &mut self,
        parsed: &ParsedPacket,
        text: &[u8],
        hop_start_known: bool,
        now_ms: u32,
    ) {
        if !self.admin_reply_use_pki {
            return;
        }
        let Some(pk) = self.admin_reply_remote_pk else {
            return;
        };
        if !self.admin.is_authorized(&pk) {
            return;
        }
        if !is_direct_packet(
            parsed.from,
            parsed.hop_start,
            parsed.hop_limit,
            parsed.relay_node,
        ) {
            return;
        }
        if !payload_is_enter_dfu(text) {
            return;
        }
        let _ = self.queue_dfu_confirm(parsed, hop_start_known, now_ms);
        self.pending_ota_dfu_seconds = Some(DFU_ENTER_DELAY_SECS);
    }

    fn queue_dfu_confirm(
        &mut self,
        parsed: &ParsedPacket,
        hop_start_known: bool,
        now_ms: u32,
    ) -> bool {
        let Some(remote_pk) = self.admin_reply_remote_pk else {
            return false;
        };
        let (hop, next_hop) = self.response_header(parsed, hop_start_known);
        let id = self.alloc_tx_id();
        let opts = DataEncodeOpts {
            want_response: false,
            request_id: parsed.id,
            bitfield: self.ours(),
            ..Default::default()
        };
        let Some((len, bytes)) = self.build_pki_app_frame(
            parsed.from,
            id,
            hop,
            TEXT_MESSAGE_APP,
            DFU_CONFIRM_TEXT,
            opts,
            &remote_pk,
            false,
            next_hop,
        ) else {
            return false;
        };
        self.pending_dfu_confirm = PendingAck {
            active: true,
            next_tx_ms: now_ms,
            len,
            bytes,
        };
        true
    }

    fn process_admin_rx(
        &mut self,
        parsed: &ParsedPacket,
        payload: &[u8],
        hop_start_known: bool,
        now_ms: u32,
    ) {
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
            self.hop_limit = self.admin.hop_limit;
            self.set_modem_preset("", preset, true, self.channel_key);
            self.pending_radio_reinit = true;
        }
        if let Some(role) = outcome.apply_device_role {
            self.set_device_role(role);
            self.last_nodeinfo_ms = None;
        }
        if !self.admin.broadcasts_fixed_position() {
            self.pending_position.active = false;
        } else if outcome.broadcast_position {
            self.schedule_position_broadcast(now_ms);
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
        let id = self.alloc_tx_id();
        let routing = encode_routing_error(error);
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
        let id = self.alloc_tx_id();
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
        self.module_reply_suppresses_ack = true;
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
                    NUM_RELIABLE_RETX,
                    None,
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
                return;
            }
        }
        let mut oldest = 0usize;
        for i in 1..MAX_PENDING_ADMIN {
            let a = self.pending_admin[i].next_tx_ms;
            let b = self.pending_admin[oldest].next_tx_ms;
            if now_ms.wrapping_sub(a) > now_ms.wrapping_sub(b) {
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
            if plaintext.is_empty() || plaintext.len() + 12 > MAX_PACKET_PAYLOAD {
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
                0,
                hop_limit,
                hop_limit,
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
        if parsed.from == 0
            || parsed.from == self.node_num
            || parsed.via_mqtt
            || crate::graph::is_placeholder_node(parsed.from)
        {
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
                    more_chunks: header.more_chunks,
                    continuation: header.continuation,
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
        for n in neighbor_list.iter() {
            self.sr_log.push(SrLogEvent::TopologyListedNeighbor {
                from: parsed.from,
                node_id: n.node_id,
                rssi: n.rssi,
                snr: n.snr,
                hears_us: n.hears_us,
                sr_active: n.signal_routing_active,
                etx_variance: n.etx_variance,
            });
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
        let last_list_ms = self.graph.last_topology_list_ms();
        if last_list_ms
            .is_some_and(|last| (1..0x8000_0000).contains(&last.wrapping_sub(requested_ms)))
        {
            self.sr_log.push(SrLogEvent::BootstrapReplyAlreadyAnswered);
            return;
        }
        if self
            .last_bootstrap_reply_ms
            .is_some_and(|last| now_ms.wrapping_sub(last) < BOOTSTRAP_REPLY_MIN_MS)
        {
            self.sr_log.push(SrLogEvent::BootstrapReplyRateLimited);
            return;
        }
        if self.schedule_topology_broadcast(now_ms, slot_ms, false) {
            self.graph.commit_topology_broadcast(now_ms, false);
            self.last_bootstrap_reply_ms = Some(now_ms);
        }
    }

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

        if self
            .graph
            .has_our_transmission(parsed.from, parsed.id, now_ms)
        {
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
        let broadcast_candidate = parsed.to == NODENUM_BROADCAST
            && self.graph.signal_routing_active()
            && parsed.from != self.node_num;
        // When coverage evidence is insufficient, delivery takes precedence over saving airtime.
        if broadcast_candidate && !self.graph.topology_healthy_for_broadcast() {
            let direct_neighbors = self.graph.neighbor_count();
            self.sr_log.push(SrLogEvent::BroadcastUnrankedThinGraph {
                from: parsed.from,
                direct_neighbors,
            });
        }
        let broadcast_plan = if broadcast_candidate && self.graph.topology_healthy_for_broadcast() {
            let ack_eligible = result.decoded_portnum
                == Some(mesh_protocol::portnum::num::TEXT_MESSAGE_APP)
                && is_direct_packet(
                    parsed.from,
                    parsed.hop_start,
                    parsed.hop_limit,
                    parsed.relay_node,
                );
            Some(self.graph.plan_broadcast_relay(
                parsed.id,
                parsed.from,
                heard_from,
                parsed.to,
                now_ms,
                half_airtime,
                ack_eligible,
            ))
        } else {
            None
        };

        if let Some(ref relay_plan) = broadcast_plan {
            if relay_plan.should_relay {
                self.graph
                    .record_node_transmission(self.node_num, parsed.from, parsed.id, now_ms);
                // Naming the coverage target makes needless relays distinguishable from useful ones in
                // captures.
                if relay_plan.coverage_for != 0 {
                    self.sr_log.push(SrLogEvent::CoverageFor {
                        neighbor: relay_plan.coverage_for,
                    });
                }
            } else {
                if relay_plan.slots_given > 0 {
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

        let mut route_verified = true;
        let picked_hop = if parsed.to != NODENUM_BROADCAST {
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
        // Naming ourselves as the next hop would make receivers wait for a forwarding copy that cannot
        // arrive.
        let mut next_hop = if picked_hop == self.node_num {
            0
        } else {
            picked_hop
        };
        let onward_hop = next_hop;

        let we_are_designated_hop =
            parsed.to != NODENUM_BROADCAST && parsed.next_hop == (self.node_num & 0xFF) as u8;

        // A sender explicitly handing us the packet will retry into the same silence; answering once
        // costs less airtime.
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
        let designated_repeat = self.designated_repeat_id.take() == Some((parsed.from, parsed.id));
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

        // Naming the previous relay would bounce the packet back towards the route that already led to
        // us.
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

        // Applying a shared floor after rank spacing would collapse adjacent rungs onto one deadline.
        let dest_ack_floor = if parsed.to != NODENUM_BROADCAST
            && heard_from == parsed.from
            && self
                .graph
                .edges()
                .find_node(parsed.from)
                .and_then(|n| n.find_edge(parsed.to))
                .is_some_and(|e| e.hears_us)
        {
            self.dest_ack_wait_ms(slot_ms)
        } else {
            0
        };

        let relayer_named = parsed.next_hop != 0 && parsed.next_hop != (parsed.to & 0xFF) as u8;
        // A permissive delivery policy for non-publishers does not prove a direct last-hop link.
        let we_can_finish = parsed.to != NODENUM_BROADCAST
            && (self.graph.caps_last_hop(parsed.to)
                || (self.graph.has_direct_edge(parsed.to)
                    && crate::graph::can_deliver(
                        self.graph.edges(),
                        Some(self.graph.capability()),
                        self.node_num,
                        parsed.to,
                    )));

        if we_are_designated_hop && picked_hop == 0 && !we_can_finish {
            self.pool.release(handle);
            self.schedule_nak(&parsed, false, ROUTING_ERROR_NO_ROUTE, now_ms);
            self.sr_log.push(SrLogEvent::RelaySkip {
                from: parsed.from,
                reason: SrSkipReason::NoRelayPath,
            });
            return plan;
        }

        let has_cost_path = we_can_finish || picked_hop != 0;
        let unicast_ranking = if parsed.to != NODENUM_BROADCAST
            && parsed.to != self.node_num
            && self.graph.signal_routing_active()
            && has_cost_path
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
                ranked.slot_delay_ms = self.unicast_slot_delay_ms(
                    &ranked,
                    dest_ack_floor,
                    half_airtime,
                    slot_ms,
                    next_hop,
                );
                Some(ranked)
            }
            _ => None,
        };
        let unicast_plan = if unicast_plan.is_none()
            && !relayer_named
            && parsed.to != NODENUM_BROADCAST
            && parsed.to != self.node_num
            && self.graph.signal_routing_active()
        {
            if self.graph.topology_healthy_for_broadcast() {
                let cover = self.graph.plan_broadcast_relay(
                    parsed.id,
                    parsed.from,
                    heard_from,
                    parsed.to,
                    now_ms,
                    half_airtime,
                    false,
                );
                let cover_carries = cover.should_relay
                    && cover.reason != crate::broadcast_relay::RelayReason::Sparse;
                if cover_carries {
                    if cover.coverage_for != 0 {
                        self.sr_log.push(SrLogEvent::CoverageFor {
                            neighbor: cover.coverage_for,
                        });
                    }
                    Some(cover)
                } else {
                    self.pool.release(handle);
                    self.log_slot_scheduling(&parsed, &cover, half_airtime);
                    self.sr_log.push(SrLogEvent::RelaySkip {
                        from: parsed.from,
                        reason: SrSkipReason::AlreadyCovered,
                    });
                    return plan;
                }
            } else {
                self.sr_log.push(SrLogEvent::BroadcastUnrankedThinGraph {
                    from: parsed.from,
                    direct_neighbors: self.graph.neighbor_count(),
                });
                Some(crate::broadcast_relay::BroadcastRelayPlan {
                    should_relay: true,
                    slot_delay_ms: crate::coordinated_relay::relay_floor_ms(self.cw_slot_ms())
                        .max(dest_ack_floor),
                    slot_index: 0,
                    candidate_count: 1,
                    reason: crate::broadcast_relay::RelayReason::Sparse,
                    ..Default::default()
                })
            }
        } else {
            unicast_plan
        };

        // A confirmed last hop can deliver even when no onward hop budget remains.
        if relayer_named && !we_are_designated_hop && !self.graph.caps_last_hop(parsed.to) {
            let stamp_byte = (next_hop & 0xFF) as u8;
            let names_designated = next_hop != 0 && stamp_byte == parsed.next_hop;
            if next_hop == 0 || names_designated {
                self.pool.release(handle);
                self.sr_log.push(SrLogEvent::RelaySkip {
                    from: parsed.from,
                    reason: SrSkipReason::NoRelayPath,
                });
                return plan;
            }
        }

        let designated_plan = if parsed.to != NODENUM_BROADCAST && relayer_named {
            Some(self.plan_designated_unicast(
                &parsed,
                heard_from,
                result.rssi,
                result.snr,
                half_airtime,
                slot_ms,
                dest_ack_floor,
                now_ms,
                unicast_ranking,
            ))
        } else {
            None
        };
        let unicast_plan = unicast_plan.or(designated_plan);

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
                    let local_measured = edge.source.is_measured()
                        && edge.etx_fixed <= crate::graph::COVERAGE_ETX_CEILING_FIXED;
                    let no_useful_onward = onward_hop == 0 || onward_hop == heard_from;
                    let dest_already_has_it =
                        edge.hears_us && self.graph.has_direct_edge(parsed.to);
                    if local_measured && (no_useful_onward || dest_already_has_it) {
                        self.pool.release(handle);
                        self.sr_log.push(SrLogEvent::RelaySkip {
                            from: parsed.from,
                            reason: SrSkipReason::ReplyRetracesLink,
                        });
                        return plan;
                    }
                }
                if edge.hears_us && unicast_plan.is_some() {
                    self.sr_log.push(SrLogEvent::UnicastDestHeardDirect {
                        id: parsed.id,
                        wait_ms: dest_ack_floor,
                    });
                }
            }
        }

        let priced_last_hop = parsed.to != NODENUM_BROADCAST
            && crate::graph::delivery_hop_cost_fixed(
                self.graph.edges(),
                Some(self.graph.capability()),
                self.node_num,
                parsed.to,
                now_ms,
                self.node_num,
            )
            .is_some();
        let intended_hop = if priced_last_hop { parsed.to } else { next_hop };
        let strong_intended = if intended_hop == 0 {
            false
        } else if priced_last_hop {
            crate::graph::has_strong_delivery_hop(
                self.graph.edges(),
                Some(self.graph.capability()),
                self.node_num,
                intended_hop,
                now_ms,
                self.node_num,
            )
        } else {
            crate::graph::has_strong_hop_to(self.graph.edges(), self.node_num, intended_hop)
        };
        let stamp_hop = if unicast_plan.as_ref().is_some_and(|p| p.nonfinal_flood) {
            0
        } else if strong_intended {
            intended_hop
        } else {
            0
        };
        let relay_hdr = match relay_header_with_next_hop_opts(
            &parsed,
            self.node_num,
            stamp_hop,
            priced_last_hop && stamp_hop != 0,
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

        // With no hop budget, an unverified target has no remaining relay path and consumes airtime
        // without delivering.
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

        let nonfinal_flood = unicast_plan.as_ref().is_some_and(|p| p.nonfinal_flood);
        let named_backup = relayer_named && !we_are_designated_hop && !nonfinal_flood;
        let unicast_flags = crate::unicast_relay::UnicastSlotFlags {
            last_hop_backup: unicast_plan.as_ref().is_some_and(|p| p.last_hop_backup),
            nonfinal_flood,
            nominated_next_hop: if nonfinal_flood { 0 } else { intended_hop },
            designated_next_hop: if named_backup { parsed.next_hop } else { 0 },
            armed_hop_limit: if named_backup { parsed.hop_limit } else { 0 },
        };
        self.graph
            .set_unicast_commit_flags(parsed.from, parsed.id, unicast_flags);

        if delay_ms == 0 {
            self.arm_relayed_unicast_followup(len, bytes, now_ms, unicast_flags, heard_from);
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
            unicast_flags,
        ) {
            return plan;
        }

        self.arm_relayed_unicast_followup(len, bytes, now_ms, unicast_flags, heard_from);
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

    // Admission may change while listen-before-talk holds a frame; rechecking must not charge it twice.
    pub fn queued_frame_allowed(&self, bytes: &[u8], now_ms: u32) -> bool {
        if bytes.len() > MAX_WIRE_LEN {
            return false;
        }
        let Ok(header) = PacketHeader::decode(bytes) else {
            return false;
        };
        let parsed = header.parse();
        if parsed.from == self.node_num {
            return true;
        }
        if !self.graph.is_rebroadcaster() {
            return false;
        }
        let mut cipher = [0; crate::pool::MAX_PACKET_PAYLOAD];
        let payload = &bytes[PACKET_HEADER_LEN..];
        cipher[..payload.len()].copy_from_slice(payload);
        let portnum = crate::topology::try_decrypt_data_full(
            &self.channel_key,
            parsed.from,
            parsed.id,
            self.channel_hash,
            parsed.channel,
            &mut cipher[..payload.len()],
        )
        .map(|(data, _)| data.portnum);
        let packet = crate::rate_limit::RateLimitPacket {
            from: parsed.from,
            to: parsed.to,
            decoded_portnum: portnum,
            now_ms,
            rebroadcast_candidate: true,
            resolved_relay: self.graph.committed_heard_from(parsed.from, parsed.id),
            airtime_ms: 0,
            channel_util_pct: self.channel_util_pct,
            graph_established: self.graph.neighbor_count() > 0,
            on_default_channel: parsed.channel == self.channel_hash
                && psk_bytes(&self.channel_key) == DEFAULT_PSK.as_slice(),
        };
        !self.rate_limit.would_drop(&packet)
            && self
                .qos
                .can_relay(portnum, parsed.channel, self.channel_util_pct)
    }

    pub fn discard_queued_forward(&mut self, from: u32, id: u32) {
        self.cancel_pending(from, id);
        self.graph.cancel_relay(from, id);
        self.cancel_t1_retransmit(from, id, T1CancelReason::Policy);
        crate::reliable::stop_reliable_for(&mut self.pending_reliable, from, id);
    }

    pub fn poll_ready_relay(&mut self, now_ms: u32) -> Option<RelayPlan> {
        let mut best_idx = None;
        let mut best_age = 0;
        for idx in 0..self.pending.len() {
            if !self.pending[idx].active {
                continue;
            }
            if self
                .graph
                .has_our_transmission(self.pending[idx].from, self.pending[idx].id, now_ms)
            {
                self.pending[idx].active = false;
                continue;
            }
            let pending = &self.pending[idx];
            if !self.queued_frame_allowed(&pending.bytes[..pending.len as usize], now_ms) {
                let from = pending.from;
                let id = pending.id;
                self.pending[idx].active = false;
                self.graph.cancel_relay(from, id);
                continue;
            }
            if now_ms.wrapping_sub(pending.tx_after_ms) >= 0x8000_0000 {
                continue;
            }
            let age = now_ms.wrapping_sub(pending.tx_after_ms);
            if best_idx.is_none() || age > best_age {
                best_age = age;
                best_idx = Some(idx);
            }
        }
        let idx = best_idx?;
        let pending = self.pending[idx];
        self.pending[idx].active = false;
        let upstream = self
            .graph
            .committed_heard_from(pending.from, pending.id)
            .unwrap_or(0);
        self.arm_relayed_unicast_followup(
            pending.len,
            pending.bytes,
            now_ms,
            pending.unicast_flags,
            upstream,
        );
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
        if self
            .last_nodeinfo_ms
            .is_none_or(|last| now_ms.wrapping_sub(last) >= NODEINFO_BROADCAST_MS)
            && !self.pending_nodeinfo.active
        {
            self.schedule_nodeinfo_broadcast(now_ms);
        }
        if self.last_telemetry_ms.is_none_or(|last| {
            now_ms.wrapping_sub(last)
                >= device_telemetry_interval_ms(self.admin.device_update_interval_secs)
        }) && !self.pending_telemetry.active
        {
            self.schedule_telemetry_broadcast(now_ms);
        }
        if !self.admin.broadcasts_fixed_position() {
            self.pending_position.active = false;
        } else if self.last_position_ms.is_none_or(|last| {
            now_ms.wrapping_sub(last)
                >= position_broadcast_interval_ms(
                    self.admin.position_broadcast_secs,
                    self.admin.device_role,
                )
        }) && !self.pending_position.active
        {
            self.schedule_position_broadcast(now_ms);
        }
        report
    }

    pub fn emit_topology_log<S: crate::sr_log::TopologyLogSink>(&self, sink: &mut S) {
        self.graph.emit_topology_log(self.node_num, sink);
    }

    pub fn received_on_radio(packet: &InboundPacket<'_>) -> u8 {
        packet.radio_id
    }

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

    #[doc(hidden)]
    pub fn remember_relay_identity(&mut self, node_id: u32, relay_byte: u8, now_ms: u32) {
        self.relay_identity
            .remember_relay_identity(node_id, relay_byte, now_ms);
    }

    fn plan_designated_unicast(
        &mut self,
        parsed: &ParsedPacket,
        heard_from: u32,
        rssi: i16,
        snr: i8,
        half_airtime: u32,
        airtime_ms: u32,
        dest_ack_floor: u32,
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
                slot_delay_ms: crate::coordinated_relay::relay_floor_ms(self.cw_slot_ms())
                    .max(dest_ack_floor),
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
                self.modem_preset,
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
        // The acknowledgement floor already includes the initial wait; adding it again would count the
        // same silence twice.
        let base = dest_ack_floor.max(crate::coordinated_relay::relay_floor_ms(self.cw_slot_ms()));
        let slot0_wait = if sr_active {
            base.saturating_add(
                crate::coordinated_relay::tx_delay_ms_contention_max_at(
                    self.channel_util_pct,
                    self.cw_slot_ms(),
                )
                .saturating_add(airtime_ms),
            )
        } else {
            base.max(tx_delay_ms_worst(self.cw_slot_ms()).saturating_add(airtime_ms))
        };
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
                    // Giving every backup the same slot would cause simultaneous replies to a silent
                    // designated hop.
                    let (rank, count) =
                        self.graph
                            .relay_slot_index(parsed.id, parsed.from, heard_from, now_ms);
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
                    let (rank, count) =
                        self.graph
                            .relay_slot_index(parsed.id, parsed.from, heard_from, now_ms);
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
            uncovered: [0; crate::broadcast_relay::UNCOVERED_LOG],
            uncovered_len: 0,
            coverage_for: 0,
            slots_given: 0,
            reserved_slots: 0,
            reserved_ranked: 0,
            absorbed: [(0, 0); crate::broadcast_relay::RANKED_LOG],
            absorbed_len: 0,
            last_hop_backup: false,
            nonfinal_flood: false,
            has_nonfinal_flood_slot: false,
        }
    }

    fn dest_ack_wait_ms(&self, airtime_ms: u32) -> u32 {
        crate::channel_access::dest_ack_wait_ms(
            airtime_ms,
            crate::coordinated_relay::tx_delay_ms_contention_max_at(
                self.channel_util_pct,
                self.cw_slot_ms(),
            ),
        )
    }

    fn response_header(&self, parsed: &ParsedPacket, hop_start_known: bool) -> (u8, u8) {
        let base = hop_limit_for_response(parsed, hop_start_known, self.hop_limit);
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
            self.modem_preset,
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

    pub fn cancel_broadcast_retransmit(&mut self, from: u32, packet_id: u32) {
        self.cancel_t1_retransmit(from, packet_id, T1CancelReason::RelayHeard);
    }

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

    pub fn has_pending_work(&self) -> bool {
        self.pending.iter().any(|p| p.active)
            || self.pending_topology.active
            || self.pending_nodeinfo.active
            || self.pending_telemetry.active
            || self.pending_position.active
            || self.pending_traceroute.active
            || self.pending_ack.active
            || self.pending_dfu_confirm.active
            || self.pending_admin.iter().any(|p| p.active)
            || self
                .pending_retransmits
                .iter()
                .any(|p| p.active && !p.canceled)
            || self.pending_reliable.iter().any(|p| p.active)
            || self.graph.has_active_relay_commits()
    }

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
        let packet_id = self.alloc_tx_id();
        let mut hop = hop_limit;
        let mut next_hop = 0u8;
        if to != NODENUM_BROADCAST && self.graph.caps_last_hop(to) {
            hop = hop.min(LAST_HOP_BUDGET);
            next_hop = (to & 0xFF) as u8;
        } else if to != NODENUM_BROADCAST {
            // A guessed gateway cannot justify appointing a specific forwarder.
            let (sr_hop, verified) =
                self.graph
                    .get_next_hop_verified(to, self.node_num, self.node_num, now_ms);
            if verified && sr_hop != 0 && sr_hop != self.node_num {
                next_hop = (sr_hop & 0xFF) as u8;
            }
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
                NUM_RELIABLE_RETX,
                None,
            );
        }
        if to == NODENUM_BROADCAST && portnum != SIGNAL_ROUTING_APP {
            let half = crate::coordinated_relay::half_airtime_ms(airtime_ms);
            let span = self.graph.relay_ladder_span_ms(
                packet_id,
                self.node_num,
                self.node_num,
                now_ms,
                half,
            );
            self.schedule_t1_broadcast(
                packet_id,
                len,
                frame,
                Some(portnum),
                Some(self.node_num),
                airtime_ms,
                0,
                span,
                now_ms,
            );
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

    pub fn set_channel_utilization(&mut self, pct: f32) {
        self.channel_util_pct = pct;
    }

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

    /// Independent retry offsets prevent relayers that heard one packet together from colliding on every
    /// attempt.
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
        let Some(named) = due.named else {
            return Some(RelayPlan {
                len: due.len,
                bytes: due.bytes,
                delay_ms: 0,
            });
        };
        if !due.redirect {
            self.sr_log
                .push(SrLogEvent::RelayRetxRepeat { id: due.packet_id });
            return Some(RelayPlan {
                len: due.len,
                bytes: due.bytes,
                delay_ms: 0,
            });
        }
        if let crate::hop_health::HopHealthEvent::BecameSuspect {
            next_hop,
            destination,
            misses,
        } = self
            .graph
            .record_hop_miss(due.to, named.nominated_hop, now_ms)
        {
            self.sr_log.push(SrLogEvent::NextHopSuspect {
                next_hop,
                destination,
                misses,
            });
        }
        let mut excl_buf = [0u32; 4];
        let mut n_excl = 0usize;
        for id in [named.nominated_hop, named.upstream, due.from, self.node_num] {
            if id == 0 || id == due.to {
                continue;
            }
            if excl_buf[..n_excl].contains(&id) {
                continue;
            }
            excl_buf[n_excl] = id;
            n_excl += 1;
        }
        let alt_route = self
            .graph
            .route_excluding(due.to, now_ms, &excl_buf[..n_excl]);
        let chain_egress = self.graph.downstream_chain_egress(due.to, now_ms);
        let alt_byte = (alt_route.next_hop & 0xFF) as u8;
        // An alternate with the same relay byte would be mistaken for the silent nominated hop.
        let stampable = alt_route.next_hop != 0
            && alt_byte != named.nominated_byte
            && (alt_route.verified || chain_egress == Some(alt_route.next_hop))
            && self.graph.capability_status(alt_route.next_hop)
                == crate::capability::CapabilityStatus::SrActive;
        if !stampable {
            self.sr_log
                .push(SrLogEvent::RelayRetxNoAlternate { id: due.packet_id });
            return None;
        }
        let mut bytes = due.bytes;
        let Ok(mut hdr) = PacketHeader::decode(&bytes[..PACKET_HEADER_LEN]) else {
            self.sr_log
                .push(SrLogEvent::RelayRetxNoAlternate { id: due.packet_id });
            return None;
        };
        hdr.next_hop = alt_byte;
        if let Ok(out) = (&mut bytes[..PACKET_HEADER_LEN]).try_into() {
            hdr.encode_to(out);
        }
        self.sr_log.push(SrLogEvent::RelayRetxRedirect {
            id: due.packet_id,
            next_hop: hdr.next_hop,
        });
        Some(RelayPlan {
            len: due.len,
            bytes,
            delay_ms: 0,
        })
    }

    fn arm_relayed_unicast_followup(
        &mut self,
        len: u8,
        bytes: [u8; MAX_WIRE_LEN],
        now_ms: u32,
        flags: crate::unicast_relay::UnicastSlotFlags,
        upstream: u32,
    ) {
        let Ok(hdr) = PacketHeader::decode(&bytes[..PACKET_HEADER_LEN]) else {
            return;
        };
        let p = hdr.parse();
        if p.to == NODENUM_BROADCAST || p.from == self.node_num {
            return;
        }
        let last_hop = crate::graph::delivery_hop_cost_fixed(
            self.graph.edges(),
            Some(self.graph.capability()),
            self.node_num,
            p.to,
            now_ms,
            self.node_num,
        )
        .is_some();
        if p.hop_limit == 0 && !last_hop {
            return;
        }
        if flags.nonfinal_flood {
            return;
        }
        let cfg = eu868_config_for_preset(self.modem_preset);
        let airtime = packet_time_ms(&cfg, len as usize, false).max(1);
        let (delay, num_retx, named) = if last_hop {
            if flags.last_hop_backup {
                return;
            }
            let nominated_hop = if flags.nominated_next_hop != 0 {
                flags.nominated_next_hop
            } else {
                p.to
            };
            let delay = self.next_hop_carry_wait_ms(nominated_hop, airtime);
            let named = NamedFollowup {
                nominated_hop,
                nominated_byte: (nominated_hop & 0xFF) as u8,
                upstream,
                delay_ms: delay,
                redirect_on_last: false,
            };
            (delay, 1, Some(named))
        } else {
            let nominated_hop = if flags.nominated_next_hop != 0 {
                flags.nominated_next_hop
            } else if p.next_hop != 0 {
                self.graph
                    .match_relay_byte_on_outgoing_edges(p.next_hop)
                    .unwrap_or(0)
            } else {
                0
            };
            if nominated_hop == 0 && p.next_hop == 0 {
                return;
            }
            let weak_flood = p.next_hop == 0;
            let delay = if weak_flood {
                self.next_hop_carry_wait_ms(nominated_hop, airtime)
            } else {
                self.named_followup_delay_ms(nominated_hop, airtime)
            };
            let nominated_byte = if nominated_hop != 0 {
                (nominated_hop & 0xFF) as u8
            } else {
                p.next_hop
            };
            let named = NamedFollowup {
                nominated_hop,
                nominated_byte,
                upstream,
                delay_ms: delay,
                redirect_on_last: !weak_flood,
            };
            let tries = if weak_flood { 1 } else { NAMED_FOLLOWUP_TRIES };
            (delay, tries, Some(named))
        };
        let armed_byte = named.as_ref().map_or(p.next_hop, |n| n.nominated_byte);
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
            num_retx,
            named,
        ) {
            self.sr_log.push(SrLogEvent::RelayRetxArmed {
                id: p.id,
                next_hop: armed_byte,
            });
        }
    }

    fn next_hop_carry_wait_ms(&self, next_hop: u32, airtime_ms: u32) -> u32 {
        if next_hop != 0 && self.graph.capability_status(next_hop).is_signal_routing() {
            crate::coordinated_relay::relay_floor_ms(self.cw_slot_ms()).saturating_add(airtime_ms)
        } else {
            tx_delay_ms_worst(self.cw_slot_ms()).saturating_add(airtime_ms)
        }
    }

    /// A destination-ACK floor applies to the originator’s frame, not to a downstream backup copy.
    fn named_followup_delay_ms(&self, nominated_hop: u32, airtime_ms: u32) -> u32 {
        let half = crate::coordinated_relay::half_airtime_ms(airtime_ms);
        let slot1_end = self
            .unicast_named_slot_delay_ms(1, 0, half, airtime_ms)
            .saturating_add(crate::coordinated_relay::tie_break_range_ms(half))
            .saturating_add(airtime_ms);
        self.sr_peer_relay_wait_ms(airtime_ms).saturating_add(
            self.next_hop_carry_wait_ms(nominated_hop, airtime_ms)
                .max(slot1_end),
        )
    }

    fn unicast_named_slot_delay_ms(
        &self,
        slot: u8,
        dest_ack_floor: u32,
        half_airtime: u32,
        airtime_ms: u32,
    ) -> u32 {
        // A large scheduling floor can delay the leader beyond the nominal turnaround; backups must also
        // allow its frame to finish.
        let earliest =
            crate::coordinated_relay::relay_floor_ms(self.cw_slot_ms()).max(dest_ack_floor);
        if slot == 0 {
            earliest
        } else {
            let peer = self.sr_peer_relay_wait_ms(airtime_ms);
            let leader_clear = peer.max(earliest.saturating_add(airtime_ms));
            leader_clear.saturating_add((slot as u32 - 1).saturating_mul(half_airtime))
        }
    }

    fn unicast_slot_delay_ms(
        &self,
        ranked: &crate::broadcast_relay::BroadcastRelayPlan,
        dest_ack_floor: u32,
        half_airtime: u32,
        airtime_ms: u32,
        nominated_next_hop: u32,
    ) -> u32 {
        if ranked.last_hop_backup {
            let early =
                crate::coordinated_relay::relay_floor_ms(self.cw_slot_ms()).max(dest_ack_floor);
            return early
                .saturating_add(airtime_ms)
                .saturating_add(self.dest_ack_wait_ms(airtime_ms));
        }
        if ranked.nonfinal_flood {
            let named_slot = ranked.slot_index.saturating_sub(1);
            return self
                .unicast_named_slot_delay_ms(named_slot, dest_ack_floor, half_airtime, airtime_ms)
                .saturating_add(airtime_ms)
                .saturating_add(self.next_hop_carry_wait_ms(nominated_next_hop, airtime_ms));
        }
        self.unicast_named_slot_delay_ms(
            ranked.slot_index,
            dest_ack_floor,
            half_airtime,
            airtime_ms,
        )
    }

    fn cancel_relayed_retx(&mut self, from: u32, id: u32, reason: RelayRetxCancelReason) {
        self.cancel_relayed_retx_from(from, id, reason, false);
    }

    fn cancel_relayed_retx_from(
        &mut self,
        from: u32,
        id: u32,
        reason: RelayRetxCancelReason,
        from_nominated: bool,
    ) {
        let Some((dest, nominated)) = stop_reliable_for(&mut self.pending_reliable, from, id)
        else {
            return;
        };
        self.sr_log
            .push(SrLogEvent::RelayRetxCanceled { id, reason });
        let success = match reason {
            RelayRetxCancelReason::ReplyHeard => true,
            RelayRetxCancelReason::CopyHeard => from_nominated,
        };
        if success {
            if let crate::hop_health::HopHealthEvent::BecameHealthy {
                next_hop,
                destination,
            } = self.graph.record_hop_success(dest, nominated)
            {
                self.sr_log.push(SrLogEvent::NextHopHealthy {
                    next_hop,
                    destination,
                });
            }
        }
    }

    pub fn poll_ack_tx(&mut self, now_ms: u32) -> Option<RelayPlan> {
        if !self.pending_ack.active {
            return None;
        }
        if now_ms.wrapping_sub(self.pending_ack.next_tx_ms) >= 0x8000_0000 {
            return None;
        }
        self.pending_ack.active = false;
        Some(RelayPlan {
            len: self.pending_ack.len,
            bytes: self.pending_ack.bytes,
            delay_ms: 0,
        })
    }

    pub fn poll_dfu_confirm_tx(&mut self, now_ms: u32) -> Option<RelayPlan> {
        if !self.pending_dfu_confirm.active {
            return None;
        }
        if now_ms.wrapping_sub(self.pending_dfu_confirm.next_tx_ms) >= 0x8000_0000 {
            return None;
        }
        self.pending_dfu_confirm.active = false;
        Some(RelayPlan {
            len: self.pending_dfu_confirm.len,
            bytes: self.pending_dfu_confirm.bytes,
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
            best = Some(match best {
                None => i,
                Some(j) => {
                    if now_ms.wrapping_sub(slot.next_tx_ms)
                        > now_ms.wrapping_sub(self.pending_admin[j].next_tx_ms)
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
        self.pending_nodeinfo.active = false;
        Some(RelayPlan {
            len: self.pending_nodeinfo.len,
            bytes: self.pending_nodeinfo.bytes,
            delay_ms: 0,
        })
    }

    pub fn poll_position_tx(&mut self, now_ms: u32) -> Option<RelayPlan> {
        if !self.admin.broadcasts_fixed_position() {
            self.pending_position.active = false;
            return None;
        }
        if !self.pending_position.active {
            return None;
        }
        if now_ms.wrapping_sub(self.pending_position.next_tx_ms) >= 0x8000_0000 {
            return None;
        }
        self.pending_position.active = false;
        Some(RelayPlan {
            len: self.pending_position.len,
            bytes: self.pending_position.bytes,
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

    pub fn release_packet(&mut self, handle: crate::pool::PacketHandle) {
        self.pool.release(handle);
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
            if data.request_id != 0 {
                let _ =
                    stop_reliable_for(&mut self.pending_reliable, self.node_num, data.request_id);
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
        let packet_id = self.alloc_tx_id();
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
        let packet_id = self.alloc_tx_id();
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

    /// Requesters can only authenticate replies encrypted with the same key path as their request.
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
        if self
            .graph
            .has_our_transmission(parsed.from, parsed.id, now_ms)
        {
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
        let packet_id = self.alloc_tx_id();
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
        self.last_nodeinfo_ms = Some(now_ms);
    }

    /// Without contention, colocated nodes answering one request overlap each other’s airtime.
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
        let packet_id = self.alloc_tx_id();
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
        let packet_id = self.alloc_tx_id();
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
        self.last_telemetry_ms = Some(now_ms);
    }

    fn schedule_position_broadcast(&mut self, now_ms: u32) {
        if !self.admin.broadcasts_fixed_position() {
            return;
        }
        let packet_id = self.alloc_tx_id();
        let Some((len, frame)) = build_fixed_position_wire_frame(
            self.node_num,
            packet_id,
            self.channel_hash,
            self.hop_limit,
            &self.channel_key,
            self.admin.latitude_i,
            self.admin.longitude_i,
            self.ok_to_mqtt(),
        ) else {
            return;
        };
        self.pending_position.active = true;
        self.pending_position.next_tx_ms = now_ms;
        self.pending_position.len = len;
        self.pending_position.bytes = frame;
        self.last_position_ms = Some(now_ms);
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
        let packet_id = self.alloc_tx_id();
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
            let packet_id = self.alloc_tx_id();
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

    /// A hardware-random boot seed prevents deterministic packet-ID reuse across restarts.
    pub fn seed_tx_ids(&mut self, seed: u32) {
        self.next_tx_id = seed;
    }

    fn alloc_tx_id(&mut self) -> u32 {
        let id = self.next_tx_id.max(1);
        self.next_tx_id = id.wrapping_add(1).max(1);
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
        unicast_flags: crate::unicast_relay::UnicastSlotFlags,
    ) -> bool {
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
                unicast_flags,
            };
            return true;
        }
        false
    }

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
            crate::unicast_relay::UnicastSlotFlags::default(),
        )
    }

    fn note_tx_cancel(&mut self, from: u32, id: u32) {
        if !self.tx_cancels.contains(&(from, id)) {
            let _ = self.tx_cancels.push((from, id));
        }
    }

    pub fn note_tx_done(&mut self, from: u32, packet_id: u32) {
        if packet_id != 0 {
            self.graph.cancel_relay(from, packet_id);
            for slot in &mut self.pending_retransmits {
                if slot.from == from && slot.packet_id == packet_id {
                    slot.fired = false;
                }
            }
        }
    }

    pub fn take_tx_cancels(&mut self, out: &mut heapless::Vec<(u32, u32), 8>) {
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
            self.note_tx_cancel(parsed.from, parsed.id);
        }
        dropped
    }

    fn is_repeated_reliable_tx(parsed: &ParsedPacket, data: Option<&DecodedData>) -> bool {
        let hop_start_known = data.is_some_and(|d| d.has_bitfield);
        hops_away(parsed.hop_start, parsed.hop_limit, hop_start_known) == Some(0)
    }

    fn maybe_cancel_relay_for_foreign_ack(
        &mut self,
        parsed: &ParsedPacket,
        data: &DecodedData,
        now_ms: u32,
    ) {
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
        // A destination reply makes every retained copy redundant, including a frame already handed to
        // the radio queue.
        let had_pending = self.cancel_pending(parsed.to, cancel_id);
        let committed = self.graph.is_committed_relay(parsed.to, cancel_id);
        if had_pending
            || committed
            || self
                .graph
                .has_our_transmission(parsed.to, cancel_id, now_ms)
        {
            self.graph.cancel_relay(parsed.to, cancel_id);
            self.note_tx_cancel(parsed.to, cancel_id);
            self.sr_log
                .push(SrLogEvent::UnicastReplyCancel { id: cancel_id });
        }
        self.cancel_relayed_retx_from(
            parsed.to,
            cancel_id,
            RelayRetxCancelReason::ReplyHeard,
            false,
        );
    }

    fn observe_inbound_graph(
        &mut self,
        parsed: &ParsedPacket,
        packet: &InboundPacket<'_>,
        now_ms: u32,
        known_relay: Option<u32>,
    ) {
        if parsed.via_mqtt {
            return;
        }
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
            }
        }
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
            self.maybe_cancel_relay_for_foreign_ack(parsed, data, now_ms);
        }

        let direct = is_direct_packet(
            parsed.from,
            parsed.hop_start,
            parsed.hop_limit,
            parsed.relay_node,
        );
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
        self.observe_inbound_graph(parsed, packet, now_ms, known_relay);

        if parsed.to != NODENUM_BROADCAST && parsed.from != self.node_num {
            let transmitter = self.resolve_heard_from_node(
                parsed.relay_node,
                parsed.from,
                packet.rssi,
                packet.snr,
                now_ms,
            );
            let named = named_followup(&self.pending_reliable, parsed.from, parsed.id);
            let from_nominated = named.is_some_and(|n| {
                (n.nominated_byte != 0 && parsed.relay_node == n.nominated_byte)
                    || (n.nominated_hop != 0 && transmitter == n.nominated_hop)
            });
            if from_nominated {
                self.cancel_relayed_retx_from(
                    parsed.from,
                    parsed.id,
                    RelayRetxCancelReason::CopyHeard,
                    true,
                );
            } else if named.is_none() {
                self.cancel_relayed_retx_from(
                    parsed.from,
                    parsed.id,
                    RelayRetxCancelReason::CopyHeard,
                    false,
                );
            }
        }

        if parsed.from == self.node_num {
            let _ = stop_reliable_for(&mut self.pending_reliable, self.node_num, parsed.id);
            self.perhaps_cancel_dupe(parsed, packet, now_ms);
            return;
        }

        if parsed.to == self.node_num
            && parsed.from != self.node_num
            && decoded_data.is_none_or(|d| d.portnum != ROUTING_APP)
            && !self.module_reply_suppresses_ack
        {
            let repeated = Self::is_repeated_reliable_tx(parsed, decoded_data);
            if repeated && parsed.want_ack {
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
        }
        if Self::is_repeated_reliable_tx(parsed, decoded_data) {
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

        // A worse-placed copy must not cancel the only node able to complete the last hop.
        let in_flight = self
            .graph
            .has_our_transmission(parsed.from, parsed.id, now_ms);
        if parsed.to != NODENUM_BROADCAST && (committed || has_pending || in_flight) {
            let next_hop = self.graph.route_to(parsed.to, now_ms).next_hop;
            let dupe_relayer = heard_relayer.filter(|&n| n != 0 && n != self.node_num);
            let flags = self
                .pending
                .iter()
                .find(|p| p.active && p.from == parsed.from && p.id == parsed.id)
                .map(|p| p.unicast_flags)
                .unwrap_or_else(|| self.graph.unicast_commit_flags(parsed.from, parsed.id));
            if self.graph.role_allows_canceling_dupe()
                && self.graph.unicast_dupe_cancels(
                    parsed.id,
                    parsed.to,
                    next_hop,
                    now_ms,
                    dupe_relayer,
                    flags,
                    parsed.next_hop,
                    parsed.relay_node,
                    parsed.hop_limit,
                )
            {
                self.graph.cancel_relay(parsed.from, parsed.id);
                let canceled_pending = self.cancel_pending(parsed.from, parsed.id);
                self.note_tx_cancel(parsed.from, parsed.id);
                if canceled_pending || has_pending {
                    self.sr_log.push(SrLogEvent::UnicastDupeCancel {
                        id: parsed.id,
                        from: parsed.from,
                    });
                }
            }
            return;
        }

        // Completed coverage makes the packet redundant regardless of a role’s preference to keep
        // relaying.
        let mut sr_coverage_cancel = false;

        if committed {
            if !has_pending {
                self.cancel_t1_retransmit(parsed.from, parsed.id, T1CancelReason::RelayHeard);
                if let Some(heard_from) = heard_relayer {
                    if !self.all_neighbors_covered(parsed.from, parsed.id, heard_from, now_ms) {
                        return;
                    }
                }
                self.graph.cancel_relay(parsed.from, parsed.id);
                self.note_tx_cancel(parsed.from, parsed.id);
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
                self.note_tx_cancel(parsed.from, parsed.id);
                self.sr_log.push(SrLogEvent::BroadcastDupeCancel {
                    id: parsed.id,
                    from: parsed.from,
                });
            }
        }

        self.cancel_t1_retransmit(parsed.from, parsed.id, T1CancelReason::RelayHeard);

        if parsed.from == self.node_num {
            let _ = stop_reliable_for(&mut self.pending_reliable, self.node_num, parsed.id);
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
            let parsed = PacketHeader::decode(&slot.bytes[..slot.len as usize])
                .ok()?
                .parse();
            let pkt = crate::rate_limit::RateLimitPacket {
                from: parsed.from,
                to: parsed.to,
                decoded_portnum: slot.decoded_portnum,
                now_ms,
                rebroadcast_candidate: true,
                resolved_relay: slot.resolved_relay,
                airtime_ms: 0,
                channel_util_pct: self.channel_util_pct,
                graph_established: self.graph.neighbor_count() > 0,
                on_default_channel: parsed.channel == self.channel_hash
                    && psk_bytes(&self.channel_key) == DEFAULT_PSK.as_slice(),
            };
            if (parsed.from != self.node_num && !self.graph.is_rebroadcaster())
                || self.rate_limit.would_drop(&pkt)
                || !self
                    .qos
                    .can_relay(slot.decoded_portnum, parsed.channel, self.channel_util_pct)
            {
                slot.active = false;
                slot.canceled = true;
                continue;
            }
            if self
                .graph
                .has_our_transmission(slot.from, slot.packet_id, now_ms)
            {
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
        let Some(mut relay_hdr) = relay_header_with_next_hop_opts(parsed, self.node_num, 0, false)
        else {
            self.pool.release(handle);
            return;
        };
        // Ordinary relayed unicasts still need the acknowledgement flag; clearing it in the shared
        // builder would break their reliable path.
        relay_hdr.clear_want_ack();
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
        // Insurers need separate slots because simultaneous retries collide exactly when the primary
        // relay failed.
        let ahead = self
            .graph
            .insurance_rung_index(parsed.id, parsed.from, heard_from, now_ms);
        let stagger = (ahead as u32).saturating_mul(half_airtime_ms);
        let span = self.graph.relay_ladder_span_ms(
            parsed.id,
            parsed.from,
            heard_from,
            now_ms,
            half_airtime_ms,
        );
        self.schedule_t1_broadcast(
            parsed.id,
            len,
            bytes,
            decoded_portnum,
            Some(heard_from),
            airtime_ms,
            stagger,
            span,
            now_ms,
        );
    }

    fn schedule_t1_broadcast(
        &mut self,
        packet_id: u32,
        len: u8,
        bytes: [u8; MAX_WIRE_LEN],
        decoded_portnum: Option<u32>,
        resolved_relay: Option<u32>,
        airtime_ms: u32,
        stagger_ms: u32,
        ladder_span_ms: u32,
        now_ms: u32,
    ) {
        let Ok(header) = PacketHeader::decode(&bytes[..len as usize]) else {
            return;
        };
        let parsed = header.parse();
        let from = parsed.from;
        for slot in &self.pending_retransmits {
            if slot.active && slot.from == from && slot.packet_id == packet_id {
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
            .max(ladder_span_ms)
            .saturating_add(airtime_ms)
            .saturating_add(stagger_ms);
        self.pending_retransmits[idx] = PendingRetransmit {
            active: true,
            canceled: false,
            fired: false,
            from,
            resolved_relay,
            packet_id,
            fire_after_ms: now_ms.wrapping_add(fire_delay),
            decoded_portnum,
            len,
            bytes,
        };
        self.sr_log.push(SrLogEvent::T1Scheduled {
            id: packet_id,
            delay_ms: fire_delay,
        });
    }

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

    fn cancel_t1_retransmit(&mut self, from: u32, packet_id: u32, reason: T1CancelReason) {
        let mut pull_back = false;
        let mut canceled = false;
        for slot in &mut self.pending_retransmits {
            if slot.from != from || slot.packet_id != packet_id {
                continue;
            }
            if slot.active && !slot.canceled {
                slot.active = false;
                slot.canceled = true;
                canceled = true;
            } else if slot.fired {
                slot.fired = false;
                pull_back = true;
                canceled = true;
            }
            break;
        }
        if pull_back {
            self.note_tx_cancel(from, packet_id);
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

    fn decrypt_topology_chunk(
        frame: &[u8],
        channel_hash: u8,
    ) -> (u32, crate::topology::PackedHeader, usize) {
        let parsed = PacketHeader::decode(frame).unwrap().parse();
        let mut cipher = frame[PACKET_HEADER_LEN..].to_vec();
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let (_port, payload) = crate::topology::try_decrypt_data(
            &key,
            parsed.from,
            parsed.id,
            channel_hash,
            parsed.channel,
            &mut cipher,
        )
        .expect("topology chunk decrypts");
        let (hdr, neighbors) =
            crate::topology::extract_packed_neighbors(&payload).expect("packed neighbors");
        (parsed.id, hdr, neighbors.len())
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
    fn two_topology_chunks_reassemble_on_the_receiver() {
        const SENDER: u32 = 0x1100_0011;
        const RECEIVER: u32 = 0x2200_0022;
        const UNLISTED: u32 = 0xDD00_00DD;
        let mut sender = Router::new(SENDER);
        for i in 0..30u32 {
            sender
                .graph_mut()
                .observe_direct_neighbor(0x2000_0000 + i, -60, 8, 1_000, 0);
        }
        assert!(sender.schedule_topology_broadcast(10_000, 16, false));
        let first = sender.poll_topology_tx(10_000).unwrap();
        let cfg = eu868_config_for_preset(sender.modem_preset());
        let airtime = packet_time_ms(&cfg, first.len as usize, false);
        let second = sender
            .poll_topology_tx(10_000 + 2 * airtime)
            .expect("second chunk");
        let hash = sender.channel_hash();
        let (id0, h0, n0) = decrypt_topology_chunk(&first.bytes[..first.len as usize], hash);
        let (id1, h1, n1) = decrypt_topology_chunk(&second.bytes[..second.len as usize], hash);
        assert_ne!(id0, id1);
        assert_eq!(h0.topology_version, h1.topology_version);
        assert!(h0.more_chunks && !h0.continuation);
        assert!(!h1.more_chunks && h1.continuation);
        assert_eq!(n0, 28);
        assert_eq!(n1, 2);

        let mut receiver = Router::new(RECEIVER);
        receiver
            .graph_mut()
            .edges_mut()
            .ensure_local_node(SENDER, 1_000);
        receiver
            .graph_mut()
            .edges_mut()
            .ensure_local_node(UNLISTED, 1_000);
        receiver.graph_mut().edges_mut().update_edge(
            RECEIVER,
            SENDER,
            UNLISTED,
            2.0,
            1_000,
            EdgeSource::Mirrored,
            true,
            0,
        );
        receiver.graph_mut().edges_mut().update_edge(
            RECEIVER,
            UNLISTED,
            SENDER,
            2.0,
            1_000,
            EdgeSource::Reported,
            true,
            0,
        );
        receiver
            .graph_mut()
            .edges_mut()
            .set_edge_hears_us(UNLISTED, SENDER, true);

        let feed = |router: &mut Router, frame: &RelayPlan, now_ms: u32| {
            router
                .process_inbound(
                    &InboundPacket {
                        radio_id: 0,
                        rssi: -70,
                        snr: 8,
                        bytes: &frame.bytes[..frame.len as usize],
                    },
                    now_ms,
                )
                .unwrap();
        };
        feed(&mut receiver, &first, 20_000);
        assert!(
            receiver
                .graph_mut()
                .edges()
                .find_node(SENDER)
                .unwrap()
                .find_edge(UNLISTED)
                .is_some(),
            "a dropped neighbour stays until the last chunk"
        );
        assert!(
            receiver
                .graph_mut()
                .edges()
                .find_node(UNLISTED)
                .unwrap()
                .find_edge(SENDER)
                .unwrap()
                .hears_us
        );
        feed(&mut receiver, &second, 20_000 + 2 * airtime);
        let (dropped, count) = {
            let from_sender = receiver.graph_mut().edges().find_node(SENDER).unwrap();
            (
                from_sender.find_edge(UNLISTED).is_none(),
                from_sender.edge_count,
            )
        };
        assert!(
            dropped,
            "the last chunk drops a neighbour the list no longer names"
        );
        assert_eq!(
            count, 30,
            "both chunks' neighbours are in the sender's list"
        );
        let hears = receiver
            .graph_mut()
            .edges()
            .find_node(UNLISTED)
            .unwrap()
            .find_edge(SENDER)
            .unwrap()
            .hears_us;
        assert!(!hears, "unlisted after the whole list is in hand");
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

    #[test]
    fn topology_ingest_logs_every_packed_neighbor_field() {
        use crate::topology::{
            encode_packed_neighbor_entry, PACKED_NEIGHBOR_ENTRY_SIZE,
            PACKED_NEIGHBOR_FLAG_HEARS_US, PACKED_NEIGHBOR_FLAG_SR_ACTIVE,
            PACKED_NEIGHBOR_HEADER_SIZE,
        };
        use mesh_radio::MODEM_SHORT_SLOW;

        const ME: u32 = 0x046b_553a;
        const PEER: u32 = 0x63dc_8f8c;
        const A: u32 = 0xd33f_1eef;
        const B: u32 = 0x979e_d146;
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let mut router = Router::with_channel(ME, key, 0x77, MODEM_SHORT_SLOW, true, 3);

        let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE + 2 * PACKED_NEIGHBOR_ENTRY_SIZE];
        write_packed_header(&mut packed, 5, true);
        encode_packed_neighbor_entry(
            &mut packed[PACKED_NEIGHBOR_HEADER_SIZE..],
            A,
            -81,
            4,
            PACKED_NEIGHBOR_FLAG_SR_ACTIVE | PACKED_NEIGHBOR_FLAG_HEARS_US,
            3,
        );
        encode_packed_neighbor_entry(
            &mut packed[PACKED_NEIGHBOR_HEADER_SIZE + PACKED_NEIGHBOR_ENTRY_SIZE..],
            B,
            -42,
            11,
            0,
            0,
        );
        let (len, frame) =
            build_topology_wire_frame(PEER, 0xA1, 0x77, 3, &key, &packed, false).unwrap();
        router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &frame[..len as usize],
                },
                1_000,
            )
            .unwrap();

        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        let mut listed = heapless::Vec::<_, 4>::new();
        for event in logs.iter() {
            if let SrLogEvent::TopologyListedNeighbor {
                from,
                node_id,
                rssi,
                snr,
                hears_us,
                sr_active,
                etx_variance,
            } = event
            {
                listed
                    .push((
                        *from,
                        *node_id,
                        *rssi,
                        *snr,
                        *hears_us,
                        *sr_active,
                        *etx_variance,
                    ))
                    .unwrap();
            }
        }
        assert_eq!(
            listed.as_slice(),
            &[
                (PEER, A, -81i8, 4i8, true, true, 3u8),
                (PEER, B, -42i8, 11i8, false, false, 0u8),
            ]
        );
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::TopologyReceived {
                from: PEER,
                neighbors: 2,
                routing_version: SIGNAL_ROUTING_VERSION,
                sr_active: true,
                more_chunks: false,
                continuation: false,
            }
        )));
    }

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
        feed(&mut router, &bootstrap(P1, 0x91), 5_000);
        let max = coordinated_relay::tx_delay_ms_contention_max(router.cw_slot_ms());
        assert!((5_000..=5_000 + max).any(|t| router.poll_topology_tx(t).is_some()));
        feed(&mut router, &bootstrap(P2, 0x92), 20_000);
        assert!((20_000..=20_000 + max).all(|t| router.poll_topology_tx(t).is_none()));
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::BootstrapReplyRateLimited)));
        feed(
            &mut router,
            &bootstrap(P1, 0x93),
            5_000 + BOOTSTRAP_REPLY_MIN_MS + 1,
        );
        let t3 = 5_000 + BOOTSTRAP_REPLY_MIN_MS + 1;
        assert!((t3..=t3 + max).any(|t| router.poll_topology_tx(t).is_some()));
    }

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

        let header = PacketHeader::from_fields(1, 2, 99, 0, 1, 2, false, false, 0, 0xAB);
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
    fn duplicate_relayed_copy_learns_downstream_via_hears_us_neighbor() {
        const ME: u32 = 0x63DC_8F8C;
        const STOCK: u32 = 0x4F51_78DC;
        const GATEWAY: u32 = 0x108A_EF6C;
        const PACKET_ID: u32 = 0x91DB_7D3C;
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(ME));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        router
            .graph_mut()
            .observe_direct_neighbor(GATEWAY, -96, 7, 0, 0);
        router
            .graph_mut()
            .edges_mut()
            .set_edge_hears_us(ME, GATEWAY, true);

        let first = encode_wire(
            PacketHeader::from_fields(
                NODENUM_BROADCAST,
                STOCK,
                PACKET_ID,
                0,
                5,
                7,
                false,
                false,
                0,
                0xF0,
            ),
            &[1, 2, 3],
        );
        let _ = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &first,
                },
                100,
            )
            .unwrap();
        assert_eq!(
            router.graph_mut().get_downstream_relay(STOCK, 150),
            None,
            "unresolved relay must not invent a path"
        );

        let second = encode_wire(
            PacketHeader::from_fields(
                NODENUM_BROADCAST,
                STOCK,
                PACKET_ID,
                0,
                5,
                7,
                false,
                false,
                0,
                (GATEWAY & 0xFF) as u8,
            ),
            &[1, 2, 3],
        );
        let dup = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -96,
                    snr: 7,
                    bytes: &second,
                },
                200,
            )
            .unwrap();
        assert!(dup.duplicate);
        assert_eq!(
            router.graph_mut().get_downstream_relay(STOCK, 250),
            Some(GATEWAY),
            "dupe via hearsUs neighbour must park the stock originator"
        );
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
        graph.edges_mut().update_edge(
            0xCC00_00CC,
            NEIGHBOR,
            STOCK,
            2.0,
            0,
            EdgeSource::Reported,
            true,
            0,
        );
        graph.edges_mut().set_edge_hears_us(NEIGHBOR, STOCK, true);

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
        assert!(router.poll_t1_retransmit(1_000 + fire_ms - 1).is_none());
        let ladder =
            coordinated_relay::half_airtime_ms(airtime) * crate::graph::MAX_EDGES_PER_NODE as u32;
        assert!(router
            .poll_t1_retransmit(1_000 + fire_ms + ladder)
            .is_some());
    }

    #[test]
    fn the_insurance_copy_asks_for_no_acknowledgement() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0xCC00_00CC));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        const NEIGHBOR: u32 = 0xBB00_00BB;
        const STOCK: u32 = 0xDD00_00DD;
        {
            let graph = router.graph_mut();
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
            graph.edges_mut().update_edge(
                0xCC00_00CC,
                NEIGHBOR,
                STOCK,
                2.0,
                0,
                EdgeSource::Reported,
                true,
                0,
            );
            graph.edges_mut().set_edge_hears_us(NEIGHBOR, STOCK, true);
        }

        let header =
            PacketHeader::from_fields(NODENUM_BROADCAST, NEIGHBOR, 99, 0, 3, 3, true, false, 0, 0);
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
        assert!(
            PacketHeader::decode(&wire[..PACKET_HEADER_LEN])
                .unwrap()
                .want_ack(),
            "the frame we heard must carry the flag, or this test proves nothing"
        );
        let airtime = coordinated_relay::DEFAULT_SLOT_MS * 10;
        let plan = router.evaluate_tx_plan(&result, 0.0, airtime, 1_000);
        assert!(plan.relay.is_none(), "we defer to the repeater");

        let slot_ms = coordinated_relay::slot_time_for_preset(router.modem_preset());
        let fire_ms = coordinated_relay::tx_delay_ms_worst(slot_ms).saturating_add(airtime);
        let ladder =
            coordinated_relay::half_airtime_ms(airtime) * crate::graph::MAX_EDGES_PER_NODE as u32;
        let fired = router
            .poll_t1_retransmit(1_000 + fire_ms + ladder)
            .expect("insurance fires");
        let sent = PacketHeader::decode(&fired.bytes[..PACKET_HEADER_LEN]).unwrap();
        assert!(
            !sent.want_ack(),
            "the insurance copy must not carry want_ack"
        );
    }

    #[test]
    fn a_copy_heard_after_t1_fired_pulls_the_frame_back() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0xCC00_00CC));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        const NEIGHBOR: u32 = 0xBB00_00BB;
        const STOCK: u32 = 0xDD00_00DD;
        {
            let graph = router.graph_mut();
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
            graph.edges_mut().update_edge(
                0xCC00_00CC,
                NEIGHBOR,
                STOCK,
                2.0,
                0,
                EdgeSource::Reported,
                true,
                0,
            );
            graph.edges_mut().set_edge_hears_us(NEIGHBOR, STOCK, true);
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
                rssi: -70,
                snr: 8,
                bytes: &relayed,
            },
            fire_at + 200,
        );
        router.take_tx_cancels(&mut cancels);
        assert!(
            cancels.contains(&(NEIGHBOR, 99)),
            "the queued insurance frame must be pulled out of the radio queue"
        );
        router.note_tx_done(NEIGHBOR, 99);
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

    #[test]
    fn t1_stands_down_when_the_peers_copy_is_heard() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(0xCC00_00CC));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        const NEIGHBOR: u32 = 0xBB00_00BB;
        const STOCK: u32 = 0xDD00_00DD;
        {
            let graph = router.graph_mut();
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
            graph.edges_mut().update_edge(
                0xCC00_00CC,
                NEIGHBOR,
                STOCK,
                2.0,
                0,
                EdgeSource::Reported,
                true,
                0,
            );
            graph.edges_mut().set_edge_hears_us(NEIGHBOR, STOCK, true);
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
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed[..5], 8).unwrap();
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

    #[test]
    fn coverage_cancels_a_committed_relay_whatever_our_role() {
        for role in [
            crate::nodeinfo::DEVICE_ROLE_CLIENT,
            crate::nodeinfo::DEVICE_ROLE_ROUTER,
            crate::nodeinfo::DEVICE_ROLE_ROUTER_LATE,
        ] {
            let mut router = Router::new(0x677a_1caf);
            router.set_device_role(role);

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

    fn setup_downstream_only_graph(router: &mut Router) {
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_RELAYER, -70, 8, 0, 0);
        router
            .graph_mut()
            .confirm_direct_neighbor_hears_us(UNI_RELAYER);
        router
            .graph_mut()
            .downstream_mut()
            .update(UNI_ME, UNI_DEST, UNI_RELAYER, 2.0, 0, false, 0);
    }

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
        let (header, _) = decode_packed_neighbors(&packed[..5], 8).unwrap();
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
        let source = PackedNeighbor {
            node_id: UNI_SOURCE,
            hears_us: false,
            ..dest
        };
        router
            .graph_mut()
            .merge_topology(UNI_RELAYER, &header, &[dest, us, source], true, 0, 0);
    }

    #[test]
    fn downstream_parent_we_hear_is_stamped_as_next_hop() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_downstream_only_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x600, true);
        let (sent, _) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, (UNI_RELAYER & 0xFF) as u8);
    }

    #[test]
    fn downstream_chain_is_stamped_as_next_hop() {
        const PARENT: u32 = 0x1100_0011;
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_RELAYER, -70, 8, 0, 0);
        router
            .graph_mut()
            .confirm_direct_neighbor_hears_us(UNI_RELAYER);
        router
            .graph_mut()
            .downstream_mut()
            .update(UNI_ME, UNI_DEST, PARENT, 2.0, 0, false, 0);
        router
            .graph_mut()
            .downstream_mut()
            .update(UNI_ME, PARENT, UNI_RELAYER, 2.0, 0, false, 0);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x70b, true);
        let (sent, _) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, (UNI_RELAYER & 0xFF) as u8);
    }

    const UNI_PEER: u32 = 0xAB00_00AB;

    fn setup_unverified_gateway_graph(router: &mut Router, listener: Option<u32>) {
        let graph = router.graph_mut();
        graph.observe_direct_neighbor(UNI_RELAYER, -70, 8, 0, 0);
        graph.capability_mut().track_topology(UNI_RELAYER, true, 0);
        graph.capability_mut().track_topology(UNI_DEST, true, 0);
        graph.confirm_direct_neighbor_hears_us(UNI_RELAYER);
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed[..5], 8).unwrap();
        let us = PackedNeighbor {
            node_id: UNI_ME,
            rssi: -70,
            snr: 8,
            signal_routing_active: false,
            hears_us: true,
            etx_variance: 0,
        };
        let dest = PackedNeighbor {
            node_id: UNI_DEST,
            hears_us: false,
            ..us
        };
        router
            .graph_mut()
            .merge_topology(UNI_RELAYER, &header, &[dest, us], true, 0, 0);
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

    #[test]
    fn guessed_route_back_the_way_it_came_is_dropped() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unverified_gateway_graph(router, None);
        let wire = unicast_wire(2, 3, 0, 0xBB, 0x701);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(!scheduled, "carrying it moves the packet away from DEST");
        assert_eq!(reason, Some(SrSkipReason::UnverifiedBacktrack));
    }

    #[test]
    fn a_frame_named_for_us_is_forwarded_even_on_a_guessed_backtrack() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unverified_gateway_graph(router, None);
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

    fn named_followup_delay(router: &Router, wire: &[u8], nominated: u32) -> u32 {
        let cfg = eu868_config_for_preset(router.modem_preset());
        let airtime = packet_time_ms(&cfg, wire.len(), false).max(1);
        router.named_followup_delay_ms(nominated, airtime)
    }

    fn expect_named_repeat(router: &mut Router, sent: &ParsedPacket, id: u32, at: u32) -> u32 {
        let repeat = router.poll_reliable_retransmit(at).expect("repeat due");
        let hdr = PacketHeader::decode(&repeat.bytes[..PACKET_HEADER_LEN])
            .unwrap()
            .parse();
        assert_eq!(hdr.next_hop, sent.next_hop, "repeat names the same hop");
        assert_eq!(hdr.hop_limit, sent.hop_limit);
        assert_eq!(hdr.relay_node, sent.relay_node);
        assert!(router.has_pending_reliable(id), "redirect still to come");
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::RelayRetxRepeat { id: eid } if *eid == id)));
        at
    }

    #[test]
    fn forwarded_want_ack_unicast_is_repeated_then_dropped_without_alternate() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x601, true);
        let (sent, armed_at) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0xBB, "route to DEST goes via RELAYER");
        assert!(router.has_pending_reliable(0x601), "named follow-up armed");
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::RelayRetxArmed {
                id: 0x601,
                next_hop: 0xBB
            }
        )));

        let delay = named_followup_delay(router, &wire, UNI_RELAYER);
        let repeated_at = expect_named_repeat(router, &sent, 0x601, armed_at + delay);
        assert!(
            router
                .poll_reliable_retransmit(repeated_at + delay - 1)
                .is_none(),
            "redirect waits a full follow-up delay after the repeat"
        );
        assert!(
            router
                .poll_reliable_retransmit(repeated_at + delay)
                .is_none(),
            "no alternate: directed retry drops rather than flooding"
        );
        assert!(!router.has_pending_reliable(0x601));
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::RelayRetxNoAlternate { id: 0x601 })));
    }

    #[test]
    fn forwarded_unicast_without_want_ack_arms_repeat_and_redirect_not_flood() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x602, false);
        let (sent, armed_at) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0xBB);
        assert!(router.has_pending_reliable(0x602));
        let delay = named_followup_delay(router, &wire, UNI_RELAYER);
        let repeated_at = expect_named_repeat(router, &sent, 0x602, armed_at + delay);
        assert!(
            router
                .poll_reliable_retransmit(repeated_at + delay)
                .is_none(),
            "named hop silent with no alternate: nothing transmitted"
        );
        assert!(!router.has_pending_reliable(0x602));
    }

    #[test]
    fn named_forward_still_arms_followup_when_ranking_has_a_later_flood_slot() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_PEER, -70, 8, 0, 0);
        router
            .graph_mut()
            .capability_mut()
            .track_topology(UNI_PEER, true, 0);
        router
            .graph_mut()
            .confirm_direct_neighbor_hears_us(UNI_PEER);
        router.graph_mut().edges_mut().update_edge(
            UNI_ME,
            UNI_PEER,
            UNI_RELAYER,
            1.5,
            0,
            EdgeSource::Reported,
            true,
            0,
        );
        router
            .graph_mut()
            .edges_mut()
            .set_edge_hears_us(UNI_PEER, UNI_RELAYER, true);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x611, false);
        let (sent, _) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0xBB);
        assert!(
            router.has_pending_reliable(0x611),
            "named hop still arms a follow-up even if ranking assigned someone else a flood slot"
        );
    }

    fn assert_originator_retry_replanned(next_hop: u8, relay: u8, id: u32, router: &mut Router) {
        setup_unicast_graph(router);
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        let first = unicast_wire_ack(3, 3, 0x55, 0xDD, id, false);
        let _ = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &first,
                },
                0,
            )
            .unwrap();
        let retry = unicast_wire_ack(3, 3, next_hop, relay, id, false);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &retry,
                },
                100,
            )
            .unwrap();
        assert!(
            !result.duplicate,
            "originator retry next_hop={next_hop:#x} relay={relay:#x} must be re-planned"
        );
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::OriginatorRetryReplanned { id: eid } if *eid == id)));
    }

    #[test]
    fn originator_retry_replanned_next_hop_zero_relay_byte_matches() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        assert_originator_retry_replanned(0, 0xDD, 0x711, router);
    }

    #[test]
    fn originator_retry_replanned_next_hop_is_us() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        assert_originator_retry_replanned((UNI_ME & 0xFF) as u8, 0xDD, 0x712, router);
    }

    #[test]
    fn originator_retry_replanned_relay_byte_zero() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        assert_originator_retry_replanned(0, 0, 0x713, router);
    }

    #[test]
    fn relayed_flood_copy_and_foreign_named_retry_stay_duplicates() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let first = unicast_wire_ack(3, 3, 0x55, 0xDD, 0x702, false);
        let _ = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &first,
                },
                0,
            )
            .unwrap();
        let relayed = unicast_wire_ack(2, 3, 0, 0xAA, 0x702, false);
        assert!(
            router
                .process_inbound(
                    &InboundPacket {
                        radio_id: 0,
                        rssi: -70,
                        snr: 8,
                        bytes: &relayed,
                    },
                    50,
                )
                .unwrap()
                .duplicate
        );
        let named_other = unicast_wire_ack(3, 3, 0x55, 0xDD, 0x702, false);
        assert!(
            router
                .process_inbound(
                    &InboundPacket {
                        radio_id: 0,
                        rssi: -70,
                        snr: 8,
                        bytes: &named_other,
                    },
                    60,
                )
                .unwrap()
                .duplicate
        );
        let preserved = unicast_wire_ack(3, 3, 0, 0xAA, 0x702, false);
        assert!(
            router
                .process_inbound(
                    &InboundPacket {
                        radio_id: 0,
                        rssi: -70,
                        snr: 8,
                        bytes: &preserved,
                    },
                    70,
                )
                .unwrap()
                .duplicate
        );
    }

    #[test]
    fn named_followup_waits_for_our_airtime_and_ranked_slot_one() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x612, false);
        let (sent, armed_at) = forward_unicast(router, &wire, 1_000);
        assert_eq!(sent.next_hop, 0xBB);
        let cfg = eu868_config_for_preset(router.modem_preset());
        let airtime = packet_time_ms(&cfg, wire.len(), false).max(1);
        let half = coordinated_relay::half_airtime_ms(airtime);
        let own_tx = router.sr_peer_relay_wait_ms(airtime);
        let slot1_end = router.unicast_named_slot_delay_ms(1, 0, half, airtime)
            + coordinated_relay::tie_break_range_ms(half)
            + airtime;
        let carry = router.next_hop_carry_wait_ms(UNI_RELAYER, airtime);
        let delay = router.named_followup_delay_ms(UNI_RELAYER, airtime);
        assert!(
            delay >= own_tx + slot1_end,
            "{delay} < {own_tx} + {slot1_end}"
        );
        assert!(delay >= own_tx + carry, "{delay} < {own_tx} + {carry}");
        assert!(
            router
                .poll_reliable_retransmit(armed_at + delay - 1)
                .is_none(),
            "must not fire before our airtime and slot 1 have passed"
        );
        assert!(router.has_pending_reliable(0x612));
        expect_named_repeat(router, &sent, 0x612, armed_at + delay);
    }

    fn add_second_path(router: &mut Router, peer: u32) {
        router
            .graph_mut()
            .observe_direct_neighbor(peer, -70, 8, 0, 0);
        router
            .graph_mut()
            .capability_mut()
            .track_topology(peer, true, 0);
        router.graph_mut().confirm_direct_neighbor_hears_us(peer);
        router.graph_mut().edges_mut().update_edge(
            UNI_ME,
            peer,
            UNI_DEST,
            1.2,
            0,
            EdgeSource::Reported,
            true,
            0,
        );
        router
            .graph_mut()
            .edges_mut()
            .set_edge_hears_us(peer, UNI_DEST, true);
        router.graph_mut().edges_mut().update_edge(
            UNI_ME,
            UNI_DEST,
            peer,
            1.2,
            0,
            EdgeSource::Mirrored,
            true,
            0,
        );
    }

    #[test]
    fn named_forward_repeats_then_redirects_to_stampable_alternate() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        add_second_path(router, UNI_PEER);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x613, false);
        let (sent, armed_at) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0xBB);
        let delay = named_followup_delay(router, &wire, UNI_RELAYER);
        let repeated_at = expect_named_repeat(router, &sent, 0x613, armed_at + delay);
        let retx = router
            .poll_reliable_retransmit(repeated_at + delay)
            .expect("redirect due");
        let hdr = PacketHeader::decode(&retx.bytes[..PACKET_HEADER_LEN])
            .unwrap()
            .parse();
        assert_eq!(hdr.next_hop, (UNI_PEER & 0xFF) as u8);
        assert_eq!(hdr.hop_start, sent.hop_start);
        assert_eq!(hdr.hop_limit, sent.hop_limit);
        assert_eq!(hdr.relay_node, sent.relay_node);
        assert!(!router.has_pending_reliable(0x613));
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::RelayRetxRedirect { id: 0x613, next_hop } if *next_hop == hdr.next_hop
        )));
    }

    #[test]
    fn redirect_refuses_an_alternate_sharing_the_nominated_byte() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        add_second_path(router, 0xAB00_00BB);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x614, false);
        let (sent, armed_at) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0xBB);
        let delay = named_followup_delay(router, &wire, UNI_RELAYER);
        let repeated_at = expect_named_repeat(router, &sent, 0x614, armed_at + delay);
        assert!(router
            .poll_reliable_retransmit(repeated_at + delay)
            .is_none());
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::RelayRetxNoAlternate { id: 0x614 })));
    }

    #[test]
    fn redirect_refuses_a_stock_alternate() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        add_second_path(router, UNI_PEER);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x617, false);
        let (sent, armed_at) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0xBB);
        router.graph_mut().capability_mut().clear();
        let alt =
            router
                .graph
                .route_excluding(UNI_DEST, armed_at, &[UNI_RELAYER, UNI_SOURCE, UNI_ME]);
        assert_eq!(
            alt.next_hop, UNI_PEER,
            "precondition: PEER is still the alternate"
        );
        let delay = named_followup_delay(router, &wire, UNI_RELAYER);
        let repeated_at = expect_named_repeat(router, &sent, 0x617, armed_at + delay);
        assert!(router
            .poll_reliable_retransmit(repeated_at + delay)
            .is_none());
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::RelayRetxNoAlternate { id: 0x617 })));
    }

    #[test]
    fn upstream_and_originator_copies_keep_the_named_followup() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x615, false);
        let (sent, _) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0xBB);
        let retry = unicast_wire_ack(3, 3, 0, 0xDD, 0x615, false);
        let dupe = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &retry,
                },
                200,
            )
            .unwrap();
        assert!(dupe.duplicate);
        assert!(
            router.has_pending_reliable(0x615),
            "originator's copy must not cancel our follow-up"
        );
        let carried = unicast_wire_ack(2, 3, 0, 0xBB, 0x615, false);
        let _ = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &carried,
                },
                400,
            )
            .unwrap();
        assert!(!router.has_pending_reliable(0x615));
    }

    #[test]
    fn upstream_relay_copy_keeps_the_named_followup() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_PEER, -70, 8, 0, 0);
        let upstream_byte = (UNI_PEER & 0xFF) as u8;
        let wire = unicast_wire_ack(2, 3, 0, upstream_byte, 0x618, false);
        let (sent, _) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.next_hop, 0xBB);
        let _ = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &wire,
                },
                200,
            )
            .unwrap();
        assert!(
            router.has_pending_reliable(0x618),
            "upstream's copy must not cancel our follow-up"
        );
    }

    #[test]
    fn nominated_hop_copy_clears_its_suspect_state() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let _ = router.graph_mut().record_hop_miss(UNI_DEST, UNI_RELAYER, 0);
        let _ = router.graph_mut().record_hop_miss(UNI_DEST, UNI_RELAYER, 1);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x616, false);
        let (sent, _) = forward_unicast(router, &wire, 10);
        assert_eq!(sent.next_hop, 0xBB);
        let carried = unicast_wire_ack(2, 3, 0, 0xBB, 0x616, false);
        let _ = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &carried,
                },
                400,
            )
            .unwrap();
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs.iter().any(|e| matches!(
            e,
            SrLogEvent::NextHopHealthy {
                next_hop: UNI_RELAYER,
                destination: UNI_DEST
            }
        )));
    }

    #[test]
    fn suspect_first_hop_is_stamped_only_without_an_alternate() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        add_second_path(router, UNI_PEER);
        assert_eq!(
            router
                .graph_mut()
                .get_next_hop_verified(UNI_DEST, UNI_SOURCE, UNI_SOURCE, 0),
            (UNI_RELAYER, true)
        );
        let _ = router.graph_mut().record_hop_miss(UNI_DEST, UNI_RELAYER, 0);
        let _ = router.graph_mut().record_hop_miss(UNI_DEST, UNI_RELAYER, 1);
        assert_eq!(
            router
                .graph_mut()
                .get_next_hop_verified(UNI_DEST, UNI_SOURCE, UNI_SOURCE, 2),
            (UNI_PEER, true),
            "suspect hop gives way to a stampable alternate"
        );
    }

    #[test]
    fn unicast_to_us_is_acked_and_a_request_keeps_its_hop_budget() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        router
            .graph_mut()
            .capability_mut()
            .track_topology(UNI_SOURCE, true, 0);
        for (want_ack, id, hop_limit, hop_start) in
            [(false, 0x901u32, 3u8, 3u8), (true, 0x902u32, 2, 3)]
        {
            let (len, frame) = build_app_wire_frame(
                UNI_ME,
                UNI_SOURCE,
                id,
                router.channel_hash(),
                hop_limit,
                hop_start,
                want_ack,
                &key,
                mesh_protocol::portnum::num::TEXT_MESSAGE_APP,
                b"hi",
                DataEncodeOpts {
                    bitfield: router.ours(),
                    ..Default::default()
                },
                0,
            )
            .expect("frame");
            let inbound = InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 8,
                bytes: &frame[..len as usize],
            };
            let _ = router.process_inbound(&inbound, id).unwrap();
            if !want_ack {
                assert!(
                    router.poll_ack_tx(id).is_none(),
                    "unsolicited delivery has no ack"
                );
                let duplicate = router
                    .process_inbound(&inbound, id.wrapping_add(1))
                    .unwrap();
                assert!(duplicate.duplicate);
                assert!(
                    router.poll_ack_tx(id).is_none(),
                    "duplicate has no implicit ack"
                );
                continue;
            }
            let ack = router.poll_ack_tx(id).expect("requested ack");
            let hdr = PacketHeader::decode(&ack.bytes[..PACKET_HEADER_LEN])
                .unwrap()
                .parse();
            assert!(hdr.hop_limit > 0, "a requested ack keeps its hop budget");
            assert_eq!(hdr.to, UNI_SOURCE);
            assert_eq!(hdr.from, UNI_ME);
        }
    }

    #[test]
    fn heard_copy_cancels_forwarded_retries() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x603, true);
        let _ = forward_unicast(router, &wire, 0);
        assert!(router.has_pending_reliable(0x603));
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
    fn unrelated_peer_copy_keeps_the_nominated_followup() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x619, true);
        let _ = forward_unicast(router, &wire, 0);
        assert!(router.has_pending_reliable(0x619));
        let peer_copy = unicast_wire_ack(2, 3, 0, (UNI_PEER & 0xFF) as u8, 0x619, true);
        let dupe = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &peer_copy,
                },
                500,
            )
            .unwrap();
        assert!(dupe.duplicate);
        assert!(
            router.has_pending_reliable(0x619),
            "only the nominated hop cancels a nominated follow-up"
        );
    }

    #[test]
    fn reply_to_origin_cancels_forwarded_retries() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x604, true);
        let _ = forward_unicast(router, &wire, 0);
        assert!(router.has_pending_reliable(0x604));
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
        let origin = crate::coordinated_relay::relay_floor_ms(
            crate::coordinated_relay::slot_time_for_preset(router.modem_preset()),
        );
        assert!(
            router.poll_ready_relay(50 + origin - 1).is_none(),
            "slot 0 sits at the ladder origin, inside the peers' turnaround"
        );
        let jitter_max = coordinated_relay::tie_break_range_ms(coordinated_relay::half_airtime_ms(
            coordinated_relay::DEFAULT_SLOT_MS,
        ));
        let relay = router
            .poll_ready_relay(50 + origin + jitter_max)
            .expect("hand-off relay ready at slot 0");
        let hdr = PacketHeader::decode(&relay.bytes[..PACKET_HEADER_LEN])
            .unwrap()
            .parse();
        assert_eq!(hdr.next_hop, 0, "route pointed back at the relayer: flood");
        assert_eq!(hdr.relay_node, 0xCC);
        assert_eq!(hdr.hop_limit, 1);
        router.record_tx_on_air(UNI_SOURCE, 0x611, 50 + origin + 20);
        assert!(
            router.poll_ready_relay(50 + origin + 10_000).is_none(),
            "the first copy's later-slot frame was replaced, not queued behind the hand-off"
        );
    }

    #[test]
    fn designated_hop_forwards_even_when_our_route_points_back_at_the_relayer() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
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
        assert!(
            plan.relay.is_none(),
            "slot 0 is scheduled, never released inside the evaluation"
        );
        let floor = coordinated_relay::relay_floor_ms(coordinated_relay::slot_time_for_preset(
            router.modem_preset(),
        ));
        let scheduled_at = router
            .relay_tx_after(UNI_SOURCE, 0x705, 0)
            .expect("the designated hop must schedule");
        assert!(
            scheduled_at >= floor,
            "designated slot 0 must wait stock's contention floor: {scheduled_at} < {floor}"
        );
        assert!(
            router
                .poll_ready_relay(scheduled_at.saturating_sub(1))
                .is_none(),
            "must not release before its slot"
        );
        let relay = router
            .poll_ready_relay(scheduled_at)
            .expect("the designated hop must forward");
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

        let copy = unicast_wire(2, 3, (UNI_DEST & 0xFF) as u8, 0x99, 0x503);
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
    fn named_backup_cancels_on_designated_hop_when_finish_unknown() {
        const DESIG: u32 = 0x9900_0099;
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        router
            .graph_mut()
            .observe_direct_neighbor(DESIG, -80, 5, 0, 0);
        router.graph_mut().confirm_direct_neighbor_hears_us(DESIG);
        router
            .graph_mut()
            .capability_mut()
            .track_topology(DESIG, true, 0);
        router.remember_relay_identity(DESIG, 0x99, 0);

        let wire = unicast_wire(7, 7, 0x99, 0xDD, 0x509);
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
            "backup waits behind designated slot 0"
        );
        let tx_after = router
            .relay_tx_after(UNI_SOURCE, 0x509, 0)
            .expect("named backup armed");
        let flags = router.graph_mut().unicast_commit_flags(UNI_SOURCE, 0x509);
        assert_eq!(flags.designated_next_hop, 0x99);
        assert_eq!(flags.armed_hop_limit, 7);
        assert!(
            !router.graph_mut().unicast_dupe_cancels(
                0x509,
                UNI_DEST,
                UNI_RELAYER,
                0,
                Some(DESIG),
                crate::unicast_relay::UnicastSlotFlags::EMPTY,
                0,
                0,
                0,
            ),
            "without designation flags a non-finisher does not cancel"
        );

        let weak = unicast_wire(6, 7, 0, 0x99, 0x509);
        let weak_dupe = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &weak,
                },
                50,
            )
            .unwrap();
        assert!(weak_dupe.duplicate);
        assert!(
            router.relay_tx_after(UNI_SOURCE, 0x509, 0).is_some(),
            "weak flood from designated hop must not cancel the named backup"
        );

        let copy = unicast_wire(6, 7, (UNI_RELAYER & 0xFF) as u8, 0x99, 0x509);
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
            router.relay_tx_after(UNI_SOURCE, 0x509, 0).is_none(),
            "strong designated hop copy must cancel even when it cannot finish"
        );
        assert!(router.poll_ready_relay(tx_after + 1).is_none());
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::UnicastDupeCancel { id: 0x509, .. })));
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
        let (header, _) = decode_packed_neighbors(&packed[..5], 8).unwrap();
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

    #[test]
    fn named_backup_without_another_hop_does_not_relay() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire(3, 3, 0xBB, 0xDD, 0x507);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(!scheduled, "restamping the designated hop is not a backup");
        assert_eq!(reason, Some(SrSkipReason::NoRelayPath));

        static ROUTER2: StaticCell<Router> = StaticCell::new();
        let router = ROUTER2.init(Router::new(UNI_ME));
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_DEST, -90, 0, 0, 0);
        let wire = unicast_wire(3, 3, 0x99, 0xDD, 0x508);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(
            !scheduled,
            "a backup with nothing to stamp must stay silent"
        );
        assert_eq!(reason, Some(SrSkipReason::NoRelayPath));
    }

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
        let (header, _) = decode_packed_neighbors(&packed[..5], 8).unwrap();
        let heard = PackedNeighbor {
            node_id: UNI_ME,
            rssi: -70,
            snr: 8,
            signal_routing_active: true,
            hears_us: true,
            etx_variance: 0,
        };
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
        router.graph_mut().edges_mut().update_edge(
            UNI_ME,
            UNI_DEST,
            UNI_PEER,
            1.2,
            0,
            crate::graph::EdgeSource::Mirrored,
            true,
            0,
        );

        let wire = unicast_wire(2, 3, 0, 0xBB, 0x506);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(
            scheduled,
            "cannot finish at RELAYER: stay in ranking, not NextHopIsRelayer"
        );
        assert_ne!(reason, Some(SrSkipReason::NextHopIsRelayer));
        assert_ne!(reason, Some(SrSkipReason::UnverifiedBacktrack));
    }

    #[test]
    fn preset_switch_drops_stale_retransmits_and_relays() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x801, true);
        let (_, released_at) = forward_unicast(router, &wire, 0);
        assert!(router.has_pending_reliable(0x801));
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

        router.radio_reconfigured(released_at + 20, coordinated_relay::DEFAULT_SLOT_MS);

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

    fn preset_switch_router(from: u8, to: u8) -> Router {
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let mut router = Router::with_channel(UNI_ME, key, 0x77, from, true, 3);
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_DEST, -70, 8, 100, 0);
        router
            .graph_mut()
            .downstream_mut()
            .update(UNI_ME, UNI_SOURCE, UNI_DEST, 2.0, 100, false, 0);
        router.remember_relay_identity(UNI_DEST, (UNI_DEST & 0xFF) as u8, 100);
        let _ = router.route_to(UNI_DEST, 100);
        router.set_modem_preset("", to, true, key);
        router.radio_reconfigured(200, coordinated_relay::DEFAULT_SLOT_MS);
        router
    }

    #[test]
    fn preset_change_purges_graph_and_re_advertises_empty_boot_topology() {
        for &(from, to) in &[
            (mesh_radio::MODEM_LONG_FAST, mesh_radio::MODEM_SHORT_SLOW),
            (mesh_radio::MODEM_SHORT_SLOW, mesh_radio::MODEM_LONG_FAST),
        ] {
            let mut router = preset_switch_router(from, to);
            assert_eq!(
                router.graph_mut().neighbor_count(),
                0,
                "from {from} to {to}"
            );
            assert_eq!(router.graph_mut().downstream().count(), 0);
            assert_eq!(router.route_to(UNI_DEST, 300).next_hop, 0);
            assert_eq!(
                router.resolve_heard_from_node((UNI_DEST & 0xFF) as u8, UNI_SOURCE, -70, 8, 300),
                crate::graph::placeholder_node_id((UNI_DEST & 0xFF) as u8),
            );
            assert_eq!(router.topology_version(), 1);
            assert!(
                router.poll_topology_tx(200).is_some(),
                "empty boot list queued from {from} to {to}"
            );
        }
    }

    #[test]
    fn same_preset_reconfigure_does_not_purge_the_graph() {
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let mut router =
            Router::with_channel(UNI_ME, key, 0x77, mesh_radio::MODEM_LONG_FAST, true, 3);
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_DEST, -70, 8, 100, 0);
        router.set_modem_preset("", mesh_radio::MODEM_LONG_FAST, true, key);
        router.radio_reconfigured(200, coordinated_relay::DEFAULT_SLOT_MS);
        assert_eq!(router.graph_mut().neighbor_count(), 1);
        assert!(router.poll_topology_tx(200).is_none());
    }

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
        assert!(router.poll_ready_relay(tx_after).is_some());
        router.record_tx_on_air(UNI_SOURCE, 0x901, tx_after);
        let mut cancels = heapless::Vec::new();
        router.take_tx_cancels(&mut cancels);
        assert!(cancels.is_empty());

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
        assert_eq!(cancels.as_slice(), &[(UNI_SOURCE, 0x901)]);
        router.take_tx_cancels(&mut cancels);
        assert!(cancels.is_empty(), "reported once");
    }

    #[test]
    fn released_broadcast_relay_is_pulled_back_only_when_covered() {
        const ME: u32 = 0xCC00_00CC;
        const SRC: u32 = 0xDD00_00DD;
        const PEER: u32 = 0x1100_0011;
        const UNIQ: u32 = 0xEE00_00EE;
        const OTHER: u32 = 0x9900_0099;
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
            let (h, _) = decode_packed_neighbors(&packed[..5], 8).unwrap();
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
        let _plan = router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0);
        let tx_after = router
            .relay_tx_after(SRC, 0xB02, 0)
            .expect("our later slot");
        assert!(router.poll_ready_relay(tx_after).is_some());
        router.record_tx_on_air(SRC, 0xB02, tx_after);
        assert!(
            router.graph_mut().is_committed_relay(SRC, 0xB02),
            "relay outlives release"
        );

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
        assert_eq!(cancels.as_slice(), &[(SRC, 0xB02)]);
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
        router.note_tx_done(UNI_SOURCE, 0x902);
        assert!(!router.graph_mut().is_committed_relay(UNI_SOURCE, 0x902));
        assert!(!router.graph_mut().has_active_relay_commits());
    }

    #[test]
    fn reply_heard_pulls_the_queued_relay() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        let wire = unicast_wire_ack(3, 3, 0, 0xDD, 0x605, true);
        let (_, released_at) = forward_unicast(router, &wire, 0);
        router.record_tx_on_air(UNI_SOURCE, 0x605, released_at);
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
        assert_eq!(cancels.as_slice(), &[(UNI_SOURCE, 0x605)]);
        let mut logs = heapless::Vec::new();
        router.drain_sr_logs(&mut logs);
        assert!(logs
            .iter()
            .any(|e| matches!(e, SrLogEvent::UnicastReplyCancel { id: 0x605 })));
    }

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
        let (header, _) = decode_packed_neighbors(&packed[..5], 8).unwrap();
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
        let jitter = half_airtime_ms(coordinated_relay::DEFAULT_SLOT_MS).max(50) / 2;
        assert!(
            tx_after + jitter >= wait,
            "tx_after {tx_after} < ack wait {wait}"
        );

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

    #[test]
    fn routing_ack_from_a_remote_leaf_is_relayed_toward_the_originator() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        const HUB: u32 = 0x1080_006C;
        const LEAF: u32 = 0x49B5_E08C;
        const CITY: u32 = 0x63DC_8F8C;
        const ORIG: u32 = 0x979E_D146;
        let router = ROUTER.init(Router::new(HUB));
        let g = router.graph_mut();
        for n in [LEAF, CITY] {
            g.observe_direct_neighbor(n, -70, 8, 0, 0);
            g.confirm_direct_neighbor_hears_us(n);
            g.capability_mut().track_topology(n, true, 0);
        }
        g.capability_mut().track_topology(ORIG, true, 0);
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed[..5], 8).unwrap();
        let nb = |id: u32, hears: bool| PackedNeighbor {
            node_id: id,
            rssi: -70,
            snr: 8,
            signal_routing_active: true,
            hears_us: hears,
            etx_variance: 0,
        };
        g.merge_topology(CITY, &header, &[nb(ORIG, true), nb(HUB, true)], true, 0, 0);
        g.merge_topology(LEAF, &header, &[nb(ORIG, false), nb(HUB, true)], true, 0, 0);
        g.merge_topology(ORIG, &header, &[nb(CITY, true)], true, 0, 0);

        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let (len, ack) = build_ack_nak_frame(
            ORIG,
            LEAF,
            0x7008,
            0x2a29669d,
            router.channel_hash(),
            3,
            ROUTING_ERROR_NONE,
            &key,
            false,
            0,
        )
        .unwrap();
        let (scheduled, reason) = unicast_skip_reason(router, &ack[..len as usize]);
        assert!(
            scheduled,
            "hub must relay the leaf's Routing ACK toward the originator, got skip {reason:?}"
        );
        assert_ne!(reason, Some(SrSkipReason::ReplyRetracesLink));
    }

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
    fn the_destination_ack_wait_absorbs_the_contention_floor_rather_than_stacking() {
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
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_SOURCE, -70, 8, 0, 0);
        router.graph_mut().edges_mut().update_edge(
            UNI_ME,
            UNI_SOURCE,
            UNI_DEST,
            2.0,
            0,
            EdgeSource::Reported,
            true,
            0,
        );
        router
            .graph_mut()
            .edges_mut()
            .set_edge_hears_us(UNI_SOURCE, UNI_DEST, true);

        let wire = unicast_wire(3, 3, 0, 0xDD, 0x703);
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
        let airtime = coordinated_relay::DEFAULT_SLOT_MS;
        let plan = router.evaluate_tx_plan(&result, 0.0, airtime, 0);
        let ack_wait = router.dest_ack_wait_ms(airtime);
        let floor = coordinated_relay::relay_floor_ms(coordinated_relay::slot_time_for_preset(
            router.modem_preset(),
        ));
        assert!(
            ack_wait > floor,
            "premise: the ACK wait is the longer floor ({ack_wait} vs {floor})"
        );
        let tx_after = plan
            .relay
            .map(|r| r.delay_ms)
            .or_else(|| router.relay_tx_after(UNI_SOURCE, 0x703, 0))
            .expect("slot 0 planned");
        let tie_break =
            coordinated_relay::tie_break_range_ms(coordinated_relay::half_airtime_ms(airtime));
        assert!(
            tx_after >= ack_wait && tx_after <= ack_wait + tie_break,
            "slot 0 waits the ACK floor: {tx_after} not in {ack_wait}..={}",
            ack_wait + tie_break
        );
        assert!(
            tx_after < floor + ack_wait,
            "the two floors must not stack: {tx_after} reached {floor} + {ack_wait}"
        );
    }

    #[test]
    fn undesignated_flood_without_route_stays_silent_when_already_covered() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_SOURCE, -40, 12, 0, 0);
        router
            .graph_mut()
            .confirm_direct_neighbor_hears_us(UNI_SOURCE);
        router
            .graph_mut()
            .capability_mut()
            .track_topology(UNI_SOURCE, true, 0);
        router
            .graph_mut()
            .edges_mut()
            .ensure_local_node(UNI_DEST, 0);
        let wire = unicast_wire(7, 7, 0, 0xDD, 0x7a01);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(
            !scheduled,
            "silent expected, scheduled={scheduled} reason={reason:?}"
        );
        assert_eq!(reason, Some(SrSkipReason::AlreadyCovered));
    }

    #[test]
    fn designated_hop_with_no_route_nacks_originator() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        router.set_device_role(crate::nodeinfo::DEVICE_ROLE_ROUTER);
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_SOURCE, -40, 12, 0, 0);
        router
            .graph_mut()
            .confirm_direct_neighbor_hears_us(UNI_SOURCE);
        router
            .graph_mut()
            .edges_mut()
            .ensure_local_node(UNI_DEST, 0);
        let wire = unicast_wire(3, 3, (UNI_ME & 0xFF) as u8, 0xDD, 0x7a02);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(!scheduled, "no data relay when designated with no route");
        assert_eq!(reason, Some(SrSkipReason::NoRelayPath));
        let nak = router
            .poll_ack_tx(0)
            .expect("NO_ROUTE NAK queued for the originator");
        let hdr = PacketHeader::decode(&nak.bytes[..PACKET_HEADER_LEN])
            .unwrap()
            .parse();
        assert_eq!(hdr.to, UNI_SOURCE);
        assert_eq!(hdr.from, UNI_ME);
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        let mut cipher = nak.bytes[PACKET_HEADER_LEN..nak.len as usize].to_vec();
        let ch = hdr.channel;
        let (data, inner) =
            crate::topology::try_decrypt_data_full(&key, hdr.from, hdr.id, ch, ch, &mut cipher)
                .expect("NAK decrypts");
        assert_eq!(data.portnum, ROUTING_APP);
        assert_eq!(data.request_id, 0x7a02);
        let routing = decode_routing_payload(&inner).expect("routing payload");
        assert_eq!(routing.error_reason, Some(ROUTING_ERROR_NO_ROUTE));
    }

    #[test]
    fn undesignated_unicast_slot_zero_waits_stocks_contention_floor() {
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
        let floor = coordinated_relay::relay_floor_ms(coordinated_relay::slot_time_for_preset(
            router.modem_preset(),
        ));
        let tx_after = plan
            .relay
            .map(|r| r.delay_ms)
            .or_else(|| router.relay_tx_after(UNI_SOURCE, 0x702, 0))
            .expect("slot 0 planned");
        assert!(
            tx_after >= floor,
            "undesignated slot 0 must wait stock's contention floor: {tx_after} < {floor}"
        );
        assert!(
            router.poll_ready_relay(floor.saturating_sub(1)).is_none(),
            "must not release below the floor"
        );
        let jitter_max = coordinated_relay::tie_break_range_ms(coordinated_relay::half_airtime_ms(
            coordinated_relay::DEFAULT_SLOT_MS,
        ));
        assert!(
            router.poll_ready_relay(floor + jitter_max).is_some(),
            "slot 0 ready at the floor plus its tie-break"
        );
    }

    #[test]
    fn undesignated_unicast_later_slot_waits_for_leader_clear_when_floor_dominates() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        router.set_modem_preset(
            "",
            mesh_radio::MODEM_LONG_MODERATE,
            true,
            CryptoKey::from_bytes(&DEFAULT_PSK),
        );
        setup_unicast_graph(router);
        let airtime = 100u32;
        let wire = unicast_wire(3, 3, 0, 0xDD, 0x703);
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
        let _ = router.evaluate_tx_plan(&result, 0.0, airtime, 0);
        let tx_after = router
            .relay_tx_after(UNI_SOURCE, 0x703, 0)
            .expect("we hold a later slot behind RELAYER");
        let floor = coordinated_relay::relay_floor_ms(coordinated_relay::slot_time_for_preset(
            mesh_radio::MODEM_LONG_MODERATE,
        ));
        let peer = router.sr_peer_relay_wait_ms(airtime);
        assert!(
            floor > peer,
            "precondition: floor {floor} must exceed peer wait {peer}"
        );
        let leader_clear = peer.max(floor.saturating_add(airtime));
        assert!(
            tx_after >= leader_clear,
            "slot 1 undercut leader clear: {tx_after} < {leader_clear} (floor={floor}, peer={peer})"
        );
    }

    #[test]
    fn unicast_designated_sr_peer_uses_half_airtime_slot() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_PEER, -70, 8, 0, 0);
        router
            .graph_mut()
            .confirm_direct_neighbor_hears_us(UNI_PEER);
        router
            .graph_mut()
            .capability_mut()
            .track_topology(UNI_PEER, true, 0);
        let wire = unicast_wire(3, 3, (UNI_PEER & 0xFF) as u8, 0xDD, 0x505);
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
            .observe_direct_neighbor(UNI_DEST, -40, 12, 0, 0);
        let wire = unicast_wire(1, 1, 0, 0xDD, 0x505);
        let (scheduled, reason) = unicast_skip_reason(router, &wire);
        assert!(
            scheduled,
            "hop_limit 0 is fine when the next hop is the destination"
        );
        assert_eq!(reason, None);
    }

    #[test]
    fn last_hop_want_ack_retries_when_the_remaining_budget_is_one() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(UNI_ME));
        setup_unicast_graph(router);
        router
            .graph_mut()
            .observe_direct_neighbor(UNI_DEST, -40, 12, 0, 0);
        router
            .graph_mut()
            .confirm_direct_neighbor_hears_us(UNI_DEST);
        let wire = unicast_wire_ack(1, 1, 0, 0xDD, 0x507, true);
        let (sent, _) = forward_unicast(router, &wire, 0);
        assert_eq!(sent.hop_limit, 0);
        assert_eq!(sent.next_hop, (UNI_DEST & 0xFF) as u8);
        assert!(
            router.has_pending_reliable(0x507),
            "a hop-0 last hop arms a follow-up cancelled only by dest"
        );
    }

    #[test]
    fn packets_addressed_to_us_bypass_rate_limit() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(LAST_HOP_ME));
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
    #[test]
    fn local_packet_ids_are_unique_and_never_zero() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(1));
        router.seed_tx_ids(0);
        assert_eq!(router.alloc_tx_id(), 1);
        assert_eq!(router.alloc_tx_id(), 2);
        router.seed_tx_ids(u32::MAX);
        assert_eq!(router.alloc_tx_id(), u32::MAX);
        assert_eq!(router.alloc_tx_id(), 1);
    }

    #[test]
    fn queued_insurance_cancellation_is_scoped_to_originator() {
        static ROUTER: StaticCell<Router> = StaticCell::new();
        let router = ROUTER.init(Router::new(1));
        router.pending_retransmits[0].from = 2;
        router.pending_retransmits[0].packet_id = 42;
        router.pending_retransmits[0].active = true;
        router.cancel_broadcast_retransmit(3, 42);
        assert!(router.pending_retransmits[0].active);
        router.cancel_broadcast_retransmit(2, 42);
        assert!(!router.pending_retransmits[0].active);
    }
}
