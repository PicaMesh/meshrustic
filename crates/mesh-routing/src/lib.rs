//! Static routing infrastructure — zero heap.
#![no_std]
// Wire builders and graph observers take every header field as a plain argument (no heap,
// no allocation-free parameter structs worth the churn); the 8-11 argument signatures are
// intentional here.
#![allow(clippy::too_many_arguments)]

pub mod admin;
pub mod admin_codec;
pub mod bridge;
pub mod broadcast_relay;
pub mod capability;
pub mod coordinated_relay;
pub mod graph;
pub mod neighbor_graph;
pub mod nodeinfo;
pub mod packet_history;
pub mod pool;
pub mod qos;
pub mod rate_limit;
pub mod relay;
pub mod relay_identity;
pub mod reliable;
pub mod router;
pub mod routing_ack;
pub mod rx_decode;
pub mod sr_log;
pub mod sr_role;
pub mod telemetry;
pub mod topology;
pub mod traceroute;
pub mod unicast_relay;

pub use admin::{
    encode_admin_response, encode_owner_response, handle_admin, AdminOutcome, AdminState,
    ADMIN_PRESET_REBOOT_SECS, ADMIN_SESSION_TTL_MS, ROUTING_ERROR_ADMIN_BAD_SESSION_KEY,
    ROUTING_ERROR_ADMIN_PUBLIC_KEY_UNAUTHORIZED, ROUTING_ERROR_BAD_REQUEST,
    ROUTING_ERROR_PKI_FAILED, ROUTING_ERROR_PKI_UNKNOWN_PUBKEY,
};
pub use admin_codec::{
    decode_admin_message, decode_channel, decode_config, encode_admin_message, encode_channel,
    encode_config, AdminMessage, AdminPayload, ConfigPayload, DeviceMetadata, WireChannel,
    WireChannelSettings, WireDeviceConfig, WireLoRaConfig, WireSecurityConfig, ADMIN_APP,
    CHANNEL_ROLE_DISABLED, CHANNEL_ROLE_PRIMARY, CHANNEL_ROLE_SECONDARY, CONFIG_TYPE_DEVICE,
    CONFIG_TYPE_LORA, CONFIG_TYPE_SECURITY, CONFIG_TYPE_SESSIONKEY, MAX_ADMIN_KEYS, REGION_EU_868,
    SESSION_PASSKEY_LEN,
};
pub use bridge::{
    evaluate_bridge_targets, should_bridge_to, BridgeDedupCache, BridgeEval, BridgeLeg,
};
pub use broadcast_relay::{
    plan_broadcast_relay, BroadcastRelayContext, BroadcastRelayPlan, RelayCandidate, RelayReason,
    POOR_LINK_ETX_THRESHOLD,
};
pub use capability::{
    CapabilityCache, CapabilityStatus, CAPABILITY_TTL_MS, MAX_CAPABILITY_RECORDS,
};
pub use coordinated_relay::{
    cw_size_from_snr, half_airtime_ms, slot_time_for_preset, transmission_record_window_ms,
    tx_delay_ms_router, tx_delay_ms_worst, DEFAULT_SLOT_MS,
};
pub use graph::{
    calculate_etx, calculate_route, etx_to_fixed, etx_to_signal, find_better_positioned_neighbor,
    fixed_to_etx, get_placeholder_for_relay, is_node_routable, is_placeholder_node,
    placeholder_node_id, verified_connectivity, DownstreamTable, EdgeSource, RoutableFilter, Route,
    RouteCache, MAX_CACHED_ROUTES, MAX_DOWNSTREAM, MAX_EDGES_PER_NODE, PLACEHOLDER_NODE_PREFIX,
};
pub use neighbor_graph::{
    MaintenanceReport, NeighborEntry, NeighborGraph, TopologyMergeResult, MAX_HEARD_TRANSMITTERS,
    MAX_NEIGHBORS, MAX_RELAY_STATES, NEIGHBOR_TTL_MS,
};
pub use nodeinfo::{
    build_nodeinfo_reply_frame, build_nodeinfo_wire_frame, decode_user, encode_user,
    NodeInfoAdvert, NodeInfoCache, NodeInfoIdentity, NodeInfoPeerEntry, DEVICE_ROLE_CLIENT,
    DEVICE_ROLE_CLIENT_HIDDEN, DEVICE_ROLE_CLIENT_MUTE, DEVICE_ROLE_REPEATER, DEVICE_ROLE_ROUTER,
    DEVICE_ROLE_TRACKER, HW_MODEL_NRF52_PROMICRO_DIY, HW_MODEL_PRIVATE, MAX_NODEINFO_PEERS,
    NODEINFO_APP, NODEINFO_BROADCAST_MS, NODEINFO_REPLY_COOLDOWN_MS,
};
pub use packet_history::{ObserveResult, PacketHistory};
pub use pool::{PacketGuard, PacketHandle, PacketPool, PacketSlot, POOL_SIZE};
pub use qos::ChannelQoS;
pub use rate_limit::NodeRateLimiter;
pub use relay::{
    copy_opaque_payload, relay_header, relay_header_with_next_hop, relay_header_with_next_hop_opts,
    relay_hop_fields, wire_may_relay,
};
pub use relay_identity::{RelayIdentityCache, MAX_RELAY_IDENTITY_ENTRIES, RELAY_ID_CACHE_TTL_MS};
pub use reliable::{PendingReliable, MAX_PENDING_RELIABLE};
pub use router::{InboundPacket, ProcessResult, RelayPlan, Router, TxPlan, MAX_WIRE_LEN};
pub use routing_ack::{
    build_ack_nak_frame, decode_routing_payload, hop_limit_for_response, retransmission_delay_ms,
    RoutingDecode, NUM_RELIABLE_RETX, RETX_PROCESSING_TIME_MS, ROUTING_APP,
    ROUTING_ERROR_MAX_RETRANSMIT, ROUTING_ERROR_NONE, ROUTING_ERROR_NO_CHANNEL,
};
pub use rx_decode::{summarize_decrypted, RxDecodeInfo, RxPayloadSummary};
pub use sr_log::{
    RelayRetxCancelReason, SrLog, SrLogEvent, SrSkipReason, T1CancelReason, TopologyLogSink,
    MAX_SR_LOG,
};
pub use sr_role::{role_is_active_routing, role_is_mute, role_is_passive};
pub use telemetry::{
    battery_level_from_mv, build_device_telemetry_wire_frame, decode_device_metrics,
    extract_device_metrics, interpret_battery_reading, is_plausible_battery_reading,
    DecodedDeviceMetrics, DeviceMetricsSnapshot, DEVICE_TELEMETRY_BROADCAST_MS,
    MAGIC_USB_BATTERY_LEVEL, TELEMETRY_APP,
};
pub use topology::{
    build_app_wire_frame, build_topology_wire_frame, decode_data_payload, decode_data_payload_full,
    decode_packed_neighbors, encode_data_payload, encode_data_payload_opts,
    encode_packed_neighbor_entry, encode_signal_routing_info, extract_packed_neighbors,
    try_decrypt_data, try_decrypt_data_full, write_packed_header, DataEncodeOpts, DecodedData,
    PackedHeader, PackedNeighbor, MAX_NEIGHBORS_PER_PACKET, MAX_TOPOLOGY_PACKETS,
    PACKED_NEIGHBOR_HEADER_SIZE, SIGNAL_ROUTING_APP, SIGNAL_ROUTING_VERSION,
};
pub use traceroute::{
    alter_on_relay, decode_route_discovery, encode_route_discovery, rebuild_relay_ciphertext,
    RouteDiscovery, ROUTE_SIZE, TRACEROUTE_APP,
};
pub use unicast_relay::{
    plan_unicast_relay, UnicastCandidate, UnicastRelayContext, BEST_EFFORT_SELF_COST,
    COST_BUCKET_FIXED, DOWNSTREAM_TIER_COST, INDIRECT_TIER, MAX_UNICAST_CANDIDATES,
};
