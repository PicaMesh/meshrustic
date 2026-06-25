//! Static routing infrastructure — zero heap.
#![no_std]

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
pub mod routing_ack;
pub mod router;
pub mod rx_decode;
pub mod sr_log;
pub mod telemetry;
pub mod topology;
pub mod traceroute;

pub use bridge::{BridgeDedupCache, BridgeEval, BridgeLeg, evaluate_bridge_targets, should_bridge_to};
pub use broadcast_relay::{
    find_best_relay_candidate as rank_broadcast_relay_candidate, plan_broadcast_relay,
    BroadcastRelayContext, BroadcastRelayPlan, RelayCandidate, POOR_LINK_ETX_THRESHOLD,
};
pub use capability::{CapabilityStatus, CapabilityCache, CAPABILITY_TTL_MS, MAX_CAPABILITY_RECORDS};
pub use coordinated_relay::{
    cw_size_from_snr, half_airtime_ms, slot_time_for_preset, tx_delay_ms_router, tx_delay_ms_worst,
    DEFAULT_SLOT_MS,
};
pub use graph::{
    calculate_etx, calculate_route, etx_to_signal, find_better_positioned_neighbor, DownstreamTable,
    EdgeSource, get_placeholder_for_relay, is_node_routable, is_placeholder_node, placeholder_node_id, verified_connectivity,
    Route, RouteCache, RoutableFilter, PLACEHOLDER_NODE_PREFIX, MAX_CACHED_ROUTES,
    MAX_DOWNSTREAM, MAX_EDGES_PER_NODE,
};
pub use neighbor_graph::{
    MaintenanceReport, NeighborEntry, NeighborGraph, TopologyMergeResult, MAX_HEARD_TRANSMITTERS,
    MAX_NEIGHBORS, MAX_RELAY_STATES, NEIGHBOR_TTL_MS,
};
pub use packet_history::{ObserveResult, PacketHistory};
pub use pool::{PacketGuard, PacketHandle, PacketPool, PacketSlot, POOL_SIZE};
pub use qos::ChannelQoS;
pub use rate_limit::NodeRateLimiter;
pub use relay::{copy_opaque_payload, relay_header, relay_header_with_next_hop, wire_may_relay};
pub use relay_identity::{RelayIdentityCache, RELAY_ID_CACHE_TTL_MS, MAX_RELAY_IDENTITY_ENTRIES};
pub use reliable::{PendingReliable, MAX_PENDING_RELIABLE};
pub use routing_ack::{
    build_ack_nak_frame, decode_routing_payload, hop_limit_for_response, retransmission_delay_ms,
    RoutingDecode, ROUTING_APP, ROUTING_ERROR_MAX_RETRANSMIT, ROUTING_ERROR_NONE,
    ROUTING_ERROR_NO_CHANNEL, NUM_RELIABLE_RETX,
};
pub use router::{InboundPacket, ProcessResult, RelayPlan, Router, TxPlan, MAX_WIRE_LEN};
pub use rx_decode::{summarize_decrypted, RxDecodeInfo, RxPayloadSummary};
pub use sr_log::{SrLog, SrLogEvent, SrSkipReason, TopologyLogSink, T1CancelReason, MAX_SR_LOG};
pub use nodeinfo::{
    build_nodeinfo_reply_frame, build_nodeinfo_wire_frame, decode_user, encode_user,
    NodeInfoAdvert, NodeInfoCache, NodeInfoIdentity, NodeInfoPeerEntry, DEVICE_ROLE_CLIENT,
    DEVICE_ROLE_CLIENT_MUTE, DEVICE_ROLE_REPEATER, DEVICE_ROLE_ROUTER, HW_MODEL_NRF52_PROMICRO_DIY,
    HW_MODEL_PRIVATE, MAX_NODEINFO_PEERS,
    NODEINFO_APP, NODEINFO_BROADCAST_MS, NODEINFO_REPLY_COOLDOWN_MS,
};
pub use telemetry::{
    battery_level_from_mv, build_device_telemetry_wire_frame, decode_device_metrics,
    extract_device_metrics, interpret_battery_reading, is_plausible_battery_reading,
    DeviceMetricsSnapshot, DecodedDeviceMetrics, DEVICE_TELEMETRY_BROADCAST_MS,
    MAGIC_USB_BATTERY_LEVEL, TELEMETRY_APP,
};
pub use topology::{
    build_app_wire_frame, build_topology_wire_frame, decode_data_payload, decode_data_payload_full, decode_packed_neighbors,
    encode_data_payload, encode_data_payload_opts, encode_signal_routing_info,
    extract_packed_neighbors, try_decrypt_data, try_decrypt_data_full, write_packed_header,
    DataEncodeOpts, DecodedData, PackedHeader, PackedNeighbor, MAX_NEIGHBORS_PER_PACKET,
    MAX_TOPOLOGY_PACKETS, PACKED_NEIGHBOR_HEADER_SIZE, SIGNAL_ROUTING_APP,
    SIGNAL_ROUTING_VERSION,
};
pub use traceroute::{
    alter_on_relay, decode_route_discovery, encode_route_discovery, rebuild_relay_ciphertext,
    RouteDiscovery, TRACEROUTE_APP, ROUTE_SIZE,
};
