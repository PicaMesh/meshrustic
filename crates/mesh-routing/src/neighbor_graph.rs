//! Topology graph and per-radio relay commit state (Phase 6 SR).

use mesh_protocol::{is_direct_packet, NODENUM_BROADCAST};
use mesh_radio::{RadioId, MODEM_DEFAULT_PRESET};

use crate::capability::{role_may_send_topology, CapabilityCache, CapabilityStatus};
use crate::coordinated_relay::slot_tie_break_ms;
use crate::graph::{
    calculate_etx, calculate_route, find_better_positioned_neighbor, is_node_routable,
    is_placeholder_node, placeholder_node_id, verified_connectivity, DownstreamTable, EdgeSource,
    EdgeStore, RoutableFilter, Route, RouteCache, EDGE_NEW, EDGE_SIGNIFICANT_CHANGE,
    MAX_EDGES_PER_NODE,
};
use crate::nodeinfo::{DEVICE_ROLE_CLIENT, DEVICE_ROLE_ROUTER, DEVICE_ROLE_ROUTER_LATE};
use crate::sr_role::role_is_active_routing;
use crate::topology::{
    write_packed_header, write_packed_header_chunk, PackedHeader, PackedNeighbor,
    MAX_NEIGHBORS_PER_PACKET, PACKED_NEIGHBOR_ENTRY_SIZE, PACKED_NEIGHBOR_FLAG_HEARS_US,
    PACKED_NEIGHBOR_FLAG_SR_ACTIVE, PACKED_NEIGHBOR_HEADER_SIZE, SIGNAL_ROUTING_VERSION,
};

pub const MAX_NEIGHBORS: usize = MAX_EDGES_PER_NODE;
pub const MAX_RELAY_STATES: usize = 32;
pub const MAX_HEARD_TRANSMITTERS: usize = 6;
pub const MAX_TOPOLOGY_VERSION_ENTRIES: usize = MAX_NEIGHBORS;
pub const TOPOLOGY_BROADCAST_MS: u32 = 600_000;
pub const TOPOLOGY_DIRTY_MIN_MS: u32 = 300_000;
/// No accepted report from a peer for this long: accept whatever version it sends next. Covers a
/// peer whose reboot broadcast we missed, a peer that came back with a moved-on counter, and a
/// receiver that was itself away. Twice the periodic interval.
pub const TOPOLOGY_RESYNC_MS: u32 = 2 * TOPOLOGY_BROADCAST_MS;
/// Nominal link assumed for edges inferred from relayed packets.
pub const INFERRED_LINK_RSSI: i32 = -70;
pub const INFERRED_LINK_SNR: f32 = 5.0;
pub const MAINTENANCE_LOG_MS: u32 = 60_000;
pub const NEIGHBOR_TTL_MS: u32 = 7_200_000;

/// Legacy SHORT_SLOW contention window; live retention uses `transmission_record_window_ms`.
pub const NODE_TX_RECORD_MS: u32 = 2_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeighborEntry {
    pub node_id: u32,
    pub rssi: i16,
    pub snr: i8,
    pub last_seen_ms: u32,
    pub signal_routing_active: bool,
    pub hears_us: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DirectNeighborSignal {
    node_id: u32,
    rssi: i16,
    snr: i8,
    last_rx_ms: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RelayCommit {
    active: bool,
    from: u32,
    id: u32,
    radio_id: u8,
    tx_after_ms: u32,
    snr: i8,
    original_heard_from: u32,
    heard_transmitters: [u32; MAX_HEARD_TRANSMITTERS],
    heard_transmitter_count: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TopologyVersionEntry {
    node_id: u32,
    version: u8,
    /// When we last accepted a report from this node (0 = never).
    last_accept_ms: u32,
    /// Version of the last report we rejected as stale, if any: a rebooted peer whose boot
    /// broadcast we missed shows as rejected versions climbing one by one.
    stale_version: u8,
    stale_valid: bool,
}

/// Neighbour ids listed so far by a multi-chunk topology report. The "unlisted neighbour does not
/// hear the sender" rule needs the whole list, so ids are gathered across chunks and the rule runs
/// on the last one; a chunk whose first packet was missed leaves the flags untouched.
#[derive(Clone, Copy, Debug)]
struct PendingListed {
    sender: u32,
    version: u8,
    count: u8,
    valid: bool,
    ids: [u32; MAX_NEIGHBORS],
}

/// Multi-chunk reports gathered at once; hubs with more than 28 neighbours are few.
const PENDING_LISTED_SLOTS: usize = 4;

impl PendingListed {
    const EMPTY: PendingListed = PendingListed {
        sender: 0,
        version: 0,
        count: 0,
        valid: false,
        ids: [0; MAX_NEIGHBORS],
    };
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NodeTxRecord {
    node_id: u32,
    packet_id: u32,
    at_ms: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    pub topology_due: bool,
    pub topology_dirty_send: bool,
    pub neighbors: u8,
    pub graph_log_due: bool,
    pub graph_aged: Option<(u8, u8)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopologyMergeResult {
    Applied { neighbors: u8, topo_v: u8 },
    Stale { received: u8, last: u8 },
    IgnoredFormat,
}

const MAX_OUR_TX_RECORDS: usize = 16;
const MAX_NODE_TX_RECORDS: usize = 32;

/// Hop budget of a last-hop unicast (see `NeighborGraph::caps_last_hop`): one hop, so the
/// destination reads it as direct (`hop_start == hop_limit`, or one hop used on a relay) and
/// every receiver sees a populated `hop_start`; the named next hop keeps stock relays out.
pub const LAST_HOP_BUDGET: u8 = 1;

pub struct NeighborGraph {
    my_node: u32,
    device_role: u32,
    modem_preset: u8,
    edges: EdgeStore,
    downstream: DownstreamTable,
    relay_states: [RelayCommit; MAX_RELAY_STATES],
    topo_versions: [TopologyVersionEntry; MAX_TOPOLOGY_VERSION_ENTRIES],
    /// Set when a report was accepted outside the forward version window (peer reboot or long
    /// silence): (sender, received version, previously stored version). Taken by the router for the log.
    last_version_resync: Option<(u32, u8, u8)>,
    /// Listed neighbour ids of multi-chunk reports still being received, one slot per sender
    /// (see `merge_topology`). A single slot let any other node's report invalidate a hub's list.
    pending_listed: [PendingListed; PENDING_LISTED_SLOTS],
    topo_version_count: u8,
    topology_version: u8,
    topology_dirty: bool,
    last_topology_ms: u32,
    last_topology_list_ms: u32,
    last_maintenance_ms: u32,
    signal_routing_active: bool,
    our_tx: [NodeTxRecord; MAX_OUR_TX_RECORDS],
    our_tx_count: u8,
    node_tx: [NodeTxRecord; MAX_NODE_TX_RECORDS],
    node_tx_count: u8,
    route_cache: RouteCache,
    capability: CapabilityCache,
    direct_signals: [DirectNeighborSignal; MAX_NEIGHBORS],
    direct_signal_count: u8,
    merge_asymmetric_skips: [(u32, u32); 4],
    merge_asymmetric_skip_count: u8,
}

impl Default for NeighborGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl NeighborGraph {
    pub const fn new() -> Self {
        Self {
            my_node: 0,
            device_role: DEVICE_ROLE_CLIENT,
            modem_preset: MODEM_DEFAULT_PRESET,
            edges: EdgeStore::new(),
            downstream: DownstreamTable::new(),
            relay_states: [RelayCommit {
                active: false,
                from: 0,
                id: 0,
                radio_id: 0,
                tx_after_ms: 0,
                snr: 0,
                original_heard_from: 0,
                heard_transmitters: [0; MAX_HEARD_TRANSMITTERS],
                heard_transmitter_count: 0,
            }; MAX_RELAY_STATES],
            topo_versions: [TopologyVersionEntry {
                node_id: 0,
                version: 0,
                last_accept_ms: 0,
                stale_version: 0,
                stale_valid: false,
            }; MAX_TOPOLOGY_VERSION_ENTRIES],
            topo_version_count: 0,
            last_version_resync: None,
            pending_listed: [PendingListed::EMPTY; PENDING_LISTED_SLOTS],
            topology_version: 0,
            topology_dirty: false,
            last_topology_ms: 0,
            last_topology_list_ms: 0,
            last_maintenance_ms: 0,
            signal_routing_active: true,
            our_tx: [NodeTxRecord {
                node_id: 0,
                packet_id: 0,
                at_ms: 0,
            }; MAX_OUR_TX_RECORDS],
            our_tx_count: 0,
            node_tx: [NodeTxRecord {
                node_id: 0,
                packet_id: 0,
                at_ms: 0,
            }; MAX_NODE_TX_RECORDS],
            node_tx_count: 0,
            route_cache: RouteCache::new(),
            capability: CapabilityCache::new(),
            direct_signals: [DirectNeighborSignal {
                node_id: 0,
                rssi: 0,
                snr: 0,
                last_rx_ms: 0,
            }; MAX_NEIGHBORS],
            direct_signal_count: 0,
            merge_asymmetric_skips: [(0, 0); 4],
            merge_asymmetric_skip_count: 0,
        }
    }

    pub const fn set_my_node(&mut self, node_id: u32) {
        self.my_node = node_id;
    }

    pub fn my_node(&self) -> u32 {
        self.my_node
    }

    pub fn edges(&self) -> &EdgeStore {
        &self.edges
    }

    #[doc(hidden)]
    pub fn edges_mut(&mut self) -> &mut EdgeStore {
        &mut self.edges
    }

    pub fn is_our_direct_neighbor(&self, node_id: u32) -> bool {
        self.edges.is_our_direct_neighbor(node_id, self.my_node)
    }

    /// Is a unicast to `destination` a last hop: the destination is a direct neighbour that
    /// hears us and stock neighbours are listening? Such a frame goes out with
    /// [`LAST_HOP_BUDGET`] and the destination named as next hop, so stock neighbours (which
    /// relay a unicast only when the next hop is unset or their own byte) leave it alone while
    /// the destination still reads it as a direct, ACK-worthy frame. Among SR peers only, the
    /// slot coordination suppresses relays by itself and the budget stays untouched.
    pub fn caps_last_hop(&self, destination: u32) -> bool {
        if destination == 0 || destination == NODENUM_BROADCAST {
            return false;
        }
        let Some(my_edges) = self.edges.find_node(self.my_node) else {
            return false;
        };
        let dest_hears_us = (0..my_edges.edge_count as usize)
            .map(|i| my_edges.edges[i])
            .any(|edge| edge.to == destination && edge.hears_us);
        if !dest_hears_us {
            return false;
        }

        let mut has_stock_neighbor = false;
        for i in 0..my_edges.edge_count as usize {
            let neighbor = my_edges.edges[i].to;
            if neighbor == 0 || neighbor == destination {
                continue;
            }
            if self.capability.status(neighbor) != CapabilityStatus::SrActive {
                has_stock_neighbor = true;
                break;
            }
        }
        has_stock_neighbor
    }

    #[doc(hidden)]
    pub fn downstream_mut(&mut self) -> &mut DownstreamTable {
        &mut self.downstream
    }

    /// Outgoing edge whose destination low byte matches `relay_byte` (non-placeholder preferred).
    pub fn match_relay_byte_on_outgoing_edges(&self, relay_byte: u8) -> Option<u32> {
        let node = self.edges.find_node(self.my_node)?;
        for i in 0..node.edge_count as usize {
            let to = node.edges[i].to;
            if (to & 0xFF) as u8 != relay_byte {
                continue;
            }
            if !is_placeholder_node(to) {
                return Some(to);
            }
        }
        None
    }

    pub fn match_relay_placeholder_on_outgoing_edges(&self, relay_byte: u8) -> Option<u32> {
        let node = self.edges.find_node(self.my_node)?;
        for i in 0..node.edge_count as usize {
            let to = node.edges[i].to;
            if (to & 0xFF) as u8 == relay_byte && is_placeholder_node(to) {
                return Some(to);
            }
        }
        None
    }

    pub fn update_node_activity(&mut self, node_id: u32, now_ms: u32) {
        self.edges
            .update_node_activity(node_id, now_ms, self.my_node);
    }

    pub fn set_device_role(&mut self, role: u32) {
        self.device_role = role;
        self.signal_routing_active = role_is_active_routing(role);
    }

    pub fn device_role(&self) -> u32 {
        self.device_role
    }

    pub const fn set_modem_preset(&mut self, modem_preset: u8) {
        self.modem_preset = modem_preset;
    }

    pub fn modem_preset(&self) -> u8 {
        self.modem_preset
    }

    fn node_tx_record_window_ms(&self) -> u32 {
        crate::coordinated_relay::transmission_record_window_ms(self.modem_preset)
    }

    pub fn is_active_routing_role(&self) -> bool {
        role_is_active_routing(self.device_role)
    }

    pub fn can_send_topology(&self) -> bool {
        role_may_send_topology(self.device_role)
    }

    pub fn track_node_role(&mut self, node_id: u32, role: u32, now_ms: u32) {
        self.capability.track_role(node_id, role, now_ms);
    }

    #[doc(hidden)]
    pub fn capability_mut(&mut self) -> &mut CapabilityCache {
        &mut self.capability
    }

    pub fn capability(&self) -> &CapabilityCache {
        &self.capability
    }

    pub fn downstream(&self) -> &DownstreamTable {
        &self.downstream
    }

    pub fn capability_status(&self, node_id: u32) -> CapabilityStatus {
        self.capability_status_at(node_id, 0)
    }

    pub fn capability_status_at(&self, node_id: u32, now_ms: u32) -> CapabilityStatus {
        if node_id == self.my_node && self.my_node != 0 {
            return self.local_capability_status();
        }
        self.capability.status_at(node_id, self.my_node, now_ms)
    }

    fn local_capability_status(&self) -> CapabilityStatus {
        if self.is_active_routing_role() {
            CapabilityStatus::SrActive
        } else if self.can_send_topology() {
            CapabilityStatus::Passive
        } else {
            CapabilityStatus::Legacy
        }
    }

    pub fn record_our_transmission(&mut self, packet_id: u32, now_ms: u32) {
        if packet_id == 0 {
            return;
        }
        for i in 0..self.our_tx_count as usize {
            if self.our_tx[i].node_id == self.my_node && self.our_tx[i].packet_id == packet_id {
                self.our_tx[i].at_ms = now_ms;
                return;
            }
        }
        if (self.our_tx_count as usize) < MAX_OUR_TX_RECORDS {
            let idx = self.our_tx_count as usize;
            self.our_tx[idx] = NodeTxRecord {
                node_id: self.my_node,
                packet_id,
                at_ms: now_ms,
            };
            self.our_tx_count += 1;
            return;
        }
        for i in 1..MAX_OUR_TX_RECORDS {
            self.our_tx[i - 1] = self.our_tx[i];
        }
        self.our_tx[MAX_OUR_TX_RECORDS - 1] = NodeTxRecord {
            node_id: self.my_node,
            packet_id,
            at_ms: now_ms,
        };
    }

    pub fn has_our_transmission(&self, packet_id: u32) -> bool {
        for i in 0..self.our_tx_count as usize {
            if self.our_tx[i].node_id == self.my_node && self.our_tx[i].packet_id == packet_id {
                return true;
            }
        }
        false
    }

    pub fn record_node_transmission(&mut self, node_id: u32, packet_id: u32, now_ms: u32) {
        if node_id == 0 || packet_id == 0 {
            return;
        }
        for i in 0..self.node_tx_count as usize {
            if self.node_tx[i].node_id == node_id && self.node_tx[i].packet_id == packet_id {
                self.node_tx[i].at_ms = now_ms;
                return;
            }
        }
        if (self.node_tx_count as usize) < MAX_NODE_TX_RECORDS {
            let idx = self.node_tx_count as usize;
            self.node_tx[idx] = NodeTxRecord {
                node_id,
                packet_id,
                at_ms: now_ms,
            };
            self.node_tx_count += 1;
            return;
        }
        let oldest = self.oldest_node_tx_index(now_ms);
        self.node_tx[oldest] = NodeTxRecord {
            node_id,
            packet_id,
            at_ms: now_ms,
        };
    }

    pub fn has_node_transmitted(&self, node_id: u32, packet_id: u32, now_ms: u32) -> bool {
        let window = self.node_tx_record_window_ms();
        for i in 0..self.node_tx_count as usize {
            let rec = self.node_tx[i];
            if rec.node_id == node_id
                && rec.packet_id == packet_id
                && now_ms.wrapping_sub(rec.at_ms) <= window
            {
                return true;
            }
        }
        false
    }

    /// Remember that we heard the source and optional relayer on-air for `packet_id`.
    ///
    /// Skips zero ids, self, and placeholder nodes so slot planning tracks real transmitters.
    pub fn record_heard_transmissions(
        &mut self,
        source: u32,
        packet_id: u32,
        relayer: Option<u32>,
        now_ms: u32,
    ) {
        if packet_id == 0 {
            return;
        }
        if source != 0 && source != self.my_node && !is_placeholder_node(source) {
            self.record_node_transmission(source, packet_id, now_ms);
        }
        if let Some(relay) = relayer {
            if relay != 0 && relay != self.my_node && relay != source && !is_placeholder_node(relay)
            {
                self.record_node_transmission(relay, packet_id, now_ms);
            }
        }
    }

    fn oldest_node_tx_index(&self, now_ms: u32) -> usize {
        let mut oldest_idx = 0usize;
        let mut oldest_age = now_ms.wrapping_sub(self.node_tx[0].at_ms);
        for i in 1..self.node_tx_count as usize {
            let age = now_ms.wrapping_sub(self.node_tx[i].at_ms);
            if age > oldest_age {
                oldest_idx = i;
                oldest_age = age;
            }
        }
        oldest_idx
    }

    pub fn apply_topology_hears_us(
        &mut self,
        sender: u32,
        our_node: u32,
        neighbors: &[PackedNeighbor],
    ) {
        for neighbor in neighbors {
            if neighbor.node_id == our_node && neighbor.hears_us {
                self.edges.set_edge_hears_us(sender, our_node, true);
                return;
            }
        }
    }

    pub fn graph_node_count(&self) -> u8 {
        self.edges.node_count()
    }

    pub fn has_graph_node(&self, node_id: u32) -> bool {
        self.edges.find_node(node_id).is_some()
    }

    pub fn neighbor_count(&self) -> u8 {
        self.edges.count_direct_neighbors(self.my_node)
    }

    /// True when we have at least one direct neighbor that could participate in SR broadcast routing.
    pub fn topology_healthy_for_broadcast(&self) -> bool {
        if self.my_node == 0 {
            return false;
        }
        let Some(node) = self.edges.find_node(self.my_node) else {
            return false;
        };
        if node.edge_count == 0 {
            return false;
        }
        let mut capable = 0u8;
        for i in 0..node.edge_count as usize {
            let neighbor = node.edges[i].to;
            if neighbor == 0 {
                continue;
            }
            if is_placeholder_node(neighbor) {
                continue;
            }
            match self.capability.status(neighbor) {
                CapabilityStatus::SrActive | CapabilityStatus::Unknown => {
                    capable = capable.saturating_add(1);
                }
                _ if self.capability.is_legacy_router(neighbor) => {
                    capable = capable.saturating_add(1);
                }
                _ => {}
            }
        }
        capable >= 1
    }

    /// True when `destination` is reachable via the topology graph or a downstream relay chain.
    pub fn topology_healthy_for_unicast(&mut self, destination: u32, now_ms: u32) -> bool {
        if self.my_node == 0 || destination == 0 || destination == self.my_node {
            return false;
        }
        let route = self.get_route(destination, now_ms);
        if route.next_hop != 0 {
            return true;
        }
        let Some(relay) = self.get_downstream_relay(destination, now_ms) else {
            return false;
        };
        self.get_route(relay, now_ms).next_hop != 0
    }

    pub fn is_known_relay_target(&self, destination: u32, now_ms: u32) -> bool {
        self.has_graph_node(destination) || self.get_downstream_relay(destination, now_ms).is_some()
    }

    pub fn topology_version(&self) -> u8 {
        self.topology_version
    }

    pub fn signal_routing_active(&self) -> bool {
        self.signal_routing_active
    }

    pub fn mark_topology_dirty(&mut self) {
        self.topology_dirty = true;
    }

    pub fn notify_originated_packet_sent(&mut self, now_ms: u32) {
        self.last_topology_ms = self
            .last_topology_ms
            .saturating_sub(TOPOLOGY_BROADCAST_MS / 2);
        let _ = now_ms;
    }

    pub fn relay_slot_index(&self, packet_id: u32, heard_from: u32, now_ms: u32) -> (u8, u8) {
        let mut stock = [0u32; MAX_EDGES_PER_NODE];
        let stock_n = self.fill_stock_relay_candidates(packet_id, heard_from, now_ms, &mut stock);
        let mut sr = [0u32; MAX_EDGES_PER_NODE + 1];
        let sr_n = self.fill_sr_relay_candidates(packet_id, heard_from, now_ms, &mut sr);
        let sr_index = sr[..sr_n as usize]
            .iter()
            .position(|&n| n == self.my_node)
            .map_or(0, |i| i as u8);
        let total = stock_n.saturating_add(sr_n).max(1);
        (stock_n.saturating_add(sr_index), total)
    }

    /// Best broadcast relay candidate: stock routers first, then SR peers (sorted by node id).
    pub fn find_best_relay_candidate(&self, packet_id: u32, heard_from: u32, now_ms: u32) -> u32 {
        let mut stock = [0u32; MAX_EDGES_PER_NODE];
        let stock_n = self.fill_stock_relay_candidates(packet_id, heard_from, now_ms, &mut stock);
        for &candidate in &stock[..stock_n as usize] {
            if !self.has_node_transmitted(candidate, packet_id, now_ms) {
                return candidate;
            }
        }
        let mut sr = [0u32; MAX_EDGES_PER_NODE + 1];
        let sr_n = self.fill_sr_relay_candidates(packet_id, heard_from, now_ms, &mut sr);
        for &candidate in &sr[..sr_n as usize] {
            if !self.has_node_transmitted(candidate, packet_id, now_ms) {
                return candidate;
            }
        }
        0
    }

    /// Phased broadcast relay schedule (stock early slots → ranked SR → downstream).
    pub fn plan_broadcast_relay(
        &self,
        packet_id: u32,
        source: u32,
        heard_from: u32,
        broadcast_dest: u32,
        now_ms: u32,
        half_airtime_ms: u32,
    ) -> crate::broadcast_relay::BroadcastRelayPlan {
        let ctx = crate::broadcast_relay::BroadcastRelayContext {
            my_node: self.my_node,
            my_node_relays: self.is_rebroadcaster(),
            edges: &self.edges,
            capability: &self.capability,
            downstream: &self.downstream,
        };
        crate::broadcast_relay::plan_broadcast_relay(
            &ctx,
            packet_id,
            source,
            heard_from,
            broadcast_dest,
            now_ms,
            half_airtime_ms,
            |node| self.has_node_transmitted(node, packet_id, now_ms),
        )
    }

    /// Cost-ranked slot for a unicast we overheard (see `unicast_relay`).
    pub fn plan_unicast_relay(
        &self,
        packet_id: u32,
        source: u32,
        heard_from: u32,
        destination: u32,
        my_next_hop: u32,
        now_ms: u32,
    ) -> Result<crate::broadcast_relay::BroadcastRelayPlan, crate::sr_log::SrSkipReason> {
        let ctx = crate::unicast_relay::UnicastRelayContext {
            my_node: self.my_node,
            edges: &self.edges,
            capability: &self.capability,
            downstream: &self.downstream,
            downstream_ttl_ms: NEIGHBOR_TTL_MS,
        };
        crate::unicast_relay::plan_unicast_relay(
            &ctx,
            packet_id,
            source,
            heard_from,
            destination,
            my_next_hop,
            now_ms,
            |node| self.has_node_transmitted(node, packet_id, now_ms),
        )
    }

    fn fill_stock_relay_candidates(
        &self,
        packet_id: u32,
        heard_from: u32,
        now_ms: u32,
        out: &mut [u32; MAX_EDGES_PER_NODE],
    ) -> u8 {
        let mut count = 0u8;
        if heard_from == 0 {
            return count;
        }
        let mut ids = [0u32; MAX_EDGES_PER_NODE];
        let n = self.edges.direct_neighbor_ids(self.my_node, &mut ids);
        for &neighbor in &ids[..n as usize] {
            if neighbor == heard_from {
                continue;
            }
            if !self.capability.is_immediate_relay_router(neighbor) {
                continue;
            }
            let can_hear = self
                .edges
                .find_node(neighbor)
                .and_then(|node| node.find_edge(heard_from))
                .is_some();
            if !can_hear {
                continue;
            }
            let _ = self.has_node_transmitted(neighbor, packet_id, now_ms);
            if (count as usize) < MAX_EDGES_PER_NODE {
                out[count as usize] = neighbor;
                count += 1;
            }
        }
        count
    }

    fn fill_sr_relay_candidates(
        &self,
        packet_id: u32,
        heard_from: u32,
        now_ms: u32,
        out: &mut [u32; MAX_EDGES_PER_NODE + 1],
    ) -> u8 {
        let mut count = 0usize;
        if !self.has_node_transmitted(self.my_node, packet_id, now_ms) {
            out[count] = self.my_node;
            count += 1;
        }
        let mut ids = [0u32; MAX_EDGES_PER_NODE];
        let n = self.edges.direct_neighbor_ids(self.my_node, &mut ids);
        for &id in &ids[..n as usize] {
            if id == heard_from {
                continue;
            }
            if self.has_node_transmitted(id, packet_id, now_ms) {
                continue;
            }
            if self.capability.is_immediate_relay_router(id) {
                continue;
            }
            out[count] = id;
            count += 1;
        }
        if count == 0 {
            out[0] = self.my_node;
            count = 1;
        }
        for i in 0..count {
            for j in (i + 1)..count {
                if out[j] < out[i] {
                    out.swap(i, j);
                }
            }
        }
        count as u8
    }

    pub fn relay_candidate_count(&self, packet_id: u32, heard_from: u32, now_ms: u32) -> u8 {
        self.relay_slot_index(packet_id, heard_from, now_ms)
            .1
            .max(1)
    }

    fn clamp_topology_rssi(rssi: i16) -> i8 {
        rssi.clamp(i8::MIN as i16, i8::MAX as i16) as i8
    }

    fn clamp_topology_snr(snr: i8) -> i8 {
        snr.clamp(-20, 20)
    }

    fn upsert_direct_signal(&mut self, node_id: u32, rssi: i16, snr: i8, now_ms: u32) {
        if node_id == 0 || node_id == self.my_node {
            return;
        }
        let snr = Self::clamp_topology_snr(snr);
        for i in 0..self.direct_signal_count as usize {
            if self.direct_signals[i].node_id == node_id {
                self.direct_signals[i].rssi = rssi;
                self.direct_signals[i].snr = snr;
                self.direct_signals[i].last_rx_ms = now_ms;
                return;
            }
        }
        let slot = if (self.direct_signal_count as usize) < MAX_NEIGHBORS {
            let idx = self.direct_signal_count as usize;
            self.direct_signal_count += 1;
            idx
        } else {
            let mut oldest = 0usize;
            let mut oldest_ms = self.direct_signals[0].last_rx_ms;
            for i in 1..MAX_NEIGHBORS {
                if self.direct_signals[i].last_rx_ms < oldest_ms {
                    oldest = i;
                    oldest_ms = self.direct_signals[i].last_rx_ms;
                }
            }
            oldest
        };
        self.direct_signals[slot] = DirectNeighborSignal {
            node_id,
            rssi,
            snr,
            last_rx_ms: now_ms,
        };
    }

    fn lookup_direct_signal(&self, node_id: u32) -> Option<&DirectNeighborSignal> {
        for i in 0..self.direct_signal_count as usize {
            if self.direct_signals[i].node_id == node_id {
                return Some(&self.direct_signals[i]);
            }
        }
        None
    }

    #[allow(dead_code)]
    fn remove_direct_signal(&mut self, node_id: u32) {
        let mut write = 0u8;
        for i in 0..self.direct_signal_count as usize {
            if self.direct_signals[i].node_id != node_id {
                if write as usize != i {
                    self.direct_signals[write as usize] = self.direct_signals[i];
                }
                write += 1;
            }
        }
        self.direct_signal_count = write;
    }

    fn prune_direct_signals(&mut self, now_ms: u32) {
        let mut write = 0u8;
        for i in 0..self.direct_signal_count as usize {
            let entry = self.direct_signals[i];
            if entry.node_id == 0 {
                continue;
            }
            if now_ms.wrapping_sub(entry.last_rx_ms) > NEIGHBOR_TTL_MS {
                continue;
            }
            let has_reported = self
                .edges
                .find_node(self.my_node)
                .and_then(|n| n.find_edge(entry.node_id))
                .map(|e| e.source == EdgeSource::Reported)
                .unwrap_or(false);
            if !has_reported {
                continue;
            }
            if write as usize != i {
                self.direct_signals[write as usize] = entry;
            }
            write += 1;
        }
        self.direct_signal_count = write;
    }

    pub fn fill_neighbor_entries(&self, out: &mut [NeighborEntry; MAX_NEIGHBORS]) -> u8 {
        let Some(node) = self.edges.find_node(self.my_node) else {
            return 0;
        };
        let count = node.edge_count as usize;
        let mut written = 0usize;
        for i in 0..count {
            let edge = node.edges[i];
            if edge.source != EdgeSource::Reported || edge.to == 0 || edge.to == self.my_node {
                continue;
            }
            if is_placeholder_node(edge.to) {
                continue;
            }
            if written >= MAX_NEIGHBORS {
                break;
            }
            let Some(signal) = self.lookup_direct_signal(edge.to) else {
                continue;
            };
            out[written] = NeighborEntry {
                node_id: edge.to,
                rssi: signal.rssi,
                snr: signal.snr,
                last_seen_ms: edge.last_update_ms,
                signal_routing_active: self.signal_routing_active,
                hears_us: edge.hears_us,
            };
            written += 1;
        }
        written as u8
    }

    pub fn topology_neighbors_for_pack(&self, out: &mut [NeighborEntry; MAX_NEIGHBORS]) -> u8 {
        self.sorted_neighbors(out)
    }

    fn sorted_neighbors(&self, out: &mut [NeighborEntry; MAX_NEIGHBORS]) -> u8 {
        let count = self.fill_neighbor_entries(out);
        let n = count as usize;
        for i in 0..n {
            for j in (i + 1)..n {
                let swap = {
                    let a = out[i];
                    let b = out[j];
                    let a_edge = self
                        .edges
                        .find_node(self.my_node)
                        .and_then(|node| node.find_edge(a.node_id));
                    let b_edge = self
                        .edges
                        .find_node(self.my_node)
                        .and_then(|node| node.find_edge(b.node_id));
                    let a_reported = a_edge
                        .map(|e| e.source == EdgeSource::Reported)
                        .unwrap_or(false);
                    let b_reported = b_edge
                        .map(|e| e.source == EdgeSource::Reported)
                        .unwrap_or(false);
                    if a_reported != b_reported {
                        b_reported
                    } else {
                        let a_etx = a_edge.map(|e| e.etx()).unwrap_or(f32::MAX);
                        let b_etx = b_edge.map(|e| e.etx()).unwrap_or(f32::MAX);
                        b_etx < a_etx
                    }
                };
                if swap {
                    out.swap(i, j);
                }
            }
        }
        count
    }

    pub fn build_topology_chunk(
        &self,
        chunk_index: u8,
        topology_version: u8,
        out: &mut [u8],
    ) -> Option<usize> {
        let mut sorted = [NeighborEntry::default(); MAX_NEIGHBORS];
        let total = self.sorted_neighbors(&mut sorted);
        if total == 0 {
            if chunk_index != 0 {
                return None;
            }
            if out.len() < PACKED_NEIGHBOR_HEADER_SIZE {
                return None;
            }
            write_packed_header(out, topology_version, self.signal_routing_active);
            return Some(PACKED_NEIGHBOR_HEADER_SIZE);
        }
        let start = (chunk_index as usize) * MAX_NEIGHBORS_PER_PACKET;
        if start >= total as usize {
            return None;
        }
        let remaining = total as usize - start;
        let count = remaining.min(MAX_NEIGHBORS_PER_PACKET);
        let need = PACKED_NEIGHBOR_HEADER_SIZE + count * PACKED_NEIGHBOR_ENTRY_SIZE;
        if out.len() < need {
            return None;
        }
        write_packed_header_chunk(
            out,
            topology_version,
            self.signal_routing_active,
            start + count < total as usize,
            chunk_index != 0,
        );
        for i in 0..count {
            let entry = sorted[start + i];
            let base = PACKED_NEIGHBOR_HEADER_SIZE + i * PACKED_NEIGHBOR_ENTRY_SIZE;
            out[base..base + 4].copy_from_slice(&entry.node_id.to_le_bytes());
            out[base + 4] = Self::clamp_topology_rssi(entry.rssi) as u8;
            out[base + 5] = Self::clamp_topology_snr(entry.snr) as u8;
            let mut flags = 0u8;
            if entry.signal_routing_active {
                flags |= PACKED_NEIGHBOR_FLAG_SR_ACTIVE;
            }
            if entry.hears_us {
                flags |= PACKED_NEIGHBOR_FLAG_HEARS_US;
            }
            out[base + 6] = flags;
            if let Some(edge) = self
                .edges
                .find_node(self.my_node)
                .and_then(|n| n.find_edge(entry.node_id))
            {
                out[base + 7] = edge.etx_variance;
            } else {
                out[base + 7] = 0;
            }
        }
        Some(need)
    }

    pub fn topology_packet_count(&self) -> u8 {
        let mut scratch = [NeighborEntry::default(); MAX_NEIGHBORS];
        let total = self.fill_neighbor_entries(&mut scratch) as usize;
        if total == 0 {
            1
        } else {
            total.div_ceil(MAX_NEIGHBORS_PER_PACKET) as u8
        }
    }

    fn topology_version_accept(received: u8, last: u8) -> bool {
        if last == 0 {
            return true;
        }
        if received == last {
            return true;
        }
        let diff = received.wrapping_sub(last);
        diff > 0 && diff < 128
    }

    /// Merge a neighbor's SR topology broadcast. `heard_on` tags the receiving radio segment.
    pub fn merge_topology(
        &mut self,
        sender: u32,
        header: &PackedHeader,
        neighbors: &[PackedNeighbor],
        is_direct_from_sender: bool,
        now_ms: u32,
        heard_on: RadioId,
    ) -> TopologyMergeResult {
        if header.format_version != crate::topology::PACKED_NEIGHBOR_FORMAT_VERSION {
            return TopologyMergeResult::IgnoredFormat;
        }
        if header.routing_version != SIGNAL_ROUTING_VERSION {
            return TopologyMergeResult::IgnoredFormat;
        }
        if !self.is_active_routing_role() && !is_direct_from_sender {
            self.capability
                .track_topology(sender, header.signal_routing_active, now_ms);
            return TopologyMergeResult::IgnoredFormat;
        }

        let received = header.topology_version;
        let (last, last_accept_ms) = self.topo_version_entry(sender);
        // Three ways in: the forward window (normal), the sender's empty boot broadcast (an
        // explicit restart: its counter starts over, so ours for it does too), or nothing accepted
        // from it for two periodic intervals (its boot broadcast was lost, it came back with a
        // moved-on counter, or we were away). Czar rebooted once and its reports were rejected as
        // stale for three hours, until its whole neighbourhood had aged out of the graph.
        // A header-only broadcast carrying version 0 is a peer's boot announcement: its version
        // counter restarted, so forget the one we tracked. Empty lists with other versions are
        // ordinary reports from a node without neighbours. Passive peers boot too (inno's restart
        // was rejected as stale for twenty minutes), so the SR-active flag plays no part here,
        // and neither does the relay byte (see below).
        // A fourth way in: the boot broadcast was lost on the air, and the peer's restarted
        // counter now shows as rejected versions climbing one by one. Two in a row cannot be
        // late copies of old reports (those arrive within seconds, not a whole interval apart),
        // so the second one re-bases us instead of waiting out two silent intervals.
        // The boot broadcast is a statement about the sender's counter, not about the link, so a
        // copy that reached us through a relay counts too: angl heard Czar's restart only through
        // A and rejected Czar's reports as stale for twenty minutes.
        let boot_reset = neighbors.is_empty() && received == 0;
        let silence = last_accept_ms != 0
            && now_ms.wrapping_sub(last_accept_ms) >= TOPOLOGY_RESYNC_MS
            && now_ms.wrapping_sub(last_accept_ms) < 0x8000_0000;
        let in_window = Self::topology_version_accept(received, last);
        let climb = !in_window && self.topo_version_climbs_after_stale(sender, received);
        if !in_window && !boot_reset && !silence && !climb {
            self.note_topo_version_stale(sender, received);
            return TopologyMergeResult::Stale { received, last };
        }
        if !in_window || (boot_reset && last != 0) {
            self.last_version_resync = Some((sender, received, last));
        }
        self.set_topo_version(sender, if boot_reset { 0 } else { received }, now_ms);
        self.capability
            .track_topology(sender, header.signal_routing_active, now_ms);

        self.edges.ensure_local_node(self.my_node, now_ms);
        self.merge_asymmetric_skip_count = 0;

        let passive_local = !self.is_active_routing_role();
        for neighbor in neighbors {
            if neighbor.node_id == 0 || (neighbor.node_id & 0xFF00_0000) == 0xFF00_0000 {
                continue;
            }
            if passive_local
                && neighbor.node_id != self.my_node
                && !self
                    .edges
                    .has_direct_reported_edge_to(self.my_node, neighbor.node_id)
                && !self
                    .edges
                    .has_direct_reported_edge_to(neighbor.node_id, self.my_node)
            {
                continue;
            }
            let etx = calculate_etx(neighbor.rssi as i32, neighbor.snr as f32);
            let relay_has_edge = self
                .edges
                .find_node(sender)
                .and_then(|n| n.find_edge(neighbor.node_id))
                .is_some();
            self.edges.update_edge(
                self.my_node,
                sender,
                neighbor.node_id,
                etx,
                now_ms,
                EdgeSource::Mirrored,
                false,
                heard_on,
            );
            self.edges
                .set_edge_hears_us(sender, neighbor.node_id, neighbor.hears_us);
            // The sender lists us as a neighbor it hears directly. That is positive
            // evidence the sender hears us. SR-passive nodes broadcast topology but
            // never relay, so this is their only way to earn `hears_us` (SR-mute nodes
            // send no topology at all and are unaffected).
            if neighbor.node_id == self.my_node {
                self.edges.set_edge_hears_us(self.my_node, sender, true);
            } else {
                // The same evidence proves the sender hears every other listed node: mark the
                // listed node's own edge to the sender (if it has reported one) as heard, so we
                // model our peers' coverage of the sender the way they model it themselves.
                // Without this, two nodes that both just learned a passive neighbour each saw
                // the other as not covering it and both took slot 0 for its packets.
                self.edges.set_edge_hears_us(neighbor.node_id, sender, true);
            }

            let has_direct_connection = neighbor.node_id == self.my_node
                || self
                    .edges
                    .has_direct_reported_edge_to(neighbor.node_id, self.my_node);

            if !has_direct_connection && neighbor.hears_us {
                let via_radio = self.edges.relay_heard_on(self.my_node, sender);
                self.downstream.update(
                    self.my_node,
                    neighbor.node_id,
                    sender,
                    etx,
                    now_ms,
                    relay_has_edge,
                    via_radio,
                );
            } else if !has_direct_connection
                && !neighbor.hears_us
                && neighbor.node_id != self.my_node
            {
                self.record_merge_asymmetric_skip(sender, neighbor.node_id);
            }
        }

        // The sender is authoritative about who it hears: a neighbour it does not list has its
        // hears_us towards the sender cleared. That needs the complete list, so chunks of a
        // multi-packet report are gathered first and the rule runs on the last one.
        let slot = self.pending_listed_slot(sender);
        if !header.continuation {
            self.pending_listed[slot] = PendingListed {
                sender,
                version: received,
                count: 0,
                valid: true,
                ids: [0; MAX_NEIGHBORS],
            };
        }
        let pending = &mut self.pending_listed[slot];
        if pending.valid && pending.sender == sender && pending.version == received {
            for neighbor in neighbors {
                if (pending.count as usize) < MAX_NEIGHBORS {
                    pending.ids[pending.count as usize] = neighbor.node_id;
                    pending.count += 1;
                } else {
                    pending.valid = false;
                }
            }
            if !header.more_chunks {
                // An empty list is no evidence: a node that has just booted has heard nobody yet,
                // and a node hearing nobody has nothing to say about who hears it.
                if pending.valid && pending.count > 0 {
                    let count = pending.count as usize;
                    let listed = pending.ids;
                    self.edges
                        .clear_hears_us_to_unlisted(sender, &listed[..count]);
                }
                self.pending_listed[slot].valid = false;
            }
        } else if header.continuation {
            // First chunk missed: this list is incomplete, leave hears_us as it was.
            pending.valid = false;
        }

        TopologyMergeResult::Applied {
            neighbors: neighbors.len() as u8,
            topo_v: received,
        }
    }

    fn record_merge_asymmetric_skip(&mut self, sender: u32, destination: u32) {
        let count = self.merge_asymmetric_skip_count as usize;
        if count >= self.merge_asymmetric_skips.len() {
            return;
        }
        self.merge_asymmetric_skips[count] = (sender, destination);
        self.merge_asymmetric_skip_count += 1;
    }

    pub fn drain_merge_asymmetric_skips(&mut self) -> impl Iterator<Item = (u32, u32)> + '_ {
        let count = self.merge_asymmetric_skip_count as usize;
        self.merge_asymmetric_skip_count = 0;
        self.merge_asymmetric_skips[..count].iter().copied()
    }

    fn topo_version_entry(&self, node_id: u32) -> (u8, u32) {
        for i in 0..self.topo_version_count as usize {
            if self.topo_versions[i].node_id == node_id {
                return (
                    self.topo_versions[i].version,
                    self.topo_versions[i].last_accept_ms,
                );
            }
        }
        (0, 0)
    }

    fn set_topo_version(&mut self, node_id: u32, version: u8, now_ms: u32) {
        let now_ms = now_ms.max(1);
        for i in 0..self.topo_version_count as usize {
            if self.topo_versions[i].node_id == node_id {
                self.topo_versions[i].version = version;
                self.topo_versions[i].last_accept_ms = now_ms;
                self.topo_versions[i].stale_valid = false;
                return;
            }
        }
        if (self.topo_version_count as usize) < MAX_TOPOLOGY_VERSION_ENTRIES {
            let idx = self.topo_version_count as usize;
            self.topo_versions[idx] = TopologyVersionEntry {
                node_id,
                version,
                last_accept_ms: now_ms,
                stale_version: 0,
                stale_valid: false,
            };
            self.topo_version_count += 1;
        }
    }

    /// Is `received` one past the version we last rejected from `node_id`?
    fn topo_version_climbs_after_stale(&self, node_id: u32, received: u8) -> bool {
        self.topo_versions[..self.topo_version_count as usize]
            .iter()
            .any(|e| {
                e.node_id == node_id && e.stale_valid && received == e.stale_version.wrapping_add(1)
            })
    }

    fn note_topo_version_stale(&mut self, node_id: u32, received: u8) {
        for e in self.topo_versions[..self.topo_version_count as usize].iter_mut() {
            if e.node_id == node_id {
                e.stale_version = received;
                e.stale_valid = true;
                return;
            }
        }
    }

    /// A report was accepted outside the forward version window (sender, received, stored).
    pub fn take_topology_version_resync(&mut self) -> Option<(u32, u8, u8)> {
        self.last_version_resync.take()
    }

    /// Slot gathering `sender`'s chunks: its open one if any, else a free one, else slot 0
    /// (whose owner then loses its half-gathered list, the only casualty of the cap).
    fn pending_listed_slot(&self, sender: u32) -> usize {
        self.pending_listed
            .iter()
            .position(|p| p.valid && p.sender == sender)
            .or_else(|| self.pending_listed.iter().position(|p| !p.valid))
            .unwrap_or(0)
    }

    /// Record a direct RF neighbor. `heard_on` is the receiving radio (`RadioId(0)` on v1 hardware).
    fn observe_relay_gateway_signal(
        &mut self,
        gateway: u32,
        rssi: i16,
        snr: i8,
        now_ms: u32,
        heard_on: RadioId,
    ) -> bool {
        if is_placeholder_node(gateway) {
            return false;
        }
        let result = self.refresh_reported_direct_neighbor(gateway, rssi, snr, now_ms, heard_on);
        if result == EDGE_NEW {
            self.downstream.clear_for_destination(gateway);
            self.topology_dirty = true;
        } else if result == EDGE_SIGNIFICANT_CHANGE {
            self.topology_dirty = true;
        }
        result == EDGE_NEW
    }

    /// Record a direct RF neighbor. `heard_on` is the receiving radio (`RadioId(0)` on v1 hardware).
    fn refresh_reported_direct_neighbor(
        &mut self,
        node_id: u32,
        rssi: i16,
        snr: i8,
        now_ms: u32,
        heard_on: RadioId,
    ) -> i8 {
        self.edges.ensure_local_node(self.my_node, now_ms);
        let result = self.edges.update_edge_from_observation(
            self.my_node,
            self.my_node,
            node_id,
            rssi,
            snr,
            now_ms,
            EdgeSource::Reported,
            heard_on,
        );
        let _ = self.edges.update_edge_from_observation(
            self.my_node,
            node_id,
            self.my_node,
            rssi,
            snr,
            now_ms,
            EdgeSource::Reported,
            heard_on,
        );
        self.upsert_direct_signal(node_id, rssi, snr, now_ms);
        result
    }

    pub fn observe_direct_neighbor(
        &mut self,
        node_id: u32,
        rssi: i16,
        snr: i8,
        now_ms: u32,
        heard_on: RadioId,
    ) -> bool {
        if node_id == 0 || node_id == self.my_node {
            return false;
        }
        let result = self.refresh_reported_direct_neighbor(node_id, rssi, snr, now_ms, heard_on);
        if result == EDGE_NEW || result == EDGE_SIGNIFICANT_CHANGE {
            self.topology_dirty = true;
        }
        self.downstream.clear_for_destination(node_id);
        result == EDGE_NEW
    }

    /// Update graph from a received packet header. `heard_on` tags which preset segment heard it.
    ///
    /// `known_relay`, when set to a resolved non-placeholder NodeNum, lets relayed-packet
    /// learning use the real gateway instead of a synthetic placeholder.
    pub fn observe_packet(
        &mut self,
        from: u32,
        hop_start: u8,
        hop_limit: u8,
        relay_node: u8,
        rssi: i16,
        snr: i8,
        now_ms: u32,
        heard_on: RadioId,
        known_relay: Option<u32>,
        packet_id: u32,
    ) -> Option<(u32, i16, i8, bool, bool)> {
        if is_direct_packet(from, hop_start, hop_limit, relay_node) {
            let is_new = self.observe_direct_neighbor(from, rssi, snr, now_ms, heard_on);
            self.record_heard_transmissions(from, packet_id, None, now_ms);
            Some((from, rssi, snr, is_new, false))
        } else if let Some((gateway, is_new, hears_us)) = self.observe_relayed_packet(
            from,
            hop_start,
            hop_limit,
            relay_node,
            rssi,
            snr,
            now_ms,
            heard_on,
            known_relay,
            packet_id,
        ) {
            Some((gateway, rssi, snr, is_new, hears_us))
        } else {
            None
        }
    }

    fn relay_gateway_for_observation(
        &mut self,
        from: u32,
        relay_node: u8,
        known_relay: Option<u32>,
        _now_ms: u32,
    ) -> u32 {
        let placeholder = placeholder_node_id(relay_node);
        // Placeholder → real NodeNum resolution only happens on directly-heard frames
        // (hop_start == hop_limit, relay byte matches originator). While a placeholder
        // remains in the graph, relayed observations keep using it as the gateway.
        if self.edges.find_node(placeholder).is_some() {
            return placeholder;
        }
        if let Some(real) = known_relay {
            if real != 0
                && real != self.my_node
                && real != from
                && !is_placeholder_node(real)
                && (real & 0xFF) as u8 == relay_node
            {
                return real;
            }
        }
        placeholder
    }

    fn observe_relayed_packet(
        &mut self,
        from: u32,
        hop_start: u8,
        hop_limit: u8,
        relay_node: u8,
        rssi: i16,
        snr: i8,
        now_ms: u32,
        heard_on: RadioId,
        known_relay: Option<u32>,
        packet_id: u32,
    ) -> Option<(u32, bool, bool)> {
        if !self.is_active_routing_role() {
            return None;
        }
        if from == 0 || (rssi == 0 && snr == 0) {
            return None;
        }
        let from_low = (from & 0xFF) as u8;
        if relay_node == 0 || relay_node == from_low {
            return None;
        }
        let gateway = self.relay_gateway_for_observation(from, relay_node, known_relay, now_ms);
        if gateway == from || gateway == self.my_node {
            return None;
        }
        // Our own echo teaches us nothing about who is behind whom. A peer that relays a packet we
        // just transmitted got it from us, so recording the source as downstream of that peer
        // invents a path back through ourselves: the peer then routes that destination to us while
        // we route it to the peer, and a unicast bounces between them (seen with the balcony node,
        // 2026-09-07).
        if self.has_our_transmission(packet_id) {
            return None;
        }
        self.edges.ensure_local_node(self.my_node, now_ms);
        // What we measured is the relay's link to us, not the relay's link to the source. An
        // inferred edge/downstream gets a nominal cost per hop the packet has travelled; with the
        // measured value a two-hop path through a node a metre away priced at 1.05 and two
        // colocated nodes routed a far hub through each other.
        let hops_used = hop_start.saturating_sub(hop_limit).max(1);
        let etx = calculate_etx(INFERRED_LINK_RSSI, INFERRED_LINK_SNR) * hops_used as f32;

        let is_new_gateway =
            self.observe_relay_gateway_signal(gateway, rssi, snr, now_ms, heard_on);

        let single_hop = hops_used == 1;
        let source_sr_active = matches!(self.capability.status(from), CapabilityStatus::SrActive);

        if !source_sr_active || single_hop {
            let result_relay_to_dest = self.edges.update_edge(
                self.my_node,
                gateway,
                from,
                etx,
                now_ms,
                EdgeSource::Mirrored,
                true,
                heard_on,
            );
            if result_relay_to_dest == EDGE_NEW || result_relay_to_dest == EDGE_SIGNIFICANT_CHANGE {
                self.route_cache.clear();
            }
        }

        // Also learn (us -> relay_gateway) so routing can egress via the relay.
        let result_us_to_relay = self.edges.update_edge_from_observation(
            self.my_node,
            self.my_node,
            gateway,
            rssi,
            snr,
            now_ms,
            EdgeSource::Mirrored,
            heard_on,
        );

        if result_us_to_relay == EDGE_NEW || result_us_to_relay == EDGE_SIGNIFICANT_CHANGE {
            self.route_cache.clear();
        }

        // Only now does the us -> gateway edge exist for a first-time placeholder relay
        // (observe_relay_gateway_signal skips placeholders), so confirm hears_us here rather
        // than before the edge update, where the flag was logged but never stored.
        let hears_us = self.maybe_confirm_hears_us_from_relay(gateway, from, packet_id);

        let can_infer_downstream = self
            .edges
            .has_direct_reported_edge_to(self.my_node, gateway)
            || is_placeholder_node(gateway);
        if can_infer_downstream
            && (single_hop || !source_sr_active)
            && !self.is_downstream_relay_for(gateway, from, now_ms)
        {
            self.downstream
                .update(self.my_node, from, gateway, etx, now_ms, false, heard_on);
            self.route_cache.clear();
        }

        self.record_heard_transmissions(from, packet_id, Some(gateway), now_ms);
        Some((gateway, is_new_gateway, hears_us))
    }

    pub fn commit_relay(
        &mut self,
        from: u32,
        id: u32,
        radio_id: u8,
        snr: i8,
        heard_from: u32,
        now_ms: u32,
        half_airtime_ms: u32,
        _cw_slot_ms: u32,
        node_num: u32,
        broadcast_plan: Option<&crate::broadcast_relay::BroadcastRelayPlan>,
    ) -> (u32, u8, u8) {
        let half = half_airtime_ms.max(50);
        let (slot_index, candidates, spacing) = if let Some(plan) = broadcast_plan {
            (plan.slot_index, plan.candidate_count, plan.slot_delay_ms)
        } else {
            let (idx, count) = self.relay_slot_index(id, heard_from, now_ms);
            (
                idx,
                count,
                crate::channel_access::slot_delay_ms(idx as u32, half),
            )
        };
        // The slot already encodes the coordinated order. Only a small deterministic tie-break
        // is added; the router-style SNR contention delay (up to 2·CW slots, several times a
        // half-airtime) used to be added here and randomised the order, which is how two
        // colocated nodes in slots 1 and 4 ended up keying up 50 ms apart.
        let delay = (spacing as i64 + slot_tie_break_ms(half, id, node_num) as i64).max(0) as u32;
        let tx_after_ms = now_ms.wrapping_add(delay);
        if let Some(idx) = self.find_relay(from, id, radio_id) {
            let commit = &mut self.relay_states[idx];
            if snr >= commit.snr {
                commit.snr = snr;
                commit.tx_after_ms = tx_after_ms;
            }
            return (commit.tx_after_ms, slot_index, candidates);
        }
        if let Some(idx) = self.alloc_relay_slot() {
            self.relay_states[idx] = RelayCommit {
                active: true,
                from,
                id,
                radio_id,
                tx_after_ms,
                snr,
                original_heard_from: heard_from,
                heard_transmitters: [0; MAX_HEARD_TRANSMITTERS],
                heard_transmitter_count: 0,
            };
            return (tx_after_ms, slot_index, candidates);
        }
        (tx_after_ms, slot_index, candidates)
    }

    pub fn relay_tx_after(&self, from: u32, id: u32, radio_id: u8) -> Option<u32> {
        self.find_relay(from, id, radio_id)
            .map(|idx| self.relay_states[idx].tx_after_ms)
    }

    /// Drop every committed relay. Returns how many were active.
    pub fn clear_relays(&mut self) -> usize {
        let mut n = 0;
        for slot in &mut self.relay_states {
            if slot.active {
                slot.active = false;
                n += 1;
            }
        }
        n
    }

    pub fn cancel_relay(&mut self, from: u32, id: u32) {
        for slot in &mut self.relay_states {
            if slot.active && slot.from == from && slot.id == id {
                slot.active = false;
            }
        }
    }

    pub fn cancel_relay_on_rebroadcast(
        &mut self,
        from: u32,
        id: u32,
        hop_start: u8,
        hop_limit: u8,
        relay_node: u8,
        our_node: u32,
        _now_ms: u32,
    ) {
        let our_low = (our_node & 0xFF) as u8;
        let relayed = hop_limit < hop_start
            || (relay_node != 0 && relay_node != our_low && relay_node != (from & 0xFF) as u8);
        if relayed {
            self.cancel_relay(from, id);
        }
    }

    pub fn get_downstream_relay(&self, destination: u32, now_ms: u32) -> Option<u32> {
        self.downstream
            .get_relay(destination, now_ms, NEIGHBOR_TTL_MS)
    }

    pub fn downstream_count_for_relay(&self, relay: u32, now_ms: u32) -> usize {
        self.downstream
            .count_for_relay(relay, now_ms, NEIGHBOR_TTL_MS)
    }

    pub fn downstream_nodes_for_relay(&self, relay: u32, out: &mut [u32], now_ms: u32) -> usize {
        self.downstream
            .nodes_for_relay(relay, out, now_ms, NEIGHBOR_TTL_MS)
    }

    pub fn is_downstream_relay_for(&self, relay: u32, destination: u32, now_ms: u32) -> bool {
        self.downstream
            .is_relay_for(relay, destination, now_ms, NEIGHBOR_TTL_MS)
    }

    pub fn transfer_downstream(&mut self, old_relay: u32, new_relay: u32, now_ms: u32) -> usize {
        self.downstream
            .transfer_downstream(old_relay, new_relay, now_ms)
    }

    pub fn replace_gateway_node(&mut self, old_node: u32, new_node: u32, now_ms: u32) {
        if old_node == 0 || new_node == 0 || old_node == new_node {
            return;
        }
        let _ = self.transfer_downstream(old_node, new_node, now_ms);
        self.downstream.clear_for_destination(old_node);
        self.route_cache.clear();
    }

    /// Replace a synthetic placeholder with a learned real node id.
    ///
    /// Call only after a **directly-heard** frame from `real_node_id` (see
    /// [`mesh_protocol::is_direct_packet`]): originator and relay byte in sync,
    /// hop budget not yet consumed.
    pub fn resolve_placeholder(
        &mut self,
        placeholder_id: u32,
        real_node_id: u32,
        now_ms: u32,
    ) -> bool {
        if !is_placeholder_node(placeholder_id) || is_placeholder_node(real_node_id) {
            return false;
        }
        if real_node_id == 0 || real_node_id == self.my_node {
            return false;
        }
        if (real_node_id & 0xFF) as u8 != (placeholder_id & 0xFF) as u8 {
            return false;
        }
        if self.edges.find_node(placeholder_id).is_none() {
            return false;
        }

        self.edges.ensure_local_node(self.my_node, now_ms);
        let mut copied = None::<(f32, mesh_radio::RadioId, bool)>;
        if let Some(my_edges) = self.edges.find_node(self.my_node) {
            for i in 0..my_edges.edge_count as usize {
                let edge = my_edges.edges[i];
                if edge.to == placeholder_id {
                    copied = Some((edge.etx(), edge.heard_on, edge.hears_us));
                    break;
                }
            }
        }
        if let Some((etx, heard_on, hears_us)) = copied {
            let result = self.edges.update_edge(
                self.my_node,
                self.my_node,
                real_node_id,
                etx,
                now_ms,
                EdgeSource::Reported,
                true,
                heard_on,
            );
            if hears_us {
                self.edges
                    .set_edge_hears_us(self.my_node, real_node_id, true);
            }
            if result == EDGE_NEW || result == EDGE_SIGNIFICANT_CHANGE {
                self.topology_dirty = true;
            }
        }

        self.replace_gateway_node(placeholder_id, real_node_id, now_ms);
        self.edges.remove_edges_to(placeholder_id);
        let _ = self.edges.remove_node(placeholder_id);
        self.route_cache.clear();
        true
    }

    pub fn get_route(&mut self, destination: u32, now_ms: u32) -> Route {
        if let Some(cached) = self.route_cache.get(destination, now_ms) {
            return cached;
        }
        let filter = RoutableFilter {
            capability: &self.capability,
            my_node: self.my_node,
            device_role: self.device_role,
        };
        let route = calculate_route(
            &self.edges,
            &self.downstream,
            self.my_node,
            destination,
            now_ms,
            Some(&filter),
        );
        if route.next_hop != 0 {
            self.route_cache.insert(route);
        }
        route
    }

    /// Route lookup including which radio should egress the first hop (Phase 9).
    pub fn route_to(&mut self, destination: u32, now_ms: u32) -> Route {
        self.get_route(destination, now_ms)
    }

    pub fn edge_heard_on(&self, peer: u32) -> RadioId {
        self.edges.relay_heard_on(self.my_node, peer)
    }

    pub fn has_verified_connectivity(&self, transmitter: u32, receiver: u32) -> (bool, bool) {
        verified_connectivity(&self.edges, &self.capability, transmitter, receiver)
    }

    pub fn is_node_routable(&self, node_id: u32) -> bool {
        let filter = RoutableFilter {
            capability: &self.capability,
            my_node: self.my_node,
            device_role: self.device_role,
        };
        is_node_routable(&filter, node_id)
    }

    pub fn get_next_hop(
        &mut self,
        destination: u32,
        source_node: u32,
        heard_from: u32,
        now_ms: u32,
    ) -> u32 {
        self.get_next_hop_verified(destination, source_node, heard_from, now_ms)
            .0
    }

    /// The next hop to stamp on a relayed unicast, and whether it came from a path the strict
    /// search confirmed end to end. Every other source of a hop here — a better-positioned
    /// neighbour, the downstream table, best-effort self relay, direct delivery — is a guess and
    /// reports `false`, so a caller can refuse to designate a node that never proved it hears
    /// the destination. Reading `Route::verified` instead described the searched route rather
    /// than the hop actually returned.
    pub fn get_next_hop_verified(
        &mut self,
        destination: u32,
        source_node: u32,
        heard_from: u32,
        now_ms: u32,
    ) -> (u32, bool) {
        self.get_next_hop_inner(destination, source_node, heard_from, now_ms, true)
    }

    fn get_next_hop_inner(
        &mut self,
        destination: u32,
        source_node: u32,
        heard_from: u32,
        now_ms: u32,
        allow_opportunistic: bool,
    ) -> (u32, bool) {
        if destination == 0 || destination == self.my_node {
            return (0, false);
        }

        let route = self.get_route(destination, now_ms);
        if route.next_hop != 0 {
            let route_cost = route.cost();
            let mut next_hop_can_hear = true;
            if heard_from != 0 && route.next_hop != heard_from {
                let (verified, _unknown) =
                    self.has_verified_connectivity(heard_from, route.next_hop);
                next_hop_can_hear = verified;
            }

            if next_hop_can_hear {
                if allow_opportunistic && route_cost > 2.0 {
                    let better = find_better_positioned_neighbor(
                        &self.edges,
                        &self.capability,
                        self.my_node,
                        self.device_role,
                        destination,
                        source_node,
                        heard_from,
                        route_cost,
                    );
                    if better != 0 {
                        return (better, false);
                    }
                }
                return (route.next_hop, route.verified);
            }

            if self.edge_hears_us(route.next_hop) {
                return (route.next_hop, route.verified);
            }

            if allow_opportunistic {
                let better = find_better_positioned_neighbor(
                    &self.edges,
                    &self.capability,
                    self.my_node,
                    self.device_role,
                    destination,
                    source_node,
                    heard_from,
                    f32::MAX,
                );
                if better != 0 {
                    return (better, false);
                }
            }

            return (self.my_node, false);
        }

        if let Some(relay_for_dest) = self.get_downstream_relay(destination, now_ms) {
            let mut relay_can_hear = true;
            let mut connectivity_unknown = false;
            if heard_from != 0 && relay_for_dest != heard_from {
                let (verified, unknown) =
                    self.has_verified_connectivity(heard_from, relay_for_dest);
                relay_can_hear = verified;
                connectivity_unknown = unknown;
            }
            if relay_can_hear && !connectivity_unknown && self.has_direct_edge(relay_for_dest) {
                return (relay_for_dest, false);
            }
        }

        if allow_opportunistic {
            let better = find_better_positioned_neighbor(
                &self.edges,
                &self.capability,
                self.my_node,
                self.device_role,
                destination,
                source_node,
                heard_from,
                f32::MAX,
            );
            if better != 0 {
                return (better, false);
            }
        }

        if heard_from != source_node && self.has_direct_edge(destination) {
            return (destination, false);
        }

        if self.is_downstream_relay_for(self.my_node, destination, now_ms) {
            self.downstream.update(
                self.my_node,
                destination,
                self.my_node,
                1.0,
                now_ms,
                false,
                0,
            );
            return (destination, false);
        }

        if let Some(dest_node) = self.edges.find_node(destination) {
            if dest_node.edge_count == 1 && dest_node.edges[0].to == self.my_node {
                self.downstream.update(
                    self.my_node,
                    destination,
                    self.my_node,
                    1.0,
                    now_ms,
                    false,
                    0,
                );
                return (destination, false);
            }
        }

        (0, false)
    }

    pub(crate) fn has_direct_edge(&self, peer: u32) -> bool {
        self.edges
            .find_node(self.my_node)
            .and_then(|n| n.find_edge(peer))
            .is_some()
    }

    #[doc(hidden)]
    pub fn edge_hears_us_for_test(&self, peer: u32) -> bool {
        self.edge_hears_us(peer)
    }

    fn edge_hears_us(&self, next_hop: u32) -> bool {
        self.edges
            .find_node(self.my_node)
            .and_then(|n| n.find_edge(next_hop))
            .map(|e| e.hears_us)
            .unwrap_or(false)
    }

    pub fn has_any_hears_us_neighbor(&self) -> bool {
        let Some(node) = self.edges.find_node(self.my_node) else {
            return false;
        };
        for i in 0..node.edge_count as usize {
            if node.edges[i].hears_us {
                return true;
            }
        }
        false
    }

    /// Whose copy acknowledges a `want_ack` broadcast to its originator: the neighbour with the
    /// best measured link to it, stock rebroadcasters given way, node id as the tie-break — the
    /// same election that decides who covers an unconfirmed neighbour. One witness answers, so
    /// the originator's implicit ACK costs one frame instead of one per node that heard it.
    pub fn is_elected_witness(&self, source: u32) -> bool {
        crate::graph::witness_owner(
            &self.edges,
            &self.capability,
            self.my_node,
            self.is_rebroadcaster(),
            source,
        ) == self.my_node
    }

    /// Do we still reach a neighbour that none of `covered_by` can deliver to? Ours are the
    /// neighbours that confirmed hearing us, plus those nobody can be shown to reach that we
    /// own — and in both cases only while a copy from us would actually arrive.
    pub fn has_unique_coverage(&self, covered_by: &[u32]) -> bool {
        self.unique_coverage_neighbor(covered_by).is_some()
    }

    /// The neighbour that makes our relay worth its airtime: ours to cover and reached by none of
    /// `covered_by`. Returned rather than reduced to a bool so the decision can be logged: "we
    /// relayed for X" is the only way to tell a justified relay from a coverage bug in the field.
    pub fn unique_coverage_neighbor(&self, covered_by: &[u32]) -> Option<u32> {
        let node = self.edges.find_node(self.my_node)?;
        for i in 0..node.edge_count as usize {
            let edge = node.edges[i];
            let neighbor = edge.to;
            if is_placeholder_node(neighbor) {
                continue;
            }
            // Ours to cover: it proved it hears us, or nobody can prove anything about it and we
            // are its owner. Otherwise it is another node's responsibility, or nobody's.
            if !edge.hears_us
                && crate::graph::coverage_owner(
                    &self.edges,
                    &self.capability,
                    self.my_node,
                    self.is_rebroadcaster(),
                    neighbor,
                ) != self.my_node
            {
                continue;
            }
            // Confirmation or ownership says whose it is; `covers` says whether a copy from us
            // would arrive at all. `hears_us` is sticky, so without this a neighbour behind a
            // decayed link stayed "ours to cover" and kept a queued relay the ranking refuses
            // (31 of 183 slots sat at the heard-once sentinel, field 2026-09-08).
            if !crate::graph::covers(&self.edges, Some(&self.capability), self.my_node, neighbor) {
                continue;
            }
            if covered_by.contains(&neighbor) {
                continue;
            }
            let covered = covered_by.iter().any(|&coverer| {
                crate::graph::covers(&self.edges, Some(&self.capability), coverer, neighbor)
            });
            if !covered {
                return Some(neighbor);
            }
        }
        None
    }

    /// Drop every committed relay for `packet_id`: the frame is on the air (or was pulled back).
    pub fn cancel_relay_for_id(&mut self, packet_id: u32) -> bool {
        let mut any = false;
        for slot in &mut self.relay_states {
            if slot.active && slot.id == packet_id {
                slot.active = false;
                any = true;
            }
        }
        any
    }

    fn find_relay_commit(&self, from: u32, id: u32) -> Option<usize> {
        self.relay_states
            .iter()
            .position(|s| s.active && s.from == from && s.id == id)
    }

    fn accumulate_heard_transmitter(&mut self, from: u32, id: u32, transmitter: u32) {
        if transmitter == 0 || transmitter == self.my_node {
            return;
        }
        let Some(idx) = self.find_relay_commit(from, id) else {
            return;
        };
        let relay = &mut self.relay_states[idx];
        for i in 0..relay.heard_transmitter_count as usize {
            if relay.heard_transmitters[i] == transmitter {
                return;
            }
        }
        if (relay.heard_transmitter_count as usize) >= MAX_HEARD_TRANSMITTERS {
            return;
        }
        relay.heard_transmitters[relay.heard_transmitter_count as usize] = transmitter;
        relay.heard_transmitter_count = relay.heard_transmitter_count.saturating_add(1);
    }

    fn build_coverage_transmitters(
        &self,
        from: u32,
        id: u32,
        out: &mut [u32; 1 + MAX_HEARD_TRANSMITTERS],
    ) -> u8 {
        let mut count = 0u8;
        let Some(idx) = self.find_relay_commit(from, id) else {
            return 0;
        };
        let relay = &self.relay_states[idx];
        if relay.original_heard_from != 0 && relay.original_heard_from != self.my_node {
            out[count as usize] = relay.original_heard_from;
            count += 1;
        }
        for i in 0..relay.heard_transmitter_count as usize {
            let transmitter = relay.heard_transmitters[i];
            if transmitter != relay.original_heard_from {
                out[count as usize] = transmitter;
                count += 1;
            }
        }
        count
    }

    /// Broadcast dupe coverage: accumulate the relayer and return true only when no unique coverage remains.
    pub fn all_neighbors_covered(&mut self, from: u32, packet_id: u32, dupe_relayer: u32) -> bool {
        if dupe_relayer == 0 || dupe_relayer == self.my_node {
            return false;
        }
        self.accumulate_heard_transmitter(from, packet_id, dupe_relayer);
        let mut covered_by = [0u32; 1 + MAX_HEARD_TRANSMITTERS];
        let count = self.build_coverage_transmitters(from, packet_id, &mut covered_by);
        !self.has_unique_coverage(&covered_by[..count as usize])
    }

    /// Distinct accumulated relayers for a committed broadcast relay (testing / diagnostics).
    pub fn relay_heard_transmitter_count(&self, from: u32, id: u32) -> u8 {
        self.find_relay_commit(from, id)
            .map(|idx| self.relay_states[idx].heard_transmitter_count)
            .unwrap_or(0)
    }

    /// True when a `hears_us` neighbor on `radio` has not yet transmitted this packet id.
    pub fn segment_has_uncovered_hears_us_neighbors(
        &self,
        radio: RadioId,
        packet_id: u32,
        heard_from: u32,
        now_ms: u32,
    ) -> bool {
        let Some(node) = self.edges.find_node(self.my_node) else {
            return false;
        };
        for i in 0..node.edge_count as usize {
            let edge = node.edges[i];
            if !edge.hears_us || edge.heard_on != radio {
                continue;
            }
            if edge.to == heard_from {
                continue;
            }
            if !self.has_node_transmitted(edge.to, packet_id, now_ms) {
                return true;
            }
        }
        false
    }

    pub fn is_committed_relay(&self, from: u32, packet_id: u32) -> bool {
        self.relay_states
            .iter()
            .any(|s| s.active && s.from == from && s.id == packet_id)
    }

    pub fn is_committed_relay_for_id(&self, packet_id: u32) -> bool {
        self.relay_states
            .iter()
            .any(|s| s.active && s.id == packet_id)
    }

    /// When a neighbor relays our packet (or one we committed to relay), mark `hears_us`.
    pub fn maybe_confirm_hears_us_from_relay(
        &mut self,
        gateway: u32,
        packet_from: u32,
        packet_id: u32,
    ) -> bool {
        if gateway == 0 || gateway == self.my_node {
            return false;
        }
        if packet_from != self.my_node && !self.is_committed_relay_for_id(packet_id) {
            return false;
        }
        let already = self
            .edges
            .find_node(self.my_node)
            .and_then(|n| n.find_edge(gateway))
            .map(|e| e.hears_us)
            .unwrap_or(false);
        if already {
            return false;
        }
        self.confirm_direct_neighbor_hears_us(gateway);
        true
    }

    pub fn has_active_relay_commits(&self) -> bool {
        self.relay_states.iter().any(|s| s.active)
    }

    pub fn role_allows_canceling_dupe(&self) -> bool {
        !matches!(
            self.device_role,
            DEVICE_ROLE_ROUTER | DEVICE_ROLE_ROUTER_LATE
        )
    }

    pub fn is_rebroadcaster(&self) -> bool {
        !crate::sr_role::role_is_mute(self.device_role)
    }

    pub fn confirm_direct_neighbor_hears_us(&mut self, neighbor: u32) {
        self.edges.set_edge_hears_us(self.my_node, neighbor, true);
    }

    pub fn clear_expired_commits(&mut self, now_ms: u32) {
        const MAX_HOLD_MS: u32 = 30_000;
        for slot in &mut self.relay_states {
            if !slot.active {
                continue;
            }
            if now_ms.wrapping_sub(slot.tx_after_ms) > MAX_HOLD_MS {
                slot.active = false;
            }
        }
    }

    pub fn run_maintenance(&mut self, now_ms: u32) -> MaintenanceReport {
        self.edges.ensure_local_node(self.my_node, now_ms);
        let before = self.neighbor_count();
        let edges_aged = self.edges.age_edges(
            self.my_node,
            now_ms,
            NEIGHBOR_TTL_MS,
            Some(&mut self.downstream),
        );
        self.prune_direct_signals(now_ms);
        let relay_in_graph = |relay: u32| self.edges.find_node(relay).is_some();
        let downstream_aged = self.downstream.age(now_ms, NEIGHBOR_TTL_MS, relay_in_graph);
        self.clear_expired_commits(now_ms);
        let (clear_hears_us, clear_hears_us_count) = self.capability.prune(now_ms, self.my_node);
        for &expired in &clear_hears_us[..clear_hears_us_count as usize] {
            self.edges.set_edge_hears_us(self.my_node, expired, false);
        }

        let after = self.neighbor_count();
        if before != after {
            self.topology_dirty = true;
            self.route_cache.clear();
        } else if edges_aged || downstream_aged {
            self.route_cache.clear();
        }

        let mut report = MaintenanceReport {
            topology_due: false,
            topology_dirty_send: false,
            neighbors: self.neighbor_count(),
            graph_log_due: false,
            graph_aged: if before != self.neighbor_count() || edges_aged {
                Some((before, self.neighbor_count()))
            } else {
                None
            },
        };

        if self.last_maintenance_ms == 0
            || now_ms.wrapping_sub(self.last_maintenance_ms) >= MAINTENANCE_LOG_MS
        {
            self.last_maintenance_ms = now_ms;
            report.graph_log_due = true;
        }

        let topo_gap = now_ms.wrapping_sub(self.last_topology_ms);
        if self.last_topology_ms == 0 || topo_gap >= TOPOLOGY_BROADCAST_MS {
            report.topology_due = true;
        } else if self.topology_dirty && topo_gap >= TOPOLOGY_DIRTY_MIN_MS {
            report.topology_due = true;
            report.topology_dirty_send = true;
        }

        report
    }

    pub fn last_topology_ms(&self) -> u32 {
        self.last_topology_ms
    }

    /// Uptime of the last topology broadcast that carried neighbours (0 = never).
    pub fn last_topology_list_ms(&self) -> u32 {
        self.last_topology_list_ms
    }

    pub fn commit_topology_broadcast(&mut self, now_ms: u32, dirty_send: bool) {
        self.last_topology_ms = now_ms;
        // A list with no entries (the boot broadcast) tells a requester nothing about who we
        // hear, so it does not count as having answered one.
        if self.neighbor_count() > 0 {
            self.last_topology_list_ms = now_ms.max(1);
        }
        self.topology_version = self.topology_version.wrapping_add(1);
        if dirty_send {
            self.topology_dirty = false;
        }
    }

    pub fn emit_topology_log<S: crate::sr_log::TopologyLogSink>(
        &self,
        node_num: u32,
        sink: &mut S,
    ) {
        use crate::sr_log::SrLogEvent;

        let mut entries = [NeighborEntry::default(); MAX_NEIGHBORS];
        let direct = self.fill_neighbor_entries(&mut entries);
        let graph_nodes = self.graph_node_count();
        let downstream_routes = self.downstream.count();
        if direct == 0 {
            sink.emit(SrLogEvent::NetworkTopologyHeader {
                direct_neighbors: 0,
                graph_nodes,
                downstream_routes,
            });
            sink.emit(SrLogEvent::NetworkTopologyUs { node_id: node_num });
            sink.emit(SrLogEvent::NetworkTopologyEmpty);
            self.emit_downstream_topology_log(sink);
            sink.emit(SrLogEvent::TopologyLoggingComplete);
            return;
        }

        sink.emit(SrLogEvent::NetworkTopologyHeader {
            direct_neighbors: direct,
            graph_nodes,
            downstream_routes,
        });
        sink.emit(SrLogEvent::NetworkTopologyUs { node_id: node_num });

        let mut direct_ids = [0u32; MAX_NEIGHBORS];
        for i in 0..direct as usize {
            direct_ids[i] = entries[i].node_id;
        }

        for (i, entry) in entries[..direct as usize].iter().copied().enumerate() {
            sink.emit(SrLogEvent::NetworkTopologyNeighbor {
                node_id: entry.node_id,
                rssi: entry.rssi,
                snr: entry.snr,
                hears_us: entry.hears_us,
                last: i + 1 == direct as usize,
            });

            let continue_pipe = i + 1 != direct as usize;
            if let Some(via_node) = self.edges.find_node(entry.node_id) {
                let mut mirrored = 0u8;
                for e in 0..via_node.edge_count as usize {
                    let edge = via_node.edges[e];
                    if edge.to == 0
                        || edge.to == node_num
                        || edge.to == entry.node_id
                        || Self::is_direct_id(edge.to, &direct_ids, direct)
                    {
                        continue;
                    }
                    mirrored += 1;
                }
                let mut seen = 0u8;
                for e in 0..via_node.edge_count as usize {
                    let edge = via_node.edges[e];
                    if edge.to == 0
                        || edge.to == node_num
                        || edge.to == entry.node_id
                        || Self::is_direct_id(edge.to, &direct_ids, direct)
                    {
                        continue;
                    }
                    seen += 1;
                    sink.emit(SrLogEvent::NetworkTopologyMirrored {
                        continue_pipe,
                        node_id: edge.to,
                        hears_us: edge.hears_us,
                        last_mirrored: seen == mirrored,
                    });
                }
            }
        }

        self.emit_downstream_topology_log(sink);
        sink.emit(SrLogEvent::TopologyLoggingComplete);
    }

    fn is_direct_id(node_id: u32, direct_ids: &[u32; MAX_NEIGHBORS], direct: u8) -> bool {
        direct_ids[..direct as usize].contains(&node_id)
    }

    fn emit_downstream_topology_log<S: crate::sr_log::TopologyLogSink>(&self, sink: &mut S) {
        use crate::sr_log::SrLogEvent;

        let count = self.downstream.count();
        if count == 0 {
            return;
        }
        sink.emit(SrLogEvent::NetworkTopologyDownstreamHeader { count });
        // Grouped by relay: one line per relay (continued when a branch exceeds a line) instead
        // of one line per destination. Relays are emitted in order of first appearance.
        let mut done = heapless::Vec::<u32, 64>::new();
        let mut emitted = 0u16;
        for i in 0..count {
            let Some(head) = self.downstream.entry(i) else {
                continue;
            };
            let relay = head.relay;
            let seen = if done.is_full() {
                (0..i).any(|j| self.downstream.entry(j).is_some_and(|e| e.relay == relay))
            } else {
                done.contains(&relay)
            };
            if seen {
                continue;
            }
            let _ = done.push(relay);
            let mut group = [0u32; crate::sr_log::DOWNSTREAM_LOG_GROUP];
            let mut len = 0usize;
            for j in i..count {
                let Some(entry) = self.downstream.entry(j) else {
                    continue;
                };
                if entry.relay != relay {
                    continue;
                }
                group[len] = entry.destination;
                len += 1;
                emitted += 1;
                if len == group.len() {
                    sink.emit(SrLogEvent::NetworkTopologyDownstreamGroup {
                        relay,
                        destinations: group,
                        len: len as u8,
                        last: emitted == count,
                    });
                    len = 0;
                }
            }
            if len > 0 {
                sink.emit(SrLogEvent::NetworkTopologyDownstreamGroup {
                    relay,
                    destinations: group,
                    len: len as u8,
                    last: emitted == count,
                });
            }
        }
    }

    fn find_relay(&self, from: u32, id: u32, radio_id: u8) -> Option<usize> {
        self.relay_states
            .iter()
            .position(|s| s.active && s.from == from && s.id == id && s.radio_id == radio_id)
    }

    fn alloc_relay_slot(&self) -> Option<usize> {
        self.relay_states.iter().position(|s| !s.active)
    }
}

#[cfg(test)]
impl NeighborGraph {
    fn test_has_edge(&self, from: u32, to: u32) -> bool {
        self.edges
            .find_node(from)
            .and_then(|n| n.find_edge(to))
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinated_relay::{
        slot_time_for_preset, transmission_record_window_ms, tx_delay_ms_worst, DEFAULT_SLOT_MS,
    };
    use crate::decode_packed_neighbors;
    use crate::graph::{calculate_etx, etx_to_fixed};
    use crate::nodeinfo::DEVICE_ROLE_REPEATER;
    use crate::topology::{write_packed_header, PackedNeighbor};
    use mesh_radio::{MODEM_SHORT_FAST, MODEM_SHORT_SLOW};

    #[test]
    fn recorded_transmission_expires_after_retention_window() {
        let mut graph = NeighborGraph::new();
        graph.set_modem_preset(MODEM_SHORT_SLOW);
        graph.record_node_transmission(0xBB, 42, 0);
        let window = transmission_record_window_ms(MODEM_SHORT_SLOW);
        assert!(graph.has_node_transmitted(0xBB, 42, window));
        assert!(!graph.has_node_transmitted(0xBB, 42, window + 1));

        graph.set_modem_preset(MODEM_SHORT_FAST);
        graph.record_node_transmission(0xCC, 7, 10_000);
        let fast_window = transmission_record_window_ms(MODEM_SHORT_FAST);
        assert!(graph.has_node_transmitted(0xCC, 7, 10_000 + fast_window));
        assert!(!graph.has_node_transmitted(0xCC, 7, 10_000 + fast_window + 1));
        assert!(fast_window > mesh_radio::contention_window_ms(MODEM_SHORT_FAST));
    }

    #[test]
    fn recorded_transmission_survives_t1_worst_delay() {
        const ME: u32 = 0xAA00_00AA;
        const GATEWAY: u32 = 0xBB00_00BB;
        const REMOTE: u32 = 0xCC00_00CC;
        const PACKET_ID: u32 = 0xDEAD_BEEF;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.set_modem_preset(MODEM_SHORT_SLOW);
        graph.observe_direct_neighbor(GATEWAY, -70, 8, 0, 0);
        graph.confirm_direct_neighbor_hears_us(GATEWAY);

        let t0 = 100_000u32;
        graph.observe_packet(REMOTE, 3, 2, 0xBB, -70, 12, t0, 0, Some(GATEWAY), PACKET_ID);

        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let cfg = mesh_radio::eu868_config_for_preset(MODEM_SHORT_SLOW);
        let airtime = mesh_radio::packet_time_ms(&cfg, 44, false);
        let t1_delay = tx_delay_ms_worst(slot).saturating_add(airtime);
        let at_t1 = t0.wrapping_add(t1_delay);
        assert!(graph.has_node_transmitted(GATEWAY, PACKET_ID, at_t1));
    }

    #[test]
    fn recorded_transmission_capacity_evicts_oldest() {
        let mut graph = NeighborGraph::new();
        let base = 10_000u32;
        for i in 0..MAX_NODE_TX_RECORDS as u32 {
            graph.record_node_transmission(0x1000 + i, i + 1, base + i);
        }
        let now = base + MAX_NODE_TX_RECORDS as u32;
        assert!(graph.has_node_transmitted(0x1000, 1, now));
        graph.record_node_transmission(0x9999, 99, now);
        assert!(!graph.has_node_transmitted(0x1000, 1, now));
        assert!(graph.has_node_transmitted(0x9999, 99, now));
        assert!(graph.has_node_transmitted(0x1001, 2, now));
    }

    #[test]
    fn direct_observe_records_source_transmission() {
        const ME: u32 = 0xAA00_00AA;
        const SOURCE: u32 = 0xBB00_00BB;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        let observed = graph.observe_packet(SOURCE, 3, 3, 0xBB, -70, 8, 100, 0, None, 42);
        assert!(observed.is_some());
        assert!(graph.has_node_transmitted(SOURCE, 42, 100));
    }

    #[test]
    fn relayed_observe_records_source_and_relayer_transmission() {
        const ME: u32 = 0xAA00_00AA;
        const RELAY: u32 = 0xBB00_00BB;
        const REMOTE: u32 = 0xCC00_00CC;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_packet(REMOTE, 3, 2, 0xBB, -70, 12, 1_000, 0, Some(RELAY), 42);
        assert!(graph.has_node_transmitted(REMOTE, 42, 1_000));
        assert!(graph.has_node_transmitted(RELAY, 42, 1_000));
    }

    #[test]
    fn relayed_observe_skips_placeholder_relayer_transmission() {
        const ME: u32 = 0xAA00_00AA;
        const REMOTE: u32 = 0xCC00_00CC;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        let placeholder = placeholder_node_id(0xBB);
        graph.observe_packet(REMOTE, 3, 2, 0xBB, -70, 12, 1_000, 0, None, 42);
        assert!(graph.has_node_transmitted(REMOTE, 42, 1_000));
        assert!(!graph.has_node_transmitted(placeholder, 42, 1_000));
    }

    #[test]
    fn record_heard_transmissions_skips_self_and_placeholders() {
        const ME: u32 = 0xAA00_00AA;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        let placeholder = placeholder_node_id(0xCD);
        graph.record_heard_transmissions(ME, 7, Some(placeholder), 0);
        assert!(!graph.has_node_transmitted(ME, 7, 0));
        assert!(!graph.has_node_transmitted(placeholder, 7, 0));
    }

    #[test]
    fn topology_health_requires_capable_direct_neighbor() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA);
        graph.observe_direct_neighbor(0xBB, -70, 8, 0, 0);
        graph.track_node_role(0xBB, DEVICE_ROLE_REPEATER, 0);
        assert!(graph.topology_healthy_for_broadcast());
        graph.capability_mut().track_topology(0xBB, false, 0);
        assert!(!graph.topology_healthy_for_broadcast());
    }

    #[test]
    fn relayed_packet_promotes_gateway_to_reported_neighbor() {
        const ME: u32 = 0xAA00_00AA;
        const RELAY: u32 = 0xBB00_00BB;
        const REMOTE: u32 = 0xCC00_00CC;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        assert_eq!(graph.neighbor_count(), 0);

        let observed = graph.observe_packet(REMOTE, 3, 2, 0xBB, -70, 12, 1_000, 0, Some(RELAY), 0);
        assert_eq!(
            observed.map(|(id, _, _, is_new, _)| (id, is_new)),
            Some((RELAY, true))
        );
        assert_eq!(graph.neighbor_count(), 1);

        let mut entries = [NeighborEntry::default(); MAX_NEIGHBORS];
        assert_eq!(graph.fill_neighbor_entries(&mut entries), 1);
        assert_eq!(entries[0].node_id, RELAY);
        assert_eq!(entries[0].rssi, -70);
        assert_eq!(entries[0].snr, 12);
    }

    #[test]
    fn relayed_packet_confirms_hears_us_for_our_packet() {
        const ME: u32 = 0xAA00_00AA;
        const RELAY: u32 = 0xBB00_00BB;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(RELAY, -80, 10, 0, 0);
        assert!(!graph
            .edges()
            .find_node(ME)
            .and_then(|n| n.find_edge(RELAY))
            .map(|e| e.hears_us)
            .unwrap_or(false));

        let observed = graph.observe_packet(ME, 3, 2, 0xBB, -70, 12, 1_000, 0, Some(RELAY), 42);
        assert_eq!(observed.map(|(_, _, _, _, hears)| hears), Some(true));
        assert!(graph
            .edges()
            .find_node(ME)
            .and_then(|n| n.find_edge(RELAY))
            .map(|e| e.hears_us)
            .unwrap_or(false));
    }

    #[test]
    fn relayed_packet_confirms_hears_us_for_committed_relay() {
        const ME: u32 = 0xAA00_00AA;
        const RELAY: u32 = 0xBB00_00BB;
        const FROM: u32 = 0xCC00_00CC;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(RELAY, -80, 10, 0, 0);
        graph.commit_relay(FROM, 99, 0, 8, RELAY, 100, 20, DEFAULT_SLOT_MS, ME, None);

        let observed = graph.observe_packet(FROM, 3, 2, 0xBB, -70, 12, 1_000, 0, Some(RELAY), 99);
        assert_eq!(observed.map(|(_, _, _, _, hears)| hears), Some(true));
        assert!(graph
            .edges()
            .find_node(ME)
            .and_then(|n| n.find_edge(RELAY))
            .map(|e| e.hears_us)
            .unwrap_or(false));
    }

    #[test]
    fn relayed_packet_does_not_add_direct_neighbor() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xB000_0002);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(0xA000_0001, -70, 8, 0, 0);
        assert_eq!(graph.neighbor_count(), 1);

        graph.observe_packet(0xC000_0003, 3, 2, 0xEF, -70, 8, 50, 0, None, 0);
        assert_eq!(
            graph.neighbor_count(),
            1,
            "remote sender on relayed packet must not become a direct neighbor"
        );
    }

    #[test]
    fn tracks_direct_neighbor_as_edge() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA);
        graph.observe_direct_neighbor(0x1234_5678, -80, 10, 1_000, 0);
        assert_eq!(graph.neighbor_count(), 1);
        graph.observe_direct_neighbor(0x1234_5678, -75, 11, 2_000, 0);
        assert_eq!(graph.neighbor_count(), 1);
        let mut entries = [NeighborEntry::default(); MAX_NEIGHBORS];
        graph.fill_neighbor_entries(&mut entries);
        assert_eq!(entries[0].rssi, -75);
        assert_eq!(entries[0].snr, 11);
    }

    #[test]
    fn relayed_packet_refreshes_direct_neighbor_signal_and_variance() {
        const ME: u32 = 0xAA00_00AA;
        const RELAY: u32 = 0xBB00_00BB;
        const REMOTE: u32 = 0xCC00_00CC;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(RELAY, -80, 10, 0, 0);
        let variance_before = graph
            .edges()
            .find_node(ME)
            .and_then(|n| n.find_edge(RELAY))
            .map(|e| e.etx_variance)
            .unwrap_or(0);

        graph.observe_packet(REMOTE, 3, 2, 0xBB, -70, 12, 1_000, 0, Some(RELAY), 0);

        let mut entries = [NeighborEntry::default(); MAX_NEIGHBORS];
        assert_eq!(graph.fill_neighbor_entries(&mut entries), 1);
        assert_eq!(entries[0].node_id, RELAY);
        assert_eq!(entries[0].rssi, -70);
        assert_eq!(entries[0].snr, 12);
        let variance_after = graph
            .edges()
            .find_node(ME)
            .and_then(|n| n.find_edge(RELAY))
            .map(|e| e.etx_variance)
            .unwrap_or(0);
        assert!(
            variance_after > variance_before,
            "reported-edge ETX variance should track relay-heard signal changes"
        );
    }

    #[test]
    fn relayed_packet_skips_signal_refresh_for_non_direct_gateway() {
        const ME: u32 = 0xAA00_00AA;
        const DIRECT: u32 = 0xDD00_00DD;
        const REMOTE: u32 = 0xCC00_00CC;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(DIRECT, -80, 10, 0, 0);
        graph.observe_packet(REMOTE, 3, 2, 0xBB, -70, 12, 1_000, 0, None, 0);

        let mut entries = [NeighborEntry::default(); MAX_NEIGHBORS];
        graph.fill_neighbor_entries(&mut entries);
        assert_eq!(entries[0].rssi, -80);
        assert_eq!(entries[0].snr, 10);
    }

    #[test]
    fn merge_topology_adds_mirrored_edges() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA);
        graph.observe_direct_neighbor(0xBB, -70, 8, 100, 0);
        let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE + 8];
        write_packed_header(&mut packed, 1, true);
        packed[5..9].copy_from_slice(&0xCCu32.to_le_bytes());
        packed[9] = 0xB6; // rssi-ish
        packed[10] = 8;
        let (header, neighbors) =
            crate::topology::decode_packed_neighbors(&packed, packed.len()).unwrap();
        let result = graph.merge_topology(0xBB, &header, &neighbors, true, 200, 0);
        assert!(matches!(result, TopologyMergeResult::Applied { .. }));
    }

    #[test]
    fn passive_sender_listing_us_confirms_hears_us() {
        const ME: u32 = 0xAA00_00AA;
        const PASSIVE: u32 = 0xBB00_00BB;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.observe_direct_neighbor(PASSIVE, -70, 8, 100, 0);
        assert!(!graph.edge_hears_us(PASSIVE));
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, false); // passive SR sender
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let us = PackedNeighbor {
            node_id: ME,
            rssi: -72,
            snr: 7,
            signal_routing_active: true,
            hears_us: true,
            etx_variance: 0,
        };
        let result = graph.merge_topology(PASSIVE, &header, &[us], true, 200, 0);
        assert!(matches!(result, TopologyMergeResult::Applied { .. }));
        assert!(graph.edge_hears_us(PASSIVE));
    }

    #[test]
    fn passive_sender_listing_a_peer_confirms_the_peer_hears_it() {
        const ME: u32 = 0xAA00_00AA;
        const PEER: u32 = 0xBB00_00BB;
        const PASSIVE: u32 = 0xCC00_00CC;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.observe_direct_neighbor(PEER, -70, 8, 100, 0);
        graph.observe_direct_neighbor(PASSIVE, -70, 8, 100, 0);
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (active, _) = decode_packed_neighbors(&packed, 8).unwrap();
        // The peer reports the passive node before the passive node has listed it.
        let listed = PackedNeighbor {
            node_id: PASSIVE,
            rssi: -60,
            snr: 10,
            signal_routing_active: false,
            hears_us: false,
            etx_variance: 0,
        };
        graph.merge_topology(PEER, &active, &[listed], true, 200, 0);
        let peer_edge = |g: &NeighborGraph| {
            g.edges()
                .find_node(PEER)
                .and_then(|n| n.find_edge(PASSIVE))
                .map(|e| e.hears_us)
        };
        assert_eq!(peer_edge(&graph), Some(false));
        // The passive node lists the peer: that proves it hears the peer.
        write_packed_header(&mut packed, 1, false);
        let (passive, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let lists_peer = PackedNeighbor {
            node_id: PEER,
            ..listed
        };
        graph.merge_topology(PASSIVE, &passive, &[lists_peer], true, 300, 0);
        assert_eq!(peer_edge(&graph), Some(true));
        // A node the peer never reported gets no edge invented for it.
        assert!(graph
            .edges()
            .find_node(PASSIVE)
            .map(|n| n.find_edge(0xDD00_00DD).is_none())
            .unwrap_or(true));
    }

    /// Field case of 2026-09-03 19:43: the gateway hears the phone poorly, so the phone is the
    /// one uncovered neighbour and both nicenanos compete to relay for it. Each had just learned
    /// the phone from its topology listing, and each modelled the other as not covering it, so
    /// both took slot 0. With the listing applied to the peer's edge too, the costs tie and the
    /// packet-parity tie-break picks one relayer on both nodes.
    #[test]
    fn peers_that_both_cover_a_passive_neighbour_agree_on_one_relayer() {
        const A: u32 = 0xbdac_ce55;
        const B: u32 = 0x046b_553a;
        const PH: u32 = 0x979e_d146;
        const GW: u32 = 0x63dc_8f8c;
        const SRC: u32 = 0xda73_f34c;
        let nb = |id: u32, rssi: i8, snr: i8, hears_us: bool| PackedNeighbor {
            node_id: id,
            rssi,
            snr,
            signal_routing_active: true,
            hears_us,
            etx_variance: 0,
        };
        let mut graph = NeighborGraph::new();
        graph.set_my_node(A);
        for (n, rssi, snr) in [(B, -1i16, 13i8), (GW, -73, 12), (PH, -48, 14)] {
            graph.observe_direct_neighbor(n, rssi, snr, 100, 0);
            graph.confirm_direct_neighbor_hears_us(n);
        }
        graph.capability_mut().track_topology(B, true, 100);
        graph.capability_mut().track_topology(GW, true, 100);
        graph.capability_mut().track_topology(PH, false, 100);
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 6, true);
        let (active, _) = decode_packed_neighbors(&packed, 8).unwrap();
        // B's report: it hears the phone as well as we do, but has no proof the phone hears it.
        graph.merge_topology(
            B,
            &active,
            &[nb(PH, -46, 12, false), nb(A, -1, 13, true)],
            true,
            150,
            0,
        );
        // The gateway hears both of us well and the phone barely (ETX far above 7).
        graph.merge_topology(
            GW,
            &active,
            &[
                nb(A, -73, 12, true),
                nb(B, -73, 12, true),
                nb(PH, -105, -3, true),
            ],
            true,
            160,
            0,
        );
        // The phone's passive listing names both of us.
        write_packed_header(&mut packed, 3, false);
        let (passive, _) = decode_packed_neighbors(&packed, 8).unwrap();
        graph.merge_topology(
            PH,
            &passive,
            &[nb(A, -50, 12, false), nb(B, -50, 12, false)],
            true,
            170,
            0,
        );

        let even = graph.plan_broadcast_relay(0xcc21_2ebc, SRC, GW, 0xffff_ffff, 200, 91);
        assert_eq!(
            &even.ranked[..1],
            &[B],
            "even packet id: lower node id relays"
        );
        assert!(!even.should_relay);
        let odd = graph.plan_broadcast_relay(0xcc21_2ebd, SRC, GW, 0xffff_ffff, 200, 91);
        assert!(odd.should_relay, "odd packet id: higher node id relays");
        assert_eq!(odd.slot_index, 0);
    }

    #[test]
    fn poor_link_does_not_count_as_coverage() {
        const ME: u32 = 0xAA00_00AA;
        const PEER: u32 = 0xBB00_00BB;
        const U: u32 = 0xCC00_00CC;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.observe_direct_neighbor(PEER, -70, 8, 100, 0);
        graph.observe_direct_neighbor(U, -70, 8, 100, 0);
        graph.confirm_direct_neighbor_hears_us(PEER);
        graph.confirm_direct_neighbor_hears_us(U);
        // U confirmed hearing the peer, but at ETX 40 (heard once, barely): not coverage.
        graph
            .edges_mut()
            .update_edge(ME, PEER, U, 40.0, 100, EdgeSource::Mirrored, true, 0);
        graph.edges_mut().set_edge_hears_us(PEER, U, true);
        assert!(graph.has_unique_coverage(&[PEER]));
        graph
            .edges_mut()
            .update_edge(ME, PEER, U, 1.5, 100, EdgeSource::Mirrored, true, 0);
        assert!(!graph.has_unique_coverage(&[PEER]));
    }

    #[test]
    fn owned_mute_neighbour_is_unique_coverage() {
        const ME: u32 = 0xAA00_00AA;
        const HIGH_PEER: u32 = 0xBB00_00BB;
        const MUTE: u32 = 0xCC00_00CC;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        for n in [HIGH_PEER, MUTE] {
            graph.observe_direct_neighbor(n, -70, 8, 100, 0);
        }
        graph.confirm_direct_neighbor_hears_us(HIGH_PEER);
        graph.capability_mut().track_topology(HIGH_PEER, true, 100);
        graph.track_node_role(MUTE, crate::nodeinfo::DEVICE_ROLE_CLIENT_MUTE, 100);
        // The mute node never earns hears_us, yet it is ours: the peer's copy does not reach it.
        assert!(graph.has_unique_coverage(&[HIGH_PEER]));
        // Once the transmitter is confirmed to reach it, it is covered like any other neighbour.
        graph
            .edges_mut()
            .update_edge(ME, HIGH_PEER, MUTE, 1.5, 100, EdgeSource::Mirrored, true, 0);
        graph.edges_mut().set_edge_hears_us(HIGH_PEER, MUTE, true);
        assert!(!graph.has_unique_coverage(&[HIGH_PEER]));
    }

    /// Ownership of a neighbour nobody can confirm goes by the measured link, with the node id
    /// only as a tie-break: the lowest id may be the node that hears it worst.
    #[test]
    fn mute_neighbour_owner_is_the_best_link_then_the_lowest_id() {
        const ME: u32 = 0xAA00_00AA;
        const NEAR_PEER: u32 = 0xEE00_00EE; // 0xFF.... would read as a placeholder id
        const MUTE: u32 = 0xCC00_00CC;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        for n in [NEAR_PEER, MUTE] {
            graph.observe_direct_neighbor(n, -70, 8, 100, 0);
        }
        graph.confirm_direct_neighbor_hears_us(NEAR_PEER);
        graph.capability_mut().track_topology(NEAR_PEER, true, 100);
        graph.track_node_role(MUTE, crate::nodeinfo::DEVICE_ROLE_CLIENT_MUTE, 100);
        // A higher-id peer that hears the mute node a bucket better owns it, id notwithstanding.
        graph
            .edges_mut()
            .update_edge(ME, ME, MUTE, 3.0, 100, EdgeSource::Reported, true, 0);
        graph
            .edges_mut()
            .update_edge(ME, NEAR_PEER, MUTE, 1.0, 100, EdgeSource::Mirrored, true, 0);
        assert_eq!(
            crate::graph::coverage_owner(graph.edges(), graph.capability(), ME, true, MUTE),
            NEAR_PEER
        );
        // Same bucket: the lowest id decides, so it comes back to us.
        graph
            .edges_mut()
            .update_edge(ME, NEAR_PEER, MUTE, 3.0, 100, EdgeSource::Mirrored, true, 0);
        assert_eq!(
            crate::graph::coverage_owner(graph.edges(), graph.capability(), ME, true, MUTE),
            ME
        );
        // A mute node never owns anything: it does not relay.
        graph.track_node_role(NEAR_PEER, crate::nodeinfo::DEVICE_ROLE_CLIENT_MUTE, 100);
        graph
            .capability_mut()
            .track_role(NEAR_PEER, crate::nodeinfo::DEVICE_ROLE_CLIENT_MUTE, 100);
        assert_eq!(
            crate::graph::coverage_owner(graph.edges(), graph.capability(), ME, false, MUTE),
            0,
            "we cannot own it either when our own role does not relay"
        );
    }

    fn topo_header(version: u8) -> crate::topology::PackedHeader {
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, version, true);
        decode_packed_neighbors(&packed, 8).unwrap().0
    }

    fn peer_report(
        graph: &mut NeighborGraph,
        peer: u32,
        version: u8,
        now_ms: u32,
    ) -> TopologyMergeResult {
        let listed = PackedNeighbor {
            node_id: 0xCC00_00CC,
            rssi: -70,
            snr: 8,
            signal_routing_active: true,
            hears_us: true,
            etx_variance: 0,
        };
        graph.merge_topology(peer, &topo_header(version), &[listed], true, now_ms, 0)
    }

    /// A version far behind the stored one is stale on its own: the forward window still holds.
    #[test]
    fn topology_version_going_backwards_is_stale() {
        const ME: u32 = 0xAA00_00AA;
        const PEER: u32 = 0xBB00_00BB;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.observe_direct_neighbor(PEER, -70, 8, 100, 0);
        assert!(matches!(
            peer_report(&mut graph, PEER, 98, 1_000),
            TopologyMergeResult::Applied { .. }
        ));
        assert!(matches!(
            peer_report(&mut graph, PEER, 1, 2_000),
            TopologyMergeResult::Stale {
                received: 1,
                last: 98
            }
        ));
        assert!(graph.take_topology_version_resync().is_none());
    }

    /// The peer's empty boot broadcast restarts its counter for us too.
    #[test]
    fn peer_boot_broadcast_resets_its_topology_version() {
        const ME: u32 = 0xAA00_00AA;
        const PEER: u32 = 0xBB00_00BB;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.observe_direct_neighbor(PEER, -70, 8, 100, 0);
        assert!(matches!(
            peer_report(&mut graph, PEER, 98, 1_000),
            TopologyMergeResult::Applied { .. }
        ));
        // Boot broadcast: zero neighbours, version 0, direct, SR-active.
        let boot = graph.merge_topology(PEER, &topo_header(0), &[], true, 2_000, 0);
        assert!(matches!(
            boot,
            TopologyMergeResult::Applied { neighbors: 0, .. }
        ));
        assert_eq!(graph.take_topology_version_resync(), Some((PEER, 0, 98)));
        // Its first real list after the reboot is accepted.
        assert!(matches!(
            peer_report(&mut graph, PEER, 1, 3_000),
            TopologyMergeResult::Applied { .. }
        ));
        assert!(matches!(
            peer_report(&mut graph, PEER, 2, 4_000),
            TopologyMergeResult::Applied { .. }
        ));
    }

    /// 2026-09-06 19:14: A rebooted, B never processed its boot broadcast and rejected versions
    /// 1, 2 and 3 as stale against 13. Two rejected versions climbing one by one are a restart.
    #[test]
    fn peer_restart_is_accepted_after_two_climbing_stale_reports() {
        const ME: u32 = 0xAA00_00AA;
        const PEER: u32 = 0xBB00_00BB;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.observe_direct_neighbor(PEER, -70, 8, 100, 0);
        assert!(matches!(
            peer_report(&mut graph, PEER, 13, 1_000),
            TopologyMergeResult::Applied { .. }
        ));
        assert!(matches!(
            peer_report(&mut graph, PEER, 1, 2_000),
            TopologyMergeResult::Stale { .. }
        ));
        // A repeat of the rejected version, or a jump, is not a climb.
        assert!(matches!(
            peer_report(&mut graph, PEER, 1, 2_500),
            TopologyMergeResult::Stale { .. }
        ));
        assert!(matches!(
            peer_report(&mut graph, PEER, 5, 3_000),
            TopologyMergeResult::Stale { .. }
        ));
        assert!(matches!(
            peer_report(&mut graph, PEER, 6, 4_000),
            TopologyMergeResult::Applied { .. }
        ));
        assert_eq!(graph.take_topology_version_resync(), Some((PEER, 6, 13)));
        assert!(matches!(
            peer_report(&mut graph, PEER, 7, 5_000),
            TopologyMergeResult::Applied { .. }
        ));
    }

    /// 2026-09-06 19:16: Dura's boot broadcast cleared B's `hears_us` for it. An empty list
    /// says nothing about who hears the sender.
    #[test]
    fn empty_list_does_not_clear_hears_us() {
        const ME: u32 = 0xAA00_00AA;
        const PEER: u32 = 0xBB00_00BB;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.observe_direct_neighbor(PEER, -70, 8, 100, 0);
        graph.confirm_direct_neighbor_hears_us(PEER);
        assert!(graph.caps_last_hop(PEER) || graph.edge_hears_us_for_test(PEER));
        let boot = graph.merge_topology(PEER, &topo_header(0), &[], true, 2_000, 0);
        assert!(matches!(boot, TopologyMergeResult::Applied { .. }));
        assert!(
            graph.edge_hears_us_for_test(PEER),
            "a boot broadcast is a restart notice, not a neighbour list"
        );
    }

    /// 2026-09-06 20:49: angl heard Czar's boot broadcast only as A's relayed copy and called
    /// Czar's reports stale for twenty minutes. The restart notice is valid however it arrived.
    #[test]
    fn relayed_boot_broadcast_resets_the_topology_version_too() {
        const ME: u32 = 0xAA00_00AA;
        const PEER: u32 = 0xBB00_00BB;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.observe_direct_neighbor(PEER, -70, 8, 100, 0);
        assert!(matches!(
            peer_report(&mut graph, PEER, 117, 1_000),
            TopologyMergeResult::Applied { .. }
        ));
        let boot = graph.merge_topology(PEER, &topo_header(0), &[], false, 2_000, 0);
        assert!(matches!(boot, TopologyMergeResult::Applied { .. }));
        assert_eq!(graph.take_topology_version_resync(), Some((PEER, 0, 117)));
        assert!(matches!(
            peer_report(&mut graph, PEER, 1, 3_000),
            TopologyMergeResult::Applied { .. }
        ));
    }

    /// The boot broadcast was missed: after two quiet intervals any version is accepted.
    #[test]
    fn passive_peer_boot_broadcast_resets_its_topology_version_too() {
        const PEER: u32 = 0xB000_000B;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xA000_000A);
        assert!(matches!(
            peer_report(&mut graph, PEER, 30, 1_000),
            TopologyMergeResult::Applied { .. }
        ));
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 0, false);
        let passive_boot = decode_packed_neighbors(&packed, 8).unwrap().0;
        assert!(matches!(
            graph.merge_topology(PEER, &passive_boot, &[], true, 2_000, 0),
            TopologyMergeResult::Applied { .. }
        ));
        assert!(
            matches!(
                peer_report(&mut graph, PEER, 1, 3_000),
                TopologyMergeResult::Applied { .. }
            ),
            "first list after a passive peer's reboot must be accepted"
        );
    }

    #[test]
    fn peer_topology_resyncs_after_two_silent_intervals() {
        const ME: u32 = 0xAA00_00AA;
        const PEER: u32 = 0xBB00_00BB;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.observe_direct_neighbor(PEER, -70, 8, 100, 0);
        assert!(matches!(
            peer_report(&mut graph, PEER, 98, 1_000),
            TopologyMergeResult::Applied { .. }
        ));
        assert!(matches!(
            peer_report(&mut graph, PEER, 3, 1_000 + TOPOLOGY_RESYNC_MS - 1),
            TopologyMergeResult::Stale { .. }
        ));
        assert!(matches!(
            peer_report(&mut graph, PEER, 3, 1_000 + TOPOLOGY_RESYNC_MS),
            TopologyMergeResult::Applied { .. }
        ));
        assert_eq!(graph.take_topology_version_resync(), Some((PEER, 3, 98)));
        // Back in the forward window from the new base.
        assert!(matches!(
            peer_report(&mut graph, PEER, 4, 1_000 + TOPOLOGY_RESYNC_MS + 10),
            TopologyMergeResult::Applied { .. }
        ));
        assert!(
            matches!(
                peer_report(&mut graph, PEER, 4, 1_000 + TOPOLOGY_RESYNC_MS + 20),
                TopologyMergeResult::Applied { .. }
            ),
            "same version is accepted as a repeat"
        );
        assert!(
            matches!(
                peer_report(&mut graph, PEER, 3, 1_000 + TOPOLOGY_RESYNC_MS + 30),
                TopologyMergeResult::Stale { .. }
            ),
            "going backwards inside the window is still stale"
        );
    }

    #[test]
    fn chunked_topology_clears_unlisted_hears_us_only_after_last_chunk() {
        const ME: u32 = 0x1100_0011;
        const SENDER: u32 = 0xAA00_00AA;
        const IN_CHUNK2: u32 = 0xBB00_00BB;
        const UNLISTED: u32 = 0xDD00_00DD;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        for node in [IN_CHUNK2, UNLISTED] {
            graph.edges.ensure_local_node(node, 1_000);
            graph.edges.update_edge(
                ME,
                node,
                SENDER,
                2.0,
                1_000,
                crate::graph::EdgeSource::Reported,
                true,
                0,
            );
            graph.edges.set_edge_hears_us(node, SENDER, true);
        }
        let hears = |g: &NeighborGraph, from: u32| {
            g.edges
                .find_node(from)
                .and_then(|n| n.find_edge(SENDER))
                .map(|e| e.hears_us)
                .unwrap_or(false)
        };
        let entry = |id: u32| PackedNeighbor {
            node_id: id,
            rssi: -70,
            snr: 8,
            signal_routing_active: true,
            hears_us: true,
            etx_variance: 0,
        };
        let header = |more: bool, cont: bool| {
            let mut p = [0u8; 16];
            write_packed_header_chunk(&mut p, 7, true, more, cont);
            decode_packed_neighbors(&p, 8).unwrap().0
        };

        // A continuation whose first chunk was missed must not clear anything.
        graph.merge_topology(
            SENDER,
            &header(false, true),
            &[entry(0xCC00_00CC)],
            true,
            2_000,
            0,
        );
        assert!(hears(&graph, IN_CHUNK2));
        assert!(hears(&graph, UNLISTED));

        // Chunk 0 lists a third node only; IN_CHUNK2 arrives in the second packet.
        graph.merge_topology(
            SENDER,
            &header(true, false),
            &[entry(0xCC00_00CC)],
            true,
            3_000,
            0,
        );
        assert!(
            hears(&graph, IN_CHUNK2),
            "not cleared while chunks are pending"
        );
        assert!(
            hears(&graph, UNLISTED),
            "not cleared while chunks are pending"
        );
        // Another node's complete report lands between the two chunks: it must not disturb the
        // gathering of SENDER's list (one slot per sender).
        const OTHER: u32 = 0xEE00_00EE;
        graph.merge_topology(
            OTHER,
            &header(false, false),
            &[entry(0xCC00_00CC)],
            true,
            3_200,
            0,
        );
        graph.merge_topology(
            SENDER,
            &header(false, true),
            &[entry(IN_CHUNK2)],
            true,
            3_500,
            0,
        );
        assert!(hears(&graph, IN_CHUNK2), "listed in the second chunk");
        assert!(!hears(&graph, UNLISTED), "absent from the whole list");
    }

    #[test]
    fn large_neighbourhood_splits_into_flagged_chunks() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0x1100_0011);
        for i in 0..30u32 {
            graph.observe_direct_neighbor(0x2000_0000 + i, -60, 8, 1_000, 0);
        }
        assert_eq!(
            graph.neighbor_count(),
            30,
            "cap must hold 30 direct neighbours"
        );
        assert_eq!(graph.topology_packet_count(), 2);
        let mut buf = [0u8; 256];
        let len0 = graph.build_topology_chunk(0, 3, &mut buf).unwrap();
        let (h0, n0) = decode_packed_neighbors(&buf[..len0], 32).unwrap();
        assert!(h0.more_chunks && !h0.continuation && !h0.is_complete_list());
        assert_eq!(n0.len(), MAX_NEIGHBORS_PER_PACKET);
        let len1 = graph.build_topology_chunk(1, 3, &mut buf).unwrap();
        let (h1, n1) = decode_packed_neighbors(&buf[..len1], 32).unwrap();
        assert!(!h1.more_chunks && h1.continuation);
        assert_eq!(n1.len(), 2);
        assert!(graph.build_topology_chunk(2, 3, &mut buf).is_none());
    }

    #[test]
    fn relayed_packet_inference_prices_the_path_per_hop_not_by_the_relay_signal() {
        const ME: u32 = 0x1100_0011;
        const RELAYER: u32 = 0xBB00_00BB;
        const FAR: u32 = 0xFA00_00FA;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.observe_direct_neighbor(RELAYER, -16, 14, 1_000, 0);
        // FAR's packet arrives via RELAYER after two hops, at bench strength (-16 dBm).
        graph.observe_packet(FAR, 7, 5, 0xBB, -16, 14, 2_000, 0, Some(RELAYER), 0x77);
        let route = graph.get_route(FAR, 2_000);
        assert_eq!(route.next_hop, RELAYER);
        let nominal =
            crate::graph::etx_to_fixed(calculate_etx(INFERRED_LINK_RSSI, INFERRED_LINK_SNR));
        assert!(
            route.cost_fixed as u32 >= 2 * nominal as u32,
            "two inferred hops must cost at least twice the nominal link: {} < {}",
            route.cost_fixed,
            2 * nominal as u32
        );
    }

    #[test]
    fn rebroadcast_cancels_commit() {
        let mut graph = NeighborGraph::new();
        graph.commit_relay(1, 2, 0, 8, 1, 100, 20, DEFAULT_SLOT_MS, 0xAA, None);
        assert!(graph.relay_tx_after(1, 2, 0).is_some());
        graph.cancel_relay_on_rebroadcast(1, 2, 3, 2, 0xAB, 0xDEAD_BEEF, 100);
        assert!(graph.relay_tx_after(1, 2, 0).is_none());
    }

    #[test]
    fn find_best_relay_prefers_stock_router() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xCC00_00CC);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 0, 0);
        graph.observe_direct_neighbor(0xDD00_00DD, -72, 7, 0, 0);
        graph.track_node_role(0xDD00_00DD, DEVICE_ROLE_ROUTER, 0);
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, false);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let neighbor = PackedNeighbor {
            node_id: 0xBB00_00BB,
            rssi: -75,
            snr: 8,
            signal_routing_active: false,
            hears_us: false,
            etx_variance: 0,
        };
        graph.merge_topology(0xDD00_00DD, &header, &[neighbor], true, 0, 0);
        assert_eq!(
            graph.find_best_relay_candidate(99, 0xBB00_00BB, 0),
            0xDD00_00DD
        );
    }

    #[test]
    fn find_best_relay_skips_packet_sender() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xCC00_00CC);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 0, 0);
        assert_eq!(
            graph.find_best_relay_candidate(99, 0xBB00_00BB, 0),
            0xCC00_00CC
        );
    }

    #[test]
    fn relayed_packet_creates_placeholder_edge() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA00_00AA);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 0, 0);
        graph.observe_packet(0xBB00_00BB, 3, 2, 0xCD, -70, 8, 100, 0, None, 0);
        let placeholder = placeholder_node_id(0xCD);
        assert!(graph.test_has_edge(placeholder, 0xBB00_00BB));
    }

    #[test]
    fn first_relay_of_our_packet_by_unknown_relayer_stores_hears_us() {
        const ME: u32 = 0xAA00_00AA;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        // Our own packet comes back relayed by a never-seen relay byte: the placeholder edge
        // is created and confirmed in the same observation.
        let observed = graph.observe_packet(ME, 3, 2, 0xCD, -70, 8, 100, 0, None, 0x42);
        let placeholder = placeholder_node_id(0xCD);
        let (gateway, _, _, _, hears_us) = observed.expect("relayed observation");
        assert_eq!(gateway, placeholder);
        assert!(hears_us, "confirmation must be reported on the first relay");
        assert!(
            graph.edge_hears_us(placeholder),
            "flag must be stored on the new us->relay edge"
        );
        // Resolving the placeholder to the real node keeps the confirmed flag.
        assert!(graph.resolve_placeholder(placeholder, 0xBEEF_00CD, 200));
        assert!(graph.edge_hears_us(0xBEEF_00CD));
    }

    #[test]
    fn relayed_packet_creates_downstream_entry() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA00_00AA);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_packet(0xBB00_00BB, 3, 2, 0xCD, -70, 8, 100, 0, None, 0);

        let placeholder = placeholder_node_id(0xCD);
        assert!(graph.test_has_edge(0xAA00_00AA, placeholder));
        assert!(graph.test_has_edge(placeholder, 0xBB00_00BB));
        assert_eq!(
            graph.get_downstream_relay(0xBB00_00BB, 200),
            Some(placeholder)
        );
    }

    #[test]
    fn relayed_packet_does_not_mark_topology_dirty() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA00_00AA);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 0, 0);
        graph.commit_topology_broadcast(1, true);

        for t in (1..20).map(|i| i * 1_000) {
            graph.observe_packet(0xCC00_00CC, 3, 2, 0xCD, -70, 8, t, 0, None, 0);
        }
        assert!(graph.get_downstream_relay(0xCC00_00CC, 20_000).is_some());

        let report = graph.run_maintenance(350_000);
        assert!(!report.topology_dirty_send);
        assert!(!report.topology_due);
    }

    #[test]
    fn relayed_packet_with_known_relay_uses_real_gateway() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA00_00AA);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        let relay = 0x1000_00CD;
        graph.observe_direct_neighbor(relay, -70, 8, 0, 0);
        graph.observe_packet(0xBB00_00BB, 3, 2, 0xCD, -70, 8, 100, 0, Some(relay), 0);

        let placeholder = placeholder_node_id(0xCD);
        assert!(!graph.has_graph_node(placeholder));
        assert_eq!(graph.get_downstream_relay(0xBB00_00BB, 200), Some(relay));
        assert!(graph.test_has_edge(relay, 0xBB00_00BB));
    }

    #[test]
    fn resolve_placeholder_rejects_low_byte_mismatch() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA00_00AA);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        // Source low byte must differ from relay byte so a placeholder is created.
        graph.observe_packet(0xBEEF_00AB, 3, 2, 0xCD, -70, 8, 100, 0, None, 0);
        let placeholder = placeholder_node_id(0xCD);
        assert!(!graph.resolve_placeholder(placeholder, 0x1234_00AB, 200));
        assert!(graph.has_graph_node(placeholder));
    }

    #[test]
    fn relayed_packet_keeps_placeholder_until_direct_frame() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA00_00AA);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        let relay = 0x1000_00CD;
        graph.observe_packet(0xBB00_00BB, 3, 2, 0xCD, -70, 8, 100, 0, None, 0);
        let placeholder = placeholder_node_id(0xCD);
        assert!(graph.has_graph_node(placeholder));

        // Relayed frame must not resolve even when the real relay is already known.
        graph.observe_packet(0xBB00_00BB, 3, 2, 0xCD, -70, 8, 200, 0, Some(relay), 0);
        assert!(graph.has_graph_node(placeholder));
        assert_eq!(
            graph.get_downstream_relay(0xBB00_00BB, 300),
            Some(placeholder)
        );
    }

    #[test]
    fn resolve_placeholder_transfers_downstream_and_removes_node() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA00_00AA);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_packet(0xBEEF_00AB, 3, 2, 0xCD, -70, 8, 100, 0, None, 0);
        let placeholder = placeholder_node_id(0xCD);
        graph
            .downstream_mut()
            .update(0xAA00_00AA, 0xDD00_00DD, placeholder, 2.0, 100, false, 0);
        assert!(graph.resolve_placeholder(placeholder, 0xBEEF_00CD, 200));
        assert!(!graph.has_graph_node(placeholder));
        assert_eq!(
            graph.get_downstream_relay(0xDD00_00DD, 200),
            Some(0xBEEF_00CD)
        );
    }

    #[test]
    fn resolve_placeholder_carries_hears_us_to_real_node() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA00_00AA);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        let placeholder = placeholder_node_id(0xCD);
        graph.observe_packet(0xBB00_00BB, 3, 2, 0xCD, -70, 8, 100, 0, None, 42);
        assert!(graph.maybe_confirm_hears_us_from_relay(placeholder, 0xAA00_00AA, 42));
        assert!(graph.resolve_placeholder(placeholder, 0xBEEF_00CD, 200));
        assert!(graph
            .edges()
            .find_node(0xAA00_00AA)
            .and_then(|n| n.find_edge(0xBEEF_00CD))
            .map(|e| e.hears_us)
            .unwrap_or(false));
    }

    #[test]
    fn merge_topology_records_asymmetric_downstream_skip() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(0xBB, -70, 8, 0, 0);
        let remote = PackedNeighbor {
            node_id: 0xCC,
            rssi: -72,
            snr: 8,
            signal_routing_active: true,
            hears_us: false,
            etx_variance: 0,
        };
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        let result = graph.merge_topology(0xBB, &header, &[remote], true, 200, 0);
        assert!(matches!(result, TopologyMergeResult::Applied { .. }));
        let skips: heapless::Vec<_, 4> = graph.drain_merge_asymmetric_skips().collect();
        assert_eq!(skips.as_slice(), &[(0xBB, 0xCC)]);
    }

    const COV_ME: u32 = 0x1000_0001;
    const COV_A: u32 = 0xA000_000A;
    const COV_B: u32 = 0xB000_000B;

    #[test]
    fn has_unique_coverage_detects_gap() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(COV_ME);
        graph.observe_direct_neighbor(COV_A, -70, 8, 0, 0);
        graph.observe_direct_neighbor(COV_B, -70, 8, 0, 0);
        graph.confirm_direct_neighbor_hears_us(COV_A);
        graph.confirm_direct_neighbor_hears_us(COV_B);
        assert!(graph.has_unique_coverage(&[COV_A]));
    }

    /// `hears_us` is sticky: a neighbour that confirmed hearing us once keeps the flag while its
    /// link decays. Ours to cover is not the same as reachable, so the cancel path asks `covers`
    /// too — otherwise a queued relay is kept for a node the ranking refuses to serve.
    #[test]
    fn a_sticky_confirmation_behind_a_decayed_link_is_not_ours_to_cover() {
        const ME: u32 = 0xAA00_00AA;
        const SRC: u32 = 0xCC00_00CC;
        const EDGE: u32 = 0xEE00_00EE;
        let mut graph = NeighborGraph::new();
        graph.set_my_node(ME);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(EDGE, -70, 8, 1_000, 0);
        graph.confirm_direct_neighbor_hears_us(EDGE);
        assert_eq!(
            graph.unique_coverage_neighbor(&[SRC]),
            Some(EDGE),
            "a sound confirmed link is ours"
        );
        // The link decays to the heard-once sentinel in both directions, as a fresh observation
        // of a barely-audible neighbour writes it; the confirmation stays.
        for (from, to) in [(ME, EDGE), (EDGE, ME)] {
            graph
                .edges_mut()
                .update_edge(ME, from, to, 40.0, 1_000, EdgeSource::Reported, true, 0);
        }
        assert_eq!(
            graph.unique_coverage_neighbor(&[SRC]),
            None,
            "confirmed but unreachable: no relay is worth its airtime"
        );
    }

    /// An inbound-only neighbour (we hear it, it never confirms hearing us) is nobody's coverage
    /// unless we own it: whoever hears it best carries its traffic, and the rest stay silent.
    #[test]
    fn inbound_only_neighbor_belongs_to_its_owner() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(COV_ME);
        graph.observe_direct_neighbor(COV_A, -70, 8, 0, 0);
        graph.observe_direct_neighbor(COV_B, -70, 8, 0, 0);
        graph.confirm_direct_neighbor_hears_us(COV_A);
        graph.capability_mut().track_topology(COV_A, true, 0);
        // Only we hear COV_B, so covering it is ours.
        assert_eq!(
            graph.unique_coverage_neighbor(&[COV_A]),
            Some(COV_B),
            "sole neighbour of an inbound-only node covers it"
        );
        // COV_A hears it better: it owns it and we have nothing left to cover.
        graph
            .edges_mut()
            .update_edge(COV_ME, COV_A, COV_B, 1.0, 0, EdgeSource::Reported, true, 0);
        assert_eq!(graph.unique_coverage_neighbor(&[COV_A]), None);
    }

    #[test]
    fn has_unique_coverage_satisfied_when_coverer_reaches_neighbor() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(COV_ME);
        graph.observe_direct_neighbor(COV_A, -70, 8, 0, 0);
        graph.observe_direct_neighbor(COV_B, -70, 8, 0, 0);
        graph.confirm_direct_neighbor_hears_us(COV_A);
        graph.confirm_direct_neighbor_hears_us(COV_B);
        let remote = PackedNeighbor {
            node_id: COV_B,
            rssi: -72,
            snr: 8,
            signal_routing_active: true,
            hears_us: true,
            etx_variance: 0,
        };
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        graph.merge_topology(COV_A, &header, &[remote], true, 100, 0);
        assert!(!graph.has_unique_coverage(&[COV_A]));
    }

    #[test]
    fn last_hop_cap_applies_regardless_of_link_quality() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xCC00_00CC);
        graph.observe_direct_neighbor(0xDD00_00DD, -70, 8, 0, 0);
        graph.confirm_direct_neighbor_hears_us(0xDD00_00DD);
        graph.observe_direct_neighbor(0xEE00_00EE, -72, 7, 0, 0);
        assert!(graph.caps_last_hop(0xDD00_00DD));
        graph.edges_mut().update_edge(
            0xCC00_00CC,
            0xCC00_00CC,
            0xDD00_00DD,
            4.0,
            0,
            EdgeSource::Reported,
            true,
            0,
        );
        assert!(
            graph.caps_last_hop(0xDD00_00DD),
            "a marginal link is still a last hop"
        );
    }

    #[test]
    fn unicast_hop_limit_skips_without_stock_neighbor() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xCC00_00CC);
        graph.observe_direct_neighbor(0xDD00_00DD, -70, 8, 0, 0);
        graph.confirm_direct_neighbor_hears_us(0xDD00_00DD);
        graph.observe_direct_neighbor(0xEE00_00EE, -72, 7, 0, 0);
        graph.capability_mut().track_topology(0xEE00_00EE, true, 0);
        assert!(!graph.caps_last_hop(0xDD00_00DD));
    }

    #[test]
    fn unicast_hop_limit_requires_hears_us() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xCC00_00CC);
        graph.observe_direct_neighbor(0xDD00_00DD, -70, 8, 0, 0);
        graph.observe_direct_neighbor(0xEE00_00EE, -72, 7, 0, 0);
        assert!(!graph.caps_last_hop(0xDD00_00DD));
    }

    #[test]
    fn topology_pack_emits_measured_rssi_snr() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA);
        graph.observe_direct_neighbor(0x1234_5678, -80, 10, 0, 0);

        let mut packed = [0u8; 64];
        let len = graph
            .build_topology_chunk(0, 1, &mut packed)
            .expect("chunk");
        let (_, neighbors) = decode_packed_neighbors(&packed[..len], len).unwrap();
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].node_id, 0x1234_5678);
        assert_eq!(neighbors[0].rssi, -80);
        assert_eq!(neighbors[0].snr, 10);
    }

    #[test]
    fn fill_neighbor_entries_skips_without_side_table() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA);
        graph
            .edges_mut()
            .update_edge(0xAA, 0xAA, 0xBB, 2.0, 100, EdgeSource::Reported, true, 0);
        assert_eq!(
            graph.fill_neighbor_entries(&mut [NeighborEntry::default(); MAX_NEIGHBORS]),
            0
        );
    }

    #[test]
    fn merge_topology_uses_rssi_snr_for_etx() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA);
        graph.observe_direct_neighbor(0xBB, -70, 8, 100, 0);
        let expected_etx = etx_to_fixed(calculate_etx(-75, 8.0));
        let neighbor = PackedNeighbor {
            node_id: 0xCC,
            rssi: -75,
            snr: 8,
            signal_routing_active: true,
            hears_us: false,
            etx_variance: 0,
        };
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        graph.merge_topology(0xBB, &header, &[neighbor], true, 200, 0);
        let edge_etx = graph
            .edges()
            .find_node(0xBB)
            .and_then(|n| n.find_edge(0xCC))
            .map(|e| e.etx_fixed)
            .expect("mirrored edge");
        assert_eq!(edge_etx, expected_etx);
    }

    #[test]
    fn merge_topology_mirrored_only_does_not_mark_dirty() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA);
        graph.observe_direct_neighbor(0xBB, -70, 8, 100, 0);
        graph.commit_topology_broadcast(100, true);
        let neighbor = PackedNeighbor {
            node_id: 0xCC,
            rssi: -75,
            snr: 8,
            signal_routing_active: true,
            hears_us: false,
            etx_variance: 0,
        };
        let mut packed = [0u8; 16];
        write_packed_header(&mut packed, 1, true);
        let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();
        graph.merge_topology(0xBB, &header, &[neighbor], true, 200, 0);
        let report = graph.run_maintenance(400_000);
        assert!(!report.topology_dirty_send);
        assert!(!report.topology_due);
    }
}
