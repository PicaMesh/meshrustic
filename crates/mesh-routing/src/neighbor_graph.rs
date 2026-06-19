//! Topology graph and per-radio relay commit state (Phase 6 SR).

use mesh_protocol::is_direct_packet;
use mesh_radio::RadioId;

use crate::capability::{role_may_send_topology, CapabilityCache, CapabilityStatus};
use crate::coordinated_relay::tx_delay_ms_router;
use crate::graph::{
    calculate_etx, calculate_route, etx_to_signal, find_better_positioned_neighbor, placeholder_node_id,
    EdgeSource, EdgeStore, DownstreamTable, Route, RouteCache, EDGE_NEW, EDGE_SIGNIFICANT_CHANGE,
    MAX_EDGES_PER_NODE,
};
use crate::nodeinfo::{
    DEVICE_ROLE_CLIENT, DEVICE_ROLE_CLIENT_MUTE, DEVICE_ROLE_ROUTER, DEVICE_ROLE_ROUTER_LATE,
};
use crate::topology::{
    write_packed_header, PackedHeader, PackedNeighbor, MAX_NEIGHBORS_PER_PACKET,
    PACKED_NEIGHBOR_ENTRY_SIZE, PACKED_NEIGHBOR_FLAG_HEARS_US, PACKED_NEIGHBOR_FLAG_SR_ACTIVE,
    PACKED_NEIGHBOR_HEADER_SIZE, SIGNAL_ROUTING_VERSION,
};

pub const MAX_NEIGHBORS: usize = MAX_EDGES_PER_NODE;
pub const MAX_RELAY_STATES: usize = 32;
pub const MAX_TOPOLOGY_VERSION_ENTRIES: usize = 24;
pub const TOPOLOGY_BROADCAST_MS: u32 = 600_000;
pub const TOPOLOGY_DIRTY_MIN_MS: u32 = 300_000;
pub const MAINTENANCE_LOG_MS: u32 = 60_000;
pub const NEIGHBOR_TTL_MS: u32 = 7_200_000;
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
struct RelayCommit {
    active: bool,
    from: u32,
    id: u32,
    radio_id: u8,
    tx_after_ms: u32,
    snr: i8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TopologyVersionEntry {
    node_id: u32,
    version: u8,
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

pub struct NeighborGraph {
    my_node: u32,
    device_role: u32,
    edges: EdgeStore,
    downstream: DownstreamTable,
    relay_states: [RelayCommit; MAX_RELAY_STATES],
    topo_versions: [TopologyVersionEntry; MAX_TOPOLOGY_VERSION_ENTRIES],
    topo_version_count: u8,
    topology_version: u8,
    topology_dirty: bool,
    last_topology_ms: u32,
    last_maintenance_ms: u32,
    signal_routing_active: bool,
    our_tx: [NodeTxRecord; MAX_OUR_TX_RECORDS],
    our_tx_count: u8,
    node_tx: [NodeTxRecord; MAX_NODE_TX_RECORDS],
    node_tx_count: u8,
    route_cache: RouteCache,
    capability: CapabilityCache,
}

impl NeighborGraph {
    pub const fn new() -> Self {
        Self {
            my_node: 0,
            device_role: DEVICE_ROLE_CLIENT,
            edges: EdgeStore::new(),
            downstream: DownstreamTable::new(),
            relay_states: [RelayCommit {
                active: false,
                from: 0,
                id: 0,
                radio_id: 0,
                tx_after_ms: 0,
                snr: 0,
            }; MAX_RELAY_STATES],
            topo_versions: [TopologyVersionEntry {
                node_id: 0,
                version: 0,
            }; MAX_TOPOLOGY_VERSION_ENTRIES],
            topo_version_count: 0,
            topology_version: 0,
            topology_dirty: false,
            last_topology_ms: 0,
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
        }
    }

    pub fn set_my_node(&mut self, node_id: u32) {
        self.my_node = node_id;
    }

    pub fn my_node(&self) -> u32 {
        self.my_node
    }

    pub fn update_node_activity(&mut self, node_id: u32, now_ms: u32) {
        self.edges
            .update_node_activity(node_id, now_ms, self.my_node);
    }

    pub fn set_device_role(&mut self, role: u32) {
        self.device_role = role;
        self.signal_routing_active = Self::role_is_active_routing(role);
    }

    pub fn is_active_routing_role(&self) -> bool {
        Self::role_is_active_routing(self.device_role)
    }

    pub fn can_send_topology(&self) -> bool {
        role_may_send_topology(self.device_role)
    }

    pub fn track_node_role(&mut self, node_id: u32, role: u32, now_ms: u32) {
        self.capability.track_role(node_id, role, now_ms);
    }

    pub fn capability_status(&self, node_id: u32) -> CapabilityStatus {
        self.capability.status(node_id)
    }

    fn role_is_active_routing(role: u32) -> bool {
        matches!(role, DEVICE_ROLE_CLIENT | DEVICE_ROLE_ROUTER | 4 | 11 | 12)
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
        for i in 1..MAX_NODE_TX_RECORDS {
            self.node_tx[i - 1] = self.node_tx[i];
        }
        self.node_tx[MAX_NODE_TX_RECORDS - 1] = NodeTxRecord {
            node_id,
            packet_id,
            at_ms: now_ms,
        };
    }

    pub fn has_node_transmitted(&self, node_id: u32, packet_id: u32, now_ms: u32) -> bool {
        for i in 0..self.node_tx_count as usize {
            let rec = self.node_tx[i];
            if rec.node_id == node_id
                && rec.packet_id == packet_id
                && now_ms.wrapping_sub(rec.at_ms) <= NODE_TX_RECORD_MS
            {
                return true;
            }
        }
        false
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
        self.last_topology_ms = self.last_topology_ms.saturating_sub(TOPOLOGY_BROADCAST_MS / 2);
        let _ = now_ms;
    }

    pub fn relay_slot_index(&self, packet_id: u32, heard_from: u32, now_ms: u32) -> (u8, u8) {
        let mut stock = [0u32; MAX_EDGES_PER_NODE];
        let stock_n = self.fill_stock_relay_candidates(packet_id, heard_from, now_ms, &mut stock);
        let mut sr = [0u32; MAX_EDGES_PER_NODE + 1];
        let sr_n = self.fill_sr_relay_candidates(packet_id, heard_from, now_ms, &mut sr);
        let mut sr_index = 0u8;
        for i in 0..sr_n as usize {
            if sr[i] == self.my_node {
                sr_index = i as u8;
                break;
            }
        }
        let total = stock_n.saturating_add(sr_n).max(1);
        (stock_n.saturating_add(sr_index), total)
    }

    /// Best broadcast relay candidate: stock routers first, then SR peers (sorted by node id).
    pub fn find_best_relay_candidate(&self, packet_id: u32, heard_from: u32, now_ms: u32) -> u32 {
        let mut stock = [0u32; MAX_EDGES_PER_NODE];
        let stock_n = self.fill_stock_relay_candidates(packet_id, heard_from, now_ms, &mut stock);
        for i in 0..stock_n as usize {
            let candidate = stock[i];
            if !self.has_node_transmitted(candidate, packet_id, now_ms) {
                return candidate;
            }
        }
        let mut sr = [0u32; MAX_EDGES_PER_NODE + 1];
        let sr_n = self.fill_sr_relay_candidates(packet_id, heard_from, now_ms, &mut sr);
        for i in 0..sr_n as usize {
            let candidate = sr[i];
            if !self.has_node_transmitted(candidate, packet_id, now_ms) {
                return candidate;
            }
        }
        0
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
        for i in 0..n as usize {
            let neighbor = ids[i];
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
        for i in 0..n as usize {
            let id = ids[i];
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
        self.relay_slot_index(packet_id, heard_from, now_ms).1.max(1)
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
            if written >= MAX_NEIGHBORS {
                break;
            }
            let (rssi, snr) = etx_to_signal(edge.etx());
            out[written] = NeighborEntry {
                node_id: edge.to,
                rssi: rssi as i16,
                snr,
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
                    let a_reported = a_edge.map(|e| e.source == EdgeSource::Reported).unwrap_or(false);
                    let b_reported = b_edge.map(|e| e.source == EdgeSource::Reported).unwrap_or(false);
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
        write_packed_header(out, topology_version, self.signal_routing_active);
        for i in 0..count {
            let entry = sorted[start + i];
            let base = PACKED_NEIGHBOR_HEADER_SIZE + i * PACKED_NEIGHBOR_ENTRY_SIZE;
            out[base..base + 4].copy_from_slice(&entry.node_id.to_le_bytes());
            out[base + 4] = entry.rssi as i8 as u8;
            out[base + 5] = entry.snr as u8;
            let mut flags = 0u8;
            if entry.signal_routing_active {
                flags |= PACKED_NEIGHBOR_FLAG_SR_ACTIVE;
            }
            if entry.hears_us {
                flags |= PACKED_NEIGHBOR_FLAG_HEARS_US;
            }
            out[base + 6] = flags;
            if let Some(edge) = self.edges.find_node(self.my_node).and_then(|n| n.find_edge(entry.node_id)) {
                out[base + 7] = edge.etx_variance;
            } else {
                out[base + 7] = 0;
            }
        }
        Some(need)
    }

    pub fn topology_packet_count(&self) -> u8 {
        let total = self.neighbor_count() as usize;
        if total == 0 {
            1
        } else {
            ((total + MAX_NEIGHBORS_PER_PACKET - 1) / MAX_NEIGHBORS_PER_PACKET) as u8
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
        let last = self.get_topo_version(sender);
        if !Self::topology_version_accept(received, last) {
            return TopologyMergeResult::Stale { received, last };
        }
        self.set_topo_version(sender, received);
        self.capability
            .track_topology(sender, header.signal_routing_active, now_ms);

        self.edges.ensure_local_node(self.my_node, now_ms);

        if neighbors.is_empty() && is_direct_from_sender && header.signal_routing_active {
            self.topology_dirty = true;
        }

        let mut dirty = false;
        let passive_local = !self.is_active_routing_role();
        for neighbor in neighbors {
            if neighbor.node_id == 0 || (neighbor.node_id & 0xFF00_0000) == 0xFF00_0000 {
                continue;
            }
            if passive_local
                && neighbor.node_id != self.my_node
                && !self.edges.has_direct_reported_edge_to(self.my_node, neighbor.node_id)
                && !self.edges.has_direct_reported_edge_to(neighbor.node_id, self.my_node)
            {
                continue;
            }
            let etx = calculate_etx(neighbor.rssi as i32, neighbor.snr as f32);
            let relay_has_edge = self
                .edges
                .find_node(sender)
                .and_then(|n| n.find_edge(neighbor.node_id))
                .is_some();
            let result = self.edges.update_edge(
                self.my_node,
                sender,
                neighbor.node_id,
                etx,
                now_ms,
                EdgeSource::Mirrored,
                false,
                heard_on,
            );
            if result == EDGE_NEW || result == EDGE_SIGNIFICANT_CHANGE {
                dirty = true;
            }
            self.edges
                .set_edge_hears_us(sender, neighbor.node_id, neighbor.hears_us);

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
            }
        }

        if dirty {
            self.topology_dirty = true;
        }

        let mut listed = [0u32; MAX_NEIGHBORS];
        let listed_count = neighbors.len().min(MAX_NEIGHBORS);
        for (i, neighbor) in neighbors.iter().take(listed_count).enumerate() {
            listed[i] = neighbor.node_id;
        }
        self.edges
            .clear_hears_us_to_unlisted(sender, &listed[..listed_count]);

        TopologyMergeResult::Applied {
            neighbors: neighbors.len() as u8,
            topo_v: received,
        }
    }

    fn get_topo_version(&self, node_id: u32) -> u8 {
        for i in 0..self.topo_version_count as usize {
            if self.topo_versions[i].node_id == node_id {
                return self.topo_versions[i].version;
            }
        }
        0
    }

    fn set_topo_version(&mut self, node_id: u32, version: u8) {
        for i in 0..self.topo_version_count as usize {
            if self.topo_versions[i].node_id == node_id {
                self.topo_versions[i].version = version;
                return;
            }
        }
        if (self.topo_version_count as usize) < MAX_TOPOLOGY_VERSION_ENTRIES {
            let idx = self.topo_version_count as usize;
            self.topo_versions[idx] = TopologyVersionEntry { node_id, version };
            self.topo_version_count += 1;
        }
    }

    /// Record a direct RF neighbor. `heard_on` is the receiving radio (`RadioId(0)` on v1 hardware).
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
        if result == EDGE_NEW || result == EDGE_SIGNIFICANT_CHANGE {
            self.topology_dirty = true;
        }
        self.downstream.clear_for_destination(node_id);
        result == EDGE_NEW
    }

    /// Update graph from a received packet header. `heard_on` tags which preset segment heard it.
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
    ) -> Option<(u32, i16, i8, bool)> {
        if is_direct_packet(from, hop_start, hop_limit, relay_node) {
            let is_new = self.observe_direct_neighbor(from, rssi, snr, now_ms, heard_on);
            Some((from, rssi, snr, is_new))
        } else {
            self.observe_relayed_packet(from, relay_node, rssi, snr, now_ms, heard_on);
            None
        }
    }

    fn observe_relayed_packet(
        &mut self,
        from: u32,
        relay_node: u8,
        rssi: i16,
        snr: i8,
        now_ms: u32,
        heard_on: RadioId,
    ) {
        if !self.is_active_routing_role() {
            return;
        }
        if from == 0 || (rssi == 0 && snr == 0) {
            return;
        }
        let from_low = (from & 0xFF) as u8;
        if relay_node == 0 || relay_node == from_low {
            return;
        }
        let placeholder = placeholder_node_id(relay_node);
        if placeholder == from || placeholder == self.my_node {
            return;
        }
        self.edges.ensure_local_node(self.my_node, now_ms);
        let result = self.edges.update_edge_from_observation(
            self.my_node,
            placeholder,
            from,
            rssi,
            snr,
            now_ms,
            EdgeSource::Mirrored,
            heard_on,
        );
        if result == EDGE_NEW || result == EDGE_SIGNIFICANT_CHANGE {
            self.topology_dirty = true;
            self.route_cache.clear();
        }
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
        cw_slot_ms: u32,
        node_num: u32,
    ) -> (u32, u8, u8) {
        let (slot_index, candidates) = self.relay_slot_index(id, heard_from, now_ms);
        let spacing = slot_index as u32 * half_airtime_ms.max(50);
        let snr_delay = tx_delay_ms_router(snr, cw_slot_ms, from, id, node_num);
        let delay = spacing.saturating_add(snr_delay);
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
            };
            return (tx_after_ms, slot_index, candidates);
        }
        (tx_after_ms, slot_index, candidates)
    }

    pub fn relay_tx_after(&self, from: u32, id: u32, radio_id: u8) -> Option<u32> {
        self.find_relay(from, id, radio_id)
            .map(|idx| self.relay_states[idx].tx_after_ms)
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
        now_ms: u32,
    ) {
        let our_low = (our_node & 0xFF) as u8;
        let relayed = hop_limit < hop_start
            || (relay_node != 0 && relay_node != our_low && relay_node != (from & 0xFF) as u8);
        if relayed {
            self.cancel_relay(from, id);
            self.record_node_transmission(from, id, now_ms);
        }
    }

    pub fn get_downstream_relay(&self, destination: u32) -> Option<u32> {
        self.downstream.get_relay(destination)
    }

    pub fn get_route(&mut self, destination: u32, now_ms: u32) -> Route {
        if let Some(cached) = self.route_cache.get(destination, now_ms) {
            return cached;
        }
        let route = calculate_route(&self.edges, &self.downstream, self.my_node, destination, now_ms);
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

    pub fn get_next_hop(&mut self, destination: u32, heard_from: u32, now_ms: u32) -> u32 {
        if destination == 0 || destination == self.my_node {
            return 0;
        }
        let route = self.get_route(destination, now_ms);
        if route.next_hop == 0 {
            return if self.has_any_hears_us_neighbor() {
                self.my_node
            } else {
                0
            };
        }
        if route.next_hop == self.my_node {
            return self.my_node;
        }

        let next_hop = route.next_hop;
        let next_hop_can_hear_transmitter = heard_from == 0
            || next_hop == heard_from
            || next_hop == destination;

        if route.cost_fixed > 200 {
            let better = find_better_positioned_neighbor(
                &self.edges,
                self.my_node,
                destination,
                heard_from,
                route.cost_fixed,
            );
            if better != 0 {
                return better;
            }
        }

        if next_hop_can_hear_transmitter {
            return next_hop;
        }

        if self.edge_hears_us(next_hop) {
            return next_hop;
        }

        if self.has_direct_edge(next_hop) {
            return next_hop;
        }

        self.my_node
    }

    fn has_direct_edge(&self, peer: u32) -> bool {
        self.edges
            .find_node(self.my_node)
            .and_then(|n| n.find_edge(peer))
            .is_some()
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

    pub fn all_hears_us_neighbors_heard_packet(
        &self,
        packet_id: u32,
        heard_from: u32,
        now_ms: u32,
    ) -> bool {
        let Some(node) = self.edges.find_node(self.my_node) else {
            return false;
        };
        let mut hears_us_count = 0u8;
        for i in 0..node.edge_count as usize {
            if !node.edges[i].hears_us {
                continue;
            }
            hears_us_count = hears_us_count.saturating_add(1);
            let neighbor = node.edges[i].to;
            if neighbor == heard_from {
                continue;
            }
            if !self.has_node_transmitted(neighbor, packet_id, now_ms) {
                return false;
            }
        }
        hears_us_count > 0
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
        self.relay_states.iter().any(|s| s.active && s.from == from && s.id == packet_id)
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
        self.device_role != DEVICE_ROLE_CLIENT_MUTE
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
        let edges_aged = self
            .edges
            .age_edges(self.my_node, now_ms, NEIGHBOR_TTL_MS, Some(&mut self.downstream));
        let relay_in_graph = |relay: u32| self.edges.find_node(relay).is_some();
        let downstream_aged = self
            .downstream
            .age(now_ms, NEIGHBOR_TTL_MS, relay_in_graph);
        self.clear_expired_commits(now_ms);
        self.capability.prune(now_ms);

        if edges_aged || downstream_aged {
            self.topology_dirty = true;
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

    pub fn commit_topology_broadcast(&mut self, now_ms: u32, dirty_send: bool) {
        self.last_topology_ms = now_ms;
        self.topology_version = self.topology_version.wrapping_add(1);
        if dirty_send {
            self.topology_dirty = false;
        }
    }

    pub fn emit_topology_log<S: crate::sr_log::TopologyLogSink>(&self, node_num: u32, sink: &mut S) {
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

        for i in 0..direct as usize {
            let entry = entries[i];
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
        for i in 0..count {
            let Some(entry) = self.downstream.entry(i) else {
                continue;
            };
            sink.emit(SrLogEvent::NetworkTopologyDownstreamRoute {
                destination: entry.destination,
                relay: entry.relay,
                last: i + 1 == count,
            });
        }
    }

    fn find_relay(&self, from: u32, id: u32, radio_id: u8) -> Option<usize> {
        self.relay_states.iter().position(|s| {
            s.active && s.from == from && s.id == id && s.radio_id == radio_id
        })
    }

    fn alloc_relay_slot(&self) -> Option<usize> {
        self.relay_states.iter().position(|s| !s.active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinated_relay::DEFAULT_SLOT_MS;
    use crate::coordinated_relay;
    use crate::topology::write_packed_header;

    #[test]
    fn relayed_packet_does_not_add_direct_neighbor() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xB000_0002);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(0xA000_0001, -70, 8, 0, 0);
        assert_eq!(graph.neighbor_count(), 1);

        graph.observe_packet(0xC000_0003, 3, 2, 0xEF, -70, 8, 50, 0);
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
    fn rebroadcast_cancels_commit() {
        let mut graph = NeighborGraph::new();
        graph.commit_relay(1, 2, 0, 8, 1, 100, 20, DEFAULT_SLOT_MS, 0xAA);
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
        assert_eq!(graph.find_best_relay_candidate(99, 0xBB00_00BB, 0), 0xDD00_00DD);
    }

    #[test]
    fn find_best_relay_skips_packet_sender() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xCC00_00CC);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 0, 0);
        assert_eq!(graph.find_best_relay_candidate(99, 0xBB00_00BB, 0), 0xCC00_00CC);
    }

    #[test]
    fn relayed_packet_creates_placeholder_edge() {
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA00_00AA);
        graph.set_device_role(DEVICE_ROLE_ROUTER);
        graph.observe_direct_neighbor(0xBB00_00BB, -70, 8, 0, 0);
        graph.observe_packet(0xBB00_00BB, 3, 2, 0xCD, -70, 8, 100, 0);
        let placeholder = placeholder_node_id(0xCD);
        assert!(graph.test_has_edge(placeholder, 0xBB00_00BB));
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
