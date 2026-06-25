//! Per-node edge lists in the topology graph.

use mesh_radio::RadioId;

use super::etx::{calculate_etx, etx_to_fixed, fixed_to_etx, EtxFixed};

pub const MAX_EDGES_PER_NODE: usize = 24;

pub const EDGE_NO_CHANGE: i8 = 0;
pub const EDGE_NEW: i8 = 1;
pub const EDGE_SIGNIFICANT_CHANGE: i8 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EdgeSource {
    #[default]
    Mirrored = 0,
    Reported = 1,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Edge {
    pub to: u32,
    pub etx_fixed: EtxFixed,
    pub last_update_ms: u32,
    pub etx_variance: u8,
    pub source: EdgeSource,
    pub hears_us: bool,
    /// Preset segment this edge was learned on (Phase 9 multi-radio).
    pub heard_on: RadioId,
}

impl Edge {
    pub fn etx(&self) -> f32 {
        fixed_to_etx(self.etx_fixed)
    }

    pub fn set_etx(&mut self, etx: f32) {
        self.etx_fixed = etx_to_fixed(etx);
    }

    pub fn etx_variance_f(&self) -> f32 {
        self.etx_variance as f32 / 20.0
    }

    pub fn update_etx_variance(&mut self, abs_change: f32) {
        let cur = self.etx_variance_f();
        let updated = 0.75 * cur + 0.25 * abs_change;
        let scaled = (updated * 20.0 + 0.5) as u16;
        self.etx_variance = scaled.min(255) as u8;
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeEdges {
    pub node_id: u32,
    pub edge_count: u8,
    pub last_full_update_ms: u32,
    pub edges: [Edge; MAX_EDGES_PER_NODE],
}

impl NodeEdges {
    pub fn find_edge_mut(&mut self, to: u32) -> Option<&mut Edge> {
        (0..self.edge_count as usize)
            .find(|&i| self.edges[i].to == to)
            .map(move |i| &mut self.edges[i as usize])
    }

    pub fn find_edge(&self, to: u32) -> Option<&Edge> {
        (0..self.edge_count as usize)
            .find(|&i| self.edges[i].to == to)
            .map(|i| &self.edges[i])
    }
}

pub struct EdgeStore {
    nodes: [NodeEdges; super::MAX_GRAPH_NODES],
    node_count: u8,
    etx_change_threshold: f32,
}

impl EdgeStore {
    pub const fn new() -> Self {
        Self {
            nodes: [NodeEdges {
                node_id: 0,
                edge_count: 0,
                last_full_update_ms: 0,
                edges: [Edge {
                    to: 0,
                    etx_fixed: 100,
                    last_update_ms: 0,
                    etx_variance: 0,
                    source: EdgeSource::Mirrored,
                    hears_us: false,
                    heard_on: 0,
                }; MAX_EDGES_PER_NODE],
            }; super::MAX_GRAPH_NODES],
            node_count: 0,
            etx_change_threshold: 1.2,
        }
    }

    pub fn node_count(&self) -> u8 {
        self.node_count
    }

    pub fn find_node(&self, node_id: u32) -> Option<&NodeEdges> {
        (0..self.node_count as usize)
            .find(|&i| self.nodes[i].node_id == node_id)
            .map(|i| &self.nodes[i])
    }

    pub fn node_id_at(&self, index: u8) -> Option<u32> {
        if (index as usize) < self.node_count as usize {
            Some(self.nodes[index as usize].node_id)
        } else {
            None
        }
    }

    pub fn find_node_mut(&mut self, node_id: u32) -> Option<&mut NodeEdges> {
        (0..self.node_count as usize)
            .find(|&i| self.nodes[i].node_id == node_id)
            .map(move |i| &mut self.nodes[i])
    }

    fn find_or_create_node(&mut self, node_id: u32, now_ms: u32, my_node: u32) -> Option<&mut NodeEdges> {
        if let Some(idx) = (0..self.node_count as usize).find(|&i| self.nodes[i].node_id == node_id) {
            return Some(&mut self.nodes[idx]);
        }
        if (self.node_count as usize) >= super::MAX_GRAPH_NODES {
            self.evict_oldest(now_ms, my_node)?;
        }
        let idx = self.node_count as usize;
        self.nodes[idx] = NodeEdges {
            node_id,
            edge_count: 0,
            last_full_update_ms: now_ms,
            edges: [Edge::default(); MAX_EDGES_PER_NODE],
        };
        self.node_count += 1;
        Some(&mut self.nodes[idx])
    }

    fn evict_oldest(&mut self, now_ms: u32, my_node: u32) -> Option<()> {
        let mut evict_idx = None;
        let mut oldest = u32::MAX;
        for i in 0..self.node_count as usize {
            if self.nodes[i].node_id == my_node {
                continue;
            }
            if now_ms.wrapping_sub(self.nodes[i].last_full_update_ms) < 120_000 {
                continue;
            }
            if self.nodes[i].last_full_update_ms < oldest {
                oldest = self.nodes[i].last_full_update_ms;
                evict_idx = Some(i);
            }
        }
        let idx = evict_idx?;
        if idx < (self.node_count as usize).saturating_sub(1) {
            self.nodes[idx] = self.nodes[self.node_count as usize - 1];
        }
        self.node_count -= 1;
        Some(())
    }

    pub fn is_our_direct_neighbor(&self, node_id: u32, my_node: u32) -> bool {
        self.find_node(my_node)
            .and_then(|node| node.find_edge(node_id))
            .is_some()
    }

    pub fn has_direct_reported_edge_to(&self, from: u32, to: u32) -> bool {
        let Some(node) = self.find_node(from) else {
            return false;
        };
        node.find_edge(to)
            .map(|e| e.source == EdgeSource::Reported)
            .unwrap_or(false)
    }

    fn reachable_via_neighbor(&self, node_id: u32) -> bool {
        for i in 0..self.node_count as usize {
            for e in 0..self.nodes[i].edge_count as usize {
                if self.nodes[i].edges[e].to == node_id {
                    return true;
                }
            }
        }
        false
    }

    pub fn update_edge(
        &mut self,
        my_node: u32,
        from: u32,
        to: u32,
        etx: f32,
        now_ms: u32,
        source: EdgeSource,
        update_timestamp: bool,
        heard_on: RadioId,
    ) -> i8 {
        if to == 0 || from == 0 {
            return EDGE_NO_CHANGE;
        }

        let is_our_node = from == my_node;
        if !is_our_node && self.find_node(from).is_none() {
            if super::placeholder::is_placeholder_node(from) {
                let _ = self.find_or_create_node(from, now_ms, my_node);
            } else if !self.is_our_direct_neighbor(from, my_node) && !self.reachable_via_neighbor(from) {
                return EDGE_NO_CHANGE;
            }
        }

        if self.find_or_create_node(from, now_ms, my_node).is_none() {
            return EDGE_NO_CHANGE;
        }
        if is_our_node {
            let _ = self.find_or_create_node(to, now_ms, my_node);
        }

        let from_idx = (0..self.node_count as usize).find(|&i| self.nodes[i].node_id == from);
        let Some(from_idx) = from_idx else {
            return EDGE_NO_CHANGE;
        };

        if update_timestamp {
            self.nodes[from_idx].last_full_update_ms = now_ms;
        }

        if let Some(edge_idx) = (0..self.nodes[from_idx].edge_count as usize)
            .find(|&i| self.nodes[from_idx].edges[i].to == to)
        {
            let edge = &mut self.nodes[from_idx].edges[edge_idx];
            if edge.source == EdgeSource::Reported && source == EdgeSource::Mirrored {
                return EDGE_NO_CHANGE;
            }
            let old_etx = edge.etx();
            let abs_change = (etx - old_etx).abs();
            let rel_change = if old_etx > 0.0 { abs_change / old_etx } else { 1.0 };
            edge.set_etx(etx);
            if update_timestamp {
                edge.last_update_ms = now_ms;
            }
            if source == EdgeSource::Reported {
                edge.update_etx_variance(abs_change);
            }
            edge.source = source;
            if heard_on != 0 && source == EdgeSource::Reported {
                edge.heard_on = heard_on;
            }
            let dynamic = self.etx_change_threshold + edge.etx_variance_f();
            if rel_change > dynamic {
                EDGE_SIGNIFICANT_CHANGE
            } else {
                EDGE_NO_CHANGE
            }
        } else if (self.nodes[from_idx].edge_count as usize) < MAX_EDGES_PER_NODE {
            let idx = self.nodes[from_idx].edge_count as usize;
            self.nodes[from_idx].edges[idx] = Edge {
                to,
                etx_fixed: etx_to_fixed(etx),
                last_update_ms: now_ms,
                etx_variance: 0,
                source,
                hears_us: false,
                heard_on,
            };
            self.nodes[from_idx].edge_count += 1;
            EDGE_NEW
        } else {
            EDGE_NO_CHANGE
        }
    }

    pub fn update_edge_from_observation(
        &mut self,
        my_node: u32,
        from: u32,
        to: u32,
        rssi: i16,
        snr: i8,
        now_ms: u32,
        source: EdgeSource,
        heard_on: RadioId,
    ) -> i8 {
        let etx = calculate_etx(rssi as i32, snr as f32);
        self.update_edge(my_node, from, to, etx, now_ms, source, true, heard_on)
    }

    pub fn relay_heard_on(&self, my_node: u32, relay: u32) -> RadioId {
        self.find_node(my_node)
            .and_then(|n| n.find_edge(relay))
            .map(|e| e.heard_on)
            .unwrap_or(0)
    }

    pub fn set_edge_hears_us(&mut self, from: u32, to: u32, hears_us: bool) {
        if let Some(node) = self.find_node_mut(from) {
            if let Some(edge) = node.find_edge_mut(to) {
                edge.hears_us = hears_us;
            }
        }
    }

    pub fn clear_hears_us_to_unlisted(&mut self, sender: u32, listed_ids: &[u32]) {
        for i in 0..self.node_count as usize {
            let node_id = self.nodes[i].node_id;
            if node_id == sender {
                continue;
            }
            let listed_here = listed_ids.iter().any(|&id| id == node_id);
            for e in 0..self.nodes[i].edge_count as usize {
                if self.nodes[i].edges[e].to == sender && self.nodes[i].edges[e].hears_us && !listed_here
                {
                    self.nodes[i].edges[e].hears_us = false;
                }
            }
        }
    }

    pub fn count_direct_neighbors(&self, my_node: u32) -> u8 {
        let mut count = 0u8;
        for i in 0..self.node_count as usize {
            let node_id = self.nodes[i].node_id;
            if node_id == my_node {
                continue;
            }
            for e in 0..self.nodes[i].edge_count as usize {
                let edge = self.nodes[i].edges[e];
                if edge.to == my_node && edge.source == EdgeSource::Reported {
                    count = count.saturating_add(1);
                    break;
                }
            }
        }
        count
    }

    pub fn direct_neighbor_ids(&self, my_node: u32, out: &mut [u32; MAX_EDGES_PER_NODE]) -> u8 {
        let Some(node) = self.find_node(my_node) else {
            return 0;
        };
        let mut written = 0u8;
        for i in 0..node.edge_count as usize {
            let edge = node.edges[i];
            if edge.source != EdgeSource::Reported || edge.to == 0 {
                continue;
            }
            if (written as usize) < MAX_EDGES_PER_NODE {
                out[written as usize] = edge.to;
                written += 1;
            }
        }
        written
    }

    pub fn age_edges(
        &mut self,
        my_node: u32,
        now_ms: u32,
        ttl_ms: u32,
        mut downstream: Option<&mut super::DownstreamTable>,
    ) -> bool {
        let mut changed = false;
        let mut n = 0u8;
        while (n as usize) < self.node_count as usize {
            if self.nodes[n as usize].node_id == my_node {
                n += 1;
                continue;
            }
            let node_id = self.nodes[n as usize].node_id;
            let mut write = 0u8;
            let edge_count = self.nodes[n as usize].edge_count;
            for i in 0..edge_count as usize {
                let edge = self.nodes[n as usize].edges[i];
                if now_ms.wrapping_sub(edge.last_update_ms) <= ttl_ms {
                    if write as usize != i {
                        self.nodes[n as usize].edges[write as usize] = edge;
                    }
                    write += 1;
                } else {
                    changed = true;
                }
            }
            self.nodes[n as usize].edge_count = write;

            if now_ms.wrapping_sub(self.nodes[n as usize].last_full_update_ms) > ttl_ms
                || self.nodes[n as usize].edge_count == 0
            {
                if let Some(ds) = downstream.as_deref_mut() {
                    ds.clear_for_relay(node_id);
                }
                self.remove_node_edges_to(node_id);
                if (n as usize) < self.node_count as usize - 1 {
                    self.nodes[n as usize] = self.nodes[self.node_count as usize - 1];
                }
                self.node_count -= 1;
                changed = true;
                continue;
            }
            n += 1;
        }
        changed
    }

    fn remove_node_edges_to(&mut self, removed: u32) {
        for i in 0..self.node_count as usize {
            let mut write = 0u8;
            let count = self.nodes[i].edge_count;
            for e in 0..count as usize {
                let edge = self.nodes[i].edges[e];
                if edge.to != removed {
                    if write as usize != e {
                        self.nodes[i].edges[write as usize] = edge;
                    }
                    write += 1;
                }
            }
            self.nodes[i].edge_count = write;
        }
    }

    pub fn remove_edges_to(&mut self, target: u32) {
        self.remove_node_edges_to(target);
    }

    pub fn remove_node(&mut self, node_id: u32) -> bool {
        if node_id == 0 {
            return false;
        }
        self.remove_node_edges_to(node_id);
        let Some(idx) = (0..self.node_count as usize).find(|&i| self.nodes[i].node_id == node_id) else {
            return false;
        };
        if idx < self.node_count as usize - 1 {
            self.nodes[idx] = self.nodes[self.node_count as usize - 1];
        }
        self.node_count -= 1;
        true
    }

    pub fn ensure_local_node(&mut self, my_node: u32, now_ms: u32) {
        if self.find_node(my_node).is_none() {
            let _ = self.find_or_create_node(my_node, now_ms, my_node);
        }
    }

    /// Refresh node activity timestamp (SignalRouting `updateNodeActivity`).
    pub fn update_node_activity(&mut self, node_id: u32, now_ms: u32, my_node: u32) -> bool {
        if node_id == 0 || node_id == my_node {
            return false;
        }
        let Some(node) = self.find_or_create_node(node_id, now_ms, my_node) else {
            return false;
        };
        node.last_full_update_ms = now_ms;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DownstreamTable;

    #[test]
    fn age_removes_nodes_with_no_outgoing_edges() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 1_000);
        let _ = edges.update_node_activity(0xBB, 1_000, 0xAA);
        assert_eq!(edges.node_count(), 2);

        let mut downstream = DownstreamTable::new();
        assert!(edges.age_edges(0xAA, 61_000, 7_200_000, Some(&mut downstream)));
        assert_eq!(edges.node_count(), 1);
        assert!(edges.find_node(0xBB).is_none());
    }

    #[test]
    fn age_keeps_node_with_mirrored_edges() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 1_000);
        edges.update_edge(
            0xAA,
            0xBB,
            0xCC,
            2.0,
            1_000,
            EdgeSource::Mirrored,
            true,
            0,
        );
        assert_eq!(edges.node_count(), 2);

        let mut downstream = DownstreamTable::new();
        assert!(!edges.age_edges(0xAA, 61_000, 7_200_000, Some(&mut downstream)));
        assert!(edges.find_node(0xBB).is_some());
        assert!(edges.find_node(0xCC).is_none());
    }

    #[test]
    fn age_clears_downstream_when_relay_node_removed() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 1_000);
        let _ = edges.update_node_activity(0xBB, 1_000, 0xAA);
        let mut downstream = DownstreamTable::new();
        downstream.update(0xAA, 0xDD, 0xBB, 2.0, 1_000, false, 0);
        assert_eq!(downstream.count(), 1);

        assert!(edges.age_edges(0xAA, 61_000, 7_200_000, Some(&mut downstream)));
        assert_eq!(downstream.count(), 0);
    }

    #[test]
    fn direct_neighbor_count_uses_reported_to_us() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 1_000);
        let _ = edges.update_node_activity(0xBB, 1_000, 0xAA);
        edges.update_edge(0xAA, 0xBB, 0xAA, 2.0, 1_000, EdgeSource::Reported, true, 0);
        assert_eq!(edges.count_direct_neighbors(0xAA), 1);
        assert_eq!(edges.direct_neighbor_ids(0xAA, &mut [0; MAX_EDGES_PER_NODE]), 0);
    }

    #[test]
    fn is_our_direct_neighbor_any_edge() {
        let mut edges = EdgeStore::new();
        edges.ensure_local_node(0xAA, 1_000);
        edges.update_edge(0xAA, 0xAA, 0xBB, 2.0, 1_000, EdgeSource::Mirrored, true, 0);
        assert!(edges.is_our_direct_neighbor(0xBB, 0xAA));
        assert!(!edges.has_direct_reported_edge_to(0xAA, 0xBB));
    }
}
