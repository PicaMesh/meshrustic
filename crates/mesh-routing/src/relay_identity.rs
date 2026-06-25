//! Relay-byte → NodeNum resolution for coordinated flooding (heard-from).

use crate::graph::{calculate_etx, is_placeholder_node, placeholder_node_id, EdgeStore};
use crate::neighbor_graph::NeighborGraph;

pub const MAX_RELAY_IDENTITY_ENTRIES: usize = 16;
pub const RELAY_ID_CACHE_TTL_MS: u32 = 600_000;
const MAX_CANDIDATES_PER_BUCKET: usize = 4;

#[derive(Clone, Copy, Default)]
struct RelayIdentityEntry {
    node_id: u32,
    last_heard_ms: u32,
}

#[derive(Clone, Copy, Default)]
struct RelayIdentityBucket {
    relay_id: u8,
    entries: [RelayIdentityEntry; MAX_CANDIDATES_PER_BUCKET],
    entry_count: u8,
}

/// Fixed-size cache mapping 1-byte relay ids to recently heard NodeNums.
pub struct RelayIdentityCache {
    buckets: [RelayIdentityBucket; MAX_RELAY_IDENTITY_ENTRIES],
    bucket_count: u8,
}

impl Default for RelayIdentityCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayIdentityCache {
    pub const fn new() -> Self {
        Self {
            buckets: [RelayIdentityBucket {
                relay_id: 0,
                entries: [RelayIdentityEntry {
                    node_id: 0,
                    last_heard_ms: 0,
                }; MAX_CANDIDATES_PER_BUCKET],
                entry_count: 0,
            }; MAX_RELAY_IDENTITY_ENTRIES],
            bucket_count: 0,
        }
    }

    pub fn remember_relay_identity(&mut self, node_id: u32, relay_byte: u8, now_ms: u32) {
        if relay_byte == 0 || node_id == 0 {
            return;
        }

        let bucket_idx = match self.find_bucket(relay_byte) {
            Some(i) => i,
            None => {
                if (self.bucket_count as usize) >= MAX_RELAY_IDENTITY_ENTRIES {
                    return;
                }
                let idx = self.bucket_count as usize;
                self.buckets[idx] = RelayIdentityBucket {
                    relay_id: relay_byte,
                    ..RelayIdentityBucket::default()
                };
                self.bucket_count += 1;
                idx
            }
        };

        self.prune_bucket_entries(bucket_idx, now_ms);

        let bucket = &mut self.buckets[bucket_idx];
        for i in 0..bucket.entry_count as usize {
            if bucket.entries[i].node_id == node_id {
                bucket.entries[i].last_heard_ms = now_ms;
                return;
            }
        }
        if (bucket.entry_count as usize) < MAX_CANDIDATES_PER_BUCKET {
            let i = bucket.entry_count as usize;
            bucket.entries[i] = RelayIdentityEntry {
                node_id,
                last_heard_ms: now_ms,
            };
            bucket.entry_count += 1;
        }
    }

    pub fn prune_relay_identity_cache(&mut self, now_ms: u32) {
        let mut b = 0usize;
        while b < self.bucket_count as usize {
            self.prune_bucket_entries(b, now_ms);
            if self.buckets[b].entry_count == 0 {
                let last = (self.bucket_count - 1) as usize;
                if b < last {
                    self.buckets[b] = self.buckets[last];
                }
                self.bucket_count -= 1;
            } else {
                b += 1;
            }
        }
    }

    pub fn resolve_relay_identity(
        &self,
        relay_byte: u8,
        rssi: i16,
        snr: i8,
        edges: &EdgeStore,
        my_node: u32,
        now_ms: u32,
    ) -> Option<u32> {
        let bucket = self.buckets[..self.bucket_count as usize]
            .iter()
            .find(|b| b.relay_id == relay_byte)?;

        let mut best_node = 0u32;
        let mut newest = 0u32;
        let mut direct = [0u32; MAX_CANDIDATES_PER_BUCKET];
        let mut direct_etx = [0u16; MAX_CANDIDATES_PER_BUCKET];
        let mut direct_count = 0usize;

        for i in 0..bucket.entry_count as usize {
            let entry = bucket.entries[i];
            if now_ms.wrapping_sub(entry.last_heard_ms) > RELAY_ID_CACHE_TTL_MS {
                continue;
            }
            if is_placeholder_node(entry.node_id) {
                continue;
            }
            if let Some(etx_fixed) = Self::direct_edge_etx_fixed(edges, my_node, entry.node_id) {
                if direct_count < MAX_CANDIDATES_PER_BUCKET {
                    direct[direct_count] = entry.node_id;
                    direct_etx[direct_count] = etx_fixed;
                    direct_count += 1;
                }
            } else if entry.last_heard_ms >= newest {
                newest = entry.last_heard_ms;
                best_node = entry.node_id;
            }
        }

        let best_direct = Self::pick_best_direct_candidate(
            bucket,
            &direct[..direct_count],
            &direct_etx[..direct_count],
            rssi,
            snr,
            now_ms,
        );

        let result = if best_direct != 0 {
            best_direct
        } else {
            best_node
        };

        if result == 0 || is_placeholder_node(result) {
            None
        } else {
            Some(result)
        }
    }

    pub fn resolve_heard_from(
        &mut self,
        relay_node: u8,
        source: u32,
        rssi: i16,
        snr: i8,
        graph: &NeighborGraph,
        now_ms: u32,
    ) -> u32 {
        if relay_node == 0 {
            return source;
        }

        if let Some(resolved) = self.resolve_relay_identity(
            relay_node,
            rssi,
            snr,
            graph.edges(),
            graph.my_node(),
            now_ms,
        ) {
            return resolved;
        }

        if let Some(real) = graph.match_relay_byte_on_outgoing_edges(relay_node) {
            self.remember_relay_identity(real, relay_node, now_ms);
            return real;
        }
        if let Some(placeholder) = graph.match_relay_placeholder_on_outgoing_edges(relay_node) {
            return placeholder;
        }

        placeholder_node_id(relay_node)
    }

    fn find_bucket(&self, relay_byte: u8) -> Option<usize> {
        (0..self.bucket_count as usize).find(|&i| self.buckets[i].relay_id == relay_byte)
    }

    fn prune_bucket_entries(&mut self, bucket_idx: usize, now_ms: u32) {
        let bucket = &mut self.buckets[bucket_idx];
        let mut i = 0usize;
        while i < bucket.entry_count as usize {
            if now_ms.wrapping_sub(bucket.entries[i].last_heard_ms) > RELAY_ID_CACHE_TTL_MS {
                let last = (bucket.entry_count - 1) as usize;
                if i < last {
                    bucket.entries[i] = bucket.entries[last];
                }
                bucket.entry_count -= 1;
            } else {
                i += 1;
            }
        }
    }

    fn direct_edge_etx_fixed(edges: &EdgeStore, my_node: u32, peer: u32) -> Option<u16> {
        edges
            .find_node(my_node)
            .and_then(|node| node.find_edge(peer))
            .map(|edge| edge.etx_fixed)
    }

    fn pick_best_direct_candidate(
        bucket: &RelayIdentityBucket,
        direct: &[u32],
        direct_etx: &[u16],
        rssi: i16,
        snr: i8,
        now_ms: u32,
    ) -> u32 {
        if direct.is_empty() {
            return 0;
        }
        if direct.len() == 1 {
            return direct[0];
        }
        if rssi != 0 {
            let packet_etx = calculate_etx(rssi as i32, snr as f32);
            let packet_etx_fixed = (packet_etx * 100.0).min(65535.0).max(1.0) as u16;
            let mut best = direct[0];
            let mut best_diff = u16::MAX;
            for (i, &node) in direct.iter().enumerate() {
                let edge_etx = direct_etx[i];
                let diff = packet_etx_fixed.abs_diff(edge_etx);
                if diff < best_diff {
                    best_diff = diff;
                    best = node;
                }
            }
            return best;
        }

        let mut best_direct = 0u32;
        let mut newest_direct = 0u32;
        for i in 0..bucket.entry_count as usize {
            let entry = bucket.entries[i];
            if now_ms.wrapping_sub(entry.last_heard_ms) > RELAY_ID_CACHE_TTL_MS {
                continue;
            }
            if direct.contains(&entry.node_id) && entry.last_heard_ms >= newest_direct {
                newest_direct = entry.last_heard_ms;
                best_direct = entry.node_id;
            }
        }
        best_direct
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighbor_graph::NeighborGraph;

    #[test]
    fn cache_remembers_and_expires() {
        let mut cache = RelayIdentityCache::new();
        let mut graph = NeighborGraph::new();
        graph.set_my_node(0xAA);

        cache.remember_relay_identity(0x1234_00CD, 0xCD, 1_000);
        assert_eq!(
            cache.resolve_relay_identity(0xCD, -70, 8, graph.edges(), 0xAA, 2_000),
            Some(0x1234_00CD)
        );

        cache.prune_relay_identity_cache(RELAY_ID_CACHE_TTL_MS + 2_001);
        assert_eq!(
            cache.resolve_relay_identity(0xCD, -70, 8, graph.edges(), 0xAA, RELAY_ID_CACHE_TTL_MS + 2_001),
            None
        );
    }

    #[test]
    fn resolve_heard_from_relay_zero_is_source() {
        let mut cache = RelayIdentityCache::new();
        let graph = NeighborGraph::new();
        assert_eq!(
            cache.resolve_heard_from(0, 0xBEEF, -70, 8, &graph, 0),
            0xBEEF
        );
    }

    #[test]
    fn resolve_heard_from_unknown_relay_yields_placeholder() {
        let mut cache = RelayIdentityCache::new();
        let graph = NeighborGraph::new();
        assert_eq!(
            cache.resolve_heard_from(0xAB, 0xBEEF, -70, 8, &graph, 0),
            placeholder_node_id(0xAB)
        );
    }
}
