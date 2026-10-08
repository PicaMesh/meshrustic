//! Downstream routing table (remote node → relay neighbor).

use mesh_radio::RadioId;

/// Match the MT+SR fork (`NEIGHBOR_GRAPH_MAX_DOWNSTREAM`).
pub const MAX_DOWNSTREAM: usize = 900;
/// Walk dest → relay → … at most this many hops before treating the chain as a cycle.
pub const MAX_DOWNSTREAM_CHAIN: usize = 16;

/// First neighbour we can hear on a downstream walk from a destination.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChainEgress {
    pub node: u32,
    pub hops: u8,
    pub cost_fixed: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DownstreamEntry {
    pub destination: u32,
    pub relay: u32,
    pub via_radio: RadioId,
    pub cost_fixed: u16,
    pub last_update_ms: u32,
    /// Set when the row came from a publisher's topology with `hearsUs` (or a
    /// capacity demotion that kept that evidence). Relayed orphans stay false.
    pub list_learned: bool,
}

pub struct DownstreamTable {
    entries: [DownstreamEntry; MAX_DOWNSTREAM],
    count: u16,
}

impl Default for DownstreamTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DownstreamTable {
    pub const fn new() -> Self {
        Self {
            entries: [DownstreamEntry {
                destination: 0,
                relay: 0,
                via_radio: 0,
                cost_fixed: 0,
                last_update_ms: 0,
                list_learned: false,
            }; MAX_DOWNSTREAM],
            count: 0,
        }
    }

    pub fn count(&self) -> u16 {
        self.count
    }

    pub fn clear(&mut self) {
        self.count = 0;
    }

    pub fn entry(&self, index: u16) -> Option<&DownstreamEntry> {
        if (index as usize) < self.count as usize {
            Some(&self.entries[index as usize])
        } else {
            None
        }
    }

    pub fn get_relay(&self, destination: u32, now_ms: u32, ttl_ms: u32) -> Option<u32> {
        self.relay_and_cost(destination, now_ms, ttl_ms)
            .map(|(relay, _)| relay)
    }

    pub fn relay_and_cost(&self, destination: u32, now_ms: u32, ttl_ms: u32) -> Option<(u32, u16)> {
        let mut best_relay = None;
        let mut best_cost = u16::MAX;
        for i in 0..self.count as usize {
            let entry = &self.entries[i];
            if entry.destination != destination {
                continue;
            }
            if now_ms.wrapping_sub(entry.last_update_ms) >= ttl_ms {
                continue;
            }
            if entry.cost_fixed < best_cost {
                best_cost = entry.cost_fixed;
                best_relay = Some(entry.relay);
            }
        }
        best_relay.map(|relay| (relay, best_cost))
    }

    /// Parent and last-hop cost when `destination` was parked from a topology list with `hearsUs`.
    pub fn list_downstream(
        &self,
        destination: u32,
        now_ms: u32,
        ttl_ms: u32,
    ) -> Option<(u32, u16)> {
        let mut best_relay = None;
        let mut best_cost = u16::MAX;
        for i in 0..self.count as usize {
            let entry = &self.entries[i];
            if entry.destination != destination || !entry.list_learned {
                continue;
            }
            if now_ms.wrapping_sub(entry.last_update_ms) >= ttl_ms {
                continue;
            }
            if entry.cost_fixed < best_cost {
                best_cost = entry.cost_fixed;
                best_relay = Some(entry.relay);
            }
        }
        best_relay.map(|relay| (relay, best_cost))
    }

    /// Walk `destination` along `via` until `is_egress` is true. Dest need not be a neighbour of
    /// its parent — a downstream row is enough. Returns none on a missing hop or a cycle.
    pub fn chain_egress(
        &self,
        destination: u32,
        now_ms: u32,
        ttl_ms: u32,
        is_egress: impl Fn(u32) -> bool,
    ) -> Option<ChainEgress> {
        if destination == 0 {
            return None;
        }
        let mut cur = destination;
        let mut hops = 0u8;
        let mut cost_fixed = 0u16;
        let mut seen = [0u32; MAX_DOWNSTREAM_CHAIN];
        loop {
            if hops as usize >= MAX_DOWNSTREAM_CHAIN {
                return None;
            }
            let (relay, hop_cost) = self.relay_and_cost(cur, now_ms, ttl_ms)?;
            if relay == 0 || relay == cur {
                return None;
            }
            if seen[..hops as usize].contains(&relay) {
                return None;
            }
            seen[hops as usize] = relay;
            hops += 1;
            cost_fixed = cost_fixed.saturating_add(hop_cost);
            if is_egress(relay) {
                return Some(ChainEgress {
                    node: relay,
                    hops,
                    cost_fixed,
                });
            }
            cur = relay;
        }
    }

    pub fn count_for_relay(&self, relay: u32, now_ms: u32, ttl_ms: u32) -> usize {
        let mut count = 0usize;
        for i in 0..self.count as usize {
            let entry = &self.entries[i];
            if entry.relay != relay {
                continue;
            }
            if now_ms.wrapping_sub(entry.last_update_ms) >= ttl_ms {
                continue;
            }
            count += 1;
        }
        count
    }

    pub fn nodes_for_relay(&self, relay: u32, out: &mut [u32], now_ms: u32, ttl_ms: u32) -> usize {
        let mut count = 0usize;
        for i in 0..self.count as usize {
            if count >= out.len() {
                break;
            }
            let entry = &self.entries[i];
            if entry.relay != relay {
                continue;
            }
            if now_ms.wrapping_sub(entry.last_update_ms) >= ttl_ms {
                continue;
            }
            out[count] = entry.destination;
            count += 1;
        }
        count
    }

    pub fn is_relay_for(&self, relay: u32, destination: u32, now_ms: u32, ttl_ms: u32) -> bool {
        for i in 0..self.count as usize {
            let entry = &self.entries[i];
            if entry.destination != destination || entry.relay != relay {
                continue;
            }
            if now_ms.wrapping_sub(entry.last_update_ms) < ttl_ms {
                return true;
            }
        }
        false
    }

    pub fn transfer_downstream(&mut self, old_relay: u32, new_relay: u32, now_ms: u32) -> usize {
        if old_relay == 0 || new_relay == 0 || old_relay == new_relay {
            return 0;
        }
        let mut moved = 0usize;
        for i in 0..self.count as usize {
            if self.entries[i].relay != old_relay {
                continue;
            }
            let destination = self.entries[i].destination;
            let cost_fixed = self.entries[i].cost_fixed;
            let via_radio = self.entries[i].via_radio;
            let list_learned = self.entries[i].list_learned;
            self.upsert_entry(
                destination,
                new_relay,
                cost_fixed,
                via_radio,
                now_ms,
                list_learned,
            );
            moved += 1;
        }
        self.clear_for_relay(old_relay);
        moved
    }

    fn upsert_entry(
        &mut self,
        destination: u32,
        relay: u32,
        cost_fixed: u16,
        via_radio: RadioId,
        now_ms: u32,
        list_learned: bool,
    ) {
        for i in 0..self.count as usize {
            if self.entries[i].destination == destination && self.entries[i].relay == relay {
                self.entries[i].cost_fixed = cost_fixed;
                self.entries[i].last_update_ms = now_ms;
                if via_radio != 0 {
                    self.entries[i].via_radio = via_radio;
                }
                if list_learned {
                    self.entries[i].list_learned = true;
                }
                return;
            }
        }
        if (self.count as usize) < MAX_DOWNSTREAM {
            let idx = self.count as usize;
            self.entries[idx] = DownstreamEntry {
                destination,
                relay,
                via_radio,
                cost_fixed,
                last_update_ms: now_ms,
                list_learned,
            };
            self.count += 1;
            return;
        }
        let mut oldest_idx = 0usize;
        let mut oldest = self.entries[0].last_update_ms;
        for i in 1..self.count as usize {
            if self.entries[i].last_update_ms < oldest {
                oldest = self.entries[i].last_update_ms;
                oldest_idx = i;
            }
        }
        self.entries[oldest_idx] = DownstreamEntry {
            destination,
            relay,
            via_radio,
            cost_fixed,
            last_update_ms: now_ms,
            list_learned,
        };
    }

    pub fn update(
        &mut self,
        my_node: u32,
        destination: u32,
        relay: u32,
        total_cost: f32,
        now_ms: u32,
        relay_has_direct_edge: bool,
        via_radio: RadioId,
    ) {
        self.update_inner(
            my_node,
            destination,
            relay,
            total_cost,
            now_ms,
            relay_has_direct_edge,
            via_radio,
            false,
        );
    }

    /// Topology list with `hearsUs`: last hop is priced from the publisher, not a relayed guess.
    pub fn update_listed(
        &mut self,
        my_node: u32,
        destination: u32,
        relay: u32,
        total_cost: f32,
        now_ms: u32,
        relay_has_direct_edge: bool,
        via_radio: RadioId,
    ) {
        self.update_inner(
            my_node,
            destination,
            relay,
            total_cost,
            now_ms,
            relay_has_direct_edge,
            via_radio,
            true,
        );
    }

    fn update_inner(
        &mut self,
        my_node: u32,
        destination: u32,
        relay: u32,
        total_cost: f32,
        now_ms: u32,
        relay_has_direct_edge: bool,
        via_radio: RadioId,
        list_learned: bool,
    ) {
        if destination == 0 || relay == 0 || destination == relay || destination == my_node {
            return;
        }
        if relay_has_direct_edge {
            return;
        }
        let cost_fixed = (total_cost * 100.0).min(65535.0) as u16;
        self.upsert_entry(
            destination,
            relay,
            cost_fixed,
            via_radio,
            now_ms,
            list_learned,
        );
    }

    pub fn update_exclusive(
        &mut self,
        my_node: u32,
        destination: u32,
        relay: u32,
        total_cost: f32,
        now_ms: u32,
        relay_has_direct_edge: bool,
        via_radio: RadioId,
    ) {
        let mut i = 0u16;
        while i < self.count {
            if self.entries[i as usize].destination == destination {
                if i < self.count - 1 {
                    self.entries[i as usize] = self.entries[(self.count - 1) as usize];
                }
                self.count -= 1;
            } else {
                i += 1;
            }
        }
        self.update(
            my_node,
            destination,
            relay,
            total_cost,
            now_ms,
            relay_has_direct_edge,
            via_radio,
        );
    }

    pub fn clear_for_relay(&mut self, relay: u32) {
        let mut i = 0u16;
        while i < self.count {
            if self.entries[i as usize].relay == relay {
                if i < self.count - 1 {
                    self.entries[i as usize] = self.entries[(self.count - 1) as usize];
                }
                self.count -= 1;
            } else {
                i += 1;
            }
        }
    }

    pub fn clear_for_destination(&mut self, destination: u32) {
        let mut i = 0u16;
        while i < self.count {
            if self.entries[i as usize].destination == destination {
                if i < self.count - 1 {
                    self.entries[i as usize] = self.entries[(self.count - 1) as usize];
                }
                self.count -= 1;
            } else {
                i += 1;
            }
        }
    }

    pub fn age(&mut self, now_ms: u32, ttl_ms: u32, relay_in_graph: impl Fn(u32) -> bool) -> bool {
        let before = self.count;
        let mut i = 0u16;
        while i < self.count {
            let entry = self.entries[i as usize];
            let expired = now_ms.wrapping_sub(entry.last_update_ms) > ttl_ms;
            if expired || !relay_in_graph(entry.relay) {
                if i < self.count - 1 {
                    self.entries[i as usize] = self.entries[(self.count - 1) as usize];
                }
                self.count -= 1;
            } else {
                i += 1;
            }
        }
        before != self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_up_to_max_downstream_entries() {
        let mut table = DownstreamTable::new();
        for i in 0..MAX_DOWNSTREAM {
            table.update(0xAA, 0x1_0000 + i as u32, 0xBB, 2.0, i as u32, false, 0);
        }
        assert_eq!(table.count(), MAX_DOWNSTREAM as u16);
    }

    #[test]
    fn get_relay_picks_lowest_cost_among_fresh_entries() {
        let mut table = DownstreamTable::new();
        table.update(0xAA, 0xDD, 0xBB, 4.0, 1_000, false, 0);
        table.update(0xAA, 0xDD, 0xCC, 2.5, 1_000, false, 0);
        assert_eq!(table.get_relay(0xDD, 1_500, 10_000), Some(0xCC));
    }

    #[test]
    fn get_relay_skips_stale_entries() {
        let mut table = DownstreamTable::new();
        table.update(0xAA, 0xDD, 0xBB, 2.0, 9_000, false, 0);
        table.update(0xAA, 0xDD, 0xCC, 5.0, 1_000, false, 0);
        assert_eq!(table.get_relay(0xDD, 10_000, 5_000), Some(0xBB));
        assert_eq!(table.get_relay(0xDD, 20_000, 5_000), None);
    }

    #[test]
    fn list_downstream_ignores_orphan_rows() {
        let mut table = DownstreamTable::new();
        table.update(0xAA, 0xDD, 0xBB, 2.0, 1_000, false, 0);
        assert!(table.list_downstream(0xDD, 1_500, 10_000).is_none());
        table.update_listed(0xAA, 0xDD, 0xCC, 3.0, 1_000, false, 0);
        assert_eq!(table.list_downstream(0xDD, 1_500, 10_000), Some((0xCC, 300)));
        assert_eq!(table.get_relay(0xDD, 1_500, 10_000), Some(0xBB));
    }

    #[test]
    fn transfer_downstream_moves_entries_to_new_relay() {
        let mut table = DownstreamTable::new();
        table.update(0xAA, 0xD1, 0x0100_0001, 2.0, 1_000, false, 0);
        table.update(0xAA, 0xD2, 0x0100_0001, 3.0, 1_000, false, 0);
        assert_eq!(
            table.transfer_downstream(0x0100_0001, 0x0200_0002, 2_000),
            2
        );
        assert_eq!(table.count_for_relay(0x0100_0001, 2_000, 10_000), 0);
        assert_eq!(table.count_for_relay(0x0200_0002, 2_000, 10_000), 2);
        let mut nodes = [0u32; 4];
        assert_eq!(
            table.nodes_for_relay(0x0200_0002, &mut nodes, 2_000, 10_000),
            2
        );
        assert!(nodes[..2].contains(&0xD1));
        assert!(nodes[..2].contains(&0xD2));
    }

    #[test]
    fn chain_walks_to_the_first_hearable_hop() {
        const ME: u32 = 0xAA;
        const HUB: u32 = 0xF6;
        const PARENT: u32 = 0x11;
        const MID: u32 = 0x33;
        const DEST: u32 = 0x22;
        let mut table = DownstreamTable::new();
        table.update(ME, DEST, MID, 1.5, 1_000, false, 0);
        table.update(ME, MID, PARENT, 1.5, 1_000, false, 0);
        table.update(ME, PARENT, HUB, 2.0, 1_000, false, 0);
        let hearable = |n: u32| n == HUB;
        let chain = table
            .chain_egress(DEST, 1_500, 10_000, hearable)
            .expect("a hearable hop on the chain");
        assert_eq!(chain.node, HUB);
        assert_eq!(chain.hops, 3);
        assert_eq!(
            table
                .chain_egress(PARENT, 1_500, 10_000, hearable)
                .map(|c| c.node),
            Some(HUB)
        );
        assert!(
            table
                .chain_egress(DEST, 1_500, 10_000, |n| n == PARENT)
                .is_some_and(|c| c.node == PARENT && c.hops == 2),
            "the hub appointing the parent does not need dest as the parent's neighbour"
        );
    }

    #[test]
    fn chain_returns_none_on_a_cycle_or_a_broken_path() {
        const ME: u32 = 0xAA;
        let mut table = DownstreamTable::new();
        table.update(ME, 0x22, 0x11, 1.0, 1_000, false, 0);
        table.update(ME, 0x11, 0x22, 1.0, 1_000, false, 0);
        assert!(table.chain_egress(0x22, 1_500, 10_000, |_| false).is_none());
        let mut broken = DownstreamTable::new();
        broken.update(ME, 0x22, 0x11, 1.0, 1_000, false, 0);
        assert!(broken
            .chain_egress(0x22, 1_500, 10_000, |n| n == 0xF6)
            .is_none());
    }
}
