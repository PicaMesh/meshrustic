//! Downstream routing table (remote node → relay neighbor).

use mesh_radio::RadioId;

pub const MAX_DOWNSTREAM: usize = 1100;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DownstreamEntry {
    pub destination: u32,
    pub relay: u32,
    pub via_radio: RadioId,
    pub cost_fixed: u16,
    pub last_update_ms: u32,
}

pub struct DownstreamTable {
    entries: [DownstreamEntry; MAX_DOWNSTREAM],
    count: u16,
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
            }; MAX_DOWNSTREAM],
            count: 0,
        }
    }

    pub fn count(&self) -> u16 {
        self.count
    }

    pub fn entry(&self, index: u16) -> Option<&DownstreamEntry> {
        if (index as usize) < self.count as usize {
            Some(&self.entries[index as usize])
        } else {
            None
        }
    }

    pub fn get_relay(&self, destination: u32) -> Option<u32> {
        (0..self.count as usize)
            .find(|&i| self.entries[i].destination == destination)
            .map(|i| self.entries[i].relay)
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
        if destination == 0 || relay == 0 || destination == relay || destination == my_node {
            return;
        }
        if relay_has_direct_edge {
            return;
        }
        let cost_fixed = (total_cost * 100.0).min(65535.0) as u16;

        for i in 0..self.count as usize {
            if self.entries[i].destination == destination && self.entries[i].relay == relay {
                self.entries[i].cost_fixed = cost_fixed;
                self.entries[i].last_update_ms = now_ms;
                if via_radio != 0 {
                    self.entries[i].via_radio = via_radio;
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
        };
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
            if now_ms.wrapping_sub(entry.last_update_ms) > ttl_ms {
                if i < self.count - 1 {
                    self.entries[i as usize] = self.entries[(self.count - 1) as usize];
                }
                self.count -= 1;
            } else if !relay_in_graph(entry.relay) {
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
            table.update(
                0xAA,
                0x1_0000 + i as u32,
                0xBB,
                2.0,
                i as u32,
                false,
                0,
            );
        }
        assert_eq!(table.count(), MAX_DOWNSTREAM as u16);
    }
}
