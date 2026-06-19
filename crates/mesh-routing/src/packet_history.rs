//! Recent-packet dedup (fixed-size ring, no heap).

const HISTORY_SIZE: usize = 64;

#[derive(Clone, Copy, Default)]
struct HistoryEntry {
    from: u32,
    id: u32,
    max_hop_limit: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveResult {
    New,
    Duplicate,
    /// Same `(from, id)` seen again with a higher `hop_limit` (upgrade path).
    Upgraded,
}

/// Tracks recently seen `(from, id)` pairs to suppress duplicate RX and relay.
pub struct PacketHistory {
    entries: [HistoryEntry; HISTORY_SIZE],
    head: usize,
}

impl Default for PacketHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketHistory {
    pub const fn new() -> Self {
        Self {
            entries: [HistoryEntry {
                from: 0,
                id: 0,
                max_hop_limit: 0,
            }; HISTORY_SIZE],
            head: 0,
        }
    }

    fn find(&self, from: u32, id: u32) -> Option<&HistoryEntry> {
        self.entries.iter().find(|e| e.from == from && e.id == id && e.from != 0)
    }

    fn find_mut(&mut self, from: u32, id: u32) -> Option<&mut HistoryEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.from == from && e.id == id && e.from != 0)
    }

    fn store(&mut self, from: u32, id: u32, hop_limit: u8) {
        if let Some(entry) = self.find_mut(from, id) {
            if hop_limit > entry.max_hop_limit {
                entry.max_hop_limit = hop_limit;
            }
            return;
        }
        self.entries[self.head] = HistoryEntry {
            from,
            id,
            max_hop_limit: hop_limit,
        };
        self.head = (self.head + 1) % HISTORY_SIZE;
    }

    /// Record or update a packet; returns whether this copy is new, a dupe, or an upgrade.
    pub fn observe(&mut self, from: u32, id: u32, hop_limit: u8) -> ObserveResult {
        if id == 0 {
            return ObserveResult::New;
        }
        if let Some(entry) = self.find(from, id) {
            if hop_limit > entry.max_hop_limit {
                self.store(from, id, hop_limit);
                return ObserveResult::Upgraded;
            }
            return ObserveResult::Duplicate;
        }
        self.store(from, id, hop_limit);
        ObserveResult::New
    }

    pub fn max_hop_limit(&self, from: u32, id: u32) -> Option<u8> {
        self.find(from, id).map(|e| e.max_hop_limit)
    }

    /// Returns `true` if this packet was already recorded.
    pub fn is_duplicate(&self, from: u32, id: u32) -> bool {
        self.find(from, id).is_some()
    }

    /// Record a packet id so duplicates are suppressed later.
    pub fn remember(&mut self, from: u32, id: u32) {
        self.store(from, id, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_and_detects_duplicates() {
        let mut history = PacketHistory::new();
        assert!(!history.is_duplicate(0x1234, 99));
        assert_eq!(history.observe(0x1234, 99, 3), ObserveResult::New);
        assert!(history.is_duplicate(0x1234, 99));
        assert_eq!(history.observe(0x1234, 99, 3), ObserveResult::Duplicate);
        assert!(!history.is_duplicate(0x1234, 100));
    }

    #[test]
    fn detects_hop_limit_upgrade() {
        let mut history = PacketHistory::new();
        assert_eq!(history.observe(0xAA, 1, 2), ObserveResult::New);
        assert_eq!(history.observe(0xAA, 1, 2), ObserveResult::Duplicate);
        assert_eq!(history.observe(0xAA, 1, 4), ObserveResult::Upgraded);
        assert_eq!(history.max_hop_limit(0xAA, 1), Some(4));
    }
}
