//! Next-hop health for named unicast forwards: remember hops that stay silent.

/// Consecutive misses before a hop is treated as suspect.
pub const HOP_HEALTH_SUSPECT_MISSES: u8 = 2;
/// An entry, suspect or not, expires this many milliseconds after its last miss.
pub const HOP_HEALTH_SUSPECT_TTL_MS: u32 = 10 * 60 * 1000;
const MAX_HOP_HEALTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HopHealthEntry {
    destination: u32,
    next_hop: u32,
    consecutive_misses: u8,
    last_miss_ms: u32,
}

impl HopHealthEntry {
    const fn empty() -> Self {
        Self {
            destination: 0,
            next_hop: 0,
            consecutive_misses: 0,
            last_miss_ms: 0,
        }
    }

    fn is_occupied(&self) -> bool {
        self.destination != 0 && self.next_hop != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HopHealthEvent {
    None,
    BecameSuspect {
        next_hop: u32,
        destination: u32,
        misses: u8,
    },
    BecameHealthy {
        next_hop: u32,
        destination: u32,
    },
}

/// Small RAM table keyed by `(destination, next hop)`. Nothing is persisted.
pub struct HopHealth {
    entries: [HopHealthEntry; MAX_HOP_HEALTH],
}

impl Default for HopHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl HopHealth {
    pub const fn new() -> Self {
        Self {
            entries: [HopHealthEntry::empty(); MAX_HOP_HEALTH],
        }
    }

    fn find(&self, destination: u32, next_hop: u32) -> Option<usize> {
        self.entries.iter().position(|e| {
            e.is_occupied() && e.destination == destination && e.next_hop == next_hop
        })
    }

    /// The live entry for the pair, after dropping it when its last miss is older than the TTL.
    fn find_live(&mut self, destination: u32, next_hop: u32, now_ms: u32) -> Option<usize> {
        let idx = self.find(destination, next_hop)?;
        if now_ms.wrapping_sub(self.entries[idx].last_miss_ms) >= HOP_HEALTH_SUSPECT_TTL_MS {
            self.entries[idx] = HopHealthEntry::empty();
            return None;
        }
        Some(idx)
    }

    /// True when `(destination, next_hop)` has reached the suspect threshold and has not expired.
    pub fn is_suspect(&mut self, destination: u32, next_hop: u32, now_ms: u32) -> bool {
        if destination == 0 || next_hop == 0 {
            return false;
        }
        self.find_live(destination, next_hop, now_ms)
            .is_some_and(|idx| self.entries[idx].consecutive_misses >= HOP_HEALTH_SUSPECT_MISSES)
    }

    /// Record that a named follow-up expired without hearing the nominated hop.
    pub fn record_miss(
        &mut self,
        destination: u32,
        next_hop: u32,
        now_ms: u32,
    ) -> HopHealthEvent {
        if destination == 0 || next_hop == 0 {
            return HopHealthEvent::None;
        }
        if let Some(idx) = self.find_live(destination, next_hop, now_ms) {
            let e = &mut self.entries[idx];
            e.consecutive_misses = e.consecutive_misses.saturating_add(1);
            e.last_miss_ms = now_ms;
            if e.consecutive_misses == HOP_HEALTH_SUSPECT_MISSES {
                return HopHealthEvent::BecameSuspect {
                    next_hop,
                    destination,
                    misses: e.consecutive_misses,
                };
            }
            return HopHealthEvent::None;
        }
        let idx = self
            .entries
            .iter()
            .position(|e| !e.is_occupied())
            .unwrap_or_else(|| {
                // Evict the oldest (earliest last_miss_ms, wrapping-aware via age).
                let mut best = 0usize;
                let mut best_age = 0u32;
                for (i, e) in self.entries.iter().enumerate() {
                    let age = now_ms.wrapping_sub(e.last_miss_ms);
                    if age >= best_age {
                        best_age = age;
                        best = i;
                    }
                }
                best
            });
        self.entries[idx] = HopHealthEntry {
            destination,
            next_hop,
            consecutive_misses: 1,
            last_miss_ms: now_ms,
        };
        HopHealthEvent::None
    }

    /// Record that the nominated hop carried the packet, or the destination answered.
    pub fn record_success(&mut self, destination: u32, next_hop: u32) -> HopHealthEvent {
        if destination == 0 || next_hop == 0 {
            return HopHealthEvent::None;
        }
        let Some(idx) = self.find(destination, next_hop) else {
            return HopHealthEvent::None;
        };
        let was_suspect = self.entries[idx].consecutive_misses >= HOP_HEALTH_SUSPECT_MISSES;
        self.entries[idx] = HopHealthEntry::empty();
        if was_suspect {
            HopHealthEvent::BecameHealthy {
                next_hop,
                destination,
            }
        } else {
            HopHealthEvent::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_misses_make_suspect_one_does_not() {
        let mut h = HopHealth::new();
        let dest = 0xEE00_00EE;
        let hop = 0xBB00_00BB;
        assert!(!h.is_suspect(dest, hop, 1_000));
        assert_eq!(h.record_miss(dest, hop, 1_000), HopHealthEvent::None);
        assert!(!h.is_suspect(dest, hop, 1_100));
        assert_eq!(
            h.record_miss(dest, hop, 2_000),
            HopHealthEvent::BecameSuspect {
                next_hop: hop,
                destination: dest,
                misses: 2,
            }
        );
        assert!(h.is_suspect(dest, hop, 2_100));
    }

    #[test]
    fn success_resets_and_foreign_copy_is_neutral() {
        let mut h = HopHealth::new();
        let dest = 0x1;
        let hop = 0x2;
        let _ = h.record_miss(dest, hop, 10);
        let _ = h.record_miss(dest, hop, 20);
        assert!(h.is_suspect(dest, hop, 30));
        // Neutral: no API call for a foreign copy; state unchanged.
        assert!(h.is_suspect(dest, hop, 40));
        assert_eq!(
            h.record_success(dest, hop),
            HopHealthEvent::BecameHealthy {
                next_hop: hop,
                destination: dest,
            }
        );
        assert!(!h.is_suspect(dest, hop, 60));
        assert_eq!(h.record_success(dest, hop), HopHealthEvent::None);
    }

    #[test]
    fn misses_older_than_ttl_do_not_count_towards_suspect() {
        let mut h = HopHealth::new();
        let dest = 0x1;
        let hop = 0x2;
        let _ = h.record_miss(dest, hop, 0);
        assert_eq!(
            h.record_miss(dest, hop, HOP_HEALTH_SUSPECT_TTL_MS),
            HopHealthEvent::None,
            "a single miss from one TTL ago is not consecutive with this one"
        );
        assert!(!h.is_suspect(dest, hop, HOP_HEALTH_SUSPECT_TTL_MS + 1));
        let t = HOP_HEALTH_SUSPECT_TTL_MS + 10;
        assert!(matches!(
            h.record_miss(dest, hop, t),
            HopHealthEvent::BecameSuspect { misses: 2, .. }
        ));
        // After expiry a suspect pair starts over and reports when it becomes suspect again.
        let later = t + HOP_HEALTH_SUSPECT_TTL_MS;
        assert!(!h.is_suspect(dest, hop, later));
        assert_eq!(h.record_miss(dest, hop, later), HopHealthEvent::None);
        assert!(matches!(
            h.record_miss(dest, hop, later + 1),
            HopHealthEvent::BecameSuspect { misses: 2, .. }
        ));
    }

    #[test]
    fn suspect_expires_after_ttl_including_u32_rollover() {
        let mut h = HopHealth::new();
        let dest = 0x1;
        let hop = 0x2;
        let near_wrap = u32::MAX - 1_000;
        let _ = h.record_miss(dest, hop, near_wrap);
        let last_miss = near_wrap.wrapping_add(1);
        let _ = h.record_miss(dest, hop, last_miss);
        assert!(h.is_suspect(dest, hop, last_miss.wrapping_add(2)));
        let after_ttl = last_miss.wrapping_add(HOP_HEALTH_SUSPECT_TTL_MS);
        assert!(!h.is_suspect(dest, hop, after_ttl));
    }

    #[test]
    fn full_table_evicts_oldest() {
        let mut h = HopHealth::new();
        for i in 0..MAX_HOP_HEALTH as u32 {
            let _ = h.record_miss(0x1000 + i, 0x2000 + i, 1_000 + i);
        }
        assert!(h.find(0x1000, 0x2000).is_some());
        let _ = h.record_miss(0xDEAD, 0xBEEF, 50_000);
        assert!(h.find(0x1000, 0x2000).is_none());
        assert!(h.find(0xDEAD, 0xBEEF).is_some());
    }
}
