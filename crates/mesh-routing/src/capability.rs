//! Peer SR capability cache (Legacy / Passive / SR-active / Unknown).

use crate::nodeinfo::{
    DEVICE_ROLE_CLIENT, DEVICE_ROLE_CLIENT_HIDDEN, DEVICE_ROLE_CLIENT_MUTE,
    DEVICE_ROLE_LOST_AND_FOUND, DEVICE_ROLE_REPEATER, DEVICE_ROLE_ROUTER,
    DEVICE_ROLE_ROUTER_CLIENT, DEVICE_ROLE_ROUTER_LATE,
};

pub const MAX_CAPABILITY_RECORDS: usize = 64;
/// Three topology broadcast intervals plus margin (1810 s).
pub const CAPABILITY_TTL_MS: u32 = 1_810_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CapabilityStatus {
    #[default]
    Unknown,
    Legacy,
    Passive,
    SrActive,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CapabilityRecord {
    node_id: u32,
    status: CapabilityStatus,
    role: u32,
    last_updated_ms: u32,
}

pub struct CapabilityCache {
    records: [CapabilityRecord; MAX_CAPABILITY_RECORDS],
    count: u8,
}

impl CapabilityCache {
    pub const fn new() -> Self {
        Self {
            records: [CapabilityRecord {
                node_id: 0,
                status: CapabilityStatus::Unknown,
                role: 0,
                last_updated_ms: 0,
            }; MAX_CAPABILITY_RECORDS],
            count: 0,
        }
    }

    pub fn status(&self, node_id: u32) -> CapabilityStatus {
        self.status_at(node_id, 0, 0)
    }

    pub fn status_at(&self, node_id: u32, my_node: u32, now_ms: u32) -> CapabilityStatus {
        let Some(rec) = self.find(node_id) else {
            return CapabilityStatus::Unknown;
        };
        if rec.node_id == my_node && my_node != 0 {
            return rec.status;
        }
        if now_ms != 0 {
            let age = now_ms.wrapping_sub(rec.last_updated_ms);
            if age > CAPABILITY_TTL_MS && age < 0x8000_0000 {
                return CapabilityStatus::Unknown;
            }
        }
        rec.status
    }

    #[doc(hidden)]
    pub fn record_count(&self) -> u8 {
        self.count
    }

    pub fn role(&self, node_id: u32) -> Option<u32> {
        self.find(node_id).map(|r| r.role)
    }

    pub fn track_role(&mut self, node_id: u32, role: u32, now_ms: u32) {
        if node_id == 0 {
            return;
        }
        let legacy = capability_from_role(role);
        if let Some(rec) = self.find_mut(node_id) {
            rec.role = role;
            rec.last_updated_ms = now_ms;
            if legacy == CapabilityStatus::Legacy {
                rec.status = CapabilityStatus::Legacy;
            }
            return;
        }
        if (self.count as usize) >= MAX_CAPABILITY_RECORDS {
            return;
        }
        let idx = self.count as usize;
        self.records[idx] = CapabilityRecord {
            node_id,
            status: legacy,
            role,
            last_updated_ms: now_ms,
        };
        self.count += 1;
    }

    pub fn track_topology(&mut self, node_id: u32, signal_routing_active: bool, now_ms: u32) {
        if node_id == 0 {
            return;
        }
        let status = if signal_routing_active {
            CapabilityStatus::SrActive
        } else {
            CapabilityStatus::Passive
        };
        if let Some(rec) = self.find_mut(node_id) {
            rec.last_updated_ms = now_ms;
            if status == CapabilityStatus::SrActive || status == CapabilityStatus::Passive {
                rec.status = status;
            }
            return;
        }
        if (self.count as usize) >= MAX_CAPABILITY_RECORDS {
            return;
        }
        let idx = self.count as usize;
        self.records[idx] = CapabilityRecord {
            node_id,
            status,
            role: 0,
            last_updated_ms: now_ms,
        };
        self.count += 1;
    }

    /// Remove stale records. Returns neighbor ids whose SR/passive capability expired;
    /// the graph should clear `hears_us` on those edges.
    pub fn prune(&mut self, now_ms: u32, my_node: u32) -> ([u32; MAX_CAPABILITY_RECORDS], u8) {
        let mut clear_hears_us = [0u32; MAX_CAPABILITY_RECORDS];
        let mut clear_hears_us_count = 0u8;
        let mut i = 0u8;
        while i < self.count {
            let idx = i as usize;
            let rec = self.records[idx];
            if rec.node_id == my_node {
                i += 1;
                continue;
            }
            let age = now_ms.wrapping_sub(rec.last_updated_ms);
            if age > CAPABILITY_TTL_MS && age < 0x8000_0000 {
                if matches!(
                    rec.status,
                    CapabilityStatus::SrActive | CapabilityStatus::Passive
                ) {
                    let n = clear_hears_us_count as usize;
                    if n < MAX_CAPABILITY_RECORDS {
                        clear_hears_us[n] = rec.node_id;
                        clear_hears_us_count += 1;
                    }
                }
                self.remove_at(i);
            } else {
                i += 1;
            }
        }
        (clear_hears_us, clear_hears_us_count)
    }

    /// Stock ROUTER / REPEATER / ROUTER_CLIENT that are not SR-active relay immediately.
    pub fn is_immediate_relay_router(&self, node_id: u32) -> bool {
        if self.status(node_id) == CapabilityStatus::SrActive {
            return false;
        }
        let Some(role) = self.role(node_id) else {
            return false;
        };
        matches!(
            role,
            DEVICE_ROLE_ROUTER | DEVICE_ROLE_REPEATER | DEVICE_ROLE_ROUTER_CLIENT
        )
    }

    pub fn is_legacy(&self, node_id: u32) -> bool {
        self.status(node_id) == CapabilityStatus::Legacy
    }

    pub fn is_legacy_router(&self, node_id: u32) -> bool {
        if self.status(node_id) != CapabilityStatus::Legacy {
            return false;
        }
        let Some(role) = self.role(node_id) else {
            return false;
        };
        matches!(
            role,
            DEVICE_ROLE_ROUTER
                | DEVICE_ROLE_ROUTER_LATE
                | DEVICE_ROLE_ROUTER_CLIENT
                | DEVICE_ROLE_REPEATER
        )
    }

    fn find(&self, node_id: u32) -> Option<&CapabilityRecord> {
        for i in 0..self.count as usize {
            if self.records[i].node_id == node_id {
                return Some(&self.records[i]);
            }
        }
        None
    }

    fn find_mut(&mut self, node_id: u32) -> Option<&mut CapabilityRecord> {
        for i in 0..self.count as usize {
            if self.records[i].node_id == node_id {
                return Some(&mut self.records[i]);
            }
        }
        None
    }

    fn remove_at(&mut self, index: u8) {
        let i = index as usize;
        if i + 1 < self.count as usize {
            self.records[i] = self.records[(self.count - 1) as usize];
        }
        self.count -= 1;
    }
}

pub fn capability_from_role(role: u32) -> CapabilityStatus {
    match role {
        DEVICE_ROLE_CLIENT_MUTE | DEVICE_ROLE_CLIENT_HIDDEN | DEVICE_ROLE_LOST_AND_FOUND => {
            CapabilityStatus::Legacy
        }
        _ => CapabilityStatus::Unknown,
    }
}

pub fn role_may_send_topology(role: u32) -> bool {
    matches!(
        role,
        DEVICE_ROLE_CLIENT
            | DEVICE_ROLE_CLIENT_MUTE
            | DEVICE_ROLE_ROUTER
            | DEVICE_ROLE_ROUTER_CLIENT
            | DEVICE_ROLE_REPEATER
            | DEVICE_ROLE_ROUTER_LATE
            | 6 // TRACKER
            | 7 // SENSOR
            | 8 // TAK
            | DEVICE_ROLE_CLIENT_HIDDEN
            | DEVICE_ROLE_LOST_AND_FOUND
            | 12 // TAK_TRACKER
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mute_role_is_legacy() {
        assert_eq!(
            capability_from_role(DEVICE_ROLE_CLIENT_MUTE),
            CapabilityStatus::Legacy
        );
    }

    #[test]
    fn immediate_relay_router_requires_role_and_not_sr_active() {
        let mut cache = CapabilityCache::new();
        cache.track_role(0xBB, DEVICE_ROLE_ROUTER, 0);
        assert!(cache.is_immediate_relay_router(0xBB));
        cache.track_topology(0xBB, true, 100);
        assert!(!cache.is_immediate_relay_router(0xBB));
    }

    #[test]
    fn status_at_returns_unknown_after_ttl() {
        let mut cache = CapabilityCache::new();
        cache.track_topology(0xBB, true, 0);
        assert_eq!(
            cache.status_at(0xBB, 0, CAPABILITY_TTL_MS),
            CapabilityStatus::SrActive
        );
        assert_eq!(
            cache.status_at(0xBB, 0, CAPABILITY_TTL_MS + 1),
            CapabilityStatus::Unknown
        );
    }

    #[test]
    fn prune_skips_local_node_and_collects_sr_expiry() {
        let mut cache = CapabilityCache::new();
        cache.track_topology(0xAA, true, 0);
        cache.track_topology(0xBB, false, 0);
        cache.track_topology(0xCC, true, 0);
        let (cleared, n) = cache.prune(CAPABILITY_TTL_MS + 1, 0xAA);
        assert_eq!(n, 2);
        assert_eq!(cleared[0], 0xBB);
        assert_eq!(cleared[1], 0xCC);
        assert_eq!(cache.record_count(), 1);
        assert_eq!(cache.status(0xAA), CapabilityStatus::SrActive);
    }

    #[test]
    fn cache_holds_max_records() {
        let mut cache = CapabilityCache::new();
        for i in 1..=MAX_CAPABILITY_RECORDS as u32 {
            cache.track_topology(i, true, 0);
        }
        assert_eq!(cache.record_count(), MAX_CAPABILITY_RECORDS as u8);
        cache.track_topology(MAX_CAPABILITY_RECORDS as u32 + 1, true, 0);
        assert_eq!(cache.record_count(), MAX_CAPABILITY_RECORDS as u8);
    }
}
