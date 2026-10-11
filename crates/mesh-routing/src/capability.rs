use crate::nodeinfo::{
    DEVICE_ROLE_CLIENT, DEVICE_ROLE_CLIENT_BASE, DEVICE_ROLE_CLIENT_HIDDEN,
    DEVICE_ROLE_CLIENT_MUTE, DEVICE_ROLE_REPEATER, DEVICE_ROLE_ROUTER, DEVICE_ROLE_ROUTER_CLIENT,
    DEVICE_ROLE_ROUTER_LATE, DEVICE_ROLE_SENSOR, DEVICE_ROLE_TAK, DEVICE_ROLE_TAK_TRACKER,
    DEVICE_ROLE_TRACKER,
};
use crate::sr_role::role_is_mute;

pub const MAX_CAPABILITY_RECORDS: usize = 64;
pub const CAPABILITY_TTL_MS: u32 = 3 * crate::neighbor_graph::TOPOLOGY_BROADCAST_MS + 20_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CapabilityStatus {
    #[default]
    Unknown,
    Legacy,
    Passive,
    SrActive,
}

impl CapabilityStatus {
    pub fn is_signal_routing(self) -> bool {
        matches!(self, Self::SrActive | Self::Passive)
    }
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

impl Default for CapabilityCache {
    fn default() -> Self {
        Self::new()
    }
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

    pub fn clear(&mut self) {
        self.count = 0;
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
            if !rec.status.is_signal_routing() {
                rec.last_updated_ms = now_ms;
                rec.status = legacy;
            }
            return;
        }
        let idx = if self.count as usize == MAX_CAPABILITY_RECORDS {
            let victim = self
                .records
                .iter()
                .enumerate()
                .filter(|(_, rec)| !rec.status.is_signal_routing())
                .max_by_key(|(_, rec)| now_ms.wrapping_sub(rec.last_updated_ms));
            let Some((idx, _)) = victim else {
                return;
            };
            idx
        } else {
            let idx = self.count as usize;
            self.count += 1;
            idx
        };
        self.records[idx] = CapabilityRecord {
            node_id,
            status: legacy,
            role,
            last_updated_ms: now_ms,
        };
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
            rec.status = status;
            return;
        }
        let idx = if self.count as usize == MAX_CAPABILITY_RECORDS {
            let victim = self
                .records
                .iter()
                .enumerate()
                .filter(|(_, rec)| !rec.status.is_signal_routing())
                .max_by_key(|(_, rec)| now_ms.wrapping_sub(rec.last_updated_ms));
            let Some((idx, _)) = victim else {
                return;
            };
            idx
        } else {
            let idx = self.count as usize;
            self.count += 1;
            idx
        };
        self.records[idx] = CapabilityRecord {
            node_id,
            status,
            role: 0,
            last_updated_ms: now_ms,
        };
    }

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

    /// A node that publishes nothing cannot prove coverage through an omitted topology list.
    pub fn publishes_topology(&self, node_id: u32) -> bool {
        matches!(
            self.status(node_id),
            CapabilityStatus::SrActive | CapabilityStatus::Passive
        )
    }

    /// A publisher’s measured list is stronger evidence than its advertised role.
    pub fn is_immediate_relay_router(&self, node_id: u32) -> bool {
        if self.publishes_topology(node_id) {
            return false;
        }
        matches!(
            self.role(node_id),
            Some(DEVICE_ROLE_ROUTER | DEVICE_ROLE_REPEATER | DEVICE_ROLE_ROUTER_CLIENT)
        )
    }

    pub fn will_not_cancel_for_us(&self, node_id: u32) -> bool {
        if self.status(node_id) == CapabilityStatus::SrActive {
            return false;
        }
        let Some(role) = self.role(node_id) else {
            return false;
        };
        matches!(role, DEVICE_ROLE_ROUTER | DEVICE_ROLE_ROUTER_LATE)
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
    if role_is_mute(role) {
        CapabilityStatus::Legacy
    } else {
        CapabilityStatus::Unknown
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
            | DEVICE_ROLE_TRACKER
            | DEVICE_ROLE_SENSOR
            | DEVICE_ROLE_TAK
            | DEVICE_ROLE_CLIENT_HIDDEN
            | DEVICE_ROLE_TAK_TRACKER
            | DEVICE_ROLE_CLIENT_BASE
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mute_roles_are_legacy() {
        assert_eq!(
            capability_from_role(DEVICE_ROLE_CLIENT_MUTE),
            CapabilityStatus::Legacy
        );
        assert_eq!(
            capability_from_role(DEVICE_ROLE_TRACKER),
            CapabilityStatus::Legacy
        );
        assert_eq!(
            capability_from_role(DEVICE_ROLE_CLIENT_HIDDEN),
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
    fn a_passive_publisher_is_not_reserved_for_either() {
        let mut cache = CapabilityCache::new();
        cache.track_role(0xBB, DEVICE_ROLE_ROUTER, 0);
        cache.track_topology(0xBB, false, 100);
        assert_eq!(cache.status(0xBB), CapabilityStatus::Passive);
        assert!(cache.publishes_topology(0xBB));
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

    #[test]
    fn nodeinfo_does_not_refresh_or_downgrade_topology_evidence() {
        let mut cache = CapabilityCache::new();
        cache.track_topology(2, true, 10);
        cache.track_role(2, DEVICE_ROLE_CLIENT, 20);
        assert_eq!(cache.status_at(2, 1, 21), CapabilityStatus::SrActive);
        assert_eq!(
            cache.status_at(2, 1, 11 + CAPABILITY_TTL_MS),
            CapabilityStatus::Unknown
        );
    }

    #[test]
    fn full_cache_admits_topology_by_replacing_non_sr_evidence() {
        let mut cache = CapabilityCache::new();
        for id in 1..=MAX_CAPABILITY_RECORDS as u32 {
            cache.track_role(id, DEVICE_ROLE_CLIENT, id);
        }
        cache.track_topology(1000, true, 100);
        assert_eq!(cache.status(1000), CapabilityStatus::SrActive);
        assert_eq!(cache.count as usize, MAX_CAPABILITY_RECORDS);
    }
}
