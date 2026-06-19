//! Peer SR capability cache (Legacy / Passive / SR-active / Unknown).

use crate::nodeinfo::{
    DEVICE_ROLE_CLIENT, DEVICE_ROLE_CLIENT_HIDDEN, DEVICE_ROLE_CLIENT_MUTE,
    DEVICE_ROLE_LOST_AND_FOUND, DEVICE_ROLE_REPEATER, DEVICE_ROLE_ROUTER,
    DEVICE_ROLE_ROUTER_CLIENT, DEVICE_ROLE_ROUTER_LATE,
};

pub const MAX_CAPABILITY_RECORDS: usize = 32;
pub const CAPABILITY_TTL_MS: u32 = 7_200_000;

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
        self.find(node_id)
            .map(|r| r.status)
            .unwrap_or(CapabilityStatus::Unknown)
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

    pub fn prune(&mut self, now_ms: u32) {
        let mut i = 0u8;
        while i < self.count {
            let age = now_ms.wrapping_sub(self.records[i as usize].last_updated_ms);
            if age >= CAPABILITY_TTL_MS && age < 0x8000_0000 {
                self.remove_at(i);
            } else {
                i += 1;
            }
        }
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
}
