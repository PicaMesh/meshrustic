//! Peer SR capability cache (Legacy / Passive / SR-active / Unknown).

use crate::nodeinfo::{
    DEVICE_ROLE_CLIENT, DEVICE_ROLE_CLIENT_BASE, DEVICE_ROLE_CLIENT_HIDDEN,
    DEVICE_ROLE_CLIENT_MUTE, DEVICE_ROLE_REPEATER, DEVICE_ROLE_ROUTER, DEVICE_ROLE_ROUTER_CLIENT,
    DEVICE_ROLE_ROUTER_LATE, DEVICE_ROLE_SENSOR, DEVICE_ROLE_TAK, DEVICE_ROLE_TAK_TRACKER,
    DEVICE_ROLE_TRACKER,
};
use crate::sr_role::role_is_mute;

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

    /// A stock ROUTER that is not SR-active: it relays immediately and draws from the router
    /// window.
    ///
    /// Does this node publish its own neighbour list?
    ///
    /// The one distinction that decides whether a role may be compensated for. Every SignalRouting
    /// node broadcasts its direct neighbours — active and passive alike — so for those we read what
    /// they published and their role tells us nothing extra. A stock node broadcasts nothing, so
    /// its role is the only thing there is.
    ///
    /// `Unknown` counts as "publishes nothing", and that is not a gap in the reasoning: a stock
    /// ROUTER is never marked `Legacy`, because the only paths into that state are a mute role and
    /// our own node. Treating `Unknown` as a publisher would mean never recognising a stock router
    /// at all.
    ///
    /// Excluding `Passive` is defensive rather than corrective. A SignalRouting node carrying a
    /// router role is active by construction — the role is in the active class, and a node
    /// advertises its active flag from that — so `Passive` alongside a router role should not
    /// arise. It is excluded because the rule is "does it publish", and answering that by listing
    /// the one status that happens to occur would leave the next reader to rediscover why.
    pub fn publishes_topology(&self, node_id: u32) -> bool {
        matches!(
            self.status(node_id),
            CapabilityStatus::SrActive | CapabilityStatus::Passive
        )
    }

    /// A **stock** node, and a ROUTER.
    ///
    /// Role only ever compensates for what a node cannot tell us. A SignalRouting node publishes
    /// its neighbours whether it is active or passive, so its role adds nothing its own list does
    /// not already say, and reading a role instead of the list would substitute a guess for a
    /// measurement. A stock node publishes nothing, so its role is all there is, and compensating
    /// for it is the only way to place it at all. So the gate is "publishes nothing", which is
    /// SR-active and passive excluded — not merely SR-active. A passive SignalRouting node still
    /// broadcasts its direct neighbours, so its role must not be compensated for either.
    ///
    /// An unclassified node is left in: a stock ROUTER is only marked legacy once something else
    /// establishes it, and until then it is `Unknown`, so requiring `Legacy` here would quietly
    /// stop reserving for the very node the window exists for.
    ///
    /// ROUTER, REPEATER and ROUTER_CLIENT. ROUTER_CLIENT and REPEATER are deprecated as
    /// *configuration* choices — 2.3.15 and 2.7.11 — but not withdrawn from the wire, and stock
    /// still gives both the high-priority rebroadcast that relays even after hearing somebody
    /// else's copy. Nodes carrying them are deployed today. Dropping them here would stop us
    /// absorbing the coverage of a node that is going to transmit regardless, and we would add a
    /// duplicate beside it. Deprecation governs what an operator should configure next; it does
    /// not change what a node already on air does.
    ///
    /// A SignalRouting ROUTER is excluded, deliberately: it coordinates with us, so it is ranked
    /// like any peer rather than reserved for.
    pub fn is_immediate_relay_router(&self, node_id: u32) -> bool {
        if self.publishes_topology(node_id) {
            return false;
        }
        matches!(
            self.role(node_id),
            Some(DEVICE_ROLE_ROUTER | DEVICE_ROLE_REPEATER | DEVICE_ROLE_ROUTER_CLIENT)
        )
    }

    /// Will this node rebroadcast regardless and *not* stand down on hearing our copy?
    ///
    /// A separate question from whether it relays early, and from whether it is a relay router at
    /// all: stock refuses to cancel a duplicate for ROUTER and ROUTER_LATE, so relaying behind one
    /// of those adds a frame rather than replacing one. Added as its own name rather than by
    /// narrowing the relay-router test, which also answers candidate admission and the owner
    /// elections and must not move.
    ///
    /// CLIENT_BASE is deliberately absent. Stock also refuses to cancel there, but only for
    /// traffic involving a favourited node, and a favourite list is local configuration that never
    /// reaches the wire — no peer can evaluate it. The occasional duplicate alongside one is
    /// accepted.
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

/// Roles that broadcast SR topology. Every role does except LOST_AND_FOUND (and unknown
/// roles): CLIENT_MUTE, TRACKER, SENSOR, TAK, TAK_TRACKER and CLIENT_HIDDEN announce their
/// direct neighbours as SR-passive even though they never relay.
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
