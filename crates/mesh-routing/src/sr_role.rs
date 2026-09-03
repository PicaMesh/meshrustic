//! MT wire `DeviceConfig.Role` → MeshRustic SR behavior (active / passive / mute).

use crate::nodeinfo::{
    DEVICE_ROLE_CLIENT, DEVICE_ROLE_CLIENT_BASE, DEVICE_ROLE_CLIENT_HIDDEN,
    DEVICE_ROLE_CLIENT_MUTE, DEVICE_ROLE_LOST_AND_FOUND, DEVICE_ROLE_REPEATER, DEVICE_ROLE_ROUTER,
    DEVICE_ROLE_ROUTER_CLIENT, DEVICE_ROLE_ROUTER_LATE, DEVICE_ROLE_TRACKER,
};

/// Mute: no packet rebroadcast; may still send topology to assist the mesh.
pub fn role_is_mute(role: u32) -> bool {
    matches!(
        role,
        DEVICE_ROLE_CLIENT_MUTE
            | DEVICE_ROLE_TRACKER
            | DEVICE_ROLE_CLIENT_HIDDEN
            | DEVICE_ROLE_LOST_AND_FOUND
    )
}

/// Active: full graph maintenance, coordinated relay, relayed-packet topology inference.
pub fn role_is_active_routing(role: u32) -> bool {
    matches!(
        role,
        DEVICE_ROLE_CLIENT
            | DEVICE_ROLE_ROUTER
            | DEVICE_ROLE_ROUTER_CLIENT
            | DEVICE_ROLE_REPEATER
            | DEVICE_ROLE_ROUTER_LATE
            | DEVICE_ROLE_CLIENT_BASE
    )
}

/// Passive: limited graph (direct neighbors); not mute and not active SR class.
pub fn role_is_passive(role: u32) -> bool {
    !role_is_mute(role) && !role_is_active_routing(role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_and_client_hidden_are_mute() {
        assert!(role_is_mute(DEVICE_ROLE_TRACKER));
        assert!(role_is_mute(DEVICE_ROLE_CLIENT_HIDDEN));
        assert!(!role_is_active_routing(DEVICE_ROLE_TRACKER));
        assert!(!role_is_active_routing(DEVICE_ROLE_CLIENT_HIDDEN));
    }

    #[test]
    fn sensor_is_passive_not_mute() {
        use crate::nodeinfo::DEVICE_ROLE_SENSOR;
        assert!(role_is_passive(DEVICE_ROLE_SENSOR));
        assert!(!role_is_mute(DEVICE_ROLE_SENSOR));
    }
}
