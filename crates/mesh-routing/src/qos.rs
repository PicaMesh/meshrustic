//! Channel congestion relay gating (stateless, 0 bytes).

use mesh_protocol::{qos_tier, QosTier};

/// Stateless relay gate based on channel utilization tier thresholds.
pub struct ChannelQoS;

impl Default for ChannelQoS {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelQoS {
    pub const fn new() -> Self {
        Self
    }

    /// Returns `true` when relay is allowed at the current channel utilization.
    pub fn can_relay(&self, decoded_portnum: Option<u32>, channel: u8, chutil_pct: f32) -> bool {
        let tier = qos_tier(decoded_portnum, channel);
        let threshold = match tier {
            QosTier::Low => 25.0,
            QosTier::Medium => 30.0,
            QosTier::High => 38.0,
            QosTier::Critical => return true,
        };
        chutil_pct < threshold
    }

    /// Human-readable threshold for logging.
    pub fn suppress_threshold_pct(decoded_portnum: Option<u32>, channel: u8) -> f32 {
        match qos_tier(decoded_portnum, channel) {
            QosTier::Low => 25.0,
            QosTier::Medium => 30.0,
            QosTier::High => 38.0,
            QosTier::Critical => f32::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_protocol::num;

    #[test]
    fn critical_never_suppressed() {
        let qos = ChannelQoS::new();
        assert!(qos.can_relay(Some(num::TEXT_MESSAGE_APP), 0, 99.0));
    }

    #[test]
    fn low_tier_blocked_at_25_percent() {
        let qos = ChannelQoS::new();
        assert!(qos.can_relay(None, 0, 24.0));
        assert!(!qos.can_relay(None, 0, 25.0));
    }

    #[test]
    fn high_tier_allows_up_to_38_percent() {
        let qos = ChannelQoS::new();
        assert!(qos.can_relay(Some(num::ROUTING_APP), 0, 37.0));
        assert!(!qos.can_relay(Some(num::ROUTING_APP), 0, 38.0));
    }
}
