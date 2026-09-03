//! Mesh port numbers for rate-limit and QoS classification.
pub mod num {
    pub const UNKNOWN_APP: u32 = 0;
    pub const TEXT_MESSAGE_APP: u32 = 1;
    pub const POSITION_APP: u32 = 3;
    pub const NODEINFO_APP: u32 = 4;
    pub const ROUTING_APP: u32 = 5;
    pub const ADMIN_APP: u32 = 6;
    pub const TEXT_MESSAGE_COMPRESSED_APP: u32 = 7;
    pub const TELEMETRY_APP: u32 = 67;
    pub const TRACEROUTE_APP: u32 = 70;
    pub const SIGNAL_ROUTING_APP: u32 = 88;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitBucket {
    Text,
    Routing,
    Other,
    /// Undecodable: a channel we hold no key for, or a PKI packet for someone else.
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QosTier {
    Low,
    Medium,
    High,
    Critical,
}

/// Rate-limit bucket for inbound classification.
///
/// `None` = decode failed / no portnum (a channel we hold no key for, or a PKI packet for
/// another node) → **UNKNOWN** bucket. A relay without the key cannot tell chat from
/// telemetry; with the OTHER threshold a private group chatting normally flowed through
/// key-holding relays and died at the first relay without the key, while the TEXT
/// threshold would let encrypted admin and DM traffic for others run at chat rates. The
/// UNKNOWN bucket sits between the two; key holders judge the same packets by their port.
pub fn rate_limit_bucket(decoded_portnum: Option<u32>) -> RateLimitBucket {
    let Some(portnum) = decoded_portnum else {
        return RateLimitBucket::Unknown;
    };
    match portnum {
        num::TEXT_MESSAGE_APP | num::TEXT_MESSAGE_COMPRESSED_APP => RateLimitBucket::Text,
        num::ROUTING_APP | num::SIGNAL_ROUTING_APP | num::TRACEROUTE_APP => {
            RateLimitBucket::Routing
        }
        _ => RateLimitBucket::Other,
    }
}

/// QoS relay tier for channel-congestion gating.
///
/// `None` or `Some(0)` → **LOW** (undecoded / unset portnum).
/// `channel` is the packet channel hash/index from the LoRa header (`MeshPacket.channel`).
pub fn qos_tier(decoded_portnum: Option<u32>, channel: u8) -> QosTier {
    let Some(portnum) = decoded_portnum.filter(|&p| p != num::UNKNOWN_APP) else {
        return QosTier::Low;
    };

    match portnum {
        num::TEXT_MESSAGE_APP | num::TEXT_MESSAGE_COMPRESSED_APP => {
            if channel == 0 {
                QosTier::Critical
            } else {
                QosTier::Medium
            }
        }
        num::ADMIN_APP => QosTier::Critical,
        num::ROUTING_APP | num::SIGNAL_ROUTING_APP | num::TRACEROUTE_APP => QosTier::High,
        _ => QosTier::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_buckets_golden() {
        assert_eq!(
            rate_limit_bucket(Some(num::TEXT_MESSAGE_APP)),
            RateLimitBucket::Text
        );
        assert_eq!(
            rate_limit_bucket(Some(num::TEXT_MESSAGE_COMPRESSED_APP)),
            RateLimitBucket::Text
        );
        assert_eq!(
            rate_limit_bucket(Some(num::ROUTING_APP)),
            RateLimitBucket::Routing
        );
        assert_eq!(
            rate_limit_bucket(Some(num::SIGNAL_ROUTING_APP)),
            RateLimitBucket::Routing
        );
        assert_eq!(
            rate_limit_bucket(Some(num::TRACEROUTE_APP)),
            RateLimitBucket::Routing
        );
        assert_eq!(
            rate_limit_bucket(Some(num::TELEMETRY_APP)),
            RateLimitBucket::Other
        );
        assert_eq!(rate_limit_bucket(None), RateLimitBucket::Other);
    }

    #[test]
    fn qos_tiers_golden() {
        assert_eq!(qos_tier(None, 0), QosTier::Low);
        assert_eq!(qos_tier(Some(num::TELEMETRY_APP), 0), QosTier::Low);
        assert_eq!(qos_tier(Some(num::NODEINFO_APP), 0), QosTier::Low);

        assert_eq!(qos_tier(Some(num::TEXT_MESSAGE_APP), 0), QosTier::Critical);
        assert_eq!(qos_tier(Some(num::TEXT_MESSAGE_APP), 1), QosTier::Medium);
        assert_eq!(qos_tier(Some(num::ADMIN_APP), 0), QosTier::Critical);
        assert_eq!(qos_tier(Some(num::ROUTING_APP), 0), QosTier::High);
        assert_eq!(qos_tier(Some(num::SIGNAL_ROUTING_APP), 0), QosTier::High);
        assert_eq!(qos_tier(Some(num::TRACEROUTE_APP), 0), QosTier::High);
    }
}
