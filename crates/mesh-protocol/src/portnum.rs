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
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QosTier {
    Low,
    Medium,
    High,
    Critical,
}

/// An opaque relay cannot distinguish chat from control traffic; a separate budget avoids punishing
/// private chat or admitting control floods at chat rates.
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

pub fn qos_tier(decoded_portnum: Option<u32>, channel: u8, primary_channel: u8) -> QosTier {
    let Some(portnum) = decoded_portnum.filter(|&p| p != num::UNKNOWN_APP) else {
        return QosTier::Low;
    };

    match portnum {
        num::TEXT_MESSAGE_APP | num::TEXT_MESSAGE_COMPRESSED_APP => {
            if channel == primary_channel {
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
        assert_eq!(rate_limit_bucket(None), RateLimitBucket::Unknown);
        assert_ne!(
            rate_limit_bucket(None),
            rate_limit_bucket(Some(num::TELEMETRY_APP))
        );
    }

    #[test]
    fn qos_tiers_golden() {
        assert_eq!(qos_tier(None, 0, 0), QosTier::Low);
        assert_eq!(qos_tier(Some(num::TELEMETRY_APP), 0, 0), QosTier::Low);
        assert_eq!(qos_tier(Some(num::NODEINFO_APP), 0, 0), QosTier::Low);

        assert_eq!(
            qos_tier(Some(num::TEXT_MESSAGE_APP), 0, 0),
            QosTier::Critical
        );
        assert_eq!(qos_tier(Some(num::TEXT_MESSAGE_APP), 1, 0), QosTier::Medium);
        assert_eq!(qos_tier(Some(num::ADMIN_APP), 0, 0), QosTier::Critical);
        assert_eq!(qos_tier(Some(num::ROUTING_APP), 0, 0), QosTier::High);
        assert_eq!(qos_tier(Some(num::SIGNAL_ROUTING_APP), 0, 0), QosTier::High);
        assert_eq!(qos_tier(Some(num::TRACEROUTE_APP), 0, 0), QosTier::High);
    }
}
