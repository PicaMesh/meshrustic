use mesh_protocol::{num, qos_tier, rate_limit_bucket, QosTier, RateLimitBucket};

#[test]
fn telemetry_uses_other_bucket_and_low_qos() {
    assert_eq!(
        rate_limit_bucket(Some(num::TELEMETRY_APP)),
        RateLimitBucket::Other
    );
    assert_eq!(qos_tier(Some(num::TELEMETRY_APP), 0), QosTier::Low);
}

#[test]
fn text_primary_channel_critical_text_bucket() {
    assert_eq!(
        rate_limit_bucket(Some(num::TEXT_MESSAGE_APP)),
        RateLimitBucket::Text
    );
    assert_eq!(qos_tier(Some(num::TEXT_MESSAGE_APP), 0), QosTier::Critical);
}

#[test]
fn routing_ports_high_tier_and_routing_bucket() {
    for port in [
        num::ROUTING_APP,
        num::SIGNAL_ROUTING_APP,
        num::TRACEROUTE_APP,
    ] {
        assert_eq!(rate_limit_bucket(Some(port)), RateLimitBucket::Routing);
        assert_eq!(qos_tier(Some(port), 0), QosTier::High);
    }
}

#[test]
fn undecoded_uses_other_and_low() {
    assert_eq!(rate_limit_bucket(None), RateLimitBucket::Other);
    assert_eq!(qos_tier(None, 0), QosTier::Low);
}
