use mesh_protocol::{num, qos_tier, rate_limit_bucket, QosTier, RateLimitBucket};
use mesh_routing::ChannelQoS;

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

#[test]
fn qos_tier_golden_table() {
    let golden_ch0: &[(Option<u32>, QosTier)] = &[
        (None, QosTier::Low),
        (Some(num::UNKNOWN_APP), QosTier::Low),
        (Some(num::TEXT_MESSAGE_APP), QosTier::Critical),
        (Some(num::TEXT_MESSAGE_COMPRESSED_APP), QosTier::Critical),
        (Some(num::POSITION_APP), QosTier::Low),
        (Some(num::NODEINFO_APP), QosTier::Low),
        (Some(num::ROUTING_APP), QosTier::High),
        (Some(num::ADMIN_APP), QosTier::Critical),
        (Some(num::TELEMETRY_APP), QosTier::Low),
        (Some(num::TRACEROUTE_APP), QosTier::High),
        (Some(num::SIGNAL_ROUTING_APP), QosTier::High),
    ];
    for &(port, expected) in golden_ch0 {
        assert_eq!(
            qos_tier(port, 0),
            expected,
            "channel 0 tier mismatch for port {port:?}"
        );
    }

    let golden_ch1: &[(Option<u32>, QosTier)] = &[
        (None, QosTier::Low),
        (Some(num::UNKNOWN_APP), QosTier::Low),
        (Some(num::TEXT_MESSAGE_APP), QosTier::Medium),
        (Some(num::TEXT_MESSAGE_COMPRESSED_APP), QosTier::Medium),
        (Some(num::POSITION_APP), QosTier::Low),
        (Some(num::NODEINFO_APP), QosTier::Low),
        (Some(num::ROUTING_APP), QosTier::High),
        (Some(num::ADMIN_APP), QosTier::Critical),
        (Some(num::TELEMETRY_APP), QosTier::Low),
        (Some(num::TRACEROUTE_APP), QosTier::High),
        (Some(num::SIGNAL_ROUTING_APP), QosTier::High),
    ];
    for &(port, expected) in golden_ch1 {
        assert_eq!(
            qos_tier(port, 1),
            expected,
            "channel 1 tier mismatch for port {port:?}"
        );
    }
}

#[test]
fn qos_threshold_boundaries() {
    let qos = ChannelQoS::new();

    assert!(qos.can_relay(None, 0, 24.9));
    assert!(!qos.can_relay(None, 0, 25.0));

    assert!(qos.can_relay(Some(num::TEXT_MESSAGE_APP), 1, 29.9));
    assert!(!qos.can_relay(Some(num::TEXT_MESSAGE_APP), 1, 30.0));

    assert!(qos.can_relay(Some(num::ROUTING_APP), 0, 37.9));
    assert!(!qos.can_relay(Some(num::ROUTING_APP), 0, 38.0));

    assert!(qos.can_relay(Some(num::TEXT_MESSAGE_APP), 0, 99.0));
    assert!(qos.can_relay(Some(num::ADMIN_APP), 0, 99.0));
}
