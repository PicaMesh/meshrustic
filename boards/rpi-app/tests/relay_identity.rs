//! Heard-from / relay-byte resolution for coordinated flooding.

use mesh_routing::{placeholder_node_id, Router, PLACEHOLDER_NODE_PREFIX};

#[test]
fn relay_node_zero_resolves_to_source() {
    let mut router = Router::new(0xAABB_CCDD);
    assert_eq!(
        router.resolve_heard_from_node(0, 0x1234_5678, -70, 10, 1_000),
        0x1234_5678
    );
}

#[test]
fn relay_byte_resolves_to_known_neighbor_via_edge() {
    let mut router = Router::new(0xAA00_00AA);
    let relay = 0xCDu8;
    let neighbor = 0x1000_00CD;
    router
        .graph_mut()
        .observe_direct_neighbor(neighbor, -70, 8, 0, 0);
    assert_eq!(
        router.resolve_heard_from_node(relay, 0xB000_0002, -72, 9, 500),
        neighbor
    );
}

#[test]
fn relay_byte_unknown_yields_placeholder() {
    let mut router = Router::new(0xCC00_00CC);
    let relay = 0x42u8;
    let resolved = router.resolve_heard_from_node(relay, 0xDD00_00DD, -70, 8, 0);
    assert_eq!(resolved, placeholder_node_id(relay));
    assert_eq!(resolved & 0xFF00_0000, PLACEHOLDER_NODE_PREFIX);
}

#[test]
fn relay_identity_cache_remembers_and_expires() {
    let mut router = Router::new(0xEE00_00EE);
    let relay = 0x77u8;
    let neighbor = 0x2000_0077;
    router
        .graph_mut()
        .observe_direct_neighbor(neighbor, -70, 8, 0, 0);
    assert_eq!(
        router.resolve_heard_from_node(relay, 0xBEEF, -70, 8, 1_000),
        neighbor
    );

    let mut fresh = Router::new(0xEE00_00EE);
    fresh.remember_relay_identity(neighbor, relay, 1_000);
    assert_eq!(
        fresh.resolve_heard_from_node(relay, 0xBEEF, -70, 8, 2_000),
        neighbor
    );

    fresh.run_maintenance(
        1_000 + mesh_routing::RELAY_ID_CACHE_TTL_MS + 1,
        mesh_routing::coordinated_relay::DEFAULT_SLOT_MS,
    );
    assert_eq!(
        fresh.resolve_heard_from_node(
            relay,
            0xBEEF,
            -70,
            8,
            1_000 + mesh_routing::RELAY_ID_CACHE_TTL_MS + 2,
        ),
        placeholder_node_id(relay)
    );
}
