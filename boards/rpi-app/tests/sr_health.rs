//! Topology-health gating for SR relay suppression.

use mesh_protocol::{PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};
use mesh_routing::{
    coordinated_relay, EdgeSource, InboundPacket, Router, DEVICE_ROLE_REPEATER, DEVICE_ROLE_ROUTER,
};
use static_cell::StaticCell;

const ME: u32 = 0xCC00_00CC;
const NEIGHBOR: u32 = 0xBB00_00BB;
const STOCK: u32 = 0xDD00_00DD;

fn setup_stock_relay_topology(router: &mut Router, healthy: bool) {
    router.set_device_role(DEVICE_ROLE_ROUTER);
    let graph = router.graph_mut();
    graph.observe_direct_neighbor(NEIGHBOR, -70, 8, 0, 0);
    graph.observe_direct_neighbor(STOCK, -72, 7, 0, 0);
    graph.track_node_role(STOCK, DEVICE_ROLE_REPEATER, 0);
    graph.capability_mut().track_topology(NEIGHBOR, false, 0);
    if !healthy {
        graph.capability_mut().track_topology(STOCK, false, 0);
    }
    graph.edges_mut().update_edge(
        ME,
        STOCK,
        NEIGHBOR,
        2.0,
        0,
        EdgeSource::Reported,
        true,
        0,
    );
}

fn evaluate_broadcast(router: &mut Router, from: u32, now_ms: u32) -> mesh_routing::TxPlan {
    let header =
        PacketHeader::from_fields(NODENUM_BROADCAST, from, 99, 0x77, 3, 3, false, false, 0, 0);
    let mut hdr = [0u8; PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    let wire = [hdr.as_slice(), &[0x01u8]].concat();
    let result = router
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 8,
                bytes: &wire,
            },
            now_ms,
        )
        .expect("inbound");
    router.evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, now_ms)
}

#[test]
fn healthy_topology_allows_suppression() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(ME));
    setup_stock_relay_topology(router, true);
    assert!(router.graph_mut().topology_healthy_for_broadcast());
    assert_eq!(
        router
            .graph_mut()
            .find_best_relay_candidate(99, NEIGHBOR, 0),
        STOCK
    );

    let plan = evaluate_broadcast(router, NEIGHBOR, 0);
    assert!(plan.relay.is_none());
    assert!(router.relay_tx_after(NEIGHBOR, 99, 0).is_none());
}

#[test]
fn unhealthy_topology_defaults_to_relay() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(ME));
    setup_stock_relay_topology(router, false);
    assert!(!router.graph_mut().topology_healthy_for_broadcast());
    assert_eq!(
        router
            .graph_mut()
            .find_best_relay_candidate(99, NEIGHBOR, 0),
        STOCK
    );

    let plan = evaluate_broadcast(router, NEIGHBOR, 0);
    assert!(plan.relay.is_none());
    assert!(router.relay_tx_after(NEIGHBOR, 99, 0).is_some());
}
