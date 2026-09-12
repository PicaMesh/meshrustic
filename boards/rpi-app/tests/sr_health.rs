//! Topology-health gating for SR relay suppression.

use mesh_protocol::{PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};
use mesh_routing::{
    coordinated_relay, EdgeSource, InboundPacket, Router, DEVICE_ROLE_REPEATER, DEVICE_ROLE_ROUTER,
};
use static_cell::StaticCell;

const ME: u32 = 0xCC00_00CC;
const NEIGHBOR: u32 = 0xBB00_00BB;
const STOCK: u32 = 0xDD00_00DD;

/// Build a two-neighbour graph around us, healthy or not.
///
/// Note what "unhealthy" has to mean here, because it is not free to choose. `topology_healthy_for_
/// broadcast` counts a direct neighbour as capable when its status is SR-active **or Unknown**, and
/// a genuine stock node is exactly `Unknown` — nothing ever marks a stock router legacy. So a real
/// stock relay router always makes the topology healthy, and the unhealthy case cannot contain one:
/// it is reached by making every neighbour a publisher, which is what the `!healthy` branch does to
/// `STOCK`. That node is then SR-passive rather than stock, despite its name, and is treated as a
/// publisher for the rest of the test. See `a_stock_router_neighbour_always_makes_topology_healthy`.
fn setup_stock_relay_topology(router: &mut Router, healthy: bool) {
    router.set_device_role(DEVICE_ROLE_ROUTER);
    let graph = router.graph_mut();
    graph.observe_direct_neighbor(NEIGHBOR, -70, 8, 0, 0);
    graph.observe_direct_neighbor(STOCK, -72, 7, 0, 0);
    graph.confirm_direct_neighbor_hears_us(NEIGHBOR);
    graph.confirm_direct_neighbor_hears_us(STOCK);
    graph.track_node_role(STOCK, DEVICE_ROLE_REPEATER, 0);
    graph.capability_mut().track_topology(NEIGHBOR, false, 0);
    if !healthy {
        graph.capability_mut().track_topology(STOCK, false, 0);
    }
    graph
        .edges_mut()
        .update_edge(ME, STOCK, NEIGHBOR, 2.0, 0, EdgeSource::Reported, true, 0);
    graph.edges_mut().set_edge_hears_us(STOCK, NEIGHBOR, true);
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
fn healthy_topology_defers_when_stock_router_covers() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(ME));
    setup_stock_relay_topology(router, true);
    assert!(router.graph_mut().topology_healthy_for_broadcast());

    let half = coordinated_relay::half_airtime_ms(coordinated_relay::DEFAULT_SLOT_MS);
    let relay_plan = router.graph_mut().plan_broadcast_relay(
        99,
        NEIGHBOR,
        NEIGHBOR,
        mesh_protocol::NODENUM_BROADCAST,
        0,
        half,
        false,
    );
    assert!(
        !relay_plan.should_relay,
        "stock REPEATER present with no unique coverage left for us"
    );
    assert!(relay_plan.candidate_count >= 2);

    let plan = evaluate_broadcast(router, NEIGHBOR, 0);
    assert!(plan.relay.is_none());
    assert!(
        router.relay_tx_after(NEIGHBOR, 99, 0).is_none(),
        "BetterNeighbor skip must not commit a redundant relay"
    );
    assert!(
        router.has_pending_work(),
        "a slot was given to the stock repeater, so its silence is insured"
    );
    let slot_ms = coordinated_relay::slot_time_for_preset(mesh_radio::MODEM_DEFAULT_PRESET);
    let fire_ms = coordinated_relay::tx_delay_ms_worst(slot_ms)
        .saturating_add(coordinated_relay::DEFAULT_SLOT_MS);
    assert!(
        router.poll_t1_retransmit(fire_ms - 1).is_none(),
        "T1 must not fire inside the defer window"
    );
    // Insurers take rungs one half-airtime apart; ours is somewhere in that ladder. Only a
    // heard copy stands it down: the graph said the repeater covers everything, and whether
    // its frame actually arrived is not something the graph can answer.
    let ladder = coordinated_relay::half_airtime_ms(coordinated_relay::DEFAULT_SLOT_MS)
        * mesh_routing::MAX_EDGES_PER_NODE as u32;
    assert!(router.poll_t1_retransmit(fire_ms + ladder).is_some());
}

#[test]
fn unhealthy_topology_defaults_to_relay() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(ME));
    setup_stock_relay_topology(router, false);
    assert!(!router.graph_mut().topology_healthy_for_broadcast());
    // Every neighbour here publishes, which is the only way to be unhealthy — so there is no stock
    // node left to defer to and we carry the frame ourselves. That is what "defaults to relay"
    // means. A real stock router could not appear in this state; it would make the graph healthy.
    assert_eq!(
        router
            .graph_mut()
            .find_best_relay_candidate(99, NEIGHBOR, 0),
        ME
    );

    let plan = evaluate_broadcast(router, NEIGHBOR, 0);
    assert!(plan.relay.is_none());
    assert!(router.relay_tx_after(NEIGHBOR, 99, 0).is_some());
}

/// A real stock relay router always makes the topology healthy, so "unhealthy" and "a stock router
/// is present" cannot hold at once.
///
/// Worth pinning because the opposite is easy to assume: health counts a neighbour whose capability
/// is `Unknown`, and `Unknown` is precisely where a stock node sits — `track_role` only marks a mute
/// role legacy, and `track_topology` is only reached from a SignalRouting broadcast, which stock
/// never sends. Anyone trying to construct "unhealthy topology behind a stock router" is chasing a
/// state the model does not have.
#[test]
fn a_stock_router_neighbour_always_makes_topology_healthy() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(ME));
    setup_stock_relay_topology(router, true);
    let graph = router.graph_mut();
    assert_eq!(
        graph.capability().status(STOCK),
        mesh_routing::CapabilityStatus::Unknown,
        "a stock node is never marked legacy or passive"
    );
    assert!(graph.capability().is_immediate_relay_router(STOCK));
    assert!(graph.topology_healthy_for_broadcast());
}
