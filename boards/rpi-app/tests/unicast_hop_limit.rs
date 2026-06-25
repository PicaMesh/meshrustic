//! Unicast hop-limit tightening for direct hears-us neighbors when stock peers exist.

use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};
use mesh_routing::{
    coordinated_relay, relay_header_with_next_hop_opts, EdgeSource, InboundPacket, ProcessResult,
    RelayPlan, Router, DEVICE_ROLE_ROUTER,
};
use static_cell::StaticCell;

const ME: u32 = 0xCC00_00CC;
const DEST: u32 = 0xDD00_00DD;
const STOCK: u32 = 0xEE00_00EE;
const SOURCE: u32 = 0xBB00_00BB;

fn setup_router(router: &mut Router, dest_etx: f32) {
    router.set_device_role(DEVICE_ROLE_ROUTER);
    let graph = router.graph_mut();
    graph.observe_direct_neighbor(DEST, -70, 8, 0, 0);
    graph.confirm_direct_neighbor_hears_us(DEST);
    graph.observe_direct_neighbor(STOCK, -72, 7, 0, 0);
    if dest_etx >= 3.0 {
        graph.edges_mut().update_edge(
            ME,
            ME,
            DEST,
            dest_etx,
            0,
            EdgeSource::Reported,
            true,
            0,
        );
    }
}

fn relay_header_for(dest_etx: f32, hop_limit: u8, hop_start: u8) -> PacketHeader {
    let parsed = PacketHeader::from_fields(
        DEST, SOURCE, 42, 0x01, hop_limit, hop_start, false, false, 0, 0,
    )
    .parse();
    let mut router = Router::new(ME);
    setup_router(&mut router, dest_etx);
    let limited = router
        .graph_mut()
        .unicast_hop_limit_for_direct_neighbor(DEST)
        .expect("hop limit applies");
    relay_header_with_next_hop_opts(&parsed, ME, 0, Some(limited)).expect("relay header")
}

fn ready_relay(router: &mut Router, result: &ProcessResult, now_ms: u32) -> RelayPlan {
    let plan = router.evaluate_tx_plan(result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, now_ms);
    if let Some(relay) = plan.relay {
        return relay;
    }
    router
        .relay_tx_after(result.parsed.from, result.parsed.id, result.radio_id)
        .and_then(|tx_after| router.poll_ready_relay(tx_after))
        .expect("relay planned or pending")
}

#[test]
fn good_link_limits_to_zero_hops() {
    let hdr = relay_header_for(2.0, 5, 3);
    assert_eq!(hdr.hop_limit(), 0);
    assert_eq!(hdr.hop_start(), 3);
}

#[test]
fn marginal_link_allows_one_hop() {
    let hdr = relay_header_for(4.0, 5, 3);
    assert_eq!(hdr.hop_limit(), 1);
    assert_eq!(hdr.hop_start(), 4);
}

#[test]
fn hop_start_preserves_hops_away_after_relay() {
    let hdr = relay_header_for(2.0, 5, 3);
    let hops_away_rx = 5u8.saturating_sub(3);
    let hops_away_tx = hdr.hop_start().saturating_sub(hdr.hop_limit());
    assert_eq!(hops_away_rx, 2);
    assert_eq!(hops_away_tx, hops_away_rx.saturating_add(1));
}

#[test]
fn all_sr_neighbors_skips_limit() {
    let mut router = Router::new(ME);
    setup_router(&mut router, 2.0);
    router.graph_mut().capability_mut().track_topology(STOCK, true, 0);
    assert_eq!(
        router
            .graph_mut()
            .unicast_hop_limit_for_direct_neighbor(DEST),
        None
    );
}

#[test]
fn router_relay_applies_limit_on_unicast() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(ME));
    setup_router(router, 2.0);

    let header = PacketHeader::from_fields(DEST, SOURCE, 99, 0x01, 5, 3, false, false, 0, 0);
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
            0,
        )
        .expect("inbound");
    let relay = ready_relay(router, &result, 0);
    let tx_hdr = PacketHeader::decode(&relay.bytes[..PACKET_HEADER_LEN]).expect("header");
    assert_eq!(tx_hdr.hop_limit(), 0);
    assert_eq!(tx_hdr.hop_start(), 3);
}
