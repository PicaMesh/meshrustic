//! Last-hop unicasts: to a direct hears-us neighbour while stock peers listen, the frame carries
//! one hop and names the destination as next hop, whatever the link quality.

use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};
use mesh_routing::{
    coordinated_relay, hops_away, relay_header_with_next_hop_opts, EdgeSource, InboundPacket,
    ProcessResult, RelayPlan, Router, DEVICE_ROLE_ROUTER, LAST_HOP_BUDGET,
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
        graph
            .edges_mut()
            .update_edge(ME, ME, DEST, dest_etx, 0, EdgeSource::Reported, true, 0);
    }
}

fn relay_header_for(dest_etx: f32, hop_limit: u8, hop_start: u8) -> PacketHeader {
    let parsed = PacketHeader::from_fields(
        DEST, SOURCE, 42, 0x01, hop_limit, hop_start, false, false, 0, 0,
    )
    .parse();
    let mut router = Router::new(ME);
    setup_router(&mut router, dest_etx);
    assert!(router.graph_mut().caps_last_hop(DEST), "last hop applies");
    relay_header_with_next_hop_opts(&parsed, ME, 0, true).expect("relay header")
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
fn last_hop_has_one_hop_and_names_the_destination_on_any_link() {
    for etx in [2.0, 4.0] {
        let hdr = relay_header_for(etx, 3, 5);
        assert_eq!(hdr.hop_limit(), LAST_HOP_BUDGET);
        assert_eq!(hdr.hop_start(), 4);
        assert_eq!(hdr.parse().next_hop, (DEST & 0xFF) as u8);
    }
}

#[test]
fn hop_start_preserves_hops_away_after_relay() {
    for &(hop_start, hop_limit) in &[(3, 3), (5, 3), (7, 4)] {
        let hdr = relay_header_for(2.0, hop_limit, hop_start);
        let hops_away_rx = hops_away(hop_start, hop_limit, true).expect("well-formed");
        let hops_away_tx = hops_away(hdr.hop_start(), hdr.hop_limit(), true).expect("consistent");
        assert_eq!(hops_away_tx, hops_away_rx.saturating_add(1));
    }
}

#[test]
fn all_sr_neighbors_skips_limit() {
    let mut router = Router::new(ME);
    setup_router(&mut router, 2.0);
    router
        .graph_mut()
        .capability_mut()
        .track_topology(STOCK, true, 0);
    assert!(!router.graph_mut().caps_last_hop(DEST));
}

#[test]
fn router_relay_applies_limit_on_unicast() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(ME));
    setup_router(router, 2.0);

    let header = PacketHeader::from_fields(DEST, SOURCE, 99, 0x01, 3, 5, false, false, 0, 0);
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
    assert_eq!(tx_hdr.hop_limit(), LAST_HOP_BUDGET);
    assert_eq!(tx_hdr.hop_start(), 4);
    assert_eq!(tx_hdr.parse().next_hop, (DEST & 0xFF) as u8);
}
