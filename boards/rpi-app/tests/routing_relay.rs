//! Router flooding relay integration tests (host).

use mesh_protocol::PacketHeader;
use mesh_routing::{coordinated_relay, InboundPacket, Router, POOL_SIZE};
use static_cell::StaticCell;

fn wire_bytes(header: PacketHeader, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(mesh_protocol::PACKET_HEADER_LEN + payload.len());
    let mut hdr = [0u8; mesh_protocol::PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    out
}

fn ready_relay(router: &mut Router, result: &mesh_routing::ProcessResult, now_ms: u32) -> mesh_routing::RelayPlan {
    let plan = router.evaluate_tx_plan(
        result,
        0.0,
        coordinated_relay::DEFAULT_SLOT_MS,
        now_ms,
    );
    if let Some(relay) = plan.relay {
        return relay;
    }
    router
        .relay_tx_after(result.parsed.from, result.parsed.id, result.radio_id)
        .and_then(|tx_after| router.poll_ready_relay(tx_after))
        .expect("relay planned or pending")
}

#[test]
fn router_relays_broadcast_with_unchanged_ciphertext() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(0xAABB_CCDD));

    let header =
        PacketHeader::from_fields(0xFFFF_FFFF, 0x1234_5678, 7, 0, 3, 3, false, false, 0, 0);
    let payload = [0xDE, 0xAD, 0xBE, 0xEF];
    let wire = wire_bytes(header, &payload);

    let inbound = InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 10,
        bytes: &wire,
    };

    let result = router.process_inbound(&inbound, 0).expect("accepted");
    let relay = ready_relay(router, &result, 0);
    let off = mesh_protocol::PACKET_HEADER_LEN;
    assert_eq!(&relay.bytes[off..off + payload.len()], payload);
    assert_eq!(router.free_pool_slots(), POOL_SIZE);
}

#[test]
fn router_skips_own_packets() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our_node = 0xCAFE_BABE;
    let router = ROUTER.init(Router::new(our_node));

    let header = PacketHeader::from_fields(0xFFFF_FFFF, our_node, 1, 0, 3, 3, false, false, 0, 0);
    let wire = wire_bytes(header, &[0x01, 0x02]);

    let inbound = InboundPacket {
        radio_id: 0,
        rssi: 0,
        snr: 0,
        bytes: &wire,
    };

    let result = router.process_inbound(&inbound, 0).expect("accepted");
    assert!(router
        .evaluate_tx_plan(&result, 0.0, coordinated_relay::DEFAULT_SLOT_MS, 0)
        .relay
        .is_none());
    assert!(router.poll_ready_relay(10_000).is_none());
}
