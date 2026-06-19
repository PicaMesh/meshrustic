//! Power-policy helpers — host checks for Phase 8 idle detection.

use mesh_protocol::PacketHeader;
use mesh_routing::{InboundPacket, Router};
use static_cell::StaticCell;

#[test]
fn router_pending_work_false_when_idle() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(0x1234_5678));
    assert!(!router.has_pending_work());
}

#[test]
fn router_pending_work_true_after_relay_commit() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(0x677a_1caf));

    let header =
        PacketHeader::from_fields(0xFFFF_FFFF, 0xAABB_CCDD, 7, 0, 3, 3, false, false, 0, 0);
    let mut wire = heapless::Vec::<u8, 64>::new();
    let mut hdr = [0u8; mesh_protocol::PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    wire.extend_from_slice(&hdr).unwrap();
    wire.extend_from_slice(&[1, 2, 3]).unwrap();

    let result = router
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -80,
                snr: 10,
                bytes: &wire,
            },
            0,
        )
        .expect("accepted");
    let _plan = router.evaluate_tx_plan(
        &result,
        0.0,
        mesh_routing::coordinated_relay::DEFAULT_SLOT_MS,
        0,
    );
    assert!(router.has_pending_work());
}
