//! Rate limiter ordering on the RX path — dedup and neighbor observation run first;
//! port handlers and reliable-RX side effects are skipped on drop.

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::{num, PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};
use mesh_radio::MODEM_SHORT_SLOW;
use mesh_routing::{
    build_app_wire_frame, build_topology_wire_frame, write_packed_header, DataEncodeOpts,
    InboundPacket, NodeInfoIdentity, Router, PACKED_NEIGHBOR_HEADER_SIZE, TELEMETRY_APP,
};
use static_cell::StaticCell;

const TEST_PUBKEY: [u8; 32] = [0xCD; 32];

fn inbound(bytes: &[u8]) -> InboundPacket<'_> {
    InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 10,
        bytes,
    }
}

fn flood_other_bucket(router: &mut Router, from: u32, channel: u8, key: &CryptoKey, t: u32) {
    for i in 0..5u32 {
        let (len, frame) = build_app_wire_frame(
            NODENUM_BROADCAST,
            from,
            0x5000 + i,
            channel,
            3,
            3,
            false,
            key,
            TELEMETRY_APP,
            &[],
            DataEncodeOpts::default(),
        )
        .expect("telemetry wire");
        router
            .process_inbound(&inbound(&frame[..len as usize]), t)
            .expect("flood rx");
    }
}

fn establish_direct_peer(router: &mut Router, from: u32, channel: u8, key: &CryptoKey, t: u32) {
    let (len, frame) = build_app_wire_frame(
        NODENUM_BROADCAST,
        from,
        0x4000,
        channel,
        3,
        3,
        false,
        key,
        TELEMETRY_APP,
        &[],
        DataEncodeOpts::default(),
    )
    .expect("direct peer wire");
    router
        .process_inbound(&inbound(&frame[..len as usize]), t)
        .expect("direct peer rx");
}

fn flood_routing_bucket(router: &mut Router, from: u32, channel: u8, key: &CryptoKey, t: u32) {
    let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE];
    write_packed_header(&mut packed, 1, true);
    for i in 0..11u32 {
        let (len, frame) = build_topology_wire_frame(from, 0x6000 + i, channel, 3, key, &packed)
            .expect("routing flood wire");
        router
            .process_inbound(&inbound(&frame[..len as usize]), t)
            .expect("flood rx");
    }
}

fn build_topology_wire(
    from: u32,
    packet_id: u32,
    channel: u8,
    key: &CryptoKey,
    listed_neighbor: u32,
) -> heapless::Vec<u8, 256> {
    let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE + 8];
    write_packed_header(&mut packed, 1, true);
    packed[5..9].copy_from_slice(&listed_neighbor.to_le_bytes());
    packed[9] = 0xB6;
    packed[10] = 8;
    packed[11] = 0x02; // hears_us
    let packed_len = PACKED_NEIGHBOR_HEADER_SIZE + 8;
    let (len, frame) = build_topology_wire_frame(from, packet_id, channel, 3, key, &packed[..packed_len])
        .expect("topology wire");
    let mut out = heapless::Vec::new();
    out.extend_from_slice(&frame[..len as usize]).unwrap();
    out
}

#[test]
fn rate_limited_packet_does_not_merge_topology() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our_node = 0xAABB_CCDD;
    let attacker = 0x1111_2222;
    let listed = 0x3333_4444;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let router = ROUTER.init({
        let mut r = Router::with_modem_preset(our_node, "", MODEM_SHORT_SLOW, true, key, 3);
        r.set_device_role(mesh_routing::DEVICE_ROLE_ROUTER);
        r
    });
    let channel = router.channel_hash();

    establish_direct_peer(router, attacker, channel, &key, 0);
    flood_routing_bucket(router, attacker, channel, &key, 0);

    let wire = build_topology_wire(attacker, 0x9001, channel, &key, listed);
    let result = router
        .process_inbound(&inbound(&wire), 1_000)
        .expect("topology rx");
    assert!(result.rate_limited);
    assert_eq!(router.graph_mut().get_downstream_relay(listed), None);

    let mut control = Router::with_modem_preset(our_node, "", MODEM_SHORT_SLOW, true, key, 3);
    control.set_device_role(mesh_routing::DEVICE_ROLE_ROUTER);
    let control_channel = control.channel_hash();
    establish_direct_peer(&mut control, attacker, control_channel, &key, 0);
    let control_wire = build_topology_wire(attacker, 0x9002, control_channel, &key, listed);
    let control_result = control
        .process_inbound(&inbound(&control_wire), 1_000)
        .expect("unlimited topology rx");
    assert!(!control_result.rate_limited);
    assert_eq!(
        control.graph_mut().get_downstream_relay(listed),
        Some(attacker)
    );
}

#[test]
fn rate_limited_nodeinfo_request_gets_no_reply() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our_node = 0x1111_1111;
    let requester = 0x2222_2222;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let router = ROUTER.init({
        let mut r = Router::with_modem_preset(our_node, "", MODEM_SHORT_SLOW, true, key, 3);
        r.set_node_identity(NodeInfoIdentity::for_node(our_node, TEST_PUBKEY));
        r
    });
    let channel = router.channel_hash();

    flood_other_bucket(router, requester, channel, &key, 0);

    let plaintext = mesh_routing::encode_data_payload_opts(
        mesh_routing::NODEINFO_APP,
        &[],
        DataEncodeOpts {
            want_response: true,
            reply_id: 0,
            request_id: 0,
        },
    );
    let mut cipher = plaintext.clone();
    mesh_crypto::encrypt_packet(&key, requester, 0x99, &mut cipher);
    let header = PacketHeader::from_fields(our_node, requester, 0x99, channel, 3, 3, false, false, 0, 0);
    let mut wire = heapless::Vec::<u8, 128>::new();
    let mut hdr = [0u8; PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    wire.extend_from_slice(&hdr).unwrap();
    wire.extend_from_slice(&cipher).unwrap();

    let result = router
        .process_inbound(&inbound(&wire), 2_000)
        .expect("nodeinfo request rx");
    assert!(result.rate_limited);
    assert!(router.poll_nodeinfo_tx(2_000).is_none());
}

#[test]
fn dedup_still_runs_when_rate_limited() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our_node = 0xDEAD_BEEF;
    let peer = 0xCAFE_BABE;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let router = ROUTER.init(Router::with_modem_preset(
        our_node,
        "",
        MODEM_SHORT_SLOW,
        true,
        key,
        3,
    ));
    let channel = router.channel_hash();
    let packet_id = 0x4242;

    let (len, frame) = build_app_wire_frame(
        NODENUM_BROADCAST,
        peer,
        packet_id,
        channel,
        3,
        3,
        false,
        &key,
        num::TEXT_MESSAGE_APP,
        b"hi",
        DataEncodeOpts::default(),
    )
    .expect("text wire");
    let bytes = &frame[..len as usize];

    let first = router
        .process_inbound(&inbound(bytes), 100)
        .expect("first hear");
    assert!(!first.duplicate);
    assert!(!first.rate_limited);

    flood_other_bucket(router, peer, channel, &key, 200);

    let dupe = router
        .process_inbound(&inbound(bytes), 300)
        .expect("duplicate hear");
    assert!(dupe.duplicate);
    assert!(!dupe.rate_limited);
}
