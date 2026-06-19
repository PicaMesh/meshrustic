//! Reliable want_ack: originate, ACK reply, implicit cancel on rebroadcast dupe.

use mesh_crypto::{encrypt_packet, CryptoKey, DEFAULT_PSK};
use mesh_protocol::{portnum::num, PacketHeader, PACKET_HEADER_LEN, NODENUM_BROADCAST};
use mesh_routing::{
    build_ack_nak_frame, coordinated_relay, encode_data_payload, retransmission_delay_ms,
    try_decrypt_data_full, InboundPacket, Router, ROUTING_APP, ROUTING_ERROR_NONE,
};
fn make_router() -> Router {
    Router::with_channel(
        0xAA00_0001,
        CryptoKey::from_bytes(&DEFAULT_PSK),
        0x77,
        mesh_radio::MODEM_SHORT_SLOW,
        true,
        3,
    )
}

fn encrypt_payload(from: u32, packet_id: u32, portnum: u32, inner: &[u8]) -> Vec<u8> {
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let plaintext = encode_data_payload(portnum, inner);
    let mut cipher = plaintext.to_vec();
    encrypt_packet(&key, from, packet_id as u64, &mut cipher);
    cipher
}

#[test]
fn send_local_schedules_reliable_retransmit() {
    let mut router = make_router();
    let slot_ms = coordinated_relay::DEFAULT_SLOT_MS;
    let airtime_ms = 200;
    let plan = router
        .send_local(
            0xBB00_0002,
            num::TEXT_MESSAGE_APP,
            b"hi",
            true,
            3,
            1_000,
            airtime_ms,
            slot_ms,
        )
        .expect("send_local");
    assert!(usize::from(plan.len) > PACKET_HEADER_LEN);
    let header = PacketHeader::decode(&plan.bytes[..PACKET_HEADER_LEN]).unwrap();
    assert!(header.parse().want_ack);

    let fire_ms = retransmission_delay_ms(airtime_ms, slot_ms);
    assert!(router
        .poll_reliable_retransmit(1_000 + fire_ms - 1, airtime_ms, slot_ms)
        .is_none());
    assert!(router
        .poll_reliable_retransmit(1_000 + fire_ms, airtime_ms, slot_ms)
        .is_some());
}

#[test]
fn incoming_want_ack_schedules_routing_ack() {
    let mut router = make_router();
    let from = 0xBB00_0002;
    let packet_id = 0x4242;
    let cipher = encrypt_payload(from, packet_id, num::TEXT_MESSAGE_APP, b"hello");
    let header = PacketHeader::from_fields(
        router.node_num(),
        from,
        packet_id,
        0x77,
        3,
        3,
        true,
        false,
        0,
        0,
    );
    let mut wire = Vec::new();
    let mut hdr = [0u8; PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    wire.extend_from_slice(&hdr);
    wire.extend_from_slice(&cipher);

    let inbound = InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 8,
        bytes: &wire,
    };
    let result = router.process_inbound(&inbound, 5_000).expect("rx");
    assert!(!result.duplicate);
    let ack = router.poll_ack_tx(5_000).expect("ack scheduled");
    let ack_header = PacketHeader::decode(&ack.bytes[..PACKET_HEADER_LEN]).unwrap();
    let parsed_ack = ack_header.parse();
    assert_eq!(parsed_ack.to, from);

    let mut ack_cipher = ack.bytes[PACKET_HEADER_LEN..ack.len as usize].to_vec();
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let (data, inner) = try_decrypt_data_full(
        &key,
        router.node_num(),
        parsed_ack.id,
        0x77,
        0x77,
        &mut ack_cipher,
    )
    .expect("decrypt ack");
    assert_eq!(data.portnum, ROUTING_APP);
    assert_eq!(data.request_id, packet_id);
    assert!(!inner.is_empty());
}

#[test]
fn implicit_ack_cancels_reliable_on_own_rebroadcast_dupe() {
    let mut router = make_router();
    let slot_ms = coordinated_relay::DEFAULT_SLOT_MS;
    let airtime_ms = 200;
    let plan = router
        .send_local(
            NODENUM_BROADCAST,
            num::TEXT_MESSAGE_APP,
            b"bc",
            true,
            3,
            1_000,
            airtime_ms,
            slot_ms,
        )
        .expect("send");
    let parsed = PacketHeader::decode(&plan.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();

    let rebroadcast = InboundPacket {
        radio_id: 0,
        rssi: -80,
        snr: 5,
        bytes: &plan.bytes[..plan.len as usize],
    };
    router.process_inbound(&rebroadcast, 2_000).expect("first hear");
    let dupe = router.process_inbound(&rebroadcast, 2_100).unwrap();
    assert!(dupe.duplicate);
    assert!(!router.has_pending_reliable(parsed.id));

    let fire_ms = retransmission_delay_ms(airtime_ms, slot_ms);
    assert!(router
        .poll_reliable_retransmit(1_000 + fire_ms, airtime_ms, slot_ms)
        .is_none());
}

#[test]
fn routing_ack_stops_pending_retransmit() {
    let mut router = make_router();
    let slot_ms = coordinated_relay::DEFAULT_SLOT_MS;
    let airtime_ms = 200;
    let plan = router
        .send_local(
            0xBB00_0002,
            num::TEXT_MESSAGE_APP,
            b"ping",
            true,
            3,
            1_000,
            airtime_ms,
            slot_ms,
        )
        .expect("send");
    let orig_id = PacketHeader::decode(&plan.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse()
        .id;

    let Some((len, ack_frame)) = build_ack_nak_frame(
        router.node_num(),
        0xBB00_0002,
        0x9999,
        orig_id,
        0x77,
        2,
        ROUTING_ERROR_NONE,
        &CryptoKey::from_bytes(&DEFAULT_PSK),
    ) else {
        panic!("build ack");
    };

    let inbound = InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 8,
        bytes: &ack_frame[..len as usize],
    };
    router.process_inbound(&inbound, 3_000).expect("ack rx");
    assert!(!router.has_pending_reliable(orig_id));
}
