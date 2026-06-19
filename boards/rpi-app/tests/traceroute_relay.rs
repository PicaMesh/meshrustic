//! TRACEROUTE_APP relay integration — append node id + SNR on rebroadcast.

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::{NODENUM_BROADCAST, PacketHeader, PACKET_HEADER_LEN};
use mesh_radio::MODEM_SHORT_SLOW;
use mesh_routing::{
    build_app_wire_frame, coordinated_relay, decode_route_discovery, encode_route_discovery,
    try_decrypt_data_full, DataEncodeOpts, InboundPacket, RouteDiscovery, Router, TRACEROUTE_APP,
};

fn ready_relay(
    router: &mut Router,
    result: &mesh_routing::ProcessResult,
    now_ms: u32,
) -> mesh_routing::RelayPlan {
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
fn router_appends_traceroute_hop_on_rebroadcast() {
    const FROM: u32 = 0x1111_1111;
    const RELAY: u32 = 0xCCCC_CCCC;
    const PACKET_ID: u32 = 0x42;
    const CHANNEL: u8 = 0x77;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);

    let mut route_wire = heapless::Vec::<u8, 128>::new();
    encode_route_discovery(&RouteDiscovery::default(), &mut route_wire);
    let (_len, wire) = build_app_wire_frame(
        NODENUM_BROADCAST,
        FROM,
        PACKET_ID,
        CHANNEL,
        3,
        3,
        false,
        &key,
        TRACEROUTE_APP,
        &route_wire,
        DataEncodeOpts::default(),
    )
    .expect("wire frame");

    let mut router = Router::with_channel(RELAY, key, CHANNEL, MODEM_SHORT_SLOW, true, 3);
    let result = router
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 10,
                bytes: &wire[..usize::from(_len)],
            },
            0,
        )
        .expect("accepted");
    assert_eq!(result.decoded_portnum, Some(TRACEROUTE_APP));

    let relay = ready_relay(&mut router, &result, 0);
    let payload_len = relay.len as usize - PACKET_HEADER_LEN;
    let mut cipher = vec![0u8; payload_len];
    cipher.copy_from_slice(&relay.bytes[PACKET_HEADER_LEN..relay.len as usize]);

    let (decoded, inner) = try_decrypt_data_full(
        &key,
        FROM,
        PACKET_ID,
        CHANNEL,
        CHANNEL,
        &mut cipher[..],
    )
    .expect("decrypt relay");
    assert_eq!(decoded.portnum, TRACEROUTE_APP);

    let rd = decode_route_discovery(&inner).expect("route discovery");
    assert_eq!(rd.route.as_slice(), &[RELAY]);
    assert_eq!(rd.snr_towards.as_slice(), &[40]);
}

#[test]
fn router_appends_traceroute_reply_on_route_back() {
    const FROM: u32 = 0x1111_1111;
    const RELAY: u32 = 0xCCCC_CCCC;
    const PACKET_ID: u32 = 0x44;
    const REQUEST_ID: u32 = 0x9999;
    const CHANNEL: u8 = 0x77;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);

    let mut route_wire = heapless::Vec::<u8, 128>::new();
    encode_route_discovery(&RouteDiscovery::default(), &mut route_wire);
    let (_len, wire) = build_app_wire_frame(
        NODENUM_BROADCAST,
        FROM,
        PACKET_ID,
        CHANNEL,
        3,
        3,
        false,
        &key,
        TRACEROUTE_APP,
        &route_wire,
        DataEncodeOpts {
            want_response: false,
            request_id: REQUEST_ID,
            reply_id: 0,
        },
    )
    .expect("wire frame");

    let mut router = Router::with_channel(RELAY, key, CHANNEL, MODEM_SHORT_SLOW, true, 3);
    let result = router
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -65,
                snr: 6,
                bytes: &wire[..usize::from(_len)],
            },
            0,
        )
        .expect("accepted");

    let relay = ready_relay(&mut router, &result, 0);
    let payload_len = relay.len as usize - PACKET_HEADER_LEN;
    let mut cipher = vec![0u8; payload_len];
    cipher.copy_from_slice(&relay.bytes[PACKET_HEADER_LEN..relay.len as usize]);

    let (_decoded, inner) = try_decrypt_data_full(
        &key,
        FROM,
        PACKET_ID,
        CHANNEL,
        CHANNEL,
        &mut cipher[..],
    )
    .expect("decrypt relay");

    let rd = decode_route_discovery(&inner).expect("route discovery");
    assert!(rd.route.is_empty());
    assert_eq!(rd.route_back.as_slice(), &[RELAY]);
    assert_eq!(rd.snr_back.as_slice(), &[24]);
}

#[test]
fn traceroute_to_us_sends_response_with_request_id() {
    const REQUESTER: u32 = 0x1111_1111;
    const TARGET: u32 = 0xCCCC_CCCC;
    const REQUEST_ID: u32 = 0xABCD_1234;
    const CHANNEL: u8 = 0x77;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);

    let mut route_wire = heapless::Vec::<u8, 128>::new();
    encode_route_discovery(&RouteDiscovery::default(), &mut route_wire);
    let (req_len, req_wire) = build_app_wire_frame(
        TARGET,
        REQUESTER,
        REQUEST_ID,
        CHANNEL,
        3,
        3,
        true,
        &key,
        TRACEROUTE_APP,
        &route_wire,
        DataEncodeOpts {
            want_response: true,
            ..Default::default()
        },
    )
    .expect("request wire");

    let mut router = Router::with_channel(TARGET, key, CHANNEL, MODEM_SHORT_SLOW, true, 3);
    let result = router
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -68,
                snr: 9,
                bytes: &req_wire[..usize::from(req_len)],
            },
            100,
        )
        .expect("accepted");

    assert_eq!(result.parsed.to, TARGET);
    let response = router.poll_traceroute_tx(100).expect("traceroute response");
    let header = PacketHeader::decode(&response.bytes[..PACKET_HEADER_LEN]).unwrap();
    let parsed = header.parse();
    assert_eq!(parsed.to, REQUESTER);
    assert_eq!(parsed.from, TARGET);

    let payload_len = response.len as usize - PACKET_HEADER_LEN;
    let mut cipher = vec![0u8; payload_len];
    cipher.copy_from_slice(&response.bytes[PACKET_HEADER_LEN..response.len as usize]);
    let (decoded, inner) = try_decrypt_data_full(
        &key,
        TARGET,
        parsed.id,
        CHANNEL,
        CHANNEL,
        &mut cipher[..],
    )
    .expect("decrypt response");
    assert_eq!(decoded.portnum, TRACEROUTE_APP);
    assert_eq!(decoded.request_id, REQUEST_ID);
    let rd = decode_route_discovery(&inner).expect("route discovery");
    assert!(rd.route.is_empty());
    assert_eq!(rd.snr_towards.as_slice(), &[36]);
}
