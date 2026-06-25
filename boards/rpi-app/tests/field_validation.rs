//! Field-validation benches on host — traceroute chain + 3-node SR line.

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::{NODENUM_BROADCAST, PACKET_HEADER_LEN};
use mesh_radio::MODEM_SHORT_SLOW;
use mesh_routing::{
    build_app_wire_frame, coordinated_relay, decode_packed_neighbors, decode_route_discovery,
    encode_route_discovery, try_decrypt_data_full, write_packed_header, DataEncodeOpts,
    InboundPacket, NeighborGraph, PackedNeighbor, RouteDiscovery, Router, TopologyMergeResult,
    TRACEROUTE_APP,
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

fn decrypt_traceroute_route(
    key: &CryptoKey,
    from: u32,
    packet_id: u32,
    channel: u8,
    relay_bytes: &[u8],
) -> RouteDiscovery {
    let payload_len = relay_bytes.len().saturating_sub(PACKET_HEADER_LEN);
    let mut cipher = vec![0u8; payload_len];
    cipher.copy_from_slice(&relay_bytes[PACKET_HEADER_LEN..]);
    let (_decoded, inner) =
        try_decrypt_data_full(key, from, packet_id, channel, channel, &mut cipher[..])
            .expect("decrypt relay");
    decode_route_discovery(&inner).expect("route discovery")
}

#[test]
fn field_traceroute_three_node_chain() {
    const A: u32 = 0xA000_0001;
    const B: u32 = 0xB000_0002;
    const C: u32 = 0xC000_0003;
    const PACKET_ID: u32 = 0x77;
    const CHANNEL: u8 = 0x77;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);

    let mut route_wire = heapless::Vec::<u8, 128>::new();
    encode_route_discovery(&RouteDiscovery::default(), &mut route_wire);
    let (len, wire) = build_app_wire_frame(
        NODENUM_BROADCAST,
        A,
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

    let mut router_b = Router::with_channel(B, key, CHANNEL, MODEM_SHORT_SLOW, true, 3);
    router_b
        .graph_mut()
        .observe_direct_neighbor(0xF000_000F, -75, 8, 0, 0);
    router_b
        .graph_mut()
        .capability_mut()
        .track_topology(0xF000_000F, true, 0);
    let result_b = router_b
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -70,
                snr: 10,
                bytes: &wire[..usize::from(len)],
            },
            0,
        )
        .expect("node B accepts");
    let relay_b = ready_relay(&mut router_b, &result_b, 0);
    let rd_b = decrypt_traceroute_route(&key, A, PACKET_ID, CHANNEL, &relay_b.bytes[..relay_b.len as usize]);
    assert_eq!(rd_b.route.as_slice(), &[B]);

    let mut router_c = Router::with_channel(C, key, CHANNEL, MODEM_SHORT_SLOW, true, 3);
    router_c
        .graph_mut()
        .observe_direct_neighbor(0xF000_000F, -75, 8, 0, 0);
    router_c
        .graph_mut()
        .capability_mut()
        .track_topology(0xF000_000F, true, 0);
    let result_c = router_c
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -68,
                snr: 9,
                bytes: &relay_b.bytes[..relay_b.len as usize],
            },
            50,
        )
        .expect("node C accepts");
    let relay_c = ready_relay(&mut router_c, &result_c, 50);
    let rd_c = decrypt_traceroute_route(&key, A, PACKET_ID, CHANNEL, &relay_c.bytes[..relay_c.len as usize]);
    assert_eq!(rd_c.route.as_slice(), &[B, C]);
}

#[test]
fn field_three_node_sr_learns_remote_route() {
    const A: u32 = 0xA000_0001;
    const B: u32 = 0xB000_0002;
    const C: u32 = 0xC000_0003;

    let mut graph_a = NeighborGraph::new();
    graph_a.set_my_node(A);
    graph_a.observe_direct_neighbor(B, -70, 8, 0, 0);

    let remote = PackedNeighbor {
        node_id: C,
        rssi: -75,
        snr: 8,
        signal_routing_active: true,
        hears_us: false,
        etx_variance: 0,
    };
    let mut packed = [0u8; 16];
    write_packed_header(&mut packed, 2, true);
    let (header, _) = decode_packed_neighbors(&packed, 8).unwrap();

    let result = graph_a.merge_topology(B, &header, &[remote], true, 100, 0);
    assert!(matches!(result, TopologyMergeResult::Applied { .. }));

    let hop = graph_a.get_next_hop(C, B, B, 100);
    assert_ne!(hop, 0, "node A should route to C via learned topology");
}
