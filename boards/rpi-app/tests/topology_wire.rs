//! Topology wire-format tests (V3 packed_neighbors).

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_radio::{primary_channel_hash, MODEM_SHORT_SLOW};
use mesh_protocol::PacketHeader;
use mesh_routing::{
    build_topology_wire_frame, decode_packed_neighbors, NeighborEntry, NeighborGraph, Router,
    TopologyMergeResult, MAX_NEIGHBORS, MAX_NEIGHBORS_PER_PACKET, PACKED_NEIGHBOR_HEADER_SIZE,
    SIGNAL_ROUTING_APP, SIGNAL_ROUTING_VERSION, write_packed_header,
};
use static_cell::StaticCell;

#[test]
fn v3_topology_field3_is_length_delimited_bytes() {
    let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE];
    write_packed_header(&mut packed, 9, true);
    assert_eq!(packed[2], SIGNAL_ROUTING_VERSION);
    let encoded = mesh_routing::encode_signal_routing_info(&packed);
    assert_eq!(encoded[0], (3 << 3) | 2);
}

#[test]
fn multi_packet_chunk_size_golden() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAA);
    for i in 0..24u32 {
        graph.observe_direct_neighbor(0x1000 + i, -70, 8, 0, 0);
    }
    // Graph node cap (24 slots including self) limits direct neighbors to 23.
    // Topology pack includes only reported edges with a cached direct signal.
    assert_eq!(graph.neighbor_count(), 23);
    let mut packed_neighbors = [NeighborEntry::default(); MAX_NEIGHBORS];
    let pack_count = graph.topology_neighbors_for_pack(&mut packed_neighbors);
    assert_eq!(pack_count, 24, "one cached signal per observed direct edge");
    assert_eq!(graph.topology_packet_count(), 1);

    let per_packet = MAX_NEIGHBORS_PER_PACKET;
    assert_eq!((usize::from(pack_count) + per_packet - 1) / per_packet, 1);
}

#[test]
fn empty_graph_builds_header_only_boot_topology() {
    let graph = NeighborGraph::new();
    assert_eq!(graph.neighbor_count(), 0);
    assert_eq!(graph.topology_packet_count(), 1);

    let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE];
    let len = graph
        .build_topology_chunk(0, 0, &mut packed)
        .expect("empty graph must emit header-only chunk");
    assert_eq!(len, PACKED_NEIGHBOR_HEADER_SIZE);
    assert_eq!(packed[2], SIGNAL_ROUTING_VERSION);

    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
    let (wire_len, frame) = build_topology_wire_frame(
        0x677A_1CAF,
        1,
        channel_hash,
        3,
        &key,
        &packed[..len],
    )
    .expect("empty topology must encode to wire frame");
    assert!(wire_len > 16);

    let header = PacketHeader::decode(&frame).unwrap();
    assert_eq!(header.parse().from, 0x677A_1CAF);
}

#[test]
fn ensure_boot_broadcasts_queues_empty_topology() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(0x677A_1CAF));
    router.set_modem_preset(
        "",
        MODEM_SHORT_SLOW,
        true,
        CryptoKey::from_bytes(&DEFAULT_PSK),
    );
    assert_eq!(router.topology_version(), 0);
    router.ensure_boot_broadcasts(100, 50);
    let topo = router.poll_topology_tx(100).expect("boot topology must be ready");
    assert!(topo.len > 16);
    assert!(router.poll_topology_tx(100).is_none());
}

#[test]
fn maintenance_does_not_rebroadcast_topology_after_one_minute() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(0x677A_1CAE));
    router.set_modem_preset(
        "",
        MODEM_SHORT_SLOW,
        true,
        CryptoKey::from_bytes(&DEFAULT_PSK),
    );

    router.ensure_boot_broadcasts(100, 50);
    let topo = router.poll_topology_tx(100).expect("boot topology must be ready");
    let header = PacketHeader::decode(&topo.bytes[..topo.len as usize]).unwrap();
    router.record_tx_on_air(header.parse().id, 100);
    assert!(router.poll_topology_tx(100).is_none());

    let report = router.run_maintenance(60_100, 50);
    assert!(!report.topology_due);
    assert!(router.poll_topology_tx(60_100).is_none());
}

#[test]
fn router_topology_tx_decrypt_round_trip() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let _router = ROUTER.init(Router::new(0xAABB_CCDD));
    let mut graph = NeighborGraph::new();
    graph.set_my_node(0xAABB_CCDD);
    graph.observe_direct_neighbor(0x1234_5678, -80, 10, 0, 0);

    let mut packed = [0u8; 64];
    let len = graph
        .build_topology_chunk(0, 1, &mut packed)
        .expect("chunk");
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
    let (wire_len, frame) = build_topology_wire_frame(
        0xAABB_CCDD,
        42,
        channel_hash,
        3,
        &key,
        &packed[..len],
    )
    .unwrap();

    let header = PacketHeader::decode(&frame).unwrap();
    assert_eq!(header.channel, channel_hash);
    let mut cipher = frame[16..wire_len as usize].to_vec();
    let (portnum, payload) = mesh_routing::try_decrypt_data(
        &key,
        0xAABB_CCDD,
        42,
        channel_hash,
        channel_hash,
        &mut cipher,
    )
    .unwrap();
    assert_eq!(portnum, SIGNAL_ROUTING_APP);
    let (hdr, neighbors) = mesh_routing::extract_packed_neighbors(&payload).unwrap();
    assert_eq!(hdr.topology_version, 1);
    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0].node_id, 0x1234_5678);
}

#[test]
fn topology_wire_uses_port_88_on_data_layer() {
    use mesh_routing::{decode_data_payload, encode_data_payload, SIGNAL_ROUTING_APP};
    let inner = mesh_routing::encode_signal_routing_info(&[1, 8, 3, 1, 1]);
    let data = encode_data_payload(SIGNAL_ROUTING_APP, &inner);
    let (portnum, payload) = decode_data_payload(&data).unwrap();
    assert_eq!(portnum, 88);
    assert_eq!(payload.as_slice(), inner.as_slice());
}

#[test]
fn merge_topology_rejects_stale_version() {
    let mut graph = NeighborGraph::new();
    let mut packed = [0u8; PACKED_NEIGHBOR_HEADER_SIZE];
    write_packed_header(&mut packed, 5, true);
    let (header, neighbors) = decode_packed_neighbors(&packed, 8).unwrap();
    assert_eq!(
        graph.merge_topology(0x1111, &header, &neighbors, true, 0, 0),
        TopologyMergeResult::Applied {
            neighbors: 0,
            topo_v: 5
        }
    );
    write_packed_header(&mut packed, 4, true);
    let (header, neighbors) = decode_packed_neighbors(&packed, 8).unwrap();
    assert_eq!(
        graph.merge_topology(0x1111, &header, &neighbors, true, 0, 0),
        TopologyMergeResult::Stale {
            received: 4,
            last: 5
        }
    );
}
