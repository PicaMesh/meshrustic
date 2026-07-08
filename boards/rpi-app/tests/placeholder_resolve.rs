//! Placeholder → real node resolution and gateway transfer.

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::{NODENUM_BROADCAST, PacketHeader, PACKET_HEADER_LEN};
use mesh_routing::{
    get_placeholder_for_relay, is_placeholder_node, InboundPacket, NeighborGraph, Router,
    DEVICE_ROLE_ROUTER,
};

const ME: u32 = 0xAA00_00AA;
const SOURCE: u32 = 0xBEEF_00AB;
const DEST: u32 = 0xCC00_00CC;
const RELAY_BYTE: u8 = 0xCD;
const REAL_RELAY: u32 = 0xBEEF_00CD;

fn wire_bytes(header: PacketHeader, payload: &[u8]) -> heapless::Vec<u8, 280> {
    let mut out = heapless::Vec::new();
    let mut hdr = [0u8; PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    let _ = out.extend_from_slice(&hdr);
    let _ = out.extend_from_slice(payload);
    out
}

fn relayed_inbound(from: u32, id: u32, relay_byte: u8, wire: &mut heapless::Vec<u8, 280>) -> InboundPacket<'_> {
    let header = PacketHeader::from_fields(
        NODENUM_BROADCAST,
        from,
        id,
        0x77,
        2,
        3,
        false,
        false,
        0,
        relay_byte,
    );
    wire.clear();
    let _ = wire.extend_from_slice(&wire_bytes(header, &[0xDE, 0xAD]));
    InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 10,
        bytes: wire.as_slice(),
    }
}

fn direct_inbound(from: u32, id: u32, wire: &mut heapless::Vec<u8, 280>) -> InboundPacket<'_> {
    let relay_byte = (from & 0xFF) as u8;
    let header = PacketHeader::from_fields(
        NODENUM_BROADCAST,
        from,
        id,
        0x77,
        3,
        3,
        false,
        false,
        0,
        relay_byte,
    );
    wire.clear();
    let _ = wire.extend_from_slice(&wire_bytes(header, &[0xBE, 0xEF]));
    InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 10,
        bytes: wire.as_slice(),
    }
}

fn relayed_placeholder(graph: &mut NeighborGraph) -> u32 {
    graph.set_my_node(ME);
    graph.set_device_role(DEVICE_ROLE_ROUTER);
    graph.observe_packet(SOURCE, 3, 2, RELAY_BYTE, -70, 8, 100, 0, None);
    let placeholder = get_placeholder_for_relay(RELAY_BYTE);
    assert!(graph.has_graph_node(placeholder));
    placeholder
}

#[test]
fn placeholder_replaced_when_real_node_learned() {
    let mut graph = NeighborGraph::new();
    let placeholder = relayed_placeholder(&mut graph);

    assert!(graph.resolve_placeholder(placeholder, REAL_RELAY, 200));
    assert!(!graph.has_graph_node(placeholder));
    assert!(!graph.resolve_placeholder(placeholder, REAL_RELAY, 300));
}

#[test]
fn downstream_transferred_on_resolution() {
    let mut graph = NeighborGraph::new();
    let placeholder = relayed_placeholder(&mut graph);
    graph
        .downstream_mut()
        .update(ME, DEST, placeholder, 2.0, 100, false, 0);

    assert!(graph.resolve_placeholder(placeholder, REAL_RELAY, 200));
    assert_eq!(graph.get_downstream_relay(DEST, 200), Some(REAL_RELAY));
    assert!(graph.is_downstream_relay_for(REAL_RELAY, DEST, 200));
    assert!(!is_placeholder_node(
        graph.get_downstream_relay(DEST, 200).unwrap_or(0)
    ));
}

#[test]
fn no_duplicate_edges_after_resolution() {
    let mut graph = NeighborGraph::new();
    let placeholder = relayed_placeholder(&mut graph);
    graph.observe_direct_neighbor(REAL_RELAY, -72, 9, 150, 0);

    assert!(graph.resolve_placeholder(placeholder, REAL_RELAY, 200));
    assert!(!graph.has_graph_node(placeholder));

    let Some(my_edges) = graph.edges().find_node(ME) else {
        panic!("missing local node");
    };
    let mut to_relay = 0u8;
    for i in 0..my_edges.edge_count as usize {
        if my_edges.edges[i].to == REAL_RELAY {
            to_relay += 1;
        }
        assert_ne!(my_edges.edges[i].to, placeholder);
    }
    assert_eq!(to_relay, 1);
}

#[test]
fn relayed_packet_uses_known_direct_neighbor_as_gateway() {
    let mut graph = NeighborGraph::new();
    graph.set_my_node(ME);
    graph.set_device_role(DEVICE_ROLE_ROUTER);
    graph.observe_direct_neighbor(REAL_RELAY, -70, 8, 0, 0);
    graph.observe_packet(SOURCE, 3, 2, RELAY_BYTE, -70, 8, 200, 0, Some(REAL_RELAY));

    let placeholder = get_placeholder_for_relay(RELAY_BYTE);
    assert!(!graph.has_graph_node(placeholder));
    assert_eq!(graph.get_downstream_relay(SOURCE, 300), Some(REAL_RELAY));
}

#[test]
fn relayed_then_direct_packet_resolves_placeholder() {
    let mut router = Router::with_channel(
        ME,
        CryptoKey::from_bytes(&DEFAULT_PSK),
        0x77,
        mesh_radio::MODEM_SHORT_SLOW,
        true,
        3,
    );
    router.set_device_role(DEVICE_ROLE_ROUTER);

    let mut wire = heapless::Vec::<u8, 280>::new();
    let relayed = relayed_inbound(SOURCE, 50, RELAY_BYTE, &mut wire);
    router.process_inbound(&relayed, 100).expect("relayed rx");
    let placeholder = get_placeholder_for_relay(RELAY_BYTE);
    assert!(router.graph_mut().has_graph_node(placeholder));
    assert_eq!(
        router.graph_mut().get_downstream_relay(SOURCE, 200),
        Some(placeholder)
    );

    let direct = direct_inbound(REAL_RELAY, 51, &mut wire);
    router.process_inbound(&direct, 300).expect("direct rx");
    assert!(!router.graph_mut().has_graph_node(placeholder));
    assert_eq!(
        router.graph_mut().get_downstream_relay(SOURCE, 400),
        Some(REAL_RELAY)
    );
}

#[test]
fn direct_then_relayed_packet_avoids_stale_placeholder() {
    let mut router = Router::with_channel(
        ME,
        CryptoKey::from_bytes(&DEFAULT_PSK),
        0x77,
        mesh_radio::MODEM_SHORT_SLOW,
        true,
        3,
    );
    router.set_device_role(DEVICE_ROLE_ROUTER);

    let mut wire = heapless::Vec::<u8, 280>::new();
    let direct = direct_inbound(REAL_RELAY, 60, &mut wire);
    router.process_inbound(&direct, 100).expect("direct rx");

    let relayed = relayed_inbound(SOURCE, 61, RELAY_BYTE, &mut wire);
    router.process_inbound(&relayed, 200).expect("relayed rx");

    let placeholder = get_placeholder_for_relay(RELAY_BYTE);
    assert!(!router.graph_mut().has_graph_node(placeholder));
    assert_eq!(
        router.graph_mut().get_downstream_relay(SOURCE, 300),
        Some(REAL_RELAY)
    );
}

#[test]
fn relayed_frame_does_not_resolve_placeholder() {
    let mut router = Router::with_channel(
        ME,
        CryptoKey::from_bytes(&DEFAULT_PSK),
        0x77,
        mesh_radio::MODEM_SHORT_SLOW,
        true,
        3,
    );
    router.set_device_role(DEVICE_ROLE_ROUTER);

    let mut wire = heapless::Vec::<u8, 280>::new();
    let relayed = relayed_inbound(SOURCE, 70, RELAY_BYTE, &mut wire);
    router.process_inbound(&relayed, 100).expect("relayed rx");
    let placeholder = get_placeholder_for_relay(RELAY_BYTE);
    assert!(router.graph_mut().has_graph_node(placeholder));

    // Hop budget consumed (hop_start > hop_limit): must not resolve even though
    // relay byte matches REAL_RELAY's low byte.
    let header = PacketHeader::from_fields(
        NODENUM_BROADCAST,
        REAL_RELAY,
        71,
        0x77,
        2,
        3,
        false,
        false,
        0,
        RELAY_BYTE,
    );
    wire.clear();
    let _ = wire.extend_from_slice(&wire_bytes(header, &[0xBE, 0xEF]));
    let relayed_from_relay = InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 10,
        bytes: wire.as_slice(),
    };
    router
        .process_inbound(&relayed_from_relay, 200)
        .expect("relayed from relay");
    assert!(router.graph_mut().has_graph_node(placeholder));
}

#[test]
fn resolve_placeholder_rejects_low_byte_mismatch() {
    let mut graph = NeighborGraph::new();
    let placeholder = relayed_placeholder(&mut graph);
    assert!(!graph.resolve_placeholder(placeholder, 0x1234_00AB, 200));
    assert!(graph.has_graph_node(placeholder));
}
