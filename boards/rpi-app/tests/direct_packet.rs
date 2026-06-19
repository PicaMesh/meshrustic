use mesh_protocol::{is_direct_packet, PacketHeader};

#[test]
fn direct_relay_node_zero() {
    assert!(is_direct_packet(0x1234_5678, 3, 3, 0));
}

#[test]
fn direct_relay_node_matches_from_low_byte() {
    assert!(is_direct_packet(0x1234_5678, 3, 3, 0x78));
}

#[test]
fn not_direct_relay_node_mismatch() {
    // Stock relay without hop decrement: hop_start == hop_limit but relay_node wrong.
    assert!(!is_direct_packet(0x1234_5678, 3, 3, 0xAB));
}

#[test]
fn not_direct_hop_decremented() {
    assert!(!is_direct_packet(0x1234_5678, 3, 2, 0));
}

#[test]
fn parsed_header_matches_is_direct_packet() {
    let header =
        PacketHeader::from_fields(0xAABB_CCDD, 0xAABB_CCDD, 1, 0, 3, 3, false, false, 0, 0xDD);
    let parsed = header.parse();
    assert!(is_direct_packet(
        parsed.from,
        parsed.hop_start,
        parsed.hop_limit,
        parsed.relay_node
    ));
}
