use mesh_protocol::{PacketHeader, ParsedPacket, PACKET_HEADER_LEN};

#[test]
fn header_length_is_sixteen() {
    assert_eq!(PacketHeader::LEN, PACKET_HEADER_LEN);
    assert_eq!(PacketHeader::LEN, 16);
}

#[test]
fn header_encode_matches_golden_vector() {
    let header = PacketHeader::from_fields(
        0x1122_3344,
        0x5566_7788,
        0xAABB_CCDD,
        0x42,
        3,
        3,
        true,
        false,
        0x11,
        0x88,
    );

    let mut encoded = [0u8; 16];
    header.encode_to(&mut encoded);

    const GOLDEN: [u8; 16] = [
        0x44, 0x33, 0x22, 0x11, // to
        0x88, 0x77, 0x66, 0x55, // from
        0xDD, 0xCC, 0xBB, 0xAA, // id
        0x6B, // flags: hop_limit=3, hop_start=3, want_ack
        0x42, // channel
        0x11, // next_hop
        0x88, // relay_node
    ];
    assert_eq!(encoded, GOLDEN);
}

#[test]
fn header_round_trip_and_parse() {
    let header = PacketHeader::from_fields(
        0xFFFF_FFFF,
        0x1234_5678,
        42,
        0x01,
        5,
        5,
        false,
        true,
        0x78,
        0x78,
    );

    let mut buf = [0u8; 16];
    header.encode_to(&mut buf);
    let decoded = PacketHeader::decode(&buf).expect("decode");
    assert_eq!(decoded, header);

    let parsed = decoded.parse();
    assert_eq!(
        parsed,
        ParsedPacket {
            to: 0xFFFF_FFFF,
            from: 0x1234_5678,
            id: 42,
            channel: 0x01,
            hop_limit: 5,
            hop_start: 5,
            want_ack: false,
            via_mqtt: true,
            next_hop: 0x78,
            relay_node: 0x78,
        }
    );
}

#[test]
fn flag_masks_extract_hop_and_ack() {
    let header = PacketHeader::from_fields(0, 1, 2, 0, 7, 2, true, false, 0, 0);
    assert_eq!(header.hop_limit(), 7);
    assert_eq!(header.hop_start(), 2);
    assert!(header.want_ack());
    assert!(!header.via_mqtt());
}

#[test]
fn legacy_hop_start_zero_clears_next_hop_and_relay() {
    let header = PacketHeader::from_fields(0, 1, 2, 0, 3, 0, false, false, 0x99, 0xAA);
    let parsed = header.parse();
    assert_eq!(parsed.hop_start, 0);
    assert_eq!(parsed.next_hop, 0);
    assert_eq!(parsed.relay_node, 0);
}
