use mesh_protocol::{MeshPacket, PortNum, SignalRoutingInfo};
use prost::Message;

#[test]
fn mesh_packet_protobuf_round_trip() {
    let packet = MeshPacket {
        from: 0x1234_5678,
        to: 0x8765_4321,
        id: 0x00FF_00FF,
        hop_limit: 3,
        hop_start: 3,
        want_ack: true,
        channel: 0x2A,
        ..Default::default()
    };

    let encoded = packet.encode_to_vec();
    let decoded = MeshPacket::decode(encoded.as_slice()).expect("decode MeshPacket");

    assert_eq!(decoded.from, packet.from);
    assert_eq!(decoded.to, packet.to);
    assert_eq!(decoded.id, packet.id);
    assert_eq!(decoded.hop_limit, packet.hop_limit);
    assert_eq!(decoded.hop_start, packet.hop_start);
    assert_eq!(decoded.want_ack, packet.want_ack);
    assert_eq!(decoded.channel, packet.channel);
}

#[test]
fn signal_routing_info_round_trip() {
    let mut packed = vec![1, 8, 3, 42, 1]; // V3 packed header: fmt=1, entry=8, routing=3, topo=42, SR=1
    let info = SignalRoutingInfo {
        packed_neighbors: packed.clone(),
    };

    let encoded = info.encode_to_vec();
    assert_eq!(encoded[0], (3 << 3) | 2);
    let decoded = SignalRoutingInfo::decode(encoded.as_slice()).expect("decode SR info");
    assert_eq!(decoded.packed_neighbors, packed);
}

#[test]
fn core_portnums_present() {
    assert_eq!(PortNum::RoutingApp as i32, 5);
    assert_eq!(PortNum::NodeinfoApp as i32, 4);
    assert_eq!(PortNum::TracerouteApp as i32, 70);
    assert_eq!(PortNum::SignalRoutingApp as i32, 88);
}
