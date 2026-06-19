//! NODEINFO wire-format tests (port 4 User payload and request/reply).

use mesh_crypto::{CryptoKey, DEFAULT_PSK, encrypt_packet};
use mesh_protocol::{PacketHeader, User, PACKET_HEADER_LEN};
use mesh_radio::{primary_channel_hash, MODEM_SHORT_SLOW};
use mesh_routing::{
    build_nodeinfo_reply_frame, build_nodeinfo_wire_frame, encode_data_payload_opts,
    encode_user, summarize_decrypted, DataEncodeOpts, NodeInfoIdentity, Router, NODEINFO_APP,
};
use prost::Message;
use static_cell::StaticCell;

const TEST_PUBKEY: [u8; 32] = [0xAB; 32];

#[test]
fn encode_user_matches_prost_core_fields() {
    let identity = NodeInfoIdentity::for_node(0x677a_1caf, TEST_PUBKEY);
    let hand = encode_user(0x677a_1caf, &identity);
    let user = User {
        id: "!677a1caf".into(),
        long_name: "MeshRustic 1caf".into(),
        short_name: "MRaf".into(),
        hw_model: 63,
        is_licensed: false,
        role: 0,
        public_key: TEST_PUBKEY.to_vec(),
        ..Default::default()
    };
    let prost = user.encode_to_vec();
    assert_eq!(hand.as_slice(), prost.as_slice());
}

#[test]
fn nodeinfo_wire_decrypt_and_summary() {
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
    let identity = NodeInfoIdentity::for_node(0x677a_1caf, TEST_PUBKEY);
    let (len, frame) = build_nodeinfo_wire_frame(
        0x677a_1caf,
        99,
        channel_hash,
        3,
        &key,
        &identity,
    )
    .unwrap();
    let mut cipher = frame[PACKET_HEADER_LEN..len as usize].to_vec();
    let (portnum, payload) = mesh_routing::try_decrypt_data(
        &key,
        0x677a_1caf,
        99,
        channel_hash,
        channel_hash,
        &mut cipher,
    )
    .unwrap();
    assert_eq!(portnum, NODEINFO_APP);
    match summarize_decrypted(portnum, &payload) {
        mesh_routing::RxPayloadSummary::NodeInfo {
            short_name,
            short_len,
            role,
        } => {
            assert_eq!(short_len, 4);
            assert_eq!(&short_name[..4], b"MRaf");
            assert_eq!(role, 0);
        }
        other => panic!("expected nodeinfo summary, got {other:?}"),
    }
}

#[test]
fn nodeinfo_reply_frame_links_request_id() {
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let channel_hash = primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK);
    let identity = NodeInfoIdentity::for_node(0x677a_1caf, TEST_PUBKEY);
    let request_id = 0xBEEF_0001;
    let (len, frame) = build_nodeinfo_reply_frame(
        0xAABB_CCDD,
        0x677a_1caf,
        77,
        request_id,
        channel_hash,
        3,
        &key,
        &identity,
    )
    .unwrap();
    let header = PacketHeader::decode(&frame[..PACKET_HEADER_LEN]).unwrap();
    assert_eq!(header.to, 0xAABB_CCDD);
    let mut cipher = frame[PACKET_HEADER_LEN..len as usize].to_vec();
    let (decoded, _) = mesh_routing::try_decrypt_data_full(
        &key,
        0x677a_1caf,
        77,
        channel_hash,
        channel_hash,
        &mut cipher,
    )
    .unwrap();
    assert_eq!(decoded.reply_id, request_id);
}

fn build_nodeinfo_request_wire(
    from: u32,
    to: u32,
    request_id: u32,
    channel_hash: u8,
    key: &CryptoKey,
) -> Vec<u8> {
    let plaintext = encode_data_payload_opts(
        NODEINFO_APP,
        &[],
        DataEncodeOpts {
            want_response: true,
            reply_id: 0,
            request_id: 0,
        },
    );
    let mut cipher = plaintext.clone();
    encrypt_packet(key, from, request_id as u64, &mut cipher);
    let header = PacketHeader::from_fields(to, from, request_id, channel_hash, 3, 3, false, false, 0, 0);
    let mut out = Vec::with_capacity(PACKET_HEADER_LEN + cipher.len());
    let mut hdr = [0u8; PACKET_HEADER_LEN];
    header.encode_to(&mut hdr);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&cipher);
    out
}

#[test]
fn router_replies_to_nodeinfo_request() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our_node = 0x1111_1111;
    let requester = 0x2222_2222;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let router = ROUTER.init({
        let mut r = Router::with_modem_preset(our_node, "", MODEM_SHORT_SLOW, true, key, 3);
        r.set_node_identity(NodeInfoIdentity::for_node(our_node, TEST_PUBKEY));
        r
    });
    let channel_hash = router.channel_hash();
    let wire = build_nodeinfo_request_wire(requester, our_node, 0x99, channel_hash, &key);

    let inbound = mesh_routing::InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 10,
        bytes: &wire,
    };
    assert!(router.process_inbound(&inbound, 1_000).is_some());
    let reply = router.poll_nodeinfo_tx(1_000).expect("nodeinfo reply queued");
    let header = PacketHeader::decode(&reply.bytes[..reply.len as usize]).unwrap();
    assert_eq!(header.from, our_node);
    assert_eq!(header.to, requester);
}

#[test]
fn router_caches_received_nodeinfo() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let peer = 0x3333_4444;
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let router = ROUTER.init(Router::with_modem_preset(0x1111_1111, "", MODEM_SHORT_SLOW, true, key, 3));
    let channel_hash = router.channel_hash();
    let identity = NodeInfoIdentity::for_node(peer, TEST_PUBKEY);
    let (len, frame) = build_nodeinfo_wire_frame(peer, 55, channel_hash, 3, &key, &identity).unwrap();

    let inbound = mesh_routing::InboundPacket {
        radio_id: 0,
        rssi: -70,
        snr: 10,
        bytes: &frame[..len as usize],
    };
    assert!(router.process_inbound(&inbound, 1_000).is_some());
    assert_eq!(router.nodeinfo_peer_count(), 1);
    let cached = router.nodeinfo_peer(peer).expect("peer cached");
    assert_eq!(
        &cached.advert.short_name[..cached.advert.short_name_len as usize],
        &identity.advert.short_name[..identity.advert.short_name_len as usize]
    );
}
