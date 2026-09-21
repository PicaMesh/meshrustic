//! PKI private `ENTER DFU` arms Adafruit BLE OTA DFU; channel/relayed/unauthorized do not.

use mesh_crypto::CryptoEngine;
use mesh_protocol::{
    num::{ROUTING_APP, TEXT_MESSAGE_APP},
    PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN,
};
use mesh_routing::{
    build_app_wire_frame, decode_data_payload_full, payload_is_enter_dfu, DataEncodeOpts,
    InboundPacket, NodeInfoIdentity, Router, DEVICE_ROLE_ROUTER, DFU_CONFIRM_TEXT,
    DFU_ENTER_DELAY_SECS, ENTER_DFU_TEXT,
};
use mesh_store::{default_channel_key, generate_keypair, NodeConfig};

fn decrypt_pki(
    frame: &[u8],
    from: u32,
    from_pub: &[u8; 32],
    to_priv: &[u8; 32],
) -> (mesh_protocol::ParsedPacket, mesh_routing::DecodedData, heapless::Vec<u8, 240>) {
    let parsed = PacketHeader::decode(&frame[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();
    let cipher = &frame[PACKET_HEADER_LEN..];
    let mut plain = vec![0u8; cipher.len()];
    let mut engine = CryptoEngine::new();
    engine.set_dh_private_key(to_priv);
    assert!(engine.decrypt_curve25519(from, from_pub, parsed.id as u64, cipher, &mut plain));
    let plain_len = cipher.len() - 12;
    let (data, inner) = decode_data_payload_full(&plain[..plain_len]).unwrap();
    (parsed, data, inner)
}

fn inbound(router: &mut Router, frame: &[u8], now: u32) {
    router
        .process_inbound(
            &InboundPacket {
                radio_id: 0,
                rssi: -40,
                snr: 5,
                bytes: frame,
            },
            now,
        )
        .unwrap();
}

fn setup_router(
    our: u32,
    node_priv: [u8; 32],
    node_pub: [u8; 32],
    admin_pubs: [[u8; 32]; 2],
) -> Router {
    let cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    let mut router = Router::new(our);
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test(admin_pubs);
    router.set_device_role(DEVICE_ROLE_ROUTER);
    router
}

fn build_pki_text(
    to: u32,
    from: u32,
    packet_id: u32,
    from_priv: &[u8; 32],
    to_pub: &[u8; 32],
    text: &[u8],
    hop_limit: u8,
    hop_start: u8,
    relay_node: u8,
    want_ack: bool,
) -> Vec<u8> {
    let plaintext = mesh_routing::encode_data_payload(TEXT_MESSAGE_APP, text);
    let mut engine = CryptoEngine::new();
    engine.set_dh_private_key(from_priv);
    let mut cipher = vec![0u8; plaintext.len() + 12];
    assert!(engine.encrypt_curve25519(
        to_pub,
        from,
        packet_id as u64,
        packet_id,
        &plaintext,
        &mut cipher,
    ));
    let header = PacketHeader::from_fields(
        to, from, packet_id, 0, hop_limit, hop_start, want_ack, false, 0, relay_node,
    );
    let mut out = vec![0u8; PACKET_HEADER_LEN + cipher.len()];
    header.encode_to((&mut out[..PACKET_HEADER_LEN]).try_into().unwrap());
    out[PACKET_HEADER_LEN..].copy_from_slice(&cipher);
    out
}

fn channel_text(
    to: u32,
    from: u32,
    packet_id: u32,
    channel_hash: u8,
    hop_limit: u8,
    hop_start: u8,
    next_hop: u8,
    text: &[u8],
) -> Vec<u8> {
    let key = default_channel_key();
    let (len, frame) = build_app_wire_frame(
        to,
        from,
        packet_id,
        channel_hash,
        hop_limit,
        hop_start,
        false,
        &key,
        TEXT_MESSAGE_APP,
        text,
        DataEncodeOpts::default(),
        next_hop,
    )
    .unwrap();
    frame[..len as usize].to_vec()
}

#[test]
fn payload_trim_and_reject() {
    assert!(payload_is_enter_dfu(ENTER_DFU_TEXT));
    assert!(payload_is_enter_dfu(b"  ENTER DFU\n"));
    assert!(!payload_is_enter_dfu(b"enter dfu"));
    assert!(!payload_is_enter_dfu(b"please ENTER DFU now"));
}

#[test]
fn pki_direct_admin_dm_arms_ota_dfu() {
    let our = 0xE010_0001u32;
    let peer = 0xF010_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x21; 16]), 21);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x22; 16]), 22);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x23; 16]), 23);
    let mut router = setup_router(our, node_priv, node_pub, [b1_pub, b2_pub]);

    let frame = build_pki_text(
        our,
        peer,
        0xDF01,
        &b1_priv,
        &node_pub,
        ENTER_DFU_TEXT,
        3,
        3,
        0,
        true,
    );
    inbound(&mut router, &frame, 1_000);
    assert_eq!(
        router.take_pending_ota_dfu_seconds(),
        Some(DFU_ENTER_DELAY_SECS)
    );

    let ack = router.poll_ack_tx(1_000).expect("routing ACK queued");
    let (ack_hdr, ack_data, _) = decrypt_pki(&ack.bytes[..ack.len as usize], our, &node_pub, &b1_priv);
    assert_eq!(ack_hdr.to, peer);
    assert_eq!(ack_data.portnum, ROUTING_APP);
    assert_eq!(ack_data.request_id, 0xDF01);
    assert!(router.poll_ack_tx(1_000).is_none());

    let confirm = router
        .poll_dfu_confirm_tx(1_000)
        .expect("confirmation queued");
    let (confirm_hdr, confirm_data, confirm_body) =
        decrypt_pki(&confirm.bytes[..confirm.len as usize], our, &node_pub, &b1_priv);
    assert_eq!(confirm_hdr.to, peer);
    assert_eq!(confirm_hdr.from, our);
    assert!(!confirm_hdr.want_ack);
    assert_eq!(confirm_data.portnum, TEXT_MESSAGE_APP);
    assert_eq!(confirm_data.request_id, 0xDF01);
    assert_eq!(confirm_body.as_slice(), DFU_CONFIRM_TEXT);
    assert!(router.poll_dfu_confirm_tx(1_000).is_none());
}

#[test]
fn channel_psk_dm_is_ignored() {
    let our = 0xE011_0001u32;
    let peer = 0xF011_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x31; 16]), 31);
    let (_b1_priv, b1_pub) = generate_keypair(Some(&[0x32; 16]), 32);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x33; 16]), 33);
    let mut router = setup_router(our, node_priv, node_pub, [b1_pub, b2_pub]);

    let frame = channel_text(
        our,
        peer,
        0xDF02,
        router.channel_hash(),
        3,
        3,
        0,
        ENTER_DFU_TEXT,
    );
    inbound(&mut router, &frame, 1_000);
    assert!(router.take_pending_ota_dfu_seconds().is_none());
}

#[test]
fn relayed_pki_dm_is_ignored() {
    let our = 0xE012_0001u32;
    let peer = 0xF012_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x41; 16]), 41);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x42; 16]), 42);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x43; 16]), 43);
    let mut router = setup_router(our, node_priv, node_pub, [b1_pub, b2_pub]);

    let frame = build_pki_text(
        our,
        peer,
        0xDF03,
        &b1_priv,
        &node_pub,
        ENTER_DFU_TEXT,
        2,
        3,
        0x99,
        false,
    );
    inbound(&mut router, &frame, 1_000);
    assert!(router.take_pending_ota_dfu_seconds().is_none());
}

#[test]
fn wrong_text_is_ignored() {
    let our = 0xE013_0001u32;
    let peer = 0xF013_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x51; 16]), 51);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x52; 16]), 52);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x53; 16]), 53);
    let mut router = setup_router(our, node_priv, node_pub, [b1_pub, b2_pub]);

    let frame = build_pki_text(our, peer, 0xDF04, &b1_priv, &node_pub, b"hello", 3, 3, 0, false);
    inbound(&mut router, &frame, 1_000);
    assert!(router.take_pending_ota_dfu_seconds().is_none());
}

#[test]
fn broadcast_is_ignored() {
    let our = 0xE014_0001u32;
    let peer = 0xF014_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x61; 16]), 61);
    let (_b1_priv, b1_pub) = generate_keypair(Some(&[0x62; 16]), 62);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x63; 16]), 63);
    let mut router = setup_router(our, node_priv, node_pub, [b1_pub, b2_pub]);

    let frame = channel_text(
        NODENUM_BROADCAST,
        peer,
        0xDF05,
        router.channel_hash(),
        3,
        3,
        0,
        ENTER_DFU_TEXT,
    );
    inbound(&mut router, &frame, 1_000);
    assert!(router.take_pending_ota_dfu_seconds().is_none());
}

#[test]
fn non_admin_pki_peer_is_ignored() {
    let our = 0xE015_0001u32;
    let peer = 0xF015_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x71; 16]), 71);
    let (_b1_priv, b1_pub) = generate_keypair(Some(&[0x72; 16]), 72);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x73; 16]), 73);
    let (stranger_priv, stranger_pub) = generate_keypair(Some(&[0x74; 16]), 74);
    let mut router = setup_router(our, node_priv, node_pub, [b1_pub, b2_pub]);
    router.seed_nodeinfo_peer_for_test(peer, stranger_pub, 1_000);

    let frame = build_pki_text(
        our,
        peer,
        0xDF06,
        &stranger_priv,
        &node_pub,
        ENTER_DFU_TEXT,
        3,
        3,
        0,
        false,
    );
    inbound(&mut router, &frame, 1_100);
    assert!(router.take_pending_ota_dfu_seconds().is_none());
}
