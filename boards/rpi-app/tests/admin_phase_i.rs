//! Phase I: get_channel, settings-load burst, Security identity keys, DEVICE stub.

use mesh_crypto::CryptoEngine;
use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};
use mesh_routing::{
    decode_admin_message, decode_data_payload_full, decode_routing_payload, encode_admin_message,
    encode_data_payload_opts, AdminMessage, AdminPayload, ConfigPayload, DataEncodeOpts,
    DecodedData, InboundPacket, NodeInfoIdentity, RelayPlan, Router, WireSecurityConfig, ADMIN_APP,
    CHANNEL_ROLE_DISABLED, CHANNEL_ROLE_PRIMARY, CONFIG_TYPE_DEVICE, CONFIG_TYPE_LORA,
    CONFIG_TYPE_SECURITY, DEVICE_ROLE_ROUTER, ROUTING_APP, ROUTING_ERROR_NONE,
};
use mesh_store::{generate_keypair, ConfigStore, NodeConfig, RamConfigStore, EMPTY_ADMIN_KEY};
use static_cell::StaticCell;

fn build_pki_admin_frame(
    to: u32,
    from: u32,
    packet_id: u32,
    from_priv: &[u8; 32],
    to_pub: &[u8; 32],
    inner: &[u8],
) -> Vec<u8> {
    build_pki_admin_frame_opts(to, from, packet_id, from_priv, to_pub, inner, false)
}

fn build_pki_admin_frame_opts(
    to: u32,
    from: u32,
    packet_id: u32,
    from_priv: &[u8; 32],
    to_pub: &[u8; 32],
    inner: &[u8],
    want_ack: bool,
) -> Vec<u8> {
    build_pki_admin_frame_full(to, from, packet_id, from_priv, to_pub, inner, want_ack, true)
}

fn build_pki_admin_frame_full(
    to: u32,
    from: u32,
    packet_id: u32,
    from_priv: &[u8; 32],
    to_pub: &[u8; 32],
    inner: &[u8],
    want_ack: bool,
    want_response: bool,
) -> Vec<u8> {
    let plaintext = encode_data_payload_opts(
        ADMIN_APP,
        inner,
        DataEncodeOpts {
            want_response,
            ..Default::default()
        },
    );
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
    let header = PacketHeader::from_fields(to, from, packet_id, 0, 3, 3, want_ack, false, 0, 0);
    let mut out = vec![0u8; PACKET_HEADER_LEN + cipher.len()];
    header.encode_to((&mut out[..PACKET_HEADER_LEN]).try_into().unwrap());
    out[PACKET_HEADER_LEN..].copy_from_slice(&cipher);
    out
}

fn decrypt_pki_routing_error(
    tx: &RelayPlan,
    peer_priv: &[u8; 32],
    node_pub: &[u8; 32],
) -> u32 {
    let header = PacketHeader::decode(&tx.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();
    let cipher = &tx.bytes[PACKET_HEADER_LEN..tx.len as usize];
    let mut engine = CryptoEngine::new();
    engine.set_dh_private_key(peer_priv);
    let mut plain = vec![0u8; cipher.len()];
    assert!(
        engine.decrypt_curve25519(header.from, node_pub, header.id as u64, cipher, &mut plain),
        "expected PKI-encrypted routing reply"
    );
    let plain_len = cipher.len() - 12;
    let (decoded, payload) = decode_data_payload_full(&plain[..plain_len]).unwrap();
    assert_eq!(decoded.portnum, ROUTING_APP);
    decode_routing_payload(&payload).unwrap().error_reason.unwrap()
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

fn decrypt_pki_admin(
    tx: &RelayPlan,
    peer_priv: &[u8; 32],
    node_pub: &[u8; 32],
) -> (DecodedData, AdminMessage) {
    let header = PacketHeader::decode(&tx.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();
    let cipher = &tx.bytes[PACKET_HEADER_LEN..tx.len as usize];
    let mut engine = CryptoEngine::new();
    engine.set_dh_private_key(peer_priv);
    let mut plain = vec![0u8; cipher.len()];
    assert!(
        engine.decrypt_curve25519(header.from, node_pub, header.id as u64, cipher, &mut plain),
        "expected PKI-encrypted admin reply"
    );
    let plain_len = cipher.len() - 12;
    let (decoded, payload) = decode_data_payload_full(&plain[..plain_len]).unwrap();
    assert_eq!(decoded.portnum, ADMIN_APP);
    (decoded, decode_admin_message(&payload).unwrap())
}

fn setup_router(
    cell: &'static StaticCell<Router>,
    our: u32,
    node_priv: [u8; 32],
    node_pub: [u8; 32],
    b1_pub: [u8; 32],
    b2_pub: [u8; 32],
) -> &'static mut Router {
    let cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    let router = cell.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);
    router.set_device_role(DEVICE_ROLE_ROUTER);
    router
}

#[test]
fn get_channel_primary_psk_and_disabled() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xE001_0001u32;
    let peer = 0xF001_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x01; 16]), 1);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x02; 16]), 2);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x03; 16]), 3);
    let router = setup_router(&ROUTER, our, node_priv, node_pub, b1_pub, b2_pub);

    let mut get = AdminMessage::default();
    get.payload = AdminPayload::GetChannelRequest(1);
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xC001,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&get),
    );
    inbound(router, &frame, 1_000);
    let tx = router.poll_admin_tx(1_000).unwrap();
    match decrypt_pki_admin(&tx, &b1_priv, &node_pub).1.payload {
        AdminPayload::GetChannelResponse(ch) => {
            assert_eq!(ch.index, 0);
            assert_eq!(ch.role, CHANNEL_ROLE_PRIMARY);
            assert_eq!(ch.settings.psk_len, 1);
            assert_eq!(ch.settings.psk[0], 0x01);
        }
        other => panic!("{:?}", other),
    }

    let mut get2 = AdminMessage::default();
    get2.payload = AdminPayload::GetChannelRequest(2);
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xC002,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&get2),
    );
    inbound(router, &frame, 1_100);
    let tx = router.poll_admin_tx(1_100).unwrap();
    match decrypt_pki_admin(&tx, &b1_priv, &node_pub).1.payload {
        AdminPayload::GetChannelResponse(ch) => {
            assert_eq!(ch.index, 1);
            assert_eq!(ch.role, CHANNEL_ROLE_DISABLED);
        }
        other => panic!("{:?}", other),
    }
}

#[test]
fn field_log_channel_then_lora_both_admin_replies() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xE002_0001u32;
    let peer = 0xF002_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x11; 16]), 11);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x12; 16]), 12);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x13; 16]), 13);
    let router = setup_router(&ROUTER, our, node_priv, node_pub, b1_pub, b2_pub);

    let mut ch = AdminMessage::default();
    ch.payload = AdminPayload::GetChannelRequest(1);
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xD001,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&ch),
    );
    inbound(router, &frame, 2_000);

    let mut lora = AdminMessage::default();
    lora.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA);
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xD002,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&lora),
    );
    inbound(router, &frame, 2_010);

    let tx1 = router.poll_admin_tx(2_010).unwrap();
    let tx2 = router.poll_admin_tx(2_010).unwrap();
    let mut payloads = [
        decrypt_pki_admin(&tx1, &b1_priv, &node_pub).1.payload,
        decrypt_pki_admin(&tx2, &b1_priv, &node_pub).1.payload,
    ];
    // Order is FIFO by next_tx_ms; accept either order.
    let mut saw_channel = false;
    let mut saw_lora = false;
    for p in &payloads {
        match p {
            AdminPayload::GetChannelResponse(_) => saw_channel = true,
            AdminPayload::GetConfigResponse(ConfigPayload::Lora(_)) => saw_lora = true,
            other => panic!("unexpected admin reply: {other:?}"),
        }
    }
    assert!(saw_channel && saw_lora, "both channel and LoRa AdminMessage replies required");
    let _ = &mut payloads;
}

#[test]
fn security_get_set_persist_and_identity_immutable() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xE003_0001u32;
    let peer = 0xF003_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x21; 16]), 21);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x22; 16]), 22);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x23; 16]), 23);
    let (flash_priv, flash_pub) = generate_keypair(Some(&[0x24; 16]), 24);
    let _ = flash_priv;

    let defaults = NodeConfig::first_boot(our, node_priv, node_pub);
    let mut store = RamConfigStore::new(defaults);
    let cfg = store.load();
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);
    router.set_device_role(DEVICE_ROLE_ROUTER);

    // Seed session.
    let mut get = AdminMessage::default();
    get.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_SECURITY);
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xE001,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&get),
    );
    inbound(router, &frame, 3_000);
    let tx = router.poll_admin_tx(3_000).unwrap();
    let (_meta, sec_msg) = decrypt_pki_admin(&tx, &b1_priv, &node_pub);
    match &sec_msg.payload {
        AdminPayload::GetConfigResponse(ConfigPayload::Security(sec)) => {
            assert_eq!(sec.public_key, node_pub);
            assert_eq!(sec.private_key, node_priv);
            assert_eq!(sec.admin_key_count, 0);
            assert!(!sec.admin_channel_enabled);
        }
        other => panic!("{:?}", other),
    }
    let passkey = sec_msg.session_passkey;

    // Set flash admin key + attempt identity rotation (must be ignored).
    let mut sec = WireSecurityConfig::default();
    sec.has_public_key = true;
    sec.public_key = [0xDE; 32];
    sec.has_private_key = true;
    sec.private_key = [0xAD; 32];
    sec.admin_keys[0] = flash_pub;
    sec.admin_key_count = 1;
    let mut set = AdminMessage::default();
    set.payload = AdminPayload::SetConfig(ConfigPayload::Security(sec));
    set.has_session_passkey = true;
    set.session_passkey = passkey;
    // Field log 23:32: client set omitted want_response; still must get Routing NONE.
    let frame = build_pki_admin_frame_full(
        our,
        peer,
        0xE002,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&set),
        true,
        false,
    );
    inbound(router, &frame, 3_100);
    assert!(
        router.poll_ack_tx(3_100).is_none(),
        "admin Routing NONE reply suppresses a separate WantAck ACK"
    );
    let set_tx = router.poll_admin_tx(3_100).expect("set completion reply");
    let set_hdr = PacketHeader::decode(&set_tx.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();
    assert!(
        set_hdr.want_ack,
        "completion reply copies WantAck so it alone stops reliable retransmit"
    );
    assert!(
        router.has_pending_reliable(set_hdr.id),
        "WantAck admin completion must retransmit until peer ACKs"
    );
    assert_eq!(
        decrypt_pki_routing_error(&set_tx, &b1_priv, &node_pub),
        ROUTING_ERROR_NONE,
        "mutating admin set completes with ROUTING_APP Error_NONE even without want_response"
    );
    // Client WantAck retry: hop_limit=0 re-ACK only — no second admin completion.
    inbound(router, &frame, 3_150);
    assert!(
        router.poll_admin_tx(3_150).is_none(),
        "WantAck dupe must not re-run admin / enqueue another completion"
    );
    let dupe_ack = router.poll_ack_tx(3_150).expect("WantAck dupe re-ACK on router");
    let dupe_hdr = PacketHeader::decode(&dupe_ack.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();
    assert_eq!(dupe_hdr.hop_limit, 0, "dupe WantAck re-ACK is hop_limit=0");
    let dupe_data = {
        let cipher = &dupe_ack.bytes[PACKET_HEADER_LEN..dupe_ack.len as usize];
        let mut engine = CryptoEngine::new();
        engine.set_dh_private_key(&b1_priv);
        let mut plain = vec![0u8; cipher.len()];
        assert!(engine.decrypt_curve25519(
            dupe_hdr.from,
            &node_pub,
            dupe_hdr.id as u64,
            cipher,
            &mut plain
        ));
        let (decoded, _) = decode_data_payload_full(&plain[..cipher.len() - 12]).unwrap();
        decoded
    };
    assert_eq!(dupe_data.portnum, ROUTING_APP);
    assert_eq!(dupe_data.request_id, 0xE002);
    assert!(router.admin_config_dirty());
    assert_eq!(router.admin_state().public_key, node_pub);
    assert_eq!(router.admin_state().private_key, node_priv);
    assert_eq!(router.admin_state().admin_public_keys[0], flash_pub);
    assert!(
        router.take_pending_reboot_seconds().is_none(),
        "admin_key-only Security set must not reboot"
    );

    let mut saved = store.load();
    router.write_admin_into_config(&mut saved);
    store.save(&saved).unwrap();
    router.clear_admin_config_dirty();

    let reloaded = store.load();
    assert_eq!(reloaded.public_key, node_pub);
    assert_eq!(reloaded.private_key, node_priv);
    assert_eq!(reloaded.admin_public_keys[0], flash_pub);

    // Clear flash keys.
    let mut clear = AdminMessage::default();
    clear.payload = AdminPayload::SetConfig(ConfigPayload::Security(WireSecurityConfig::default()));
    clear.has_session_passkey = true;
    clear.session_passkey = router.admin_state().session_passkey;
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xE003,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&clear),
    );
    inbound(router, &frame, 3_200);
    let _ = router.poll_admin_tx(3_200);
    assert_eq!(router.admin_state().admin_public_keys[0], EMPTY_ADMIN_KEY);
}

#[test]
fn get_device_role_and_module_config_stub() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xE004_0001u32;
    let peer = 0xF004_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x31; 16]), 31);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x32; 16]), 32);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x33; 16]), 33);
    let router = setup_router(&ROUTER, our, node_priv, node_pub, b1_pub, b2_pub);

    let mut get = AdminMessage::default();
    get.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_DEVICE);
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xF001,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&get),
    );
    inbound(router, &frame, 4_000);
    let tx = router.poll_admin_tx(4_000).unwrap();
    match decrypt_pki_admin(&tx, &b1_priv, &node_pub).1.payload {
        AdminPayload::GetConfigResponse(ConfigPayload::Device(dev)) => {
            assert_eq!(dev.role, DEVICE_ROLE_ROUTER);
        }
        other => panic!("{:?}", other),
    }

    let mut modreq = AdminMessage::default();
    modreq.payload = AdminPayload::GetModuleConfigRequest(0);
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xF002,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&modreq),
    );
    inbound(router, &frame, 4_100);
    let tx = router.poll_admin_tx(4_100).unwrap();
    assert!(matches!(
        decrypt_pki_admin(&tx, &b1_priv, &node_pub).1.payload,
        AdminPayload::GetModuleConfigResponse
    ));
}

#[test]
fn rapid_multi_get_queue_and_rate_limit() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xE005_0001u32;
    let peer = 0xF005_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x41; 16]), 41);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x42; 16]), 42);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x43; 16]), 43);
    let router = setup_router(&ROUTER, our, node_priv, node_pub, b1_pub, b2_pub);

    let requests = [
        (0xA001u32, AdminPayload::GetChannelRequest(1)),
        (0xA002, AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA)),
        (0xA003, AdminPayload::GetConfigRequest(CONFIG_TYPE_DEVICE)),
        (0xA004, AdminPayload::GetConfigRequest(CONFIG_TYPE_SECURITY)),
    ];

    let now = 5_000u32;
    for (id, payload) in requests {
        let mut msg = AdminMessage::default();
        msg.payload = payload;
        let frame = build_pki_admin_frame(
            our,
            peer,
            id,
            &b1_priv,
            &node_pub,
            &encode_admin_message(&msg),
        );
        inbound(router, &frame, now);
    }

    let mut replies = 0;
    while let Some(tx) = router.poll_admin_tx(now) {
        let (_meta, msg) = decrypt_pki_admin(&tx, &b1_priv, &node_pub);
        assert!(matches!(
            msg.payload,
            AdminPayload::GetChannelResponse(_)
                | AdminPayload::GetConfigResponse(_)
                | AdminPayload::GetModuleConfigResponse
        ));
        replies += 1;
    }
    assert_eq!(replies, 4, "all four rapid admin gets must produce replies");
}

#[test]
fn pki_want_ack_ack_is_pki_and_admin_sets_request_id() {
    // Field log 2026-08-10 21:20: PKI admin WantAck got channel-PSK ACKs → app retransmits;
    // admin replies must set Data.request_id and (when WantAck) serve as the sole ACK.
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xE006_0001u32;
    let peer = 0xF006_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x51; 16]), 51);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x52; 16]), 52);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x53; 16]), 53);
    let router = setup_router(&ROUTER, our, node_priv, node_pub, b1_pub, b2_pub);

    let req_id = 0x8f8b_7001u32;
    let mut get = AdminMessage::default();
    get.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_SECURITY);
    let frame = build_pki_admin_frame_opts(
        our,
        peer,
        req_id,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&get),
        true,
    );
    inbound(router, &frame, 6_000);

    assert!(
        router.poll_ack_tx(6_000).is_none(),
        "AdminMessage reply suppresses a separate WantAck ACK"
    );

    let admin_tx = router.poll_admin_tx(6_000).expect("admin reply");
    let hdr = PacketHeader::decode(&admin_tx.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();
    assert!(hdr.want_ack, "admin reply copies request WantAck");
    let (meta, msg) = decrypt_pki_admin(&admin_tx, &b1_priv, &node_pub);
    assert_eq!(meta.request_id, req_id, "admin reply Data.request_id must echo request");
    assert_eq!(meta.reply_id, req_id);
    // Reply must be PKI (Ch=0) so pure-PKI clients accept it as the WantAck stop.
    assert_eq!(hdr.channel, 0);
    match msg.payload {
        AdminPayload::GetConfigResponse(ConfigPayload::Security(sec)) => {
            assert_eq!(sec.public_key, node_pub);
            assert_eq!(sec.private_key, node_priv);
        }
        other => panic!("{:?}", other),
    }
}
