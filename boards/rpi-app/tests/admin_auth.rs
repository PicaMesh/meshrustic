use mesh_crypto::{CryptoEngine, CryptoKey, DEFAULT_PSK};
use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};
use mesh_radio::{primary_channel_hash, MODEM_DEFAULT_PRESET, MODEM_SHORT_FAST};
use mesh_routing::{
    build_app_wire_frame, decode_admin_message, decode_data_payload_full, decode_routing_payload,
    encode_admin_message, encode_data_payload_opts, try_decrypt_data_full, AdminPayload,
    ConfigPayload, DataEncodeOpts, InboundPacket, NodeInfoIdentity, Router, WireLoRaConfig,
    WireSecurityConfig, ADMIN_APP, CONFIG_TYPE_LORA, CONFIG_TYPE_SECURITY, REGION_EU_868,
    ROUTING_APP, ROUTING_ERROR_ADMIN_BAD_SESSION_KEY, ROUTING_ERROR_ADMIN_PUBLIC_KEY_UNAUTHORIZED,
    ROUTING_ERROR_PKI_FAILED,
};
use mesh_store::{
    generate_keypair, ConfigStore, NodeConfig, RamConfigStore, BUILTIN_ADMIN_PUBLIC_KEYS,
    EMPTY_ADMIN_KEY,
};
use static_cell::StaticCell;

fn channel_key() -> CryptoKey {
    CryptoKey::from_bytes(&DEFAULT_PSK)
}

fn channel_hash() -> u8 {
    primary_channel_hash("", MODEM_DEFAULT_PRESET, true, &DEFAULT_PSK)
}

fn channel_admin_frame(to: u32, from: u32, id: u32, inner: &[u8]) -> Vec<u8> {
    let (len, frame) = build_app_wire_frame(
        to,
        from,
        id,
        channel_hash(),
        3,
        3,
        false,
        &channel_key(),
        ADMIN_APP,
        inner,
        DataEncodeOpts::default(),
        0,
    )
    .unwrap();
    frame[..len as usize].to_vec()
}

fn build_pki_admin_frame(
    to: u32,
    from: u32,
    packet_id: u32,
    from_priv: &[u8; 32],
    to_pub: &[u8; 32],
    inner: &[u8],
) -> Vec<u8> {
    let plaintext = encode_data_payload_opts(
        ADMIN_APP,
        inner,
        DataEncodeOpts {
            want_response: true,
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
    let header = PacketHeader::from_fields(to, from, packet_id, 0, 3, 3, false, false, 0, 0);
    let mut out = vec![0u8; PACKET_HEADER_LEN + cipher.len()];
    header.encode_to((&mut out[..PACKET_HEADER_LEN]).try_into().unwrap());
    out[PACKET_HEADER_LEN..].copy_from_slice(&cipher);
    out
}

fn pki_inbound(router: &mut Router, frame: &[u8], now: u32) {
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

fn session_via_pki(
    router: &mut Router,
    peer: u32,
    peer_priv: &[u8; 32],
    node_pub: &[u8; 32],
    packet_id: u32,
    now: u32,
) -> [u8; 8] {
    let get = mesh_routing::AdminMessage {
        payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA),
        ..Default::default()
    };
    let frame = build_pki_admin_frame(
        router.node_num(),
        peer,
        packet_id,
        peer_priv,
        node_pub,
        &encode_admin_message(&get),
    );
    pki_inbound(router, &frame, now);
    let _ = router.poll_admin_tx(now);
    router.admin_state().session_passkey
}

fn decrypt_pki_routing_nak(
    tx: &mesh_routing::RelayPlan,
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
        "expected PKI-encrypted routing NAK"
    );
    let plain_len = cipher.len() - 12;
    let (decoded, payload) = decode_data_payload_full(&plain[..plain_len]).unwrap();
    assert_eq!(decoded.portnum, ROUTING_APP);
    decode_routing_payload(&payload)
        .unwrap()
        .error_reason
        .unwrap()
}

#[test]
fn unauthorized_cannot_change_config() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xA001_0001u32;
    let peer = 0xB001_0002u32;
    let (node_priv, node_pub) = generate_keypair([0x10; 32]);
    let (peer_priv, peer_pub) = generate_keypair([0x20; 32]);
    let (b1_priv, b1_pub) = generate_keypair([0x30; 32]);
    let (_b2_priv, b2_pub) = generate_keypair([0x40; 32]);
    let cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);
    router.seed_nodeinfo_peer_for_test(peer, peer_pub, 50);
    let _ = b1_priv;

    let set = mesh_routing::AdminMessage {
        payload: AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
            use_preset: true,
            modem_preset: MODEM_SHORT_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
            config_ok_to_mqtt: true,
        })),
        has_session_passkey: true,
        session_passkey: [1; 8],
    };
    let frame = build_pki_admin_frame(
        our,
        peer,
        1,
        &peer_priv,
        &node_pub,
        &encode_admin_message(&set),
    );
    pki_inbound(router, &frame, 100);
    assert_eq!(router.modem_preset(), MODEM_DEFAULT_PRESET);
    let tx = router.poll_admin_tx(100).unwrap();
    assert_eq!(
        decrypt_pki_routing_nak(&tx, &peer_priv, &node_pub),
        ROUTING_ERROR_ADMIN_PUBLIC_KEY_UNAUTHORIZED
    );
}

#[test]
fn builtin1_and_builtin2_can_set_lora() {
    static ROUTERS: [StaticCell<Router>; 2] = [StaticCell::new(), StaticCell::new()];
    for (i, cell) in ROUTERS.iter().enumerate() {
        let our = 0xA002_0001u32 + i as u32;
        let peer = 0xB002_0002u32;
        let (node_priv, node_pub) = generate_keypair([0x50 + i as u8; 32]);
        let (b1_priv, b1_pub) = generate_keypair([0x60 + i as u8; 32]);
        let (b2_priv, b2_pub) = generate_keypair([0x70 + i as u8; 32]);
        let cfg = NodeConfig::first_boot(our, node_priv, node_pub);
        let router = cell.init(Router::new(our));
        router.load_node_config(&cfg);
        router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
        router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);

        let (admin_priv, _admin_pub) = if i == 0 {
            (b1_priv, b1_pub)
        } else {
            (b2_priv, b2_pub)
        };
        let passkey = session_via_pki(router, peer, &admin_priv, &node_pub, 0x10, 1_000);

        let set = mesh_routing::AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
                use_preset: true,
                modem_preset: MODEM_SHORT_FAST as u32,
                region: REGION_EU_868,
                hop_limit: 3,
                tx_power: 27,
                config_ok_to_mqtt: true,
            })),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let frame = build_pki_admin_frame(
            our,
            peer,
            0x11,
            &admin_priv,
            &node_pub,
            &encode_admin_message(&set),
        );
        pki_inbound(router, &frame, 2_000);
        let _ = router.poll_admin_tx(2_000);
        assert_eq!(router.modem_preset(), MODEM_SHORT_FAST);
    }
}

#[test]
fn flash_admin_key_pki_round_trip_and_get_omits_builtins() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xA003_0001u32;
    let peer = 0xB003_0002u32;
    let (admin_priv, admin_pub) = generate_keypair([0xAB; 32]);
    let (node_priv, node_pub) = generate_keypair([0xCD; 32]);
    let mut cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    cfg.admin_public_keys[0] = admin_pub;
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));

    let passkey = session_via_pki(router, peer, &admin_priv, &node_pub, 0x30, 3_000);

    let set = mesh_routing::AdminMessage {
        payload: AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
            use_preset: true,
            modem_preset: MODEM_SHORT_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
            config_ok_to_mqtt: true,
        })),
        has_session_passkey: true,
        session_passkey: passkey,
    };
    let frame = build_pki_admin_frame(
        our,
        peer,
        0x31,
        &admin_priv,
        &node_pub,
        &encode_admin_message(&set),
    );
    pki_inbound(router, &frame, 3_100);
    let _ = router.poll_admin_tx(3_100);
    assert_eq!(router.modem_preset(), MODEM_SHORT_FAST);

    let sget = mesh_routing::AdminMessage {
        payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_SECURITY),
        has_session_passkey: true,
        session_passkey: router.admin_state().session_passkey,
    };
    let frame = build_pki_admin_frame(
        our,
        peer,
        0x32,
        &admin_priv,
        &node_pub,
        &encode_admin_message(&sget),
    );
    pki_inbound(router, &frame, 3_200);
    let _ = router.poll_admin_tx(3_200);

    let msg = mesh_routing::AdminMessage {
        payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_SECURITY),
        ..Default::default()
    };
    let out = mesh_routing::handle_admin(
        router.admin_state_mut(),
        &admin_pub,
        &NodeInfoIdentity::for_node(our, node_pub),
        our,
        &DEFAULT_PSK,
        channel_hash(),
        mesh_routing::DEVICE_ROLE_ROUTER,
        &encode_admin_message(&msg),
        3_250,
    );
    let sec = match out.response.unwrap().payload {
        AdminPayload::GetConfigResponse(ConfigPayload::Security(s)) => s,
        other => panic!("{other:?}"),
    };
    assert_eq!(sec.admin_key_count, 1);
    assert_eq!(sec.admin_keys[0], admin_pub);
    assert!(sec.has_public_key);
    assert_eq!(sec.public_key, node_pub);
    assert!(sec.has_private_key);
    assert_eq!(sec.private_key, node_priv);
    assert_ne!(sec.admin_keys[0], BUILTIN_ADMIN_PUBLIC_KEYS[0]);
    assert_ne!(sec.admin_keys[0], BUILTIN_ADMIN_PUBLIC_KEYS[1]);
    let _ = WireSecurityConfig::default();
}

#[test]
fn stale_pki_then_channel_admin_cannot_mutate() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xA006_0001u32;
    let peer = 0xB006_0002u32;
    let (admin_priv, admin_pub) = generate_keypair([0x11; 32]);
    let (node_priv, node_pub) = generate_keypair([0x22; 32]);
    let mut cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    cfg.admin_public_keys[0] = admin_pub;
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));

    let passkey = session_via_pki(router, peer, &admin_priv, &node_pub, 0x60, 6_000);

    let set = mesh_routing::AdminMessage {
        payload: AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
            use_preset: true,
            modem_preset: MODEM_SHORT_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
            config_ok_to_mqtt: true,
        })),
        has_session_passkey: true,
        session_passkey: passkey,
    };
    let frame = channel_admin_frame(our, peer, 0x61, &encode_admin_message(&set));
    pki_inbound(router, &frame, 6_100);
    assert_eq!(router.modem_preset(), MODEM_DEFAULT_PRESET);
    let tx = router.poll_admin_tx(6_100).unwrap();
    let mut cipher = tx.bytes[PACKET_HEADER_LEN..tx.len as usize].to_vec();
    let header = PacketHeader::decode(&tx.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();
    let (decoded, payload) = try_decrypt_data_full(
        &channel_key(),
        header.from,
        header.id,
        channel_hash(),
        header.channel,
        &mut cipher,
    )
    .unwrap();
    assert_eq!(decoded.portnum, ROUTING_APP);
    assert_eq!(
        decode_routing_payload(&payload).unwrap().error_reason,
        Some(ROUTING_ERROR_ADMIN_PUBLIC_KEY_UNAUTHORIZED)
    );
}

#[test]
fn clearing_flash_keys_leaves_builtins() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xA004_0001u32;
    let peer = 0xB004_0002u32;
    let (node_priv, node_pub) = generate_keypair([0x81; 32]);
    let (b1_priv, b1_pub) = generate_keypair([0x82; 32]);
    let (b2_priv, b2_pub) = generate_keypair([0x83; 32]);
    let mut cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    cfg.admin_public_keys[0] = [0x77; 32];
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);

    let passkey = session_via_pki(router, peer, &b1_priv, &node_pub, 0x40, 4_000);
    let set = mesh_routing::AdminMessage {
        payload: AdminPayload::SetConfig(ConfigPayload::Security(WireSecurityConfig::default())),
        has_session_passkey: true,
        session_passkey: passkey,
    };
    let frame = build_pki_admin_frame(
        our,
        peer,
        0x41,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&set),
    );
    pki_inbound(router, &frame, 4_100);
    let _ = router.poll_admin_tx(4_100);
    assert_eq!(router.admin_state().admin_public_keys[0], EMPTY_ADMIN_KEY);
    let _ = session_via_pki(router, peer, &b2_priv, &node_pub, 0x42, 4_200);
}

#[test]
fn bad_session_key_rejects_set() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xA005_0001u32;
    let peer = 0xB005_0002u32;
    let (node_priv, node_pub) = generate_keypair([0x91; 32]);
    let (b1_priv, b1_pub) = generate_keypair([0x92; 32]);
    let (_b2_priv, b2_pub) = generate_keypair([0x93; 32]);
    let cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);
    let _ = session_via_pki(router, peer, &b1_priv, &node_pub, 0x50, 5_000);

    let set = mesh_routing::AdminMessage {
        payload: AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
            use_preset: true,
            modem_preset: MODEM_SHORT_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
            config_ok_to_mqtt: true,
        })),
        has_session_passkey: true,
        session_passkey: [0xFF; 8],
    };
    let frame = build_pki_admin_frame(
        our,
        peer,
        0x51,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&set),
    );
    pki_inbound(router, &frame, 5_100);
    assert_eq!(router.modem_preset(), MODEM_DEFAULT_PRESET);
    let tx = router.poll_admin_tx(5_100).unwrap();
    assert_eq!(
        decrypt_pki_routing_nak(&tx, &b1_priv, &node_pub),
        ROUTING_ERROR_ADMIN_BAD_SESSION_KEY
    );
}

#[test]
fn pki_decrypt_failure_nak_is_pki_encrypted() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xA007_0001u32;
    let peer = 0xB007_0002u32;
    let (node_priv, node_pub) = generate_keypair([0xA1; 32]);
    let (peer_priv, peer_pub) = generate_keypair([0xA2; 32]);
    let (wrong_priv, _wrong_pub) = generate_keypair([0xA3; 32]);
    let cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.seed_nodeinfo_peer_for_test(peer, peer_pub, 50);

    let get = mesh_routing::AdminMessage {
        payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA),
        ..Default::default()
    };
    let frame = build_pki_admin_frame(
        our,
        peer,
        0x70,
        &wrong_priv,
        &node_pub,
        &encode_admin_message(&get),
    );
    pki_inbound(router, &frame, 7_000);
    let tx = router.poll_admin_tx(7_000).unwrap();
    assert_eq!(
        decrypt_pki_routing_nak(&tx, &peer_priv, &node_pub),
        ROUTING_ERROR_PKI_FAILED
    );
}

#[test]
fn ram_store_survives_admin_lora_change() {
    let defaults = NodeConfig::first_boot(1, [1; 32], [2; 32]);
    let mut store = RamConfigStore::new(defaults);
    let mut cfg = store.load();
    cfg.lora.apply_modem_preset(MODEM_SHORT_FAST);
    store.save(&cfg).unwrap();
    assert_eq!(store.load().lora.modem_preset, MODEM_SHORT_FAST);
}

#[allow(dead_code)]
fn _decode_admin_message_keep(x: &[u8]) {
    let _ = decode_admin_message(x);
}
