//! Device telemetry interval: default, admin set, persist/reload, zero→default.

use mesh_crypto::{CryptoEngine, CryptoKey, DEFAULT_PSK};
use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};
use mesh_radio::{eu868_config_for_preset, MODEM_DEFAULT_PRESET, MODEM_SHORT_SLOW};
use mesh_routing::{
    decode_admin_message, decode_data_payload_full, decode_routing_payload, encode_admin_message,
    encode_data_payload_opts, min_device_update_interval_secs, AdminMessage, AdminPayload,
    DataEncodeOpts, DeviceMetricsSnapshot, InboundPacket, ModuleConfigPayload, NodeInfoIdentity,
    RelayPlan, Router, WireTelemetryConfig, ADMIN_APP, DEVICE_TELEMETRY_BROADCAST_MS,
    MAGIC_USB_BATTERY_LEVEL, MODULE_CONFIG_TYPE_TELEMETRY, ROUTING_APP, ROUTING_ERROR_BAD_REQUEST,
    ROUTING_ERROR_NONE,
};
use mesh_store::{generate_keypair, ConfigStore, NodeConfig, RamConfigStore};
use static_cell::StaticCell;

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

fn decrypt_pki_admin(tx: &RelayPlan, peer_priv: &[u8; 32], node_pub: &[u8; 32]) -> AdminMessage {
    let header = PacketHeader::decode(&tx.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();
    let cipher = &tx.bytes[PACKET_HEADER_LEN..tx.len as usize];
    let mut engine = CryptoEngine::new();
    engine.set_dh_private_key(peer_priv);
    let mut plain = vec![0u8; cipher.len()];
    assert!(engine.decrypt_curve25519(header.from, node_pub, header.id as u64, cipher, &mut plain));
    let plain_len = cipher.len() - 12;
    let (decoded, payload) = decode_data_payload_full(&plain[..plain_len]).unwrap();
    assert_eq!(decoded.portnum, ADMIN_APP);
    decode_admin_message(&payload).unwrap()
}

fn decrypt_pki_routing_error(tx: &RelayPlan, peer_priv: &[u8; 32], node_pub: &[u8; 32]) -> u32 {
    let header = PacketHeader::decode(&tx.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();
    let cipher = &tx.bytes[PACKET_HEADER_LEN..tx.len as usize];
    let mut engine = CryptoEngine::new();
    engine.set_dh_private_key(peer_priv);
    let mut plain = vec![0u8; cipher.len()];
    assert!(engine.decrypt_curve25519(header.from, node_pub, header.id as u64, cipher, &mut plain));
    let plain_len = cipher.len() - 12;
    let (decoded, payload) = decode_data_payload_full(&plain[..plain_len]).unwrap();
    assert_eq!(decoded.portnum, ROUTING_APP);
    decode_routing_payload(&payload)
        .unwrap()
        .error_reason
        .unwrap()
}

fn seed_metrics(router: &mut Router) {
    router.update_device_metrics(DeviceMetricsSnapshot {
        battery_level: Some(MAGIC_USB_BATTERY_LEVEL),
        voltage_v: Some(0.0),
        channel_utilization: 0.0,
        air_util_tx: 0.0,
        uptime_seconds: 0,
    });
}

fn issue_passkey(
    router: &mut Router,
    our: u32,
    peer: u32,
    b1_priv: &[u8; 32],
    node_pub: &[u8; 32],
    packet_id: u32,
    now: u32,
) -> [u8; 8] {
    let mut get = AdminMessage::default();
    get.payload = AdminPayload::GetModuleConfigRequest(MODULE_CONFIG_TYPE_TELEMETRY);
    let frame = build_pki_admin_frame(
        our,
        peer,
        packet_id,
        b1_priv,
        node_pub,
        &encode_admin_message(&get),
    );
    inbound(router, &frame, now);
    let tx = router.poll_admin_tx(now).expect("telemetry get reply");
    let msg = decrypt_pki_admin(&tx, b1_priv, node_pub);
    assert!(msg.has_session_passkey);
    match msg.payload {
        AdminPayload::GetModuleConfigResponse(ModuleConfigPayload::Telemetry(tel)) => {
            assert_eq!(
                tel.device_update_interval,
                router.admin_state().device_update_interval_secs
            );
        }
        other => panic!("expected telemetry module config, got {other:?}"),
    }
    msg.session_passkey
}

#[test]
fn default_interval_is_twenty_minutes() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let router = ROUTER.init(Router::with_modem_preset(
        0x677a_1caf,
        "",
        MODEM_SHORT_SLOW,
        true,
        key,
        3,
    ));
    seed_metrics(router);

    router.run_maintenance(1_000, 100);
    assert!(router.poll_telemetry_tx(1_000).is_some());

    router.run_maintenance(1_000 + DEVICE_TELEMETRY_BROADCAST_MS - 1, 100);
    assert!(router
        .poll_telemetry_tx(1_000 + DEVICE_TELEMETRY_BROADCAST_MS - 1)
        .is_none());

    router.run_maintenance(1_000 + DEVICE_TELEMETRY_BROADCAST_MS, 100);
    assert!(router
        .poll_telemetry_tx(1_000 + DEVICE_TELEMETRY_BROADCAST_MS)
        .is_some());
}

#[test]
fn zero_means_default_not_disable() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xC0A1_0001u32;
    let peer = 0xD0A1_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x21; 16]), 1);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x22; 16]), 2);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x23; 16]), 3);
    let defaults = NodeConfig::first_boot(our, node_priv, node_pub);
    let mut store = RamConfigStore::new(defaults);
    let cfg = store.load();

    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);
    seed_metrics(router);

    let passkey = issue_passkey(router, our, peer, &b1_priv, &node_pub, 0xA101, 1_000);
    let mut set = AdminMessage::default();
    set.has_session_passkey = true;
    set.session_passkey = passkey;
    set.payload =
        AdminPayload::SetModuleConfig(ModuleConfigPayload::Telemetry(WireTelemetryConfig {
            device_update_interval: 0,
        }));
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xA102,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&set),
    );
    inbound(router, &frame, 1_100);
    let tx = router.poll_admin_tx(1_100).unwrap();
    assert_eq!(
        decrypt_pki_routing_error(&tx, &b1_priv, &node_pub),
        ROUTING_ERROR_NONE
    );

    router.run_maintenance(2_000, 100);
    assert!(router.poll_telemetry_tx(2_000).is_some());
    router.run_maintenance(2_000 + DEVICE_TELEMETRY_BROADCAST_MS, 100);
    assert!(router
        .poll_telemetry_tx(2_000 + DEVICE_TELEMETRY_BROADCAST_MS)
        .is_some());
}

#[test]
fn set_interval_and_persist_reload() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    static ROUTER2: StaticCell<Router> = StaticCell::new();
    let our = 0xC0A2_0001u32;
    let peer = 0xD0A2_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x31; 16]), 1);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x32; 16]), 2);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x33; 16]), 3);
    let defaults = NodeConfig::first_boot(our, node_priv, node_pub);
    let mut store = RamConfigStore::new(defaults);
    let cfg = store.load();

    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);
    seed_metrics(router);

    let passkey = issue_passkey(router, our, peer, &b1_priv, &node_pub, 0xA201, 3_000);
    let interval_secs = 600u32;
    let mut set = AdminMessage::default();
    set.has_session_passkey = true;
    set.session_passkey = passkey;
    set.payload =
        AdminPayload::SetModuleConfig(ModuleConfigPayload::Telemetry(WireTelemetryConfig {
            device_update_interval: interval_secs,
        }));
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xA202,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&set),
    );
    inbound(router, &frame, 3_100);
    let tx = router.poll_admin_tx(3_100).unwrap();
    assert_eq!(
        decrypt_pki_routing_error(&tx, &b1_priv, &node_pub),
        ROUTING_ERROR_NONE
    );
    assert!(router.admin_config_dirty());

    let mut saved = store.load();
    router.write_admin_into_config(&mut saved);
    store.save(&saved).unwrap();
    router.clear_admin_config_dirty();
    assert_eq!(saved.device_update_interval_secs, interval_secs);

    let reloaded = store.load();
    let router2 = ROUTER2.init(Router::new(our));
    router2.load_node_config(&reloaded);
    router2.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router2.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);
    seed_metrics(router2);

    let interval_ms = interval_secs * 1_000;
    router2.run_maintenance(10_000, 100);
    assert!(router2.poll_telemetry_tx(10_000).is_some());
    router2.run_maintenance(10_000 + interval_ms - 1, 100);
    assert!(router2
        .poll_telemetry_tx(10_000 + interval_ms - 1)
        .is_none());
    router2.run_maintenance(10_000 + interval_ms, 100);
    assert!(router2.poll_telemetry_tx(10_000 + interval_ms).is_some());

    let mut get = AdminMessage::default();
    get.payload = AdminPayload::GetModuleConfigRequest(MODULE_CONFIG_TYPE_TELEMETRY);
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xA203,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&get),
    );
    inbound(router2, &frame, 20_000);
    let tx = router2.poll_admin_tx(20_000).unwrap();
    match decrypt_pki_admin(&tx, &b1_priv, &node_pub).payload {
        AdminPayload::GetModuleConfigResponse(ModuleConfigPayload::Telemetry(tel)) => {
            assert_eq!(tel.device_update_interval, interval_secs);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn below_airtime_floor_is_rejected() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xC0A3_0001u32;
    let peer = 0xD0A3_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x41; 16]), 1);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x42; 16]), 2);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x43; 16]), 3);
    let defaults = NodeConfig::first_boot(our, node_priv, node_pub);
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&defaults);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);

    let floor = min_device_update_interval_secs(&eu868_config_for_preset(MODEM_DEFAULT_PRESET));
    assert!(floor > 1, "floor should be >1s so reject path is testable");

    let passkey = issue_passkey(router, our, peer, &b1_priv, &node_pub, 0xA301, 5_000);
    let mut set = AdminMessage::default();
    set.has_session_passkey = true;
    set.session_passkey = passkey;
    set.payload =
        AdminPayload::SetModuleConfig(ModuleConfigPayload::Telemetry(WireTelemetryConfig {
            device_update_interval: floor - 1,
        }));
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xA302,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&set),
    );
    inbound(router, &frame, 5_100);
    let tx = router.poll_admin_tx(5_100).unwrap();
    assert_eq!(
        decrypt_pki_routing_error(&tx, &b1_priv, &node_pub),
        ROUTING_ERROR_BAD_REQUEST
    );
}
