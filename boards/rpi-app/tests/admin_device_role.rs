//! Device role get/set via admin and persistence across store reload (X2).

use mesh_crypto::CryptoEngine;
use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};
use mesh_routing::{
    decode_data_payload_full, decode_routing_payload, encode_admin_message,
    encode_data_payload_opts, AdminPayload, ConfigPayload, DataEncodeOpts, InboundPacket,
    NodeInfoIdentity, RelayPlan, Router, WireDeviceConfig, ADMIN_APP, CONFIG_TYPE_DEVICE,
    DEVICE_ROLE_CLIENT, DEVICE_ROLE_ROUTER, ROUTING_APP, ROUTING_ERROR_NONE,
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

fn decrypt_pki_routing_error(tx: &RelayPlan, peer_priv: &[u8; 32], node_pub: &[u8; 32]) -> u32 {
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
    decode_routing_payload(&payload)
        .unwrap()
        .error_reason
        .unwrap()
}

fn inbound(router: &mut Router, bytes: &[u8], now_ms: u32) {
    let _ = router.process_inbound(
        &InboundPacket {
            radio_id: 0,
            rssi: -70,
            snr: 8,
            bytes,
        },
        now_ms,
    );
}

#[test]
fn set_router_role_survives_reload_with_firmware_boot_order() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xC101_0001u32;
    let peer = 0xD101_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x41; 16]), 41);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x42; 16]), 42);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x43; 16]), 43);
    let defaults = NodeConfig::first_boot(our, node_priv, node_pub);
    let mut store = RamConfigStore::new(defaults);
    let cfg = store.load();

    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);
    assert_eq!(router.device_role(), DEVICE_ROLE_CLIENT);

    let mut get = mesh_routing::AdminMessage::default();
    get.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_DEVICE);
    let frame = build_pki_admin_frame(
        our,
        peer,
        1,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&get),
    );
    inbound(router, &frame, 1_000);
    let _ = router.poll_admin_tx(1_000);
    let passkey = router.admin_state().session_passkey;

    let mut set = mesh_routing::AdminMessage::default();
    set.payload = AdminPayload::SetConfig(ConfigPayload::Device(WireDeviceConfig {
        role: DEVICE_ROLE_ROUTER,
    }));
    set.has_session_passkey = true;
    set.session_passkey = passkey;
    let frame = build_pki_admin_frame(
        our,
        peer,
        2,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&set),
    );
    inbound(router, &frame, 2_000);
    let set_tx = router
        .poll_admin_tx(2_000)
        .expect("device set completion reply");
    assert_eq!(
        decrypt_pki_routing_error(&set_tx, &b1_priv, &node_pub),
        ROUTING_ERROR_NONE
    );
    assert_eq!(router.device_role(), DEVICE_ROLE_ROUTER);
    assert!(router.admin_config_dirty());

    let mut saved = store.load();
    router.write_admin_into_config(&mut saved);
    store.save(&saved).unwrap();
    router.clear_admin_config_dirty();

    let reloaded = store.load();
    assert_eq!(reloaded.device_role, DEVICE_ROLE_ROUTER as u8);

    // Same order as boards/nrf52840/src/main.rs: load, then set_node_identity(for_node).
    static ROUTER2: StaticCell<Router> = StaticCell::new();
    let router2 = ROUTER2.init(Router::new(our));
    router2.load_node_config(&reloaded);
    router2.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    assert_eq!(
        router2.device_role(),
        DEVICE_ROLE_ROUTER,
        "identity rebuild must not wipe the persisted role"
    );
    assert_eq!(router2.admin_state().device_role, DEVICE_ROLE_ROUTER);

    let mut saved2 = reloaded;
    router2.write_admin_into_config(&mut saved2);
    assert_eq!(
        saved2.device_role, DEVICE_ROLE_ROUTER as u8,
        "export after identity rebuild must still save ROUTER"
    );
}

#[test]
fn corrupt_flash_role_clamps_to_client() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xC102_0001u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x51; 16]), 51);
    let mut cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    cfg.device_role = 99;
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    assert_eq!(router.device_role(), DEVICE_ROLE_CLIENT);
    let mut exported = cfg;
    router.write_admin_into_config(&mut exported);
    assert_eq!(exported.device_role, DEVICE_ROLE_CLIENT as u8);
}
