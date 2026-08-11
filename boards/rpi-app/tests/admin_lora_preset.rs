//! LoRa modem preset get/set via admin and persistence across store reload.

use mesh_crypto::{CryptoEngine, DEFAULT_PSK};
use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};
use mesh_radio::{
    eu868_config_for_preset, primary_channel_hash, MODEM_SHORT_FAST, MODEM_SHORT_SLOW,
};
use mesh_routing::{
    decode_data_payload_full, decode_routing_payload, encode_admin_message, encode_data_payload_opts,
    AdminPayload, ConfigPayload, DataEncodeOpts, InboundPacket, NodeInfoIdentity, RelayPlan, Router,
    WireLoRaConfig, ADMIN_APP, CONFIG_TYPE_LORA, REGION_EU_868, ROUTING_APP, ROUTING_ERROR_NONE,
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

#[test]
fn set_lora_persists_and_reloads_channel_hash() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xC001_0001u32;
    let peer = 0xD001_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x11; 16]), 1);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x12; 16]), 2);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x13; 16]), 3);
    let defaults = NodeConfig::first_boot(our, node_priv, node_pub);
    let mut store = RamConfigStore::new(defaults);
    let cfg = store.load();

    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);

    assert_eq!(
        router.channel_hash(),
        primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK)
    );

    let mut get = mesh_routing::AdminMessage::default();
    get.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA);
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
    set.payload = AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
        use_preset: true,
        modem_preset: MODEM_SHORT_FAST as u32,
        region: REGION_EU_868,
        hop_limit: 3,
        tx_power: 27,
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
    let set_tx = router.poll_admin_tx(2_000).expect("LoRa set completion reply");
    assert_eq!(
        decrypt_pki_routing_error(&set_tx, &b1_priv, &node_pub),
        ROUTING_ERROR_NONE,
        "LoRa set_config needs the same want_response → ROUTING NONE as Security"
    );
    assert_eq!(router.modem_preset(), MODEM_SHORT_FAST);
    let expected_hash = primary_channel_hash("", MODEM_SHORT_FAST, true, &DEFAULT_PSK);
    assert_eq!(router.channel_hash(), expected_hash);
    // Soft radio reinit — never schedule MCU reset (UF2 boards enter upload mode).
    assert!(
        router.take_pending_radio_reinit(),
        "LoRa preset change must request soft radio reinit"
    );
    assert!(router.take_pending_reboot_seconds().is_none());

    // Board soft-reinit uses eu868_config_for_preset(router.modem_preset()).
    let radio = eu868_config_for_preset(router.modem_preset());
    assert_eq!(radio.spreading_factor, 7, "SHORT_FAST must be SF7 (was SF8 on SHORT_SLOW)");
    assert_eq!(radio.bandwidth_khz, 250.0);
    assert_eq!(radio.coding_rate, 5);
    assert_eq!(radio.modem_preset, MODEM_SHORT_FAST);
    let slow_radio = eu868_config_for_preset(MODEM_SHORT_SLOW);
    assert_eq!(slow_radio.spreading_factor, 8);
    assert_ne!(radio.spreading_factor, slow_radio.spreading_factor);

    assert!(router.admin_config_dirty());
    let mut saved = store.load();
    router.write_admin_into_config(&mut saved);
    store.save(&saved).unwrap();
    router.clear_admin_config_dirty();

    let reloaded = store.load();
    assert_eq!(reloaded.lora.modem_preset, MODEM_SHORT_FAST);
    assert_eq!(reloaded.lora.spreading_factor, 7);
    assert_eq!(reloaded.lora.bandwidth_khz, 250.0);
    assert_eq!(reloaded.lora.coding_rate, 5);
    assert_eq!(reloaded.primary_channel_hash(), expected_hash);

    // Boot path: main.rs applies eu868_config_for_preset(config.lora.modem_preset).
    let boot_radio = eu868_config_for_preset(reloaded.lora.modem_preset);
    assert_eq!(boot_radio.spreading_factor, reloaded.lora.spreading_factor);
    assert_eq!(boot_radio.bandwidth_khz, reloaded.lora.bandwidth_khz);

    static ROUTER2: StaticCell<Router> = StaticCell::new();
    let router2 = ROUTER2.init(Router::new(our));
    router2.load_node_config(&reloaded);
    assert_eq!(router2.modem_preset(), MODEM_SHORT_FAST);
    assert_eq!(router2.channel_hash(), expected_hash);
}

#[test]
fn get_lora_reports_current_preset_after_set() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0xC002_0001u32;
    let peer = 0xD002_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x88; 16]), 8);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x89; 16]), 9);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x8A; 16]), 10);
    let cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);

    let mut get = mesh_routing::AdminMessage::default();
    get.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA);
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
    assert_eq!(router.admin_state().modem_preset, MODEM_SHORT_SLOW);
    let passkey = router.admin_state().session_passkey;

    let mut set = mesh_routing::AdminMessage::default();
    set.payload = AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
        use_preset: true,
        modem_preset: MODEM_SHORT_FAST as u32,
        region: REGION_EU_868,
        hop_limit: 3,
        tx_power: 27,
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
    let _ = router.poll_admin_tx(2_000);
    assert_eq!(router.modem_preset(), MODEM_SHORT_FAST);
}
