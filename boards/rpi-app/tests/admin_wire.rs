//! AdminMessage wire / session seed / begin-commit via real PKI (builtin override).

use mesh_crypto::CryptoEngine;
use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};
use mesh_radio::{MODEM_SHORT_FAST, MODEM_SHORT_SLOW};
use mesh_routing::{
    encode_admin_message, encode_data_payload_opts, AdminPayload, ConfigPayload, DataEncodeOpts,
    InboundPacket, NodeInfoIdentity, Router, WireLoRaConfig, ADMIN_APP, CONFIG_TYPE_LORA,
    CONFIG_TYPE_SESSIONKEY, REGION_EU_868,
};
use mesh_store::{generate_keypair, NodeConfig};
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

#[test]
fn admin_sessionkey_and_owner_metadata_seed() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0x1000_0001u32;
    let peer = 0x2000_0002u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x11; 16]), 1);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x21; 16]), 2);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x31; 16]), 3);
    let cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    let router = ROUTER.init(Router::new(our));
    router.load_node_config(&cfg);
    router.set_node_identity(NodeInfoIdentity::for_node(our, node_pub));
    router.set_builtin_admin_public_keys_for_test([b1_pub, b2_pub]);

    let mut req = mesh_routing::AdminMessage::default();
    req.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_SESSIONKEY);
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xA001,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&req),
    );
    inbound(router, &frame, 1_000);
    assert!(router.poll_admin_tx(1_000).is_some());
    assert!(router.admin_state().has_session);

    let mut owner = mesh_routing::AdminMessage::default();
    owner.payload = AdminPayload::GetOwnerRequest;
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xA002,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&owner),
    );
    inbound(router, &frame, 1_100);
    assert!(router.poll_admin_tx(1_100).is_some());

    let mut meta = mesh_routing::AdminMessage::default();
    meta.payload = AdminPayload::GetDeviceMetadataRequest;
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xA003,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&meta),
    );
    inbound(router, &frame, 1_200);
    assert!(router.poll_admin_tx(1_200).is_some());
}

#[test]
fn admin_get_lora_and_begin_commit() {
    static ROUTER: StaticCell<Router> = StaticCell::new();
    let our = 0x1000_0011u32;
    let peer = 0x2000_0022u32;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x41; 16]), 11);
    let (b1_priv, b1_pub) = generate_keypair(Some(&[0x42; 16]), 12);
    let (_b2_priv, b2_pub) = generate_keypair(Some(&[0x43; 16]), 13);
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
        0xB001,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&get),
    );
    inbound(router, &frame, 2_000);
    assert!(router.poll_admin_tx(2_000).is_some());
    assert_eq!(router.admin_state().modem_preset, MODEM_SHORT_SLOW);
    let passkey = router.admin_state().session_passkey;

    // ADMIN_APP is exempt from the OTHER 4/90s inbound limit (Phase I); spacing is
    // still harmless for begin/set/commit sequencing.
    const GAP: u32 = 100_000;

    let mut begin = mesh_routing::AdminMessage::default();
    begin.payload = AdminPayload::BeginEditSettings;
    begin.has_session_passkey = true;
    begin.session_passkey = passkey;
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xB002,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&begin),
    );
    inbound(router, &frame, 2_000 + GAP);
    let _ = router.poll_admin_tx(2_000 + GAP);

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
        0xB003,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&set),
    );
    inbound(router, &frame, 2_000 + 2 * GAP);
    let _ = router.poll_admin_tx(2_000 + 2 * GAP);
    assert_eq!(router.modem_preset(), MODEM_SHORT_SLOW);

    let mut commit = mesh_routing::AdminMessage::default();
    commit.payload = AdminPayload::CommitEditSettings;
    commit.has_session_passkey = true;
    commit.session_passkey = passkey;
    let frame = build_pki_admin_frame(
        our,
        peer,
        0xB004,
        &b1_priv,
        &node_pub,
        &encode_admin_message(&commit),
    );
    inbound(router, &frame, 2_000 + 3 * GAP);
    let _ = router.poll_admin_tx(2_000 + 3 * GAP);
    assert_eq!(router.modem_preset(), MODEM_SHORT_FAST);
    assert!(
        router.take_pending_radio_reinit(),
        "commit LoRa preset must soft-reinit radio, not reboot"
    );
    assert!(router.take_pending_reboot_seconds().is_none());
}
