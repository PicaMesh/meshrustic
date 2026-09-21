//! Fixed-position broadcasts: admin cadence and coordinates, no replies to requests.

use mesh_crypto::{encrypt_packet, CryptoKey, DEFAULT_PSK};
use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};
use mesh_routing::{
    decode_fixed_position, encode_admin_message, encode_data_payload_opts, try_decrypt_data_full,
    AdminMessage, AdminPayload, ConfigPayload, DataEncodeOpts, InboundPacket, Router,
    WireFixedPosition, WirePositionConfig, CONFIG_TYPE_POSITION, LOC_MANUAL, POSITION_APP,
    POSITION_BROADCAST_SECS_CLIENT, POSITION_PRECISION_BITS,
};
use mesh_store::{generate_keypair, NodeConfig};

fn admin(router: &mut Router, from: u32, remote_pk: &[u8; 32], msg: &AdminMessage, now: u32) {
    router.process_admin_as_pki_peer_for_test(
        remote_pk,
        from,
        now,
        &encode_admin_message(msg),
        now,
    );
}

fn passkey(router: &mut Router, from: u32, remote_pk: &[u8; 32], now: u32) -> [u8; 8] {
    let mut get = AdminMessage::default();
    get.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_POSITION);
    admin(router, from, remote_pk, &get, now);
    assert!(router.admin_state().has_session);
    router.admin_state().session_passkey
}

#[test]
fn fixed_position_broadcasts_on_the_configured_cadence_and_ignores_requests() {
    let our = 0xA11C_E001;
    let peer = 0xB22D_E002;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x31; 16]), 1);
    let (_peer_priv, peer_pub) = generate_keypair(Some(&[0x32; 16]), 2);
    let (_other_priv, other_pub) = generate_keypair(Some(&[0x33; 16]), 3);
    let cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    let mut router = Router::new(our);
    router.load_node_config(&cfg);
    router.set_builtin_admin_public_keys_for_test([peer_pub, other_pub]);

    let now = 10_000u32;
    let key = passkey(&mut router, peer, &peer_pub, now);
    let mut set = AdminMessage::default();
    set.payload = AdminPayload::SetConfig(ConfigPayload::Position(WirePositionConfig {
        position_broadcast_secs: POSITION_BROADCAST_SECS_CLIENT + 600,
        fixed_position: true,
    }));
    set.has_session_passkey = true;
    set.session_passkey = key;
    admin(&mut router, peer, &peer_pub, &set, now + 1);
    let _ = router.poll_admin_tx(now + 1);

    let key = passkey(&mut router, peer, &peer_pub, now + 2);
    let mut fix = AdminMessage::default();
    fix.payload = AdminPayload::SetFixedPosition(WireFixedPosition {
        latitude_i: 52_520_000,
        longitude_i: 13_405_000,
        has_latitude_i: true,
        has_longitude_i: true,
    });
    fix.has_session_passkey = true;
    fix.session_passkey = key;
    admin(&mut router, peer, &peer_pub, &fix, now + 3);

    let tx = router
        .poll_position_tx(now + 3)
        .expect("set_fixed_position sends immediately");
    let header = PacketHeader::decode(&tx.bytes[..PACKET_HEADER_LEN])
        .unwrap()
        .parse();
    assert_eq!(header.to, mesh_protocol::NODENUM_BROADCAST);
    assert_eq!(header.from, our);
    let mut cipher = tx.bytes[PACKET_HEADER_LEN..tx.len as usize].to_vec();
    let (data, body) = try_decrypt_data_full(
        &CryptoKey::from_bytes(&DEFAULT_PSK),
        our,
        header.id,
        header.channel,
        header.channel,
        &mut cipher,
    )
    .unwrap();
    assert_eq!(data.portnum, POSITION_APP);
    assert!(!data.want_response);
    let pos = decode_fixed_position(&body).unwrap();
    assert_eq!(pos.latitude_i, 52_520_000);
    assert_eq!(pos.longitude_i, 13_405_000);
    assert_eq!(pos.location_source, LOC_MANUAL);
    assert_eq!(pos.precision_bits, POSITION_PRECISION_BITS);

    let interval_ms = (POSITION_BROADCAST_SECS_CLIENT + 600) * 1_000;
    router.run_maintenance(now + 3 + interval_ms - 1, 100);
    assert!(router.poll_position_tx(now + 3 + interval_ms - 1).is_none());

    let request = position_request(peer, our, 0x51, router.channel_hash());
    let _ = router.process_inbound(
        &InboundPacket {
            radio_id: 0,
            rssi: -50,
            snr: 8,
            bytes: &request,
        },
        now + 4,
    );
    assert!(
        router.poll_position_tx(now + 4).is_none(),
        "position requests are not answered"
    );

    router.run_maintenance(now + 3 + interval_ms, 100);
    assert!(router.poll_position_tx(now + 3 + interval_ms).is_some());

    let mut saved = cfg;
    router.write_admin_into_config(&mut saved);
    assert!(saved.fixed_position);
    assert!(saved.has_fixed_coords);
    assert_eq!(saved.latitude_i, 52_520_000);
    assert_eq!(
        saved.position_broadcast_secs,
        POSITION_BROADCAST_SECS_CLIENT + 600
    );

    let key = passkey(&mut router, peer, &peer_pub, now + 5);
    let mut clear = AdminMessage::default();
    clear.payload = AdminPayload::RemoveFixedPosition;
    clear.has_session_passkey = true;
    clear.session_passkey = key;
    admin(&mut router, peer, &peer_pub, &clear, now + 6);
    router.run_maintenance(now + 6 + interval_ms, 100);
    assert!(router.poll_position_tx(now + 6 + interval_ms).is_none());
    assert!(!router.admin_state().broadcasts_fixed_position());
}

#[test]
fn no_broadcast_until_fixed_position_is_enabled_and_coordinates_are_set() {
    let our = 0xA11C_E010;
    let peer = 0xB22D_E011;
    let (node_priv, node_pub) = generate_keypair(Some(&[0x41; 16]), 4);
    let (_peer_priv, peer_pub) = generate_keypair(Some(&[0x42; 16]), 5);
    let (_other_priv, other_pub) = generate_keypair(Some(&[0x43; 16]), 6);
    let cfg = NodeConfig::first_boot(our, node_priv, node_pub);
    let mut router = Router::new(our);
    router.load_node_config(&cfg);
    router.set_builtin_admin_public_keys_for_test([peer_pub, other_pub]);

    let now = 20_000u32;
    router.run_maintenance(now, 100);
    assert!(router.poll_position_tx(now).is_none());
    router.run_maintenance(now + POSITION_BROADCAST_SECS_CLIENT * 1_000, 100);
    assert!(
        router
            .poll_position_tx(now + POSITION_BROADCAST_SECS_CLIENT * 1_000)
            .is_none(),
        "unset position must not broadcast at the default cadence"
    );

    let key = passkey(&mut router, peer, &peer_pub, now + 1);
    let mut set = AdminMessage::default();
    set.payload = AdminPayload::SetConfig(ConfigPayload::Position(WirePositionConfig {
        position_broadcast_secs: POSITION_BROADCAST_SECS_CLIENT,
        fixed_position: true,
    }));
    set.has_session_passkey = true;
    set.session_passkey = key;
    admin(&mut router, peer, &peer_pub, &set, now + 2);
    router.run_maintenance(now + 2, 100);
    assert!(
        router.poll_position_tx(now + 2).is_none(),
        "fixed position without coordinates must not broadcast"
    );

    let key = passkey(&mut router, peer, &peer_pub, now + 3);
    let mut fix = AdminMessage::default();
    fix.payload = AdminPayload::SetFixedPosition(WireFixedPosition {
        latitude_i: 52_520_000,
        longitude_i: 13_405_000,
        has_latitude_i: true,
        has_longitude_i: true,
    });
    fix.has_session_passkey = true;
    fix.session_passkey = key;
    admin(&mut router, peer, &peer_pub, &fix, now + 4);

    let key = passkey(&mut router, peer, &peer_pub, now + 5);
    let mut off = AdminMessage::default();
    off.payload = AdminPayload::SetConfig(ConfigPayload::Position(WirePositionConfig {
        position_broadcast_secs: POSITION_BROADCAST_SECS_CLIENT,
        fixed_position: false,
    }));
    off.has_session_passkey = true;
    off.session_passkey = key;
    admin(&mut router, peer, &peer_pub, &off, now + 6);
    assert!(
        router.poll_position_tx(now + 6).is_none(),
        "a frame queued before disable must not be transmitted"
    );
    router.run_maintenance(now + 6 + POSITION_BROADCAST_SECS_CLIENT * 1_000, 100);
    assert!(
        router
            .poll_position_tx(now + 6 + POSITION_BROADCAST_SECS_CLIENT * 1_000)
            .is_none(),
        "coordinates stay stored, but a disabled fixed position must not broadcast"
    );
    assert!(router.admin_state().has_fixed_coords);
    assert!(!router.admin_state().fixed_position);
}

fn position_request(from: u32, to: u32, id: u32, channel_hash: u8) -> Vec<u8> {
    let key = CryptoKey::from_bytes(&DEFAULT_PSK);
    let plaintext = encode_data_payload_opts(
        POSITION_APP,
        &[],
        DataEncodeOpts {
            want_response: true,
            ..Default::default()
        },
    );
    let mut cipher = plaintext.clone();
    encrypt_packet(&key, from, id as u64, &mut cipher);
    let header = PacketHeader::from_fields(to, from, id, channel_hash, 3, 3, false, false, 0, 0);
    let mut out = vec![0u8; PACKET_HEADER_LEN + cipher.len()];
    header.encode_to((&mut out[..PACKET_HEADER_LEN]).try_into().unwrap());
    out[PACKET_HEADER_LEN..].copy_from_slice(&cipher);
    out
}
