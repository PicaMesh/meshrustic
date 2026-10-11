use mesh_crypto::{encrypt_packet, CryptoKey, DEFAULT_PSK};
use mesh_protocol::{PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};
use mesh_routing::{encode_data_payload, InboundPacket, Router};

fn frame(router: &Router, from: u32, id: u32, port: u32) -> Vec<u8> {
    let mut payload = encode_data_payload(port, &[]);
    encrypt_packet(
        &CryptoKey::from_bytes(&DEFAULT_PSK),
        from,
        id as u64,
        &mut payload,
    );
    let header = PacketHeader::from_fields(
        NODENUM_BROADCAST,
        from,
        id,
        router.channel_hash(),
        3,
        3,
        false,
        false,
        0,
        from as u8,
    );
    let mut bytes = vec![0; PACKET_HEADER_LEN];
    header.encode_to(bytes.as_mut_slice().try_into().unwrap());
    bytes.extend_from_slice(&payload);
    bytes
}

#[test]
fn queued_foreign_frames_follow_role_and_congestion_changes() {
    let mut router = Router::new(1);
    let telemetry = frame(&router, 2, 1, 67);
    assert!(router.queued_frame_allowed(&telemetry, 0));
    router.set_channel_utilization(25.0);
    assert!(!router.queued_frame_allowed(&telemetry, 1));
    let text = frame(&router, 2, 2, 1);
    assert!(router.queued_frame_allowed(&text, 1));
    router.set_device_role(mesh_routing::nodeinfo::DEVICE_ROLE_CLIENT_MUTE);
    assert!(!router.queued_frame_allowed(&text, 2));
    let ours = frame(&router, 1, 3, 67);
    assert!(router.queued_frame_allowed(&ours, 2));
}

#[test]
fn repeated_queue_checks_do_not_charge_admission_and_observe_later_bans() {
    let mut router = Router::new(1);
    let queued = frame(&router, 2, 100, 67);
    for now in 0..100 {
        assert!(router.queued_frame_allowed(&queued, now));
    }
    for id in 1..=4 {
        let bytes = frame(&router, 2, id, 67);
        let result = router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -70,
                    snr: 8,
                    bytes: &bytes,
                },
                100 + id,
            )
            .unwrap();
        assert_eq!(result.rate_limited, id == 4);
        if let Some(handle) = result.handle {
            router.release_packet(handle);
        }
    }
    assert!(!router.queued_frame_allowed(&queued, 105));
}
