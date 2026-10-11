use mesh_routing::{
    admin_codec as admin, nodeinfo, position, routing_ack, telemetry, topology, traceroute,
};

fn decode_all(bytes: &[u8]) {
    let _ = admin::decode_admin_message(bytes);
    let _ = admin::decode_config(bytes);
    let _ = admin::decode_module_config(bytes);
    let _ = admin::decode_channel(bytes);
    let _ = admin::decode_channel_settings(bytes);
    let _ = admin::decode_device_config(bytes);
    let _ = admin::decode_lora_config(bytes);
    let _ = admin::decode_security_config(bytes);
    let _ = admin::decode_position_config(bytes);
    let _ = admin::decode_telemetry_config(bytes);
    let _ = nodeinfo::decode_user(bytes);
    let _ = position::decode_fixed_position(bytes);
    let _ = routing_ack::decode_routing_payload(bytes);
    let _ = telemetry::decode_device_metrics(bytes);
    let _ = telemetry::extract_device_metrics(bytes);
    let _ = topology::decode_data_payload_full(bytes);
    let _ = topology::extract_packed_neighbors(bytes);
    let _ = topology::decode_packed_neighbors(bytes, 32);
    let _ = traceroute::decode_route_discovery(bytes);
    for port in [1, 3, 4, 5, 6, 67, 70, 73] {
        let _ = mesh_routing::summarize_decrypted(port, bytes);
    }
}

#[test]
fn malformed_wire_inputs_do_not_panic() {
    let mut state = 0x5730_134bu32;
    let mut bytes = [0; 256];
    for round in 0..20_000 {
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        decode_all(&bytes[..round % 257]);
    }
    for byte in 0..=255 {
        bytes.fill(byte);
        for len in 0..=256 {
            decode_all(&bytes[..len]);
        }
    }
}

#[test]
fn truncated_and_overflowing_wire_fields_are_rejected() {
    for bytes in [&[0][..], &[0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f][..]] {
        assert!(admin::decode_admin_message(bytes).is_none());
        assert!(admin::decode_config(bytes).is_none());
        assert!(nodeinfo::decode_user(bytes).is_none());
        assert!(topology::decode_data_payload_full(bytes).is_none());
    }
    let overflow = [0x08, 0xff, 0xff, 0xff, 0xff, 0x10];
    assert!(admin::decode_admin_message(&overflow).is_none());
    assert!(topology::decode_data_payload_full(&overflow).is_none());
}

#[test]
fn admin_signed_fields_interoperate_with_generated_protobuf() {
    use prost::Message;
    let message = mesh_routing::AdminMessage {
        payload: mesh_routing::AdminPayload::RebootSeconds(-1),
        ..Default::default()
    };
    let bytes = mesh_routing::encode_admin_message(&message);
    let parsed = mesh_protocol::proto::AdminMessage::decode(bytes.as_slice()).unwrap();
    assert_eq!(
        parsed.payload_variant,
        Some(mesh_protocol::proto::admin_message::PayloadVariant::RebootSeconds(-1))
    );
    let channel = mesh_routing::WireChannel {
        index: 2,
        ..Default::default()
    };
    let bytes = mesh_routing::encode_channel(&channel);
    assert_eq!(
        mesh_protocol::proto::Channel::decode(bytes.as_slice())
            .unwrap()
            .index,
        2
    );
}

#[test]
fn oversized_broadcast_intervals_cannot_become_immediately_due() {
    for seconds in [i32::MAX as u32, u32::MAX] {
        let position = position::position_broadcast_interval_ms(seconds, 0);
        let telemetry = telemetry::device_telemetry_interval_ms(seconds);
        for delay in [position, telemetry] {
            assert!(delay <= i32::MAX as u32);
            let now = u32::MAX - 100;
            let due = now.wrapping_add(delay);
            assert!(now.wrapping_sub(due) >= 0x8000_0000);
        }
    }
}
