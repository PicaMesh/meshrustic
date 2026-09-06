//! Field-trace replays: packet sequences observed on the bench, replayed against a `Router` and
//! the board's `ChannelAccess` gate, asserting what the interop contract (docs/INTEROP_CONTRACT.md)
//! requires. Each scenario names the day it was seen so the log in `tmp/` can be consulted.

use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::PacketHeader;
use mesh_radio::MODEM_SHORT_SLOW;
use mesh_routing::channel_access::{ChannelAccess, PEER_TURNAROUND_MS};
use mesh_routing::topology::PACKED_NEIGHBOR_ENTRY_SIZE;
use mesh_routing::{
    build_app_wire_frame, build_topology_wire_frame, encode_route_discovery, write_packed_header,
    DataEncodeOpts, InboundPacket, RouteDiscovery, Router, SrLogEvent, MAX_SR_LOG,
    PACKED_NEIGHBOR_HEADER_SIZE, TRACEROUTE_APP,
};
use mesh_routing::{hops_away, try_decrypt_data_full};

const CHANNEL: u8 = 0x77;

/// A node on the bench: routes frames into `router`, keeps the board's gate in step.
struct Bench {
    router: Router,
    access: ChannelAccess,
    key: CryptoKey,
}

impl Bench {
    fn new(node: u32) -> Self {
        let key = CryptoKey::from_bytes(&DEFAULT_PSK);
        Self {
            router: Router::with_channel(node, key, CHANNEL, MODEM_SHORT_SLOW, true, 3),
            access: ChannelAccess::new(),
            key,
        }
    }

    /// Receive `frame` at `now_ms`, as the radio task does: router first, then the gate.
    fn hear(&mut self, frame: &[u8], now_ms: u32) {
        self.router
            .process_inbound(
                &InboundPacket {
                    radio_id: 0,
                    rssi: -45,
                    snr: 12,
                    bytes: frame,
                },
                now_ms,
            )
            .expect("frame accepted");
        self.access.note_rx(now_ms, 0);
    }

    fn logs(&mut self) -> heapless::Vec<SrLogEvent, MAX_SR_LOG> {
        let mut out = heapless::Vec::new();
        self.router.drain_sr_logs(&mut out);
        out
    }
}

/// Packed topology list: header plus one entry per neighbour (RSSI −70, SNR 8, hears us).
fn packed_list(version: u8, neighbours: &[u32]) -> heapless::Vec<u8, 240> {
    let mut packed = heapless::Vec::new();
    let mut header = [0u8; PACKED_NEIGHBOR_HEADER_SIZE];
    write_packed_header(&mut header, version, true);
    packed.extend_from_slice(&header).unwrap();
    for n in neighbours {
        let mut entry = [0u8; PACKED_NEIGHBOR_ENTRY_SIZE];
        entry[..4].copy_from_slice(&n.to_le_bytes());
        entry[4] = (-70i8) as u8;
        entry[5] = 8;
        entry[6] = 0x03; // SR-active, hears us
        packed.extend_from_slice(&entry).unwrap();
    }
    packed
}

fn topology_frame(bench: &Bench, from: u32, id: u32, packed: &[u8]) -> (u8, [u8; 256]) {
    build_topology_wire_frame(from, id, CHANNEL, 5, &bench.key, packed, false)
        .expect("topology frame")
}

/// 2026-09-06 02:29: Czar was rebooted by admin; its version counter restarted at 0 after 108.
/// Both nicenanos must accept the restart with exactly one resync and reject nothing.
#[test]
fn czar_reboot_restarts_its_version_counter_without_stale_rejections() {
    const ME: u32 = 0xBDAC_CE55;
    const CZAR: u32 = 0x63DC_8F8C;
    let mut bench = Bench::new(ME);

    let (len, frame) = topology_frame(&bench, CZAR, 0x1001, &packed_list(108, &[ME]));
    bench.hear(&frame[..len as usize], 1_000);
    // Boot: header-only, version 0.
    let (len, frame) = topology_frame(&bench, CZAR, 0x1002, &packed_list(0, &[]));
    bench.hear(&frame[..len as usize], 61_000);
    // First real list after the boot, then the normal cadence.
    for (i, version) in [0u8, 1, 2, 3].iter().enumerate() {
        let (len, frame) = topology_frame(
            &bench,
            CZAR,
            0x1003 + i as u32,
            &packed_list(*version, &[ME, 0x9797_9797]),
        );
        bench.hear(&frame[..len as usize], 66_000 + i as u32 * 600_000);
    }

    let logs = bench.logs();
    let resyncs = logs
        .iter()
        .filter(|e| matches!(e, SrLogEvent::TopologyVersionResync { .. }))
        .count();
    let stale = logs
        .iter()
        .filter(|e| matches!(e, SrLogEvent::TopologyStale { .. }))
        .count();
    assert_eq!(
        resyncs, 1,
        "one resync for the boot broadcast; log: {logs:?}"
    );
    assert_eq!(stale, 0, "no report of a rebooted peer may be called stale");
}

/// 2026-09-06 12:18: A answered Dura's traceroute within one millisecond of the request; every
/// peer node was still busy with the request and none heard the reply. The reply must be ready
/// in the router but the gate must hold it for the peers' turnaround, and no separate ACK may
/// precede it.
#[test]
fn reply_to_a_direct_request_is_held_for_the_peer_turnaround() {
    const ME: u32 = 0xBDAC_CE55;
    const DURA: u32 = 0x979E_D146;
    let mut bench = Bench::new(ME);
    let mut route = heapless::Vec::<u8, 128>::new();
    encode_route_discovery(&RouteDiscovery::default(), &mut route);
    let (len, request) = build_app_wire_frame(
        ME,
        DURA,
        0x9822_AA0B,
        CHANNEL,
        7,
        7,
        true,
        &bench.key,
        TRACEROUTE_APP,
        &route,
        DataEncodeOpts {
            want_response: true,
            ..Default::default()
        },
    )
    .expect("request");
    let t0 = 10_000;
    bench.hear(&request[..len as usize], t0);

    assert!(
        bench.router.poll_ack_tx(t0).is_none(),
        "the reply is the ACK; no separate ACK frame"
    );
    let reply = bench
        .router
        .poll_traceroute_tx(t0)
        .expect("reply ready in the router at once");
    let hdr = PacketHeader::decode(&reply.bytes[..16]).unwrap().parse();
    assert_eq!(hdr.to, DURA);
    assert_eq!(
        hdr.relay_node,
        (ME & 0xFF) as u8,
        "own relay byte on originated frames"
    );
    // The board may not key up before the peers listen again.
    assert!(!bench.access.may_transmit(t0 + 1));
    assert!(!bench.access.may_transmit(t0 + PEER_TURNAROUND_MS - 1));
    assert!(bench.access.may_transmit(t0 + PEER_TURNAROUND_MS));
}

/// 2026-09-06 15:18: A's hop-0 reply to Dura reached every peer on the desk, yet Dura never
/// acknowledged it while it acknowledged the peers' own hop-0 replies. Stock acknowledges a
/// response only when it knows the response travelled zero hops, and it knows the hop count of
/// a zero-`hop_start` frame only when the Data carries the bitfield. Our reply must therefore
/// carry it, and a stock receiver must then read the reply as direct.
#[test]
fn hop_zero_reply_is_readable_as_direct_by_a_stock_receiver() {
    const ME: u32 = 0xBDAC_CE55;
    const DURA: u32 = 0x979E_D146;
    let mut bench = Bench::new(ME);
    bench
        .router
        .graph_mut()
        .observe_direct_neighbor(DURA, -44, 14, 1_000, 0);
    bench
        .router
        .graph_mut()
        .confirm_direct_neighbor_hears_us(DURA);
    // A stock neighbour, so the last-hop cap applies and the reply goes out with zero hops.
    bench
        .router
        .graph_mut()
        .observe_direct_neighbor(0xEE59_4922, -60, 11, 1_000, 0);
    let mut route = heapless::Vec::<u8, 128>::new();
    encode_route_discovery(&RouteDiscovery::default(), &mut route);
    let (len, request) = build_app_wire_frame(
        ME,
        DURA,
        0x9822_AA1C,
        CHANNEL,
        7,
        7,
        true,
        &bench.key,
        TRACEROUTE_APP,
        &route,
        DataEncodeOpts {
            want_response: true,
            ..Default::default()
        },
    )
    .expect("request");
    bench.hear(&request[..len as usize], 10_000);
    let reply = bench.router.poll_traceroute_tx(10_000).expect("reply");
    let hdr = PacketHeader::decode(&reply.bytes[..16]).unwrap().parse();
    assert_eq!(
        (hdr.hop_start, hdr.hop_limit),
        (0, 0),
        "capped last-hop reply"
    );
    let mut cipher = [0u8; 240];
    let n = reply.len as usize - 16;
    cipher[..n].copy_from_slice(&reply.bytes[16..reply.len as usize]);
    let (data, _) = try_decrypt_data_full(
        &bench.key,
        hdr.from,
        hdr.id,
        CHANNEL,
        hdr.channel,
        &mut cipher[..n],
    )
    .expect("decodable Data");
    assert_eq!(data.request_id, 0x9822_AA1C);
    assert!(
        data.has_bitfield,
        "stock reads hop_start only when the bitfield is present"
    );
    assert_eq!(
        hops_away(hdr.hop_start, hdr.hop_limit, data.has_bitfield),
        Some(0),
        "a stock receiver must see zero hops and acknowledge"
    );
    // 2026-09-06 17:29: Dura acknowledged B's reply but the Meshtastic Android app showed no
    // route: it takes a zero bitfield on a zero-hop_start frame for a legacy frame and drops
    // the traceroute. The default LoRa setting keeps the MQTT bit on, so the word is nonzero.
    assert!(bench.router.ok_to_mqtt(), "OK-to-MQTT is on by default");
    assert_ne!(
        data.bitfield, 0,
        "a zero bitfield hides a hop-0 reply in the app"
    );
}
