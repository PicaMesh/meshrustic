//! Opaque relay — forward on-air frames without decoding portnum or protobuf.
//!
//! MeshRustic relays **all** portnums (text, telemetry, ATAK, unknown, undecoded/wrong-key
//! ciphertext). Protobuf types exist only for ports the router must **parse** (routing, SR,
//! nodeinfo, traceroute). Relay copies the encrypted payload bytes unchanged.

use mesh_protocol::{PacketHeader, ParsedPacket};

/// Whether this frame is eligible for relay consideration at the wire layer.
///
/// Does not inspect payload or portnum. Further gates (dedup, rate limit, QoS, SR slot,
/// hop limit, `is_rebroadcaster`) apply in `Router::evaluate_tx_plan`.
pub fn wire_may_relay(rx: &ParsedPacket, from_us: bool, to_us: bool) -> bool {
    !from_us && !to_us && rx.hop_limit > 0
}

/// Build the on-air header for relaying a received frame.
///
/// Payload bytes are not modified — copy separately with [`copy_opaque_payload`].
/// Relay header updates: decrement `hop_limit`, set `relay_node` to our node byte.
pub fn relay_header(rx: &ParsedPacket, our_node: u32) -> Option<PacketHeader> {
    relay_header_with_next_hop(rx, our_node, 0)
}

/// Same as [`relay_header`], but sets `next_hop` for SR unicast forwarding when non-zero.
pub fn relay_header_with_next_hop(
    rx: &ParsedPacket,
    our_node: u32,
    next_hop: u32,
) -> Option<PacketHeader> {
    relay_header_with_next_hop_opts(rx, our_node, next_hop, None)
}

/// Build a relay header, optionally applying a direct-neighbor hop budget instead of decrementing.
pub fn relay_header_with_next_hop_opts(
    rx: &ParsedPacket,
    our_node: u32,
    next_hop: u32,
    direct_neighbor_hop_limit: Option<u8>,
) -> Option<PacketHeader> {
    if rx.hop_limit == 0 {
        return None;
    }

    let (hop_limit, hop_start) = relay_hop_fields(rx, direct_neighbor_hop_limit)?;
    let relay_node = (our_node & 0xFF) as u8;
    // Every relay names its own next hop or none, as stock NextHopRouter does. Copying the
    // incoming byte was wrong both ways: when it named us, the frame left still naming us, so
    // legacy nodes (which relay a unicast only when next_hop is clear or their own byte) never
    // touched it and SR peers waited for a second copy from us; when it named a node that stayed
    // silent, keeping its byte kept legacy routers out of the recovery.
    let next_hop_byte = if next_hop != 0 {
        (next_hop & 0xFF) as u8
    } else {
        0
    };

    Some(PacketHeader::from_fields(
        rx.to,
        rx.from,
        rx.id,
        rx.channel,
        hop_limit,
        hop_start,
        rx.want_ack,
        rx.via_mqtt,
        next_hop_byte,
        relay_node,
    ))
}

/// Outgoing hop fields for a relay: normal decrement, or a direct-neighbor hop budget.
pub fn relay_hop_fields(
    rx: &ParsedPacket,
    direct_neighbor_hop_limit: Option<u8>,
) -> Option<(u8, u8)> {
    if rx.hop_limit == 0 {
        return None;
    }
    match direct_neighbor_hop_limit {
        Some(limited) => {
            let hops_away_rx = rx.hop_limit.saturating_sub(rx.hop_start);
            let hops_away_tx = hops_away_rx.saturating_add(1);
            let hop_start = hops_away_tx.saturating_add(limited);
            Some((limited, hop_start))
        }
        None => Some((rx.hop_limit - 1, rx.hop_start)),
    }
}

/// Copy encrypted payload bytes unchanged into a TX pool slot.
pub fn copy_opaque_payload(dst: &mut crate::pool::PacketSlot, src: &crate::pool::PacketSlot) {
    let len = src.payload_len as usize;
    debug_assert!(len <= dst.payload.len());
    dst.payload[..len].copy_from_slice(&src.payload[..len]);
    dst.payload_len = src.payload_len;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{PacketPool, POOL_SIZE};
    use mesh_protocol::PacketHeader;
    use static_cell::StaticCell;

    #[test]
    fn relay_preserves_opaque_payload_bytes() {
        static POOL: StaticCell<PacketPool> = StaticCell::new();
        let pool = POOL.init(PacketPool::new());

        let rx_handle = pool.alloc().unwrap();
        let tx_handle = pool.alloc().unwrap();

        let header =
            PacketHeader::from_fields(0xFFFF_FFFF, 0x1234_5678, 99, 0x01, 3, 3, false, false, 0, 0);
        let parsed = header.parse();
        let fake_cipher = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22];

        {
            let rx = pool.get_mut(rx_handle).unwrap();
            rx.header = header;
            rx.payload[..fake_cipher.len()].copy_from_slice(&fake_cipher);
            rx.payload_len = fake_cipher.len() as u16;
        }

        let tx_hdr = relay_header(&parsed, 0xAABB_CCDD).expect("relay header");
        let mut staging = crate::pool::PacketSlot::empty();
        {
            let rx = pool.get(rx_handle).unwrap();
            copy_opaque_payload(&mut staging, rx);
        }
        {
            let tx = pool.get_mut(tx_handle).unwrap();
            tx.header = tx_hdr;
            copy_opaque_payload(tx, &staging);
        }

        let tx = pool.get(tx_handle).unwrap();
        assert_eq!(&tx.payload[..fake_cipher.len()], fake_cipher);
        assert_eq!(tx.payload_len, fake_cipher.len() as u16);
        assert_eq!(tx.header.hop_limit(), 2);
        assert_eq!(tx.header.relay_node, 0xDD);

        pool.release(rx_handle);
        pool.release(tx_handle);
        assert_eq!(pool.free_count(), POOL_SIZE);
    }

    #[test]
    fn wire_may_relay_ignores_portnum() {
        let parsed = PacketHeader::from_fields(1, 2, 3, 0, 2, 2, false, false, 0, 0).parse();
        assert!(wire_may_relay(&parsed, false, false));
        assert!(!wire_may_relay(&parsed, true, false));
        assert!(!wire_may_relay(&parsed, false, true));
        assert!(!wire_may_relay(
            &PacketHeader::from_fields(1, 2, 3, 0, 0, 0, false, false, 0, 0).parse(),
            false,
            false
        ));
    }

    #[test]
    fn relay_without_own_route_clears_the_incoming_next_hop() {
        // Named as next hop (0xCC) but with no onward route: the frame must not keep naming us.
        let parsed = PacketHeader::from_fields(
            0xDD00_00DD,
            0xBB00_00BB,
            1,
            0,
            5,
            5,
            false,
            false,
            0xCC,
            0xBB,
        )
        .parse();
        let hdr = relay_header_with_next_hop_opts(&parsed, 0xCC00_00CC, 0, None).expect("relay");
        assert_eq!(hdr.parse().next_hop, 0);
        assert_eq!(hdr.parse().relay_node, 0xCC);

        // Relaying behind a silent designated node (0x99): its byte is dropped too, so legacy
        // routers can carry our copy at once instead of after the retry fallback.
        let parsed = PacketHeader::from_fields(
            0xDD00_00DD,
            0xBB00_00BB,
            2,
            0,
            5,
            5,
            false,
            false,
            0x99,
            0xBB,
        )
        .parse();
        let hdr = relay_header_with_next_hop_opts(&parsed, 0xCC00_00CC, 0, None).expect("relay");
        assert_eq!(hdr.parse().next_hop, 0);
    }

    #[test]
    fn relay_with_own_route_names_that_next_hop() {
        let parsed = PacketHeader::from_fields(
            0xDD00_00DD,
            0xBB00_00BB,
            3,
            0,
            5,
            5,
            false,
            false,
            0xCC,
            0xBB,
        )
        .parse();
        let hdr = relay_header_with_next_hop_opts(&parsed, 0xCC00_00CC, 0xEE00_00EE, None)
            .expect("relay");
        assert_eq!(hdr.parse().next_hop, 0xEE);
    }

    #[test]
    fn direct_neighbor_hop_limit_adjusts_hop_start() {
        let parsed =
            PacketHeader::from_fields(0xDD00_00DD, 0xBB00_00BB, 1, 0, 5, 3, false, false, 0, 0)
                .parse();
        let hdr = relay_header_with_next_hop_opts(&parsed, 0xCC00_00CC, 0, Some(0)).expect("relay");
        assert_eq!(hdr.hop_limit(), 0);
        assert_eq!(hdr.hop_start(), 3);
        assert_eq!(hdr.hop_start().saturating_sub(hdr.hop_limit()), 3);
    }

    #[test]
    fn direct_neighbor_hop_limit_marginal_allows_one_hop() {
        let parsed =
            PacketHeader::from_fields(0xDD00_00DD, 0xBB00_00BB, 1, 0, 5, 3, false, false, 0, 0)
                .parse();
        let hdr = relay_header_with_next_hop_opts(&parsed, 0xCC00_00CC, 0, Some(1)).expect("relay");
        assert_eq!(hdr.hop_limit(), 1);
        assert_eq!(hdr.hop_start(), 4);
        assert_eq!(hdr.hop_start().saturating_sub(hdr.hop_limit()), 3);
    }
}
