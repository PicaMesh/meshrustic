//! Reliable retransmit slots: want_ack packets we originate, and want_ack unicasts we forward
//! with a designated next hop (retried until someone carries the packet on; the last retry is
//! sent with `next_hop` cleared so any node may relay it, as Meshtastic's NextHopRouter does).

use mesh_protocol::{PacketHeader, PACKET_HEADER_LEN};

use crate::router::MAX_WIRE_LEN;
use crate::routing_ack::NUM_RELIABLE_RETX;

pub const MAX_PENDING_RELIABLE: usize = 4;

#[derive(Clone, Copy)]
pub struct PendingReliable {
    pub active: bool,
    /// Originator of the frame (our node for packets we originate).
    pub from: u32,
    pub packet_id: u32,
    pub to: u32,
    /// Forwarded copy of someone else's unicast: last retry clears `next_hop`.
    pub relayed: bool,
    pub num_retx: u8,
    pub next_tx_ms: u32,
    pub len: u8,
    pub bytes: [u8; MAX_WIRE_LEN],
}

impl PendingReliable {
    pub const fn inactive() -> Self {
        Self {
            active: false,
            from: 0,
            packet_id: 0,
            to: 0,
            relayed: false,
            num_retx: 0,
            next_tx_ms: 0,
            len: 0,
            bytes: [0; MAX_WIRE_LEN],
        }
    }
}

pub fn schedule_reliable(
    slots: &mut [PendingReliable; MAX_PENDING_RELIABLE],
    from: u32,
    packet_id: u32,
    to: u32,
    relayed: bool,
    len: u8,
    bytes: [u8; MAX_WIRE_LEN],
    retx_delay_ms: u32,
    now_ms: u32,
) -> bool {
    if slots
        .iter()
        .any(|s| s.active && s.from == from && s.packet_id == packet_id)
    {
        return true; // already armed for this packet
    }
    let idx = match slots.iter().position(|s| !s.active) {
        Some(i) => i,
        None => return false,
    };
    slots[idx] = PendingReliable {
        active: true,
        from,
        packet_id,
        to,
        relayed,
        num_retx: NUM_RELIABLE_RETX,
        next_tx_ms: now_ms.wrapping_add(retx_delay_ms),
        len,
        bytes,
    };
    true
}

/// Stop retries of a frame identified by originator and id (relayed copies included).
pub fn stop_reliable_for(
    slots: &mut [PendingReliable; MAX_PENDING_RELIABLE],
    from: u32,
    packet_id: u32,
) -> bool {
    let mut stopped = false;
    for slot in slots.iter_mut() {
        if slot.active && slot.from == from && slot.packet_id == packet_id {
            slot.active = false;
            stopped = true;
        }
    }
    stopped
}

pub fn stop_reliable(slots: &mut [PendingReliable; MAX_PENDING_RELIABLE], packet_id: u32) -> bool {
    let mut stopped = false;
    for slot in slots.iter_mut() {
        if slot.active && slot.packet_id == packet_id {
            slot.active = false;
            stopped = true;
        }
    }
    stopped
}

pub fn bump_reliable_delays(slots: &mut [PendingReliable; MAX_PENDING_RELIABLE], airtime_ms: u32) {
    for slot in slots.iter_mut() {
        if slot.active {
            slot.next_tx_ms = slot.next_tx_ms.wrapping_add(airtime_ms);
        }
    }
}

/// Pop the next due retransmit. `retx_delay_for(len)` yields the delay until the following
/// attempt for a frame of that wire length (airtime depends on the frame, not on a constant).
/// A frame due for retransmission. `fallback` is set on the final retry of a relayed copy,
/// whose header has just had `next_hop` cleared.
pub struct DueRetransmit {
    pub from: u32,
    pub packet_id: u32,
    pub relayed: bool,
    pub fallback: bool,
    pub len: u8,
    pub bytes: [u8; MAX_WIRE_LEN],
}

pub fn due_retransmit(
    slots: &mut [PendingReliable; MAX_PENDING_RELIABLE],
    now_ms: u32,
    retx_delay_for: impl Fn(u8) -> u32,
) -> Option<DueRetransmit> {
    for slot in slots.iter_mut() {
        if !slot.active {
            continue;
        }
        if now_ms.wrapping_sub(slot.next_tx_ms) >= 0x8000_0000 {
            continue;
        }
        if now_ms < slot.next_tx_ms {
            continue;
        }
        if slot.num_retx == 0 {
            slot.active = false;
            continue;
        }
        slot.num_retx -= 1;
        slot.next_tx_ms = now_ms.wrapping_add(retx_delay_for(slot.len));
        let mut fallback = false;
        if slot.relayed && slot.num_retx == 0 {
            // Last try: release the packet to flooding so any neighbour may carry it.
            if let Ok(mut hdr) = PacketHeader::decode(&slot.bytes[..PACKET_HEADER_LEN]) {
                if hdr.next_hop != 0 {
                    hdr.next_hop = 0;
                    if let Ok(out) = (&mut slot.bytes[..PACKET_HEADER_LEN]).try_into() {
                        hdr.encode_to(out);
                    }
                    fallback = true;
                }
            }
        }
        return Some(DueRetransmit {
            from: slot.from,
            packet_id: slot.packet_id,
            relayed: slot.relayed,
            fallback,
            len: slot.len,
            bytes: slot.bytes,
        });
    }
    None
}
