//! Reliable send retransmit slots (want_ack originated packets).

use crate::router::MAX_WIRE_LEN;
use crate::routing_ack::{retransmission_delay_ms, NUM_RELIABLE_RETX};

pub const MAX_PENDING_RELIABLE: usize = 4;

#[derive(Clone, Copy)]
pub struct PendingReliable {
    pub active: bool,
    pub packet_id: u32,
    pub to: u32,
    pub num_retx: u8,
    pub next_tx_ms: u32,
    pub len: u8,
    pub bytes: [u8; MAX_WIRE_LEN],
}

impl PendingReliable {
    pub const fn inactive() -> Self {
        Self {
            active: false,
            packet_id: 0,
            to: 0,
            num_retx: 0,
            next_tx_ms: 0,
            len: 0,
            bytes: [0; MAX_WIRE_LEN],
        }
    }
}

pub fn schedule_reliable(
    slots: &mut [PendingReliable; MAX_PENDING_RELIABLE],
    packet_id: u32,
    to: u32,
    len: u8,
    bytes: [u8; MAX_WIRE_LEN],
    airtime_ms: u32,
    slot_ms: u32,
    now_ms: u32,
) -> bool {
    let idx = match slots.iter().position(|s| !s.active) {
        Some(i) => i,
        None => return false,
    };
    let delay = retransmission_delay_ms(airtime_ms, slot_ms);
    slots[idx] = PendingReliable {
        active: true,
        packet_id,
        to,
        num_retx: NUM_RELIABLE_RETX,
        next_tx_ms: now_ms.wrapping_add(delay),
        len,
        bytes,
    };
    true
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

pub fn bump_reliable_delays(
    slots: &mut [PendingReliable; MAX_PENDING_RELIABLE],
    airtime_ms: u32,
) {
    for slot in slots.iter_mut() {
        if slot.active {
            slot.next_tx_ms = slot.next_tx_ms.wrapping_add(airtime_ms);
        }
    }
}

pub fn due_retransmit(
    slots: &mut [PendingReliable; MAX_PENDING_RELIABLE],
    now_ms: u32,
    airtime_ms: u32,
    slot_ms: u32,
) -> Option<(u8, [u8; MAX_WIRE_LEN])> {
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
        let delay = retransmission_delay_ms(airtime_ms, slot_ms);
        slot.next_tx_ms = now_ms.wrapping_add(delay);
        return Some((slot.len, slot.bytes));
    }
    None
}
