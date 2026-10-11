use crate::router::MAX_WIRE_LEN;

pub const MAX_PENDING_RELIABLE: usize = 4;

pub const NAMED_FOLLOWUP_TRIES: u8 = 2;

#[derive(Clone, Copy)]
pub struct NamedFollowup {
    pub nominated_hop: u32,
    pub nominated_byte: u8,
    pub upstream: u32,
    pub delay_ms: u32,
    pub redirect_on_last: bool,
}

#[derive(Clone, Copy)]
pub struct PendingReliable {
    pub active: bool,
    pub from: u32,
    pub packet_id: u32,
    pub to: u32,
    pub relayed: bool,
    pub named: Option<NamedFollowup>,
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
            named: None,
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
    num_retx: u8,
    named: Option<NamedFollowup>,
) -> bool {
    if slots
        .iter()
        .any(|s| s.active && s.from == from && s.packet_id == packet_id)
    {
        return true;
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
        named,
        num_retx,
        next_tx_ms: now_ms.wrapping_add(retx_delay_ms),
        len,
        bytes,
    };
    true
}

pub fn named_followup(
    slots: &[PendingReliable; MAX_PENDING_RELIABLE],
    from: u32,
    packet_id: u32,
) -> Option<NamedFollowup> {
    slots
        .iter()
        .find(|s| s.active && s.from == from && s.packet_id == packet_id)
        .and_then(|s| s.named)
}

pub fn stop_reliable_for(
    slots: &mut [PendingReliable; MAX_PENDING_RELIABLE],
    from: u32,
    packet_id: u32,
) -> Option<(u32, u32)> {
    let mut stopped = None;
    for slot in slots.iter_mut() {
        if slot.active && slot.from == from && slot.packet_id == packet_id {
            stopped = Some((slot.to, slot.named.map_or(0, |n| n.nominated_hop)));
            slot.active = false;
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

pub struct DueRetransmit {
    pub from: u32,
    pub packet_id: u32,
    pub to: u32,
    pub relayed: bool,
    pub named: Option<NamedFollowup>,
    pub redirect: bool,
    pub len: u8,
    pub bytes: [u8; MAX_WIRE_LEN],
}

pub fn due_retransmit(
    slots: &mut [PendingReliable; MAX_PENDING_RELIABLE],
    now_ms: u32,
    retx_delay_for: impl Fn(u32, u32, u8) -> u32,
) -> Option<DueRetransmit> {
    for slot in slots.iter_mut() {
        if !slot.active {
            continue;
        }
        if now_ms.wrapping_sub(slot.next_tx_ms) >= 0x8000_0000 {
            continue;
        }
        if slot.num_retx == 0 {
            slot.active = false;
            continue;
        }
        slot.num_retx -= 1;
        let delay = match slot.named {
            Some(n) => n.delay_ms,
            None => retx_delay_for(slot.from, slot.packet_id, slot.len),
        };
        slot.next_tx_ms = now_ms.wrapping_add(delay);
        let redirect = slot.named.is_some_and(|n| n.redirect_on_last) && slot.num_retx == 0;
        if redirect {
            slot.active = false;
        }
        return Some(DueRetransmit {
            from: slot.from,
            packet_id: slot.packet_id,
            to: slot.to,
            relayed: slot.relayed,
            named: slot.named,
            redirect,
            len: slot.len,
            bytes: slot.bytes,
        });
    }
    None
}
