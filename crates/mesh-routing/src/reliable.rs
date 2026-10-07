//! Reliable retransmit slots: want_ack packets we originate, priced last-hop follow-ups, and
//! the follow-up of a named non-final forward when the nominated hop stays silent: one repeat
//! to the same hop, then (when `redirect_on_last`) one directed alternate retry.

use crate::router::MAX_WIRE_LEN;

pub const MAX_PENDING_RELIABLE: usize = 4;

/// Follow-up tries of a strong named forward: the repeat to the nominated hop, then the redirect.
pub const NAMED_FOLLOWUP_TRIES: u8 = 2;

/// Follow-up state of a nominated forward (named intermediate or last hop).
#[derive(Clone, Copy)]
pub struct NamedFollowup {
    /// Nominated next hop (full node id); 0 when its relay byte did not resolve.
    pub nominated_hop: u32,
    /// The `next_hop` byte we stamped, or the nominee's node byte when we flooded a weak hop.
    /// A copy whose `relay_node` matches is the nominated hop's.
    pub nominated_byte: u8,
    /// Node we heard the packet from when arming the follow-up.
    pub upstream: u32,
    /// Wait after each try before the next one is due.
    pub delay_ms: u32,
    /// When true, the last try searches for a directed alternate. Weak floods and last hops
    /// leave this false and simply repeat the on-air header.
    pub redirect_on_last: bool,
}

#[derive(Clone, Copy)]
pub struct PendingReliable {
    pub active: bool,
    /// Originator of the frame (our node for packets we originate).
    pub from: u32,
    pub packet_id: u32,
    pub to: u32,
    /// Forwarded copy of someone else's unicast.
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
        named,
        num_retx,
        next_tx_ms: now_ms.wrapping_add(retx_delay_ms),
        len,
        bytes,
    };
    true
}

/// The named follow-up armed for a frame, if any.
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

/// Stop retries of a frame identified by originator and id (relayed copies included).
/// Returns the cleared slot's destination and nominated hop when one was active.
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

/// A frame due for retransmission. `redirect` marks the last try of a named follow-up: the
/// router must search for an alternate and patch or drop the frame. An earlier named try is
/// the unchanged repeat to the nominated hop.
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
        if now_ms < slot.next_tx_ms {
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
        // A redirect is the only further attempt: clear the slot now so a drop leaves nothing pending.
        if redirect {
            slot.active = false;
        }
        // The header stays as we first sent it; the router patches next_hop for a redirect.
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
