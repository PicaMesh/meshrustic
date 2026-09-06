//! Channel access: when this node may key up, and how long peers need before they can.
//!
//! One physical fact drives every number here: after a frame ends, the other radios that
//! received it are not listening. A Meshtastic receiver reads the frame out, decrypts it, runs
//! its modules and only then re-arms; Meshtastic-based peers were measured at 69–172 ms of
//! that per frame. A frame
//! that starts inside that window is lost by every such receiver, and a frame that starts inside
//! our own previous frame's tail is lost by everyone still reading that one.
//!
//! The board asks [`ChannelAccess`] before releasing anything to the radio; the router derives
//! every "how long will a peer take to answer" wait from the same constants, so the sender's
//! restraint and the listeners' expectations agree. Slot-coordinated relays start their ladder
//! at [`SLOT_ORIGIN_MS`] for the same reason.

/// Time a peer needs after a frame ends before it is listening again (69–172 ms measured on
/// Meshtastic-based peers, plus margin). Also the origin of the coordinated relay slot ladder.
pub const PEER_TURNAROUND_MS: u32 = 250;

/// Minimum silence after one of our own frames before the next one starts.
pub const TX_GAP_MS: u32 = 100;

/// First coordinated relay slot fires this long after the frame it answers; slot k fires at
/// `SLOT_ORIGIN_MS + k * half_airtime`. Every SignalRouting node uses the same origin.
pub const SLOT_ORIGIN_MS: u32 = PEER_TURNAROUND_MS;

/// Wait before relaying a unicast whose destination heard the source directly: it needs the
/// turnaround, its contention delay (twice our maximum, since the channel may look busier to
/// it) and the ACK's own airtime.
pub fn dest_ack_wait_ms(ack_airtime_ms: u32, contention_max_ms: u32) -> u32 {
    PEER_TURNAROUND_MS
        .saturating_add(contention_max_ms.saturating_mul(2))
        .saturating_add(ack_airtime_ms)
}

/// Wait before acting in place of a designated SR next hop: its turnaround, its contention
/// delay and one airtime for its relay to leave the air.
pub fn peer_relay_wait_ms(airtime_ms: u32, contention_max_ms: u32) -> u32 {
    PEER_TURNAROUND_MS
        .saturating_add(contention_max_ms)
        .saturating_add(airtime_ms)
}

/// Delay of coordinated relay slot `slot` (0-based) after the frame it answers.
pub fn slot_delay_ms(slot: u32, half_airtime_ms: u32) -> u32 {
    SLOT_ORIGIN_MS.saturating_add(slot.saturating_mul(half_airtime_ms))
}

/// Gate between the router's frames and the radio. Times are `u32` milliseconds that wrap.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChannelAccess {
    hold_until_ms: u32,
    holding: bool,
}

impl ChannelAccess {
    pub const fn new() -> Self {
        Self {
            hold_until_ms: 0,
            holding: false,
        }
    }

    fn extend(&mut self, until_ms: u32, now_ms: u32) {
        if !self.holding || until_ms.wrapping_sub(self.hold_until_ms) < 0x8000_0000 {
            self.hold_until_ms = until_ms;
        }
        self.holding =
            self.hold_until_ms.wrapping_sub(now_ms) < 0x8000_0000 && self.hold_until_ms != now_ms;
    }

    /// A frame was received (or a transmission was deferred because one was arriving). Hold for
    /// the peers' turnaround or the contention backoff, whichever is longer; holds only extend.
    pub fn note_rx(&mut self, now_ms: u32, contention_backoff_ms: u32) {
        let hold = contention_backoff_ms.max(PEER_TURNAROUND_MS);
        self.extend(now_ms.wrapping_add(hold), now_ms);
    }

    /// One of our frames finished: keep the air clear for [`TX_GAP_MS`].
    pub fn note_tx_done(&mut self, now_ms: u32) {
        self.extend(now_ms.wrapping_add(TX_GAP_MS), now_ms);
    }

    /// May a frame be handed to the radio now?
    pub fn may_transmit(&self, now_ms: u32) -> bool {
        !self.holding || now_ms.wrapping_sub(self.hold_until_ms) < 0x8000_0000
    }

    /// Milliseconds until the hold clears (0 when clear).
    pub fn remaining_ms(&self, now_ms: u32) -> u32 {
        if self.may_transmit(now_ms) {
            0
        } else {
            self.hold_until_ms.wrapping_sub(now_ms)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reception_holds_for_at_least_the_turnaround() {
        let mut ca = ChannelAccess::new();
        assert!(ca.may_transmit(1_000));
        ca.note_rx(1_000, 20);
        assert!(!ca.may_transmit(1_000 + PEER_TURNAROUND_MS - 1));
        assert!(ca.may_transmit(1_000 + PEER_TURNAROUND_MS));
        ca.note_rx(2_000, PEER_TURNAROUND_MS + 300);
        assert_eq!(ca.remaining_ms(2_000), PEER_TURNAROUND_MS + 300);
    }

    #[test]
    fn holds_only_extend_and_tx_gap_applies() {
        let mut ca = ChannelAccess::new();
        ca.note_rx(1_000, 0);
        ca.note_tx_done(1_010); // shorter hold must not shorten the running one
        assert_eq!(ca.remaining_ms(1_010), PEER_TURNAROUND_MS - 10);
        ca.note_tx_done(1_000 + PEER_TURNAROUND_MS + 5);
        assert!(!ca.may_transmit(1_000 + PEER_TURNAROUND_MS + 5 + TX_GAP_MS - 1));
        assert!(ca.may_transmit(1_000 + PEER_TURNAROUND_MS + 5 + TX_GAP_MS));
    }

    #[test]
    fn wraps_across_the_u32_boundary() {
        let mut ca = ChannelAccess::new();
        ca.note_rx(u32::MAX - 10, 0);
        assert!(!ca.may_transmit(5));
        assert!(ca.may_transmit(PEER_TURNAROUND_MS));
    }

    #[test]
    fn peer_waits_derive_from_the_turnaround() {
        assert_eq!(dest_ack_wait_ms(80, 60), PEER_TURNAROUND_MS + 120 + 80);
        assert_eq!(peer_relay_wait_ms(80, 60), PEER_TURNAROUND_MS + 60 + 80);
        assert_eq!(slot_delay_ms(0, 50), SLOT_ORIGIN_MS);
        assert_eq!(slot_delay_ms(3, 50), SLOT_ORIGIN_MS + 150);
    }
}
