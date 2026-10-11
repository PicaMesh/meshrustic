pub const PEER_TURNAROUND_MS: u32 = 250;

pub const TX_GAP_MS: u32 = 100;

pub const SLOT_ORIGIN_MS: u32 = PEER_TURNAROUND_MS;

pub fn dest_ack_wait_ms(ack_airtime_ms: u32, contention_max_ms: u32) -> u32 {
    PEER_TURNAROUND_MS
        .saturating_add(contention_max_ms.saturating_mul(2))
        .saturating_add(ack_airtime_ms)
}

pub fn peer_relay_wait_ms(airtime_ms: u32, contention_max_ms: u32) -> u32 {
    PEER_TURNAROUND_MS
        .saturating_add(contention_max_ms)
        .saturating_add(airtime_ms)
}

pub fn slot_delay_ms(slot: u32, half_airtime_ms: u32, slot_time_ms: u32) -> u32 {
    crate::coordinated_relay::relay_floor_ms(slot_time_ms)
        .saturating_add(slot.saturating_mul(half_airtime_ms))
}

#[derive(Clone, Debug, Default)]
pub struct ChannelAccess {
    hold_until_ms: u32,
    holding: core::cell::Cell<bool>,
}

impl ChannelAccess {
    pub const fn new() -> Self {
        Self {
            hold_until_ms: 0,
            holding: core::cell::Cell::new(false),
        }
    }

    fn extend(&mut self, until_ms: u32, now_ms: u32) {
        if !self.holding.get() || until_ms.wrapping_sub(self.hold_until_ms) < 0x8000_0000 {
            self.hold_until_ms = until_ms;
        }
        self.holding.set(
            self.hold_until_ms.wrapping_sub(now_ms) < 0x8000_0000 && self.hold_until_ms != now_ms,
        );
    }

    /// A tiny contention draw must not shorten the radio turnaround hold.
    pub fn note_rx(&mut self, now_ms: u32, contention_backoff_ms: u32) {
        let hold = contention_backoff_ms.max(PEER_TURNAROUND_MS);
        self.extend(now_ms.wrapping_add(hold), now_ms);
    }

    pub fn note_tx_done(&mut self, now_ms: u32) {
        self.extend(now_ms.wrapping_add(TX_GAP_MS), now_ms);
    }

    pub fn may_transmit(&self, now_ms: u32) -> bool {
        if self.holding.get() && now_ms.wrapping_sub(self.hold_until_ms) < 0x8000_0000 {
            self.holding.set(false);
        }
        !self.holding.get()
    }

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
        ca.note_tx_done(1_010);
        assert_eq!(ca.remaining_ms(1_010), PEER_TURNAROUND_MS - 10);
        ca.note_tx_done(1_000 + PEER_TURNAROUND_MS + 5);
        assert!(!ca.may_transmit(1_000 + PEER_TURNAROUND_MS + 5 + TX_GAP_MS - 1));
        assert!(ca.may_transmit(1_000 + PEER_TURNAROUND_MS + 5 + TX_GAP_MS));
    }

    #[test]
    fn a_second_reception_extends_the_hold_and_never_shortens_it() {
        let mut ca = ChannelAccess::new();
        ca.note_rx(1_000, 0);
        ca.note_rx(1_100, 0);
        assert_eq!(ca.remaining_ms(1_100), PEER_TURNAROUND_MS);

        let mut ca = ChannelAccess::new();
        ca.note_rx(1_000, PEER_TURNAROUND_MS + 300);
        ca.note_rx(1_100, 0);
        assert_eq!(ca.remaining_ms(1_100), PEER_TURNAROUND_MS + 200);
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
        let slot = 10u32;
        let floor = crate::coordinated_relay::relay_floor_ms(slot);
        assert_eq!(slot_delay_ms(0, 50, slot), floor);
        assert_eq!(slot_delay_ms(3, 50, slot), floor + 150);
    }
    #[test]
    fn expired_channel_hold_cannot_reappear_after_clock_wrap() {
        let mut access = ChannelAccess::new();
        access.note_tx_done(10);
        assert!(access.may_transmit(10 + TX_GAP_MS));
        assert!(access.may_transmit(11));
    }
}
