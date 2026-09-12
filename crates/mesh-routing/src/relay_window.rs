//! The stock-router window: where reserved positions and early ranked positions sit, and where
//! the ladder's first rung lands once the window has been laid out.
//!
//! A stock ROUTER's delay is a hardware-seeded draw from a window whose width is set by the SNR it
//! measured, a value that appears nowhere on the wire. Neither the draw nor the width is ours to
//! compute, so a reserved position orders *our expectation* that the router transmits — not its
//! transmission. That is why reservations are spaced by one slot time, stock's own granularity
//! here, rather than by half an airtime: spacing an expectation by the airtime of a frame we are
//! not sending states a precision we do not have, and it is the only spacing under which the
//! window has a defined capacity.
//!
//! A ranked position is the opposite: it is a real transmit time of ours, so it takes a rung's
//! separation — one floored half-airtime — and two of them can never collide because the ranking
//! assigns them.

use crate::channel_access::SLOT_ORIGIN_MS;
use crate::coordinated_relay::CW_MAX;

/// Positions the window holds, at stock's granularity: `2·CWmax − 1`.
pub const WINDOW_POSITIONS: u8 = 2 * CW_MAX - 1;

/// Width of the stock-router window, in milliseconds.
pub const fn window_width_ms(slot_time_ms: u32) -> u32 {
    slot_time_ms.saturating_mul(WINDOW_POSITIONS as u32)
}

/// Lays positions out from the window's start, each taking its own width.
///
/// Reservations and ranked positions share one window and one cursor: they are placed in rank
/// order, so a top-ranked SR ROUTER is early at every preset, and a candidate for which no
/// position remains falls past the transition keeping its rank.
#[derive(Debug, Clone, Copy)]
pub struct WindowLayout {
    width_ms: u32,
    slot_time_ms: u32,
    half_airtime_ms: u32,
    /// Start of the next free position.
    cursor_ms: u32,
    /// Start of the last position actually placed, and its width.
    last_placed_end_ms: Option<u32>,
    placed: u8,
}

impl WindowLayout {
    pub fn new(slot_time_ms: u32, half_airtime_ms: u32) -> Self {
        Self {
            width_ms: window_width_ms(slot_time_ms),
            slot_time_ms,
            half_airtime_ms,
            cursor_ms: 0,
            last_placed_end_ms: None,
            placed: 0,
        }
    }

    fn place(&mut self, width_ms: u32) -> Option<u32> {
        if self.placed >= WINDOW_POSITIONS {
            return None;
        }
        let at = self.cursor_ms;
        if at >= self.width_ms {
            return None;
        }
        self.cursor_ms = at.saturating_add(width_ms);
        self.last_placed_end_ms = Some(at);
        self.placed = self.placed.saturating_add(1);
        Some(at)
    }

    /// Reserve the next position for a stock relay router. One slot time wide.
    pub fn place_reserved(&mut self) -> Option<u32> {
        self.place(self.slot_time_ms)
    }

    /// Take the next position for a ranked candidate of ours. One floored half-airtime wide.
    pub fn place_ranked(&mut self) -> Option<u32> {
        self.place(self.half_airtime_ms)
    }

    pub const fn is_empty(&self) -> bool {
        self.last_placed_end_ms.is_none()
    }

    pub const fn placed(&self) -> u8 {
        self.placed
    }

    /// Where the ladder's first rung goes.
    ///
    /// Anchored to [`SLOT_ORIGIN_MS`], the literal 250 ms, and deliberately not to
    /// [`crate::coordinated_relay::relay_floor_ms`] — even though the window laid out above *is*
    /// the `2·CWmax − 1` slots immediately below that border, so the two are one geometry expressed
    /// twice. Moving this origin onto the preset-derived border is a separate change with its own
    /// ordering constraint, and doing it here would shift on-air timing at LONG_FAST and slower
    /// (448 ms against 250) as a side effect of a change that is meant to be about *placement*.
    /// Until then the two anchors disagree: at SHORT_SLOW the window ends at 150 ms and the first
    /// rung sits at 250, so a reservation rarely moves it at all.
    ///
    /// The empty case is stated separately on purpose. Folding it into the formula leaves the last
    /// position at zero and degenerates to a bare half-airtime — on a mesh with no router at all
    /// that is 6,095 ms at LONG_SLOW, which is the bug an earlier capacity rule was withdrawn for.
    ///
    /// When the window is occupied the rung clears the last position by **at least** one floored
    /// half-airtime, never exactly one: with a single reservation and no ranked position at
    /// SHORT_SLOW the separation is the whole transition. It is not the bare transition either,
    /// because at LONG_FAST and slower a half-airtime exceeds it and a rung there would land inside
    /// the preceding position's frame.
    pub fn first_rung_ms(&self) -> u32 {
        match self.last_placed_end_ms {
            None => SLOT_ORIGIN_MS,
            Some(last) => SLOT_ORIGIN_MS.max(last.saturating_add(self.half_airtime_ms)),
        }
    }
}

/// Hands out transmit positions in rank order: the window first, the ladder past the transition
/// once it is full.
///
/// One allocator rather than one accumulator shared by two loops. The reservation pre-pass and the
/// ranking loop previously advanced the same `slot_delay` by a half-airtime each, which priced a
/// reservation as if it were a rung of ours and left the rung index to be reconstructed by dividing
/// a delay. Here each position is placed by its own rule and carries its own index, so the index is
/// what was assigned rather than what can be inferred afterwards.
#[derive(Debug, Clone, Copy)]
pub struct PositionAllocator {
    window: WindowLayout,
    half_airtime_ms: u32,
    /// Frozen when the window first runs out: the ladder's start cannot move afterwards, or a
    /// later spill would reorder the positions already handed out.
    ladder_start_ms: Option<u32>,
    next_index: u8,
}

impl PositionAllocator {
    pub fn new(slot_time_ms: u32, half_airtime_ms: u32) -> Self {
        Self {
            window: WindowLayout::new(slot_time_ms, half_airtime_ms),
            half_airtime_ms,
            ladder_start_ms: None,
            next_index: 0,
        }
    }

    fn spill(&mut self) -> u32 {
        let start = *self
            .ladder_start_ms
            .get_or_insert_with(|| self.window.first_rung_ms());
        let rung = self.next_index.saturating_sub(self.window.placed());
        start.saturating_add((rung as u32).saturating_mul(self.half_airtime_ms))
    }

    /// The position a stock relay router holds: one slot time wide, inside the window.
    pub fn take_reserved(&mut self) -> u32 {
        let at = match self.window.place_reserved() {
            Some(at) => at,
            None => self.spill(),
        };
        self.next_index = self.next_index.saturating_add(1);
        at
    }

    /// The rung a ranked candidate of ours holds: inside the window while a half-airtime still
    /// fits, otherwise on the ladder past the transition.
    ///
    /// An SR node's position is ours to place and is a real transmit time, so it takes a rung's
    /// separation rather than a reservation's. Letting it sit inside the window is what makes a
    /// top-ranked SR ROUTER early at every preset; when the window is full the candidate keeps its
    /// rank on the ladder.
    pub fn take_rung(&mut self) -> u32 {
        let at = match self.window.place_ranked() {
            Some(at) => at,
            None => self.spill(),
        };
        self.next_index = self.next_index.saturating_add(1);
        at
    }

    /// Index the next position will be given: what a rung index means once positions are placed
    /// by rule rather than spaced by one constant.
    pub const fn next_index(&self) -> u8 {
        self.next_index
    }

    /// Where a transmission goes when nothing was placed ahead of it.
    pub fn first_free_ms(&mut self) -> u32 {
        if self.window.is_empty() {
            crate::channel_access::SLOT_ORIGIN_MS
        } else {
            self.spill()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinated_relay::{half_airtime_ms, slot_time_for_preset};
    use mesh_radio::{eu868_config_for_preset, packet_time_ms, MODEM_LONG_FAST, MODEM_SHORT_SLOW};

    fn half_for(preset: u8, payload: usize) -> u32 {
        let cfg = eu868_config_for_preset(preset);
        half_airtime_ms(packet_time_ms(&cfg, payload, true))
    }

    /// Capacity for ranked positions, against the figures the design tabulates.
    fn ranked_capacity(preset: u8, payload: usize) -> u8 {
        let mut w = WindowLayout::new(slot_time_for_preset(preset), half_for(preset, payload));
        let mut n = 0u8;
        while w.place_ranked().is_some() {
            n += 1;
        }
        n
    }

    #[test]
    fn the_window_holds_stocks_own_granularity() {
        assert_eq!(WINDOW_POSITIONS, 15);
        assert_eq!(window_width_ms(slot_time_for_preset(MODEM_SHORT_SLOW)), 150);
        assert_eq!(window_width_ms(slot_time_for_preset(MODEM_LONG_FAST)), 420);
    }

    #[test]
    fn reservations_sit_one_slot_apart_not_one_airtime_apart() {
        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let mut w = WindowLayout::new(slot, half_for(MODEM_SHORT_SLOW, 48));
        assert_eq!(w.place_reserved(), Some(0));
        assert_eq!(w.place_reserved(), Some(slot));
        assert_eq!(w.place_reserved(), Some(2 * slot));
    }

    #[test]
    fn ranked_positions_sit_one_half_airtime_apart() {
        let half = half_for(MODEM_SHORT_SLOW, 48);
        let mut w = WindowLayout::new(slot_time_for_preset(MODEM_SHORT_SLOW), half);
        assert_eq!(w.place_ranked(), Some(0));
        assert_eq!(w.place_ranked(), Some(half));
    }

    #[test]
    fn ranked_capacity_matches_the_design_table() {
        // design Item 3b, recomputed from this crate's own airtime function
        assert_eq!(ranked_capacity(MODEM_SHORT_SLOW, 29), 3);
        assert_eq!(ranked_capacity(MODEM_SHORT_SLOW, 253), 1);
        assert_eq!(ranked_capacity(MODEM_LONG_FAST, 29), 2);
        assert_eq!(ranked_capacity(MODEM_LONG_FAST, 253), 1);
    }

    #[test]
    fn the_window_never_holds_more_than_its_positions() {
        // A slot time small against the window still cannot exceed the position count.
        let mut w = WindowLayout::new(1, 1);
        let mut n = 0u16;
        while w.place_reserved().is_some() {
            n += 1;
        }
        assert_eq!(n, WINDOW_POSITIONS as u16);
    }

    #[test]
    fn an_empty_window_puts_the_first_rung_at_the_transition() {
        // Not at a bare half-airtime: that is the degenerate case a withdrawn rule produced.
        let w = WindowLayout::new(
            slot_time_for_preset(MODEM_LONG_FAST),
            half_for(MODEM_LONG_FAST, 253),
        );
        assert!(w.is_empty());
        assert_eq!(w.first_rung_ms(), SLOT_ORIGIN_MS);
    }

    #[test]
    fn an_occupied_window_clears_its_last_position_by_at_least_a_half_airtime() {
        for &(preset, payload) in &[
            (MODEM_SHORT_SLOW, 29usize),
            (MODEM_SHORT_SLOW, 253),
            (MODEM_LONG_FAST, 29),
            (MODEM_LONG_FAST, 253),
        ] {
            let half = half_for(preset, payload);
            let mut w = WindowLayout::new(slot_time_for_preset(preset), half);
            let first = w.place_reserved().expect("room for one");
            let rung = w.first_rung_ms();
            assert!(
                rung >= first + half,
                "preset {preset} payload {payload}: rung {rung} must clear {first} by {half}"
            );
            assert!(rung >= SLOT_ORIGIN_MS);
        }
    }

    #[test]
    fn positions_are_indexed_by_assignment_not_by_dividing_a_delay() {
        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let half = half_for(MODEM_SHORT_SLOW, 48);
        let mut a = PositionAllocator::new(slot, half);
        assert_eq!(a.next_index(), 0);
        let r0 = a.take_reserved();
        assert_eq!((r0, a.next_index()), (0, 1));
        let r1 = a.take_reserved();
        // A reservation advances by a slot time, so dividing this delay by a half-airtime would
        // put both reservations at index 0. The index is assigned, not inferred.
        assert_eq!(r1, slot);
        assert_eq!(r1 / half, 0);
        assert_eq!(a.next_index(), 2);
    }

    #[test]
    fn rungs_take_window_positions_while_a_half_airtime_fits() {
        let half = half_for(MODEM_SHORT_SLOW, 48);
        let mut a = PositionAllocator::new(slot_time_for_preset(MODEM_SHORT_SLOW), half);
        // Empty window: the first ranked position is at the window start, not the transition.
        assert_eq!(a.take_rung(), 0);
        assert_eq!(a.take_rung(), half);
        assert_eq!(a.take_rung(), 2 * half);
    }

    #[test]
    fn a_full_window_spills_ranked_positions_onto_the_ladder() {
        // One half-airtime that fills the whole SHORT_SLOW window: the first ranked fits, the
        // second must clear the transition.
        let half = window_width_ms(slot_time_for_preset(MODEM_SHORT_SLOW));
        let mut a = PositionAllocator::new(slot_time_for_preset(MODEM_SHORT_SLOW), half);
        assert_eq!(a.take_rung(), 0);
        assert_eq!(a.take_rung(), SLOT_ORIGIN_MS.max(half));
    }

    #[test]
    fn a_reservation_pushes_the_first_rung_later_never_earlier() {
        for &(preset, payload) in &[
            (MODEM_SHORT_SLOW, 48usize),
            (MODEM_SHORT_SLOW, 253),
            (MODEM_LONG_FAST, 48),
            (MODEM_LONG_FAST, 253),
        ] {
            let half = half_for(preset, payload);
            let slot = slot_time_for_preset(preset);
            let mut bare = PositionAllocator::new(slot, half);
            let without = bare.take_rung();
            let mut held = PositionAllocator::new(slot, half);
            held.take_reserved();
            let with = held.take_rung();
            assert!(
                with >= without,
                "preset {preset} payload {payload}: {with} must not precede {without}"
            );
        }
    }

    #[test]
    fn reservations_and_ranked_positions_interleave_in_the_window() {
        // Worked example from the design: SHORT_SLOW, 48 B — one reservation at 0, then ranked
        // positions a half-airtime apart inside what remains.
        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let half = half_for(MODEM_SHORT_SLOW, 48);
        let mut a = PositionAllocator::new(slot, half);
        assert_eq!(a.take_reserved(), 0);
        assert_eq!(a.take_rung(), slot);
        assert_eq!(a.take_rung(), slot + half);
    }

    #[test]
    fn nothing_placed_means_the_transition() {
        let mut a = PositionAllocator::new(
            slot_time_for_preset(MODEM_SHORT_SLOW),
            half_for(MODEM_SHORT_SLOW, 48),
        );
        assert_eq!(a.first_free_ms(), SLOT_ORIGIN_MS);
    }

    #[test]
    fn a_single_reservation_at_short_slow_is_cleared_by_the_whole_transition() {
        // The invariant is "at least" one half-airtime, not "exactly": here it is far more.
        let half = half_for(MODEM_SHORT_SLOW, 48);
        let mut w = WindowLayout::new(slot_time_for_preset(MODEM_SHORT_SLOW), half);
        w.place_reserved();
        assert_eq!(w.first_rung_ms(), SLOT_ORIGIN_MS);
    }
}
