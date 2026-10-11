//! Reservations describe another router’s uncertain draw; ranked positions are actual transmissions and
//! need airtime separation.

use crate::coordinated_relay::{relay_floor_ms, CW_MAX};

pub const WINDOW_POSITIONS: u8 = 2 * CW_MAX - 1;

pub const fn window_width_ms(slot_time_ms: u32) -> u32 {
    slot_time_ms.saturating_mul(WINDOW_POSITIONS as u32)
}

#[derive(Debug, Clone, Copy)]
pub struct WindowLayout {
    width_ms: u32,
    slot_time_ms: u32,
    half_airtime_ms: u32,
    cursor_ms: u32,
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

    pub fn place_reserved(&mut self) -> Option<u32> {
        self.place(self.slot_time_ms)
    }

    pub fn place_ranked(&mut self) -> Option<u32> {
        self.place(self.half_airtime_ms)
    }

    pub const fn is_empty(&self) -> bool {
        self.last_placed_end_ms.is_none()
    }

    pub const fn placed(&self) -> u8 {
        self.placed
    }

    /// At slow presets, a frame can outlast the transition window; the next rung must also clear the
    /// preceding frame.
    pub fn first_rung_ms(&self) -> u32 {
        let transition = relay_floor_ms(self.slot_time_ms);
        match self.last_placed_end_ms {
            None => transition,
            Some(last) => transition.max(last.saturating_add(self.half_airtime_ms)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PositionAllocator {
    window: WindowLayout,
    half_airtime_ms: u32,
    /// Moving the ladder origin after allocating a rung would reorder already assigned positions.
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

    pub fn take_reserved(&mut self) -> u32 {
        let at = match self.window.place_reserved() {
            Some(at) => at,
            None => self.spill(),
        };
        self.next_index = self.next_index.saturating_add(1);
        at
    }

    pub fn take_rung(&mut self) -> u32 {
        let at = match self.window.place_ranked() {
            Some(at) => at,
            None => self.spill(),
        };
        self.next_index = self.next_index.saturating_add(1);
        at
    }

    pub fn take_late_rung(&mut self) -> u32 {
        let at = self.spill();
        self.next_index = self.next_index.saturating_add(1);
        at
    }

    pub const fn next_index(&self) -> u8 {
        self.next_index
    }

    pub fn first_free_ms(&mut self) -> u32 {
        if self.window.is_empty() {
            self.window.first_rung_ms()
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
        assert_eq!(ranked_capacity(MODEM_SHORT_SLOW, 29), 3);
        assert_eq!(ranked_capacity(MODEM_SHORT_SLOW, 253), 1);
        assert_eq!(ranked_capacity(MODEM_LONG_FAST, 29), 2);
        assert_eq!(ranked_capacity(MODEM_LONG_FAST, 253), 1);
    }

    #[test]
    fn the_window_never_holds_more_than_its_positions() {
        let mut w = WindowLayout::new(1, 1);
        let mut n = 0u16;
        while w.place_reserved().is_some() {
            n += 1;
        }
        assert_eq!(n, WINDOW_POSITIONS as u16);
    }

    #[test]
    fn an_empty_window_puts_the_first_rung_at_the_transition() {
        let slot = slot_time_for_preset(MODEM_LONG_FAST);
        let w = WindowLayout::new(slot, half_for(MODEM_LONG_FAST, 253));
        assert!(w.is_empty());
        assert_eq!(w.first_rung_ms(), relay_floor_ms(slot));
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
            let slot = slot_time_for_preset(preset);
            let mut w = WindowLayout::new(slot, half);
            let first = w.place_reserved().expect("room for one");
            let rung = w.first_rung_ms();
            assert!(
                rung >= first + half,
                "preset {preset} payload {payload}: rung {rung} must clear {first} by {half}"
            );
            assert!(rung >= relay_floor_ms(slot));
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
        assert_eq!(r1, slot);
        assert_eq!(r1 / half, 0);
        assert_eq!(a.next_index(), 2);
    }

    #[test]
    fn late_rungs_never_enter_the_early_window() {
        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let half = half_for(MODEM_SHORT_SLOW, 48);
        let floor = relay_floor_ms(slot);
        let mut a = PositionAllocator::new(slot, half);
        assert_eq!(a.take_late_rung(), floor);
        assert_eq!(a.take_late_rung(), floor + half);
        let mut b = PositionAllocator::new(slot, half);
        b.take_rung();
        assert!(b.take_late_rung() >= floor);
    }

    #[test]
    fn rungs_take_window_positions_while_a_half_airtime_fits() {
        let half = half_for(MODEM_SHORT_SLOW, 48);
        let mut a = PositionAllocator::new(slot_time_for_preset(MODEM_SHORT_SLOW), half);
        assert_eq!(a.take_rung(), 0);
        assert_eq!(a.take_rung(), half);
        assert_eq!(a.take_rung(), 2 * half);
    }

    #[test]
    fn a_full_window_spills_ranked_positions_onto_the_ladder() {
        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let half = window_width_ms(slot);
        let mut a = PositionAllocator::new(slot, half);
        assert_eq!(a.take_rung(), 0);
        assert_eq!(a.take_rung(), relay_floor_ms(slot).max(half));
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
        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let half = half_for(MODEM_SHORT_SLOW, 48);
        let mut a = PositionAllocator::new(slot, half);
        assert_eq!(a.take_reserved(), 0);
        assert_eq!(a.take_rung(), slot);
        assert_eq!(a.take_rung(), slot + half);
    }

    #[test]
    fn nothing_placed_means_the_transition() {
        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let mut a = PositionAllocator::new(slot, half_for(MODEM_SHORT_SLOW, 48));
        assert_eq!(a.first_free_ms(), relay_floor_ms(slot));
    }

    #[test]
    fn a_single_reservation_at_short_slow_is_cleared_by_the_whole_transition() {
        let slot = slot_time_for_preset(MODEM_SHORT_SLOW);
        let half = half_for(MODEM_SHORT_SLOW, 48);
        let mut w = WindowLayout::new(slot, half);
        w.place_reserved();
        assert_eq!(w.first_rung_ms(), relay_floor_ms(slot));
    }
}
