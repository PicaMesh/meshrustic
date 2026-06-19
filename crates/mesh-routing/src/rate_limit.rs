//! Per-node inbound rate limiting (16 slots, 368 B).

use mesh_protocol::{rate_limit_bucket, RateLimitBucket};

const MAX_SLOTS: usize = 16;
const WINDOW_MS: u32 = 90_000;

const THRESHOLD_TEXT: u8 = 30;
const THRESHOLD_ROUTING: u8 = 10;
const THRESHOLD_OTHER: u8 = 4;

#[derive(Clone, Copy, Default)]
struct Slot {
    from: u32,
    text: u8,
    routing: u8,
    other: u8,
    limited: bool,
    window_start_ms: u32,
}

/// Fixed-size per-node abuse filter on the RX path.
pub struct NodeRateLimiter {
    slots: [Slot; MAX_SLOTS],
}

impl Default for NodeRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeRateLimiter {
    pub const fn new() -> Self {
        Self {
            slots: [Slot {
                from: 0,
                text: 0,
                routing: 0,
                other: 0,
                limited: false,
                window_start_ms: 0,
            }; MAX_SLOTS],
        }
    }

    /// Returns `true` when the packet should be dropped for rate abuse.
    pub fn should_drop(&mut self, from: u32, decoded_portnum: Option<u32>, now_ms: u32) -> bool {
        let bucket = rate_limit_bucket(decoded_portnum);
        let slot = self.find_or_alloc(from, now_ms);

        if slot.limited {
            slot.window_start_ms = now_ms;
            return true;
        }

        if now_ms.wrapping_sub(slot.window_start_ms) >= WINDOW_MS {
            slot.text = 0;
            slot.routing = 0;
            slot.other = 0;
            slot.window_start_ms = now_ms;
        }

        let (count, threshold) = match bucket {
            RateLimitBucket::Text => (&mut slot.text, THRESHOLD_TEXT),
            RateLimitBucket::Routing => (&mut slot.routing, THRESHOLD_ROUTING),
            RateLimitBucket::Other => (&mut slot.other, THRESHOLD_OTHER),
        };

        *count = count.saturating_add(1);
        if *count > threshold {
            slot.limited = true;
            slot.window_start_ms = now_ms;
            return true;
        }

        false
    }

    fn find_or_alloc(&mut self, from: u32, now_ms: u32) -> &mut Slot {
        if let Some(idx) = self.slots.iter().position(|s| s.from == from) {
            return &mut self.slots[idx];
        }

        if let Some(idx) = self.slots.iter().position(|s| s.from == 0) {
            self.slots[idx] = Slot {
                from,
                window_start_ms: now_ms,
                ..Slot::default()
            };
            return &mut self.slots[idx];
        }

        let idx = self
            .slots
            .iter()
            .position(|s| !s.limited && s.from != 0)
            .or_else(|| self.slots.iter().position(|s| !s.limited))
            .unwrap_or(0);
        self.slots[idx] = Slot {
            from,
            window_start_ms: now_ms,
            ..Slot::default()
        };
        &mut self.slots[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_protocol::num;

    #[test]
    fn other_bucket_limits_at_four() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0xAABB_CCDD;
        for i in 0..4 {
            assert!(
                !limiter.should_drop(from, None, i * 1000),
                "packet {i} should pass"
            );
        }
        assert!(limiter.should_drop(from, None, 5000));
        assert!(limiter.should_drop(from, None, 6000));
    }

    #[test]
    fn routing_bucket_has_higher_threshold() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0x1111_2222;
        for i in 0..10 {
            assert!(
                !limiter.should_drop(from, Some(num::ROUTING_APP), i * 100),
                "packet {i} should pass"
            );
        }
        assert!(limiter.should_drop(from, Some(num::ROUTING_APP), 2000));
    }
}
