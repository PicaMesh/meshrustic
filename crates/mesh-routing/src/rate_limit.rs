//! Per-node inbound rate limiting (16 slots, 368 B).
//!
//! Each tracked node keeps three independent buckets (TEXT, ROUTING, OTHER). A limit
//! on one bucket does not affect the others; each bucket has its own window, count, and
//! limited flag.

use mesh_protocol::{rate_limit_bucket, RateLimitBucket};

const MAX_SLOTS: usize = 16;
const WINDOW_MS: u32 = 90_000;

const THRESHOLD_TEXT: u8 = 30;
const THRESHOLD_ROUTING: u8 = 10;
const THRESHOLD_OTHER: u8 = 4;

#[derive(Clone, Copy, Default)]
struct Bucket {
    window_start_ms: u32,
    count: u8,
    limited: bool,
}

#[derive(Clone, Copy, Default)]
struct Slot {
    from: u32,
    text: Bucket,
    routing: Bucket,
    other: Bucket,
    #[allow(dead_code)]
    max_hop_seen: u8,
}

impl Slot {
    fn any_limited(&self) -> bool {
        self.text.limited || self.routing.limited || self.other.limited
    }

    fn bucket_mut(&mut self, kind: RateLimitBucket) -> &mut Bucket {
        match kind {
            RateLimitBucket::Text => &mut self.text,
            RateLimitBucket::Routing => &mut self.routing,
            RateLimitBucket::Other => &mut self.other,
        }
    }
}

fn fresh_slot(from: u32, now_ms: u32) -> Slot {
    let bucket = Bucket {
        window_start_ms: now_ms,
        ..Bucket::default()
    };
    Slot {
        from,
        text: bucket,
        routing: bucket,
        other: bucket,
        ..Slot::default()
    }
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
                text: Bucket {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                },
                routing: Bucket {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                },
                other: Bucket {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                },
                max_hop_seen: 0,
            }; MAX_SLOTS],
        }
    }

    /// Returns `true` when the packet should be dropped for rate abuse.
    pub fn should_drop(&mut self, from: u32, decoded_portnum: Option<u32>, now_ms: u32) -> bool {
        let bucket_kind = rate_limit_bucket(decoded_portnum);
        let threshold = match bucket_kind {
            RateLimitBucket::Text => THRESHOLD_TEXT,
            RateLimitBucket::Routing => THRESHOLD_ROUTING,
            RateLimitBucket::Other => THRESHOLD_OTHER,
        };

        let slot = self.find_or_alloc(from, now_ms);
        let bucket = slot.bucket_mut(bucket_kind);

        if bucket.limited {
            let window_age = now_ms.wrapping_sub(bucket.window_start_ms);
            if window_age >= WINDOW_MS {
                bucket.limited = false;
                bucket.count = 0;
                bucket.window_start_ms = now_ms;
            } else {
                bucket.window_start_ms = now_ms;
                return true;
            }
        }

        if now_ms.wrapping_sub(bucket.window_start_ms) >= WINDOW_MS {
            bucket.count = 0;
            bucket.window_start_ms = now_ms;
        }

        bucket.count = bucket.count.saturating_add(1);
        if bucket.count > threshold {
            bucket.limited = true;
            bucket.window_start_ms = now_ms;
            return true;
        }

        false
    }

    fn find_or_alloc(&mut self, from: u32, now_ms: u32) -> &mut Slot {
        if let Some(idx) = self.slots.iter().position(|s| s.from == from) {
            return &mut self.slots[idx];
        }

        if let Some(idx) = self.slots.iter().position(|s| s.from == 0) {
            self.slots[idx] = fresh_slot(from, now_ms);
            return &mut self.slots[idx];
        }

        let idx = self
            .slots
            .iter()
            .position(|s| !s.any_limited() && s.from != 0)
            .or_else(|| self.slots.iter().position(|s| !s.any_limited()))
            .unwrap_or(0);
        self.slots[idx] = fresh_slot(from, now_ms);
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

    #[test]
    fn limiting_other_bucket_does_not_limit_text() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0xDEAD_BEEF;
        for i in 0..5 {
            limiter.should_drop(from, None, i * 1000);
        }
        assert!(
            limiter.should_drop(from, None, 6000),
            "OTHER bucket should be limited"
        );
        assert!(
            !limiter.should_drop(from, Some(num::TEXT_MESSAGE_APP), 7000),
            "TEXT bucket should still accept packets"
        );
    }

    #[test]
    fn limited_node_recovers_after_quiet_window() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0x1234_5678;
        for _ in 0..4 {
            assert!(!limiter.should_drop(from, None, 0));
        }
        assert!(
            limiter.should_drop(from, None, 0),
            "5th OTHER packet should trip the limit"
        );
        assert!(
            !limiter.should_drop(from, None, WINDOW_MS + 1),
            "quiet for a full window should lift the limit"
        );
    }

    #[test]
    fn activity_during_limit_prevents_recovery() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0x8765_4321;
        for _ in 0..4 {
            assert!(!limiter.should_drop(from, None, 0));
        }
        assert!(limiter.should_drop(from, None, 0));

        let mut t = WINDOW_MS - 1;
        for _ in 0..5 {
            assert!(
                limiter.should_drop(from, None, t),
                "activity every WINDOW_MS-1 ms should stay limited"
            );
            t = t.wrapping_add(WINDOW_MS - 1);
        }
    }

    #[test]
    fn each_bucket_has_its_own_window() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0xCAFE_BABE;

        for i in 0..10 {
            assert!(
                !limiter.should_drop(from, Some(num::ROUTING_APP), i * 1000),
                "routing packet {i} should pass"
            );
        }
        for i in 0..29 {
            assert!(
                !limiter.should_drop(from, Some(num::TEXT_MESSAGE_APP), 10_000 + i * 100),
                "text packet {i} should pass"
            );
        }

        assert!(
            limiter.should_drop(from, Some(num::ROUTING_APP), 20_000),
            "11th routing packet should drop"
        );
        assert!(
            !limiter.should_drop(from, Some(num::TEXT_MESSAGE_APP), 21_000),
            "30th text packet not yet reached"
        );
    }
}
