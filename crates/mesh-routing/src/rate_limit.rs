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
    max_hop_seen: u8,
}

impl Slot {
    fn any_limited(&self) -> bool {
        self.text.limited || self.routing.limited || self.other.limited
    }

    fn oldest_window_start(&self) -> u32 {
        self.text
            .window_start_ms
            .min(self.routing.window_start_ms)
            .min(self.other.window_start_ms)
    }

    fn bucket_mut(&mut self, kind: RateLimitBucket) -> &mut Bucket {
        match kind {
            RateLimitBucket::Text => &mut self.text,
            RateLimitBucket::Routing => &mut self.routing,
            RateLimitBucket::Other => &mut self.other,
        }
    }
}

fn fresh_slot(from: u32, now_ms: u32, hops: u8) -> Slot {
    let bucket = Bucket {
        window_start_ms: now_ms,
        ..Bucket::default()
    };
    Slot {
        from,
        text: bucket,
        routing: bucket,
        other: bucket,
        max_hop_seen: hops,
    }
}

fn hops_away(hop_start: u8, hop_limit: u8) -> u8 {
    if hop_start == 0 || hop_limit >= hop_start {
        0
    } else {
        hop_start - hop_limit
    }
}

/// Fixed-size per-node abuse filter on the RX path.
pub struct NodeRateLimiter {
    node_num: u32,
    slots: [Slot; MAX_SLOTS],
}

impl Default for NodeRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeRateLimiter {
    pub const fn new() -> Self {
        Self::with_node_num(0)
    }

    pub const fn with_node_num(node_num: u32) -> Self {
        Self {
            node_num,
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
    pub fn should_drop(
        &mut self,
        from: u32,
        decoded_portnum: Option<u32>,
        hop_start: u8,
        hop_limit: u8,
        now_ms: u32,
    ) -> bool {
        if from == 0 || from == self.node_num {
            return false;
        }

        let bucket_kind = rate_limit_bucket(decoded_portnum);
        let threshold = match bucket_kind {
            RateLimitBucket::Text => THRESHOLD_TEXT,
            RateLimitBucket::Routing => THRESHOLD_ROUTING,
            RateLimitBucket::Other => THRESHOLD_OTHER,
        };

        let hops = hops_away(hop_start, hop_limit);
        let slot = self.find_or_alloc(from, hops, now_ms);
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
        if bucket.count >= threshold {
            bucket.limited = true;
            bucket.window_start_ms = now_ms;
            return true;
        }

        false
    }

    fn find_eviction_candidate(slots: &[Slot; MAX_SLOTS]) -> usize {
        let mut candidate: Option<usize> = None;
        for (i, slot) in slots.iter().enumerate() {
            if slot.from == 0 || slot.any_limited() {
                continue;
            }
            candidate = Some(match candidate {
                None => i,
                Some(c) => {
                    let s = &slots[i];
                    let cur = &slots[c];
                    if s.max_hop_seen > cur.max_hop_seen {
                        i
                    } else if s.max_hop_seen == cur.max_hop_seen
                        && s.oldest_window_start() < cur.oldest_window_start()
                    {
                        i
                    } else {
                        c
                    }
                }
            });
        }
        if let Some(c) = candidate {
            return c;
        }

        let mut oldest = 0usize;
        let mut found = false;
        for (i, slot) in slots.iter().enumerate() {
            if slot.from == 0 {
                continue;
            }
            if !found || slot.oldest_window_start() < slots[oldest].oldest_window_start() {
                oldest = i;
                found = true;
            }
        }
        oldest
    }

    fn find_or_alloc(&mut self, from: u32, hops: u8, now_ms: u32) -> &mut Slot {
        if let Some(idx) = self.slots.iter().position(|s| s.from == from) {
            if hops > self.slots[idx].max_hop_seen {
                self.slots[idx].max_hop_seen = hops;
            }
            return &mut self.slots[idx];
        }

        if let Some(idx) = self.slots.iter().position(|s| s.from == 0) {
            self.slots[idx] = fresh_slot(from, now_ms, hops);
            return &mut self.slots[idx];
        }

        let idx = Self::find_eviction_candidate(&self.slots);
        self.slots[idx] = fresh_slot(from, now_ms, hops);
        &mut self.slots[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_protocol::num;

    fn drop_other(limiter: &mut NodeRateLimiter, from: u32, now_ms: u32) -> bool {
        limiter.should_drop(from, None, 3, 3, now_ms)
    }

    fn drop_routing(limiter: &mut NodeRateLimiter, from: u32, now_ms: u32) -> bool {
        limiter.should_drop(from, Some(num::ROUTING_APP), 3, 3, now_ms)
    }

    fn drop_text(limiter: &mut NodeRateLimiter, from: u32, now_ms: u32) -> bool {
        limiter.should_drop(from, Some(num::TEXT_MESSAGE_APP), 3, 3, now_ms)
    }

    impl NodeRateLimiter {
        fn is_tracking(&self, from: u32) -> bool {
            self.slots.iter().any(|s| s.from == from)
        }

        fn active_slot_count(&self) -> usize {
            self.slots.iter().filter(|s| s.from != 0).count()
        }
    }

    fn fill_slot(limiter: &mut NodeRateLimiter, from: u32, now_ms: u32) {
        assert!(!drop_other(limiter, from, now_ms));
    }

    fn limit_other(limiter: &mut NodeRateLimiter, from: u32, base_ms: u32) {
        let mut t = base_ms;
        loop {
            if drop_other(limiter, from, t) {
                return;
            }
            t += 1;
            assert!(t <= base_ms + 16, "failed to trip OTHER bucket limit for {from:#x}");
        }
    }

    #[test]
    fn other_bucket_limits_at_four() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0xAABB_CCDD;
        for i in 0..3 {
            assert!(
                !drop_other(&mut limiter, from, i * 1000),
                "packet {i} should pass"
            );
        }
        assert!(
            drop_other(&mut limiter, from, 3000),
            "4th OTHER packet should drop"
        );
        assert!(drop_other(&mut limiter, from, 4000));
    }

    #[test]
    fn routing_bucket_has_higher_threshold() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0x1111_2222;
        for i in 0..9 {
            assert!(
                !drop_routing(&mut limiter, from, i * 100),
                "packet {i} should pass"
            );
        }
        assert!(
            drop_routing(&mut limiter, from, 900),
            "10th routing packet should drop"
        );
    }

    #[test]
    fn text_bucket_limits_at_thirty() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0x5555_6666;
        for i in 0..29 {
            assert!(
                !drop_text(&mut limiter, from, i * 100),
                "packet {i} should pass"
            );
        }
        assert!(
            drop_text(&mut limiter, from, 2900),
            "30th text packet should drop"
        );
    }

    #[test]
    fn limiting_other_bucket_does_not_limit_text() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0xDEAD_BEEF;
        for i in 0..4 {
            drop_other(&mut limiter, from, i * 1000);
        }
        assert!(
            drop_other(&mut limiter, from, 6000),
            "OTHER bucket should be limited"
        );
        assert!(
            !drop_text(&mut limiter, from, 7000),
            "TEXT bucket should still accept packets"
        );
    }

    #[test]
    fn limited_node_recovers_after_quiet_window() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0x1234_5678;
        for _ in 0..3 {
            assert!(!drop_other(&mut limiter, from, 0));
        }
        assert!(
            drop_other(&mut limiter, from, 0),
            "4th OTHER packet should trip the limit"
        );
        assert!(
            !drop_other(&mut limiter, from, WINDOW_MS + 1),
            "quiet for a full window should lift the limit"
        );
    }

    #[test]
    fn activity_during_limit_prevents_recovery() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0x8765_4321;
        for _ in 0..3 {
            assert!(!drop_other(&mut limiter, from, 0));
        }
        assert!(drop_other(&mut limiter, from, 0));

        let mut t = WINDOW_MS - 1;
        for _ in 0..5 {
            assert!(
                drop_other(&mut limiter, from, t),
                "activity every WINDOW_MS-1 ms should stay limited"
            );
            t = t.wrapping_add(WINDOW_MS - 1);
        }
    }

    #[test]
    fn each_bucket_has_its_own_window() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0xCAFE_BABE;

        for i in 0..9 {
            assert!(
                !drop_routing(&mut limiter, from, i * 1000),
                "routing packet {i} should pass"
            );
        }
        for i in 0..28 {
            assert!(
                !drop_text(&mut limiter, from, 10_000 + i * 100),
                "text packet {i} should pass"
            );
        }

        assert!(
            drop_routing(&mut limiter, from, 20_000),
            "10th routing packet should drop"
        );
        assert!(
            !drop_text(&mut limiter, from, 21_000),
            "29th text packet should still pass"
        );
    }

    #[test]
    fn eviction_prefers_farthest_non_limited() {
        let mut limiter = NodeRateLimiter::new();
        for i in 0..16u32 {
            fill_slot(&mut limiter, 0x1000 + i, i);
        }
        assert!(!limiter.should_drop(0x1002, None, 5, 3, 100));
        assert!(!limiter.should_drop(0x1008, None, 8, 3, 100));

        assert!(!drop_other(&mut limiter, 0x2000, 200));

        assert!(limiter.is_tracking(0x2000));
        assert!(!limiter.is_tracking(0x1008), "farthest non-limited slot evicted");
        assert!(limiter.is_tracking(0x1002));
    }

    #[test]
    fn eviction_never_drops_limited_entry_when_unlimited_exists() {
        let mut limiter = NodeRateLimiter::new();
        for i in 0..16u32 {
            fill_slot(&mut limiter, 0x1000 + i, i);
        }
        limit_other(&mut limiter, 0x1000, 1_000);
        assert!(!limiter.should_drop(0x100F, None, 10, 3, 2_000));

        assert!(!drop_other(&mut limiter, 0x2000, 3_000));

        assert!(limiter.is_tracking(0x1000), "limited entry kept");
        assert!(!limiter.is_tracking(0x100F), "farthest unlimited entry evicted");
        assert!(limiter.is_tracking(0x2000));
    }

    #[test]
    fn all_limited_evicts_oldest_window() {
        let mut limiter = NodeRateLimiter::new();
        for i in 0..16u32 {
            fill_slot(&mut limiter, 0x1000 + i, i * 1_000);
        }
        for i in 0..16u32 {
            limit_other(&mut limiter, 0x1000 + i, i * 1_000 + 100);
        }

        assert!(!drop_other(&mut limiter, 0x2000, 50_000));

        assert!(!limiter.is_tracking(0x1000), "oldest limited window evicted");
        assert!(limiter.is_tracking(0x2000));
        assert!(limiter.is_tracking(0x100F));
    }

    #[test]
    fn hops_away_computes_from_hop_fields() {
        assert_eq!(hops_away(0, 0), 0);
        assert_eq!(hops_away(3, 3), 0);
        assert_eq!(hops_away(5, 3), 2);
        assert_eq!(hops_away(2, 5), 0);
    }

    #[test]
    fn from_zero_is_never_rate_limited() {
        let mut limiter = NodeRateLimiter::with_node_num(0xBEEF_BEEF);
        for i in 0..10 {
            assert!(
                !limiter.should_drop(0, None, 3, 3, i * 1000),
                "from=0 must never drop"
            );
        }
        assert_eq!(limiter.active_slot_count(), 0);
    }

    #[test]
    fn own_node_is_never_rate_limited() {
        let own = 0xCAFE_BABE;
        let mut limiter = NodeRateLimiter::with_node_num(own);
        for i in 0..10 {
            assert!(
                !limiter.should_drop(own, None, 3, 3, i * 1000),
                "own node must never drop"
            );
            assert!(
                !limiter.should_drop(own, Some(num::TEXT_MESSAGE_APP), 3, 3, i * 100),
                "own node text must never drop"
            );
        }
        assert_eq!(limiter.active_slot_count(), 0);
    }
}
