//! Per-node inbound rate limiting (SignalRouting).
//!
//! Originator path: up to 16 sources, each with TEXT / ROUTING / OTHER / UNKNOWN packet-count
//! buckets. RELAY path: rebroadcast candidates charge the last hop — 8 resolved NodeID slots
//! plus one shared bucket for unresolved `relay_node` bytes — using an airtime budget tightened
//! by local channel utilization.
//!
//! Uniform hysteresis: trip / clear / fixed window; while limited, drop matching traffic. Originator
//! clear=0 (quiet window); RELAY clear>0 (lift when count is below clear at window roll).

use mesh_protocol::{rate_limit_bucket, RateLimitBucket};

const MAX_ORIGINATORS: usize = 16;
const MAX_RELAYS: usize = 8;
const WINDOW_MS: u32 = 90_000;

const THRESHOLD_TEXT: u32 = 30;
const THRESHOLD_ROUTING: u32 = 10;
const THRESHOLD_OTHER: u32 = 4;
/// Undecodable traffic. Sized so a relayed remote-admin Channels screen (channel 0, LoRa
/// config, then channels 1..7 one at a time: nine requests, nine replies) loads in one window.
const THRESHOLD_UNKNOWN: u32 = 12;
const ORIGINATOR_CLEAR: u32 = 0;

const RELAY_TRIP_PACKETS: u32 = 60;
const RELAY_CLEAR_PACKETS: u32 = 15;
const RELAY_REF_AIRTIME_MS: u32 = 100;
const RELAY_TRIP_FLOOR_MS: u32 = 20 * RELAY_REF_AIRTIME_MS;
const RELAY_TRIP_CEIL_MS: u32 = 120 * RELAY_REF_AIRTIME_MS;
const RELAY_CLEAR_FLOOR_MS: u32 = 5 * RELAY_REF_AIRTIME_MS;
const RELAY_CLEAR_CEIL_MS: u32 = 40 * RELAY_REF_AIRTIME_MS;

#[derive(Clone, Copy, Default)]
struct BucketState {
    window_start_ms: u32,
    /// Packets (originator) or airtime ms (RELAY).
    count: u32,
    limited: bool,
}

#[derive(Clone, Copy, Default)]
struct OriginatorEntry {
    node_id: u32,
    text: BucketState,
    routing: BucketState,
    other: BucketState,
    unknown: BucketState,
}

impl OriginatorEntry {
    fn any_limited(&self) -> bool {
        self.text.limited || self.routing.limited || self.other.limited || self.unknown.limited
    }

    fn oldest_window_start(&self) -> u32 {
        self.text
            .window_start_ms
            .min(self.routing.window_start_ms)
            .min(self.other.window_start_ms)
            .min(self.unknown.window_start_ms)
    }

    fn bucket_mut(&mut self, kind: RateLimitBucket) -> &mut BucketState {
        match kind {
            RateLimitBucket::Text => &mut self.text,
            RateLimitBucket::Routing => &mut self.routing,
            RateLimitBucket::Other => &mut self.other,
            RateLimitBucket::Unknown => &mut self.unknown,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct RelayEntry {
    node_id: u32,
    relay: BucketState,
}

/// Inputs for one inbound rate-limit decision.
pub struct RateLimitPacket {
    pub from: u32,
    pub to: u32,
    pub decoded_portnum: Option<u32>,
    pub now_ms: u32,
    /// Would this frame be a rebroadcast candidate on this node (role + hop budget)?
    pub rebroadcast_candidate: bool,
    /// Resolved last-hop NodeID when known and non-placeholder; `None` → shared unresolved bucket.
    pub resolved_relay: Option<u32>,
    pub airtime_ms: u32,
    pub channel_util_pct: f32,
}

/// Graph proximity for eviction (never frame `hop_start` / `hop_limit`).
#[derive(Clone, Copy, Debug, Default)]
pub struct GraphProximity {
    pub in_graph: bool,
    /// 0 = unknown / not in graph; 255 = in graph but no usable route length.
    pub hops: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitKind {
    Text = 0,
    Routing = 1,
    Other = 2,
    Unknown = 3,
    Relay = 4,
    RelayUnresolved = 5,
}

impl RateLimitKind {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitEvent {
    Trip { node_id: u32, kind: RateLimitKind },
    Clear { node_id: u32, kind: RateLimitKind },
}

/// Fixed-size per-node abuse filter on the RX path.
pub struct NodeRateLimiter {
    node_num: u32,
    enabled: bool,
    window_ms: u32,
    originators: [OriginatorEntry; MAX_ORIGINATORS],
    originator_count: u8,
    relays: [RelayEntry; MAX_RELAYS],
    relay_count: u8,
    unresolved_relay: BucketState,
    last_event: Option<RateLimitEvent>,
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

    /// Our own node id: packets from it are never limited.
    pub fn set_node_num(&mut self, node_num: u32) {
        self.node_num = node_num;
    }

    pub const fn with_node_num(node_num: u32) -> Self {
        Self {
            node_num,
            enabled: true,
            window_ms: WINDOW_MS,
            originators: [OriginatorEntry {
                node_id: 0,
                text: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                },
                routing: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                },
                other: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                },
                unknown: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                },
            }; MAX_ORIGINATORS],
            originator_count: 0,
            relays: [RelayEntry {
                node_id: 0,
                relay: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                },
            }; MAX_RELAYS],
            relay_count: 0,
            unresolved_relay: BucketState {
                window_start_ms: 0,
                count: 0,
                limited: false,
            },
            last_event: None,
        }
    }

    /// Runtime kill-switch (AC17). Default enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn take_event(&mut self) -> Option<RateLimitEvent> {
        self.last_event.take()
    }

    /// Returns `true` when the packet should be dropped for rate abuse.
    ///
    /// Packets addressed to us are never limited. `ADMIN_APP` is not exempt by portnum.
    pub fn should_drop<F>(&mut self, pkt: &RateLimitPacket, mut proximity: F) -> bool
    where
        F: FnMut(u32) -> GraphProximity,
    {
        self.last_event = None;
        if !self.enabled {
            return false;
        }
        if pkt.from == 0 || pkt.from == self.node_num {
            return false;
        }
        if pkt.to == self.node_num {
            return false;
        }

        let mut drop = false;

        let bucket_kind = rate_limit_bucket(pkt.decoded_portnum);
        let (trip, kind) = match bucket_kind {
            RateLimitBucket::Text => (THRESHOLD_TEXT, RateLimitKind::Text),
            RateLimitBucket::Routing => (THRESHOLD_ROUTING, RateLimitKind::Routing),
            RateLimitBucket::Other => (THRESHOLD_OTHER, RateLimitKind::Other),
            RateLimitBucket::Unknown => (THRESHOLD_UNKNOWN, RateLimitKind::Unknown),
        };

        {
            let node_id = pkt.from;
            let idx = self.get_or_create_originator(pkt.from, pkt.now_ms, &mut proximity);
            let entry = &mut self.originators[idx];
            let bucket = entry.bucket_mut(bucket_kind);
            let (limited, ev) = Self::check_and_update_bucket(
                bucket,
                trip,
                ORIGINATOR_CLEAR,
                1,
                pkt.now_ms,
                self.window_ms,
                node_id,
                kind,
            );
            if let Some(ev) = ev {
                self.last_event = Some(ev);
            }
            if limited {
                drop = true;
            }
        }

        if pkt.rebroadcast_candidate && !drop {
            let air_ms = if pkt.airtime_ms == 0 {
                RELAY_REF_AIRTIME_MS
            } else {
                pkt.airtime_ms
            };
            let (trip_ms, clear_ms) = Self::relay_budgets(air_ms, pkt.channel_util_pct);

            if self.unresolved_relay.window_start_ms == 0 {
                self.unresolved_relay.window_start_ms = pkt.now_ms;
            }

            if let Some(resolved) = pkt.resolved_relay.filter(|&id| id != 0 && id != self.node_num)
            {
                let idx = self.get_or_create_relay(resolved, pkt.now_ms, &mut proximity);
                let node_id = self.relays[idx].node_id;
                let bucket = &mut self.relays[idx].relay;
                let (limited, ev) = Self::check_and_update_bucket(
                    bucket,
                    trip_ms,
                    clear_ms,
                    air_ms,
                    pkt.now_ms,
                    self.window_ms,
                    node_id,
                    RateLimitKind::Relay,
                );
                if let Some(ev) = ev {
                    self.last_event = Some(ev);
                }
                if limited {
                    drop = true;
                }
            } else {
                let (limited, ev) = Self::check_and_update_bucket(
                    &mut self.unresolved_relay,
                    trip_ms,
                    clear_ms,
                    air_ms,
                    pkt.now_ms,
                    self.window_ms,
                    0,
                    RateLimitKind::RelayUnresolved,
                );
                if let Some(ev) = ev {
                    self.last_event = Some(ev);
                }
                if limited {
                    drop = true;
                }
            }
        }

        drop
    }

    fn relay_budgets(air_ms: u32, channel_util_pct: f32) -> (u32, u32) {
        let air = if air_ms == 0 {
            RELAY_REF_AIRTIME_MS
        } else {
            air_ms
        };
        // B_preset: ~60 packet-equivalents at this frame's airtime (modem/preset sensitive).
        let base_trip = RELAY_TRIP_PACKETS.saturating_mul(air);
        let mut scale = 1.0f32;
        if channel_util_pct > 25.0 {
            let t = ((channel_util_pct - 25.0) / 25.0).min(1.0);
            scale = 1.0 - 0.5 * t;
        }
        let mut trip_ms = (base_trip as f32 * scale) as u32;
        trip_ms = trip_ms.clamp(RELAY_TRIP_FLOOR_MS, RELAY_TRIP_CEIL_MS);
        let mut clear_ms = (trip_ms * RELAY_CLEAR_PACKETS) / RELAY_TRIP_PACKETS;
        clear_ms = clear_ms.clamp(RELAY_CLEAR_FLOOR_MS, RELAY_CLEAR_CEIL_MS);
        (trip_ms, clear_ms)
    }

    /// clear==0: sticky quiet window (originator). clear>0: fixed-window hysteresis (RELAY).
    fn check_and_update_bucket(
        b: &mut BucketState,
        trip: u32,
        clear: u32,
        charge: u32,
        now_ms: u32,
        window_ms: u32,
        node_id: u32,
        kind: RateLimitKind,
    ) -> (bool, Option<RateLimitEvent>) {
        let mut event = None;
        if b.limited && clear == 0 {
            if now_ms.wrapping_sub(b.window_start_ms) >= window_ms {
                b.limited = false;
                b.count = 0;
                b.window_start_ms = now_ms;
                event = Some(RateLimitEvent::Clear { node_id, kind });
            } else {
                b.window_start_ms = now_ms;
                return (true, event);
            }
        }

        if now_ms.wrapping_sub(b.window_start_ms) >= window_ms {
            if b.limited && clear > 0 && b.count < clear {
                b.limited = false;
                event = Some(RateLimitEvent::Clear { node_id, kind });
            }
            b.count = 0;
            b.window_start_ms = now_ms;
        }

        b.count = b.count.saturating_add(charge);

        if !b.limited && b.count >= trip {
            b.limited = true;
            b.window_start_ms = now_ms;
            return (true, Some(RateLimitEvent::Trip { node_id, kind }));
        }

        (b.limited, event)
    }

    fn find_originator(&self, node_id: u32) -> Option<usize> {
        self.originators[..self.originator_count as usize]
            .iter()
            .position(|e| e.node_id == node_id)
    }

    fn find_originator_eviction_candidate<F>(&self, proximity: &mut F) -> usize
    where
        F: FnMut(u32) -> GraphProximity,
    {
        let count = self.originator_count as usize;
        let mut candidate: Option<usize> = None;
        for i in 0..count {
            let e = &self.originators[i];
            if e.any_limited() {
                continue;
            }
            let prox = proximity(e.node_id);
            candidate = Some(match candidate {
                None => i,
                Some(c) => {
                    let cand = proximity(self.originators[c].node_id);
                    if !prox.in_graph && cand.in_graph {
                        i
                    } else if prox.in_graph == cand.in_graph {
                        // Farthest first, oldest window breaking a tie.
                        let farther = prox.hops > cand.hops;
                        let same_distance_but_staler = prox.hops == cand.hops
                            && e.oldest_window_start() < self.originators[c].oldest_window_start();
                        if farther || same_distance_but_staler {
                            i
                        } else {
                            c
                        }
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
        for i in 1..count {
            if self.originators[i].oldest_window_start()
                < self.originators[oldest].oldest_window_start()
            {
                oldest = i;
            }
        }
        oldest
    }

    fn get_or_create_originator<F>(
        &mut self,
        node_id: u32,
        now_ms: u32,
        proximity: &mut F,
    ) -> usize
    where
        F: FnMut(u32) -> GraphProximity,
    {
        if let Some(idx) = self.find_originator(node_id) {
            return idx;
        }
        let idx = if (self.originator_count as usize) < MAX_ORIGINATORS {
            let i = self.originator_count as usize;
            self.originator_count += 1;
            i
        } else {
            self.find_originator_eviction_candidate(proximity)
        };
        let fresh = BucketState {
            window_start_ms: now_ms,
            count: 0,
            limited: false,
        };
        self.originators[idx] = OriginatorEntry {
            node_id,
            text: fresh,
            routing: fresh,
            other: fresh,
            unknown: fresh,
        };
        idx
    }

    fn find_relay(&self, node_id: u32) -> Option<usize> {
        self.relays[..self.relay_count as usize]
            .iter()
            .position(|e| e.node_id == node_id)
    }

    fn find_relay_eviction_candidate<F>(&self, proximity: &mut F) -> usize
    where
        F: FnMut(u32) -> GraphProximity,
    {
        let count = self.relay_count as usize;
        let mut candidate: Option<usize> = None;
        for i in 0..count {
            let e = &self.relays[i];
            if e.relay.limited {
                continue;
            }
            let prox = proximity(e.node_id);
            candidate = Some(match candidate {
                None => i,
                Some(c) => {
                    let cand = proximity(self.relays[c].node_id);
                    if !prox.in_graph && cand.in_graph {
                        i
                    } else if prox.in_graph == cand.in_graph {
                        // Farthest first, oldest window breaking a tie.
                        let farther = prox.hops > cand.hops;
                        let same_distance_but_staler = prox.hops == cand.hops
                            && e.relay.window_start_ms < self.relays[c].relay.window_start_ms;
                        if farther || same_distance_but_staler {
                            i
                        } else {
                            c
                        }
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
        for i in 1..count {
            if self.relays[i].relay.window_start_ms < self.relays[oldest].relay.window_start_ms {
                oldest = i;
            }
        }
        oldest
    }

    fn get_or_create_relay<F>(&mut self, node_id: u32, now_ms: u32, proximity: &mut F) -> usize
    where
        F: FnMut(u32) -> GraphProximity,
    {
        if let Some(idx) = self.find_relay(node_id) {
            return idx;
        }
        let idx = if (self.relay_count as usize) < MAX_RELAYS {
            let i = self.relay_count as usize;
            self.relay_count += 1;
            i
        } else {
            self.find_relay_eviction_candidate(proximity)
        };
        self.relays[idx] = RelayEntry {
            node_id,
            relay: BucketState {
                window_start_ms: now_ms,
                count: 0,
                limited: false,
            },
        };
        idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_protocol::num;

    fn no_graph(_id: u32) -> GraphProximity {
        GraphProximity::default()
    }

    fn originator_pkt(from: u32, port: Option<u32>, now_ms: u32) -> RateLimitPacket {
        RateLimitPacket {
            from,
            to: 0xFFFF_FFFF,
            decoded_portnum: port,
            now_ms,
            rebroadcast_candidate: false,
            resolved_relay: None,
            airtime_ms: RELAY_REF_AIRTIME_MS,
            channel_util_pct: 0.0,
        }
    }

    fn drop_other(limiter: &mut NodeRateLimiter, from: u32, now_ms: u32) -> bool {
        limiter.should_drop(
            &originator_pkt(from, Some(num::POSITION_APP), now_ms),
            no_graph,
        )
    }

    fn drop_undecodable(limiter: &mut NodeRateLimiter, from: u32, now_ms: u32) -> bool {
        limiter.should_drop(&originator_pkt(from, None, now_ms), no_graph)
    }

    fn drop_routing(limiter: &mut NodeRateLimiter, from: u32, now_ms: u32) -> bool {
        limiter.should_drop(
            &originator_pkt(from, Some(num::ROUTING_APP), now_ms),
            no_graph,
        )
    }

    fn drop_text(limiter: &mut NodeRateLimiter, from: u32, now_ms: u32) -> bool {
        limiter.should_drop(
            &originator_pkt(from, Some(num::TEXT_MESSAGE_APP), now_ms),
            no_graph,
        )
    }

    fn drop_admin(limiter: &mut NodeRateLimiter, from: u32, now_ms: u32) -> bool {
        limiter.should_drop(
            &originator_pkt(from, Some(num::ADMIN_APP), now_ms),
            no_graph,
        )
    }

    #[test]
    fn undecodable_packets_have_their_own_bucket() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0xE0E0_0001;
        for i in 0..THRESHOLD_UNKNOWN - 1 {
            assert!(
                !drop_undecodable(&mut limiter, from, i * 100),
                "undecodable packet {i} must not trip the OTHER threshold"
            );
        }
        assert!(
            drop_undecodable(&mut limiter, from, 5_000),
            "12th undecodable packet drops"
        );
        assert!(!drop_other(&mut limiter, from, 5_100));
        assert!(!drop_text(&mut limiter, from, 5_200));
        assert!(!drop_routing(&mut limiter, from, 5_300));
    }

    #[test]
    fn admin_app_counts_as_other_when_not_to_us() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0xADAD_0001;
        // ADMIN_APP is OTHER — trips at 4 when not addressed to us.
        for i in 0..3 {
            assert!(
                !drop_admin(&mut limiter, from, i * 100),
                "admin get {i} should pass"
            );
        }
        assert!(
            drop_admin(&mut limiter, from, 300),
            "4th ADMIN_APP (not to-us) must rate-limit"
        );
        // Independent OTHER counter already limited; TEXT still free.
        assert!(!drop_text(&mut limiter, from, 400));
    }

    #[test]
    fn to_us_never_limited() {
        let mut limiter = NodeRateLimiter::with_node_num(0xAAAA_AAAA);
        let from = 0xBBBB_BBBB;
        for i in 0..20 {
            let pkt = RateLimitPacket {
                from,
                to: 0xAAAA_AAAA,
                decoded_portnum: Some(num::POSITION_APP),
                now_ms: i * 100,
                rebroadcast_candidate: true,
                resolved_relay: None,
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
            };
            assert!(!limiter.should_drop(&pkt, no_graph));
        }
    }

    impl NodeRateLimiter {
        fn is_tracking_originator(&self, from: u32) -> bool {
            self.find_originator(from).is_some()
        }

        fn active_originator_count(&self) -> usize {
            self.originator_count as usize
        }

        fn tracks_relay(&self, node_id: u32) -> bool {
            self.find_relay(node_id).is_some()
        }

        fn relay_limited(&self, node_id: u32) -> bool {
            self.find_relay(node_id)
                .map(|i| self.relays[i].relay.limited)
                .unwrap_or(false)
        }

        fn unresolved_relay_limited(&self) -> bool {
            self.unresolved_relay.limited
        }

        fn debug_relay_budgets(&self, air_ms: u32, chutil: f32) -> (u32, u32) {
            Self::relay_budgets(air_ms, chutil)
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
            assert!(
                t <= base_ms + 16,
                "failed to trip OTHER bucket limit for {from:#x}"
            );
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
    fn eviction_prefers_not_in_graph_then_farthest() {
        let mut limiter = NodeRateLimiter::new();
        let keep = 0x1000_000F;
        let mut proximity = |id: u32| {
            if id == keep {
                GraphProximity {
                    in_graph: true,
                    hops: 1,
                }
            } else {
                GraphProximity::default()
            }
        };
        for i in 0..16u32 {
            let from = 0x1000_0000 + i;
            assert!(!limiter.should_drop(
                &originator_pkt(from, Some(num::POSITION_APP), i),
                &mut proximity
            ));
        }
        assert!(!limiter.should_drop(
            &originator_pkt(0x2000_0000, Some(num::POSITION_APP), 200),
            &mut proximity
        ));
        assert!(limiter.is_tracking_originator(0x2000_0000));
        assert!(
            !limiter.is_tracking_originator(0x1000_0000),
            "not-in-graph (and farthest among them by hops=0 / oldest) evicted"
        );
        assert!(limiter.is_tracking_originator(keep));
    }

    #[test]
    fn eviction_never_drops_limited_entry_when_unlimited_exists() {
        let mut limiter = NodeRateLimiter::new();
        for i in 0..16u32 {
            fill_slot(&mut limiter, 0x1000 + i, i);
        }
        limit_other(&mut limiter, 0x1000, 1_000);
        // Bump hops on a non-limited far node via a fresh proximity that treats all equal;
        // farthest among unlimited with default hops=0 is oldest window (0x1001 after fill).
        assert!(!drop_other(&mut limiter, 0x100F, 2_000));
        assert!(!drop_other(&mut limiter, 0x2000, 3_000));

        assert!(limiter.is_tracking_originator(0x1000), "limited entry kept");
        assert!(limiter.is_tracking_originator(0x2000));
        assert_eq!(limiter.active_originator_count(), 16);
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

        assert!(
            !limiter.is_tracking_originator(0x1000),
            "oldest limited window evicted"
        );
        assert!(limiter.is_tracking_originator(0x2000));
        assert!(limiter.is_tracking_originator(0x100F));
    }

    #[test]
    fn from_zero_is_never_rate_limited() {
        let mut limiter = NodeRateLimiter::with_node_num(0xBEEF_BEEF);
        for i in 0..10 {
            assert!(
                !limiter.should_drop(&originator_pkt(0, None, i * 1000), no_graph),
                "from=0 must never drop"
            );
        }
        assert_eq!(limiter.active_originator_count(), 0);
    }

    #[test]
    fn own_node_is_never_rate_limited() {
        let own = 0xCAFE_BABE;
        let mut limiter = NodeRateLimiter::with_node_num(own);
        for i in 0..10 {
            assert!(
                !limiter.should_drop(&originator_pkt(own, None, i * 1000), no_graph),
                "own node must never drop"
            );
            assert!(
                !drop_text(&mut limiter, own, i * 100),
                "own node text must never drop"
            );
        }
        assert_eq!(limiter.active_originator_count(), 0);
    }

    #[test]
    fn shared_unresolved_relay_trips_independently() {
        let mut limiter = NodeRateLimiter::new();
        // Distinct originators so only the shared RELAY bucket accumulates.
        for i in 0..59u32 {
            let pkt = RateLimitPacket {
                from: 0x2200_0000 + i,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: i,
                rebroadcast_candidate: true,
                resolved_relay: None,
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
            };
            assert!(!limiter.should_drop(&pkt, no_graph), "relay charge {i}");
        }
        let trip = RateLimitPacket {
            from: 0x2200_003B,
            to: 0xFFFF_FFFF,
            decoded_portnum: Some(num::TEXT_MESSAGE_APP),
            now_ms: 59,
            rebroadcast_candidate: true,
            resolved_relay: None,
            airtime_ms: RELAY_REF_AIRTIME_MS,
            channel_util_pct: 0.0,
        };
        assert!(limiter.should_drop(&trip, no_graph));
        assert!(limiter.unresolved_relay_limited());
    }

    #[test]
    fn resolved_relay_independent_of_shared() {
        let mut limiter = NodeRateLimiter::new();
        let resolved = 0x0A00_0011;
        for i in 0..59u32 {
            let pkt = RateLimitPacket {
                from: 0x2200_0000 + i,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: i,
                rebroadcast_candidate: true,
                resolved_relay: Some(resolved),
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
            };
            assert!(!limiter.should_drop(&pkt, no_graph));
        }
        let trip = RateLimitPacket {
            from: 0x2200_003B,
            to: 0xFFFF_FFFF,
            decoded_portnum: Some(num::TEXT_MESSAGE_APP),
            now_ms: 59,
            rebroadcast_candidate: true,
            resolved_relay: Some(resolved),
            airtime_ms: RELAY_REF_AIRTIME_MS,
            channel_util_pct: 0.0,
        };
        assert!(limiter.should_drop(&trip, no_graph));
        assert!(limiter.tracks_relay(resolved));
        assert!(limiter.relay_limited(resolved));
        assert!(!limiter.unresolved_relay_limited());

        let other = RateLimitPacket {
            from: 0x2200_003C,
            to: 0xFFFF_FFFF,
            decoded_portnum: Some(num::TEXT_MESSAGE_APP),
            now_ms: 60,
            rebroadcast_candidate: true,
            resolved_relay: None,
            airtime_ms: RELAY_REF_AIRTIME_MS,
            channel_util_pct: 0.0,
        };
        assert!(!limiter.should_drop(&other, no_graph));
    }

    #[test]
    fn direct_first_hop_keys_relay_on_originator() {
        // Mirrors router: direct frames pass resolved_relay=Some(from).
        let mut limiter = NodeRateLimiter::new();
        let neighbor = 0x0A0A_0A0A;
        for i in 0..3u32 {
            let pkt = RateLimitPacket {
                from: neighbor,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::POSITION_APP),
                now_ms: i,
                rebroadcast_candidate: true,
                resolved_relay: Some(neighbor),
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
            };
            assert!(!limiter.should_drop(&pkt, no_graph), "packet {i}");
        }
        assert!(
            limiter.tracks_relay(neighbor),
            "direct last hop must use originator RELAY slot"
        );
        assert_eq!(limiter.unresolved_relay.count, 0);
    }

    #[test]
    fn airutil_tightens_relay_trip() {
        let limiter = NodeRateLimiter::new();
        let (trip_low, clear_low) = limiter.debug_relay_budgets(100, 0.0);
        let (trip_high, clear_high) = limiter.debug_relay_budgets(100, 50.0);
        assert_eq!(trip_low, 6000);
        assert_eq!(trip_high, 3000);
        assert!(trip_high < trip_low);
        assert!(clear_high < clear_low);
        let (trip_max, _) = limiter.debug_relay_budgets(100, 100.0);
        assert_eq!(trip_max, 3000);
        assert!(trip_max >= RELAY_TRIP_FLOOR_MS);
        // Longer airtime raises B_preset (clamped to ceiling).
        let (trip_long, _) = limiter.debug_relay_budgets(200, 0.0);
        assert_eq!(trip_long, RELAY_TRIP_CEIL_MS);
        let (trip_short, _) = limiter.debug_relay_budgets(50, 0.0);
        assert_eq!(trip_short, 3000); // 60*50
    }

    #[test]
    fn relay_recovers_when_count_below_clear() {
        let mut limiter = NodeRateLimiter::new();
        let resolved = 0x0A00_00AA;
        for i in 0..60u32 {
            let pkt = RateLimitPacket {
                from: 0x3300_0000 + i,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: i,
                rebroadcast_candidate: true,
                resolved_relay: Some(resolved),
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
            };
            let _ = limiter.should_drop(&pkt, no_graph);
        }
        assert!(limiter.relay_limited(resolved));
        // Quiet window with no charges: at roll, count was reset on trip so count=charge of trip
        // packet only if we don't roll... After trip, window_start=now. Advance past window with
        // a single light charge below clear (15*100=1500). First packet after window rolls and
        // lifts if previous count < clear.
        // After trip, count >= trip and limited; window restarted. Roll once with count still high
        // keeps limited and zeroes count; then a few charges under clear then another roll lifts.
        let after_trip = 60;
        // Roll window while still "busy" enough to stay limited: charge above clear in the window.
        for i in 0..20u32 {
            let pkt = RateLimitPacket {
                from: 0x3400_0000 + i,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: after_trip + i,
                rebroadcast_candidate: true,
                resolved_relay: Some(resolved),
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
            };
            assert!(limiter.should_drop(&pkt, no_graph));
        }
        // Now roll with low activity: one packet after full window from last activity.
        let quiet_roll = after_trip + 20 + WINDOW_MS;
        // First, force a window boundary with zero-ish prior count: wait without traffic from
        // last packet time, then send under-clear traffic across one full window.
        // Last activity at after_trip+19. At quiet_roll, window rolls; count from previous
        // window was 20*100=2000 >= clear 1500 so stays limited and count resets to 0 then +100.
        assert!(limiter.should_drop(
            &RateLimitPacket {
                from: 0x3500_0001,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: quiet_roll,
                rebroadcast_candidate: true,
                resolved_relay: Some(resolved),
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
            },
            no_graph
        ));
        assert!(limiter.relay_limited(resolved));
        // Next window: only 5 packet-eq (500 < 1500 clear) then roll → lift.
        for i in 0..5u32 {
            let _ = limiter.should_drop(
                &RateLimitPacket {
                    from: 0x3600_0000 + i,
                    to: 0xFFFF_FFFF,
                    decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                    now_ms: quiet_roll + 1 + i,
                    rebroadcast_candidate: true,
                    resolved_relay: Some(resolved),
                    airtime_ms: RELAY_REF_AIRTIME_MS,
                    channel_util_pct: 0.0,
                },
                no_graph,
            );
        }
        let lift_at = quiet_roll + 1 + WINDOW_MS;
        assert!(
            !limiter.should_drop(
                &RateLimitPacket {
                    from: 0x3700_0001,
                    to: 0xFFFF_FFFF,
                    decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                    now_ms: lift_at,
                    rebroadcast_candidate: true,
                    resolved_relay: Some(resolved),
                    airtime_ms: RELAY_REF_AIRTIME_MS,
                    channel_util_pct: 0.0,
                },
                no_graph
            ),
            "RELAY should lift when prior window count < clear"
        );
        assert!(!limiter.relay_limited(resolved));
    }

    #[test]
    fn enabled_kill_switch_disables_drops() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0xABCD_0001;
        for i in 0..4u32 {
            let _ = drop_other(&mut limiter, from, i);
        }
        assert!(drop_other(&mut limiter, from, 10));
        limiter.set_enabled(false);
        assert!(!drop_other(&mut limiter, from, 11));
        limiter.set_enabled(true);
        assert!(drop_other(&mut limiter, from, 12));
    }

    #[test]
    fn relay_eviction_keeps_in_graph_relay() {
        let mut limiter = NodeRateLimiter::new();
        let keep = 0x0A00_0008;
        let mut proximity = |id: u32| {
            if id == keep {
                GraphProximity {
                    in_graph: true,
                    hops: 1,
                }
            } else {
                GraphProximity::default()
            }
        };
        for b in 1u32..=8 {
            let relay = 0x0A00_0000 + b;
            assert!(!limiter.should_drop(
                &RateLimitPacket {
                    from: 0x2200_0000 + b,
                    to: 0xFFFF_FFFF,
                    decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                    now_ms: b,
                    rebroadcast_candidate: true,
                    resolved_relay: Some(relay),
                    airtime_ms: RELAY_REF_AIRTIME_MS,
                    channel_util_pct: 0.0,
                },
                &mut proximity
            ));
        }
        assert!(limiter.tracks_relay(keep));
        assert!(!limiter.should_drop(
            &RateLimitPacket {
                from: 0x2200_0099,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: 100,
                rebroadcast_candidate: true,
                resolved_relay: Some(0x0A00_0080),
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
            },
            &mut proximity
        ));
        assert!(limiter.tracks_relay(keep));
        assert!(limiter.tracks_relay(0x0A00_0080));
    }

    #[test]
    fn originator_limited_does_not_charge_relay() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0x3333_3333;
        for i in 0..4u32 {
            let pkt = RateLimitPacket {
                from,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::POSITION_APP),
                now_ms: i,
                rebroadcast_candidate: true,
                resolved_relay: None,
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
            };
            let _ = limiter.should_drop(&pkt, no_graph);
        }
        assert!(limiter.unresolved_relay.count < RELAY_TRIP_PACKETS * RELAY_REF_AIRTIME_MS);
        // After originator OTHER trips, further candidates must not charge RELAY.
        let before = limiter.unresolved_relay.count;
        let pkt = RateLimitPacket {
            from,
            to: 0xFFFF_FFFF,
            decoded_portnum: Some(num::POSITION_APP),
            now_ms: 10,
            rebroadcast_candidate: true,
            resolved_relay: None,
            airtime_ms: RELAY_REF_AIRTIME_MS,
            channel_util_pct: 0.0,
        };
        assert!(limiter.should_drop(&pkt, no_graph));
        assert_eq!(limiter.unresolved_relay.count, before);
    }
}
