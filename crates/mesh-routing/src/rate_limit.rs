//! Per-node inbound rate limiting (SignalRouting).
//!
//! Originator path: up to 16 sources, each with TEXT / ROUTING / OTHER / UNKNOWN packet-count
//! buckets. RELAY path: rebroadcast candidates charge the last hop — 8 resolved NodeID slots
//! plus one shared bucket for unresolved `relay_node` bytes — using an airtime budget tightened
//! by local channel utilization. Young path: one shared packet-count bucket for originators first
//! heard less than 30 minutes ago, so a flood of minted identities buys one slot, not one each.
//!
//! Uniform hysteresis: trip / clear / fixed window; while limited, drop matching traffic. Every
//! bucket clears the same way: at the window roll, when the count for that window is below the
//! clear threshold. Originator clear is half its trip, RELAY and YOUNG a quarter of theirs.
//!
//! Dest drop: while any originator bucket for a node is limited, unicast frames addressed to
//! that node on the default public channel are logged and dropped without charging the sender.
//! WantResponse replies from other nodes would otherwise keep flooding after the originator
//! itself is already silenced. Unicast on a non-default channel is not dest-dropped.

use mesh_protocol::{rate_limit_bucket, RateLimitBucket, NODENUM_BROADCAST};

const MAX_ORIGINATORS: usize = 16;
const MAX_RELAYS: usize = 8;
const MAX_YOUNG: usize = 32;
const WINDOW_MS: u32 = 90_000;
/// First-sighting records live only while the originator is younger than this.
const YOUNG_AGE_MS: u32 = 30 * 60 * 1000;
/// Do not enforce the young bucket until we ourselves have been up this long.
const WARMUP_MS: u32 = 30 * 60 * 1000;
/// Trip well above the measured 24-packet / 90 s legitimate peak (and the 12-identity
/// burst in the same window) and far below flood volume. 48 is 2× that peak; 12 is the
/// RELAY-style quarter-of-trip clear, so a burst of new nodes can recover without a
/// fully silent window. Thirty minutes is a commitment, not a tuning knob.
const YOUNG_TRIP: u32 = 48;
const YOUNG_CLEAR: u32 = 12;
const ANNOUNCE_REFRACTORY_MS: u32 = 30 * 60 * 1000;
const ANNOUNCE_CHUTIL_HIGH: f32 = 25.0;
const ANNOUNCE_MAX_IDS: usize = 4;

const THRESHOLD_TEXT: u32 = 30;
const THRESHOLD_ROUTING: u32 = 10;
const THRESHOLD_OTHER: u32 = 4;
/// Undecodable traffic. Sized so a relayed remote-admin Channels screen (channel 0, LoRa
/// config, then channels 1..7 one at a time: nine requests, nine replies) loads in one window.
const THRESHOLD_UNKNOWN: u32 = 12;
/// Half the trip that limited the originator, floored at 1.
///
/// A clear of 0 means "sticky until a fully silent window", and every packet arriving while
/// limited restarts that window, so an originator that keeps talking never recovers: brushing a
/// threshold once costs it the bucket permanently. Half, not the quarter RELAY uses, because these
/// thresholds are small — a quarter of OTHER's 4 is 1, which demands a completely silent window
/// and reinstates the behaviour being fixed.
const ORIGINATOR_CLEAR_RATIO_NUM: u32 = 1;
const ORIGINATOR_CLEAR_RATIO_DEN: u32 = 2;

const fn originator_clear(trip: u32) -> u32 {
    let clear = (trip * ORIGINATOR_CLEAR_RATIO_NUM) / ORIGINATOR_CLEAR_RATIO_DEN;
    if clear < 1 {
        1
    } else {
        clear
    }
}

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

#[derive(Clone, Copy, Default)]
struct YoungSighting {
    node_id: u32,
    first_seen_ms: u32,
}

/// Snapshot the coverage path consults: a node whose traffic the young bucket is
/// currently dropping is not a coverage target. Ownership of a stock neighbour
/// that nobody will relay for is a wasted slot.
#[derive(Clone, Copy, Debug)]
pub struct YoungCoverageGate {
    pub active: bool,
    pub table_full: bool,
    pub ids: [u32; MAX_YOUNG],
    pub id_count: u8,
}

impl YoungCoverageGate {
    pub const fn empty() -> Self {
        Self {
            active: false,
            table_full: false,
            ids: [0; MAX_YOUNG],
            id_count: 0,
        }
    }

    pub fn blocks(&self, node_id: u32) -> bool {
        if !self.active || node_id == 0 {
            return false;
        }
        if self.table_full {
            return true;
        }
        self.ids[..self.id_count as usize].contains(&node_id)
    }
}

impl Default for YoungCoverageGate {
    fn default() -> Self {
        Self::empty()
    }
}

/// Up to four young originator IDs, fixed-width, for the diagnostic announcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct YoungAnnounce {
    pub ids: [u32; ANNOUNCE_MAX_IDS],
    pub count: u8,
}

/// Fixed-width young IDs. The bytes are attacker-chosen and do not belong in free text.
pub fn format_young_announce(ann: &YoungAnnounce, out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut pos = 0usize;
    let push = |out: &mut [u8], pos: &mut usize, b: u8| {
        if *pos < out.len() {
            out[*pos] = b;
            *pos += 1;
        }
    };
    push(out, &mut pos, b'Y');
    for i in 0..ann.count as usize {
        push(out, &mut pos, b' ');
        push(out, &mut pos, b'!');
        let id = ann.ids[i];
        for n in 0..8 {
            let nib = ((id >> (28 - 4 * n)) & 0xF) as usize;
            push(out, &mut pos, HEX[nib]);
        }
    }
    pos
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
    /// Do we hold a graph yet (at least one direct neighbour)? Gates the shared unresolved
    /// RELAY slot only; see `charges_unresolved_relay`.
    pub graph_established: bool,
    /// Frame is on this node's default (public) channel. Dest-drop of unicast to a limited
    /// originator applies only here; private-channel DMs are left alone.
    pub on_default_channel: bool,
}

/// Should this frame charge the one shared bucket for unresolved `relay_node` bytes?
///
/// Not until we hold a graph. Just after boot every relay byte is unresolved, so the single
/// shared slot trips on ordinary traffic and suppresses exactly the relays a node needs in order
/// to learn who its neighbours are — the limiter would deny itself the evidence that lifts it.
/// One known direct neighbour is enough; resolved last hops are charged either way.
fn charges_unresolved_relay(graph_established: bool) -> bool {
    graph_established
}

fn is_unicast_dest(to: u32) -> bool {
    to != 0 && to != NODENUM_BROADCAST
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
    Young = 6,
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
    /// Default-channel unicast addressed to an originator that is already limited.
    DestDrop { node_id: u32 },
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
    young: [YoungSighting; MAX_YOUNG],
    young_count: u8,
    alumni: [u32; MAX_YOUNG],
    alumni_count: u8,
    young_bucket: BucketState,
    boot_ms: u32,
    boot_known: bool,
    announce_broadcast: bool,
    last_announce_ms: u32,
    announce_ever: bool,
    pending_announce: Option<YoungAnnounce>,
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
            young: [YoungSighting {
                node_id: 0,
                first_seen_ms: 0,
            }; MAX_YOUNG],
            young_count: 0,
            alumni: [0; MAX_YOUNG],
            alumni_count: 0,
            young_bucket: BucketState {
                window_start_ms: 0,
                count: 0,
                limited: false,
            },
            boot_ms: 0,
            boot_known: false,
            announce_broadcast: false,
            last_announce_ms: 0,
            announce_ever: false,
            pending_announce: None,
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

    pub fn take_announce(&mut self) -> Option<YoungAnnounce> {
        self.pending_announce.take()
    }

    /// Broadcast of the young-bucket diagnostic is opt-in. Local log and the host
    /// interface fire regardless.
    pub fn set_announce_broadcast(&mut self, enabled: bool) {
        self.announce_broadcast = enabled;
    }

    pub fn announce_broadcast(&self) -> bool {
        self.announce_broadcast
    }

    /// Test/boot hook: treat `boot_ms` as the moment we came up.
    pub fn set_boot_ms(&mut self, boot_ms: u32) {
        self.boot_ms = boot_ms;
        self.boot_known = true;
    }

    pub fn warmed_up(&self, now_ms: u32) -> bool {
        self.boot_known && now_ms.wrapping_sub(self.boot_ms) >= WARMUP_MS
    }

    pub fn young_limited(&self) -> bool {
        self.young_bucket.limited
    }

    pub fn young_table_full(&self) -> bool {
        self.young_count as usize >= MAX_YOUNG
    }

    /// Coverage asks this, not `should_drop`: a node whose traffic is being dropped
    /// is not a coverage target.
    pub fn coverage_gate(&self, now_ms: u32) -> YoungCoverageGate {
        let mut ids = [0u32; MAX_YOUNG];
        let n = self.young_count as usize;
        for (i, slot) in ids.iter_mut().enumerate().take(n) {
            *slot = self.young[i].node_id;
        }
        YoungCoverageGate {
            active: self.warmed_up(now_ms) && self.young_bucket.limited,
            table_full: self.young_table_full(),
            ids,
            id_count: self.young_count,
        }
    }

    /// True when any originator bucket for `node_id` is currently limited.
    pub fn originator_limited(&self, node_id: u32) -> bool {
        self.find_originator(node_id)
            .map(|i| self.originators[i].any_limited())
            .unwrap_or(false)
    }

    /// Returns `true` when the packet should be dropped for rate abuse.
    ///
    /// Packets addressed to us are never limited. `ADMIN_APP` is not exempt by portnum.
    /// Default-channel unicast *to* a limited originator is dropped without charging the
    /// sender, so WantResponse replies do not keep flooding after the originator is silenced.
    pub fn should_drop<F>(&mut self, pkt: &RateLimitPacket, mut proximity: F) -> bool
    where
        F: FnMut(u32) -> GraphProximity,
    {
        self.last_event = None;
        self.pending_announce = None;
        if !self.enabled {
            return false;
        }
        if pkt.from == 0 || pkt.from == self.node_num {
            return false;
        }
        if pkt.to == self.node_num {
            return false;
        }
        if self.should_drop_to_limited_dest(pkt) {
            self.last_event = Some(RateLimitEvent::DestDrop { node_id: pkt.to });
            return true;
        }

        self.note_boot(pkt.now_ms);

        let mut drop = false;

        let bucket_kind = rate_limit_bucket(pkt.decoded_portnum);
        let decoded = !matches!(bucket_kind, RateLimitBucket::Unknown);
        if decoded {
            self.note_originator(pkt.from, pkt.now_ms);
        }
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
                originator_clear(trip),
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

        if decoded && self.warmed_up(pkt.now_ms) && self.is_young(pkt.from, pkt.now_ms) {
            let (limited, ev) = Self::check_and_update_bucket(
                &mut self.young_bucket,
                YOUNG_TRIP,
                YOUNG_CLEAR,
                1,
                pkt.now_ms,
                self.window_ms,
                0,
                RateLimitKind::Young,
            );
            if let Some(ev) = ev {
                self.last_event = Some(ev);
                if matches!(ev, RateLimitEvent::Trip { .. }) {
                    self.maybe_announce(pkt.now_ms, pkt.channel_util_pct);
                }
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

            if let Some(resolved) = pkt
                .resolved_relay
                .filter(|&id| id != 0 && id != self.node_num)
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
            } else if charges_unresolved_relay(pkt.graph_established) {
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

    /// Unicast on the default channel to an originator we already limited. Does not create
    /// a slot and does not charge the sender: the flood being stopped is *replies to* the
    /// banned node, not traffic *from* the nodes answering it.
    fn should_drop_to_limited_dest(&self, pkt: &RateLimitPacket) -> bool {
        if !pkt.on_default_channel || !is_unicast_dest(pkt.to) {
            return false;
        }
        self.originator_limited(pkt.to)
    }

    fn note_boot(&mut self, now_ms: u32) {
        if !self.boot_known {
            self.boot_ms = now_ms;
            self.boot_known = true;
        }
    }

    fn find_young(&self, node_id: u32) -> Option<usize> {
        self.young[..self.young_count as usize]
            .iter()
            .position(|e| e.node_id == node_id)
    }

    fn in_alumni(&self, node_id: u32) -> bool {
        self.alumni[..self.alumni_count as usize].contains(&node_id)
    }

    fn add_alumni(&mut self, node_id: u32) {
        if self.in_alumni(node_id) {
            return;
        }
        if (self.alumni_count as usize) < MAX_YOUNG {
            self.alumni[self.alumni_count as usize] = node_id;
            self.alumni_count += 1;
            return;
        }
        self.alumni.copy_within(1..MAX_YOUNG, 0);
        self.alumni[MAX_YOUNG - 1] = node_id;
    }

    fn remove_young_at(&mut self, idx: usize) {
        let last = self.young_count as usize - 1;
        if idx < last {
            self.young[idx] = self.young[last];
        }
        self.young[last] = YoungSighting {
            node_id: 0,
            first_seen_ms: 0,
        };
        self.young_count -= 1;
    }

    fn expire_if_old(&mut self, node_id: u32, now_ms: u32) {
        let Some(idx) = self.find_young(node_id) else {
            return;
        };
        let age = now_ms.wrapping_sub(self.young[idx].first_seen_ms);
        if (YOUNG_AGE_MS..0x8000_0000).contains(&age) {
            self.add_alumni(node_id);
            self.remove_young_at(idx);
        }
    }

    fn note_originator(&mut self, node_id: u32, now_ms: u32) {
        self.expire_if_old(node_id, now_ms);
        if self.find_young(node_id).is_some() || self.in_alumni(node_id) {
            return;
        }
        if (self.young_count as usize) < MAX_YOUNG {
            let i = self.young_count as usize;
            self.young[i] = YoungSighting {
                node_id,
                first_seen_ms: now_ms,
            };
            self.young_count += 1;
        }
    }

    /// No record + room → established (fail open). No record + full → young (fail closed).
    fn is_young(&self, node_id: u32, now_ms: u32) -> bool {
        if let Some(idx) = self.find_young(node_id) {
            let age = now_ms.wrapping_sub(self.young[idx].first_seen_ms);
            return !(YOUNG_AGE_MS..0x8000_0000).contains(&age);
        }
        if self.in_alumni(node_id) {
            return false;
        }
        self.young_count as usize >= MAX_YOUNG
    }

    fn relay_any_limited(&self) -> bool {
        if self.unresolved_relay.limited {
            return true;
        }
        self.relays[..self.relay_count as usize]
            .iter()
            .any(|e| e.relay.limited)
    }

    fn maybe_announce(&mut self, now_ms: u32, channel_util_pct: f32) {
        if self.relay_any_limited() || channel_util_pct > ANNOUNCE_CHUTIL_HIGH {
            return;
        }
        if self.announce_ever {
            let elapsed = now_ms.wrapping_sub(self.last_announce_ms);
            if elapsed < ANNOUNCE_REFRACTORY_MS {
                return;
            }
        }
        let mut ann = YoungAnnounce {
            ids: [0; ANNOUNCE_MAX_IDS],
            count: 0,
        };
        let n = (self.young_count as usize).min(ANNOUNCE_MAX_IDS);
        for i in 0..n {
            ann.ids[i] = self.young[i].node_id;
            ann.count += 1;
        }
        self.last_announce_ms = now_ms;
        self.announce_ever = true;
        self.pending_announce = Some(ann);
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

    /// Fixed-window hysteresis: at the window roll, a limited bucket lifts when its count for
    /// that window fell below `clear`. `clear == 0` is the sticky quiet window, kept only for
    /// callers that ask for it; no production bucket does.
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

    fn get_or_create_originator<F>(&mut self, node_id: u32, now_ms: u32, proximity: &mut F) -> usize
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
            to: NODENUM_BROADCAST,
            decoded_portnum: port,
            now_ms,
            rebroadcast_candidate: false,
            resolved_relay: None,
            airtime_ms: RELAY_REF_AIRTIME_MS,
            channel_util_pct: 0.0,
            graph_established: true,
            on_default_channel: true,
        }
    }

    fn dest_pkt(from: u32, to: u32, on_default: bool, now_ms: u32) -> RateLimitPacket {
        RateLimitPacket {
            from,
            to,
            decoded_portnum: Some(num::NODEINFO_APP),
            now_ms,
            rebroadcast_candidate: true,
            resolved_relay: None,
            airtime_ms: RELAY_REF_AIRTIME_MS,
            channel_util_pct: 0.0,
            graph_established: true,
            on_default_channel: on_default,
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
                graph_established: true,
                on_default_channel: true,
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

        fn debug_tracks_young(&self, from: u32) -> bool {
            self.find_young(from).is_some()
        }

        fn debug_young_count(&self) -> usize {
            self.young_count as usize
        }

        fn debug_is_young(&self, from: u32, now_ms: u32) -> bool {
            self.is_young(from, now_ms)
        }

        fn debug_young_count_value(&self) -> u32 {
            self.young_bucket.count
        }

        fn debug_seed_young(&mut self, from: u32, first_seen_ms: u32) {
            self.note_originator(from, first_seen_ms);
        }
    }

    #[test]
    fn originator_clear_is_half_the_trip_and_never_zero() {
        // Half, not RELAY's quarter. OTHER's trip is 4: a quarter is 1, which would demand a
        // completely silent window and so reinstate the sticky behaviour this ratio replaces.
        assert_eq!(originator_clear(THRESHOLD_OTHER), 2);
        assert_eq!(THRESHOLD_OTHER / 4, 1);
        assert_eq!(originator_clear(THRESHOLD_TEXT), 15);
        assert_eq!(originator_clear(THRESHOLD_ROUTING), 5);
        assert_eq!(originator_clear(THRESHOLD_UNKNOWN), 6);
        // A trip of 1 must still clear at 1, not at 0: a clear of 0 is the sticky window.
        assert_eq!(originator_clear(1), 1);
        assert!(originator_clear(THRESHOLD_OTHER) > 0);
    }

    #[test]
    fn a_limited_originator_that_keeps_talking_still_recovers() {
        // The defect this pins: with clear == 0 the bucket was sticky until a fully silent
        // window, and every packet arriving while limited restarted that window — so a node
        // that kept talking at any rate at all could never come back. One packet per window is
        // far below OTHER's trip of 4 and must clear.
        let mut limiter = NodeRateLimiter::new();
        let from = 0x1122_3344;
        limit_other(&mut limiter, from, 0);
        assert!(limiter.originator_limited(from));

        let mut now = WINDOW_MS;
        let mut cleared_after = None;
        for window in 1..=4u32 {
            let dropped = drop_other(&mut limiter, from, now);
            if !dropped {
                cleared_after = Some(window);
                break;
            }
            now += WINDOW_MS;
        }
        assert!(
            cleared_after.is_some(),
            "a talking originator never recovered: still limited after four quiet windows"
        );
        assert!(!limiter.originator_limited(from));
    }

    #[test]
    fn an_originator_still_over_the_clear_stays_limited() {
        // The other half of the hysteresis: recovery is earned by dropping below the clear
        // threshold, not merely by the window rolling over.
        let mut limiter = NodeRateLimiter::new();
        let from = 0x5566_7788;
        limit_other(&mut limiter, from, 0);
        assert!(limiter.originator_limited(from));

        // Three packets per window is above OTHER's clear of 2 in every window.
        let mut now = WINDOW_MS;
        for _ in 0..4 {
            for i in 0..3u32 {
                assert!(drop_other(&mut limiter, from, now + i));
            }
            now += WINDOW_MS;
        }
        assert!(limiter.originator_limited(from));
    }

    #[test]
    fn the_shared_unresolved_relay_slot_is_not_charged_without_a_graph() {
        // Just after boot every relay byte is unresolved, so charging the one shared slot would
        // trip it on ordinary traffic and suppress the very relays that build the graph.
        let mut limiter = NodeRateLimiter::new();
        for i in 0..200u32 {
            let pkt = RateLimitPacket {
                from: 0x7700_0000 + i,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: i,
                rebroadcast_candidate: true,
                resolved_relay: None,
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
                graph_established: false,
                on_default_channel: true,
            };
            let _ = limiter.should_drop(&pkt, no_graph);
        }
        assert!(!limiter.unresolved_relay_limited());

        // With a graph, the same traffic charges the slot and trips it.
        let mut limiter = NodeRateLimiter::new();
        for i in 0..200u32 {
            let pkt = RateLimitPacket {
                from: 0x7700_0000 + i,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: i,
                rebroadcast_candidate: true,
                resolved_relay: None,
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
                graph_established: true,
                on_default_channel: true,
            };
            let _ = limiter.should_drop(&pkt, no_graph);
        }
        assert!(limiter.unresolved_relay_limited());
    }

    #[test]
    fn a_resolved_last_hop_is_charged_with_or_without_a_graph() {
        // The gate is scoped to the shared unresolved slot: a resolved NodeID names a real
        // relayer and is accountable from the first frame.
        let resolved = 0x0B00_00BB;
        let mut limiter = NodeRateLimiter::new();
        for i in 0..200u32 {
            let pkt = RateLimitPacket {
                from: 0x8800_0000 + i,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: i,
                rebroadcast_candidate: true,
                resolved_relay: Some(resolved),
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
                graph_established: false,
                on_default_channel: true,
            };
            let _ = limiter.should_drop(&pkt, no_graph);
        }
        assert!(limiter.relay_limited(resolved));
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
        // Recovery is decided at a window roll, on the count the window just ended with. The
        // first roll still sees the four packets that tripped the bucket, so it only resets the
        // count; the roll after that sees the quiet window and lifts. Two rolls, not one — the
        // price of clearing on measured traffic rather than on a bucket that any packet could
        // hold shut indefinitely.
        assert!(
            drop_other(&mut limiter, from, WINDOW_MS + 1),
            "the first roll still carries the count that tripped the bucket"
        );
        assert!(
            !drop_other(&mut limiter, from, 2 * WINDOW_MS + 2),
            "a quiet window below the clear threshold should lift the limit"
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
                graph_established: true,
                on_default_channel: true,
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
            graph_established: true,
            on_default_channel: true,
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
                graph_established: true,
                on_default_channel: true,
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
            graph_established: true,
            on_default_channel: true,
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
            graph_established: true,
            on_default_channel: true,
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
                graph_established: true,
                on_default_channel: true,
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
                graph_established: true,
                on_default_channel: true,
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
                graph_established: true,
                on_default_channel: true,
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
                graph_established: true,
                on_default_channel: true,
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
                    graph_established: true,
                    on_default_channel: true,
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
                    graph_established: true,
                    on_default_channel: true,
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
                    graph_established: true,
                    on_default_channel: true,
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
                graph_established: true,
                on_default_channel: true,
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
                graph_established: true,
                on_default_channel: true,
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
            graph_established: true,
            on_default_channel: true,
        };
        assert!(limiter.should_drop(&pkt, no_graph));
        assert_eq!(limiter.unresolved_relay.count, before);
    }

    fn warmed(limiter: &mut NodeRateLimiter) {
        limiter.set_boot_ms(0);
    }

    #[test]
    fn established_originator_is_never_charged_to_young() {
        let mut limiter = NodeRateLimiter::new();
        warmed(&mut limiter);
        let from = 0xAE00_0001;
        limiter.debug_seed_young(from, 0);
        assert!(limiter.debug_tracks_young(from));
        assert!(
            !drop_other(&mut limiter, from, WARMUP_MS),
            "aged-out originator is established and must not trip young"
        );
        assert!(
            !limiter.debug_tracks_young(from),
            "record released at 30 min"
        );
        for i in 0..YOUNG_TRIP {
            assert!(
                !limiter.debug_is_young(from, WARMUP_MS + 1 + i),
                "released record is established"
            );
            assert_eq!(
                limiter.debug_young_count_value(),
                0,
                "established traffic must not charge the young bucket"
            );
            let _ = drop_text(&mut limiter, from, WARMUP_MS + 1 + i);
        }
        assert!(!limiter.young_limited());
    }

    #[test]
    fn forged_identities_share_one_young_bucket() {
        let mut limiter = NodeRateLimiter::new();
        warmed(&mut limiter);
        let t = WARMUP_MS;
        for i in 0..YOUNG_TRIP - 1 {
            let from = 0xF100_0000 + i;
            assert!(
                !drop_text(&mut limiter, from, t + i),
                "young identity {i} shares the bucket and must not trip yet"
            );
        }
        assert!(
            drop_text(&mut limiter, 0xF100_0000 + YOUNG_TRIP - 1, t + YOUNG_TRIP),
            "a flood of distinct young originators trips the shared bucket"
        );
        assert!(limiter.young_limited());

        let mut established = NodeRateLimiter::new();
        warmed(&mut established);
        for i in 0..YOUNG_TRIP {
            let from = 0xE100_0000 + i;
            established.debug_seed_young(from, 0);
            assert!(
                !drop_text(&mut established, from, t + i),
                "the same volume from established originators must not trip young"
            );
        }
        assert!(!established.young_limited());
    }

    #[test]
    fn young_record_is_released_after_thirty_minutes() {
        let mut limiter = NodeRateLimiter::new();
        warmed(&mut limiter);
        let from = 0xAA00_00AA;
        assert!(!drop_other(&mut limiter, from, WARMUP_MS));
        assert!(limiter.debug_tracks_young(from));
        assert_eq!(limiter.debug_young_count(), 1);
        assert!(!drop_other(&mut limiter, from, WARMUP_MS + YOUNG_AGE_MS));
        assert!(
            !limiter.debug_tracks_young(from),
            "first-sighting record is deleted once the node is no longer young"
        );
        assert_eq!(limiter.debug_young_count(), 0);
    }

    #[test]
    fn no_record_fails_open_with_room_and_closed_when_full() {
        let mut limiter = NodeRateLimiter::new();
        warmed(&mut limiter);
        let now = WARMUP_MS;
        assert!(
            !limiter.debug_is_young(0xB100_0001, now),
            "no record and room in the table means established"
        );
        for i in 0..MAX_YOUNG as u32 {
            limiter.debug_seed_young(0xB200_0000 + i, now);
        }
        assert!(limiter.young_table_full());
        assert!(
            limiter.debug_is_young(0xB300_0001, now),
            "no record and a full table means young"
        );
        assert!(!limiter.debug_tracks_young(0xB300_0001));
    }

    #[test]
    fn young_bucket_is_not_enforced_during_warmup() {
        let mut limiter = NodeRateLimiter::new();
        for i in 0..YOUNG_TRIP + 4 {
            assert!(
                !drop_text(&mut limiter, 0xC100_0000 + i, i),
                "warmup replaces persistence: do not drop the mesh as young after boot"
            );
        }
        assert!(!limiter.young_limited());
        assert!(!limiter.warmed_up(YOUNG_TRIP + 4));
    }

    #[test]
    fn young_bucket_clears_below_clear_without_a_silent_window() {
        let mut limiter = NodeRateLimiter::new();
        warmed(&mut limiter);
        let t = WARMUP_MS;
        for i in 0..YOUNG_TRIP {
            let _ = drop_text(&mut limiter, 0xD100_0000 + i, t + i);
        }
        assert!(limiter.young_limited());
        // Window roll with count still high keeps the limit and zeroes; a few charges
        // under clear, then another roll, lifts — RELAY hysteresis, not a quiet window.
        let busy = t + YOUNG_TRIP;
        for i in 0..20u32 {
            let _ = drop_text(&mut limiter, 0xD200_0000 + i, busy + i);
        }
        let roll = busy + 20 + WINDOW_MS;
        assert!(drop_text(&mut limiter, 0xD300_0001, roll));
        for i in 0..5u32 {
            let _ = drop_text(&mut limiter, 0xD400_0000 + i, roll + 1 + i);
        }
        assert!(
            !drop_text(&mut limiter, 0xD500_0001, roll + 1 + WINDOW_MS),
            "young bucket must lift when the prior window is under the clear threshold"
        );
        assert!(!limiter.young_limited());
    }

    #[test]
    fn undecodable_traffic_does_not_charge_young() {
        let mut limiter = NodeRateLimiter::new();
        warmed(&mut limiter);
        let t = WARMUP_MS;
        for i in 0..YOUNG_TRIP {
            assert!(
                !drop_undecodable(&mut limiter, 0x1100_0000 + i, t + i),
                "undecodable frames belong to UNKNOWN, not young"
            );
        }
        assert!(!limiter.young_limited());
        assert_eq!(limiter.debug_young_count(), 0);
        assert!(!limiter.debug_tracks_young(0x1100_0000));
    }

    #[test]
    fn young_announce_respects_refractory_and_congestion() {
        let mut limiter = NodeRateLimiter::new();
        warmed(&mut limiter);
        let t = WARMUP_MS;
        for i in 0..YOUNG_TRIP {
            let _ = drop_text(&mut limiter, 0xA100_0000 + i, t + i);
        }
        let first = limiter.take_announce();
        assert!(first.is_some(), "first trip may announce");
        assert!(first.unwrap().count <= 4);

        for i in 0..YOUNG_TRIP {
            let _ = drop_text(&mut limiter, 0xA200_0000 + i, t + WINDOW_MS + 10 + i);
        }
        assert!(
            limiter.take_announce().is_none(),
            "refractory is independent of how often the bucket trips"
        );

        let mut congested = NodeRateLimiter::new();
        warmed(&mut congested);
        for i in 0..YOUNG_TRIP {
            let pkt = RateLimitPacket {
                from: 0xA300_0000 + i,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: t + i,
                rebroadcast_candidate: false,
                resolved_relay: None,
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 40.0,
                graph_established: true,
                on_default_channel: true,
            };
            let _ = congested.should_drop(&pkt, no_graph);
        }
        assert!(congested.young_limited());
        assert!(
            congested.take_announce().is_none(),
            "suppressed while channel utilisation is high"
        );

        let mut relay_busy = NodeRateLimiter::new();
        // Young is not enforced until we have been up 30 min; RELAY still is.
        // Trip RELAY first, then trip young after warm-up, or the young bucket
        // would drop the flood before RELAY ever charged.
        for i in 0..60u32 {
            let pkt = RateLimitPacket {
                from: 0xA400_0000 + i,
                to: 0xFFFF_FFFF,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: i,
                rebroadcast_candidate: true,
                resolved_relay: None,
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
                graph_established: true,
                on_default_channel: true,
            };
            let _ = relay_busy.should_drop(&pkt, no_graph);
        }
        assert!(relay_busy.unresolved_relay_limited());
        assert!(!relay_busy.young_limited());
        for i in 0..YOUNG_TRIP {
            let _ = drop_text(&mut relay_busy, 0xA500_0000 + i, WARMUP_MS + i);
        }
        assert!(relay_busy.young_limited());
        assert!(
            relay_busy.take_announce().is_none(),
            "suppressed while the RELAY bucket is limiting"
        );
    }

    #[test]
    fn young_announce_is_fixed_width_ids() {
        let ann = YoungAnnounce {
            ids: [0xAABB_CCDD, 0x0102_0304, 0, 0],
            count: 2,
        };
        let mut buf = [0u8; 48];
        let n = format_young_announce(&ann, &mut buf);
        assert_eq!(&buf[..n], b"Y !aabbccdd !01020304");
    }

    #[test]
    fn default_channel_unicast_to_limited_originator_is_dropped() {
        let mut limiter = NodeRateLimiter::new();
        let banned = 0x0BAD_F00D;
        let responder = 0x1111_2222;
        for i in 0..THRESHOLD_OTHER {
            assert_eq!(
                drop_other(&mut limiter, banned, i * 100),
                i + 1 >= THRESHOLD_OTHER,
                "other charge {i}"
            );
        }
        assert!(limiter.originator_limited(banned));

        assert!(
            limiter.should_drop(&dest_pkt(responder, banned, true, 400), no_graph),
            "default-channel unicast to a limited originator must drop"
        );
        assert_eq!(
            limiter.take_event(),
            Some(RateLimitEvent::DestDrop { node_id: banned })
        );
        assert!(
            !limiter.originator_limited(responder),
            "dest-drop must not charge the responder"
        );
        assert!(!limiter.is_tracking_originator(responder));

        assert!(
            !limiter.should_drop(&dest_pkt(responder, banned, false, 401), no_graph),
            "non-default unicast to a limited originator must pass"
        );
        assert!(
            !limiter.should_drop(
                &originator_pkt(responder, Some(num::NODEINFO_APP), 402),
                no_graph
            ),
            "broadcast from a responder is not dest-dropped"
        );
    }

    #[test]
    fn dest_drop_does_not_apply_to_relay_only_limit() {
        let mut limiter = NodeRateLimiter::new();
        let last_hop = 0x0A00_0011;
        for i in 0..59u32 {
            let pkt = RateLimitPacket {
                from: 0x2200_0000 + i,
                to: NODENUM_BROADCAST,
                decoded_portnum: Some(num::TEXT_MESSAGE_APP),
                now_ms: i,
                rebroadcast_candidate: true,
                resolved_relay: Some(last_hop),
                airtime_ms: RELAY_REF_AIRTIME_MS,
                channel_util_pct: 0.0,
                graph_established: true,
                on_default_channel: true,
            };
            assert!(!limiter.should_drop(&pkt, no_graph), "relay charge {i}");
        }
        let trip = RateLimitPacket {
            from: 0x2200_003B,
            to: NODENUM_BROADCAST,
            decoded_portnum: Some(num::TEXT_MESSAGE_APP),
            now_ms: 59,
            rebroadcast_candidate: true,
            resolved_relay: Some(last_hop),
            airtime_ms: RELAY_REF_AIRTIME_MS,
            channel_util_pct: 0.0,
            graph_established: true,
            on_default_channel: true,
        };
        assert!(limiter.should_drop(&trip, no_graph));
        assert!(limiter.relay_limited(last_hop));
        assert!(!limiter.originator_limited(last_hop));
        assert!(
            !limiter.should_drop(&dest_pkt(0x1111_2222, last_hop, true, 100), no_graph),
            "RELAY-limited last hop is not an originator ban"
        );
    }

    #[test]
    fn dest_drop_lifts_when_originator_clears() {
        let mut limiter = NodeRateLimiter::new();
        let banned = 0x0BAD_F00D;
        let responder = 0x1111_2222;
        for _ in 0..3 {
            assert!(!drop_other(&mut limiter, banned, 0));
        }
        assert!(drop_other(&mut limiter, banned, 0));
        assert!(limiter.should_drop(&dest_pkt(responder, banned, true, 400), no_graph));

        assert!(drop_other(&mut limiter, banned, WINDOW_MS + 1));
        assert!(!drop_other(&mut limiter, banned, 2 * WINDOW_MS + 2));
        assert!(!limiter.originator_limited(banned));
        assert!(!limiter.should_drop(
            &dest_pkt(responder, banned, true, 2 * WINDOW_MS + 3),
            no_graph
        ));
    }
}
