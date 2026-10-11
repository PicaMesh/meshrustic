//! Replies to a silenced source can sustain a flood even after its own transmissions are limited.

use core::cell::Cell;

use mesh_protocol::{rate_limit_bucket, RateLimitBucket, NODENUM_BROADCAST};

const MAX_ORIGINATORS: usize = 16;
const MAX_RELAYS: usize = 8;
const MAX_YOUNG: usize = 32;
/// A generous alumni capacity avoids charging established city-mesh peers as new arrivals.
const MAX_ALUMNI: usize = 128;
const WINDOW_MS: u32 = 90_000;
const YOUNG_AGE_MS: u32 = 30 * 60 * 1000;
const WARMUP_MS: u32 = 30 * 60 * 1000;
/// The admission threshold leaves headroom above measured legitimate new-node bursts; hysteresis permits
/// recovery without complete silence.
const YOUNG_TRIP: u32 = 48;
const YOUNG_CLEAR: u32 = 12;
const ANNOUNCE_REFRACTORY_MS: u32 = 30 * 60 * 1000;
const ANNOUNCE_CHUTIL_HIGH: f32 = 25.0;
const ANNOUNCE_MAX_IDS: usize = 4;

const MAX_DESTS: usize = 8;
const DEST_TRIP: u32 = 20;
const DEST_CLEAR: u32 = 5;
const DEST_MIN_SENDERS: u8 = 3;
const DEST_SENDER_SLOTS: usize = 8;

const THRESHOLD_TEXT: u32 = 30;
const THRESHOLD_ROUTING: u32 = 10;
const THRESHOLD_OTHER: u32 = 4;
const THRESHOLD_UNKNOWN: u32 = 12;
/// Small packet budgets need a half-trip recovery threshold; a quarter of four would require a
/// completely silent window.
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
    count: u32,
    limited: bool,
    clear_threshold: u32,
}

#[derive(Clone, Copy, Default)]
struct OriginatorEntry {
    node_id: u32,
    last_seen_ms: u32,
    text: BucketState,
    routing: BucketState,
    other: BucketState,
    unknown: BucketState,
}

impl OriginatorEntry {
    fn any_limited(&self) -> bool {
        self.text.limited || self.routing.limited || self.other.limited || self.unknown.limited
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
struct DestEntry {
    node_id: u32,
    dest: BucketState,
    senders: [u32; DEST_SENDER_SLOTS],
    sender_count: u8,
}

#[derive(Clone, Default)]
struct YoungSighting {
    node_id: u32,
    first_seen_ms: u32,
    graduated: Cell<bool>,
}

#[derive(Clone, Copy, Debug)]
pub struct YoungCoverageGate {
    pub active: bool,
    pub table_full: bool,
    pub ids: [u32; MAX_YOUNG],
    pub id_count: u8,
    established: [u32; MAX_ALUMNI + MAX_YOUNG],
    established_count: u8,
}

impl YoungCoverageGate {
    pub const fn empty() -> Self {
        Self {
            active: false,
            table_full: false,
            ids: [0; MAX_YOUNG],
            id_count: 0,
            established: [0; MAX_ALUMNI + MAX_YOUNG],
            established_count: 0,
        }
    }

    pub fn blocks(&self, node_id: u32) -> bool {
        if !self.active || node_id == 0 {
            return false;
        }
        if self.table_full {
            return !self.established[..self.established_count as usize].contains(&node_id);
        }
        self.ids[..(self.id_count as usize).min(MAX_YOUNG)].contains(&node_id)
    }
}

impl Default for YoungCoverageGate {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct YoungAnnounce {
    pub ids: [u32; ANNOUNCE_MAX_IDS],
    pub count: u8,
}

pub fn format_young_announce(ann: &YoungAnnounce, out: &mut [u8]) -> usize {
    const PREFIX: &[u8] = b"Young nodes Rate Limit";
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut pos = 0usize;
    let push = |out: &mut [u8], pos: &mut usize, b: u8| {
        if *pos < out.len() {
            out[*pos] = b;
            *pos += 1;
        }
    };
    for &b in PREFIX {
        push(out, &mut pos, b);
    }
    for &id in ann.ids.iter().take(ann.count as usize) {
        push(out, &mut pos, b' ');
        push(out, &mut pos, b'!');
        for n in 0..8 {
            let nib = ((id >> (28 - 4 * n)) & 0xF) as usize;
            push(out, &mut pos, HEX[nib]);
        }
    }
    pos
}

pub struct RateLimitPacket {
    pub from: u32,
    pub to: u32,
    pub decoded_portnum: Option<u32>,
    pub now_ms: u32,
    pub rebroadcast_candidate: bool,
    pub resolved_relay: Option<u32>,
    pub airtime_ms: u32,
    pub channel_util_pct: f32,
    pub graph_established: bool,
    pub on_default_channel: bool,
}

/// A newly booted relay has unresolved neighbours; a shared limit at that point could deny the
/// observations needed to resolve them.
fn charges_unresolved_relay(graph_established: bool) -> bool {
    graph_established
}

fn is_unicast_dest(to: u32) -> bool {
    to != 0 && to != NODENUM_BROADCAST
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GraphProximity {
    pub in_graph: bool,
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
    Dest = 7,
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
    DestDrop { node_id: u32 },
}

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
    alumni: [u32; MAX_ALUMNI],
    alumni_count: u8,
    young_bucket: BucketState,
    dests: [DestEntry; MAX_DESTS],
    dest_count: u8,
    boot_ms: u32,
    boot_known: bool,
    boot_warmed: Cell<bool>,
    announce_broadcast: bool,
    last_announce_ms: u32,
    announce_ever: bool,
    pending_announce: Option<YoungAnnounce>,
    last_event: Option<RateLimitEvent>,
}

impl BucketState {
    fn limited_at(&self, now_ms: u32, window_ms: u32, clear: u32) -> bool {
        let clear = if self.clear_threshold != 0 {
            self.clear_threshold
        } else {
            clear
        };
        let windows = now_ms.wrapping_sub(self.window_start_ms) / window_ms;
        self.limited && (windows == 0 || (windows == 1 && self.count >= clear))
    }

    fn roll(&mut self, now_ms: u32, window_ms: u32, clear: u32) -> bool {
        let windows = now_ms.wrapping_sub(self.window_start_ms) / window_ms;
        if windows == 0 {
            return false;
        }
        let cleared = self.limited && !self.limited_at(now_ms, window_ms, clear);
        if cleared {
            self.limited = false;
        }
        self.count = 0;
        self.window_start_ms = self.window_start_ms.wrapping_add(windows * window_ms);
        cleared
    }
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
                last_seen_ms: 0,
                text: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                    clear_threshold: 0,
                },
                routing: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                    clear_threshold: 0,
                },
                other: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                    clear_threshold: 0,
                },
                unknown: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                    clear_threshold: 0,
                },
            }; MAX_ORIGINATORS],
            originator_count: 0,
            relays: [RelayEntry {
                node_id: 0,
                relay: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                    clear_threshold: 0,
                },
            }; MAX_RELAYS],
            relay_count: 0,
            unresolved_relay: BucketState {
                window_start_ms: 0,
                count: 0,
                limited: false,
                clear_threshold: 0,
            },
            young: [const {
                YoungSighting {
                    node_id: 0,
                    first_seen_ms: 0,
                    graduated: Cell::new(false),
                }
            }; MAX_YOUNG],
            young_count: 0,
            alumni: [0; MAX_ALUMNI],
            alumni_count: 0,
            young_bucket: BucketState {
                window_start_ms: 0,
                count: 0,
                limited: false,
                clear_threshold: 0,
            },
            dests: [DestEntry {
                node_id: 0,
                dest: BucketState {
                    window_start_ms: 0,
                    count: 0,
                    limited: false,
                    clear_threshold: 0,
                },
                senders: [0; DEST_SENDER_SLOTS],
                sender_count: 0,
            }; MAX_DESTS],
            dest_count: 0,
            boot_ms: 0,
            boot_known: false,
            boot_warmed: Cell::new(false),
            announce_broadcast: false,
            last_announce_ms: 0,
            announce_ever: false,
            pending_announce: None,
            last_event: None,
        }
    }

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

    pub fn set_announce_broadcast(&mut self, enabled: bool) {
        self.announce_broadcast = enabled;
    }

    pub fn announce_broadcast(&self) -> bool {
        self.announce_broadcast
    }

    pub fn set_boot_ms(&mut self, boot_ms: u32) {
        self.boot_ms = boot_ms;
        self.boot_known = true;
        self.boot_warmed.set(false);
    }

    pub fn warmed_up(&self, now_ms: u32) -> bool {
        if self.boot_known && now_ms.wrapping_sub(self.boot_ms) >= WARMUP_MS {
            self.boot_warmed.set(true);
        }
        self.boot_warmed.get()
    }

    pub fn young_limited(&self) -> bool {
        self.young_bucket.limited
    }

    pub fn young_table_full(&self, now_ms: u32) -> bool {
        self.active_young_count(now_ms) >= MAX_YOUNG
    }

    pub fn coverage_gate(&self, now_ms: u32) -> YoungCoverageGate {
        if !self.enabled
            || !self.warmed_up(now_ms)
            || !self
                .young_bucket
                .limited_at(now_ms, self.window_ms, YOUNG_CLEAR)
        {
            return YoungCoverageGate::empty();
        }
        let mut ids = [0u32; MAX_YOUNG];
        let mut id_count = 0u8;
        for i in 0..self.young_count as usize {
            if !Self::young_age_active(&self.young[i], now_ms) {
                continue;
            }
            ids[id_count as usize] = self.young[i].node_id;
            id_count += 1;
        }
        let mut established = [0; MAX_ALUMNI + MAX_YOUNG];
        let mut established_count = self.alumni_count;
        established[..established_count as usize]
            .copy_from_slice(&self.alumni[..established_count as usize]);
        for sighting in &self.young[..self.young_count as usize] {
            if !Self::young_age_active(sighting, now_ms) {
                established[established_count as usize] = sighting.node_id;
                established_count += 1;
            }
        }
        YoungCoverageGate {
            active: self.enabled
                && self.warmed_up(now_ms)
                && self
                    .young_bucket
                    .limited_at(now_ms, self.window_ms, YOUNG_CLEAR),
            table_full: self.young_table_full(now_ms),
            ids,
            id_count,
            established,
            established_count,
        }
    }

    pub fn originator_limited(&self, node_id: u32) -> bool {
        self.find_originator(node_id)
            .map(|i| self.originators[i].any_limited())
            .unwrap_or(false)
    }

    pub fn dest_volume_limited(&self, node_id: u32) -> bool {
        self.find_dest(node_id)
            .map(|i| self.dests[i].dest.limited)
            .unwrap_or(false)
    }

    pub fn would_drop(&self, pkt: &RateLimitPacket) -> bool {
        if !self.enabled || pkt.from == 0 || pkt.from == self.node_num || pkt.to == self.node_num {
            return false;
        }
        if self.should_drop_to_limited_dest(pkt) {
            return true;
        }
        let kind = rate_limit_bucket(pkt.decoded_portnum);
        if self.find_originator(pkt.from).is_some_and(|i| {
            let e = &self.originators[i];
            let (b, trip) = match kind {
                RateLimitBucket::Text => (&e.text, THRESHOLD_TEXT),
                RateLimitBucket::Routing => (&e.routing, THRESHOLD_ROUTING),
                RateLimitBucket::Other => (&e.other, THRESHOLD_OTHER),
                RateLimitBucket::Unknown => (&e.unknown, THRESHOLD_UNKNOWN),
            };
            b.limited_at(pkt.now_ms, self.window_ms, originator_clear(trip))
        }) {
            return true;
        }
        if kind != RateLimitBucket::Unknown
            && self.warmed_up(pkt.now_ms)
            && self.is_young(pkt.from, pkt.now_ms)
            && self
                .young_bucket
                .limited_at(pkt.now_ms, self.window_ms, YOUNG_CLEAR)
        {
            return true;
        }
        if !pkt.rebroadcast_candidate {
            return false;
        }
        if let Some(id) = pkt
            .resolved_relay
            .filter(|&id| id != 0 && id != self.node_num && !crate::graph::is_placeholder_node(id))
        {
            self.find_relay(id).is_some_and(|i| {
                self.relays[i]
                    .relay
                    .limited_at(pkt.now_ms, self.window_ms, RELAY_CLEAR_FLOOR_MS)
            })
        } else {
            pkt.graph_established
                && self.unresolved_relay.limited_at(
                    pkt.now_ms,
                    self.window_ms,
                    RELAY_CLEAR_FLOOR_MS,
                )
        }
    }

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

        self.note_boot(pkt.now_ms);

        let dest_volume_drop = self.charge_dest_volume(pkt, &mut proximity);
        if dest_volume_drop || self.should_drop_to_limited_dest(pkt) {
            if !matches!(
                self.last_event,
                Some(RateLimitEvent::Trip {
                    kind: RateLimitKind::Dest,
                    ..
                })
            ) {
                self.last_event = Some(RateLimitEvent::DestDrop { node_id: pkt.to });
            }
            return true;
        }

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

        if let Some(idx) = self.get_or_create_originator(pkt.from, pkt.now_ms, &mut proximity) {
            let node_id = pkt.from;
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

            if self.unresolved_relay.window_start_ms == 0
                && self.unresolved_relay.count == 0
                && !self.unresolved_relay.limited
            {
                self.unresolved_relay.window_start_ms = pkt.now_ms;
            }

            if let Some(resolved) = pkt.resolved_relay.filter(|&id| {
                id != 0 && id != self.node_num && !crate::graph::is_placeholder_node(id)
            }) {
                let Some(idx) = self.get_or_create_relay(resolved, pkt.now_ms, &mut proximity)
                else {
                    return drop;
                };
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

    fn should_drop_to_limited_dest(&self, pkt: &RateLimitPacket) -> bool {
        if !pkt.on_default_channel || !is_unicast_dest(pkt.to) {
            return false;
        }
        self.originator_limited_at(pkt.to, pkt.now_ms)
            || self.dest_volume_limited_at(pkt.to, pkt.now_ms)
    }

    fn dest_volume_port(decoded_portnum: Option<u32>) -> bool {
        matches!(
            decoded_portnum,
            Some(
                mesh_protocol::num::POSITION_APP
                    | mesh_protocol::num::NODEINFO_APP
                    | mesh_protocol::num::TELEMETRY_APP
            )
        )
    }

    fn charges_dest_volume(pkt: &RateLimitPacket) -> bool {
        pkt.on_default_channel
            && is_unicast_dest(pkt.to)
            && pkt.rebroadcast_candidate
            && Self::dest_volume_port(pkt.decoded_portnum)
    }

    fn dest_window_will_roll(b: &BucketState, now_ms: u32, window_ms: u32) -> bool {
        now_ms.wrapping_sub(b.window_start_ms) >= window_ms
    }

    fn roll_dest_senders(entry: &mut DestEntry, now_ms: u32, window_ms: u32) {
        if Self::dest_window_will_roll(&entry.dest, now_ms, window_ms) {
            entry.senders = [0; DEST_SENDER_SLOTS];
            entry.sender_count = 0;
        }
    }

    fn note_dest_sender(entry: &mut DestEntry, from: u32) {
        if from == 0 {
            return;
        }
        if entry.senders[..entry.sender_count as usize].contains(&from) {
            return;
        }
        if (entry.sender_count as usize) < DEST_SENDER_SLOTS {
            entry.senders[entry.sender_count as usize] = from;
            entry.sender_count += 1;
        }
    }

    /// Quiet destination bans must expire even when no new chargeable control traffic arrives.
    fn charge_dest_volume<F>(&mut self, pkt: &RateLimitPacket, proximity: &mut F) -> bool
    where
        F: FnMut(u32) -> GraphProximity,
    {
        if !is_unicast_dest(pkt.to) || !pkt.on_default_channel {
            return false;
        }

        if Self::charges_dest_volume(pkt) {
            let Some(idx) = self.get_or_create_dest(pkt.to, pkt.now_ms, proximity) else {
                return self.dest_volume_limited(pkt.to);
            };
            let entry = &mut self.dests[idx];
            Self::roll_dest_senders(entry, pkt.now_ms, self.window_ms);
            Self::note_dest_sender(entry, pkt.from);
            let trip = if entry.dest.limited || entry.sender_count >= DEST_MIN_SENDERS {
                DEST_TRIP
            } else {
                u32::MAX
            };
            let node_id = entry.node_id;
            let (limited, ev) = Self::check_and_update_bucket(
                &mut entry.dest,
                trip,
                DEST_CLEAR,
                1,
                pkt.now_ms,
                self.window_ms,
                node_id,
                RateLimitKind::Dest,
            );
            if let Some(ev) = ev {
                self.last_event = Some(ev);
            }
            return limited;
        }

        if let Some(idx) = self.find_dest(pkt.to) {
            let entry = &mut self.dests[idx];
            Self::roll_dest_senders(entry, pkt.now_ms, self.window_ms);
            let node_id = entry.node_id;
            let trip = if entry.dest.limited || entry.sender_count >= DEST_MIN_SENDERS {
                DEST_TRIP
            } else {
                u32::MAX
            };
            let (_limited, ev) = Self::check_and_update_bucket(
                &mut entry.dest,
                trip,
                DEST_CLEAR,
                0,
                pkt.now_ms,
                self.window_ms,
                node_id,
                RateLimitKind::Dest,
            );
            if let Some(ev) = ev {
                self.last_event = Some(ev);
            }
        }
        self.dest_volume_limited(pkt.to)
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

    fn add_alumni(&mut self, node_id: u32) -> bool {
        if self.in_alumni(node_id) {
            return true;
        }
        if (self.alumni_count as usize) >= MAX_ALUMNI {
            return false;
        }
        self.alumni[self.alumni_count as usize] = node_id;
        self.alumni_count += 1;
        true
    }

    fn remove_young_at(&mut self, idx: usize) {
        let last = self.young_count as usize - 1;
        if idx < last {
            self.young[idx] = self.young[last].clone();
        }
        self.young[last] = YoungSighting {
            node_id: 0,
            first_seen_ms: 0,
            graduated: Cell::new(false),
        };
        self.young_count -= 1;
    }

    fn young_age_active(sighting: &YoungSighting, now_ms: u32) -> bool {
        if now_ms.wrapping_sub(sighting.first_seen_ms) >= YOUNG_AGE_MS {
            sighting.graduated.set(true);
        }
        !sighting.graduated.get()
    }

    fn active_young_count(&self, now_ms: u32) -> usize {
        let mut n = 0usize;
        for i in 0..self.young_count as usize {
            if Self::young_age_active(&self.young[i], now_ms) {
                n += 1;
            }
        }
        n
    }

    fn find_aged_young(&self, now_ms: u32) -> Option<usize> {
        self.young[..self.young_count as usize]
            .iter()
            .position(|e| !Self::young_age_active(e, now_ms))
    }

    fn expire_if_old(&mut self, node_id: u32, now_ms: u32) {
        let Some(idx) = self.find_young(node_id) else {
            return;
        };
        if Self::young_age_active(&self.young[idx], now_ms) {
            return;
        }
        // A graduated node must remain established when the alumni table is full.
        if self.add_alumni(node_id) {
            self.remove_young_at(idx);
        }
    }

    fn insert_young(&mut self, node_id: u32, now_ms: u32) {
        if (self.young_count as usize) >= MAX_YOUNG {
            return;
        }
        let i = self.young_count as usize;
        self.young[i] = YoungSighting {
            node_id,
            first_seen_ms: now_ms,
            graduated: Cell::new(false),
        };
        self.young_count += 1;
    }

    fn note_originator(&mut self, node_id: u32, now_ms: u32) {
        self.expire_if_old(node_id, now_ms);
        if self.find_young(node_id).is_some() || self.in_alumni(node_id) {
            return;
        }
        if !self.warmed_up(now_ms) {
            let _ = self.add_alumni(node_id);
            return;
        }
        if (self.young_count as usize) < MAX_YOUNG {
            self.insert_young(node_id, now_ms);
            return;
        }
        let Some(idx) = self.find_aged_young(now_ms) else {
            return;
        };
        let old = self.young[idx].node_id;
        let _ = self.add_alumni(old);
        self.remove_young_at(idx);
        self.insert_young(node_id, now_ms);
    }

    fn is_young(&self, node_id: u32, now_ms: u32) -> bool {
        if let Some(idx) = self.find_young(node_id) {
            return Self::young_age_active(&self.young[idx], now_ms);
        }
        if self.in_alumni(node_id) {
            return false;
        }
        self.active_young_count(now_ms) >= MAX_YOUNG
    }

    fn relay_any_limited(&self, now_ms: u32) -> bool {
        if self
            .unresolved_relay
            .limited_at(now_ms, self.window_ms, RELAY_CLEAR_FLOOR_MS)
        {
            return true;
        }
        self.relays[..self.relay_count as usize].iter().any(|e| {
            e.relay
                .limited_at(now_ms, self.window_ms, RELAY_CLEAR_FLOOR_MS)
        })
    }

    fn maybe_announce(&mut self, now_ms: u32, channel_util_pct: f32) {
        if self.relay_any_limited(now_ms) || channel_util_pct > ANNOUNCE_CHUTIL_HIGH {
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
        for i in 0..self.young_count as usize {
            if ann.count as usize >= ANNOUNCE_MAX_IDS {
                break;
            }
            if !Self::young_age_active(&self.young[i], now_ms) {
                continue;
            }
            ann.ids[ann.count as usize] = self.young[i].node_id;
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
        b.clear_threshold = clear;
        if b.roll(now_ms, window_ms, clear) {
            event = Some(RateLimitEvent::Clear { node_id, kind });
        }

        b.count = b.count.saturating_add(charge);

        if !b.limited && b.count >= trip {
            b.limited = true;
            b.window_start_ms = now_ms;
            return (true, Some(RateLimitEvent::Trip { node_id, kind }));
        }

        (b.limited, event)
    }

    fn originator_limited_at(&self, node_id: u32, now_ms: u32) -> bool {
        self.find_originator(node_id).is_some_and(|i| {
            let e = &self.originators[i];
            [
                (e.text, THRESHOLD_TEXT),
                (e.routing, THRESHOLD_ROUTING),
                (e.other, THRESHOLD_OTHER),
                (e.unknown, THRESHOLD_UNKNOWN),
            ]
            .iter()
            .any(|(b, t)| b.limited_at(now_ms, self.window_ms, originator_clear(*t)))
        })
    }

    fn dest_volume_limited_at(&self, node_id: u32, now_ms: u32) -> bool {
        self.find_dest(node_id).is_some_and(|i| {
            self.dests[i]
                .dest
                .limited_at(now_ms, self.window_ms, DEST_CLEAR)
        })
    }

    fn eviction_candidate<F>(
        entries: impl Iterator<Item = (u32, bool, u32)>,
        proximity: &mut F,
    ) -> Option<usize>
    where
        F: FnMut(u32) -> GraphProximity,
    {
        let mut best = None;
        let mut best_rank = (false, 0, 0);
        for (i, (id, limited, age)) in entries.enumerate() {
            if limited {
                continue;
            }
            let p = proximity(id);
            let rank = (!p.in_graph, p.hops, age);
            if best.is_none() || rank > best_rank {
                best = Some(i);
                best_rank = rank;
            }
        }
        best
    }

    fn find_originator(&self, node_id: u32) -> Option<usize> {
        self.originators[..self.originator_count as usize]
            .iter()
            .position(|e| e.node_id == node_id)
    }

    fn find_originator_eviction_candidate<F>(&self, now_ms: u32, proximity: &mut F) -> Option<usize>
    where
        F: FnMut(u32) -> GraphProximity,
    {
        Self::eviction_candidate(
            self.originators[..self.originator_count as usize]
                .iter()
                .map(|e| {
                    (
                        e.node_id,
                        self.originator_limited_at(e.node_id, now_ms),
                        now_ms.wrapping_sub(e.last_seen_ms),
                    )
                }),
            proximity,
        )
    }

    fn get_or_create_originator<F>(
        &mut self,
        node_id: u32,
        now_ms: u32,
        proximity: &mut F,
    ) -> Option<usize>
    where
        F: FnMut(u32) -> GraphProximity,
    {
        if let Some(idx) = self.find_originator(node_id) {
            self.originators[idx].last_seen_ms = now_ms;
            return Some(idx);
        }
        let idx = if (self.originator_count as usize) < MAX_ORIGINATORS {
            let i = self.originator_count as usize;
            self.originator_count += 1;
            i
        } else {
            self.find_originator_eviction_candidate(now_ms, proximity)?
        };
        let fresh = BucketState {
            window_start_ms: now_ms,
            count: 0,
            limited: false,
            clear_threshold: 0,
        };
        self.originators[idx] = OriginatorEntry {
            node_id,
            last_seen_ms: now_ms,
            text: fresh,
            routing: fresh,
            other: fresh,
            unknown: fresh,
        };
        Some(idx)
    }

    fn find_relay(&self, node_id: u32) -> Option<usize> {
        self.relays[..self.relay_count as usize]
            .iter()
            .position(|e| e.node_id == node_id)
    }

    fn find_relay_eviction_candidate<F>(&self, now_ms: u32, proximity: &mut F) -> Option<usize>
    where
        F: FnMut(u32) -> GraphProximity,
    {
        Self::eviction_candidate(
            self.relays[..self.relay_count as usize].iter().map(|e| {
                (
                    e.node_id,
                    e.relay
                        .limited_at(now_ms, self.window_ms, RELAY_CLEAR_FLOOR_MS),
                    now_ms.wrapping_sub(e.relay.window_start_ms),
                )
            }),
            proximity,
        )
    }

    fn get_or_create_relay<F>(
        &mut self,
        node_id: u32,
        now_ms: u32,
        proximity: &mut F,
    ) -> Option<usize>
    where
        F: FnMut(u32) -> GraphProximity,
    {
        if let Some(idx) = self.find_relay(node_id) {
            return Some(idx);
        }
        let idx = if (self.relay_count as usize) < MAX_RELAYS {
            let i = self.relay_count as usize;
            self.relay_count += 1;
            i
        } else {
            self.find_relay_eviction_candidate(now_ms, proximity)?
        };
        self.relays[idx] = RelayEntry {
            node_id,
            relay: BucketState {
                window_start_ms: now_ms,
                count: 0,
                limited: false,
                clear_threshold: 0,
            },
        };
        Some(idx)
    }

    fn find_dest(&self, node_id: u32) -> Option<usize> {
        self.dests[..self.dest_count as usize]
            .iter()
            .position(|e| e.node_id == node_id)
    }

    fn find_dest_eviction_candidate<F>(&self, now_ms: u32, proximity: &mut F) -> Option<usize>
    where
        F: FnMut(u32) -> GraphProximity,
    {
        Self::eviction_candidate(
            self.dests[..self.dest_count as usize].iter().map(|e| {
                (
                    e.node_id,
                    e.dest.limited_at(now_ms, self.window_ms, DEST_CLEAR),
                    now_ms.wrapping_sub(e.dest.window_start_ms),
                )
            }),
            proximity,
        )
    }

    fn get_or_create_dest<F>(
        &mut self,
        node_id: u32,
        now_ms: u32,
        proximity: &mut F,
    ) -> Option<usize>
    where
        F: FnMut(u32) -> GraphProximity,
    {
        if let Some(idx) = self.find_dest(node_id) {
            return Some(idx);
        }
        let idx = if (self.dest_count as usize) < MAX_DESTS {
            let i = self.dest_count as usize;
            self.dest_count += 1;
            i
        } else {
            self.find_dest_eviction_candidate(now_ms, proximity)?
        };
        self.dests[idx] = DestEntry {
            node_id,
            dest: BucketState {
                window_start_ms: now_ms,
                count: 0,
                limited: false,
                clear_threshold: 0,
            },
            senders: [0; DEST_SENDER_SLOTS],
            sender_count: 0,
        };
        Some(idx)
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
        dest_reply(from, to, Some(num::NODEINFO_APP), true, on_default, now_ms)
    }

    fn dest_reply(
        from: u32,
        to: u32,
        port: Option<u32>,
        rebroadcast_candidate: bool,
        on_default: bool,
        now_ms: u32,
    ) -> RateLimitPacket {
        RateLimitPacket {
            from,
            to,
            decoded_portnum: port,
            now_ms,
            rebroadcast_candidate,
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

        fn dest_charge(&self, node_id: u32) -> u32 {
            self.find_dest(node_id)
                .map(|i| self.dests[i].dest.count)
                .unwrap_or(0)
        }

        fn dest_senders(&self, node_id: u32) -> u8 {
            self.find_dest(node_id)
                .map(|i| self.dests[i].sender_count)
                .unwrap_or(0)
        }

        fn tracks_dest(&self, node_id: u32) -> bool {
            self.find_dest(node_id).is_some()
        }

        fn debug_relay_budgets(&self, air_ms: u32, chutil: f32) -> (u32, u32) {
            Self::relay_budgets(air_ms, chutil)
        }

        fn debug_tracks_young(&self, from: u32) -> bool {
            self.find_young(from).is_some()
        }

        fn debug_in_alumni(&self, from: u32) -> bool {
            self.in_alumni(from)
        }

        fn debug_alumni_count(&self) -> usize {
            self.alumni_count as usize
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
            if self.find_young(from).is_some() || self.in_alumni(from) {
                return;
            }
            if (self.young_count as usize) >= MAX_YOUNG {
                return;
            }
            let i = self.young_count as usize;
            self.young[i] = YoungSighting {
                node_id: from,
                first_seen_ms,
                graduated: Cell::new(false),
            };
            self.young_count += 1;
        }
    }

    #[test]
    fn originator_clear_is_half_the_trip_and_never_zero() {
        assert_eq!(originator_clear(THRESHOLD_OTHER), 2);
        assert_eq!(THRESHOLD_OTHER / 4, 1);
        assert_eq!(originator_clear(THRESHOLD_TEXT), 15);
        assert_eq!(originator_clear(THRESHOLD_ROUTING), 5);
        assert_eq!(originator_clear(THRESHOLD_UNKNOWN), 6);
        assert_eq!(originator_clear(1), 1);
        assert!(originator_clear(THRESHOLD_OTHER) > 0);
    }

    #[test]
    fn a_limited_originator_that_keeps_talking_still_recovers() {
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
        let mut limiter = NodeRateLimiter::new();
        let from = 0x5566_7788;
        limit_other(&mut limiter, from, 0);
        assert!(limiter.originator_limited(from));

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
    fn traffic_below_hysteresis_threshold_allows_recovery() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0x8765_4321;
        for _ in 0..3 {
            assert!(!drop_other(&mut limiter, from, 0));
        }
        assert!(drop_other(&mut limiter, from, 0));

        assert!(drop_other(&mut limiter, from, WINDOW_MS - 1));
        assert!(drop_other(&mut limiter, from, 2 * WINDOW_MS - 2));
        assert!(!drop_other(&mut limiter, from, 3 * WINDOW_MS - 3));
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
        assert!(!drop_other(&mut limiter, 0x100F, 2_000));
        assert!(!drop_other(&mut limiter, 0x2000, 3_000));

        assert!(limiter.is_tracking_originator(0x1000), "limited entry kept");
        assert!(limiter.is_tracking_originator(0x2000));
        assert_eq!(limiter.active_originator_count(), 16);
    }

    #[test]
    fn all_limited_entries_survive_identity_churn() {
        let mut limiter = NodeRateLimiter::new();
        for i in 0..16u32 {
            fill_slot(&mut limiter, 0x1000 + i, i * 1_000);
        }
        for i in 0..16u32 {
            limit_other(&mut limiter, 0x1000 + i, i * 1_000 + 100);
        }

        assert!(!drop_other(&mut limiter, 0x2000, 50_000));

        assert!(
            limiter.is_tracking_originator(0x1000),
            "active bans must survive table churn"
        );
        assert!(!limiter.is_tracking_originator(0x2000));
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
        let (trip_long, _) = limiter.debug_relay_budgets(200, 0.0);
        assert_eq!(trip_long, RELAY_TRIP_CEIL_MS);
        let (trip_short, _) = limiter.debug_relay_budgets(50, 0.0);
        assert_eq!(trip_short, 3000);
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
        let after_trip = 60;
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
        let quiet_roll = after_trip + 20 + WINDOW_MS;
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
        assert!(limiter.young_table_full(now));
        assert!(
            limiter.debug_is_young(0xB300_0001, now),
            "no record and 32 active young means fail-closed young"
        );
        assert!(!limiter.debug_tracks_young(0xB300_0001));
    }

    #[test]
    fn parked_rows_do_not_fail_closed_a_busy_mesh() {
        let mut limiter = NodeRateLimiter::new();
        warmed(&mut limiter);
        let t0 = WARMUP_MS;
        let mut next = 0xE100_0000u32;
        while limiter.debug_alumni_count() < MAX_ALUMNI {
            let wave = next;
            let room = MAX_YOUNG - limiter.debug_young_count();
            for j in 0..room as u32 {
                limiter.debug_seed_young(wave + j, t0);
            }
            next = wave + room as u32;
            for j in 0..room as u32 {
                let _ = drop_other(&mut limiter, wave + j, t0 + YOUNG_AGE_MS);
            }
        }
        for i in 0..MAX_YOUNG as u32 {
            limiter.debug_seed_young(0xE200_0000 + i, t0);
        }
        let parked_now = t0 + YOUNG_AGE_MS + 1;
        for i in 0..MAX_YOUNG as u32 {
            let _ = drop_other(&mut limiter, 0xE200_0000 + i, parked_now);
            assert!(limiter.debug_tracks_young(0xE200_0000 + i));
            assert!(!limiter.debug_is_young(0xE200_0000 + i, parked_now));
        }
        assert_eq!(limiter.debug_young_count(), MAX_YOUNG);
        assert!(
            !limiter.young_table_full(parked_now),
            "aged-parked must not count as active-full"
        );
        assert!(
            !limiter.debug_is_young(0xE300_0001, parked_now),
            "busy-mesh overflow must fail open, not charge ordinary traffic"
        );
        assert!(!drop_text(&mut limiter, 0xE300_0001, parked_now));
        assert!(limiter.debug_tracks_young(0xE300_0001));
        assert!(limiter.debug_is_young(0xE300_0001, parked_now));
        assert_eq!(limiter.debug_young_count(), MAX_YOUNG);
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
        assert_eq!(
            limiter.debug_young_count(),
            0,
            "warm-up sightings must not enter the young table"
        );
        assert!(
            limiter.debug_alumni_count() > 0,
            "warm-up sightings are established (alumni)"
        );
        assert!(limiter.debug_in_alumni(0xC100_0000));
    }

    #[test]
    fn warmup_nodes_stay_established_after_warmup() {
        let mut limiter = NodeRateLimiter::new();
        let from = 0xC200_0001;
        assert!(!drop_text(&mut limiter, from, 1_000));
        assert!(limiter.debug_in_alumni(from));
        assert!(!limiter.debug_tracks_young(from));
        let t = WARMUP_MS + 1;
        for i in 0..YOUNG_TRIP {
            assert!(
                !limiter.debug_is_young(from, t + i),
                "boot-neighbour must not become young after warm-up"
            );
            assert_eq!(limiter.debug_young_count_value(), 0);
            let _ = drop_text(&mut limiter, from, t + i);
        }
        assert!(!limiter.young_limited());
    }

    #[test]
    fn alumni_never_reyouths_when_table_turns_over() {
        let mut limiter = NodeRateLimiter::new();
        warmed(&mut limiter);
        let t0 = WARMUP_MS;
        let mut next_id = 0xD100_0000u32;
        while limiter.debug_alumni_count() < MAX_ALUMNI {
            let wave_start = next_id;
            let room = MAX_YOUNG - limiter.debug_young_count();
            for j in 0..room as u32 {
                limiter.debug_seed_young(wave_start + j, t0);
            }
            next_id = wave_start + room as u32;
            for j in 0..room as u32 {
                let id = wave_start + j;
                assert!(
                    !drop_other(&mut limiter, id, t0 + YOUNG_AGE_MS),
                    "graduate into alumni"
                );
            }
        }
        assert_eq!(limiter.debug_alumni_count(), MAX_ALUMNI);
        let early = 0xD100_0000;
        assert!(limiter.debug_in_alumni(early));
        let parked = 0xD200_0001;
        limiter.debug_seed_young(parked, t0);
        assert!(!drop_other(&mut limiter, parked, t0 + YOUNG_AGE_MS + 1));
        assert!(
            limiter.debug_tracks_young(parked),
            "aged entry stays parked when alumni is full"
        );
        assert!(!limiter.debug_is_young(parked, t0 + YOUNG_AGE_MS + 1));
        for i in 0..YOUNG_TRIP {
            assert!(!limiter.debug_is_young(early, t0 + YOUNG_AGE_MS + 2 + i));
            let _ = drop_text(&mut limiter, early, t0 + YOUNG_AGE_MS + 2 + i);
        }
        assert!(!limiter.debug_tracks_young(early));
        assert!(limiter.debug_in_alumni(early));
        assert!(!limiter.young_limited());
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
            relay_busy.take_announce().is_some(),
            "an idle relay bucket expires before young admission warms up"
        );
    }

    #[test]
    fn young_announce_is_fixed_width_ids() {
        let ann = YoungAnnounce {
            ids: [0xAABB_CCDD, 0x0102_0304, 0, 0],
            count: 2,
        };
        let mut buf = [0u8; 80];
        let n = format_young_announce(&ann, &mut buf);
        assert_eq!(&buf[..n], b"Young nodes Rate Limit !aabbccdd !01020304");
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

    fn dest_sender(i: u32) -> u32 {
        0x1111_0001 + i
    }

    fn charge_dest_storm(limiter: &mut NodeRateLimiter, dest: u32, n: u32, start_ms: u32) -> bool {
        charge_dest_storm_from(limiter, dest, n, start_ms, 0)
    }

    fn charge_dest_storm_from(
        limiter: &mut NodeRateLimiter,
        dest: u32,
        n: u32,
        start_ms: u32,
        sender_base: u32,
    ) -> bool {
        let mut last = false;
        for i in 0..n {
            last = limiter.should_drop(
                &dest_pkt(dest_sender(sender_base + i), dest, true, start_ms + i),
                no_graph,
            );
        }
        last
    }

    #[test]
    fn dest_volume_trips_at_20_with_sender_diversity() {
        let mut limiter = NodeRateLimiter::new();
        let dest = 0x0D05_7001;
        for i in 0..19 {
            assert!(
                !limiter.should_drop(&dest_pkt(dest_sender(i), dest, true, i), no_graph),
                "dest charge {i} must not trip"
            );
        }
        assert!(!limiter.dest_volume_limited(dest));
        assert!(limiter.dest_senders(dest) >= DEST_MIN_SENDERS);
        let last_from = dest_sender(19);
        assert!(limiter.should_drop(&dest_pkt(last_from, dest, true, 19), no_graph));
        assert!(limiter.dest_volume_limited(dest));
        assert_eq!(
            limiter.take_event(),
            Some(RateLimitEvent::Trip {
                node_id: dest,
                kind: RateLimitKind::Dest,
            })
        );
        assert!(
            !limiter.is_tracking_originator(last_from),
            "dest-volume drop must not charge the responder"
        );
    }

    #[test]
    fn dest_volume_trips_with_exactly_three_senders() {
        let mut limiter = NodeRateLimiter::new();
        let dest = 0x0D05_7008;
        let senders = [dest_sender(0), dest_sender(1), dest_sender(2)];
        for i in 0..20 {
            limiter.should_drop(&dest_pkt(senders[i % 3], dest, true, i as u32), no_graph);
        }
        assert!(limiter.dest_volume_limited(dest));
        assert_eq!(limiter.dest_senders(dest), 3);
    }

    #[test]
    fn dest_volume_does_not_trip_from_two_senders() {
        let mut limiter = NodeRateLimiter::new();
        let dest = 0x0D05_7002;
        let senders = [dest_sender(0), dest_sender(1)];
        for i in 0..24 {
            limiter.should_drop(&dest_pkt(senders[i % 2], dest, true, i as u32), no_graph);
            assert!(
                !limiter.dest_volume_limited(dest),
                "two senders must not dest-volume trip at {i}"
            );
        }
        assert_eq!(limiter.dest_senders(dest), 2);
        assert_eq!(limiter.dest_charge(dest), 24);
    }

    #[test]
    fn dest_volume_does_not_charge_text_or_routing() {
        let mut limiter = NodeRateLimiter::new();
        let dest = 0x0D05_7003;
        for i in 0..20 {
            assert!(!limiter.should_drop(
                &dest_reply(
                    dest_sender(i),
                    dest,
                    Some(num::TEXT_MESSAGE_APP),
                    true,
                    true,
                    i,
                ),
                no_graph
            ));
            assert!(!limiter.should_drop(
                &dest_reply(
                    dest_sender(100 + i),
                    dest,
                    Some(num::ROUTING_APP),
                    true,
                    true,
                    100 + i,
                ),
                no_graph
            ));
        }
        assert!(!limiter.tracks_dest(dest));
        assert!(!limiter.dest_volume_limited(dest));
    }

    #[test]
    fn dest_volume_ignores_non_rebroadcast_and_non_default() {
        let mut limiter = NodeRateLimiter::new();
        let dest = 0x0D05_7004;
        for i in 0..20 {
            assert!(!limiter.should_drop(
                &dest_reply(
                    dest_sender(i),
                    dest,
                    Some(num::NODEINFO_APP),
                    false,
                    true,
                    i,
                ),
                no_graph
            ));
            assert!(!limiter.should_drop(
                &dest_reply(
                    dest_sender(50 + i),
                    dest,
                    Some(num::NODEINFO_APP),
                    true,
                    false,
                    50 + i,
                ),
                no_graph
            ));
        }
        assert!(!limiter.dest_volume_limited(dest));
    }

    #[test]
    fn dest_volume_dest_drops_text_after_trip() {
        let mut limiter = NodeRateLimiter::new();
        let dest = 0x0D05_7005;
        assert!(charge_dest_storm(&mut limiter, dest, 20, 0));
        let text = dest_reply(
            0xAAAA_0001,
            dest,
            Some(num::TEXT_MESSAGE_APP),
            true,
            true,
            20,
        );
        assert!(limiter.should_drop(&text, no_graph));
        assert_eq!(
            limiter.take_event(),
            Some(RateLimitEvent::DestDrop { node_id: dest })
        );
        assert!(
            !limiter.is_tracking_originator(0xAAAA_0001),
            "dest-drop must not charge the TEXT sender"
        );
    }

    #[test]
    fn dest_volume_clears_after_quiet_window() {
        let mut limiter = NodeRateLimiter::new();
        let dest = 0x0D05_7006;
        assert!(charge_dest_storm(&mut limiter, dest, 20, 0));
        assert!(limiter.dest_volume_limited(dest));

        assert!(limiter.should_drop(
            &dest_pkt(dest_sender(40), dest, true, WINDOW_MS + 20),
            no_graph
        ));
        assert!(limiter.dest_volume_limited(dest));

        assert!(!limiter.should_drop(
            &dest_pkt(dest_sender(41), dest, true, 2 * WINDOW_MS + 21),
            no_graph
        ));
        assert!(!limiter.dest_volume_limited(dest));
    }

    #[test]
    fn dest_volume_stays_limited_while_the_flood_continues() {
        let mut limiter = NodeRateLimiter::new();
        let dest = 0x0D05_7007;
        assert!(charge_dest_storm(&mut limiter, dest, 20, 0));
        for i in 0..6 {
            assert!(
                limiter.should_drop(
                    &dest_pkt(dest_sender(30 + i as u32), dest, true, 20 + i as u32),
                    no_graph
                ),
                "flood packet {i}"
            );
        }
        assert!(limiter.should_drop(
            &dest_pkt(dest_sender(50), dest, true, WINDOW_MS + 26),
            no_graph
        ));
        assert!(limiter.dest_volume_limited(dest));
    }

    #[test]
    fn dest_volume_eviction_keeps_a_limited_dest() {
        let mut limiter = NodeRateLimiter::new();
        let keep = 0x0D05_00AA;
        assert!(charge_dest_storm(&mut limiter, keep, 20, 0));
        assert!(limiter.dest_volume_limited(keep));

        for i in 0..MAX_DESTS as u32 {
            let dest = 0x0D05_1000 + i;
            assert!(!limiter.should_drop(
                &dest_pkt(dest_sender(80 + i), dest, true, 100 + i),
                no_graph
            ));
        }
        assert!(
            limiter.dest_volume_limited(keep),
            "a dest-volume limited sink must not be evicted"
        );
        assert!(limiter.tracks_dest(keep));
    }

    #[test]
    fn dest_volume_full_limited_table_does_not_evict() {
        let mut limiter = NodeRateLimiter::new();
        let mut kept = [0u32; MAX_DESTS];
        for i in 0..MAX_DESTS as u32 {
            let dest = 0x0D05_2000 + i;
            kept[i as usize] = dest;
            assert!(charge_dest_storm_from(
                &mut limiter,
                dest,
                20,
                i * 20,
                i * 20,
            ));
            assert!(limiter.dest_volume_limited(dest));
        }

        let extra = 0x0D05_2FFF;
        let _ = charge_dest_storm_from(&mut limiter, extra, 20, 200, 200);
        assert!(
            !limiter.dest_volume_limited(extra),
            "a full table of dest-volume bans must not open a ninth slot"
        );
        assert!(!limiter.tracks_dest(extra));
        for dest in kept {
            assert!(
                limiter.dest_volume_limited(dest),
                "limited dest !{dest:08x} must survive a full table"
            );
        }
    }

    #[test]
    fn idle_originator_ban_expires_for_destination_and_release_queries() {
        let mut limiter = NodeRateLimiter::with_node_num(1);
        for _ in 0..=THRESHOLD_OTHER {
            drop_other(&mut limiter, 2, 10);
        }
        let mut packet = originator_pkt(2, Some(num::POSITION_APP), 10);
        assert!(limiter.would_drop(&packet));
        packet.now_ms = 10 + 2 * WINDOW_MS;
        assert!(!limiter.would_drop(&packet));
        assert!(!limiter.should_drop(
            &dest_reply(3, 2, Some(num::TEXT_MESSAGE_APP), true, true, packet.now_ms),
            no_graph
        ));
    }

    #[test]
    fn full_originator_table_preserves_live_bans() {
        let mut limiter = NodeRateLimiter::with_node_num(1);
        for source in 2..2 + MAX_ORIGINATORS as u32 {
            for _ in 0..=THRESHOLD_OTHER {
                drop_other(&mut limiter, source, 10);
            }
        }
        for source in 100..200 {
            drop_other(&mut limiter, source, 20);
        }
        for source in 2..2 + MAX_ORIGINATORS as u32 {
            assert!(limiter.would_drop(&originator_pkt(source, Some(num::POSITION_APP), 21)));
        }
    }

    #[test]
    fn full_relay_table_preserves_live_bans() {
        let mut limiter = NodeRateLimiter::with_node_num(1);
        for i in 0..MAX_RELAYS {
            let mut packet = originator_pkt(100 + i as u32, None, 10);
            packet.resolved_relay = Some(200 + i as u32);
            packet.rebroadcast_candidate = true;
            packet.airtime_ms = RELAY_TRIP_CEIL_MS + 1;
            assert!(limiter.should_drop(&packet, no_graph));
        }
        for source in 1000..1100 {
            let mut packet = originator_pkt(source, None, 20);
            packet.resolved_relay = Some(source);
            packet.rebroadcast_candidate = true;
            limiter.should_drop(&packet, no_graph);
        }
        for i in 0..MAX_RELAYS {
            let mut packet = originator_pkt(300 + i as u32, None, 21);
            packet.resolved_relay = Some(200 + i as u32);
            packet.rebroadcast_candidate = true;
            assert!(limiter.would_drop(&packet));
        }
    }

    #[test]
    fn young_graduation_and_boot_warmup_survive_clock_wrap() {
        let mut limiter = NodeRateLimiter::with_node_num(1);
        limiter.set_boot_ms(100);
        assert!(limiter.warmed_up(100 + WARMUP_MS));
        assert!(limiter.warmed_up(101));
        limiter.debug_seed_young(2, 100);
        assert!(!limiter.is_young(2, 100 + YOUNG_AGE_MS));
        assert!(!limiter.is_young(2, 101));
    }

    #[test]
    fn full_young_gate_exempts_established_nodes_and_honors_switch() {
        let mut limiter = NodeRateLimiter::with_node_num(1);
        limiter.set_boot_ms(0);
        limiter.alumni[0] = 2;
        limiter.alumni_count = 1;
        for id in 100..100 + MAX_YOUNG as u32 {
            limiter.debug_seed_young(id, WARMUP_MS);
        }
        limiter.young_bucket = BucketState {
            window_start_ms: WARMUP_MS,
            count: YOUNG_TRIP + 1,
            limited: true,
            clear_threshold: YOUNG_CLEAR,
        };
        let gate = limiter.coverage_gate(WARMUP_MS + 1);
        assert!(gate.table_full && gate.active);
        assert!(!gate.blocks(2));
        assert!(gate.blocks(999));
        limiter.set_enabled(false);
        assert!(!limiter.coverage_gate(WARMUP_MS + 2).blocks(999));
    }

    #[test]
    fn release_policy_queries_do_not_charge_buckets() {
        let mut limiter = NodeRateLimiter::with_node_num(1);
        let packet = originator_pkt(2, Some(num::POSITION_APP), 10);
        assert!(!limiter.should_drop(&packet, no_graph));
        for _ in 0..100 {
            assert!(!limiter.would_drop(&packet));
        }
        assert_eq!(limiter.originators[0].other.count, 1);
    }

    #[test]
    fn non_volume_traffic_does_not_trip_a_destination_without_sender_diversity() {
        let mut limiter = NodeRateLimiter::with_node_num(1);
        for id in 0..=DEST_TRIP {
            limiter.should_drop(&dest_pkt(2, 9, true, id), no_graph);
        }
        assert_eq!(limiter.dests[0].sender_count, 1);
        for source in [3, 4] {
            let packet = dest_reply(source, 9, Some(num::TEXT_MESSAGE_APP), true, true, 30);
            assert!(!limiter.should_drop(&packet, no_graph));
        }
        assert!(!limiter.dest_volume_limited(9));
    }

    #[test]
    fn destination_sender_diversity_resets_a_window_started_at_zero() {
        let mut limiter = NodeRateLimiter::with_node_num(1);
        limiter.should_drop(&dest_pkt(2, 9, true, 0), no_graph);
        limiter.should_drop(&dest_pkt(3, 9, true, 1), no_graph);
        limiter.should_drop(&dest_pkt(4, 9, true, WINDOW_MS), no_graph);
        assert_eq!(limiter.dests[0].sender_count, 1);
    }

    #[test]
    fn diagnostic_formatter_handles_invalid_public_count() {
        let announcement = YoungAnnounce {
            ids: [1, 2, 3, 4],
            count: u8::MAX,
        };
        for len in 0..80 {
            let mut output = [0u8; 80];
            assert!(format_young_announce(&announcement, &mut output[..len]) <= len);
        }
    }
}
