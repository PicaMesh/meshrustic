# MeshRustic interoperability contract

What a MeshRustic node puts on the air, how it reads what others put there, and how it times
its transmissions, stated as rules with the stock Meshtastic behaviour each rule derives from,
the MeshRustic function that implements it, and the test that pins it. Every SignalRouting node
on the mesh follows the same rules; this document is the wire and timing contract MeshRustic
holds itself to. Rules are prose; code lives in the code.

## 1. Channel access and timing

Model: after any frame ends, the radios that received it are not listening for up to about
170 ms (measured on Meshtastic-based peers as their per-packet processing time) while they read it out and
re-arm. Every timing rule below follows from that one figure, `PEER_TURNAROUND_MS`
(250 ms) in `channel_access`, plus the preset's slot time, its contention window and the frame
airtime. Every SignalRouting node uses the same figure.

- **No frame within the turnaround after a reception.** After any received frame, or a
  transmission deferred because a frame was arriving, the node keys up no sooner than the
  turnaround or the contention backoff, whichever is longer. Implemented by
  `ChannelAccess::note_rx` and `ChannelAccess::may_transmit`; the board's radio task consults it
  before releasing router frames and passes the same verdict to `RadioSlot::service`, so a
  frame already queued in the radio cannot key up on its own. Derived from stock's per-packet
  `getTxDelayMsec` contention delay and the measured peer processing time. Tests:
  `channel_access` unit tests.
- **Gap after our own frame.** At least `TX_GAP_MS` (100 ms) of silence follows each of our
  frames before the next one starts (`ChannelAccess::note_tx_done`). Stock never sends two
  frames back to back because each carries its own contention delay.
- **Coordinated relay slots start at the turnaround.** Slot k of the SignalRouting ladder fires
  at `SLOT_ORIGIN_MS` plus k half-airtimes (`channel_access::slot_delay_ms`, used by
  `plan_broadcast_relay` and `NeighborGraph::commit_relay`). Undesignated cost-ranked unicast
  slot 0 uses the same origin (`Router::evaluate_tx_plan`), as does a unicast that names us as
  next hop (`plan_designated_unicast`). All SignalRouting nodes share the origin, so slot order
  agrees at every preset. Tests: `sr_slot_schedule`, `broadcast_relay` unit tests,
  `undesignated_unicast_slot_zero_waits_for_peer_turnaround`.
- **Waiting for a designated SR next hop.** Before acting in its place, a candidate waits the
  turnaround plus the peer's maximum contention delay plus one airtime
  (`channel_access::peer_relay_wait_ms`, via `Router::sr_peer_relay_wait_ms`). For a stock next
  hop the wait is stock's worst-case delay plus one airtime (`tx_delay_ms_worst`).
- **Waiting for a destination's ACK.** When the source's topology lists the destination as
  hearing it, every relay candidate first waits the turnaround plus twice the maximum contention
  delay plus the ACK airtime (`channel_access::dest_ack_wait_ms`, via `Router::dest_ack_wait_ms`);
  a reply heard cancels the queued relay (`Router::perhaps_cancel_dupe`). Test:
  `peer_waits_derive_from_the_turnaround`, `dest_ack_wait_includes_processing_allowance`.

## 2. Header fields on frames we originate

- **Hop fields.** Originated frames carry `hop_start` equal to `hop_limit`, as stock does.
  Replies (`Router::response_header`) use stock's hops-used-plus-margin rule from
  `hop_limit_for_response`. A request that reached us through a relay keeps its reply's hop
  budget. Tests: `reply_to_direct_hearing_neighbour_is_hop_limited_when_stock_nodes_are_around`.
- **Last hop.** A unicast to a direct neighbour that hears us, while stock neighbours listen
  (`NeighborGraph::caps_last_hop`), goes out with `LAST_HOP_BUDGET` (one hop) and the
  destination's byte as next hop, whether we originate it (`Router::send_local`, replies, ACKs)
  or relay it (`relay_header_with_next_hop_opts`, which rewrites `hop_start` so hops used stay
  countable). Stock relays a unicast only when the next hop is unset or its own byte, so the
  frame is left alone; the destination reads zero hops used and acknowledges; and `hop_start` is
  populated, which the Meshtastic Android app requires before it shows a traceroute reply. Among
  SR peers only, slot coordination suppresses relays and the budget stays untouched. Tests:
  `last_hop_relay_has_one_hop_and_names_the_destination`, `unicast_hop_limit`,
  `last_hop_reply_is_direct_for_stock_and_left_alone_by_stock_relays`.
- **Relay byte.** Every frame we originate carries our own low node byte in `relay_node`, as
  stock does since 2.5 (`build_app_wire_frame`, the topology, nodeinfo and telemetry frame
  builders, the PKI frame builder). Receivers treat a relay byte equal to the sender's byte, or
  zero, as a direct transmission (`is_direct_packet`).
- **Next hop.** A relayed unicast carries the next hop from our own route or zero, never the
  byte inherited from the incoming frame (`relay_header_with_next_hop_opts`). Zero means "any
  relay may carry it", stock's `NO_NEXT_HOP_PREFERENCE`.
- **Data bitfield.** Every Data payload we originate carries `Data.bitfield`
  (`encode_data_payload_opts`, `DataBitfield::Ours`), as stock does since 2.5: bit 1 mirrors
  `want_response`, bit 0 is our LoRa "OK to MQTT" setting (stock's `config_ok_to_mqtt`, admin
  field 105, persisted in the flash record, on by default). Its presence is what tells a stock
  receiver that our `hop_start` is populated; a zero-`hop_start` frame without it has travelled
  an unknown number of hops (`hops_away`, stock's `getHopsAway`), and stock never acknowledges a
  response whose hop count it does not know. A frame we re-encode for relay keeps the origin's
  word verbatim
  (`DataBitfield::Origin`), so gateways and receivers read what the origin wrote. Tests:
  `originated_data_carries_the_bitfield`, `relayed_data_keeps_the_origin_bitfield`,
  `hop_zero_reply_is_readable_as_direct_by_a_stock_receiver`.

## 3. Acknowledgements and replies

- **A reply is the ACK.** When a module answers a request that asked for an ACK, the reply,
  carrying the request id, is the acknowledgement and no separate ACK frame is sent
  (`module_reply_suppresses_ack`, set by the admin and traceroute reply paths, checked in
  `Router::process_reliable_rx`). Stock behaves the same through `MeshModule::currentReply`.
  Test: `traceroute_reply_replaces_the_separate_ack`.
- **Any reply with our request id ends our retransmit.** Our reliable retransmit of a request
  stops on an ACK, a NAK or a module reply that carries the request id
  (`Router::process_reliable_rx`, stock's `ReliableRouter`). Test:
  `traceroute_reply_stops_our_reliable_retransmit`.
- **Responses are acknowledged only when direct.** A response addressed to us (request or reply
  id set) with WantAck gets a hop-0 ACK only if it travelled zero hops or named us as next hop
  (`Router::process_reliable_rx`, stock's `ReliableRouter::sniffReceived`); a relayed response
  was acknowledged implicitly by its relay. Response hop budgets follow stock's
  `getHopLimitForResponse` (`hop_limit_for_response`): hops used plus margin, zero for a
  zero-hop request, the configured limit when the hop count is unknown.
- **Routing ACKs that retrace the link are not relayed** (`SrSkipReason::ReplyRetracesLink`).

## 3a. Unicast routes

- **An edge is one-directional evidence, priced at the receiver.** A node listing a neighbour
  says it hears that neighbour, at the RSSI and SNR it measured on that neighbour's signal.
  `calculate_route` therefore runs Dijkstra backwards from the destination: a settled node is
  reached by the nodes it lists (at the cost it measured), by the nodes whose edge to it carries
  `hears_us`, and, if it publishes no topology (`route::publishes_topology`), by anyone who hears
  it. An edge is never used against its direction and every hop costs what its receiver measured.
  Intermediate hops must be routable; the destination need not. The route carries `hops`, logged
  as `Route to !X via !Y cost=C hops=H`. `find_better_positioned_neighbor` applies the same
  evidence rule through `route::can_deliver`. Tests: `one_way_edge_is_not_a_route`,
  `route_cost_is_measured_at_the_receiver`.
- **Delivery vs confirmed coverage.** Route search and unicast ranking treat a hop as
  deliverable via `route::can_deliver` (optimistic when the receiver does not publish topology).
  Broadcast absorb, pre-cover, ranking coverage, and unique-coverage cancel share one admission
  rule: `route::covers` — evidence graded by whether the receiver reports (§3b), over a link at
  or below `COVERAGE_ETX_CEILING_FIXED` — or, for a neighbour nobody can be shown to reach,
  `route::coverage_owner` naming that relay. Absorb credits exactly what admission credited
  (`admits_coverage`, test `an_owner_taking_a_slot_absorbs_the_neighbour_it_owns`): crediting only `covers` left an owned neighbour uncovered after its owner
  took a slot, and a later phase relayed for it again. A sticky-but-hopeless `hears_us` link is
  not coverage in any of them.
  Shared helpers: `delivery_hop_cost_fixed`, `hop_cost_fixed`. Tests: `can_deliver_*`,
  `known_to_hear_ignores_stock_optimism`, `covers_requires_a_link_that_is_not_hopeless`,
  `one_way_list_to_publishing_dest_is_not_a_direct_path`.
- **Inbound-gateway fallback.** When no confirmed path exists (and the downstream table has
  none either), the search runs again allowing hops into a topology-publishing node that never
  confirmed the sender, at `UNVERIFIED_HOP_COST_FACTOR` times their cost, so the node that hears
  the far side still carries the frame out; a one-way edge is usually a marginal link or a
  truncated list. The route is marked unverified (`Route::verified`, logged as `unverified`),
  a confirmed path of any length wins over it, and passive nodes are never chosen as the
  gateway. Test: `inbound_gateway_is_the_fallback_only_without_a_confirmed_path`.
- **A next hop equal to the destination's byte names no relayer.** A unicast whose next hop is
  the destination's own low byte is planned as one with no named relayer: the cost ranking
  decides, nobody owns slot 0 (`Router::evaluate_tx_plan`, `relayer_named`). Test:
  `next_hop_equal_to_the_destination_names_no_relayer`.
- **Cost-ranked unicast coordination.** When no next hop is named (or the destination byte
  names none), every SR overhearer ranks itself and its SR neighbours by deliverable cost to
  the destination (`plan_unicast_relay`); the best placed keys up first and the rest cancel on
  its copy. Slot 0 waits `SLOT_ORIGIN_MS`; later slots wait for the leader's peer relay window
  then space by half an airtime. Tests: `undesignated_unicast_defers_to_the_neighbour_that_reaches_the_destination`,
  `undesignated_unicast_slot_zero_waits_for_peer_turnaround`.
- **Soft coverage skips.** `UnicastCovered` for a shared downstream gateway, or for a
  better-positioned SR neighbour, applies only when that node is known to hold this copy
  (`heard_from` or has already transmitted this id). A neighbour that *could* hear the
  transmitter is not enough. Tests: `shared_downstream_suppresses_only_when_gateway_holds_copy`,
  `sr_neighbour_must_have_transmitted_to_suppress_us`.
- **Next hop is the relayer.** If our *verified* path next hop is the node we heard from, we
  drop the relay only when that node can finish delivery to the destination (`can_deliver` or
  downstream). Otherwise the next hop is cleared and we stay in the ranking as backup. Tests:
  `unicast_not_relayed_back_to_the_relayer`, `next_hop_is_relayer_clears_when_they_cannot_finish`.
- **A guessed route is never stamped.** The verdict belongs to the hop the picker returned, not
  to the searched route: `NeighborGraph::get_next_hop_verified` reports `false` for a
  better-positioned neighbour, the downstream table, best-effort self relay and direct delivery,
  and `Route::verified` is false until the strict search sets it, so an empty route never claims
  one (test `only_the_confirmed_search_reports_a_verified_route`). Such a route may carry a
  unicast,
  but its next hop is cleared before transmission: the node it names never confirmed it hears
  the destination, and a designation makes every other candidate stand down and wait for a copy
  that node may have no way to send. Cleared, we are one ranked candidate among several. Test:
  `guessed_route_is_never_stamped_as_next_hop`.
- **A guessed route that runs back is contained.** If the only route is unverified *and* names
  the node we heard the packet from, and the frame was not addressed to us as its next hop, the
  relay is dropped, not merely stripped of its next hop
  (`SrSkipReason::UnverifiedBacktrack`, logged as `guessed route runs back`). It would carry the
  packet away from its destination onto our own side of the mesh, where the only path anyone
  knows is the one it arrived on, and for a `want_ack` unicast it invites the far side to retry
  through us. A verified route pointing back is the case above: the evidence says that direction
  reaches the destination. A frame that named us is forwarded with the next hop cleared instead:
  the sender is waiting on us specifically and its retries would designate us again, so one copy
  from us costs less than three from it. Tests: `guessed_route_back_the_way_it_came_is_dropped`,
  `a_frame_named_for_us_is_forwarded_even_on_a_guessed_backtrack`.
- **Designated next hop and backup.** A wire next hop that is not us owns slot 0; every other
  candidate shifts one slot behind the peer or stock wait (`plan_designated_unicast`). Ranking
  `Err` does not abort that backup. Forward and backup TX stamp **our path** next hop; flood
  (`next_hop = 0`) only on the last relayed `want_ack` retry. Tests:
  `unicast_designated_*`, `designated_hop_backup_survives_ranking_skip` (a coverage skip keeps
  the backup, at its unranked slot rung rather than all backups sharing slot 1),
  `forwarded_want_ack_unicast_is_retried_then_released_to_flooding`.

## 3b. Broadcast relay and T1

- **Unique coverage owns a slot.** A broadcast relay slot is taken when we still uniquely reach
  a neighbour that the transmitter and earlier coverers do not. Otherwise we take no ranked slot.
  Pending later slots cancel when unique coverage is gone (`has_unique_coverage` /
  `perhaps_cancel_dupe`). Tests: broadcast coverage cases in `broadcast_relay` /
  `sr_slot_schedule` / `sr_coverage`.
- **Coverage is evidence graded by whether the receiver reports** (`route::covers`), over a link
  that is not hopeless (delivery-direction cost at or below `COVERAGE_ETX_CEILING_FIXED`). A node
  that publishes topology is held to it: it must be known to hear the transmitter
  (`known_to_hear`: `hears_us` on the transmitter's edge, or the receiver listing the
  transmitter), because its silence about the transmitter is itself information. A node that
  publishes nothing — stock, mute, or not yet classified — can never confirm anything, so the
  transmitter's own edge to it is all the evidence there will ever be. Holding the second class to
  the first class's standard made every neighbour of one silent node relay every frame for it.
  `hears_us` is sticky, hence the cost half: a peer that heard the transmitter once keeps the flag
  while its link decays. The rule prices pre-coverage from the transmitter's list, each
  candidate's coverage set, the absorbed coverage of earlier slots, and unique coverage. Tests:
  `covers_requires_a_link_that_is_not_hopeless`, `covers_a_silent_node_on_the_senders_own_edge`,
  `one_way_listed_neighbor_is_not_precovered`, `hopeless_confirmed_neighbor_is_not_precovered`,
  `poor_link_does_not_count_as_coverage`,
  `a_sticky_confirmation_behind_a_decayed_link_is_not_ours_to_cover`.
- **A neighbour nobody can be shown to reach belongs to one relayer** (`route::coverage_owner`).
  Its receive path is all anyone can measure, so the owner is the node hearing it best, compared
  in `OWNER_COST_BUCKET_FIXED` buckets, with stock ROUTER/REPEATER/ROUTER_CLIENT given way first
  (they rebroadcast regardless of SR and already hold the earliest slots) and the lowest node id
  as the final tie-break. Mute and passive nodes never own: they do not relay. **Ownership stops
  at the coverage ceiling**: a link past `COVERAGE_ETX_CEILING_FIXED` (the "heard once" ETX 40
  sentinel included) delivers nothing, so its holder owns nothing and the neighbour is simply
  out of reach. Ownership decides *who* carries such a neighbour, never *whether* it is
  reachable — without that bound the ranking credited unique coverage to a node that cannot
  deliver and handed it the first slot, so the packet waited a full defer window for a relay
  that could not come. Measured 2026-09-08: 74 of 183 slots went out over links worse than the
  ceiling, and one node's insurance fired 65 times in 109 minutes to carry those packets
  instead. Test: `a_hopeless_link_owns_nothing`. Applied both in the
  slot ranking and in unique coverage, so the branch does not relay N times for the same node.
  Unique coverage additionally ignores our own non-`Reported` edges in the *ranking* only, so that
  peers computing slot order from the reported topology reach our conclusion; the dupe-cancel path
  does not need the same filter, because no production path leaves a Mirrored edge on a real
  neighbour of ours (test `no_production_path_leaves_a_mirrored_self_edge`).
  **Only a silent neighbour has an owner**: one that publishes topology and does not list a
  candidate has reported that the candidate cannot reach it, and that silence is evidence, so
  nobody owns it (test `a_publisher_has_no_owner`). The consequence is deliberate and worth
  stating plainly: a topology-publishing neighbour — SR-active or passive — that never lists us
  is nobody's coverage and gets no relay from anyone, because every node's own report says none
  of us reaches it. Not everything in the graph is coverable, and the alternative is spending a
  slot against the node's own report; it becomes coverable the moment it lists somebody, which
  sets `hears_us` on that node's edge and satisfies `covers`. This is also why the ranking keeps
  `delivery_hop_cost_fixed` for pricing — `can_deliver` failing is that same report, not a
  missing measurement.
  **The stock-coverage phase is gone**, and with it a second owner election and its own
  legacy-role predicates. It relayed for a mute or legacy neighbour "nobody ranked ahead
  covers" — but it applied no ETX ceiling and iterated our Mirrored edges as well, so it relayed
  in exactly the three states the coverage model calls undeliverable: a link past the ceiling, a
  link at the heard-once sentinel, and a neighbour we never measured directly. Where our link is
  sound the ranking already carries it, because coverage admits a silent neighbour on our own
  edge. This is a deliberate narrowing, not a no-op: over an ETX-8 link a copy arrives about one
  time in eight, and the phase spent a slot on it. Field: `via=stock` fired once in about ten
  days of logs (2026-09-06), in a state where every candidate had zero unique coverage, and a
  peer's duplicate cancelled it 200 ms later. Tests:
  `mute_stock_neighbour_only_we_reach_is_carried_by_the_ranking`,
  `a_mute_neighbour_past_the_ceiling_is_nobody_s_relay`.
  Tests: `a_hopeless_link_owns_nothing`,
  `mute_neighbour_owner_is_the_best_link_then_the_lowest_id`,
  `silent_neighbour_is_relayed_for_by_the_best_link_only`,
  `inbound_only_neighbor_belongs_to_its_owner`.
- **The ranking inputs are logged on the defer path too**, not only when we relay
  (`log_slot_scheduling`): a log that shows we stood down without showing who we stood down for
  cannot tell a correct deferral from a slot handed to a node that cannot deliver. That gap is
  why the 2026-09-08 ownership defect had to be found through a peer's log instead of our own.
- **We log the neighbour we relay for** (`SrLogEvent::CoverageFor`): a relay nobody needs and a
  relay that saves a node are indistinguishable in a field log otherwise. The name comes from the
  ranking that made the decision (`BroadcastRelayPlan::coverage_for`, the winning candidate's
  first neighbour the transmitter did not reach), never recomputed afterwards against a different
  set of coverers — that named neighbours a ranked peer does reach. `unique_coverage_neighbor`
  answers the dupe question instead: is any neighbour left uncovered by the nodes that have
  actually transmitted. Test: `plan_names_the_neighbour_the_relay_is_for`.
- **Sole candidate.** When the candidate list is only us — nobody else here can carry the frame,
  or we have not classified any neighbour yet — the ranking's coverage question has nothing to
  weigh, and our copy is the only witness its transmitter can ever get, so we relay immediately
  (`RelayReason::Sparse`). This is a node's state for its first topology interval after boot,
  where behaving like a plain rebroadcaster is right, and it is what makes a two-node mesh work.
- **T1 stands in for a transmission that was expected and did not happen, and for nothing
  else.** Deferring arms it when either is true, both known at that moment:
  **a slot was given** — `BroadcastRelayPlan::slots_given > 0`, i.e. a stock relay router or a
  ranked SR peer is expected to relay, so if their copy never comes ours is the redundancy that
  covers the loss; or
  **a witness is owed** — the frame carries `want_ack`, reached us straight from its originator
  (`hop_start == hop_limit`), and `NeighborGraph::is_elected_witness` makes us its answerer.
  Stock's reliable router turns a heard rebroadcast of its own packet into an implicit ACK
  and otherwise retransmits it three times, so one elected witness replaces three
  frames from the sender. A frame that arrived relayed was already witnessed — the relay's own
  transmission is the rebroadcast its source heard — so no witness is owed for it.
  Neither reason means no transmission is expected and nobody is waiting to be told
  (`SrSkipReason::AlreadyCovered`, logged as `no slot given, no witness owed`). Measured over
  30 min on three field nodes (2026-09-08): this declines about 100 copies per node and cut T1
  traffic roughly tenfold, while delivery between two colocated nodes was unchanged (3.2%
  asymmetric ids with it, 2.9% without).
- **A heard copy stops the insurance even after it fired.** The frame leaves the router but can
  still be waiting behind listen-before-talk, so a copy heard in that window pulls it back out
  of the radio TX queue (`note_tx_cancel`, the same path a committed relay uses); once the radio
  reports the transmission there is nothing left to cancel. Without it an insurer that fired
  before hearing the first one put a second copy on the air 0.4 to 1.0 s later — six times in
  109 minutes (2026-09-08) — because the insurance rungs are half an airtime apart, which is
  shorter than the enqueue-to-air latency. Test: `a_copy_heard_after_t1_fired_pulls_the_frame_back`.
- **Once armed, only a heard copy stands it down** (`T1CancelReason::RelayHeard`, or our own
  transmission). The coverage question is deliberately *not* asked again at fire time: it
  answers "who needs a relay", not "did the expected frame actually arrive". Two of the seven
  late copies measured on 2026-09-08 carried frames to nodes the graph believed were covered —
  `0x3fd7bd50` reached MR22, and `0x750cc87a` reached two nodes, only via the late copy — because
  the covering link was marginal (−84 to −93 dBm) and the frame was lost on it. Coverage is
  topology; per-frame loss is invisible to it, and T1 is the layer that absorbs it.
  Our own originated broadcasts keep their own timer and are not judged by this rule; a ranked
  commit never arms T1.
  Any heard rebroadcast cancels T1; T1 never fires if we already recorded our own transmission.
  Insurers stagger: every node that armed T1 waits its unranked slot rung
  (`relay_slot_index`, one half-airtime apart) after the defer window, and the first firing
  cancels the rest. Firing together would collide exactly when the ranked relay is the frame
  that went missing.
  Originator T1 in `send_local` remains a separate “did anyone rebroadcast?” timer with the same
  cancel-on-rebroadcast helpers. Tests: `t1_retransmit_fires_after_defer_window`,
  `t1_stands_down_when_the_peers_copy_is_heard`, `no_expected_transmission_arms_no_insurance`,
  `elected_witness_answers_when_no_slot_was_given`,
  `source_witness_is_the_neighbour_the_source_can_hear`, `ranked_broadcast_slot_does_not_arm_t1`.

## 4. Duplicates and hand-offs

- **A duplicate that names us as next hop is a hand-off.** It is processed as a fresh reception
  and forwarded; if our route points back at the node that handed it over, it goes out with the
  next hop cleared instead of being dropped (`Router::process_inbound` duplicate branch,
  `designated_repeat_id`). Stock's `NextHopRouter` does the same under `weWereNextHop`. Before
  re-planning, the earlier copy's pending frame, relay commit and armed retry are cancelled.
  Test: `duplicate_naming_us_as_next_hop_is_forwarded_with_next_hop_cleared`.
- **One frame per packet.** The pending relay table holds at most one frame per packet
  (`Router::store_pending` replaces), and a packet we have already transmitted is never released
  again (`Router::poll_ready_relay`).
- **Other duplicates cancel our pending copy** when the copy shows the packet is moving on
  (`Router::perhaps_cancel_dupe`); broadcast copies are pulled back only when the transmitters
  heard so far cover every neighbour we reach.

## 5. Topology reports

- **Cadence.** Periodic every `TOPOLOGY_BROADCAST_MS`; a dirty broadcast no sooner than
  `TOPOLOGY_DIRTY_MIN_MS` after the last one; a header-only version-0 broadcast at boot; direct
  SR neighbours answer a boot broadcast once per `BOOTSTRAP_REPLY_MIN_MS`. Originated packets do
  not reset the timer.
- **A bootstrap request is answered by any list, not only by its own reply.** The request is
  recorded with the time it arrived, and the queued reply is dropped if a broadcast carrying
  neighbours went out after that time (`SrLogEvent::BootstrapReplyAlreadyAnswered`): the
  requester already has what it asked for, and a second list under the next version number is
  accepted by every receiver as a fresh report and duplicated by every relayer. The reply is
  deliberately not gated on the periodic timer, so that a booting neighbour never waits out a
  broadcast interval; this rule is what keeps that from doubling the list. A header-only boot
  broadcast of our own does not count as an answer — it names no neighbours. Test:
  `bootstrap_reply_is_dropped_when_a_list_already_went_out`.
- **Version acceptance** (`NeighborGraph::merge_topology`): first contact accepts any version;
  then a repeat or a forward move of 1 to 127; a header-only version-0 broadcast, direct or
  relayed, resets the tracked version, active or passive sender; after `TOPOLOGY_RESYNC_MS` without an accepted
  report, any version is taken as the new base; and when the boot broadcast was lost, two
  consecutive rejected reports whose versions climb by one re-base us on the second (late copies
  of old reports never arrive an interval apart). Tests: `peer_boot_broadcast_resets_its_topology_version`,
  `passive_peer_boot_broadcast_resets_its_topology_version_too`,
  `peer_topology_resyncs_after_two_silent_intervals`,
  `relayed_boot_broadcast_resets_the_topology_version_too`,
  `peer_restart_is_accepted_after_two_climbing_stale_reports`.
- **An empty list clears nothing.** The "an unlisted neighbour does not hear the sender" rule
  runs only on a complete, non-empty list: a boot broadcast is a restart notice, and a node that
  hears nobody says nothing about who hears it. Test: `empty_list_does_not_clear_hears_us`.
- **Multi-packet lists.** Lists longer than `MAX_NEIGHBORS_PER_PACKET` go out as chunks of one
  version, spaced twice the chunk airtime (`Router::poll_topology_tx`), flagged in the header
  (`PACKED_HEADER_FLAG_MORE_CHUNKS`, `PACKED_HEADER_FLAG_CONTINUATION`). The "an unlisted
  neighbour does not hear the sender" rule runs only once the whole list is in hand, gathered per
  sender (`PendingListed`); a continuation without its first chunk changes nothing. Older
  receivers ignore the flags. Tests:
  `chunked_topology_clears_unlisted_hears_us_only_after_last_chunk`,
  `large_neighbourhood_splits_into_flagged_chunks`.
- **A publisher that goes quiet loses our direct link.** A node whose lists we accept promises
  one every `TOPOLOGY_BROADCAST_MS`; heard nothing at all from it for `PUBLISHER_SILENCE_MS` (two
  intervals, the same silence horizon as `TOPOLOGY_RESYNC_MS`) and we retract our own two edges to
  it (`NeighborGraph::prune_silent_publishers`). `NEIGHBOR_TTL_MS` is how long a topology is worth
  remembering, not how long we owe a neighbour airtime: until the edge goes, every coverage
  decision still counts that neighbour as ours to carry, so a node that has left the air draws a
  relay out of us for every frame whose sender we cannot show reached it. Only our own claim is
  retracted — the node stays in the graph, so a peer that still hears it keeps it reachable and a
  unicast for it still finds that route. Stock and legacy neighbours keep the full
  `NEIGHBOR_TTL_MS`: they promise no cadence, so their silence is not evidence. Tests:
  `a_publisher_silent_for_two_intervals_stops_being_ours_to_carry`,
  `a_silent_stock_neighbour_keeps_the_full_ttl`,
  `a_pruned_publisher_is_still_reachable_through_a_peer`,
  `a_publisher_heard_on_any_frame_stays_our_neighbour`.
- **Edge capacity.** Forty edges per node and forty graph nodes; a full edge list replaces its
  worst edge (ETX plus age) when a better one arrives (`EdgeStore::update_edge`).
- **Inferred paths.** Edges and downstream entries learned from relayed packets are priced at a
  nominal link per hop travelled (`INFERRED_LINK_RSSI`, `INFERRED_LINK_SNR` in
  `observe_relayed_packet`), never at the measured strength of the relay's link to us. A copy of a
  packet **we** transmitted teaches nothing: the peer relaying it got it from us, so recording the
  source as downstream of that peer invents a path back through ourselves, and the two nodes then
  name each other as next hop for that destination until a unicast bounces between them. Our own
  transmissions are therefore skipped (`has_our_transmission`).

## 6. Inbound policing

- Per source node and 90 s window: TEXT 30, ROUTING 10, OTHER 4, UNKNOWN 12; packets addressed to
  us and ADMIN are exempt (`NodeRateLimiter`).

## 7. Robustness

- Packet ids are a counter mixed with uptime, seeded at boot from the RNG peripheral
  (`Router::seed_tx_ids`), so no two boots or two nodes replay the same id sequence; stock
  draws random ids too. Our own-transmission record is keyed by id alone and topology receive
  no longer consults it (the sender check already excludes our own echoes).

- A panic or hard fault resets the chip (`main.rs` panic and HardFault handlers); flip-link
  places the stack below the statics so an overflow faults instead of corrupting them; a 30 s
  hardware watchdog is fed from the radio loop and from the radio-init failure loop. The boot
  log reports the reset reason. `just size nrf52840` prints sections, largest statics and
  largest stack frames; check it whenever a static or a frame grows.
- Every USB log line is written through bounded helpers (`put`, `put_u32`, `put_hex8`, and
  friends); a line that would overflow its buffer is truncated, never sliced past it.
