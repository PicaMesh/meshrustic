# MeshRustic interoperability contract

What a MeshRustic node puts on the air, how it reads what others put there, and how it times
its transmissions, stated as rules with the stock Meshtastic behaviour each rule derives from,
the MeshRustic function that implements it, and the test that pins it. Every SignalRouting node
on the mesh follows the same rules; this document is the wire and timing contract MeshRustic
holds itself to. Rules are prose; code lives in the code.

## 1. Channel access and timing

Model: every wait below is built from stock's own contention geometry — the preset's CAD slot
time and its contention window (`coordinated_relay`) — the frame airtime, and a fixed guard after
somebody else's frame: the turnaround, `PEER_TURNAROUND_MS` (250 ms) in `channel_access`. Every
SignalRouting node uses the same figures, so ladders computed independently agree.

**The turnaround is margin, not a measured deaf window.** Peers take up to about 170 ms of
per-packet processing between a frame ending and the decoded packet reaching their router, and
that figure was once read here as time off air. It is not: both radio paths re-arm the receiver
before delivering the frame upward, so a peer is listening again long before it has finished with
the frame it just took. Nothing below depends on the 170 ms figure, and each wait states what it
is actually waiting for.

- **The modem preset table is stock's, row for row.** Bandwidth, spreading factor and coding
  rate for every preset, in both the normal and wide-LoRa variants, match stock's own table
  (`mesh_radio::modem_preset_params`), and a preset stock has no case for lands on the same
  default stock gives it. This is the hardest interop surface there is: a wrong row is not a
  degraded link but no link at all, because two nodes on either side of it are not on the same
  channel. Five rows were wrong — SHORT_TURBO's wide bandwidth, LONG_TURBO and VERY_LONG_SLOW
  ungrouped, LONG_MODERATE a copy of MEDIUM_SLOW, and LONG_SLOW's coding rate — and every
  quantity below derives from them, so the error reached the symbol time, the airtime, the rung
  spacing and the slot time alike. Tests: `modem_presets_match_stock`,
  `long_moderate_is_not_medium_slow`, `long_turbo_is_not_short_turbo`.
- **The CAD slot time truncates once, where stock truncates.** Stock computes its slot time as a
  CAD duration plus a fixed propagation-and-MAC allowance and lets integer arithmetic drop the
  remainder at the end; `mesh_radio::slot_time_ms` does the same, carrying the symbol time at
  1000× and truncating only on the final division. Rounding at a different point moves the slot
  time by a millisecond at some presets, and since the contention bands are whole multiples of
  it, a one-millisecond disagreement scales into a band that no longer lines up with stock's.
  The result is pinned per preset (8, 8, 10, 12, 17, 17, 48, 28, 89, and the LONG_FAST default
  for VERY_LONG_SLOW) by `slot_time_matches_stock_at_every_preset`.
- **No frame within the turnaround after a reception.** After any received frame, or a
  transmission deferred because a frame was arriving, the node keys up no sooner than the
  turnaround or the contention backoff, whichever is longer. Implemented by
  `ChannelAccess::note_rx` and `ChannelAccess::may_transmit`; the board's radio task consults it
  before releasing router frames and passes the same verdict to `RadioSlot::service`, so a
  frame already queued in the radio cannot key up on its own. The contention half is stock's
  own per-packet `getTxDelayMsec` delay; the turnaround half is the guard above. Tests:
  `channel_access` unit tests.
- **Gap after our own frame.** At least `TX_GAP_MS` (100 ms) of silence follows each of our
  frames before the next one starts (`ChannelAccess::note_tx_done`). Stock never sends two
  frames back to back because each carries its own contention delay.
- **The broadcast ladder starts at the turnaround; unicast slot 0 starts at stock's contention
  floor.** Rung k of the SignalRouting broadcast ladder fires at `SLOT_ORIGIN_MS` plus k
  half-airtimes (`channel_access::slot_delay_ms`, used by `plan_broadcast_relay` and
  `NeighborGraph::commit_relay`). Undesignated cost-ranked unicast slot 0, and a unicast that
  names us as next hop, instead wait `coordinated_relay::relay_floor_ms` — twice `CW_MAX` slot
  times, the boundary below which no stock non-router ever transmits
  (`Router::evaluate_tx_plan`, `plan_designated_unicast`). The two answer different questions and
  had been sharing one value by accident: a unicast relay that keyed up earlier than the floor
  would go out while a stock neighbour was still inside its own contention window, so that
  neighbour could not have heard our copy, would not cancel its own, and the duplicate we were
  avoiding would happen anyway. Both figures derive from quantities every SignalRouting node
  computes identically, so the broadcast ladder's rung order agrees at every preset. Tests:
  `sr_slot_schedule`, `broadcast_relay` unit tests,
  `undesignated_unicast_slot_zero_waits_stocks_contention_floor`.
- **Two floors keep rungs apart, and both are absolute.** Rung spacing is half the packet
  airtime floored at `MIN_RUNG_SPACING_MS` (50 ms), and the tie-break range is half of that
  floored spacing, floored again at `MIN_TIE_BREAK_RANGE_MS` (20 ms)
  (`coordinated_relay::half_airtime_ms`, `tie_break_range_ms`). They are wall-clock quantities,
  not preset-derived: the range derives from the *floored* half, and deriving either from the
  slot time would cut node separation into the 5–6 ms band where colocated nodes stop hearing
  each other in time to cancel. The invariant that the range never reaches the spacing is pinned
  at every preset and frame length by `tie_break_range_stays_below_rung_spacing_everywhere`.
- **Every rung carries a strictly positive tie-break.** `coordinated_relay::slot_tie_break_ms`
  adds 1 to `tie_break_range_ms` milliseconds, deterministic per packet id and node id, applied
  once where a relay is committed (`NeighborGraph::commit_relay`) so that a ranked rung, a
  sole-candidate relay and an acknowledgement all get it. It is never zero and never negative:
  zero is what let two nodes key up together — all 38 measured broadcast doubles were separated
  only by this offset, mean 6.55 ms — and a signed offset could pull a rung in front of its own
  slot. The full contention delay was applied here once and randomised the rung order outright,
  which is how two colocated nodes in rungs 1 and 4 ended up 50 ms apart.
- **Waiting for a designated SR next hop.** Before acting in its place, a candidate waits the
  turnaround plus the peer's maximum contention delay plus one airtime
  (`channel_access::peer_relay_wait_ms`, via `Router::sr_peer_relay_wait_ms`). For a stock next
  hop the wait is stock's worst-case delay plus one airtime (`tx_delay_ms_worst`).
- **Waiting for a destination's ACK.** When we heard the frame straight from its source and the
  source's topology lists the destination as hearing it, every relay candidate first waits the
  turnaround plus twice the maximum contention delay plus the ACK airtime
  (`channel_access::dest_ack_wait_ms`, via `Router::dest_ack_wait_ms`); a reply heard cancels the
  queued relay (`Router::perhaps_cancel_dupe`). Tests:
  `peer_waits_derive_from_the_turnaround`, `dest_ack_wait_includes_processing_allowance`.
- **Unicast waits are floors on one instant, so they compose by `max`.** The contention floor,
  the destination's ACK wait and the wait for a leader's copy to leave the air are all measured
  from the frame we just heard, and each says "not before this". The applicable ones are combined
  by taking the largest, never by adding: waiting for the destination's answer already carries us
  well past stock's contention boundary, and summing the two delayed every relay on a confirmed
  link by a whole contention window — 448 ms at LONG_FAST — for nothing. Rung spacing is then
  added *on top of* the surviving floor rather than folded into the comparison, because a floor
  large enough to swallow the spacing would drop two adjacent rungs onto the same millisecond.
  Test: `the_destination_ack_wait_absorbs_the_contention_floor_rather_than_stacking`.

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

- **Link cost is priced from decode margin, not from absolute signal strength.** `calculate_etx`
  takes the modem preset in force (`NeighborGraph::modem_preset`, itself a mirror of the stored LoRa
  config) along with the observed RSSI and SNR. A LoRa frame decodes when SNR clears the
  demodulator's minimum for the spreading factor in use — a datasheet figure that runs from about
  -7.5 dB at the fastest preset's spreading factor to about -20 dB at the slowest — so the curve's
  dominant term is *decode margin*, the reported SNR minus that preset's threshold: deeply negative
  margin prices a link near the curve's floor regardless of RSSI, margin at the threshold itself
  prices a link as marginal, and margin a few dB above it saturates the price near its best. RSSI
  contributes only a second, much narrower term — a mild, monotonic shading for capture effect,
  interference margin and estimate confidence at very weak absolute signal strength — never enough
  on its own to move a link across the coverage ceiling except in a narrow band right at the
  crossover. A reported SNR that is not finite (a corrupted reading) is priced as though it were far
  below every preset's threshold, not passed through: the curve is total for every
  `(modem_preset, rssi, snr)`, including non-finite and out-of-range inputs. ETX is still the
  reciprocal of the resulting delivery probability, stored at the same fixed-point scale
  (`ETX_MIN_FIXED`, `ETX_MAX_FIXED`) as before; only the function of `(rssi, snr, modem_preset)` that
  produces it changed. `etx_to_signal` is the inverse used only by its own round-trip test — no
  production path calls it — and, since an ETX alone cannot say how much of it was RSSI and how much
  was margin, it reports a fixed representative RSSI and recovers SNR as the preset's threshold plus
  the recovered margin.
  `COVERAGE_ETX_CEILING_FIXED` is unchanged by this: recalibrating the curve changes which
  `(modem_preset, rssi, snr)` triples clear it, which is the point, not the ceiling itself.
  `OWNER_COST_BUCKET_FIXED`/`COST_BUCKET_FIXED` (§3b's cost buckets) and `broadcast_relay`'s own
  `BIDI_ETX_CEILING`, which gates a candidate's bidirectional-priority tier, are unchanged too — the
  new curve's own worst output still sits well below `BIDI_ETX_CEILING`, so it still excludes the
  same worst-case links from that tier. The wire format carries raw RSSI/SNR
  per neighbour, never ETX, so this is a local scoring change only: old and new firmware keep
  exchanging topology correctly and disagree only on the price each puts on it, until every node in a
  branch runs the recalibrated curve.
- **Every healthy link now prices into one cost bucket, and that is accepted, not a defect.** Once
  decode margin reaches the curve's saturation point, every stronger reading — more margin, more
  RSSI, both — moves the price by only a few hundredths of an ETX, so at a fast preset every link
  with a comfortable margin lands within a single `COST_BUCKET_FIXED`/`OWNER_COST_BUCKET_FIXED`
  bucket regardless of how much better one is than another. Two consequences follow, and only one of
  them is left as-is. Ranking among these links falls through to the node-id tie-break, which is the
  intended behaviour of a bucketed comparison, not a symptom: ETX means expected transmissions, and a
  link with 20 dB of margin and one with 10 dB both deliver on essentially the first try, so pricing
  them alike is the curve being honest, not imprecise — the old curve's spread across that same
  range was false precision the recalibration exists to remove. Cost is only the secondary ranking
  key behind unique coverage, and the discrimination that actually matters operationally — healthy,
  marginal, and hopeless — is exactly what the margin curve's shape is built to preserve; nothing
  here is remediated, and re-spreading the curve to manufacture ranking differences among healthy
  links would reintroduce the false precision this change removes.
  The second consequence is assessed separately: `EdgeStore`'s `etx_change_threshold` is a relative
  comparison, and a change confined to the saturated band moves the ratio by less than its 1.2
  trigger, so `mark_topology_dirty` is not called and `topology_dirty_send` stays unset for it — the
  change reaches peers only on the next periodic broadcast (`TOPOLOGY_BROADCAST_MS`, 600 s) rather
  than being pushed out early. This is judged immaterial: a change too small to cross a cost bucket
  can never change which candidate leads a coverage or ownership ranking, so a peer still costing the
  edge at its last-known-healthy value for up to one broadcast interval reaches the same routing
  decisions it would have reached with the update in hand immediately. Not remediated, for the same
  reason the ranking consequence is not: `etx_change_threshold` stays untouched.
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
  its copy. Slot 0 waits the largest floor that applies to it — stock's own contention floor
  (`coordinated_relay::relay_floor_ms`), or the destination's ACK wait where that is longer;
  later slots take the larger of that floor and the leader's peer relay window, then space by
  half an airtime. Tests:
  `undesignated_unicast_defers_to_the_neighbour_that_reaches_the_destination`,
  `undesignated_unicast_slot_zero_waits_stocks_contention_floor`.
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
  candidate shifts one slot behind the peer or stock wait (`plan_designated_unicast`). When the
  designated hop is us we take slot 0 at the largest floor in force, not at once. The
  reservation others wait out is how long until that node's copy has left the air, and the two
  cases start their clocks in different places: an **SR** peer obeys this same model, so it keys
  up at the floor and needs its own contention delay plus one airtime *on top of* it; a **stock**
  node knows nothing of the floor and starts contending the moment it hears the frame, so its
  copy is clear after its own worst case plus one airtime, and the floor only applies as a lower
  bound. Adding the floor to the stock case would count the same silence twice. Ranking `Err`
  does not abort that backup. Forward and backup TX stamp **our path** next hop; flood
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
  at the coverage ceiling**: a link past `COVERAGE_ETX_CEILING_FIXED` (the curve's own floor
  included) delivers nothing, so its holder owns nothing and the neighbour is simply
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
  else.** Deferring arms it on one condition, known at that moment:
  a rung was given out — `BroadcastRelayPlan::slots_given > 0`, i.e. a stock relay router, a
  ranked SR peer, or an answerer ahead of us in the acknowledgement pass is expected to
  transmit, so if their copy never comes ours is the redundancy that covers the loss.
  No rung given means no transmission is expected and nobody is waiting to be told
  (`SrSkipReason::AlreadyCovered`, logged as `no rung given, nothing expected`). A rung given
  is logged by kind — a reserved stock router (`SrSkipReason::RouterExpected`) or a ranked peer
  (`SrSkipReason::BetterNeighbor`) — because one is an expectation we cannot coordinate with and
  the other is one we can, and merging them makes the reservation's effect invisible in a
  capture. Measured over 30 min on three field nodes (2026-09-08): declining the rest costs
  about 100 copies per node and cut T1 traffic roughly tenfold, while delivery between two
  colocated nodes was unchanged (3.2% asymmetric ids with it, 2.9% without).
  **The `want_ack` witness election is gone.** It armed T1 whenever a frame carrying `want_ack`
  arrived straight from its originator and an election named us its answerer. Stock strips
  `want_ack` from every broadcast before it reaches the air — 0 of 83,727 broadcast receptions
  carry the flag — so the term could never fire on the wire, and the need behind it is served by
  the acknowledgement pass below, which does not depend on the flag.
  **The insurance copy carries no `want_ack` of its own** (`Header::clear_want_ack`, applied
  where T1 snapshots the frame rather than in the shared relay builder). A copy that kept the
  flag would invite the far side to start its own reply ladder over a frame we sent only as
  redundancy.
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
  `ranked_broadcast_slot_does_not_arm_t1`.
- **When the ladder comes out empty, somebody still answers** (`plan_acknowledgement`,
  `RelayReason::Acknowledgement`). The ranking drops every candidate with no unique coverage,
  because the cost it ranks on is the mean delivery cost over the unique targets and an empty
  target set has nothing to price. A fully-covered broadcast therefore earns no transmission at
  all — which is correct for coverage and wrong for the sender, because the only delivery
  confirmation stock has for a broadcast is hearing somebody rebroadcast it. Suppressing every
  copy removes the signal its retry ladder waits on, so it retransmits into silence and the
  phone reports a failure for a message that in fact arrived everywhere.
  So a second pass runs, with its own price, only when the first left the ladder empty and
  nothing was reserved. **Scope**: a text broadcast that reached us straight from its originator
  (`is_direct_packet` — hop budget and relay byte both), decided at the router where the portnum
  and header are known. A frame that arrived relayed was rebroadcast by definition, so its
  originator already has its confirmation.
  **Direction**: the opposite of coverage. Coverage asks whether a relay reaches a target; an
  acknowledgement asks whether the *originator* hears the relay, because a copy it cannot hear
  tells it nothing. `route::acknowledgement_price_fixed` therefore demands positive,
  one-directional evidence — the source's own list naming the candidate, or us watching the
  source's traffic carried by it — prices it as the source would measure it, and refuses a
  guessed link or one past `COVERAGE_ETX_CEILING_FIXED`. The symmetric test would not do: a
  direct observation writes both edge directions from one measurement, and symmetry is the one
  thing an acknowledgement may not assume.
  **Candidates** are ourselves plus the neighbours we can hear that are SR-active or immediate
  relay routers and have a price, ordered by that price in `COST_BUCKET_FIXED` buckets, then by
  packet-id parity and node id so the work rotates across packets instead of always falling to
  the same node. Rungs start at `SLOT_ORIGIN_MS` and space by half an airtime; a rung ahead of
  ours counts toward `slots_given`, so T1 insures an answer that never comes.
  **We stand down** for a neighbour that will rebroadcast regardless and will not cancel for us
  (`Capability::will_not_cancel_for_us`, stock ROUTER and ROUTER_LATE) when it can hear the
  transmitter: its copy is already the acknowledgement. A stock CLIENT is deliberately not such
  a node — it floods later than our rung and cancels on hearing us, so answering first removes
  its copy rather than adding to ours. Tests: `somebody_answers_when_the_ladder_is_empty`,
  `the_source_hears_the_first_answerer_best`, `reservation_and_rung_are_counted_apart`.

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
- **Coverage decides a committed relay's cancel; our role decides everything else.** The two
  gates answer different questions. Coverage is about the packet — the neighbours we would have
  carried have been carried by somebody else, so our copy would add a duplicate and nothing
  more. `NeighborGraph::role_allows_canceling_dupe` is about the node — whether a router may
  fall silent for reasons of its own — and stock keeps ROUTER and ROUTER_LATE rebroadcasting
  through duplicates on purpose. For a relay *we* committed to under the coverage model,
  coverage wins: the frame may still be pullable out of the radio queue, and a covered relay
  that goes out anyway is a duplicate we chose. Without this a node configured ROUTER or
  ROUTER_LATE cancelled its insurance and then transmitted regardless. Traffic we never
  committed to keeps stock's behaviour for our role unchanged. Tests:
  `coverage_cancels_a_committed_relay_whatever_our_role`,
  `role_still_governs_traffic_we_did_not_commit_to`.

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
- **Three ways a neighbour proves it hears us, one definition.** Its topology list names us; we
  watch it carry a frame of ours; or a frame of its own reaches us **direct** and names our byte
  as its next hop. The third is new: a next hop is learned from traffic received, so a peer could
  only have chosen to route through us by hearing us. All three go through
  `NeighborGraph::confirm_direct_neighbor_hears_us`, which reports whether the flag actually
  changed. It must be a direct frame — on a relayed one the next-hop byte was stamped by the
  relayer and says nothing about the originator — and never a broadcast, where the field carries
  no designation. Without this a reply to a neighbour whose list has not reached us yet cannot be
  framed as a last hop, so it goes out with a spare hop and gets relayed: field 2026-09-08, a
  traceroute reply to a neighbour 47 dB down was carried by two further relays because its
  requester had rebooted and had not yet published a list naming us. Tests:
  `a_direct_frame_routed_through_us_proves_the_sender_hears_us`,
  `a_relayed_frame_naming_us_proves_nothing_about_its_sender`.
- **Three classes of edge, and only two of them are evidence.** An edge is `Reported` (we
  measured it ourselves), `Mirrored` (a peer published a measurement of one of its own links) or
  `Inferred` (nobody measured it: we minted it because a relayed frame crossed the link, priced at
  `INFERRED_LINK_RSSI`/`INFERRED_LINK_SNR` per hop travelled). The classes rank in that order and
  a weaker one never displaces a stronger one, whichever arrives last — neither by overwriting it
  (`EdgeStore::update_edge`) nor by evicting it from a full edge list. Before this rule a single
  relayed frame repriced a link its own gateway had published as hopeless, from ETX 15.9 to the
  nominal 1.57, and two nodes holding identical reports disagreed about coverage according to
  which relayed frames each had happened to hear.
- **Coverage is priced on measurements only; reachability may use a guess.** `hop_cost_fixed`
  skips `Inferred` edges and returns no price when only a guess exists, so `covers`,
  `coverage_owner`, `acknowledgement_price_fixed` and both slot rankings (through
  `delivery_hop_cost_fixed`)
  refuse to let a guess excuse a transmission — no price means no coverage, which means we relay.
  The route search prices its own hops straight from the edges and still travels over an inferred
  edge, which is the one thing inferring an edge is for. A candidate's coverage set is likewise
  what that candidate published, and for ourselves what we publish: `Inferred` edges are in
  nobody's set, in the ranking, in absorb and in the dupe-cancel path alike.
- **A link we invent is only ever a link nobody will publish.** A relayed frame teaches an edge
  `gateway → source` only when the gateway is a stock (`Legacy`) node or an unresolved
  placeholder. The gateway is the sole node that can publish that edge, so inventing one for a
  gateway that publishes topology overwrote what it had already told us. Reachability learned from
  relayed frames lives in the downstream table, which is gated separately, on the source and the
  hop count, because no publisher supplies it.
- **The reverse direction of our own measurement is an assumption, not a measurement.** Observing
  a neighbour writes `us → neighbour` as `Reported` and `neighbour → us` as `Inferred`: we cannot
  measure how well it hears us. Recorded as `Reported` it outranked and permanently blocked the
  neighbour's own published measurement of us, and priced our link from our own guess while every
  peer priced it from our published list, so each node credited itself with more coverage than any
  peer credited it with. Our direct-neighbour count is therefore the set we measured and publish,
  not the set that holds an edge back to us.
- **Noting that a node is alive never creates a graph node for it.** A relayed frame proves the
  source exists, not that we know a link to it. `update_node_activity` refreshes an existing node
  only: creating an edgeless one meant the next maintenance pass removed it and, with it, every
  peer's published edge pointing at it, which returned only on that peer's next broadcast. Field
  2026-09-08: about a hundred aging passes in 45 minutes on a graph that never changed size, and a
  gateway's coverage set wandering packet to packet.
- **A complete list is authoritative about the sender's own edges, not only about `hears_us`.**
  When the last chunk of a non-empty list is in hand, edges from that sender to nodes the list no
  longer names are removed (`EdgeStore::retain_listed_edges`), leaving our own measurements and
  placeholders alone. Before this, an entry a rebooted peer had dropped stayed in its coverage set
  until `NEIGHBOR_TTL_MS`.
- **A publisher that goes quiet loses our direct link.** A node whose lists we accept promises
  one every `TOPOLOGY_BROADCAST_MS`; heard nothing at all from it for `PUBLISHER_SILENCE_MS` (two
  intervals, the same silence horizon as `TOPOLOGY_RESYNC_MS`) and we retract our own two edges to
  it (`NeighborGraph::prune_silent_publishers`). `NEIGHBOR_TTL_MS` is how long a topology is worth
  remembering, not how long we owe a neighbour airtime: until the edge goes, every coverage
  decision still counts that neighbour as ours to carry, so a node that has left the air draws a
  relay out of us for every frame whose sender we cannot show reached it. Only our own claim is
  retracted — the node stays in the graph, so a peer that still hears it keeps it reachable and a
  unicast for it still finds that route. **Coverage goes further than our own edge**: past the
  same horizon the node is nobody's coverage target (`route::is_silent_publisher`, applied inside
  `admits_coverage`, and in `unique_coverage_neighbor` so the cancel path follows the same rule
  the ranking used; test `cancel_path_applies_the_silence_rule`). A peer's published
  edge to it outlives our retraction by up to a broadcast interval, so without that every node
  credits its peers with covering a node that has gone — and each of those peers, having retracted
  it under the same rule, declines the slot it was handed. Field 2026-09-08: the branch gateway
  died, and both desk nodes then handed 95% of frames to a peer for a node none of them still
  reached, leaving the insurance to carry everything three seconds late. The judgement is on when
  we last heard the node itself, not on a peer naming it in a list; hearing it again restores it.
  Stock and legacy neighbours keep the full
  `NEIGHBOR_TTL_MS`: they promise no cadence, so their silence is not evidence. Tests:
  `a_publisher_we_stopped_hearing_is_nobody_s_target`,
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
