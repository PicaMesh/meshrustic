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
  Broadcast absorb, pre-cover and unique-coverage cancel use `route::known_to_hear` only
  (confirmed `hears_us` or reverse list), so mute or silent neighbours are not counted as
  covered. Shared helpers: `delivery_hop_cost_fixed`. Tests: `can_deliver_*`,
  `known_to_hear_ignores_stock_optimism`, `one_way_list_to_publishing_dest_is_not_a_direct_path`.
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
- **Next hop is the relayer.** If our path next hop is the node we heard from, we drop the
  relay only when that node can finish delivery to the destination (`can_deliver` or
  downstream). Otherwise the next hop is cleared and we stay in the ranking as backup. Tests:
  `unicast_not_relayed_back_to_the_relayer`, `next_hop_is_relayer_clears_when_they_cannot_finish`.
- **Designated next hop and backup.** A wire next hop that is not us owns slot 0; every other
  candidate shifts one slot behind the peer or stock wait (`plan_designated_unicast`). Ranking
  `Err` does not abort that backup. Forward and backup TX stamp **our path** next hop; flood
  (`next_hop = 0`) only on the last relayed `want_ack` retry. Tests:
  `unicast_designated_*`, `designated_hop_backup_survives_ranking_skip`,
  `forwarded_want_ack_unicast_is_retried_then_released_to_flooding`.

## 3b. Broadcast relay and T1

- **Unique coverage owns a slot.** A broadcast relay slot is taken when we still uniquely reach
  a neighbour that the transmitter and earlier coverers do not (`known_to_hear`). Otherwise we
  take no ranked slot. Pending later slots cancel when unique coverage is gone
  (`has_unique_coverage` / `perhaps_cancel_dupe`). Tests: broadcast coverage cases in
  `broadcast_relay` / `sr_slot_schedule` / `sr_coverage`.
- **T1 is no-slot insurance, not a second coverage path.** When we defer with no ranked slot
  (`BetterNeighbor`), we arm T1 so that if nobody retransmits, a late copy still reaches the
  source for confirmation (`arm_t1_for_deferred_broadcast`). A ranked commit never arms T1.
  Any heard rebroadcast cancels T1; T1 never fires if we already recorded our own transmission.
  Originator T1 in `send_local` remains a separate “did anyone rebroadcast?” timer with the same
  cancel-on-rebroadcast helpers. Tests: `t1_retransmit_fires_after_defer_window`,
  `ranked_broadcast_slot_does_not_arm_t1`.

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
- **Edge capacity.** Forty edges per node and forty graph nodes; a full edge list replaces its
  worst edge (ETX plus age) when a better one arrives (`EdgeStore::update_edge`).
- **Inferred paths.** Edges and downstream entries learned from relayed packets are priced at a
  nominal link per hop travelled (`INFERRED_LINK_RSSI`, `INFERRED_LINK_SNR` in
  `observe_relayed_packet`), never at the measured strength of the relay's link to us.

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
