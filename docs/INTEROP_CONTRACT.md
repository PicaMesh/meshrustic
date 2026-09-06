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
  `plan_broadcast_relay` and `NeighborGraph::commit_relay`). All SignalRouting nodes share the
  origin, so slot order agrees at every preset. Tests:
  `sr_slot_schedule`, `broadcast_relay` unit tests.
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
  Replies (`Router::response_hop_limit`) use stock's hops-used-plus-margin rule from
  `hop_limit_for_response`, capped to 0 (1 on a marginal link) when the requester is a direct
  neighbour that hears us, stock neighbours are present, and the request itself arrived direct;
  a request that reached us through a relay keeps its reply's hop budget. Tests:
  `reply_to_direct_hearing_neighbour_is_hop_limited_when_stock_nodes_are_around`.
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
  response whose hop count it does not know. The Meshtastic Android app goes further and shows a
  zero-`hop_start` traceroute reply only when the bitfield word is nonzero, which is why the
  MQTT bit defaults on. A frame we re-encode for relay keeps the origin's word verbatim
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

- **An edge is one-directional evidence.** A node listing a neighbour says it hears that
  neighbour. A route hop from A to B needs B to hear A: A's edge to B carries `hears_us`, or B
  lists A. A node that publishes topology and confirms neither does not hear A and is never
  routed through that hop; a node that publishes none (stock, unclassified) cannot be ruled out
  (`route::can_deliver`, applied in `calculate_route` and `find_better_positioned_neighbor`).
  Test: `one_way_edge_is_not_a_route`.
- **A next hop equal to the destination's byte names no relayer.** Stock's `NextHopRouter`
  learns the destination itself as next hop from a direct reply. Such a unicast is planned as one
  with no next hop: the cost ranking decides, nobody owns slot 0 (`Router::evaluate_tx_plan`,
  `relayer_named`). Test: `next_hop_equal_to_the_destination_names_no_relayer`.

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
  then a repeat or a forward move of 1 to 127; a header-only version-0 direct broadcast resets the
  tracked version, active or passive sender; after `TOPOLOGY_RESYNC_MS` without an accepted
  report, any version is taken as the new base. Tests: `peer_boot_broadcast_resets_its_topology_version`,
  `passive_peer_boot_broadcast_resets_its_topology_version_too`,
  `peer_topology_resyncs_after_two_silent_intervals`.
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

- A panic or hard fault resets the chip (`main.rs` panic and HardFault handlers); flip-link
  places the stack below the statics so an overflow faults instead of corrupting them; a 30 s
  hardware watchdog is fed from the radio loop and from the radio-init failure loop. The boot
  log reports the reset reason. `just size nrf52840` prints sections, largest statics and
  largest stack frames; check it whenever a static or a frame grows.
- Every USB log line is written through bounded helpers (`put`, `put_u32`, `put_hex8`, and
  friends); a line that would overflow its buffer is truncated, never sliced past it.
