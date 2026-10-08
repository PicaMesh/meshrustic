# Graph horizon plan: priced edges to L2/L3, downstream beyond

Status: **MeshRustic Phases 1–4 + L3-on (Phase 6) on `graph-horizon`**. Fork port / size (Phase 5) and INTEROP (Phase 7) still open. When behaviour is stable across both trees, fold the normative parts into [`INTEROP_CONTRACT.md`](INTEROP_CONTRACT.md) §3a / §5 and keep this file as the work plan + rationale.

Applies to **MeshRustic** (`crates/mesh-routing`) and the **MT+SR fork** (`NeighborGraph` / `SignalRoutingModule`) in lockstep. Implementers must use **git worktrees** (§10); do not hack this on the primary Lab checkouts.

---

## 1. Problem

Verified multi-hop ETX needs a **receiver-priced edge graph**. Today:

- On-air topology is **direct neighbours only** (correct).
- Routing mixes **EdgeStore + downstream + Dijkstra**, but far destinations often collapse to a **single downstream spine** (`hops: 0, unverified`), so path ETX does not arbitrate among real alternatives.
- Publisher slots and create-gates under-retain **second-hop** lists, so chains like Dura→Czar→FCM6→… never become a verified sum even when traceroute works.

We need an explicit **horizon**: price a shallow ball of published links, park everything else behind a frontier gateway, and stop pretending Dijkstra over the whole city.

---

## 2. Goals

1. **Edge ball** holds us, our RF neighbours (L1), nodes that hear L1 but are not our neighbours (L2), and optionally nodes that hear L2 but are not L1/L2 (L3) — as **undifferentiated** EdgeStore publishers (no separate “L1 table” vs “L2 table”).
2. Prefer **L2→L1** (and **L3→L2**) edges from the **hearing node’s own list**: that node knows whom it can hear.
3. Treat **neighbours of the outermost priced publishers** (with `hearsUs=1`) as **downstream through that publisher**, enabling **~3-hop priced paths** (edges through the ball + one list-priced last hop).
4. Any originator **not** in the edge ball, learned only from a relayed frame, becomes **downstream of the peer that relayed to us**. **No Dijkstra** for those destinations — hand the frame to that gateway (or the hearable hop on a short chain to it).
5. Fit **nRF52840-class RAM** (~256 KB SRAM; SoftDevice may leave ~224 KB). Prefer reshaping existing tables over 900 full node records.
6. Ship MeshRustic + fork with matching semantics and tests.

## 3. Non-goals

- City-wide SPF or unbounded graph growth.
- Protocol change to embed multi-hop lists in topology packets (interop stays: each node still publishes **only its RF neighbours**).
- Moving the hot graph to external / QSPI flash.
- Using extra flash on SenseCAP Solar Node as a substitute for SRAM.
- Driving Mesh Lab off-limits nodes (`inno`, personal Dura via harness) as part of this work.

---

## 4. Definitions

| Label | Meaning | How we learn them |
|---|---|---|
| **L0** | Us | Local id |
| **L1** | Our RF neighbours | `Reported` `us → N` from direct air frames |
| **L2** | Nodes that **hear at least one L1**, and are **not** L1 | Prefer: **L2’s topology lists an L1**. Bootstrap / corroboration: L1 lists L2 with `hearsUs=1` (L1 claims L2 hears them) |
| **L3** | Nodes that **hear at least one L2**, and are **not** L1/L2 | Prefer: **L3’s topology lists an L2**. Optional phase; same pattern as L2 |
| **Edge ball** | All EdgeStore publisher slots we keep for Dijkstra | L0 + L1 + L2 (+ L3 if enabled) |
| **Frontier publisher** | Outermost ball node whose further listed peers we refuse as new publishers | Typically L2 if L3 off; L3 if L3 on |
| **List-downstream** | Destinations from a frontier (or any ball) publisher’s list with `hearsUs=1` that we do **not** promote into the ball | `dest via publisher`, cost = publisher’s measured ETX |
| **Orphan** | Node not in the ball and not list-downstream of a ball publisher | Learned from relayed RX; `dest via RF gateway peer` |

**Hop labels are admission / eviction metadata only.** Dijkstra does not branch on “L1 vs L2”; it only sees edges.

**Topology dump:** the periodic Network Topology log tags each ball node `[L1]` / `[L2]` / `[L3]` / `[L?]` and prints a header census `(L1=a L2=b L3=c)`. List-downstream and orphan rows stay `[downstream]` — they are not ball class.

### 4.1 Evidence preference (critical)

For a link between ball node A and ball node B:

| Prefer | Why |
|---|---|
| **B→A from B’s list** when B reports hearing A | B measured A’s signal; correct receiver price for hop A→B in backward Dijkstra |
| L1→L2 from L1’s list | Useful to **discover** L2 and to price hops when L2’s list is not yet ingested |
| When both exist | **Hearing node’s list wins** on that directed edge (Mirrored from the hearer’s report outranks the reverse claim for that direction). Do not let L1’s guess of “L2 hears me” permanently block L2’s own `L2→L1` measurement |

Same rule for L3→L2 vs L2→L3.

### 4.2 `hearsUs=1`

Keep the existing meaning: on a publisher’s list entry for X, `hearsUs` means **X has been shown to hear the publisher** (TX path publisher→X is credible).

- List-downstream rows require `hearsUs=1` (already the merge gate for parking listed non-neighbours).
- Sticky `hearsUs` alone is not live coverage; **list freshness / TTL / cost** still apply when stamping or ranking.

---

## 5. Target routing behaviour

### 5.1 `calculate_route` modes

```
1. Destination in EdgeStore (or reachable by strict/fallback Dijkstra on ball edges)
   → backward Dijkstra as today (strict, then optional unverified reverse into publishers).

2. Destination is list-downstream of ball node M (Y via M, hearsUs-gated when learned)
   → Dijkstra to M (must succeed on ball edges).
   → next_hop = first hop toward M.
   → cost_fixed ≈ path(us→…→M) + cost(M→Y) from the downstream row (M’s list ETX).
   → verified = true when path us→…→M is strict-verified **and** M→Y was learned from M’s
     topology with `hearsUs=1` (M reports Y hears M). Otherwise false.

3. Destination is orphan (F via G)
   → Do NOT run Dijkstra toward F.
   → next_hop = G if G is an L1 neighbour we hear; else chain_egress until hearable peer.
   → verified = false.
   → Delivery delegated to that peer’s better local knowledge.
```

Inbound-gateway fallback (penalised reverse into publishers) remains last resort when (1) and (2) fail; it must not override a live orphan or list-downstream parent without policy.

### 5.2 Unicast / relay implications

- **Stamping:** list-downstream behind reachable M may stamp next hop toward M (same family as today’s stamped downstream chain). Orphans: do not stamp a guessed deep path; gateway handoff only.
- **Coverage / ranking:** ball edges and `covers` / `can_deliver` unchanged in spirit; orphans do not invent coverage of F via Dijkstra.
- **Sticky downstream + publisher must list relay** (recent MeshRustic/fork fix) stays for **orphan / relayed inference**. List-downstream from topo merge uses list+`hearsUs` authority instead.

### 5.3 What we publish on air

Unchanged: **only our L1 list**. Horizon is a **local** retention policy. Peers may run older firmware; we must not require them to publish L2/L3.

---

## 6. Topology ingest

### 6.1 Sources

| Source | When accepted | Effect |
|---|---|---|
| Direct RF topology from L1 | Always (existing) | Mirror L1→listed; bootstrap L2 candidates via `hearsUs`; list-downstream for listed non-ball nodes with `hearsUs` if not promoting |
| Topology from L2 (RF-direct or **accepted non-neighbour ingest**) | Sender qualifies as L2 (lists ≥1 L1, or already tagged L2) | Prefer writing **L2→listed** Mirrored edges for listed L1 (and other ball nodes). Promote listed L3 candidates if L3 enabled. Non-promoted listed with `hearsUs` → list-downstream via L2 |
| Topology from L3 | Optional phase; sender lists ≥1 L2 | Same pattern one hop further |
| Relayed data frames | Existing observe path | Orphan / sticky downstream only if originator ∉ ball |

### 6.2 Non-neighbour topology ingest (required for preferred L2→L1)

L2 often is **not** RF-adjacent. To prefer L2→L1 we must accept L2’s topology when we can trust it:

**Proposed acceptance (implement behind a clear gate):**

1. Frame is a topology report from sender S.
2. S is not L1 (no `Reported us→S`), **or** S is L1 (then normal path).
3. S is allowed if:
   - S already in ball as L2/L3, **or**
   - S’s list (this report) names ≥1 of our L1 with a credible entry (S reports hearing L1), **or**
   - an L1 lists S with `hearsUs=1` (bootstrap before first S list).
4. RF path: accept **both** direct RX of S’s topology **and** topology received **via an L1 relay**, when S qualifies under (3). Relayed ingest must authenticate S’s payload (same crypto/channel as today) and record `heard_via` (parent L1) for TTL / demotion. Do **not** invent edges from the relay’s SNR to S’s neighbours — only S’s listed measurements.

**Passive / CLIENT roles:** today passive nodes skip some non-direct merges — revisit so **phone-class routers that run SR** still build L2 lists; mute/passive non-routers may keep a thinner ball.

### 6.3 Edge write priority on merge

For each listed neighbour X of sender S:

1. If S ∈ ball and X ∈ ball (or X is L0): `update_edge(S→X)` from S’s measurement (**preferred directed evidence**).
2. If S ∈ ball, X ∉ ball, `hearsUs`, and X should not be promoted: `downstream.update(X, relay=S, cost=etx)`.
3. If S ∈ ball, X ∉ ball, promotion rules say X becomes L2/L3: create publisher slot for X only after admission; still write S→X.
4. Never grow publishers past configured max depth (L2-only vs L3-enabled).

Bootstrap from L1 list before L2 list exists:

- L1 lists L2 with `hearsUs` → admit L2 identity; write L1→L2; **do not** treat L1→L2 as permanent winner over a later L2→L1.

### 6.4 Authoritative retain

Complete list from S still **`retain_listed_edges`** for S’s own outgoing edges (existing rule). L2 silence / parent loss demotes L2 (see §8).

---

## 7. Data structures and memory

### 7.1 Keep (reshape, don’t replace)

| Structure | Role after change |
|---|---|
| `EdgeStore` / per-node edge arrays | Entire **edge ball** (L1+L2(+L3)); undifferentiated |
| `DownstreamTable` | **List-downstream** + **orphans** only (shrink default cap if ball grows) |
| Dijkstra scratch | Sized to `MAX_GRAPH_NODES` |
| Pending multi-chunk lists | Per sender (already multi-slot); must cover L2/L3 senders |

### 7.2 Add

| Addition | Purpose |
|---|---|
| **Hop / class tag** per graph node (or side array) | `L1 / L2 / L3 / Unknown` for admission and eviction — not for Dijkstra math |
| **Parent / reachability hint** (optional) | e.g. which L1 makes this L2 reachable; for TTL demotion |
| **Route mode** in logs / `Route` | e.g. `Ball` / `ListDownstream` / `OrphanGateway` for field debug |

### 7.3 Capacity targets (nRF52840)

Start from MeshRustic’s proven static router (~80 KB class) and fork’s 32×32 heap comment.

| Knob | Suggested starting point | Notes |
|---|---|---|
| `MAX_GRAPH_NODES` | **32–40** | Not 900. Whole ball. |
| `MAX_EDGES_PER_NODE` | **32–40** | Unchanged order |
| Effective edge slots | ~**30×30 ≈ 900** | Same order as today’s downstream row count, different shape |
| `MAX_DOWNSTREAM` | **256–512** (MeshRustic may leave headroom ≤1100 during transition) | List-downstream of frontiers + orphans |
| L3 publishers | Same EdgeStore type as L1/L2 when depth=3 (recommended). Do **not** invent a hybrid “downstream with full LQ” — see §7.5 | Avoid filling 40 slots with L3 churn if depth left at 2 |

**Do not** allocate 900 `NodeEdges`. Downstream rows stay small (`destination, relay, cost, …`).

Measure with `just size nrf52840` after each phase. Fork ESP32-C3 (angl): heap check before raising 32→40; nRF52840 / Solar Node: static allocation preferred (MeshRustic pattern).

### 7.4 Alternative structures (only if needed)

- Sorted / hashed `dest → downstream` if linear scans dominate (unlikely below ~512).
- Sparse edge arena (one flat edge pool of ~900) **if** per-node arrays waste too much — larger refactor; defer until size data demands it.

### 7.5 L3: EdgeStore vs “downstream with link quality”

**Recommendation: L3 uses the same EdgeStore edge type as L1/L2** when depth=3 is enabled. Do not build a hybrid downstream row that carries full LQ.

Downstream today already stores a scalar **`cost_fixed`** (ETX×100 from the publisher’s list RSSI/SNR at merge time). It does **not** store variance, silence/`last_heard`, `EdgeSource`, or participate in Dijkstra as an intermediate.

| Approach | Pros | Cons |
|---|---|---|
| L3 as **list-downstream of L2** (existing `cost_fixed`) | Simple; one last priced hop `…→L2→L3` | L3 cannot be a Dijkstra waypoint to L3’s neighbours; weak silence/variance; second “almost-edge” type if you bolt on RSSI/SNR/variance |
| Enrich downstream with full LQ | Feels like “proper costing” | Duplicates `Edge`; still not in the Dijkstra graph unless you teach search to walk downstream — that *is* a second graph |
| L3 as **EdgeStore** (same as L1/L2) | One code path; real Dijkstra/costing; prefer L3→L2 from L3’s list | Uses publisher slots; needs eviction by class |

**List-downstream** (scalar cost + `hearsUs`) stays the right shape for nodes **beyond** the outermost ball depth (beyond L2 if depth=2, beyond L3 if depth=3), and for **orphans**.

---

## 8. Admission, eviction, TTL

### 8.1 Admit publisher

- **L1:** `Reported us→N`.
- **L2:** not L1; and (L2 lists an L1 **or** an L1 lists L2 with `hearsUs=1`).
- **L3 (optional):** not L1/L2; and (L3 lists an L2 **or** an L2 lists L3 with `hearsUs=1`).

Refuse new publishers that only appear as orphan relay sources.

### 8.2 Eviction when `node_count` full

Eviction is **demotion into downstream**, not a hard forget — when possible.

**Victim selection (first match wins):**

1. Never consider **L0 (us)** or **L1** as victims when admitting an L2/L3 (never sacrifice an RF neighbour for a deeper publisher).
2. Among remaining publishers, prefer **farthest class first**: Unknown → L3 → L2.
3. Within that class, prefer the node with the **fewest edges** (`edge_count`). Tie-break: oldest `last_full_update_ms` (then highest mean ETX if still tied).

**On evict of publisher V:**

1. Choose parent **P** = an **L1 neighbour** through which V is (or was) reachable — prefer the L1 on the best current ball path toward V, else the stored reachability/parent hint from admission, else any L1 that lists V / that V lists with `hearsUs`.
2. Write **`downstream: V via P`** with cost from the best available hop evidence (path cost to V if known, else L1’s mirrored ETX to V, else nominal). This is gateway handoff: later routes to V use orphan/list-downstream mode (§5.1), not Dijkstra through V’s old edge list.
3. **Reparent or drop** V’s former list-downstream children (`Y via V`): reparent to **P** (`Y via P`) when we still want them, else clear — do not leave dangling `via V` after V leaves EdgeStore.
4. Remove V’s `NodeEdges` slot (all of V’s ball edges go away).

If no suitable L1 parent **P** exists, refuse to admit the newcomer (or drop V without downstream) rather than inventing a parent.

**Per-node edge lists** (`MAX_EDGES_PER_NODE` full) stay as today: replace worst edge if the new one is better — no demotion to downstream for a single edge.

**Downstream table full:** replace oldest row (optional later: prefer orphans over list-downstream of a live ball parent).

### 8.3 Demotion / retract

- **Capacity demotion** (§8.2): farthest / fewest-edges publisher → `via` L1 neighbour.
- L1 lost (`retract_direct_link` / silence): recompute; L2/L3 that **only** depended on that L1 lose parent — demote to downstream behind another L1 if one remains, else clear their edges and list-downstream children.
- L2/L3 list silence: TTL; `retain_listed_edges`; children follow parent loss rules above.
- Orphan rows: existing TTL; sticky parent / L1 flip rules unchanged.

### 8.4 Edge expiry cascade (reachability prune)

When an **edge becomes inactive** (TTL / retain_listed / silence retract / explicit clear):

1. **Remove that edge** from EdgeStore.
2. Recompute which ball publishers are still **reachable from us** over remaining edges (typically: undirected for reachability walk, or “listed/mirrored path from an L1 we still hold” — implementation must match Dijkstra’s usable directions, but the invariant is: *no orphaned island in the ball*).
3. For every publisher **U** that is **no longer reachable** through any remaining path:
   - Remove **all of U’s edges** (U as `from` and edges that only existed to hold U).
   - **Demote U** to downstream behind a remaining L1 if one still makes sense (§8.2 parent pick); else drop U.
   - Reparent or clear list-downstream children that used `via U`.
4. Publishers still reachable by **another** path keep their edge lists intact — do not cascade through them.

Examples:

- Lose sole `L1a → L2`: if L2 has no other path from us (no `L1b → L2`, no other bridge), drop L2’s publisher slot and L2→* edges; demote L2 (and dependents) behind `L1a` or another L1 if appropriate.
- Lose `L1a → L2` but `L1b → L2` remains: keep L2 and its edges; only the expired edge is gone.
- Expire one edge on L2’s list (`L2 → X`) while L2 stays reachable: remove that edge only; X may remain as publisher if reachable otherwise, else demote/cascade X the same way.

Maintenance passes that already age edges / prune silent publishers must call this cascade (or share one `prune_unreachable_from_root` helper) so TTL and capacity demotion stay consistent.

### 8.5 Depth cap

Compile-time or config: `GRAPH_MAX_DEPTH = 2` (L2) or `3` (L3). Promotion past depth → list-downstream or ignore.

---

## 9. Relayed packets and orphans

When observing a relayed frame from originator F via gateway G:

1. If F ∈ ball or F is list-downstream of a ball node → do **not** orphan-steal; update activity only as today; optional refresh of existing downstream parent if list claim allows.
2. If F ∉ ball → `downstream: F via G` under existing gates (`G` hears us; publisher F must list G when F publishes; sticky parent; skip our own TX copies).
3. Routing to F uses **orphan mode** (§5.1.3): hand to G, no Dijkstra to F.

Inferred edges for placeholders remain for measurement/ranking as today; they must not expand the ball past depth policy.

---

## 10. Implementer setup — git worktrees (required)

Do **not** implement this on the primary `master` / `signal_based_routing` checkouts used for Mesh Lab and day-to-day work. Create **dedicated worktrees** before Phase 1 so Lab flashing, log analysis, and this change stay isolated.

### 10.1 Layout

Use the shared worktrees directory (create it if missing):

`/home/sebastian/work/PicaMesh/github/worktrees/`

| Tree | Repo | Suggested path | Suggested branch |
|---|---|---|---|
| **MeshRustic** | `meshrustic` | `…/worktrees/meshrustic-graph-horizon` | `graph-horizon` |
| **MT+SR fork** | `meshtastic_firmware` | `…/worktrees/meshtastic-graph-horizon` | `graph-horizon` |

Both trees are required for lockstep behaviour (Phases 1–4 in Rust first is fine; Phase 5 ports to the fork worktree). Keep this plan available in-tree or copy it:

- Source of truth: `docs/GRAPH_HORIZON_PLAN.md` on the `graph-horizon` branch (also mirrored under `tmp/` for local drafts; `tmp/` is gitignored).

### 10.2 Create the worktrees

From the primary MeshRustic clone (adjust remote/base if needed):

```bash
mkdir -p /home/sebastian/work/PicaMesh/github/worktrees

# MeshRustic
cd /home/sebastian/work/PicaMesh/github/meshrustic
git fetch origin
git worktree add -b graph-horizon \
  /home/sebastian/work/PicaMesh/github/worktrees/meshrustic-graph-horizon \
  origin/master

# MT+SR fork (primary clone path as on this machine)
cd /home/sebastian/work/mesh/meshtastic/meshtastic_firmware
git fetch origin
git worktree add -b graph-horizon \
  /home/sebastian/work/PicaMesh/github/worktrees/meshtastic-graph-horizon \
  origin/signal_based_routing
```

If `graph-horizon` already exists, use `git worktree add <path> graph-horizon` without `-b`.

Verify:

```bash
git -C /home/sebastian/work/PicaMesh/github/meshrustic worktree list
git -C /home/sebastian/work/mesh/meshtastic/meshtastic_firmware worktree list
```

### 10.3 Rules for implementers / agents

1. **All edits, builds, and tests for this feature** run inside the two worktree paths above (or successor paths named in the PR).
2. **Do not** flash Mesh Lab from the horizon worktree unless Sebastian explicitly asks; Lab stays on the primary checkouts / known-good images.
3. **Do not** merge or push until the paired MeshRustic + fork changes are ready to review together (or clearly sequenced PRs that reference each other).
4. Copy or symlink this plan into the MeshRustic worktree at start of Phase 1 if the agent only mounts that tree.
5. When finished or abandoned: remove worktrees with `git worktree remove <path>` (and delete the branch only if Sebastian asks).

### 10.4 First checklist item

Before any code change:

- [ ] MeshRustic worktree created on `graph-horizon`
- [ ] Fork worktree created on `graph-horizon`
- [ ] Plan file present in the MeshRustic worktree (`tmp/GRAPH_HORIZON_PLAN.md` or agreed path)
- [ ] Confirm `cwd` for the session is the MeshRustic worktree (fork worktree for Phase 5+)

---

## 11. Implementation phases

### Phase 0 — Spec freeze (short)

- [x] **L2 topo ingest:** both direct RX and via L1 relay (§6.2).
- [x] **`Route::verified` for list-downstream:** true when ball path to M is strict **and** M lists Y with `hearsUs=1` (M reports Y hears M). See §5.1 / §14.
- [x] Agree depth default: **`GRAPH_MAX_DEPTH = 3` (L3 on)** — superseded Phase 0’s L2-only default; see §14.
- [ ] Point this plan from README or INTEROP “work in progress” note if desired.
- [x] **Create worktrees** (§10) before Phase 1.
- [x] Plan tracked at `docs/GRAPH_HORIZON_PLAN.md`.

### Phase 1 — Horizon metadata + admission (MeshRustic worktree first)

- [x] Tag graph nodes with class / depth.
- [x] Gate `find_or_create_node` / `update_edge` create path: only L0–L2 (or L3).
- [x] Eviction by class: farthest first, fewest edges tie-break; demote victim to downstream via L1 (§8.2).
- [x] Edge expiry cascade: remove inactive edge; prune unreachable publishers’ edges; keep if alternate path (§8.4).
- [x] Unit tests: L3 demoted before L2; L1 never evicted for L3; after evict, `V via P` exists and V’s EdgeStore slot is gone; children reparented or cleared.
- [x] Unit tests: sole bridge edge expires → far publisher and its edges gone (demoted); second bridge remains → far publisher kept.

### Phase 2 — Prefer hearer’s list (L2→L1)

- [x] Accept topology from L2 under §6.2.
- [x] On L2 merge, write L2→L1 (and L2→other listed ball nodes) as authoritative Mirrored for that direction.
- [x] Ensure L1→L2 bootstrap does not block later L2→L1 (`sourceRank` / update rules).
- [x] Tests: after L2 list, backward Dijkstra prices hop using L2’s measurement of L1.

### Phase 3 — List-downstream + route composition

- [x] Frontier list entries with `hearsUs` → downstream via frontier (not new publishers past depth).
- [x] `calculate_route` mode (2): Dijkstra to M + add M→Y cost.
- [x] Logging: route mode, hops, verified (`RouteMode` on `Route`).
- [x] Tests: synthetic us–L1–L2–Y cost sum; Y not in EdgeStore as publisher.

### Phase 4 — Orphan handoff clarity

- [x] Explicit skip Dijkstra for orphan dests.
- [x] Tests: F only heard via G → next_hop G, unverified, no ball growth.
- [x] Confirm sticky / list-claim tests still pass.

### Phase 5 — Caps, size, fork port (fork worktree)

- [ ] Tune `MAX_GRAPH_NODES` / `MAX_DOWNSTREAM`; `just size nrf52840` in the **MeshRustic** worktree.
- [ ] Port Phases 1–4 to fork C++ in **`…/worktrees/meshtastic-graph-horizon`** with same tests/logs.
- [ ] ESP32-C3 heap check if caps rise.

### Phase 6 — L3

- [x] Enable depth 3 (`GRAPH_MAX_DEPTH = 3`).
- [x] Ingest L3 lists that name L2; list-downstream beyond L3.
- [ ] Field validate memory and churn on a hub.

### Phase 7 — Contract + field

- [ ] Normative text in `INTEROP_CONTRACT.md`.
- [ ] Field: Dura-class paths (e.g. toward FCM6 / MR22 / Z00x) show priced multi-hop or explicit orphan gateway — not bogus single-candidate unverified costs where the ball should apply.
- [ ] Retire obsolete comments (32×32 “can’t do 40×40” where nRF52840 static fits).

---

## 12. Test plan (minimum)

| Test | Expect |
|---|---|
| L1 list admits L2 with `hearsUs`, not as L1 | Class L2; `Reported us→L2` absent |
| L2 list writes L2→L1 preferred | Route us→L1 uses L2’s price on reverse hop as designed |
| L2 list Y with `hearsUs`, depth=3 | Y admitted as L3 publisher |
| L3 list Z with `hearsUs`, depth=3 | Z downstream of L3, not publisher |
| Route to Z | next_hop toward L3 via L1; list-downstream mode; verified when path to L3 is strict |
| Orphan F via G | next_hop G; no Dijkstra; verified false |
| Full ball | Evict L2/L3 before L1; no panic |
| L1 retract | Dependent L2 demoted; downstream via L2 cleared if unreachable |
| Sticky orphan | Relayed hearing does not steal parent without list claim |
| Passive/active role matrix | Documented merge behaviour for non-direct L2 topo |
| Fork parity | Same scenarios in C++ tests or shared golden vectors |

Reuse / extend existing suites under `boards/rpi-app/tests/` and `mesh-routing` unit tests; mirror in fork where present.

---

## 13. Files likely touched

**MeshRustic**

- `crates/mesh-routing/src/graph/mod.rs` — caps, depth constant
- `crates/mesh-routing/src/graph/edge.rs` — create gate, class tag, eviction
- `crates/mesh-routing/src/graph/downstream.rs` — unchanged API; possibly helpers for “parent in ball”
- `crates/mesh-routing/src/graph/route.rs` — route modes, list-downstream composition
- `crates/mesh-routing/src/neighbor_graph.rs` — merge_topology, observe_relayed, maintenance/TTL
- `docs/INTEROP_CONTRACT.md` — after behaviour ships
- `boards/nrf52840` — size only unless RAM layout tweaks needed

**Fork**

- `NeighborGraph.h` / `.cpp`
- `SignalRoutingModule.cpp` (merge / relayed / logging)
- Matching unit tests

---

## 14. Open decisions (resolve in Phase 0)

### Resolved

1. **L2 topology ingest path:** **both** direct RF reception of L2’s topology **and** ingest when that topology arrives relayed through an L1 peer (§6.2).

2. **`Route::verified` for list-downstream** (`Y via M`): **`verified=true`** when
   - Dijkstra `us → … → M` is **strict** (ball edges only), **and**
   - `M→Y` came from **M’s topology** with **`hearsUs=1`** (M reports that Y hears M).

   If `hearsUs` is missing/cleared, or the path to M is only an unverified/inbound-gateway fallback, keep **`verified=false`**. Orphan handoff stays unverified.

   This aligns stamping with “downstream chain is stamped”: the last hop has the same TX-path authority as a mirrored list edge, even though Y is not an EdgeStore publisher.

### Resolved in Phase 0 / Phase 6 (2026-10-06)

3. **Depth default:** **`GRAPH_MAX_DEPTH = 3` (L3 on).** EdgeStore keeps L0+L1+L2+L3. Nodes that only hear L3 become list-downstream of that L3 (or orphans). Compile-time constant; set to 2 to shrink the ball without code changes.

4. **CLIENT_MUTE / passive:** Keep today’s thinner merge for **local** passive roles (skip non-neighbour listed peers in `merge_topology`). **SR-active** roles build the full L2/L3 ball, including non-neighbour L2/L3 topo ingest (§6.2). Mute/passive non-routers do not grow a deep ball from relayed lists.

5. **Downstream cap:** Keep `MAX_DOWNSTREAM = 1100` until field/size data; retune in Phase 5.

6. **Multi-radio:** `heard_on` / `via_radio` follow the existing merge path; L2/L3 ingest records the radio the topology frame arrived on (direct or via L1 relay), and does not invent edges from the relay’s SNR.

### Previously open (closed above)

~~3–6~~

---

## 15. Success criteria

- Destinations inside the ball or one `hearsUs` hop behind a frontier show **multi-hop priced routes** with meaningful ETX differences among next hops when alternatives exist.
- Destinations only known via relay show **orphan gateway handoff**, not fake SPF.
- nRF52840 release still boots; `just size nrf52840` within SRAM budget; Solar Node / nice!nano same class.
- MeshRustic and fork agree on INTEROP text and do not regress sticky-downstream / hearsUs retain tests.
- Lab or field capture (MeshRustic USB ingest for remote publishers) shows L2→L1 edges appearing after L2 lists, not only L1→L2 mirrors.

---

## 16. Summary diagram

```
                    [ Y ]  list-downstream (hearsUs=1 on L3's list)
                      ↑
                     cost from L3's measurement
                      │
[us] ──Reported──► [L1] ◄──preferred── [L2] ◄──preferred── [L3]
                      │                   │
                      │                   └── Mirrored to other ball nodes
                      │
                      └── RF neighbour

[ F ] orphan ──via──► [G] L1 peer that relayed F to us
        (no Dijkstra; hand to G)
```

Edge ball = priced Dijkstra domain.  
Beyond frontier lists = downstream.  
Unknown air copies = orphan gateway.
