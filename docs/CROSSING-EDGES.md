# Crossing edges: how modes work

Every crossing — a cursor leaving one machine and arriving on the other —
is governed by **two independent choices**:

| Axis | Config key | Values | What it decides |
|---|---|---|---|
| **Connection mode** | `mode` | `Bidirectional` (Both ways) · `ServerClient` (Controller only) · `ClientOnly` (Receiver only) | **Who may drive whom.** |
| **Edge discipline** | `edge_mode` + `double_edge_style` | `Single`, or `Double` with style `Mirror` (default) | **Which edges open a crossing and which edges of the driven machine send control home.** |

The two axes are orthogonal. Every combination is valid, each machine
makes its own choices, and both machines should normally be set to the
same disciplines for a symmetric feel (nothing synchronizes them across
the link — see [What each machine owns](#what-each-machine-owns)).

---

## 1. Connection mode (who may drive whom)

| Mode | UI name | May this machine drive? | May the peer drive this machine? |
|---|---|---|---|
| `Bidirectional` | Both ways | ✅ Yes | ✅ Yes |
| `ServerClient` | Controller only | ✅ Yes | ❌ No |
| `ClientOnly` | Receiver only | ❌ No | ✅ Yes |

The choice is enforced on **both** ends of the handshake: a `ClientOnly`
machine never initiates a session, and a `ServerClient` machine refuses
every inbound control session. A `ClientOnly` peer paired with a
`ServerClient` peer is a one-way link in the controller's direction only —
even if both forgot to agree, the handshake is the backstop, not the UI.

Connection mode never changes *where* crossings land. It changes only
whether they may happen at all. A `ClientOnly` machine still shows lit
exit edges in the illustration, but they carry the role caveat: the arrow
heads only ever point one way (arrow heads sit on the machine being
driven; "Both ways" puts a head on both ends of every arrow).

---

## 2. Screen arrangement and the grid rule

Disciplines only decide crossings **between arranged neighbours**. The
arrangement is a grid of screens; two screens are neighbours when one
directly abuts the other on a shared edge.

- A crossing opens **only** through an edge that faces a real arranged
  neighbour (Deskflow/MWB parity). Top/bottom edges never open a
  crossing — an unarranged edge stays local forever; it can never
  fling control to the other computer.
- On a **two-machine (lone-peer)** link in **Double** mode, the outer
  horizontal edge that has *no* neighbour also leads to the lone peer.
  That is the whole point of a double edge: the two machines are the
  only screens in the universe, so both horizontal edges are meaningful.
- In **Single** mode, only the arranged facing edge opens a crossing.
- Layout is defined per machine in its own config; the two sides of a
  link normally mirror each other (here: Mint at `x = −1`, width 1920 on
  the laptop's side; the laptop at `x = +1` on Mint's side — each machine
  sees the other on the side it arranged).
- Geometry is measured on each machine (`topology local geometry
  measured`) and the peer's geometry is exchanged over the link and
  cached (`peer_geometry`), so the crossing math always uses real pixel
  dimensions, never the 1920×1080 fallback, on screen edges.

---

## 3. Edge discipline: the two crossing modes

Both modes share the same crossing mechanics — a push must build an
**8-pixel** sustained overflow (`EDGE_PUSH_PX`) on one edge streak before a
handoff commits, resting jitter can never cross, and entries land
**32 px** inside the peer from the entry edge (`ENTRY_INSET_PX`) with a
**40 px** inside-movement arming threshold (`SETTLE_PX`) before any
home-facing overflow may return. What differs per mode is *which* edges
open a crossing and *which* edges of the driven machine send control
back.

### 3.1 Single edge

| Rule | Behavior |
|---|---|
| Open a crossing | **Facing edge only.** On a side-by-side two-machine link, that is the edge the peer sits across from. |
| Peer entry edge (Mirror is the stored style but is irrelevant in Single) | The entry edge **opposite the exit** (the facing edge is mirrored by arrangement), mapped proportionally on the along axis. Entries land inset from the facing edge. |
| Return home | Only through the same edge the peer faces — the home-facing edge adjacent to the driving machine. Any outer edge clamps forever; it can never carry control home. |
| Landing on return | Mirror image of the exit edge (inverse mapping), landing pinned inside that edge (`RETURN_INSET_PX` = 8), along axis mapped proportionally. |
| Feel | One corridor, one direction at a time: the "Spotlight/ultrawide" classic. Lowest complexity; recommended when you always swap machines deliberately. |

Single mode is for users who want the crossing to be unambiguous — "the
ear-only corridor". It never triggers on the far side of a machine.

### 3.2 Double edge — Mirror (the default)

Mirror makes the far (mirror-image) edge a full peer edge too.

| Rule | Behavior |
|---|---|
| Open a crossing | **Either horizontal edge of either machine.** Facing edge → facing entry. Outer edge → far entry (mirror image). Top/bottom never cross. |
| Peer entry edge | **Inverted**: exiting the local **left** enters the peer through its **right** edge and vice versa (exit right → peer's left). Entry mirror of the exit, along axis mapped proportionally. |
| Return home | **Either horizontal edge of the driven machine.** Both face home in Mirror; a sustained shove out of either side returns control. |
| Landing on return | Mirror rule, same as entry in reverse: pushing out the peer's **left** returns through the local **right** edge, and vice versa (inverse landing). If you exited laptop-right → mint-left, you come home to the laptop's right edge when you exit mint-left, and to the laptop's left edge when you exit mint-right. |
| Feel | The classic double-edge mode: edge to edge, mirror-image feel. The physical gesture "push left past the far edge" always works, in both directions. |

Mirror is the recommended mode for a two-machine desk.

### 3.3 Legacy disciplines (removed)

Earlier releases shipped two more Double disciplines, Fixed left and Fixed
right (entry pinned to the peer's left / right edge, return pinned to the
same edge). They were removed: Mirror covers both use cases symmetrically
and the fixed modes made each side of the link behave differently enough
to be permanently surprising. Configs carrying `FixedLeft` or `FixedRight`
deserialize as `Mirror`, so older installs keep working — crossings from
an "old-fixed" machine simply behave as Mirror.

### 3.4 Summary table — all modes

| Discipline | Outer edge crosses (lone peer)? | Peer entry edge | Return home through | Return landing |
|---|---|---|---|---|
| **Single** | ❌ | opposite the exit (mirrored facing) | facing edge only | inverse (mirrored) edge, inset |
| **Mirror** | ✅ | inverse of the exit (left↔right) | **either** horizontal edge | inverse of the pushed edge (mirrored), inset |

All crossings in every discipline land inset from the entry edge
(`ENTRY_INSET_PX`, 32 px), with the along axis mapped proportionally; all
returns land inset from the landing edge (`RETURN_INSET_PX`, 8 px).

---

## 4. The return path, in detail

Entering is only half the story. Once a machine is driving the peer,
that peer's screen is owned by the driver — it draws every input event
and refuses to open further crossings (no automatic third hop; a lone
peer can't go anywhere else anyway).

The router on the **driving** machine tracks the virtual cursor inside
the peer and decides when control comes home:

1. **Entry is disarmed.** The entry edge starts in a Schmitt-trigger
   "disarmed" state: overflow there clamps until the cursor has settled
   **≥ 40 px** (`SETTLE_PX`) inside the peer. After that, either horizontal
   outward run accumulates a return budget.
2. **Armed return brush guard.** Overflow must build up to
   **20 px** (`RETURN_EDGE_PX`) of same-edge accumulated overflow before the
   return fires — a 1-pixel brush of the boundary while roaming near the
   edge never ends the drive.
3. **Sustained-pressure window.** An optional hold window
   (`return_hold`; shipped at **0 ms**, i.e. event-only) may additionally
   require the overflow run to have lasted a wall-clock duration.
4. **Post-handoff grace.** For **40 ms** (`handoff_grace`, shipped) after a
   crossing commits, home-facing overflow clamps instead of returning —
   the crossing's own fling tail can't snap control straight back.
5. **Escape hatch for unarmed entry.** Even never-settled pushes home
   return eventually: an un-armed entry edge accumulates **64 px**
   (`RETURN_PUSH_PX`) of home-ward overflow and fires. Jitter alternates
   with inside movement and can never reach the budget; a deliberate
   shove always does.
6. **Return landing.** `restore_local_at_edge` places the local cursor
   pinned inside the landing edge (inverse edge in Mirror and Single), and
   arms a refractory (`post_return_edge`,
   **250 ms**, `POST_RETURN_HOLD_MS`) on the local landing edge so the held
   shove that just came home can't instantly re-open a crossing on the
   same gesture.
7. Telemetry: every would-be clamp names itself (`stuck edge …` in the
   journal) with the edge, position, overflow depth and reason, so a
   stuck edge is debuggable from logs alone.

---

## 5. Both directions are the same code, same rules

There is no "master" machine in the routing layer. Each machine runs its
own `EdgeRouter`, its own copy of the full discipline table, and its own
copy of these constants. The direction of travel is just an exit edge on
one machine and an entry edge on the other:

- **Windows → Mint**: the Windows daemon's router decides a crossing opens when you push at the Windows edge; it computes Mint's entry edge from **Windows's own `double_edge_style`** and the rest of the crossing is a clamp/armed return bound to Windows's discipline.
- **Mint → Windows**: symmetric — Mint's router, Mint's discipline applies.

So the two sides must agree on the discipline for a symmetric feel.
They can legitimately disagree, and then each direction of travel follows
its own rules — e.g. Windows on `Single` while Mint is on `Mirror` makes
Windows→Mint crossings life on the facing edge only, while Mint→Windows
crossings use either edge as usual. A mismatch is never an error; it's
just two different machines doing two different jobs. (This asymmetry is
exactly what made earlier single-direction tests feel broken while the
other direction looked fine.)

**Set the same discipline on both machines.** The UI persists the edge
discipline only locally; there is no link-time reconciliation.

---

## 6. What each machine owns

| State | Owner | Notes |
|---|---|---|
| `edge_mode` (`Single` / `Double`) | Each machine | Hot-applied to the live drive on both machines independently (`live edge mode applied` / `topology entry style hot-applied`). |
| `double_edge_style` (only `Mirror`; legacy `FixedLeft`/`FixedRight` load as `Mirror`) | Each machine | Only read in Double mode on a lone-peer link. |
| `layout` (screen arrangement, fingerprints, dims) | Each machine | Applied live; measured dims win over the 1920×1080 fallback; a change can only move crossings, never manufacture new ones. |
| `mode` (connection mode) | Each machine | Enforced on both handshake ends (see §1). |
| Peer fingerprint, pairing code, clipboard | Daemon + Windows UI / Mint agent | Orthogonal to edges. |
| Connection-mode role lights, edge bars | UI | Lit bars = edges open for a crossing **per the current role and mode**, not per the link. |

---

## 7. The constants (for maintainers)

| Constant | Value | Meaning |
|---|---|---|
| `EDGE_PUSH_PX` | 8 px | Overflow budget that must accumulate on one edge streak to open a crossing. |
| `PHANTOM_START_GUARD_PX` | 64 px | Pushes starting beyond this from the border get per-event credit capped below full crossing depth — a fling from mid-screen pins at the border instead of crossing. |
| `ENTRY_INSET_PX` | 32 px | Where the peer's cursor lands (inside the entry edge). |
| `SETTLE_PX` | 40 px | Distance the cursor must move inside from the entry edge to arm the return. |
| `RETURN_EDGE_PX` | 20 px | Armed return brush guard: same-edge overflow that must accumulate before control returns home. |
| `RETURN_PUSH_PX` | 64 px | Unarmed escape-hatch budget (never-settled shoves still return home). |
| `RETURN_INSET_PX` | 8 px | Where the local cursor lands on return (inside the landing edge). |
| `POST_RETURN_HOLD_MS` | 250 ms | Refractory on the local landing edge after a return. |
| `POST_RETURN_CLEAR_PX` | 64 px | Refractory clears once the cursor comes back inside by this depth. |
| `return_hold` (daemon) | 0 ms | Sustained-pressure window. Event-only by default; the router's own rule is the unit-tested truth. |
| `handoff_grace` (daemon) | 40 ms | Post-crossing window in which home-facing overflow clamps, so a crossing's own fling tail never snaps control home. |
| `idle_home_secs` (config, default `10`) | Seconds of no outbound traffic on a drive after which control auto-returns home — the cursor can never strand the machine hostage mid-roam. The drive-opening crossing, like every forwarded event, stamps the activity clock, so a drive opened from an idle machine is never judged idle milliseconds in. |

---

## 8. Where it is chosen in the UI

Devices tab → **Crossing edges**: one tile per discipline (Single,
Mirror), each an illustration of the two monitors with the live roles.
The tile that is in force wears a green highlight box; the live mode
name appears in green next to both "Screen arrangement" and "Crossing
edges" headings. The **Screen arrangement** mesh above the tiles shows
the same disciplines against the live arrangement — the Single mode
shows one centered arrow; the double mode shows the paired (short facing + long far) staggered arrows.
modes show the paired (short facing + long far) staggered arrows.

Changing the discipline applies to the **next crossing** — no re-link is
required (`topology entry style hot-applied`). The daemon's status
serves the live values, so the UI and the live router can never drift
far behind each other.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Exiting left on Windows lands on Mint's left edge | Windows is on an old `FixedLeft` config — the legacy value is read as **Mirror** now, so Windows exits enter the mirror edge (Mint's right) | Restart both machines' TheKVM services; an explicit Single/Mirror re-pick on Devices → Crossing edges confirms the live value. |
| One direction returns home, the other doesn't | The two machines run different `double_edge_style`s | Align both; Mirror is symmetric both directions. |
| Pushing out the far/outer edge does nothing on Single mode | By design — Single crosses on the facing edge only | Switch to Double (Mirror) or use the facing edge. |
| Crossing works then control "bounces" back instantly | The crossing fling tail hit the return budget within the post-crossing grace window — nothing to fix; it is clamped by design for the first 40 ms | Move the cursor a few pixels inside and push again deliberately. |
| The bottom edge never crosses | No peer is arranged across the bottom edge — grid rule, not a bug | Arrange a peer there (two-machine: rearrange the side-by-side layout), or it will never open. |
| A stuck edge reports "no peer arranged there" | Same: the overflowed edge faces nothing | Same as above — arrange the peer or accept the clamp. |

---

## 10. The contract, in one place

Per machine, always true:

1. A crossing opens only on a sustained **8 px** overflow on one edge streak;
   resting noise never crosses.
2. The entry edge and the return discipline are decided by the **driving**
   machine's `double_edge_style` (Double mode) at crossing time.
3. **Mirror**: left↔right both open (lone peer) and both return; entry is the
   inverse of the exit; return lands inverse of the push.
4. **Single**: only the facing edge opens; returns fire only through it; the
   outer edge is a wall in both directions.
5. Top/bottom edges never open or return a crossing.
7. Return after entry is armed only once the cursor settles **≥ 40 px**
   inside the peer.
8. A return can never happen within **40 ms** of the crossing that started
   it (post-crossing grace), and a roaming 1-pixel brush of the boundary
   never fires one either.

Regression tests pin this contract in `kvm-core::layout`
(`mirror_facing_entry_returns_from_both_edges`,
`mirror_outer_entry_returns_from_both_edges`,
`single_mode_only_the_facing_edge_crosses_and_returns`, plus the older
`mirror_double_returns_through_either_edge_once_settled`, and the
`opposite_edges_mirror` suite) — see
[kvm-core/src/layout.rs](../kvm-core/src/layout.rs).
