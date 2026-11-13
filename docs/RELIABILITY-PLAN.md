# TheKVM — Reliability & Polish Plan (complete problem catalogue)

**Status:** Living document. Written 2026-11-13 after a full cross-machine audit
(code read, live logs on both machines, screen captures, three parallel research
agents). **Owner decision:** docs/RELIABILITY-PLAN.md is the committed reference;
this pass implements the tray menu and visual-cue fixes first, then reliability,
then Linux efficiency, then auto-connect.
**Scope:** Windows `LAPTOP-A1JUOKI0` (192.168.1.10) and Linux Mint `hs01` (192.168.1.12),
X11, `thekvmd.service`.
**Rule for this document:** every item names the symptom in plain language, the
evidence, the exact technical root cause, the fix, and how to verify. Nothing is
marked done until it is verified on both machines (or honestly marked
"needs live reproduction").

---

## 0. How to read this

Priorities, in the order the owner asked for:

1. **Tray menu** — the bottom-right menu must do what it says, on both OSes (Quit = full teardown everywhere).
2. **Visual cues** — the current state must always be obvious at a glance (full V1–V11 set).
3. **Reliability** — the link must work flawlessly for as long as the machines are up.
4. **Mode adherence** — changing the role must take effect immediately and stay enforced.
5. **Linux efficiency** — near-zero idle cost on the Mint side.
6. **Auto-connect / IP healing** — the link must come back by itself after boot *or* IP change.

Each problem is tagged:
- **[CODE-VERIFIED]** — root cause confirmed in source.
- **[LOG-EVIDENCE]** — confirmed in live logs on both machines.
- **[NEEDS-LIVE-REPRO]** — needs a running session to confirm the exact trigger.

---

## 1. Reliability (the "works fresh, breaks after days" class)

### R1. Slow / unresponsive cursor after days of use — [NEEDS-LIVE-REPRO]
**Symptom:** the pointer drags, lags or stutters over long sessions.
**Evidence:** owner reports; also `AGENT-HANDOFF.md` Problem 2 (mint→Windows
direction still not smooth) and Problem 1 (hourglass cursor flap loop).
**Likely mechanism** (from v0.9.58 audit, still believed current):
- Episode teardown/re-dial loop ("parked → cold redial"), edge-return hysteresis
  eating the push, phantom-handoff veto, motion starting on the fallback
  stream before UDP arms, yield after rest.
- Each flap is a full episode teardown + grab release + cold re-dial; the
  hourglass is the OS's busy cursor reacting to the engage/release cycle.
**Fix plan:**
1. Capture a 60 s log window during the sluggishness
   (`journalctl -u thekvmd`, `~/.config/thekvm/link-*.log` on Mint;
   `%LocalAppData%\TheKVM\link-*.log` on Windows).
2. Count `X11 local suppression engaged → released` pairs per second. If > 2/s,
   fix the flap loop (see R3); do not fix the cursor in isolation.
3. Verify `topology handoff activated` lines: `open_ms` should be ~0 on
   re-cross (`resumed=true`). Any repeated cold re-dials mean the parked
   stream is dying — check `take_parked_for`, keep-alive gap, lease timeout.
4. Remove the first-crossing cold dial: pre-warm the parked stream and
   arm UDP **before** `THEKVM_STATUS edge-ready` is printed, and gate the first
   push on it.
**Verification:** one 60 s drive each direction with zero `yielding` lines,
`resumed=true` on every re-cross, cursor shape never changes.

### R2. Link drops / needs re-connect after days — [LOG-EVIDENCE]
**Symptom:** after uptime, the link gets unreliable and needs a manual reconnect.
**Evidence:** Windows `ui.log` (13/11) shows repeated
`poll: daemon control failed: control pipe open timed out after 3s (daemon not accepting)`
followed by `poll: daemon reachable again after failures`; also
`presence: daemon lease unavailable (The pipe is being closed. (os error 232))`.
**Likely mechanism:**
- The daemon accepts UI control clients on a pipe/socket. Somewhere the accept
  loop or the per-client semaphore stops accepting new clients (or pipes back
  up), so the UI's control RPCs time out. The UI logs "not accepting" for 3 s
  then recovers.
- `single-instance lock unavailable (os error 10048)` also logged — TIME_WAIT
  accumulation on 42109 (see R10).
**Fix plan:**
1. In `kvm-daemon/src/service.rs`, find the control accept loop and confirm it
   is not bounded/leaking (semaphore permit leak, long-blocking handler,
   spawn without cap).
2. Make the UI control client set a short timeout and retry with jittered
   backoff; never spin-retry. Any total failure must surface the persistent
   daemon-offline banner (see V7), not 13k silent warnings.
3. Add watchdog to the daemon: if the control accept queue is stuck, restart
   the accept task; log once.
**Verification:** leave the pair linked for 48 h; `ui.log` stays within a few
WARN lines; daemon stays responsive to control RPCs.

### R3. Spontaneous disconnects / re-link churn — [LOG-EVIDENCE]
**Symptom:** the link drops and re-dials by itself, over and over.
**Evidence:** Mint `ui.log`:
```
link: peer re-epoch … -> …; adopting the fresh epoch
link: banned epoch …
session: child inherits the daemon identity (one face per machine)
```
repeating every few minutes. The peer re-epoching without the user pressing
Disconnect means the QUIC peer is being torn down and re-established — the
peer identity is re-minted each reconnect.
**Likely mechanism:** a re-dial loop caused by (a) an unhealthy parked stream
that never recovers, (b) epoch-ban cooldowns stacking, (c) the idle-dual
arbitrator releasing the drive, (d) IP-heal re-dial with a stale address
(see R4) — each teardown re-mints the link epoch.
**Fix plan:**
1. Trace one epoch-cycle end-to-end with timestamps; identify the first
   teardown reason (`crossing_refused`, `yield`, `ReturnHome`, keep-alive
   timeout, lease, stall breaker).
2. If the drive exits on idle: rest ≠ abandonment — an idle-but-live drive
   must hold until the cursor crosses back (handoff Problem 2b, item 1).
3. Teardown should notify the peer once (buyer-needs-to-know), not re-epoch
   forever; persistent churn = back-off and stop re-dialing, show the user a
   persistent status banner (see V7) requiring manual reconnect.
**Verification:** 24 h idle-drive session with zero re-epoch lines.

### R4. IP change ⇒ very slow to adapt / auto-connect — [LOG-EVIDENCE]
**Symptom:** when one machine's LAN IP changes, the link takes a long time to
find it again and reconnect by itself.
**Evidence:** Mint `peers.json` pins `LAPTOP-A1JUOKI0` at the **stale**
`192.168.1.7:42110`; the Windows peer book pins `LAPTOP-Q6DV7H1D` at the stale
`192.168.1.7:42110`. Mint keeps logging
`dialling back LAPTOP-A1JUOKI0 at 192.168.1.7:42110 for two-way edge`.
Windows `config.json` is `auto_connect_address = 192.168.1.12:42110`,
`auto_connect_enabled = true` — its peer 0c07.. IS at `192.168.1.12` (good).
**Mechanism:** the healing path exists (`heal_peer_address`,
`kvm-daemon/src/service.rs:2614`, discovery scan, hostname resolution) but:
- It is only consulted on the dial attempt at *some* call sites
  (`:2818`, `:2974`, `:3107`), and each stale hit costs the full dial timeout
  before the heal runs.
- The stale peer book entry is never *pruned* after a successful heal
  (need to verify in code + on disk).
- The dial (and dial-back) tries the stale address first, so adaptation is
  one timeout + one discovery scan per attempt.
**Fix plan:**
1. Heal **before** dialing, not only on dial failure: resolve the pinned peer
   to a live address via discovery/history first, then dial the healed address.
2. On successful session, **rewrite** the stale peers.json address entry
   (heal-and-pin in the peer book, not just in memory).
3. Prune addresses that fail N consecutive times (keep the fingerprint, mark
   the address dead) so dial falls straight to the healed address.
4. Make auto-connect work off discovery: on failure, fall back to LAN scan +
   pinned fingerprint match before giving up (not after minutes of timeouts).
**Verification:** change Mint's IP; both machines re-link in < 30 s with no
config edits; peers.json shows the new address.

### R5. First crossing is slow even with "warming up" shown — [NEEDS-LIVE-REPRO]
**Symptom:** `open_ms` is large on the first crossing; `resumed=false`.
**Evidence:** handoff v0.9.58 Problem 2a.
**Fix plan:** verify the pre-warm actually arms UDP before `edge-ready`; if
not, gate the first push on it. Budget ~0 ms for a resumed cross on LAN.
**Verification:** first crossing `open_ms < 50`, `resumed=true`.

### R6. Drive exits on inactivity / sudden mid-use exit — [NEEDS-LIVE-REPRO]
**Symptom:** while Mint drives the Windows screen, control drops back to Mint
on its own; also after resting, the response is very slow/massive lag.
**Evidence:** handoff v0.9.58 Problem 2b (three faces: idle-dual arbitration
during rest; mid-use `ReturnHome`/hop-edge/yield; parked episode died).
**Fix plan:**
1. Rest ≠ activity loss: hold an idle-but-live drive indefinitely; only the
   facing edge (or a genuine takeover) releases it.
2. At the exact exit timestamp, classify `ReturnHome` vs `yield` vs
   stall-breaker teardown — three different code paths.
3. Parked-episode lease: keep-alive ping must keep the park alive for the
   whole rest window; measure `open_ms` on the first motion after rest.
**Verification:** rest 60 s mid-drive, resume normally, no exit, `open_ms` small.

### R7. First clicks after a crossing do nothing — [NEEDS-LIVE-REPRO]
**Symptom:** the first clicks after control transfers are swallowed.
**Evidence:** handoff v0.9.58 Problem 2c.
**Fix plan:**
1. Determine whether clicks are missing on the capture side or dropped on the
   injection side (census logs).
2. Likely suspects: `event_barrier` dropping the first events after
   `resume_parked_session`; injector `ensure_session` not ready; Windows
   `BLOCK_LOCAL` held a beat too long; held-button StateSync order.
3. Fix the losing side only.
**Verification:** click immediately after 20 crossings; every click registers.

### R8. Multi-hour freeze where clicks stop — [NEEDS-LIVE-REPRO]
**Symptom:** after hours of use, clicks stop doing anything.
**Evidence:** handoff v0.9.58 Problem 5 (regression watch).
**Fix plan:** after any fix set, run a multi-hour drive; if clicks die, capture
the log at the moment of death and check the capture channel, injector
session, suppression-stuck-engaged, drive-task wedge, `event_barrier`.
**Verification:** 4+ h session, zero lost clicks.

### R9. Hourglass cursor — [LOG-EVIDENCE]
**Symptom:** the OS pointer turns to a busy circle around crossings.
**Evidence:** handoff v0.9.58 Problem 1; the underlying mechanism is the
episode flap loop (see R1/R3) plus OS cursor shape on drive entry.
**Fix plan:** fix the flap first (R3). Then check that entry does not set the
cursor shape on either platform (X11 cage/hide, Windows hook state).
**Verification:** cursor never leaves the user's configured shape.

### R10. Control-pipe TIME_WAIT / unguarded dual UI — [LOG-EVIDENCE]
**Symptom:** intermittent "daemon not accepting" and "single-instance lock
unavailable" warnings; occasionally two UIs running against one daemon.
**Evidence:** `ui.log`:
```
single-instance lock unavailable (Only one usage of each socket address (protocol/network address/port) is normally permitted. (os error 10048)); running unguarded
presence: daemon lease unavailable (The pipe is being closed. (os error 232)); retrying quietly
poll: daemon control failed: control pipe open timed out after 3s (daemon not accepting)
```
**Mechanism (CODE-VERIFIED style, see agent report T6):**
- `kvm-ui/src/main.rs:163-205`: on `bind` failure it logs "running unguarded"
  *before* probing; the probe (`TcpStream::connect`) can succeed against any
  local listener on 42109, so double-clicking TheKVM silently starts a
  second unguarded instance (no window, tray broken) — or, if nothing is on
  42109, it swallows every future launch.
- No SO_REUSEADDR/named-mutex/flock; TIME_WAIT on 42109 accumulates from the
  probe connections (each dropped probe leaves a TIME_WAIT).
**Fix plan:**
1. Windows: named mutex (`Global\TheKVM-SingleInstance`) or `socket2` with
   `SO_REUSEADDR`; Linux: `flock` on a lock file.
2. Probe by PID (child_guard-style) instead of port-connect; log precisely
   which of the two failure modes happened.
3. Gate the hide-to-tray path on tray readiness (see T1).
**Verification:** double-clicking the app twice never creates a second
process or breaks the first.

### R11. Log spam buries real errors — [LOG-EVIDENCE]
**Symptom:** 13k ERROR/WARN lines in `ui.log`; real problems invisible.
**Evidence:** `Select-String 'ERROR|WARN'` count = 13542 in
`%AppData%\Roaming\TheKVM\ui.log` (4 days).
**Fix plan:** log once per transition (with a counter), not per second; make
`presence lease unavailable` and `poll: daemon control failed` transition-only
with a summary every 60 s. Clear the clipboard-offered duplicates (see R12).
**Verification:** `ui.log` < 1k lines/day with the same behaviour.

### R12. Clipboard relay spam — [LOG-EVIDENCE]
**Symptom:** the same image/text "offered" to the relay multiple times in a
row; `applied peer image paste` duplicates; the relay is not de-duplicating.
**Evidence:** `%AppData%\Roaming\TheKVM\ui.log` has hundreds of
`clipboard relay: offered local image` pairs with identical byte counts within
1-10 ms (e.g. `offered local text (6 bytes)` then `offered local image (2356 bytes)`
repeated). Both machines re-offer content they just applied from the peer.
**Likely mechanism:** the poll sends every observed clipboard change without
comparing against what the peer last supplied; image apply then re-reads the
OS clipboard and re-offers it (echo loop), amplified for images.
**Fix plan:** keep a `last_applied_hash` (text and image); never re-offer
content identical to what was last applied from the peer (this is different
from the sender-side `last_text` dedup, which already exists).
**Verification:** alternate copies 5×; each machine applies each paste exactly
once.

---

## 2. Mode adherence ("changing the role does nothing")

### M1. Live sessions ignore a role change entirely — [CODE-VERIFIED]
**Symptom:** switching this machine to "Control other only" or
"Be controlled only" does not stop an already-running inbound peer from driving it.

**Evidence:** the live-config bridge in `kvm-daemon/src/service.rs`
(≈12300-12330) applies only `edge_mode`, `double_edge_style`, and `layout`
to running episodes — **never** `mode`. `process_remote_input` injects with no
mode check at all (≈12332-12369). Role gating (`mode_allows_incoming` /
`mode_allows_outgoing`, ≈14360-14366) happens at the Hello handshake only
(`≈10632-10639`) and at dial time (`≈13498-13500`); `Hello{mode}` is frozen
for the episode's life.

**Fix plan:**
1. Add `mode` to the live-config bridge: on any mode change, immediately
   (a) revoke injection rights for inbound episodes that this machine no
   longer allows, and (b) stop sending input outbound if no longer allowed.
2. On `ClientOnly`: ban the current inbound-capable epoch and notify the
   peer (see M3) so the parked peer session tears down cleanly.
3. On `ServerClient`: refuse new inbound hellos *and* reject parked inbound
   input with a one-time `peer notification` the peer can show the user.
4. The UI must poll daemon status and reflect the *enforced* role, not the
   requested one.
**Verification:** change role with the link live; within 1 s the peer can no
longer type/click; the UI shows the enforced role.

### M2. Peer's role never reaches the UI during a live link — [CODE-VERIFIED]
**Symptom:** arrowheads and availability render from a stale/default peer role;
the "Be controlled only" peer still looks driveable.
**Evidence:** `peer-mode` is only set from the idle auto-scan path
(`kvm-ui/src/main.rs:3669-3689`, called only when no session exists and auto-discover
is on) — never during a live link; the daemon exposes no peer-mode field in
`Status`. (Agent 3 report, §2.3.)
**Fix plan:**
1. Echo the peer's role in `Accepted`/Hello-derived status (protocol bump is
   acceptable — see V4 for the same fix) or per-poll LAN discovery filtered by
   pinned fingerprint (cheap on LAN).
2. At minimum, gate the "drive available" affordances on the actually-in-use
   role and gray out impossible directions honestly.
**Verification:** flip peer to "Be controlled only"; within 1 s the local exit
edges and arrows show "peer cannot be driven".

### M3. ClientOnly does not tear down an open peer session — [CODE-VERIFIED]
**Symptom:** "Be controlled only" leaves the peer's session dangling on a dead
QUIC connection; the user sees nothing change.
**Evidence:** `relink_with_new_settings` (`kvm-ui/src/main.rs:2603-2660`) does
an epoch ban + peer notify for Bidirectional/ServerClient changes, but for
`ClientOnly` it only stops the local child and never bans the epoch, never
notifies the peer — the peer keeps injecting into a connection we no longer
read, or the peer sees a dead link with no explanation.
**Fix plan:** make `ClientOnly` pay the same epoch ban + notify path (it is
the same disconnect class as any other deliberate exclusion).
**Verification:** switch to "Be controlled only"; the peer immediately reports
the session ended; `crossing` between the pair no longer works until switched
back.

### M4. The UI shows a false "Connected" for inbound-only links — [CODE-VERIFIED]
**Symptom:** the Connect tab shows a verified green dot + "Connected to …" even
though this UI never verified the peer; the pair may be in a one-way state.
**Evidence:** `follow_link` calls `set_session(..., Some(..))` on inbound
links (`kvm-ui/src/main.rs:3948`); `set_session` unconditionally claims
"Connected" + `session_verified = true` (`main.rs:5627-5639`), contradicting
its own contract.
**Fix plan:** use `set_session_connected` only when the dial-back child
verifies; paint inbound-only links as "linked (inbound only)" with a distinct
grey/teal cue and no green dot.
**Verification:** link from Mint side only; UI shows "inbound only".

### M5. No feedback when the inbound door is shut — [CODE-VERIFIED]
**Symptom:** if this machine is "Control other only", the peer's Hello is
rejected with "controller-only"; this machine's screen shows nothing.
**Evidence:** agent 3 report, §1.5/§1.6; `DaemonStatus.controller_paused_peers`
(`kvm-protocol/src/control.rs:352`) is never read by the UI.
**Fix plan:** surface `controller_paused_peers` and reject-streak counts in the
status poll; show a persistent "This machine is not accepting connections from
<peer> (its role is controller-only)" cue; also warn when both machines are
"Control other only" (no possible link).
**Verification:** set both machines to "Control other only"; both UIs show the
warning; switching one back restores the link.

### M6. Role in the UI polls back to the requested value — [CODE-VERIFIED]
**Symptom:** the dropdown/label flicker between requested and enforced role.
**Evidence:** `daemon_status` poll overwrites `mode-index`/`role-text` every
second from the live daemon config (`main.rs:2283-2293`).
**Fix plan:** poll is the *enforcement* truth; the dropdown should show the
enforced role (this is correct behaviour) but with an honest "applying…"
during the fetch window (tie to `set_role_display`), and never paint a
transition that cannot be enforced (see M1).
**Verification:** role changes show one visible "applying" tick, then settle.

---

## 3. Visual cues (what the user sees)

### V1. No cue for which machine currently has control — [CODE-VERIFIED]
**Symptom:** the owner cannot tell which side is driving.
**Evidence:** `driving-text` is fed only from the UI's supervised child
stderr (`main.rs:4533-4544`) — it covers the outbound half only; the daemon's
`ActiveSession.driving` / `last_input_age_ms` exist in
`kvm-protocol/src/control.rs:436-446` and are ignored by `follow_link`
(`main.rs:3902-3914`).
**Fix plan:**
1. Consume `ActiveSession.driving` and `last_input_age_ms` per poll.
2. Render: "You drive this laptop" / "hs01 is driving this laptop" with a
   matching chevron/arrow head on the arrangement mesh, plus a subtle colored
   edge glow on the machine whose screen currently receives input.
3. Optional: a status-bar cue at the bottom of the window.
**Verification:** crossing either way flips the cue instantly.

### V2. No edge-crossing feedback / animation — [CODE-VERIFIED]
**Symptom:** crossing an edge is silent — no highlight, no pulse, no animation.
**Evidence:** `edge-active` property (`app.slint:1132`) is written by
`set_edge_active` ("a session slot exists", `main.rs:3647-3665`) and has **no
Slint consumer at all**.
**Fix plan:**
1. Give `edge-active` a real consumer: pulse the exit/entry edge bars for a
   few hundred ms on an inbound/outbound handoff (driven by the daemon's
   handoff events — extend `ActiveSession` with an epoch/handoff counter if
   needed, or use the child's `driving` transition).
2. Chevron button flashes already exist (450 ms timer, `app.slint:331-340`;
   keep) — mirror the pattern for the monitor exit edge on the mesh.
3. Add entry-point pulse on the receiving side (`MonitorCard` enter bars glow
   while the peer is inbound-driving).
**Verification:** every crossing flashes the crossed edge once on both
machines.

### V3. Mode choices don't visibly take effect — [CODE-VERIFIED]
**Symptom:** switching role shows no applied feedback; the user cannot tell
whether it did anything.
**Evidence:** role press only shows a transient `set_status` ("Applying role…",
`main.rs:1055`) then whatever the daemon does; no donut, no Applied flash
(an `edge-applying` donut + timeout exists for edge tiles, `main.rs:4506-4512,
5807-5821`, but not for role changes).
**Fix plan:** give the role dropdown the edge-tile treatment: while the
SetConfig outcome is pending, show the shared `SpinnerArc`; on `Applied`,
flash the dropdown green/chevron; on failure, show an actionable error in the
persistent banner (see V7).
**Verification:** every role switch shows a visible apply → applied tick.

### V4. Arrow heads are role-driven but stale — [CODE-VERIFIED]
**Symptom:** arrowheads show the last *idle-scan* peer role (or default
"Both ways") during the link, so they don't reflect reality.
**Evidence:** `peer-mode` is only set in the idle auto-scan branch
(`main.rs:776-782`); no call sites set it during a live link (agent 3 §2.3).
**Fix plan:** per-poll refresh from the LAN discovery advertisement (already
fresh daemon-side) — cheap, local, no protocol bump; also send the peer's role
in the next Accepted/ConfigEcho if a bump is available.
**Verification:** role flip on either machine flips arrowheads within a poll.

### V5. Arrangement mesh is lit even with the link down — [CODE-VERIFIED]
**Symptom:** the mesh shows green exit edges and arrows when not linked.
**Evidence:** `refresh_arrangement` builds from the peer book + saved layout
(`main.rs:3603-3645`); mesh `enabled = linked-peer-name != ""`
(`app.slint:1709`) — lit bars/arrows show without any live session.
**Fix plan:** bind mesh `enabled` (or a new `link-live` bool) to the verified
session state (outbound child verified / inbound latch), dim the exit/entry
bars and arrows when the link is down; keep the drag gesture for arrangement.
**Verification:** with link down, mesh shows dim screens and no lit edges.

### V6. Exit edges stay green under "Be controlled only" — [CODE-VERIFIED]
**Symptom:** exit edges/chevrons suggest "you can drive out" when the role
forbids it.
**Evidence:** role drives arrowheads only, never the bars/chevrons
(`app.slint:360-363, 366-369, 427-440`).
**Fix plan:** role-gate the exit bars: when this machine is `ClientOnly`,
render exit edges dimmed/stubbed; when `ServerClient`, render entry edges
dimmed/stubbed.
**Verification:** role flips dim/un-dim the correct edges.

### V7. Daemon-offline has no persistent cue — [CODE-VERIFIED]
**Symptom:** when the daemon is down, the window looks healthy after 7 s.
**Evidence:** `set_daemon_offline` sets `connected=false` (`main.rs:2300-2313`)
which only toggles the "Start background service" button
(`app.slint:1622-1626`); the message folds into the 7 s transient footer.
**Fix plan:** persistent banner bar (above the tab strip) driven by
`connected`: "Background service offline — click to restart" / error detail;
clicking restarts the daemon (root-capable via the control pipe or a relaunch
path).
**Verification:** kill the daemon; the banner persists until restored.

### V8. Power LED / monitor borders never respond — [CODE-VERIFIED]
**Symptom:** static local-green border and LED even when nothing is live.
**Evidence:** `MonitorCard` border always `#22c55e` for local, LED static
(`app.slint:172, 229`).
**Fix plan:** bind border/LED to the live link state: dim when no link,
bright when this machine drives, teal when peer drives.
**Verification:** LED/border changes with crossing.

### V9. Tray icon may be invisible / abstract — [CODE-VERIFIED]
**Symptom:** the TheKVM icon is not visible in the tray.
**Evidence:** `build_icon` falls back to a **fully transparent** 64×64 RGBA
(`kvm-ui/src/tray.rs:313-320`) — if the icon buffer is ever refused by the
backend, TheKVM becomes an invisible tray icon (window-only via hide-to-tray =
around + unreachable).
**Fix plan:** fall back to a solid, high-contrast glyph (never transparent);
state-dependent icon (dim = link down, bright = linked); also restore on
double-click (`ClickEvent::Double` is currently ignored, `tray.rs:231-234`).
**Verification:** the icon is always visible; dim/bright follows link state.

### V10. Role change has no Applied feedback — [CODE-VERIFIED]
(See V3.)

### V11. Arrowheads stale in the tiles too — [CODE-VERIFIED]
**Symptom:** tiles draw role arrowheads from a frozen `our-mode`/`peer-mode`.
**Evidence:** `EdgeModePicker` passes `arranged-peer-on-right` but it is
dropped on the floor (`app.slint:835, 851-886` vs `app.slint:795-799`); the
diagram derives `peer-on-right` from `mode != 3` (`app.slint:648`), i.e. fixed
right tiles never match the real arrangement.
**Fix plan:** forward `arranged-peer-on-right` into `EdgeModeTile` →
`EdgeModeDiagram` instead of `mode != 3`; for the three non-fixed disciplines,
follow the live arrangement.
**Verification:** swap the arrangement; the tiles re-draw to match.

---

## 4. Bottom system tray menu

### T1. The tray can be dead while the app thinks it is alive — [CODE-VERIFIED]
**Symptom:** close button hides the window; no tray icon; app unreachable.
**Evidence:** `spawn_tray()` returns `Some(rx)` unconditionally
(`tray.rs:194`); the Linux path `gtk::init().is_err() → return`
(`tray.rs:95-97`) and the Windows path `if let Ok(Some(handles)) =
build_tray_handles` else silent `return` (`tray.rs:131-134`) both leave
`tray_alive == true` (`main.rs:2024-2028`); `on_close_requested` hides
(`main.rs:2066-2102`).
**Fix plan:**
1. Build the tray handles synchronously, or send a readiness token over a
   channel; return `None` (or block a few seconds) if any step fails.
2. Gate `on_close_requested`'s hide-to-tray on real tray readiness; otherwise
   keep the old exit-on-close behaviour (or confirm with the user).
3. Log the failure reason so it's visible.
**Verification:** uninstall the tray backend (e.g. remove libappindicator);
close button no longer strands the app; user gets a message.

### T2. Dark-menu subclass installed on the wrong window — [CODE-VERIFIED]
**Symptom (owner):** Windows tray menu shows only "Show TheKVM".
**Evidence:** `install_windows_dark_menu()` finds the tray window with bare
`FindWindowW("tray_icon_app", None)` (`tray.rs:421-424`) — **no PID filter**.
The correct pattern exists in `find_menu_window` (`tray.rs:603-639`). Any
other muda/tray-icon app (any Tauri app on the machine) that sorts earlier in
Z-order gets TheKVM's subclass installed on it: that other app's
`WM_MEASUREITEM`/`WM_DRAWITEM`/`WM_COMMAND` run through TheKVM's owner-draw;
the KVM's own menu never receives them and its items can come up
non-composed/blank — exactly "menu only shows one row". No log line anywhere.
**Fix plan:**
1. `EnumWindows` + `GetWindowThreadProcessId == our pid`; install only on the
   matched window; log success/failure.
2. Re-apply on `TrayIcon` re-creation if needed (one-time `OnceLock` latches
   it today — see also T5).
**Verification:** right-click TheKVM tray → all four items render, selectable,
dark-themed; other apps' menus unaffected.

### T3. First-use dark-menu window may miss the subclass — [CODE-VERIFIED]
**Symptom:** popup frame/behavior light even after T2 is fixed.
**Evidence:** `find_menu_window()` is called inside `WM_INITMENUPOPUP`
(`tray.rs:747`) before the `#32768` window necessarily exists →
`MENU_WINDOW_SUBCLASS_ID` never installed; the `WM_NCPAINT` arm
(`tray.rs:725-729`) never fires.
**Fix plan:** retry the lookup on a one-shot 50 ms timer after
`WM_INITMENUPOPUP`; or install the subclass as soon as the window is known to
exist.
**Verification:** every right-click paints the dark frame.

### T4. GDI brush leak per right-click — [CODE-VERIFIED]
**Evidence:** `WM_INITMENUPOPUP` creates a fresh `SolidBrush` for the menu
background and never deletes it (`tray.rs:735-745`).
**Fix plan:** one static brush (process lifetime), no per-click allocation.
**Verification:** GDI object count stable across 100 right-clicks.

### T5. Darkening work per paint; flicker — [CODE-VERIFIED]
**Evidence:** `WM_NCPAINT` → `darken_menu_window` (`tray.rs:725-729`,
`tray.rs:644-672`) re-runs `SetWindowTheme` + full-frame `frame_rect_solid`
with a per-paint `GetWindowDC`.
**Fix plan:** install the menu-window subclass first (T3), then paint once on
`WM_NCPAINT` of the menu's own proc only, no per-paint DC fetch beyond the
bounding rect.
**Verification:** no flicker; menu paints correctly every time.

### T6. Single-instance lock is unguarded and swallows launches — [LOG-EVIDENCE][CODE-VERIFIED]
(Duplicates R10.) **Owner-visible effects:** on rare races a second unguarded
UI appears; or TheKVM appears to not launch at all.
**Fix plan:** see R10 (named mutex / flock / PID probe + logging).

### T7. Linux "Show TheKVM" opens the window in the background — [CODE-VERIFIED]
**Symptom (owner):** on Mint, clicking "Show TheKVM" does not raise the window
to the foreground/top.
**Evidence:** `focus_main_window()` is a no-op on non-Windows
(`tray.rs:400-401`); `on_tray_command` waits for focus to settle after
`ui.window().show()` (`main.rs:2037-2047`), but nothing activates/raises the
window on X11/Wayland.
**Fix plan:** on Linux, use `x11rb::xproto::set_input_focus`/
`_NET_ACTIVE_WINDOW` (or `xdg-activate` on Wayland) to raise/activate the
main window; if the toolkit exposes `bring_to_foreground`, use it.
**Verification:** from behind another app, "Show TheKVM" always raises the
window above it.

### T8. Silent tray failures + Disconnect with hidden window — [CODE-VERIFIED]
**Symptom:** tray clicks feel dead; tray Disconnect gives zero visible feedback.
**Evidence:** `install_windows_dark_menu` and watcher spawn discard errors
(`tray.rs:418-419`; `main.rs:2061-2063`); tray commands while hidden neither
re-show nor flash the window (`main.rs:2049-2056`).
**Fix plan:** log every silent branch; after any Disconnect/Quit command,
re-show (or flash/taskbar-alert) the window so the result is always visible.
**Verification:** each tray command shows something on screen.

### T9. "Quit TheKVM" does not stop both machines or close ports — [CODE-VERIFIED]
**Symptom (owner):** quitting the app leaves the background service (and on
the other machine, a process) able to drive this machine; ports stay open;
everything does not stop instantly on all sides.
**Evidence:** `quit_full_terminate` (`main.rs:5062-5091`) does ban the link
epoch + kill the child + notify peers + kill the UI-spawned user daemon +
`process::exit(0)` — but it deliberately leaves the **machine's system
service** (thekvmd / TheKVM) running (`tray.rs:4-9`), and on Windows the
pre-login controller (`service.rs:10167-10209`) keeps driving
`0.0.0.0:42110` regardless of the logged-in UI.
A user does not read "Quit TheKVM" as "leave the remote-input service alive".
**Fix plan (choose with owner — see open question Q3 in §7):**
1. Default Quit: full teardown — bilateral disconnect, notify peers, stop the
   UI-spawned processes, and also stop/leave-disabled the machine's system
   service (with optional `--keep-service`).
2. Rename/re-tool the tray items: "Quit TheKVM (stops background service)"
   plus explicit "Stop background service…".
3. Whatever is chosen, Quit must also close the machine's listener (or the
   port stays bound and the peer's stale epoch is honored).
**Verification:** quit from one machine; the other machine cannot drive it;
port 42110 is down on the quitting machine; no TheKVM processes remain.

### T10. Duplicate label tables — [CODE-VERIFIED]
**Evidence:** `TRAY_LABELS` (`tray.rs:49-50`) and `TRAY_MENU_LABELS`
(`tray.rs:240`) are two identical `[&str; 4]`.
**Fix plan:** one constant.
**Verification:** compile; text matches widths.

### T11. Invisible fallback tray icon — [CODE-VERIFIED]
(See V9.)
**Fix plan:** solid fallback glyph; double-click restores the window.

### T12. macOS tray inert — [CODE-VERIFIED]
**Evidence:** `cfg(not(any(linux,windows)))` just polls (`tray.rs:169-192`);
muda's macOS menu needs the AppKit runloop.
**Fix plan:** out of scope for this delivery; note in docs.

### T13. Dark menu internals — [CODE-VERIFIED]
`dark_menu_bar` (muda's) is never wired; the popup frame relies on
`SetMenuInfo(MIM_BACKGROUND)` (T3/T4 fix). Documented.

### T14. Residual quit teardown gap — [CODE-VERIFIED]
**Evidence:** `quit_full_terminate` doesn't tombstone inbound addresses
(unlike the Connect-tab Disconnect, `main.rs:1385-1404`).
**Fix plan:** after exit, the epoch ban is what protects us; make it explicit
and verified — and if the service stays (T9 variant), at least epoch-ban all
inbound sessions so no stale redial can re-open input.

---

## 5. Auto-connect & IP healing

(See also R3, R4.)

### A1. Auto-connect works but is fragile to IP change — [LOG-EVIDENCE]
**Fix:** heal-before-dial + rewrite peer book on success (R4); default-on
auto-connect is respected; the pre-login controller re-reads config every
2 s (`service.rs:10167-10185`, `10211-10294`).

### A2. Stale peer books never cleaned — [LOG-EVIDENCE]
Windows peers.json holds `LAPTOP-Q6DV7H1D` at `192.168.1.7` (dead machine);
Mint peers.json holds `LAPTOP-A1JUOKI0` at `192.168.1.7` (stale).
**Fix:** prune unreachable pinned peers after N consecutive failures (mark
address dead, keep fingerprint); surface in Settings (peers list) with a
per-peer "forget" action.

### A3. Auto-connect doesn't retry fast enough — [LOG-EVIDENCE]
Epoch churn (R3) shows repeated re-dial attempts; the failure backoff is
buried in the retry path. Fix per R4 step 4; back off to 30 s and log once.

### A4. No visible "Auto-connect" state — [CODE-VERIFIED]
The settings toggle exists; there is no persistent cue of "auto-connect will
re-link after boot". Add to Settings + status bar.

---

## 6a. Daemon/UI failure-chain root causes (v2, from parallel research)

These are the confirmed mechanisms behind the multi-day breakdown. R1-R10 are
ranked by likelihood of producing the owner's symptoms.

### D1 / R1. Capture-helper process leak — **HIGH (matches the observed process multiplication)** — [CODE-VERIFIED]
`ServiceCaptureProxy::create` (`kvm-daemon/src/windows_helper.rs:526-619`) spawns
2 capture helpers, waits 15 s for all to connect, and on partial failure/timeout
bails **without** setting the shared `stop` flag: the already-spawned reader
threads never exit, the helper processes never see EOF, and every failed attempt
leaks 2 helper processes. The controller retries **every 2 s**
(`service.rs:3001-3035`). Fix: on bail set `stop=true`, `shutdown(Both)` every
accepted socket, join the reader threads; bound the respawn rate.

### D2 / R2. Split-brain daemon on the shared control pipe — **HIGH** — [CODE-VERIFIED]
System service and any UI-spawned user-session daemon serve the **same** pipe
name `\\.\pipe\thekvm-control` (`kvm-protocol/src/control.rs:10-20`). When the
service is down/bind-fails, the UI auto-spawns a user-session daemon on Missing
errors (`kvm-ui/src/main.rs:668-700`) and the SCM stops restarting the service
after 3 failures (`packaging/windows/install-service.ps1:125`), leaving the
user-session daemon as this machine's long-lived face with a wrong identity
and peer book. Fix: on Windows never spawn a user-session daemon (mirror Linux),
or isolate the pipe; surface SCM state in a persistent banner.

### D3 / R3. Presence lease reconnect clears ALL controller pauses — **HIGH** — [CODE-VERIFIED]
`ControlRequest::PresenceLease` → `presence_begin()` then unconditionally
`resume_all_controllers()` (`control.rs:623-626`), wiping the entire paused set.
Every transient lease flap resurrects an explicitly Disconnected/quit link.
Fix: clear pauses only on genuine first launch per process, not per reconnect.

### D4 / R4. Control pipe instance pool can be permanently exhausted — **HIGH** — [CODE-VERIFIED]
4 accept workers, 64-instance pool; one-shot handlers read the first frame with
**no timeout** (`control.rs:600`). A client that connects and never writes pins
its pipe instance forever; after 64 pins the pool dies silently with exactly the
two warnings in the owner's log. Fix: 10-30 s timeout + pinned-handler reaper +
loud pool-exhaustion log.

### D5 / R5. Fatal service errors exit instead of degrading — **HIGH** — [CODE-VERIFIED]
`run()` propagates every setup error via `?`; SCM restarts 3 times then stops
for a day (`reset=86400`). Fix: degrade-not-die (serve control, refuse links);
persistent banner; fix installer recovery policy.

### D6 / R6. Logs unbounded — [CODE-VERIFIED]
`ui.log` one line/sec forever; `control.log` no cap; `daemon.log` 8 MB only at
open. ~10 MB/day in failure states. Fix: caps + rate-limited failure lines.

### D7 / R7. `on_ui_gone` is dead code — [CODE-VERIFIED]
The documented "hang up every inbound when the app goes away" never happens
(`service.rs:1085-1105` is `#[allow(dead_code)]`, never called). Fix or remove
the promise honestly.

### D8 / R8. Discovery responder re-parses config per request, no gate — [CODE-VERIFIED]
`service.rs:10433-10454`: every discovery request reads `config.json` on disk
synchronously and ignores `ui_present`. Fix: cache + presence-gate + rate-limit.

### D9 / R9. No end-to-end timeout on control RPCs — [CODE-VERIFIED]
Only the open is bounded (3 s); read is bare. A wedged-but-connected daemon
freezes the poll thread silently. Fix: one timeout around the whole round trip.

### D10 / R10. Redundant user-session daemons persist — [CODE-VERIFIED]
`track_user_daemon` drops redundant handles without killing. Fix: kill or refuse.

---

## 6b. Async churn / peer-address learning (v2)

### E1 / B1. Re-epoch storm + 32-slot ban set is wiped, not rotated — **CRITICAL** — [CODE-VERIFIED]
Every unclean drop mints a fresh epoch (`service.rs:2941+`, `mint_epoch_id`);
the UI adopts the newer epoch and kills/respawns its child
(`kvm-ui/src/main.rs:4063-4103`); `end_link` `clear()`s the 32-slot set
(`service.rs:582-589`) and `HashSet::take(32)` persists an arbitrary subset
(`service.rs:1284-1299`). After ~32 flaps all prior bans — including explicit
Disconnects — are lost. Fix: FIFO eviction, deterministic persist, persist on
every insert, per-peer re-epoch adoption limiter.

### E2 / B2. No circuit breaker on a stale dial address — **CRITICAL** — [CODE-VERIFIED]
`heal_peer_address` only runs on dial failure (`service.rs:2810+`) and healed
addresses are used in-memory but never persisted on the outbound path; the stale
pinned entry (`192.168.1.7`) is retried forever as a 750 ms /24 unicast sweep +
DNS per retry, once a second, forever. Fix: persist heal on every heal; per-address
circuit breaker; surface the stale address in the UI.

### E3 / B3. How Mint learns the peer address — [CODE-VERIFIED, table in agent report]
`sessions` (live inbound) self-heals; `recent_inbound` (15 min); peer book;
`config.auto_connect_address` (forever). Nothing outbound-only ever refreshes
these; a peer that never dials Mint stays `.7` forever. Fix: refresh
`recent_inbound`/book from verified *discovery* sightings too, and write back
heal results.

### E4 / B4. Fresh-epoch adoption bypasses the 30 s throttle — [CODE-VERIFIED]
`main.rs:4104-4132`: adoption attempts always fire immediately. Combined with B1
each flap is an immediate fork+exec. Fix: per-peer adoption limiter.

---

## 6c. Linux efficiency, concrete (v2)

### F1 / A1. Failed-dial retry loop = full /24 sweep + DNS + JSON re-parse **every second, forever** — **CRITICAL** — [CODE-VERIFIED]
`service.rs:2810-2995` retry loop with 1 s cadence; `heal_peer_address`
(`service.rs:2614-2760`) incl. `discovery::scan(750ms)` (`service.rs:2704`) +
getaddrinfo per name + `if_addrs` per scan + two JSON file parses per iteration.
Fix: cache if_addrs; cache/rate-limit heal scans (≥15-30 s cadence, one
concurrent); no per-iteration book/config reloads.

### F2 / A2. Linux tray pumps GTK at 20 Hz forever — **HIGH** — [CODE-VERIFIED]
`tray.rs:105`: `glib::timeout_add_local(50ms)`; fallback loop `tray.rs:188`.
Fix: event-driven or ≥250-500 ms.

### F3 / A3. X11 capture wakes 10 Hz idle (62 Hz with a key held) — **HIGH** — [CODE-VERIFIED]
`kvm-platform/src/x11_capture.rs:1314-1319`: `timeout_ms = 100` (62 ms-ish while
typematic). Evdev fallback same shape. Fix: ~1 s poll when no `held_keys`;
wake via capture eventfd.

### F4 / A4. 4-6 control round-trips/sec + a 1 s blocking LAN scan on the UI poll thread — **MEDIUM** — [CODE-VERIFIED]
`kvm-ui/src/main.rs`: Status + ListPendingPairings + ListPendingLinks per tick;
auto-scan does `block_on(discovery::scan(1s))` on the same thread every ~15 ticks.
Fix: batch pending requests or poll them on a slower timer; off-thread scan.

### F5 / A5. uinput writes block under a shared mutex, no timeout — **MEDIUM** — [CODE-VERIFIED]
`kvm-platform/src/inject.rs` (~217-225, 287-302): blocking `write_all`, no
O_NONBLOCK, mutex held across. Fix: O_NONBLOCK fd, bounded write, drop-and-recreate.

### F6 / A6. Capture thread spins 50 Hz on a full drive channel — **MEDIUM** — [CODE-VERIFIED]
`service.rs:5285-5306` `capture_send_bounded`: infinite `sleep(20ms)` loop on
`TrySendError::Full`. Fix: bounded retry; drop-oldest + counter + warn.

### F7 / A7. Topology child re-reads `config.json` synchronously every 500 ms — **LOW/MEDIUM** — [CODE-VERIFIED]
`service.rs:3705-3712`, `4475-4489`. Fix: ≥1-2 s cadence or inotify.

### F8 / A8. Clipboard fallback path polls every 500 ms with no XFixes — **LOW** — [CODE-VERIFIED]
`service.rs:8112-8220`, `clipboard.rs:338-461` (XFixes 1 s poll is genuinely
near-zero — keep). Fallback branch re-reads text every 500 ms forever. Fix:
gate image/text re-reads on ownership change.

### F9 / A9. `ui.log` open→append→close per line, unbounded — LOW — [CODE-VERIFIED]
`main.rs:5097-5112`. Fix: buffered fd + rotation.

### F10 / A10. Pre-login controller ticks `loginctl` every 2 s when the UI is absent — LOW — [CODE-VERIFIED]
`service.rs:10211-10294` (`interactive_session_active` 1500-1566). Fix: D-Bus cache or 10-30 s cadence.

---

## 6. Linux efficiency

### L1. Idle CPU not near zero — [NEEDS-LIVE-REPRO]
**Symptom:** Mint feels warm; the owner reports "problems with super efficiency".
**Evidence:** `kvm-daemon serve` up 38+ days (RSS 12 MB, 0.0 % CPU at the
sample instant — good snapshot, not a guarantee); `kvm-ui` 0.7 % CPU, 99 MB
RSS over 13 h.
**Open questions for live measurement (fill in after measuring):**
- The X11 grab/suppression loop, the clipboard poll cadence, the UI status
  poll (1 s), the tray glib 50 ms drain — measure each.
- The target: < 0.5 % average CPU at idle on X11.
**Fix plan:**
1. Profile one 60 s idle window with `perf top` / `valgrind
   --tool=callgrind` on Linux: identify the hot loop.
2. Idle the clipboard relay when the OS clipboard hasn't changed (compare a
   cheap hash before offering); dedupe per R12.
3. Idle the status poll to 3-5 s when applied and unchanged; wake on control
   events (the pipe delivers the user actions instantly regardless).
4. On X11, ensure the capture path is pure event-driven (no timer spin); the
   grab flap loop (R1) is both a reliability and an efficiency bug.
**Verification:** 60 s idle profile shows < 0.5 %; no grab engage/release
pairs while idle.

### L2. Long-running daemon health — [NEEDS-LIVE-REPRO]
38-day uptime: check for fd leak, parked-stream leak, clipboard stash
growth. Add `/proc/<pid>/status` VmRSS + FD count logging hourly in debug.
**Verification:** RSS flat over 7 days.

### L3. Daemon watchdog / restart policy — [NEEDS-LIVE-REPRO]
`thekvmd.service` has `Restart=always, RestartSec=1` — fine — but no
`StartLimitBurst` guard; add `Restart=on-failure` with sane burst limits and
watch the journal for restart storms.

---

## 7. Open questions — resolved by the owner (2026-11-13)

### Q1. Quit semantics → **Full teardown everywhere.**
"Quit TheKVM" must disconnect both machines, close ports, stop the background
service, and kill everything instantly on all sides. The tray item gets no
"keep the service" variant.

### Q2. Cursor flap → fix the flap (R1/R3), not the cursor.

### Q3. Background service model → none. Quit means everything stops.

### Q4. Visual cues scope → **all of them** (V1–V11), in this pass.

### Q5. IP healing → both boot auto-connect and post-DHCP healing are in scope (R4).

### Implementation order (owner-approved): tray first, then visual cues, then reliability, then mode, then Linux.

---

## 8. Acceptance checklist (the bar for "done")

- [ ] One 60 s drive per direction, zero unexpected yields, no snap-backs.
- [ ] `resumed=true` on re-crosses; first cross < 50 ms.
- [ ] Rest 60 s mid-drive: drive holds; first motion instant.
- [ ] Switching role takes effect instantly, both directions, mid-link.
- [ ] Clipboard: alternate copies 5× each way, text then images, instant.
- [ ] Cursor never changes shape while linked.
- [ ] No control-pipe timeouts in `ui.log` over 48 h.
- [ ] Tray: all four items work on Windows and Linux; Quit per Q1; Show
      raises the window on Linux.
- [ ] Whole UI: daemon-offline banner persists; linked/unlinked mesh honest;
      arrowheads + drive cue always accurate.
- [ ] Auto-connect: boot → link re-establishes; IP change → re-link < 30 s.
- [ ] 4+ h session, zero lost clicks.
- [ ] Linux idle < 0.5 % CPU; no grab flap while idle.
