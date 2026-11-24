# TheKVM — Phase 3 Work Plan (parseable problem list)

> Source: user request 2026-11-24. Everything below is split into discrete,
> trackable problems. Status legend: `OPEN` → `INVESTIGATING` → `FIXED` →
> `BUILT` → `DEPLOYED` → `USER-VERIFIED`. Testing policy: **white-box only**
> (logs + static code review by the agent). Hands-on device testing is done
> by the user. No hands-on testing by the agent.

Baseline at time of writing: git HEAD `8ad7861`, both desktops and the
Android APK at v0.9.94. Windows `LAPTOP-A1JUOKI0` (192.168.1.6),
Mint `hs01` (192.168.1.12), phone `192.168.1.9`.

---

## A. Technical bugs (fix first, highest priority)

### A1 — Asymmetric cross-control: Mint→Windows works, Windows→Mint does not
- **Symptom (user):** just before this report both machines were connected;
  Linux Mint could cross over into Windows, but Windows could not cross
  over into Linux Mint.
- **Suspicion:** direction-specific gate in daemon admission, layout/
  geometry negotiation, local-input suppression/grab, or the Windows
  service (LocalSystem, session 0) injection path. Prior handoff doc says
  "Windows-hardware-driving-Mint is the good direction", so this may be a
  regression or a flipped edge/handoff state after the auto-connect churn.
- **Work:** read logs from both daemons for the exact window; compare
  `session-accepted`, `handoff`, `yielding`, `crossing_refused`,
  `ReturnHome`, `local suppression` lines in both directions; find the
  asymmetric branch; fix symmetrically; add regression test if pure logic.
- **Status:** OPEN

### A2 — Windows local input dies completely
- **Symptom (user):** a little before this report Windows completely
  stopped working — mouse clicks and keyboard strokes did not work on
  Windows from Windows itself (local machine input, not remote).
- **Suspicion:** a stuck grab / local-input suppression that never released
  after a drive episode, or a leaked uinput/SendInput hook, or the UI/daemon
  being killed during deploy while a grab was active. Windows service runs
  as LocalSystem; a helper holding a low-level hook could suppress input.
- **Work:** check Windows logs/Event Viewer TheKVM-related entries and
  `control.log`, find grab engage without matching release, add a watchdog
  / unconditional release on session end and on daemon shutdown. Fix must
  guarantee local input is never left suppressed.
- **Status:** OPEN

### A3 — Horizontal scrolling imperfect and not bidirectional
- **Symptom (user):** horizontal scrolling still does not work perfectly;
  must work both ways — Mint trackpad → Windows and Windows → Mint.
- **Known prior fix:** Linux evdev capture now forwards both pan axes per
  frame (commit `d62265d`). Residual bug may be on the receiving/injection
  side (`SmoothWheel` handling, axis sign/scale, Windows `SendInput` wheel
  vs HWHEEL) or in the Android→desktop path.
- **Work:** trace the full horizontal-scroll path in both directions in
  code + logs; fix axis mapping/sign on both Windows and Linux injectors;
  add regression tests for both-axis handling.
- **Status:** OPEN

### A4 — Auto-reconnect after manual disconnect is one-way / wrong
- **Symptom (user):** after clicking Disconnect inside an active session,
  the app keeps auto-connecting in a way that lets the *other* computer
  enter ours, but ours cannot control theirs. This only happens on
  auto-reconnect after a manual disconnect.
- **Required behaviour:** after an explicit Disconnect, **do not** auto
  reconnect at all — automatic reconnect is only allowed after the app
  has been restarted (fresh process). Manual disconnect must persist for
  the lifetime of the process.
- **Work:** find the auto-connect state flag; add a "suppressed until
  restart" latch set by Disconnect; make sure it gates both directions
  (outgoing dial and incoming acceptance); verify mode/role is symmetric
  after a legitimate restart-triggered reconnect.
- **Status:** OPEN

### A5 — Delete a pairing so it never auto-connects again
- **Symptom/requirement (user):** need a way to delete a pairing used for
  auto-connect, so that computer does not always reconnect.
- **Work:** expose a "Forget / Remove pairing" action in the Devices UI
  (already partially present for Android?) for every remembered peer on
  every platform; remove from peers.json and clear `auto_connect_address`
  when that peer is removed; verify it survives restart.
- **Status:** OPEN

---

## B. Multi-node mode (new capability)

### B1 — Three modes, up to N devices (count to be confirmed)
- Keep the existing 2-device mechanism and its GUI exactly as-is.
- Add a toggle: **2-device ↔ multi-node**.
- Multi-node modes:
  - **Client / server:** exactly one server; the server can control all
    clients; clients cannot control the server or each other.
  - **Both-way:** every node can cross into and control every other node.
  - (Third mode naming to be confirmed — likely "Server" role selection.)
- Setup should be automatic: one device sends the request; approving on
  the other devices connects the whole mesh.
- **Status:** OPEN (spec clarification pending — see Open Questions)

### B2 — Grid configuration popup in Devices section
- Popup/window with a grid of **5×3** cells and visible grid lines.
- Each machine is a draggable box that shows its name; double-click and
  drag to place it in a cell, matching physical placement.
- Boxes must look like little monitors/screens: blue screen graphic in
  light theme, distinct graphic in grey/dark theme; beautiful, not plain
  rectangles.
- A spinner/progress indicator appears in a proper place whenever a grid
  change is applied.
- **Status:** OPEN (spec clarification pending)

### B3 — Edge mapping / wrap-around rules
- Crossing follows "double edge wrap around": the last machine on the
  grid's right edge enters the first machine's left edge (wrap).
- All other edges connect to whichever cell/edge touches in the GUI grid.
- Configuration derived from grid placement, not connection order.
- **Status:** OPEN

---

## C. Theme + GUI redesign

### C1 — Two themes
- Change theme from pure black to:
  - **Dark:** `#121212` grey base.
  - **Light:** white background, black text, blue highlights.
- Toggle in Settings. Default / current availability to be confirmed.
- **Status:** OPEN (spec clarification pending)

### C2 — Main Connect section redesign
- Current layout described as "pure chaos and really bad mapping", with
  three large weirdly-shaped rectangle buttons.
- Modernise the section: change how items are listed, keep it efficient
  and functional, make small scaling/positioning changes, avoid large
  structural changes to the rest of the app.
- Devices dropdown/settings bars stay visually unchanged in structure.
- **Status:** OPEN

---

## D. Process / delivery

- **D1:** Write this MD file with problems split into parseable readable
  items — DONE (this file).
- **D2:** Investigate A1–A5 via logs + code only (white-box). No hands-on
  testing by agent; user tests on real hardware.
- **D3:** Fix A1–A5, implement B1–B3 and C1–C2.
- **D4:** Build all three targets (Windows, Linux/Mint, Android APK),
  deploy to Windows + Mint, publish APK to the existing GitHub Release,
  report hashes and exact verification evidence.
- **Status:** OPEN

---

## Open Questions (must be resolved before large implementation)

1. **Device cap:** "more than 5 devices" vs "upto 5 devices" — what is the
   actual maximum node count? Grid is 5×3 = 15 cells; is that 15 devices,
   or 5 devices placed in a 5×3 canvas?
2. **Theme availability:** toggle light/dark in settings, but "for now only
   dark mode" — should light mode be implemented now or only dark with the
   toggle present?
3. **Mode names:** "client server and both way" — is the third mode
   "Server" (remote-controlled only), or is there a separate controller/
   server role split? Confirm exact three role names.
4. **A2 scope:** was Windows local input dead because of a stuck grab from
   TheKVM, or was the whole OS input stack hung? Any Event Viewer error
   around the timestamp would help narrow this.

---

## Resolutions (confirmed after white-box investigation)

Open questions answered by the user:
- **Device cap = 15** machines in a 5×3 grid.
- **Both themes now**: dark `#121212`, light white/black text/blue accents,
  toggle in Settings.
- **Three existing modes apply**: `Bidirectional` (all nodes cross each
  other), `ServerClient` (one server controls all clients), `ClientOnly`
  (receiver only). The legacy 2-device UI is kept unchanged; multi-node is
  an opt-in toggle in Devices.

### Root causes found (with code evidence)
- **A1 (one-way crossing):** `validate_input_capability` in
  `kvm-daemon/src/service.rs` rejected a lock-screen-enabled Hello on Linux
  while Windows merely downgraded it. With Windows' checkbox on by default,
  every Windows→Mint Hello was rejected while Mint→Windows was accepted.
  Also, warm topology crossings called `open_episode_stream` directly and
  skipped the outgoing-mode gate. Both are now symmetric: capability is
  downgraded everywhere, and `open_episode_stream` enforces
  `mode_allows_outgoing`.
- **A2 (Windows local input died):** the suppression watchdog cleared
  `BLOCK_LOCAL`, but `Win32Capture::next_event` re-armed it from the shared
  `exclusive` flag every 100 ms inside its own timeout loop, which the
  capture-thread watchdog could never reach while the user was idle. Added
  a process-wide `SUPPRESSION_FORCE_RELEASE` latch: a watchdog firing keeps
  local input free until a fresh `set_exclusive(true)` re-engages a drive.
- **A3 (horizontal scroll):** Android negated horizontal pan while the Linux
  evdev path did not; Windows PTP axis-lock zeroed the horizontal axis on
  any vertically-wobbly pan and a false pinch dropped pan frames. Fixed:
  one canonical sign on all senders, both axes always forwarded, vertical
  invert only on Y, faster pinch takeover, and pan forwarded on the frame
  a false pinch ends. Regression tests updated.
- **A4 (one-way state after Disconnect):** Android's `stop()` only dropped
  an `Arc`, never closed the QUIC connection, and left the peer free to
  dial back while auto-connect re-dialled within ~2 s. Fixed with a
  process-lifetime `auto_disconnected` latch, real connection close, and a
  daemon-side inbound `DISCONNECTED_PEERS` latch lifted only by a fresh app
  launch (`ResumeControllers`) or an explicit Connect.
- **A5 (delete pairing):** Android `Forget` now tombstones the fingerprint
  in `Store.deleted`, so discovery and in-flight connects can never
  resurrect it. Desktop already had permanent `Unpair`.

### Implemented features
- **B1/B2/B3:** Android Devices page gains a multi-node toggle, three mode
  chips, a 5×3 grid popup with monitor-like draggable boxes, name labels,
  grid lines, a spinner while applying, and permanent placement storage.
  `Apply to all computers` sends a new `WireMessage::MeshConfig` to every
  connected desktop; each daemon rebuilds its `Layout` from the shared grid
  and persists it. `Layout::neighbor_for_edge` now wraps the right edge to
  the first machine on the same row when three or more machines are placed
  (two-device links stay strict).
- **C1/C2:** global `Theme` palette with both themes, Settings toggle, and
  a modernised compact Devices list. The dropdown and control bars keep
  their structure.

## Desktop round (same requirements applied to Windows/Linux UI)

### Second-round root causes (logs + code, 2026-11-24)
- **Watchdog log spam (Windows + Mint):** the OS-thread watchdog fired on a
  stale heartbeat (`< 4s`) while the drive keep-alive interval is 5s. Every
  idle cycle therefore read as "drive task wedged" with `stale_ms` growing
  forever on Mint and oscillating ~4s on Windows. Raised the OS-watchdog
  threshold to 12s; the capture-thread watchdog (which already gates on the
  exclusive flag) is unchanged.
- **X11 horizontal scroll:** the same dominant-axis lock as the Windows PTP
  bug also existed in `kvm-platform/src/x11_capture.rs`: on a horizontal
  pan, vertical wobble locked `Y` and zeroed X for the gesture (and vice
  versa). Both axes now forward on every event; regression tests updated.
- **Version proof:** workspace version bumped `0.9.94` → `0.9.95`, so daemon
  logs show the new build ("did you launch the older version?" answered by
  the version string, not by trust).

### Desktop GUI (Windows-first, verified by screenshot loop)
- **Theme:** shared `Theme` palette (same values as Android): dark
  `#121212` / light white + black text + blue accents. Settings toggle
  persisted in `ui-theme.txt`; native widgets follow `Palette` in both
  modes.
- **Toggles:** all 7 std-widgets `Switch` replacements replaced with a
  custom smooth `ToggleSwitch` (pill + knob, no stair-step aliasing).
- **Dropdowns:** both std-widgets `ComboBox` replaced with a custom
  `DeviceDropdown` using the same pill/popup language as the role dropdown.
- **One Connect/Disconnect button:** the Connect-tab session strip is now
  a single toggle button (Connect ⇔ Disconnect). Nearby-device Connect
  rows hide while linked.
- **Advanced unreachable:** the trailing `vertical-stretch: 1` spacers made
  every tab's content exactly viewport-high, so nothing ever overflowed and
  `ScrollView` never scrolled. Replaced with a fixed 28px spacer, so the
  Advanced disclosure is reachable by scrolling. Verify by screenshot.
- **Multi-node on desktop:** Devices gains the same opt-in toggle, three
  mode chips, and a 5×3 grid overlay (grid lines, monitor-style cards with
  names, drag/tap-to-place, spinner). `Apply to all computers` sends a new
  `ControlRequest::PushMesh`; the daemon pushes bare `MeshConfig` frames
  (pinned, no input session, same fingerprint-checked pattern as
  `LinkEnded`) to every pinned peer, and each receiver rebuilds its
  `Layout` from the shared grid. Placements also persist locally so
  navigation works even if a peer is offline at apply time.
- **Not in this build (deliberate):** a desktop grid push requires peers'
  apps to be running (presence gate, as for any link). Peers that miss the
  push apply the identical grid from their own peer book when their user
  opens it.
