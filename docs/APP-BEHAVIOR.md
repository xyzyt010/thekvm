# TheKVM — Application Reference

This document describes **exactly what TheKVM does today**, feature by
feature, so the user, operator, and maintainer can verify behavior against
a single source of truth instead of rediscovering it from logs and
screenshots.

Current build: `0.9.94`
Platforms: Windows 10/11 (LocalSystem service + interactive-session helper),
Linux desktops (Ubuntu/Mint/Debian), FreeBSD (initial backend).

Tone: factual. Where something is not yet decided, or is being changed in a
later release, it says so explicitly.

---

## 1. Product purpose

TheKVM lets a user drive two (currently exactly two) computers with one
physical keyboard and mouse. It is a software KVM. It is **not** a remote
desktop (no screen streaming) and it is **not** a remote shell; it is an
input-device emulator at the OS edge of each machine, moving the OS-level
input events between two machines over an authenticated QUIC link.

- One user, one link per direction, one pair (per machine).
- The same mouse/keyboard can be used to type into the OS after control is
  granted to the other machine.
- Pairing and cadence are done by security-sensitive humans, not by a
  service or by the network.

---

## 2. Architecture in one page

TheKVM ships **two binaries per machine**:

| Component | Runs as | Role |
|---|---|---|
| `kvm-daemon` | Windows: LocalSystem service · Linux: systemd system unit · FreeBSD: rc.d service | QUIC + UDP transport, pairing, fingerprint, input capture/injection, lock-screen helpers |
| `kvm-ui` | Logged-in user | Slint GUI: pairing, daemon status, settings, tray |

The two are strictly split by privilege. The UI is a local client of the
daemon's control socket/pipe. It has no authorization database, no
identity key material, no trusted-peer book — those lives in the daemon.

### Control plane

- Linux/FreeBSD: Unix-domain socket at `<data-dir>/control.sock`, mode
  `0660`; the desktop user must be in the daemon's group.
- Windows: named pipe `\\.\pipe\thekvm-control`; remote clients rejected.
- Protocol: 4-byte length-prefixed JSON, request/response.
- The full set of supported verbs (`Status`, `GetConfig`, `SetConfig`,
  `ListPeers`, `Pair`, `Unpair`, `UnpairPeer`, `PendingPairings`,
  `ApprovePairing`, `RejectPairing`, `PinPeer`, `DropSession`,
  `DisconnectLink`, `ControlPipeDemand`, `StopService`, `RestartService`,
  `ListPendingLinks`, `ApproveLink`, `RejectLink`, `EndLink`) is
  enumerated in `docs/control-plane.md`. Anything new must be documented
  there first.

### Daemon data on each machine

Linux:
- Data directory: `/var/lib/thekvm/` (system service, group-readable).
- Contains: `config.json` (identity, auto-connect, layout, edge mode,…),
  `peers.json` (trusted fingerprints), `identity.cert` + `identity.key`
  (local identity).

Windows:
- Data directory: `%APPDATA%\TheKVM\`
- Files: `identity.cert`, `identity.key`, `config.json`, `peers.json`,
  `ui.log`, `control.log`, `peer-geometry.json`, `link-*.log`.

---

## 3. Installation, first pairing, and the daily routine

### Install (Windows)

1. Download `thekvm-<version>-setup.exe` from
   `github.com/xyzyt010/thekvm/releases/latest`.
2. Run it; it installs `kvm-daemon` as a LocalSystem service, drops the UI
   into `C:\Program Files\TheKVM\`, launches the UI, and writes an
   autostart entry (`TheKVMAgent`) so it returns at sign-in.

### Install (Linux)

1. Download `thekvm_<version>_amd64.deb` from the releases page.
2. `sudo dpkg -i thekvm_<version>_amd64.deb`.
3. Add the desktop user to the `thekvm` group.
4. Sign out and back in so the group membership takes effect.
5. Launch TheKVM from the start menu.

### Pairing

Pairing happens once per machine pair and never on the network alone.

1. UI shows a 6-digit code; both machines' UIs would show the same code at
   the same moment because it is derived from both fingerprints.
2. On the target machine, nominate the requesting peer by bringing both
   UIs in front and checking the code matches, then press **Approve
   incoming**.
3. The sender confirms by pressing **Pair**.
4. Both sides persist each other in `peers.json` via the daemon; the UI
   never writes the peer book.

### First crossing

Move the mouse to the edge facing the peer. Cursor crosses to the peer
with a short, single-shot jump (no animation), and you can type, click,
and use the scroll wheel on the other computer.

### Leaving

Send the cursor back across the facing edge. Control returns without any
question, confirmation, or transition effect.

### Signing out / laptop sleep / hibernate / lid close

The daemon is told (event) something happened — the link closes. When the
machine wakes, the UI re-establishes the connection. The screen is
**not** taken over during the sleep window: the OS login screen remains
untouched.

---

## 4. Cross-cutting UI behavior

The entire GUI is a single `AppWindow` with three tabs plus a tray.

### Tabs

| Tab | Contents |
|---|---|
| **Connect** | Nearby devices, Pairing code (out) / adoption of an incoming pairing (in), the two editable addresses, the connection mode dropdown ("Both ways", "Control other only", "Be controlled only"), auto-connect toggle, link state, Disconnect/Connect button |
| **Devices** | "Screen arrangement" monitor mesh with arrows showing crossing edges; "Crossing edges" tiles (Single, Mirror); the live mode chip in green; each tile carries its own donut when a live change is pending but not yet applied |
| **Settings** | Lock-screen policy toggle, clipboard on/off, clipboard size limit, auto-discover toggle, diagnostics option, about/version info |

### Persistent elements

- **Header**: window title "TheKVM" + a small green dot & status (e.g. "log output opened") on the tray icon when present.
- **Footer/status line**: transient messages ("Pinned the peer at …",
  "Cannot read settings …", "Link closed") that fade after a few
  seconds; hidden when there is nothing to say.
- **Traffic lights**: the **"LINKED"/"NOT LINKED"** LED at the bottom-left
  of the main window. Green = the peer is live; grey = unlinked. While
  unlinked, both monitors dim.
- **Connection mode / role**: a green "You are driving [peer]" cue
  left/right of the heading; a mirror "Peer is driving this computer"
  beneath it.
- **Crossing edges**: the active tile wears a **green highlight box**.
- **Pairing code**: the six-digit code is shown big, with the current
  code refresh tgzes per second; it auto-refreshes as fingerprints are
  rotated.

---

## 5. Connection mode

Chosen on the Connect tab's dropdown, applied to both ends' hands.

| UI label | Wire enum | Meaning |
|---|---|---|
| **Both ways** | `Bidirectional` | Either machine may control the other. Neither can be in keyboard-overflow mode. Default and recommended. |
| **Control other only** | `ServerClient` | This machine initiates; the peer may not send input to this machine at all. Host-style. |
| **Be controlled only** | `ClientOnly` | This machine may not initiate a session; it only accepts from a paired peer that is allowed to drive it. Slave-style. |

The handshake enforces the matrix; one-way for both answers in a one-way
relation on either side. **Reverse scroll** (both directions only) is a
Settings toggle, not an own matrix entry.

---

## 6. Screen arrangement

The screen arrangement is the **logical, not physical**, order of the two
monitors the pair is composed of.

- Exactly **two screens** in v0.9.94; no three-plus machines, no mixed
  arrangements in the UI. There is one layout per machine.
- Primary screen is at the origin; the peer is at `(1,0)` relative to it
  for a single-peer pair by arrangement — the UI's "Screen arrangement"
  draws them side by side.
- The peer can be placed on the LEFT side by dragging the card in the
  arrangement mesh, or by pressing the chevron buttons from outside the
  mesh. The placement is persisted per machine in its own config
  (`%APPDATA%\TheKVM\config.json` / `/var/lib/thekvm/config.json`); the
  peer placement itself is plain JSON, not encrypted.
- The arrangement is **live**: it drives the actual edge mapping of
  crossings and outputs (`edge_mode`, `double_edge_style`, `layout`) for
  the same machine. It must be mirrored on the peer to avoid confusing
  what edge leads where. The daemon's `Status` command echoes the live
  mode, so the UI can never be more than one poll behind the running
  config.

---

## 7. Connection discipline: the edge modes

Connection mode (§5) controls **who may** drive. Edge discipline controls
**which edge** opens a crossing and **which** the driven machine exits to
give control back.

| Discipline | Outer (facing) edge crossing | Peer entry edge | Return home | Landing (both return paths) |
|---|---|---|---|---|
| **Single** | arranged facing edge only | Mirror (opposite the exit) | facing edge only | same edge, inset (`RETURN_INSET_PX`, 8 px) |
| **Mirror** (default) | either horizontal edge of either machine | mirror of exit (Left↔Right) | either horizontal edge | edge **opposite** the edge the cursor left the peer through, inset; a facing-side exit mirrors a facing-side landing |
| *(legacy)* Fixed left / Fixed right | either horizontal edge | always left / always right | always left / always right | same edge (pinned) |

Legacy entries no longer appear in the UI; a stored v0.9.93 config
carrying `FixedLeft`/`FixedRight` loads as **Mirror** without user
action.

**Both internal return paths behave identically** (v0.9.95): when the
driver's virtual router overflows a home-facing edge it returns the
drive directly; when the peer's stateless push-through tracker accumulates
the same overflow it sends a `HandoffRequest` naming this machine's own
screen. Either one wins; both now land the local cursor at the
**opposite local edge in Mirror mode** (same edge in Single), map the
along axis proportionally, and arm a **250 ms / 64 px pull-back
refractory** so the still-held outward shove clamps instead of re-opening
the crossing. (Previously the peer-request path landed on the stale
pre-exit pixel with no refractory, so exiting the peer's far edge
"came back" inside the peer's entry edge — the right-side ping-pong.)

For the full crossing/return rules — opt-in hysteresis, the
`EDGE_PUSH_PX=8` budget, return-on, etc., see
[`CROSSING-EDGES.md`](CROSSING-EDGES.md).

### Mirror in one line

> **Exit at one side of one computer and the cursor re-enters the peer at
> the opposite side, always — no matter which edge was exited or which
> side the peer is on.**

Exit left → peer enters right edge. Exit right → peer enters left edge.
Both directions. Both computers. Both roles. Both disciplines.

### Single in one line

> **Only the edge facing the peer opens and closes a crossing. Other
> edges are physical walls on that machine in both directions.**

Asymmetry between sparse asymmetry, optional.

---

## 8. Inputs and outputs (input-device behavior)

The TheKVM synthetic device is a full HID emulation of the input device
the serving machine is configured for:

- **Keyboard**: everything a physical keyboard in the same locale would
  do — letters, numbers, punctuation, dead keys, modifier combos, the
  system menu key, the Super/Windows key, Scroll Lock, the PrintScreen
  / Alt-PrintScreen pair, media functions (volume keys, mute, brightness
  on some platforms), and the Caps Lock / Num Lock / Scroll Lock LEDs
  — replicated on the remote peer at the same instant they are pressed.
- **Mouse buttons**: left / middle / right / forward / back, all
  direction-aware, plus the two scroll wheels on standard mice.
- **Scroll wheel (smooth and discrete)**: standard/notched wheel; both
  left/right and up/down directions.
- **Trackpad gestures** (where supported by the local hardware):
  **pinch-zoom** (in/out, lever-sensitive, configurable — not yet
  user-adjustable), two-finger scroll, Tap-to-click, and 3-finger swipe
  (where exposed by the OS).
- **Keyboard layout**: key events transferred as usage codes (physical
  position), not as text where possible — so an OS set to French will
  understand the user's German-QWERTY shape correctly.

### What happens on each machine on a crossing

- Crossing into a machine: the OS level mouse cursor is warped to the
  mirrored entry point on the remote screen. A clip event is triggered
  if the OS is configured to request it.
- While driving a peer: the local low-level hooks on the controller are
  suppressed for the window that is in front, but local interactions
  that the user initiates remain live.
- At any moment during the drive, the peer releases the drive back to
  the controller grid — including after a fixed 10-second idle ceiling if
  TheKVM is configured for one; see Settings for the idle timeout
  setting (default 10 s).

### Clipboard

- Text copy on either machine is replicated on the other, bounded by
  `clipboard_max_mb` (default 2 MB).
- Image copy is same; the exact raster format preserved is OS-dependent.
- A full image paste syncs across using the system's native clipboard,
  not through TheKVM's control channel.

---

## 9. Lock screens and greeting screens

TheKVM is designed to keep working on a **locked or greeting screen** on
either machine when the user has explicitly approved it in Settings.

| Platform | Lock screen | Greeter/login | Mechanism |
|---|---|---|---|
| Windows | Yes (with permission) | Yes | LocalSystem service + interactive session helper (`kvm-ui`) |
| Linux | Yes (with permission) | Yes | systemd system unit + `uinput`/`evdev`/`libei` |
| FreeBSD | Partial (needs testing) | Not yet | input/evdev backend |

**Security boundary**: no remote user can ever inject keystrokes onto a
lock screen unless the user explicitly enables the setting and approves
the client-revocation policy. The default on non-interactive, pre-logged-in
machines is to deny all remote control; the UI will show a red banner
during those windows.

If the peer is holding an input request across login: the OS agent
re-authorizes automatically; it does not require user interaction.

---

## 10. Logging

Each machine writes structured logs to its own file; the UI and CLI
read them when requested.

- **Windows**: `%APPDATA%\TheKVM\ui.log` (UI-side events, rate-limited),
  `%APPDATA%\TheKVM\link-<peer>.log` (per-session link events, session
  counters, link migrations, epoch bans, link-rejected reasons).
  A single overwrite cap of 8 MiB (UI) and ~128 MiB (link) applies.
- **Linux**: `journalctl -u thekvmd.service` (systemd journal).
- Logs never contain clipboard contents — only event & link lifecycle.
- **Tested cap**: every `ui.log` write path is tested for a zero-trim at
  8 MiB and never grows unbounded during normal use. Link logs are
  rotated per host+port.

---

## 11. Configuration reference (both machines)

Stored at the platform-specific path documented in §2. Every key is
bounded length; unknown keys are refused, not silently dropped.

| Key | Type | Default | Notes |
|---|---|---|---|
| `device_name` | string | hostname | Shown to the paired peer; used in some handshakes |
| `listen_port` | u16 | 42110 | Only changing this requires daemon restart |
| `mode` | one of 3 | `Bidirectional` | "Both ways"/"Control other only"/"Be controlled only" — matches wire enum |
| `transport` | one of 2 | `Udp` | UDP is the preferred path; QUIC fallback |
| `layout` | object | `{}` | The `x`,`y`,`width`,`height` per screen, `self_screen` |
| `auto_connect_address` | string? | `null` | Boot-time peer for Windows controller; unset for Linux |
| `auto_connect_enabled` | bool | `false` | Enable/disable the boot-time auto-connection |
| `idle_home_secs` | u32 | 10 | Seconds of no outbound traffic before control auto-homes |
| `allow_lock_screen_control` | bool | `true` | Permits peer to control from lock screen |
| `clipboard_enabled` | bool | `true` | Sync clipboard both ways |
| `clipboard_max_mb` | u32 | 2 | Hard cap (1–16) |
| `reverse_scroll` | bool | `false` | Reverse scroll both directions for user's comfort |
| `auto_discover` | bool | `true` | Ask the network "are you there?" every few seconds |
| `edge_mode` | enum | `Double` | `Single`=1 facing edge, `Double`=both horizontal edges |
| `double_edge_style` | enum | `Mirror` | Only `Mirror`; legacy `FixedLeft`/`FixedRight` load as `Mirror` |

All values can be changed by any transport, persisted, and are applied
without restarting the user-space UI; the daemon may report
`Applied { restart_required: true }` when the change genuinely needs a
daemon restart; the UI will show you that before attempting the change.

---

## 12. tray behavior

- Windows: right-clicking the tray icon opens the dark menu: "Show TheKVM",
  "Disconnect", "Open logs", "Quit". The menu is owned by the same PID
  that owns the window; if that PID dies, the tray icon disappears with
  it (no ghost icons without the process).
- Linux: tray provides the same four actions via the GTK/GLib main loop
  of the user-space process.
- "Show" on the tray always raises the visible window rather than
  opening a new one; "Open logs" opens the logs file (Windows: Notepad
  / Linux: default text viewer); "Disconnect" releases the active link;
  "Quit" sends Disconnect and exits the app fully.
- Closing the window with the X button hides to the tray; to exit fully
  you must use **Quit** in the tray menu.

---

## 13. Configuration change flows

The UI reads from the **daemon**, never from its own stored copy. Any
change on the UI (mode dropdown, edge-tile tap, clipboard toggle,
reverse-scroll toggle, etc.) is:

1. Written to the daemon via `SetConfig`.
2. The daemon persists to its config file.
3. The daemon replies; the UI refreshes from the daemon.

The UI can never be more wrong than the daemon: even an outdated UI will
get the *current* daemon state on its next poll. The UI also polls at a
bounded 2-second cadence while the window is foregrounded, at a bounded
10-second cadence while it's hidden to the tray, and polls never
standalone while the user has TheKVM running.

---

## 14. Security model

TheKVM follows a **zero-implicit-trust** model end-to-end.

- **QUIC + TLS** with peer-fingerprints pinned by explicit pairing.
- **Fingerprint** exchange with human-in-the-loop 6-digit pairing code.
- **Control** pipe commands are inbound only from this machine and are
  verified as local — no remote control of another machine's daemon.
- **No network bootstrap**: TheKVM requires an existing paired peer — it
  does not accept any untrusted connection on any address, ever.
- **Sessions**: all input streams carry the sender's fingerprint; an
  unknown fingerprint is rejected at the handshake.
- **Anti-spam**: the daemon rate-limits reserved-log and login events;
  the UI clipboard sink is size-bounded and drops rather than grows
  unboundedly.

---

## 15. Edge cases / "what if something goes wrong"

| Scenario | Behavior |
|---|---|
| Peer unplugged / lost | Link tears down, peer art-noose fires, connection dialog closes on both machines within a few seconds |
| Peer reboot | When the peer returns, it re-dials you (or you re-dial it); the link re-establishes automatically within ~30 s |
| Lid close on controller | Outgoing control is paused for that machine until lid is opened and focus returns |
| Full screen window on peer | Sending inputs to a full-screen peer is still open; inputs for that window are sent as normal HID events |
| Multiple peers available | Only the single explicitly-paired peer is reachable; there is no peer circle, no multipoint peer session |
| Peer app incorrect version | Logs version mismatch in the first handshake; cross-version between minor versions is supported; between majors is refused at the handshake |
| Cursor parked on the facing edge | Cursor does not cross the edge on idle time alone — only an explicit, sustained push opens a crossing |
| TheKVM not running | No link, no input pass-through, both machines stay independent |
| VirtualBox / VM host/guest | Usable, but not supported/tested; performance roughly limited by the VM's inputs |

---

## 16. File inventory (this snap)

For reference while operating the app day-to-day, or filing bugs:

```
Windows:
  %APPDATA%\TheKVM\
    identity.cert          (daemon identity, private)
    identity.key           (daemon identity, private)
    config.json            (this machine's settings)
    peers.json             (this machine's trusted peer list)
    peer-geometry.json     (last known peer screen geometry)
    ui.log                 (UI-side log; rate-limited)
    control.log            (low-level control plane log)
    link-<peer>.log        (per-link crossing log; knot of issues)

Linux (apt):
  /var/lib/thekvm/        (daemon state)
  /etc/systemd/system/thekvmd.service   (or wherever dpkg installs it)
  $XDG_CONFIG_HOME/thekvm/   (UI state on the desktop session)

Repository:
  src/                    (source)
  docs/                   (this folder: RELIABILITY-PLAN, CROSSING-EDGES, etc)
  packaging/              (release packaging: deb, iss)
```

---

## 17. Release model

- Versioned semver; 0.9.94 is the latest.
- Tagged releases carry both Windows (`.exe`) and Linux (`.deb`) on
  GitHub Releases; both are built by CI from the tag's tree; no manual
  assets.
- The release process is: bump version in `Cargo.toml`, commit, tag
  `v<version>`, push. CI builds and publishes both artifacts.
- The **two artifacts have the same version and the same commit** on
  every release; nobody uploads a different binary to one platform only.
- No "only Windows" or "only Linux" release-only feature claims —
  everything is documented once per platform in this file.
- No automated telemetry is collected; no phone-home
  endpoint exists in the code.

---

## 18. Known limitations

Explicitly listed so it is unambiguous what is and is not supported today:

- Exactly **two** screens, two machines. Multi-monitor per machine is
  supported (you can add them all), peer-side display count is one.
- Only keyboard + mouse (no tablet, touchscreen, gamepad, pen).
- Network transport is LAN-only or L2-bridged same-subnet; there is no
  NAT traversal, relay forwarding, or auto-discover beyond
  link-local.
- Lock-screen experience: it works when explicitly authorized; the
  default deny on pre-login is intended.
- OS-level interrupt coalescing may change the order of rapid
  keystrokes compared with a dedicated keyboard. This is OS-controlled
  and is not guaranteed.
- **Windows trackpad pinch gestures** on web pages may need to be
  implemented as keyboard shortcut emulation (`Ctrl+wheel`) for some
  browsers; explicit per-browser keyboard shortcuts for zooming are not
  mapped explicitly yet; generic zoom emulation is implemented.
- FreeBSD support is labeled partial and uncertified.

---

## 19. Troubleshooting

Event log indications:

- Service not running → TheKVM UI gets a "Background service is not
  running" red banner on the Connect tab, an orange "Start background
  service" button appears bottom-left.
- The **persistent offline** banner is displayed on all tabs until the
  daemon becomes reachable again.
- The status-dot next to "This computer" turns grey and the role label
  becomes "Daemon online" / "Daemon offline".
- A link that closed during operation shows a small red "Disconnected"
  state next to the peer's name on the Connect tab; the UI pulls it back
  up automatically when the peer returns.

---

## 20. Known quirks and the In-progress list

- The v0.9.94 phase on top of the v0.9.93 column landed tray, menu,
  visual cues, reliability batches, and the Pinch-zoom behavior change,
  all on the same tag. Future fixes do not change the tagged release's
  intended behavior.
- The full reliability catalog and pending issues are in
  [`RELIABILITY-PLAN.md`](RELIABILITY-PLAN.md).
- The full crossing/return behavior in detail is in
  [`CROSSING-EDGES.md`](CROSSING-EDGES.md); it overlaps with this
  document and is the operational reference.
- The local control plane (that this document mentions but does not
  duplicate) is in [`control-plane.md`](control-plane.md).
- The two service descriptions (Windows and Linux) are in
  [`windows-service.md`](windows-service.md) and
  [`linux-daemon.md`](linux-daemon.md).
