# TheKVM

Cross-OS software KVM (keyboard/mouse sharing) over QUIC. Phase 1: Windows,
desktop Linux (Ubuntu/Debian, Fedora/RHEL, Arch), and an initial FreeBSD
evdev/uinput backend, with x86_64 and ARM64 targets where toolchains are
available.

Ready-to-run first-iteration builds for Windows x86_64 and Linux x86_64
(Ubuntu-family, including Linux Mint) live in [`dist/`](dist/) with a
5-minute Mint ↔ Windows pairing guide in [`dist/README.md`](dist/README.md).

## Current lock-screen verdict

Post-boot lock-screen and login-greeter input is feasible on Windows and on supported Ubuntu/Linux configurations, but the mechanisms are different and the behavior is not universally identical. Windows requires a LocalSystem service plus interactive-session helper processes; Linux requires a boot-start system daemon with kernel-level virtual HID injection through `/dev/uinput`.

The current code contains a buildable vertical slice: platform-neutral HID
events, framed QUIC control/key/button sessions, compact binary QUIC datagrams
for pointer motion, explicit fingerprint confirmation, Linux evdev/uinput
injection plus compositor-mediated Wayland/libei capture for topology user
sessions, Windows Raw Input plus low-level hook/SendInput backends, a live local control endpoint, a
LocalSystem SCM entry point, and the Windows interactive-session helper
bridge. The topology path now maps configured screen edges, activates the
selected peer, and can continue a handoff through another peer. UI
pairing is finalized by the daemon so the privileged service and the UI cannot
silently maintain different peer books. The deployment templates are still
starting points, and physical greeter, lock-screen, multi-session, cursor
positioning, and compositor compatibility testing remains.
See the full [project audit](docs/project-audit.md) for the evidence, limits,
and acceptance matrix.
The physical test procedure is in [docs/acceptance-runbook.md](docs/acceptance-runbook.md).

The repository CI matrix reproduces the native Windows/Linux gates and checks
the ARM64 Linux and FreeBSD platform backends on every push and pull request.
The Windows LAN integration check can be run with
`powershell -File tools/lan-integration.ps1`, and the Linux/FreeBSD-style Unix
check with `sh tools/lan-integration.sh`; both use isolated temporary state and
exercise strict controller/receiver roles, reciprocal pairing, authoritative
names, status, and revocation.

## Architecture

Two binaries per machine:

| Component | Runs as | Responsibilities |
|---|---|---|
| `kvm-daemon` | Windows: LocalSystem service · Linux: systemd system unit (`input` group) · FreeBSD: rc.d service | QUIC transport, pairing, input capture/injection incl. lock screen |
| `kvm-ui` | Logged-in user | Slint GUI: pairing UX, daemon status, settings |

## Crates

- `kvm-core` — shared types, config, event model
- `kvm-protocol` — QUIC transport (quinn), certificate-fingerprint pairing,
  wire messages
- `kvm-platform` — per-OS capture/inject backends (Linux evdev/uinput plus
  Wayland/libei and XInput2 topology capture, FreeBSD evdev/uinput, and Win32)
- `kvm-daemon` — privileged daemon binary
- `kvm-ui` — Slint desktop app

## Modes

1. **Bidirectional** — either machine may control the other when a session is connected
2. **Controller only** — configure the server/controller with `--mode
   server-client`; it initiates sessions and accepts no incoming control
3. **Receiver only** — configure the client/receiver with `--mode
   receiver-only`; it accepts paired incoming control and cannot initiate input

For a strict one-way setup, use `server-client` on the controlling machine and
`receiver-only` on the controlled machine. The handshake enforces both local
roles, so a receiver-only peer cannot quietly initiate a reverse session.

## First vertical slice

Build the workspace with `cargo build --workspace`. On two machines, set the
same `THEKVM_DATA_DIR` convention for the daemon and UI during development,
start `kvm-daemon serve`, pair each peer with `kvm-daemon pair <ip:port>`, and
enable the privileged receiver explicitly:

```text
kvm-daemon configure --mode bidirectional --allow-lock-screen-control
# optional friendly name used by LAN discovery, pairing, and session handshakes
kvm-daemon configure --device-name "Office workstation"
# optional Windows service controller peer (boot-time MWB-style path)
kvm-daemon configure --auto-connect <peer-ip:42110> --allow-lock-screen-control
# print this machine's pairing invite (address + fingerprint in one string)
kvm-daemon invite
# pair from an invite: the fingerprint is pinned before any trust is written
kvm-daemon pair thekvm://v1/<peer-ip:42110>#<fingerprint>
# optional topology import
kvm-daemon configure --layout ./layout.json
kvm-daemon capture <peer-ip:42110>
# startup/login agent: retry until the peer is available
kvm-daemon connect <peer-ip:42110>
# topology mode: edge-handoff to the peer mapped in layout.json
kvm-daemon connect
kvm-daemon doctor
```

`kvm-daemon send <peer-ip:42110>` sends a press/release test for the requested
USB HID usage (`0x04` is A). The Linux receiver and optional controller service
templates are in
`packaging/linux`; the Windows service installer is in `packaging/windows`.
For a source-checkout Linux installation, build with `cargo build --release`
and run `sudo sh packaging/linux/install.sh`; it installs and enables only the
receiver service. The optional physical-input controller remains a separate
explicit enablement step after pairing and topology configuration.
Use `kvm-daemon discover` to find responding TheKVM receivers on the local
IPv4 LAN before pairing; discovery only returns a name, QUIC port, and
certificate fingerprint, and never authorizes input.
Use `kvm-daemon peers` to inspect trusted fingerprints and
`kvm-daemon unpair <fingerprint>` to revoke one.
`kvm-daemon status` queries the running daemon over the local control endpoint.
The UI's Trusted peers panel provides the same list and revocation action.
Configuration updates are patch-like: omitting `--mode` or either lock-screen
policy switch preserves the existing value. Use
`--allow-lock-screen-control` or `--disable-lock-screen-control` when changing
that policy explicitly.
Pairing requires consent on both devices: the initiating user confirms the
displayed peer fingerprint, then the receiving UI shows the pending request.
Approve it with **Approve incoming** or
`kvm-daemon approve-pairing <fingerprint>`; inspect or reject requests with
`kvm-daemon pending-pairings` and `kvm-daemon reject-pairing <fingerprint>`.
The peer is not added to either trusted-peer book until both sides complete
this exchange. Both endpoints also derive and display the same six-digit
**pairing verification code** from the two certificate fingerprints — compare
it across the two machines before confirming, exactly like Bluetooth numeric
comparison. The receiver's challenge carries its own derivation of the code
and the initiator aborts the pairing automatically when the two derivations
disagree, which would indicate a relayed connection presenting different
certificates to each side.
To deliberately replace this machine's certificate/key identity, stop the
daemon and run `kvm-daemon rotate-identity --yes`; peers that accept this
machine must then be paired again against the new fingerprint.

The `capture` command is a fixed-peer diagnostic sender. `connect` keeps the
capture backend alive and retries the QUIC session after a peer/network
failure, making it suitable for a user-session startup entry. With no address,
`connect` uses the configured layout and paired peer addresses for edge
handoff. The layout schema and tested edge-router state machine are in
`kvm-core` and can be imported with `--layout`; topology `connect` uses that
router with relative pointer handoff and QUIC datagrams. Each newly connected
session also receives a reliable snapshot of held keys/buttons, so a reconnect
does not silently lose a modifier or preserve stale remote input. Handoff
coordinates now negotiate the configured logical screen geometry and preserve
the inclusive screen edges. X11 sessions also attempt native pointer warping
when control returns; Wayland intentionally cannot provide arbitrary pointer
warping through the portal, and runtime multi-monitor/DPI discovery is still
future work. Topology startup seeds the router from the current Windows or X11
pointer when the platform exposes that position, and restores the saved local
coordinate after a failed remote handoff. Opt-in text-only clipboard synchronization is available for normal
logged-in sessions when both peers enable it; rich clipboard formats,
clipboard history, and file transfer remain future work.

On Windows, relative mouse motion is captured through a hidden message-only
window registered with Raw Input (`RIDEV_INPUTSINK`), so movement continues to
arrive when the pointer is parked at a local screen edge. The low-level mouse
hook remains responsible for buttons, wheel, and local-event suppression, and
is also retained as a fallback if Raw Input registration fails. Synthetic
`SendInput` events are excluded from the low-level capture path.

Each receiver admits one live input controller at a time. A second trusted peer
is rejected with an auditable busy response instead of racing virtual keyboard
and mouse state; pairing and discovery remain available while that session is
active.

The current Linux receiver backend is deliberately privileged: it writes
virtual HID devices through `/dev/uinput`, so Linux sessions require the local
`allow_lock_screen_control` opt-in. Windows also supports ordinary paired
desktop sessions without that flag; only a session requesting Winlogon access
requires the capability on both sides. For topology mode, a logged-in Linux
Wayland controller tries the compositor-mediated input-capture portal/libei
backend, then XInput2 on X11, and finally evdev. The portal is consent-based
and session-scoped; it does not provide pre-login capture. On logged-in Linux
X11 sessions, fixed-peer mode uses XInput2 without requiring `/dev/input`;
headless/pre-login fixed-peer capture retains the privileged evdev path, while
Wayland fixed-peer capture requires the compositor-mediated topology path.

The Linux evdev capture backend tracks pressed controls per physical device and
queues release events when a device disconnects. This prevents a pulled or
hot-unplugged keyboard/mouse from leaving remote state held until the network
lease expires.

Clipboard synchronization is deliberately independent of privileged input. It
is negotiated in the QUIC handshake, bounded to 48 KiB per text update, and
does not run from the LocalSystem/Linux system-daemon pre-login paths because
those processes do not own the logged-in user's clipboard session. Start the
controller from the logged-in user session when clipboard sync is required.

On Windows, `packaging/windows/install-service.ps1` can optionally configure
the LocalSystem service as a boot-time controller as well as a receiver. Pass
`-PeerAddress <peer-ip:42110> -EnableLockScreenControl` after pairing. The
service then uses desktop-bound capture helpers on Default and Winlogon; omit
the peer argument for receiver-only operation. Revoking that peer releases the
active service-controller session and stops its retry loop. A service restart is
required after changing this setting.
The installer stores service state in `%ProgramData%\TheKVM`, protects the
identity key with machine-bound DPAPI, and applies a local SYSTEM/
Administrators ACL to keep the service and CLI on one daemon identity. State
files use flushed replacement writes; Windows uses a replace-and-write-through
file move so an update cannot delete the previous valid state first.
