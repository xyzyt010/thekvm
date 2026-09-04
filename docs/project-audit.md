# TheKVM project audit and lock-screen feasibility

**Audit date:** 2026-09-01  
**Repository:** TheKVM Rust workspace  
**Scope:** Windows, desktop Linux (Ubuntu/Debian, Fedora/RHEL, Arch), and
initial FreeBSD backend coverage; x86_64 and ARM64 where toolchains are
available; LAN keyboard/mouse sharing over QUIC.

## Executive verdict

The product idea is technically viable, including post-boot login and lock-screen input. The repository now has a buildable first vertical slice of the cross-OS KVM and the Windows service/helper boundary required for the lock-screen path. It is not yet a release-ready product: deployment, session lifecycle, compositor coverage, pairing hardening, and physical acceptance testing remain.

| Target | Verdict | Correct implementation boundary |
|---|---|---|
| Windows-to-Windows, normal desktop | Yes | User agent plus a normal Windows input backend |
| Windows-to-Windows, Windows sign-in/lock screen | Yes | Auto-start LocalSystem service plus SYSTEM helper process(es) in the target interactive session/desktop; this is the pattern used by current PowerToys Mouse Without Borders |
| Windows-to-Ubuntu, Ubuntu sign-in/lock screen | Technically yes after boot | A boot-start Linux system daemon must inject through persistent `/dev/uinput` virtual HID devices; Wayland portals are not the pre-login mechanism |
| Ubuntu-to-Ubuntu, Ubuntu sign-in/lock screen | Technically yes after boot | Same Linux receiver path on the target; the sender still needs a supported capture backend |
| FreeBSD-to-FreeBSD / FreeBSD receiver | Initial backend only | Shared evdev/uinput implementation plus rc.d/devfs templates; exact FreeBSD release and desktop/seat behavior must be validated |
| “Exactly identical to MWB on every Linux desktop” | No | Linux has no single Winlogon desktop or universal greeter/locker contract. Behavior must be validated per display manager, compositor, seat, and distro release |
| LUKS/BitLocker pre-OS unlock prompt | Not in the ordinary design | This is an initramfs/boot-environment problem, not a normal desktop daemon problem. Treat it as a separate product and threat model |

For the specific question—**is this possible for Ubuntu AMD64?**—the defensible answer is: **yes for the graphical login greeter and an already-running session lock screen, once the Linux kernel, network, input device, and graphical stack are up; no as a universal guarantee across all Ubuntu desktop configurations, and no for the normal pre-kernel LUKS prompt.**

### Implementation update

The first vertical slice has now been implemented after this audit: the wire
event model uses USB HID usages with explicit press/release and relative-motion
events; QUIC application messages are length-framed; pointer motion/wheel use
compact versioned binary datagrams; pairing has visible fingerprint
confirmation on both devices and saved-address sessions use TLS certificate
pinning; Linux
evdev/uinput, Wayland/libei, and XInput2 topology capture plus Windows Raw
Input and low-level hook/SendInput backends compile; and the daemon
enforces pairing, mode, port, and lock-screen request policy. The topology
router maps screen edges, propagates handoff coordinates and overshoot, and
can continue through another paired peer. The Windows SCM path launches SYSTEM
helpers in the active console session's Winlogon and Default desktops when the
peer requests the privileged capability, forwarding events through an
authenticated loopback bridge. The optional Windows boot-time controller path
now launches the same desktop-bound helper pattern for local capture, connects
to one explicitly configured paired peer with retry, suppresses local input
only after the remote session is accepted, and recreates the helpers when the
active console session changes; local revocation releases the active session
and stops that controller. The UI↔daemon control endpoint now owns live
configuration and daemon-identity pairing. The Linux topology controller path
now tries the compositor-mediated Wayland input-capture portal/libei backend,
then XInput2 raw capture on X11, and falls back to evdev when unavailable;
logged-in X11 fixed-peer mode also uses XInput2, while pre-login/headless
fixed-peer capture retains the global evdev path because the portal API is
edge-based rather than a global desktop hook.
Linux packaging validation, compositor-specific cursor positioning, and
physical lock-screen validation remain. Topology startup seeds the router from
the current Windows or X11 pointer when available, and failed handoffs restore
the saved local coordinate. The wire protocol now advertises the
configured logical screen geometry during the handshake and carries it with
topology handoffs, so different configured resolutions are mapped at both
directions without changing the legacy-peer path. X11 can perform a native
root-window pointer warp on restoration; Wayland arbitrary pointer warping is
still compositor-controlled and therefore remains unavailable here.

The daemon now records security-relevant pairing/session admission and
lock-screen capability decisions in a local `audit.log` without recording
keystrokes or pointer data. The Linux deployment templates now include both the
boot-time privileged receiver (`thekvmd.service`) and an explicitly optional
boot-time controller agent (`thekvm-agent.service`). Topology disconnect and
keepalive failure paths restore local pointer ownership and attempt platform
cursor restoration.
The daemon also answers metadata-only IPv4 LAN discovery requests on UDP
`42111`; discovery never bypasses fingerprint confirmation or peer admission.
Each receiver now holds a single input-session lease, rejecting a second live
controller while leaving pairing and discovery available. This keeps key/button
state deterministic when a stale controller reconnects or multiple trusted
peers are present.
The Slint UI can run the same scan and prefill a single discovered peer's
address, while polling daemon status so restarts and active-session changes are
visible without relaunching the UI.
The UI also reads the daemon-owned trusted-peer list, presents authenticated
incoming pairing requests for explicit approval/rejection, and can revoke a
fingerprint; the running daemon broadcasts revocation to active input sessions
so held controls are released immediately. The Windows LocalSystem
auto-controller consumes that cancellation and stops instead of reconnecting to
the revoked peer. The CLI prefers the same control endpoint and only edits the
peer file directly when the daemon is offline. Fingerprint input is
canonicalized case-insensitively.
Configuration updates are patch-like: omitted mode and lock-screen policy
fields preserve their current values, while the CLI exposes explicit enable and+disable switches. This prevents an unrelated device-name, layout, or port
change from silently widening privileged input policy. A fixed-peer capture now
starts with local input pass-through, enables exclusive capture only after the+authenticated state-sync handshake, and releases it again on peer loss, Ctrl+C,
or protocol failure.
Opt-in text clipboard synchronization is negotiated per input session and
works in fixed-peer and topology controller paths when both normal user
sessions expose a clipboard. It is bounded to 48 KiB per update and excludes
images, rich formats, history, and files; privileged pre-login services do not
attempt to access a desktop user's clipboard.
Windows identity keys are now stored as machine-bound DPAPI blobs, with a
legacy raw-key migration path. The Windows service installer configures the
shared `%ProgramData%\TheKVM` directory and ACLs it to SYSTEM and local
Administrators so the CLI and LocalSystem service cannot silently create
different daemon identities. Persistent configuration, peer, and identity
replacements use flushed temporary files; Windows uses `MoveFileExW` with
replace-and-write-through flags so an update does not delete the last good
state before the replacement is committed. The wire decoder also bounds and
validates peer names, certificate fingerprints, and rejection text before
those values enter pairing/session state.
The offline `kvm-daemon rotate-identity --yes` command replaces the local
certificate/key through the same flushed replacement path, refuses to run
while the daemon is live, and reports the new fingerprint so accepting peers
can be paired again.
The configured device name is authoritative across LAN discovery, pairing, and
session handshakes; it is bounded to 128 UTF-8 bytes and rejects control
characters, while older local UI control frames continue to preserve it.
Isolated Windows and native Linux two-daemon loopback runs completed
reciprocal pairing over separate QUIC ports in the strict
`server-client`/`receiver-only` role configuration. Each run queried the
receiver's pending queue and approved both network pairing requests through
the receiver control endpoint before trust was persisted. Each daemon then
reported the configured remote name, mode, and fingerprint in its status and
peer book, the receiver rejected a reverse send, and revocation was applied
live. This validates transport, two-sided consent, role enforcement, and state
exchange; it is not a substitute for real cross-machine input testing.
For incoming input sessions, the receiver now provisions its native injector
before sending `Accepted`; an unavailable Linux uinput device or Windows
interactive helper therefore rejects the session before the controller can
believe it has an active receiver. Daemon shutdown also converges process
signals (SIGINT/SIGTERM on Unix, Ctrl+C on Windows), SCM stop notification, the
QUIC endpoint, discovery responder, and local control server through the same
shutdown path.

## What is in this repository

The repository also includes a GitHub Actions matrix in
`.github/workflows/ci.yml`: native Windows and Linux workspace gates plus
ARM64 Linux and FreeBSD platform checks. Windows ARM64 is intentionally not
claimed by CI until a runner with the required ARM64 Windows SDK and C/C++
toolchain is used. The Windows job also runs the isolated two-daemon LAN role
and revocation check after building the release binaries; the Linux job runs
the matching Unix-socket integration gate.
`tools/lan-integration.ps1` provides an isolated Windows two-daemon LAN
acceptance run covering reciprocal QUIC pairing, strict one-way role
enforcement, configured names, status, and case-insensitive live revocation.
`tools/lan-integration.sh` provides the same gate for Linux/FreeBSD-style Unix
control endpoints.
The physical Windows/Linux lock-screen procedure is documented in
[`docs/acceptance-runbook.md`](acceptance-runbook.md); it explicitly separates
automated transport evidence from compositor/display-manager acceptance.

The workspace has five crates:

- `kvm-core`: serializable configuration, a platform-neutral input-event enum, and a geometry-aware screen layout/edge router.
- `kvm-protocol`: QUIC endpoint construction, certificate pinning/pairing,
  metadata-only LAN discovery, and a JSON peer book.
- `kvm-platform`: Linux evdev/uinput, Wayland/libei topology capture, and
  XInput2 topology capture, FreeBSD evdev/uinput injection, and Windows Raw
  Input plus low-level hook/SendInput backends.
- `kvm-daemon`: a command-line daemon with `serve`, `pair`, `discover`, `send`,
  `capture`, `connect`, `status`, `doctor`, `configure`, `rotate-identity`,
  `peers`, `unpair`, `pending-pairings`, `approve-pairing`, and
  `reject-pairing` commands. `doctor` performs read-only platform and
  desktop-session checks so
  missing uinput access or a missing Wayland/X11 environment is diagnosable
  before capture starts.
- `kvm-ui`: a Slint window with pairing, LAN discovery, live daemon status,
  bidirectional/controller-only/receiver-only mode and lock policy, and topology
 JSON import; incoming pairing approval/rejection is also exposed through the
 same local control endpoint.

The intended process split is sound in principle:

```text
unprivileged user agent / Slint UI
        | authenticated local IPC
privileged OS component
        | authenticated QUIC session
peer privileged OS component
        | native input injection
target desktop, greeter, or lock screen
```

The daemon provides the privileged network/input component. On Windows SCM
execution, the service does not inject from Session 0: it supervises SYSTEM
helpers in the interactive session. The Slint UI uses the local control
endpoint for live status/configuration and performs both sides of the pairing
consent flow; after the initiator confirms the fingerprint, the receiver must
approve the pending request before the daemon commits the peer to the
privileged peer book. See [`docs/control-plane.md`](control-plane.md).

## Current implementation findings

### Build and portability

- `cargo check --workspace --target x86_64-pc-windows-msvc` succeeds, including the Windows SCM/helper code.
- The Linux platform crate compiles for `aarch64-unknown-linux-musl`, including
  the portal/libei adapter, XInput2 raw capture, evdev/uinput ioctl declarations,
  and tests, when
  cross-compiling with `RUSTFLAGS="--cfg libei"`. The override is needed only
  because `input-capture 0.4.0` currently uses the build host's Unix cfg in
  its build script; a native Linux build does not need it.
- `cargo check -p kvm-platform --target x86_64-unknown-freebsd` succeeds,
  including the shared evdev/uinput backend.
- `cargo check -p kvm-core --target aarch64-pc-windows-msvc` succeeds.
- `cargo build --workspace --release`, `cargo test --workspace`, strict
  Clippy, and `cargo fmt --all -- --check` have been run successfully on the
  development host.
  Linux CI now also runs the same strict Clippy gate for the native Linux build.
- Native WSL2 Ubuntu x86_64 validation now succeeds for the complete workspace,
  including the Slint UI. The native Linux daemon release build succeeds, and
  the Linux platform unit suite passes all 14 tests. The complete native Linux
  release workspace build and workspace test run both succeed; the latest
  workspace test run passes 59 tests across the core, daemon, platform, and
  protocol crates. The September 2026 iteration re-validated the native Linux
  release workspace build (including the Slint UI with QR rendering) and the
  workspace test run passes 71 tests (13 core, 14 daemon, 14 platform,
  30 protocol); the Unix two-daemon LAN gate also passes with the new
  pairing verification-code assertions. Ready-to-run Windows x86_64 and
  Linux x86_64 builds ship in `dist/` with installers and a Mint ↔ Windows
  pairing guide. The first full-workspace attempt only failed because its isolated
  3.8 GB `/tmp` tmpfs filled during Slint compilation; placing Cargo's target
  directory on the host filesystem completed the same checks successfully.
- A Windows ARM64 workspace check remains toolchain-gated on this development
  host: Visual Studio's ARM64 MSVC compiler is installed, but the `ring`
  0.17.14 ARM64-Windows build path forces `clang`/`clang-cl`, which is not
  installed. A release environment also needs the matching ARM64 Windows SDK
  and linker environment. This is a release-environment prerequisite, not a
  Rust source diagnostic.
- Full daemon checks for non-host targets additionally require a target C
  compiler/sysroot for `ring`; the platform crate's ARM64 musl and FreeBSD
  checks are independent of that host-toolchain limitation.
- The source-checkout Linux installer places binaries under `/usr/bin` (the
  same path used by the systemd units), creates the dedicated receiver user,
  loads and persists the `uinput` kernel module, verifies `/dev/uinput`,
  installs the udev rule and service units, and enables only the receiver by
  default. It accepts `--desktop-user LOGIN` (or `THEKVM_DESKTOP_USER`) to
  enroll the logged-in desktop user in the daemon's control group; the optional
  controller unit remains an explicit operator choice.
- FreeBSD now compiles through the evdev/uinput backend shared with Linux;
  FreeBSD hardware, kernel-module, devfs-permission, desktop-seat, and
  pre-login behavior still require validation. Other BSDs remain unsupported.

### Event model and input correctness

The wire model in [`kvm-core/src/event.rs`](../kvm-core/src/event.rs) now uses
USB HID keyboard usages, relative pointer motion, explicit button/key
press-release state, wheel deltas, and packet sequence numbers. Linux and
Windows native namespaces are converted at the platform boundary. Receiver
backends maintain pressed-state ledgers and issue release-all on stream close;
the sender emits QUIC keep-alives during capture and the receiver applies a
15-second input lease so held state is released after a silent/dead sender.
Every newly established input stream also carries a bounded reliable snapshot
of the sender's currently held keys/buttons; the receiver releases its old
ledger and reconstructs that state before processing subsequent events. This
prevents a reconnect from losing a held modifier or leaving stale remote input
down. Capability negotiation carries the configured role and explicit
lock-screen request through the session handshake. Timestamping, peer/session
IDs, and richer loss recovery remain future protocol work.

### Topology geometry and cursor restoration

The session handshake carries an optional `ScreenGeometry` for each peer's
configured local screen. `PointerHandoff` and `HandoffRequest` repeat the
coordinate-space descriptor so the receiver/controller can remap positions
when two layout files use different dimensions. Mapping preserves `0` and the
last pixel as exact endpoints and keeps the old behavior when an older peer
omits the optional fields. The Linux X11 path uses `XWarpPointer` through the
root window for logged-in cursor restoration, and topology startup can seed the
router from the current root-window pointer. This is not yet a complete
multi-monitor/DPI implementation: screen geometry is currently configured
logical geometry, Wayland cannot be arbitrarily warped through the portal, and
physical compositor coverage is still required.

### Text clipboard synchronization

The wire protocol carries an explicit clipboard capability bit in `Hello` and
`Accepted`. Only when both peers accept it does the session exchange bounded
`ClipboardText` messages. Each direction has its own monotonically increasing
revision, and the receiving agent remembers the applied text so a remote write
does not immediately echo back. The platform adapter currently uses the
user-session clipboard on Windows, Linux, and the initial FreeBSD target; a
system service without a user's clipboard session simply declines the
capability. This is intentionally separate from pre-login input injection.

### Linux capture and injection

The Linux backend is now a real first implementation, but not yet a
distribution-complete backend:

- `evdev_capture` discovers device capabilities, filters non-keyboard/mouse
  nodes, ignores TheKVM virtual devices, preserves queued events, aggregates
  relative motion/wheel deltas through `SYN_REPORT`, and maps evdev keys to
  USB HID usages.
- `uinput` creates virtual keyboard and mouse devices, emits relative motion,
  buttons, wheel, and key transitions, tracks pressed state, and releases all
  state on teardown.
- `evdev_capture` periodically re-enumerates `/dev/input/event*`, avoids
  duplicate opens, drops disconnected nodes on `POLLHUP`/device errors, and
  filters kernel autorepeat notifications so a reconnect does not duplicate
  key presses. Each device tracks its held keys/buttons and queues synthetic
  releases before removal, preventing a physical hot-unplug from leaving the
  remote receiver stuck until the session lease expires.
- Linux receiver sessions are gated by the explicit
  `allow_lock_screen_control` configuration and paired-peer policy because
  the current evdev/uinput backend is below the compositor. Windows permits normal
  paired desktop sessions without that flag; requesting Winlogon access still
  requires explicit opt-in on both sides.
- Logged-in Linux topology sessions try the xdg-desktop-portal
  input-capture/libei backend. It installs barriers on all four edges,
  translates libei keyboard/button/relative-motion/scroll events into the
  shared wire model, retains fractional motion/scroll remainder, and releases
  compositor capture when the edge has no configured neighbor or the peer is
  unavailable. Portal consent and compositor support are required; failure
  falls back to evdev. Logged-in X11 fixed-peer mode uses the same XInput2
  backend without `/dev/input`; pre-login/headless fixed-peer mode remains on
  global evdev capture because the portal API does not provide a global
  desktop hook.
- Remaining work is X11 seat/lifecycle behavior, packaging validation, and a
  compatibility matrix for GDM, SDDM, LightDM, X11, Wayland, and multi-seat
  configurations. Physical compositor testing must confirm that XInput2
  grabs, portal barriers, and the relative router see the first handoff motion
  correctly on each supported stack.

For normal logged-in Wayland capture, use the compositor-mediated Remote Desktop/Input Capture and libei path where available. For the special receiver feature, use a small system daemon with persistent virtual HID devices. Those are different security directions: receiving remote input below the compositor is the requested privileged feature; capturing a local user’s physical input below the compositor should not be enabled casually.

### Windows lock-screen architecture

The Windows implementation now follows the documented privilege boundary; the
physical behavior still needs validation on supported Windows versions.

Microsoft documents that the interactive window station has `Default`, `ScreenSaver`, and `Winlogon` desktops; only one is the input desktop, and the Winlogon desktop ACL includes LocalSystem while ordinary applications generally cannot access it. See:

- [Windows desktops and the Winlogon ACL](https://learn.microsoft.com/en-us/windows/win32/winstation/desktops)
- [OpenInputDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-openinputdesktop)
- [SetThreadDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setthreaddesktop)
- [SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput)

However, Microsoft also documents that services run in Session 0, cannot directly interact with users on modern Windows, and should use a separate GUI/helper process in the interactive session. See [Interactive Services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services) and [CreateProcessAsUser](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera).

The current PowerToys Mouse Without Borders source makes the distinction concrete:

- [`Worker.cs`](https://github.com/microsoft/PowerToys/blob/main/src/modules/MouseWithoutBorders/App/Service/Worker.cs) is the service-side supervisor. It launches the application for `winlogon` and `default` desktops.
- [`NativeMethods.cs`](https://github.com/microsoft/PowerToys/blob/main/src/modules/MouseWithoutBorders/App/Service/NativeMethods.cs) finds the target session’s `winlogon` process, duplicates its token, sets `STARTUPINFO.lpDesktop` to `winsta0\<desktop>`, and calls `CreateProcessAsUser`.
- The normal application installs the low-level input hook in [`frmInputCallback.cs`](https://github.com/microsoft/PowerToys/blob/main/src/modules/MouseWithoutBorders/App/Form/frmInputCallback.cs).
- Microsoft’s user-facing documentation explicitly says that enabling **Use Service** allows Mouse Without Borders to control elevated applications and the lock screen, and warns about the additional security risk: [Mouse Without Borders](https://learn.microsoft.com/en-us/windows/powertoys/mouse-without-borders).

TheKVM now models the first Windows path as:

```text
SCM auto-start LocalSystem service in Session 0
        |
        +-- per-interactive-session SYSTEM helper on winsta0\winlogon
        +-- per-interactive-session SYSTEM helper on winsta0\default
        |
        +-- authenticated loopback IPC and lifecycle/session-change handling
```

Do not depend on the obsolete “Allow service to interact with desktop” checkbox. Do not assume that calling `SetThreadDesktop` from a Session 0 service is enough. A desktop-bound helper with no conflicting windows/hooks, recreated or reattached as desktop/session state changes, is the safer design to validate against current Windows versions.

The two long-lived helpers are not a blind fan-out: before each input event,
the helper queries its desktop's `UOI_IO` flag and only the active input desktop
calls `SendInput`; the inactive helper releases any stale local ledger. This
prevents duplicate keystrokes when both Default and Winlogon helpers are alive
during a desktop transition. Microsoft documents `GetUserObjectInformation`
and `UOI_IO` as the desktop input-ownership query: [GetUserObjectInformation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getuserobjectinformationa).

`WTSQueryUserToken` is appropriate for user-scoped work only when the service genuinely needs the logged-on user’s token; Microsoft marks it as a highly trusted service API. `SendSAS` is a separate optional secure-attention feature controlled by local policy, not a prerequisite for ordinary remote typing into an existing sign-in UI.

## Why the Linux answer is different

Linux’s normal desktop input path is layered differently. The kernel exposes evdev devices; compositors and display managers consume them. The kernel’s official uinput documentation states that a process can create a virtual input device through `/dev/uinput` and send events that are delivered to userspace and in-kernel consumers: [Linux kernel uinput documentation](https://docs.kernel.org/input/uinput.html).

That makes a boot-start daemon with a persistent virtual keyboard and mouse the right Linux mechanism. The daemon does not need to connect to a user’s X11 display or obtain a Wayland portal consent dialog in order to create the virtual device. The resulting event is presented to the input stack like a device, subject to the target machine’s seat and device policy.

There are still real limits:

- `libinput` requires input-device identification and assigns devices to physical/logical seats. Its documentation states that `ID_INPUT` plus an input-type property are required and that the default physical seat is `seat0`; multi-seat setups need deliberate assignment: [libinput udev device configuration](https://wayland.freedesktop.org/libinput/doc/latest/device-configuration-via-udev.html).
- Wayland’s Remote Desktop/Input Capture portal is session- and compositor-mediated. Starting a portal session typically presents a consent dialog, and the portal’s input transport is tied to libei: [Remote Desktop portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html) and [Input Capture portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.InputCapture.html). This is the correct path for normal user-session capture, but it cannot be the only pre-login design.
- A systemd **system** unit can start independently of a user login; a user unit is not equivalent. The daemon must keep the virtual devices alive across greeter/session transitions and must handle device re-enumeration and seat changes.
- Ubuntu desktop editions and versions can use different display managers, X11/Wayland sessions, lock-screen implementations, policies, and multi-seat arrangements. A successful `uinput` write proves kernel delivery, not a universal promise that every graphical authentication surface will accept every event in every configuration.

The Linux claim should therefore be “privileged kernel-level input injection can reach supported post-boot greeters and lock screens,” with an explicit compatibility matrix and test suite—not “Linux has the exact MWB feature.”

## QUIC and protocol assessment

QUIC is a reasonable transport choice. The current crate uses `quinn` with
TLS 1.3-capable rustls and ALPN. The application protocol is usable for the
first slice, with important production improvements still needed:

- JSON messages are protected by a bounded four-byte length frame on QUIC
  streams. Key/button transitions and control messages use the reliable
  ordered stream; pointer motion and wheel updates use bounded QUIC DATAGRAM
  messages with sequence numbers, receiver-side duplicate suppression, and a
  newest-motion ordering check so reordered datagrams cannot move the cursor
  backward during a busy LAN handoff.
  RFC 9221 defines QUIC DATAGRAM for secure unreliable application data that
  shares the connection’s authenticated context: [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html).
- Pairing intentionally accepts arbitrary certificates long enough to display
  and confirm a fingerprint. Normal sessions using a saved peer address now
  use a verifier backed by that persisted pin during the TLS handshake, and
  every session is still checked against the peer book before input injection.
  Manual addresses retain the application-layer fallback so they can resolve a
  hostname or newly configured address without weakening the admission check.
- The CLI and UI both require the initiator to confirm the displayed peer
  fingerprint. The receiver daemon now holds the authenticated request for
  explicit local approval/rejection before the peer is pinned; this prevents
  a user-only peer book from being mistaken for service authorization. Both
  endpoints additionally derive and display the same six-digit pairing
  verification code from the two certificate fingerprints (Bluetooth-style
  numeric comparison), the receiver's pairing challenge carries its own
  derivation, and the initiator aborts the ceremony automatically when the
  two derivations disagree. Pairing invites (`thekvm://` URLs carrying the
  LAN address and certificate fingerprint, rendered as QR codes in the UI's
  Invite tab and printable via `kvm-daemon invite`) remove address typing
  and pin the expected fingerprint before any trust is written. Decoding a
  QR with a camera on the pairing machine itself remains future work.
- Identity keys are protected with Windows DPAPI on supported Windows builds,
  with migration of pre-DPAPI raw keys; Unix keys remain ordinary files with
  restrictive permissions and still need Secret Service/keyring integration
  for a polished desktop deployment. The Windows installer explicitly points
  configuration at the service's shared `%ProgramData%\TheKVM` state directory
  so the installing user's profile cannot diverge from LocalSystem's state.

The protocol has a reliable control stream, a bounded framed key/button input
stream, compact binary pointer datagrams, monotonically increasing sequence
numbers, periodic QUIC liveness, explicit role/capability negotiation,
screen-edge handoff messages, reliable held-state resynchronization on session
creation, and mandatory release-all cleanup on normal close or a 15-second
input lease timeout. Peer/session IDs, stronger datagram loss recovery, and
cross-session replay protection remain future protocol work.

## Recommended delivery sequence

### Phase 0 — make the prototype honest and buildable

1. **Implemented for the first slice:** deterministic framing, helper-IPC, and
   input-state tests are covered by the repository CI gates.
2. **Implemented for the first slice:** the local UI↔daemon state model exposes
   status, configuration, peer listing, revocation, discovery, and diagnostics.
3. **Partially implemented:** Unix secret-store integration remains
   outstanding; mutual user confirmation is implemented in the daemon, CLI, UI,
   and control-plane tests, now including the six-digit pairing verification
   code displayed on both endpoints with automatic mismatch abort. Explicit
   offline identity rotation is also implemented and tested.
4. **Implemented in code; physical validation outstanding:** session-change
   recovery and helper recreation cover Windows console/RDP/fast-user-switch
   transitions.

### Phase 1 — one trustworthy end-to-end path

1. **Partially implemented:** Linux system packaging and udev policy are
   present; validate GDM/SDDM/LightDM plus X11/Wayland behavior on real hosts.
2. **Partially implemented:** Linux sender capture has X11, Wayland/libei,
   filtering, and hotplug foundations; complete seat, no-self-capture, and
   display/session lifecycle validation.
3. **Outstanding physical acceptance:** test the Windows service/helper path on
   normal desktop, UAC/elevated windows, sign-in, lock, fast user switch, RDP,
   sleep/resume, and disconnect cleanup.
4. **Outstanding physical acceptance:** complete Windows sender capture
   validation around Raw Input edge-safe motion and keyboard layout/scancode
   handling.
5. **Partially implemented:** pairing has fingerprint confirmation on both
   devices, certificate pinning, DPAPI/restricted-file storage, revocation, and
   explicit offline identity rotation; add Secret Service integration and
   physical multi-machine approval testing before release.

### Phase 2 — polished KVM behavior

Complete platform cursor boundary handling around the topology router, add
multi-monitor/DPI mapping and relative/absolute pointer negotiation,
rich clipboard formats, clipboard history, file transfer, diagnostics, audit
logs, and richer topology editing in the UI. Basic bounded text clipboard
sync is already implemented for normal user sessions. The current router and
platform exclusivity switches are the first working handoff layer, not final
cursor semantics.

### Phase 3 — compatibility expansion

Complete Fedora/RHEL, Arch, FreeBSD, and ARM64 packaging, then add the other
BSDs and publish a compatibility matrix only after automated and physical tests
establish what “supported” means for each compositor/display manager
combination.

## Minimum acceptance matrix

Before calling the lock-screen feature complete, test at least:

| Receiver | Session state | Required result |
|---|---|---|
| Ubuntu AMD64 + GDM + Wayland | login greeter | remote keyboard can focus/type into the intended credential fields; no stuck keys after disconnect |
| Ubuntu AMD64 + GDM + Wayland | locked user session | unlock UI receives keyboard/mouse events; normal user session resumes correctly |
| Ubuntu AMD64 + GDM + Xorg | greeter and lock | same as above |
| Ubuntu AMD64 + SDDM + Plasma Wayland | greeter and lock | either pass or explicitly report unsupported, with diagnostics |
| Ubuntu AMD64 + multiple seats | non-default seat | events go only to the approved seat |
| Windows 10/11 x86_64 and ARM64 | sign-in, lock, UAC, fast user switch | service/helper lifecycle and input delivery work without exposing an unauthenticated SYSTEM IPC surface |
| Any target | network loss during held key/button | all remote state is released or safely resynchronized |

Do not include LUKS or BitLocker unlock in this matrix. It requires an explicitly designed pre-OS network/input environment and should never be implied by “lock-screen support.”
