# Linux: uinput system daemon (lock-screen + greeter control)

Targeted at Ubuntu/Debian, Fedora/RHEL, and Arch — x86_64 and ARM64.
Post-boot greeter and lock-screen control is supported only after validation
for the selected display manager, compositor, seat, and input policy.

## Why it works

`/dev/uinput` creates virtual input devices at the kernel evdev layer — below
X11, Wayland, and a particular greeter. Correct device classification and seat
assignment are still required; this is a privileged equivalent, not an exact
Linux copy of Windows' Winlogon desktop model.

Deskflow/Barrier's ordinary per-user backends cannot use this pre-login path;
the receiver must be a separately privileged system daemon.

## Install steps

### 1. udev rule (no root needed at runtime)

```bash
# /etc/udev/rules.d/99-thekvm-uinput.rules
KERNEL=="uinput", GROUP="input", MODE="0660"
```

```bash
sudo udevadm control --reload && sudo udevadm trigger
```

### 2. Dedicated system user

```bash
sudo groupadd --system thekvm
sudo useradd --system --gid thekvm --groups input --home-dir /var/lib/thekvm --create-home thekvm
sudo install -d -o thekvm -g thekvm -m 0770 /var/lib/thekvm
```

### 3. systemd system unit (NOT a user unit — user units start after login)

```ini
# /etc/systemd/system/thekvmd.service
[Unit]
Description=TheKVM cross-OS KVM privileged input daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=thekvm
SupplementaryGroups=input
ExecStart=/usr/bin/kvm-daemon serve
Restart=on-failure
RestartSec=3
# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/thekvm
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now thekvmd.service
```

The daemon creates `/var/lib/thekvm/control.sock` with mode `0660` for the
desktop UI and administrative CLI. The source-checkout installer can enroll
the intended desktop user automatically:

```bash
sudo sh packaging/linux/install.sh --desktop-user "$USER"
```

If the installer was run without that option, use the equivalent manual
enrollment command:

```bash
sudo usermod -aG thekvm "$USER"
```

Start a new login session after changing group membership. Do not make the
socket world-writable: its `SetConfig` and `Pair` operations affect a
privileged daemon.

`WantedBy=multi-user.target` starts the daemon at boot, before any login. This
keeps the receiver available early; it does not by itself prove that every
greeter or lock screen accepts the virtual device.

The source-checkout installer loads the `uinput` kernel module immediately,
persists it in `/etc/modules-load.d/thekvm.conf`, reloads the udev rule, and
refuses to finish if `/dev/uinput` is still absent. The system unit also has a
`ConditionPathExists=/dev/uinput` guard. This makes a missing kernel input
device an explicit installation/service failure instead of a misleading
healthy-looking daemon with no receiver path.

The system daemon intentionally does not read a desktop user's clipboard.
Text clipboard synchronization is opt-in and session-scoped: run the
controller (`kvm-daemon connect` or `capture`) from the logged-in desktop user
when both peers have enabled the setting. It is limited to UTF-8 text updates
of at most 48 KiB; images, rich formats, clipboard history, and file transfer
are not included.

### Optional pre-login controller startup

`packaging/linux/thekvm-agent.service` is a separate system unit for a Linux
machine whose physical keyboard and mouse should automatically control the
configured topology. Install and enable it only after pairing peers and
importing a non-empty layout:

```bash
sudo install -m 0644 packaging/linux/thekvm-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now thekvm-agent.service
```

The agent opens `/dev/input/event*` as the `thekvm` service user and starts
before a desktop login. This is a privileged capture path: a remote paired
peer can receive physical input, and the local configured capability can make
the peer's receiver usable at its greeter or lock screen. Keep the unit
disabled on receiver-only machines. Because it is a system service, it cannot
use a logged-in user's Wayland portal, X11 display, or clipboard.

### Optional logged-in desktop controller

For topology capture through Wayland/libei or XInput2, install the separate
user unit after the desktop user has been added to the `thekvm` group:

```bash
mkdir -p ~/.config/systemd/user
install -m 0644 packaging/linux/thekvm-agent-user.service \
  ~/.config/systemd/user/thekvm-agent-user.service
systemctl --user daemon-reload
systemctl --user enable --now thekvm-agent-user.service
```

This unit inherits `WAYLAND_DISPLAY`, `DISPLAY`, and the session D-Bus
environment. It uses the desktop user's own
`~/.local/share/thekvm` identity, peer book, and layout; do not point it at the
system daemon's `/var/lib/thekvm` because the private identity key is
intentionally readable only by the service account. Pair and configure the
desktop controller as that user before enabling the unit:

```bash
mkdir -p ~/.local/share/thekvm
export THEKVM_DATA_DIR="$HOME/.local/share/thekvm"
kvm-daemon pair <receiver-ip:42110>
kvm-daemon configure --layout ./layout.json --enable-clipboard
```

It is the recommended controller for normal logged-in desktop use and for
text clipboard synchronization. The system unit and this user unit are
alternatives; do not enable both on one controller.

### 4. Firewall

```bash
# Ubuntu/Debian
sudo ufw allow 42110/udp
# Fedora/RHEL
sudo firewall-cmd --permanent --add-port=42110/udp && sudo firewall-cmd --reload
# Arch (iptables/nftables per your setup)
```

## Scope boundary (honest parity with MWB)

Covered target: OS kernel and normal input stack are up, with a login greeter
or lock screen showing. Not covered by this ordinary daemon: a LUKS passphrase
at boot; that would require a separate initramfs/early-network design.

## Capture side (sending machine)

Stay inside the compositor's security model:
- Topology Wayland: libei + Input Capture portal (consent-respecting). The
  `kvm-daemon connect` path tries this backend when launched inside the
  logged-in desktop session. It captures the four screen edges, translates
  libei events into TheKVM's shared HID/relative-motion model, and releases
  compositor capture when the edge has no configured neighbor or a peer is
  unavailable. The portal may display a compositor consent prompt and falls
  back to evdev when unavailable.
- Fixed-peer Linux: logged-in X11 sessions use XInput2 without opening
  `/dev/input`; headless/pre-login sessions use the privileged global evdev
  path. Wayland remains portal/topology-only because the Input Capture portal
  is edge-based rather than a global desktop hook.
- Topology X11: XInput2 raw capture is used without opening `/dev/input`; TheKVM
  grabs all master devices only while a remote topology screen is active and
  releases the grab when control returns locally. If XInput2 is unavailable,
  the path falls back to evdev. Logged-in X11 sessions also use the root-window
  pointer warp path when a topology handoff restores local control. This is
  bounded to the configured logical screen coordinates; multi-monitor offsets
  and compositor-specific DPI transforms are not discovered yet.

Do NOT route capture through uinput too — injection-below-the-compositor is
the feature; capture-below-the-compositor would be a security hole.

## Diagnostics

Run `kvm-daemon doctor` from the same context that will run the controller or
receiver. It reports read-only checks for `/dev/uinput`, `/dev/input`, the
Wayland/X11/D-Bus session environment, and the selected topology capture order.
It does not create devices, grab input, or modify configuration. A user-session
controller should be diagnosed from the logged-in desktop; a pre-login
receiver should be diagnosed through the system service account.
