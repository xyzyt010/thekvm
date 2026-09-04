# Deployment templates

The files in this directory include a small Linux installer and platform
service templates for the first privileged receiver deployment. They are not
distribution packages: review the service account, device policy, firewall,
and display-seat assumptions for the target machine before broad deployment.

## Linux

From a source checkout, build a release binary and run
`sudo sh packaging/linux/install.sh --desktop-user "$USER"`. The user argument
may also be supplied through `THEKVM_DESKTOP_USER`; when invoked through
`sudo`, `SUDO_USER` is used if no explicit user is supplied. It installs
`kvm-daemon` (and `kvm-ui` when present) to `/usr/bin`, creates a `thekvm`
system user and group with access to the `input` group, enrolls the selected
desktop user in the daemon group, installs `linux/99-thekvm-uinput.rules`, and
loads/persists the `uinput` kernel module, verifies `/dev/uinput` exists, and
installs `linux/thekvmd.service` as `/etc/systemd/system/thekvmd.service`.
The receiver service is enabled automatically; set
`allow_lock_screen_control` through the UI or CLI. A fresh installation initializes
the daemon in strict `receiver-only` mode; select another role explicitly when
the host should also control peers:

```sh
kvm-daemon configure --mode bidirectional --allow-lock-screen-control
```

For automatic physical-input capture on a Linux controller, also install
`linux/thekvm-agent.service` and enable it after pairing peers and importing a
non-empty layout:

```sh
sudo install -m 0644 packaging/linux/thekvm-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now thekvm-agent.service
```

The agent reads the same `/var/lib/thekvm` identity, peer book, and topology as
the receiver daemon. It is intentionally a separate optional unit because it
has read access to physical `/dev/input/event*` devices and can begin sending
input before a desktop login. Do not enable it on a machine that should only
receive input.

The Linux system daemon must be validated against the target display manager
and seat before the distribution is called supported.

The daemon creates `/var/lib/thekvm/control.sock` with mode `0660`. The
installer enrolls the selected desktop user in the daemon's group so the UI can
control the system service without `sudo`; do not make the socket
world-writable. If no user was selected, add the intended user manually with
`sudo usermod -aG thekvm USER` and start a new login session.
The service unit uses `UMask=0007` and the data directory must be installed
with matching group ownership.

The packaged Linux UI connects to `/var/lib/thekvm/control.sock` by default,
while its temporary discovery identity remains in the logged-in user's config
directory. Set `THEKVM_CONTROL_DATA_DIR` only when the daemon uses a custom
control-data location; set `THEKVM_DATA_DIR` for a single-user development
setup where UI and daemon intentionally share all state.

Text clipboard synchronization is a separate normal-user-session capability.
Enable it from the UI or with `kvm-daemon configure --enable-clipboard` on both
peers, then run the controller from the logged-in desktop user. The boot-time
`thekvmd.service` and optional `thekvm-agent.service` deliberately do not read
or modify a user's clipboard. Updates are text-only and capped at 48 KiB.
Rich clipboard data and file transfer are not implemented. The installer does
not enable the optional physical-input controller; enable it only after
pairing and importing a trusted topology.

For topology mode on a logged-in Linux desktop, pair/configure a desktop-user
data directory, then install `linux/thekvm-agent-user.service` as a user unit:
`THEKVM_DATA_DIR=$HOME/.local/share/thekvm kvm-daemon pair <receiver>` and
`THEKVM_DATA_DIR=$HOME/.local/share/thekvm kvm-daemon configure --layout
<layout.json>`. The unit uses that private identity and inherits the desktop's
Wayland/X11 session environment; it tries the
compositor's input-capture portal/libei backend, which may require consent,
then uses XInput2 raw capture on X11, and falls back to evdev if neither
user-session backend is available. Logged-in X11 fixed-peer mode also uses
XInput2, while headless/pre-login fixed-peer capture uses privileged evdev.
Wayland fixed-peer capture remains portal/topology-only because the portal is
edge-based rather than a global desktop hook. The system
`thekvm-agent.service` remains the optional pre-login evdev controller; the
system and user controller units are alternatives.

## Windows

The daemon listens for metadata-only LAN discovery requests on UDP `42111` in
addition to the QUIC input port (`42110`). Discovery results are not trust
decisions:
the user must still confirm the displayed certificate fingerprint through
`kvm-daemon pair` or the UI pairing flow.

`windows/install-service.ps1` registers the daemon with the Service Control
Manager as LocalSystem. The service supervises an authenticated loopback
helper on `winsta0\\default`, and adds a second helper on
`winsta0\\winlogon` when a session explicitly requests lock-screen
capability. Both helpers are created from the active session's
`winlogon.exe` token. This is the required Windows privilege boundary for
post-boot sign-in and lock-screen input. Physical validation on supported
Windows versions is still required.

To enable the optional MWB-style controller side in the same boot service,
provide an already-paired peer during installation. A peer implies the
controller-only role unless `-Mode bidirectional` is supplied:

```powershell
.\windows\install-service.ps1 -PeerAddress "peer-host:42110" -DeviceName "Office workstation" -EnableLockScreenControl
```

The service then creates authenticated capture helpers on the Default and
Winlogon desktops, connects to that peer with retry, and suppresses local
input only after the remote session is established. Without `-PeerAddress`,
the installer selects the strict `receiver-only` role and clears any
previously saved auto-peer. To install a bidirectional service without a
boot-time controller, pass `-Mode bidirectional`. A configured auto-connect
peer is explicit privileged state and requires a service restart after
changes.

The service applies an explicit local-only SDDL ACL to the control named pipe.
The first slice grants LocalSystem, local administrators, and interactive users
access so the UI works without elevation. Before a broad release, replace the
interactive-users entry with a dedicated TheKVM desktop-user group.

For a receiver-only Windows service, run `kvm-daemon connect` as a logged-in
user startup task when using the configured topology, or
`kvm-daemon connect <peer-ip:42110>` for a fixed peer. The target's system
service listens at boot; this ordinary controller capture path remains
user-session scoped. `windows/install-agent.ps1` registers topology mode,
while `windows/install-agent.ps1 -PeerAddress <peer-ip:42110>` registers a
fixed-peer logon task with an interactive, non-elevated user token. The
explicit `-PeerAddress ... -EnableLockScreenControl` service-controller mode
documented above is the separate privileged exception for pre-login capture.
