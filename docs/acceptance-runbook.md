# TheKVM physical acceptance runbook

This runbook is for two disposable machines on a private LAN. It verifies
the actual input path, service startup, lock-screen behavior, and cleanup.
Build and protocol tests do not prove these desktop behaviors.

## Safety and test preparation

1. Do not use a production workstation or a machine containing unsaved work.
   The lock-screen option deliberately gives a paired peer privileged input
   reach.
2. Record the OS version, architecture, display manager, session type, active
   seat, and whether the machine is local-console or RDP/remote.
3. Keep a local keyboard available on every receiver. If a test misbehaves,
   stop the controller process or service and use the local keyboard to disable
   `allow_lock_screen_control` and unpair the peer.
4. Use a private LAN or an isolated VLAN. TheKVM discovery is metadata-only,
   but the QUIC listener must still be firewalled to the intended network.
5. Build the current source and record the commit/artifact hashes before each
   run:

   ```powershell
   cargo test --workspace
   cargo build --workspace --release
   ```

## Automated Windows LAN gate

On Windows, run the isolated transport check first:

```powershell
powershell -ExecutionPolicy Bypass -File tools/lan-integration.ps1
```

It starts two local daemon instances on separate QUIC ports and control pipes,
performs reciprocal pairing in the strict controller-only/receiver-only
configuration, verifies configured names and live status, proves that the
receiver rejects a reverse send, and revokes a peer using an uppercase
fingerprint. It does not inject into the desktop or test Winlogon.

On Linux or FreeBSD, run the Unix equivalent after a release build:

```sh
sh tools/lan-integration.sh
```

It uses isolated Unix control sockets and disposable state. Like the Windows
gate, it validates the authenticated control plane and role policy only; it
does not require `/dev/uinput` or a graphical session.

## Windows sign-in and lock-screen receiver

The target receiver must be tested with the LocalSystem service. The controller
may be another Windows service or a logged-in user agent for normal desktop
tests.

1. Install the binaries under a stable path such as
   `C:\Program Files\TheKVM`.
2. Configure and pair the target using the daemon-owned ProgramData directory.
   Pair from an elevated shell or through the UI's local control pipe:

   ```powershell
   $env:THEKVM_DATA_DIR = "$env:ProgramData\TheKVM"
   .\kvm-daemon.exe configure --device-name "Windows receiver" --allow-lock-screen-control
   .\kvm-daemon.exe pair <controller-ip>:42110
   ```

   Pair in the reverse direction when bidirectional control is required.
   For each pairing, approve the request on the receiving machine after it
   appears in the UI, or run `kvm-daemon pending-pairings` followed by
   `kvm-daemon approve-pairing <controller-fingerprint>`. Do not proceed
   until both daemon peer counts show the expected trusted peer.
3. Install/reinstall the receiver service:

   ```powershell
   .\packaging\windows\install-service.ps1 `
     -InstallDirectory "C:\Program Files\TheKVM" `
     -DataDirectory "$env:ProgramData\TheKVM" `
     -DeviceName "Windows receiver" `
     -Mode receiver-only `
     -EnableLockScreenControl
   ```

4. Confirm the service is running as `LocalSystem`, starts automatically, and
   listens on UDP `42110`. Confirm Windows Firewall allows the listener only on
   the intended profiles.
5. From the controller, establish the fixed-peer connection. Verify that the
   target's normal desktop receives keyboard, buttons, wheel, and relative
   pointer motion.
6. Lock the target with `Win+L`. Verify that the remote keyboard can focus the
   sign-in controls and enter a harmless test account's password. Verify that
   mouse movement/buttons do not duplicate when the target transitions between
   `Default` and `Winlogon`.
7. Sign in, lock again, unlock locally, and repeat after a service restart.
8. Test console disconnect/reconnect, fast-user switching, RDP connect/disconnect
   where applicable, sleep/resume, and a target reboot. The controller should
   retry without sending stale key or button state.
9. Disconnect the controller while holding a key and while holding a mouse
   button. Verify the target releases both within the input-session lease and
   does not retain the control after reconnect.
10. Revoke the controller fingerprint from the UI Trusted peers panel or:

    ```powershell
    .\kvm-daemon.exe unpair <controller-fingerprint>
    ```

    Verify an active receiver session closes and held input is released. A new
    connection from that fingerprint must be rejected.

## Ubuntu/Linux receiver: AMD64 graphical greeter and lock screen

This is the direct answer to the original Ubuntu AMD64 question: the feature
is testable after the kernel, network, graphical stack, and `/dev/uinput` are
available. It is not a LUKS pre-OS unlock feature and is not a universal
promise for every compositor.

1. Record the exact Ubuntu release and session:

   ```sh
   uname -a
   dpkg-query -W gdm3 sddm lightdm 2>/dev/null || true
   printf 'session=%s display=%s wayland=%s seat=%s\n' \
     "$XDG_SESSION_TYPE" "$DISPLAY" "$WAYLAND_DISPLAY" "$XDG_SEAT"
   ```

2. Build on Ubuntu or copy a native compatible release binary. Install the
   receiver using the source-checkout installer:

   ```sh
   cargo build --workspace --release
   sudo sh packaging/linux/install.sh
   sudo usermod -aG thekvm "$USER"
   # Start a fresh login after changing group membership.
   ```

   The installer loads and persists `uinput`, installs the udev rule, checks
   `/dev/uinput`, and enables only the receiver service. If `/dev/uinput` is
   absent, it must fail rather than report a false healthy installation.
3. Pair the target through the daemon control endpoint. From an elevated/root
   administrative shell when necessary:

   ```sh
   sudo THEKVM_DATA_DIR=/var/lib/thekvm kvm-daemon configure \
     --device-name "Ubuntu receiver" --allow-lock-screen-control
   sudo THEKVM_DATA_DIR=/var/lib/thekvm kvm-daemon pair <controller-ip>:42110
   sudo THEKVM_DATA_DIR=/var/lib/thekvm kvm-daemon pending-pairings
   sudo THEKVM_DATA_DIR=/var/lib/thekvm kvm-daemon approve-pairing <controller-fingerprint>
   sudo systemctl status thekvmd.service
   sudo THEKVM_DATA_DIR=/var/lib/thekvm kvm-daemon doctor
   ```

   Pair in the reverse direction for bidirectional control. The desktop user
   should approve each incoming request at the receiver before testing
   sessions. The desktop user should use the UI/control socket rather than
   copying the system daemon's private identity key.
4. With the Ubuntu target at its graphical login greeter, send a harmless
   keyboard sequence from a paired controller. Verify the expected field gets
   focus and that a disconnect releases held controls.
5. Log in, lock the session, and repeat keyboard, mouse, wheel, reconnect, and
   release tests. Repeat after restarting `thekvmd.service` and after reboot.
6. Run the same matrix for each target combination:

   | Display manager | Session | Result | Notes |
   |---|---|---|---|
   | GDM | Wayland | pass/fail | portal is for capture; receiver is uinput |
   | GDM | Xorg | pass/fail | separate greeter X server |
   | SDDM | Plasma Wayland/X11 | pass/fail | record Plasma version |
   | LightDM | X11 | pass/fail | record locker/greeter |

7. If the machine has multiple seats, verify events go only to the intended
   seat. If a compositor or greeter does not accept the virtual device, record
   it as an unsupported configuration with the `doctor` output; do not silently
   label it as Ubuntu-wide support.

## Linux controller capture

For a logged-in Wayland controller, install the user unit and allow the
compositor's input-capture consent prompt:

```sh
mkdir -p ~/.config/systemd/user
install -m 0644 packaging/linux/thekvm-agent-user.service \
  ~/.config/systemd/user/thekvm-agent-user.service
systemctl --user daemon-reload
systemctl --user enable --now thekvm-agent-user.service
```

Topology mode tries Wayland/libei, then XInput2 on X11, then privileged evdev.
Logged-in X11 fixed-peer mode also uses XInput2; a headless or pre-login
fixed-peer controller uses the privileged evdev path. Do not enable both the
system and user controller units on the same machine.

Verify topology by moving across every configured edge, including different
screen dimensions, returning control to the local screen, disconnecting the
peer at each edge, and reconnecting while a modifier is held.

## Evidence to retain

For every run, save:

- exact OS/kernel/architecture and display-manager/session details;
- `kvm-daemon doctor` output from the relevant user and system contexts;
- service status and firewall rules;
- the configured peer fingerprint and layout (never private identity keys);
- daemon stderr/journal output and `audit.log`;
- a result for each row of the matrix, including failures and reproductions.

The audit log records pairing, session admission, lock-screen capability, busy
session, and revocation boundaries without recording keystrokes or pointer
coordinates.

## Explicit non-goal

Neither the Windows service nor the Linux system daemon claims to control a
BitLocker or LUKS passphrase prompt before the normal operating system input
stack is running. That would require a separate pre-OS network/initramfs
design and a different threat model.
