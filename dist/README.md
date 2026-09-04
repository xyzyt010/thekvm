# TheKVM first-iteration binaries

Two ready-to-run builds of the same 0.1.1 workspace, verified by the
repository gates on the build machine (Windows `lan-integration.ps1` and
Linux `lan-integration.sh` both pass, including the six-digit pairing
verification-code assertions).

The Linux binaries are linked against a glibc 2.35 baseline, so they run on
Ubuntu 22.04 / Linux Mint 21 and everything newer (Mint 22, Debian 12,
Fedora, Arch). The Windows and Linux installers are self-contained: they
copy the binaries from their own directory and, on Linux, auto-install the
UI's fontconfig dependency via apt/dnf/pacman/zypper/apk.

| Folder | Target | Binaries |
|---|---|---|
| `windows-x86_64` | Windows 10/11 x86_64 | `kvm-daemon.exe`, `kvm-ui.exe`, `install-service.ps1`, `install-agent.ps1` |
| `linux-x86_64` | Ubuntu/Debian-family x86_64 incl. Linux Mint 21+ | `kvm-daemon`, `kvm-ui`, udev rule, systemd units, `install.sh` |

The Linux daemon links only glibc/libgcc/libm. The Linux UI additionally
needs the desktop font stack (`libfontconfig1`, present by default on Mint
and Ubuntu desktops). ARM64 and FreeBSD builds remain toolchain-gated as
documented in `docs/project-audit.md`.

## 5-minute Mint ↔ Windows pairing (LAN)

Do this once on each machine, with both on the same LAN:

1. **Windows** — install and start the receiver service (elevated PowerShell
   in `windows-x86_64`):
   ```powershell
   .\install-service.ps1 -DeviceName "Windows desk"
   ```
   Then open the UI (`kvm-ui.exe`), note the **Local address** on the Status
   tab (for example `192.168.1.20:42110`).
2. **Linux Mint** — install the receiver (terminal in `linux-x86_64`):
   ```sh
   sudo sh install.sh --desktop-user "$USER"
   ```
   Launch `kvm-ui`, open the **Invite** tab: it shows this machine's invite
   as a QR code plus copyable `thekvm://…` text containing its LAN address
   and certificate fingerprint.
3. **Pair** — on the Windows UI **Pair** tab, either paste the Mint invite
   (address field accepts `thekvm://` URLs and pins the fingerprint from
   the start) or type the Mint LAN address and press **Pair**.
4. **Compare the six-digit verification code** shown on both screens. They
   must be identical; approving mismatched codes is the one step that stops
   a machine-in-the-middle.
5. **Approve** the incoming request on the Mint UI (or
   `kvm-daemon approve-pairing <fingerprint>`). Both peer books now trust
   each other.
6. **Control** — run `kvm-daemon connect <peer-ip:42110>` on the controller
   (or import a `layout.json` topology and run bare `kvm-daemon connect`
   for screen-edge handoff), or set the Windows boot-time controller peer
   in the UI Settings tab.

Modes: **Bidirectional** (either side may control the other),
**Controller only** (`server-client`), **Receiver only** (`receiver-only`).
For strict one-way control, set server-client on the controller and
receiver-only on the controlled machine; the handshake enforces both roles.

## Lock-screen coverage in this build

- **Windows → Windows sign-in/lock screen:** the LocalSystem service plus its
  Winlogon/Default desktop helpers deliver input to the credential UI.
  Enable **Allow lock-screen control** on both peers.
- **Windows/Linux → Linux greeter or lock screen:** the systemd receiver
  injects through `/dev/uinput` virtual HID below the display stack, so the
  GDM/SDDM/LightDM greeter and a locked session accept remote input once the
  kernel, network, and graphical stack are up. Requires the same explicit
  opt-in on the Linux receiver.
- **Not covered by design:** LUKS/BitLocker pre-OS unlock prompts. See
  `docs/project-audit.md` for the compatibility matrix and the physical
  acceptance runbook in `docs/acceptance-runbook.md`.
