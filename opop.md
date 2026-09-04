# Modernizing Software KVM: Research Findings & Technical Blueprint

**Scope:** Wireless, cross-OS keyboard/mouse sharing ("software KVM"). Phase 1 target: Windows + Desktop Linux (Ubuntu/Debian, Fedora/RHEL, Arch — x86_64 and ARM64).
**Research date:** August 2026.

> **Status note:** This is the original design draft. Its lock-screen sections contain simplified assumptions that are corrected by the later audit in [`docs/project-audit.md`](docs/project-audit.md). In particular, Windows uses interactive helper processes launched onto the target desktop, while Linux support is conditional on the display manager, compositor, seat, and input-stack configuration.

---

## Table of Contents

1. [Competitive landscape — what exists today](#1-competitive-landscape)
2. [Why the incumbents fall short](#2-why-the-incumbents-fall-short)
3. [The core mystery, solved: how Mouse Without Borders controls the lock screen](#3-the-core-mystery-solved)
4. [Step-by-step: recreating this exactly on Windows](#4-step-by-step-windows)
5. [Can Linux do this? Yes — but via a different mechanism](#5-linux-equivalent)
6. [Step-by-step: recreating this on Linux](#6-step-by-step-linux)
7. [Security hardening: don't repeat MWB's mistakes](#7-security-hardening)
8. [Recommended architecture for your Phase 1 build](#8-recommended-architecture)
9. [Packaging plan (Ubuntu/Debian, Fedora/RHEL, Arch — x86_64 + ARM64)](#9-packaging-plan)
10. [Reference list](#10-references)

---

## 1. Competitive landscape

| Tool | License / Cost | Platforms | Linux ARM64 | Wayland | Protocol | Pre-login / lock-screen control | Status (2026) |
|---|---|---|---|---|---|---|---|
| **Deskflow** | Free, OSS | Win / macOS / Linux (X11+Wayland) / BSD | Yes (Arch Linux ARM, Fedora aarch64, Flatpak) | Yes, via libei + xdg-desktop-portal | Custom event protocol over TCP, TLS by default | No | Actively developed; widely seen as the current best all-rounder |
| **Input Leap** | Free, OSS | Win / macOS / Linux (X11, partial Wayland) | Partial | Partial (libei merged, depends on compositor/portal) | Same lineage as Barrier/Synergy 1.x | No | Development has slowed; many contributors moved to Deskflow |
| **Barrier** | Free, OSS | Win / macOS / Linux (X11 only) / BSD | Limited | No | Synergy 1.9 fork | No | Officially discontinued/unmaintained; successor is Input Leap |
| **Synergy 3 (Symless)** | Commercial, $29–39+ (tiered Lite/Max) | Win / macOS / Linux | Via AUR/community packages | Improving | Proprietary | No | Actively sold and maintained; GPL-2 roots, now closed commercial layer |
| **Lan Mouse** | Free, OSS | Win / macOS / Linux (X11+Wayland) | Yes — pure Rust, cross-compiles cleanly | Yes — libei, portal, or layer-shell backend per compositor | DTLS-encrypted UDP (WebRTC.rs), mandatory encryption | No | Small active team; the most modern *engine* of the open-source options |
| **Mouse Without Borders** (Microsoft Garage / now in PowerToys) | Free, OSS (MIT, inside `microsoft/PowerToys`) | **Windows only** | N/A | N/A | Custom TCP protocol, ports 15100/15101, pre-shared key | **Yes** — this is its defining feature | Actively developed as a first-party PowerToys module |
| **ShareMouse** | Freemium/paid | **Windows + macOS only — no Linux** | N/A | N/A | Proprietary, AES option | Partial (Windows lock/unlock sync, remote login after cold boot) | Actively sold |
| **Multiplicity / Input Director** | Paid, proprietary | Windows only | N/A | N/A | Proprietary | Limited | Legacy enterprise tools, low relevance to your cross-OS goal |

**Bottom line for your project:** there is no existing tool that is both (a) genuinely cross-platform Windows↔Linux↔Linux and (b) capable of pre-login/lock-screen control. Every OSS tool that has (a) lacks (b), and the only tool with (b) is locked to Windows-only by design. That gap is your actual opportunity.

---

## 2. Why the incumbents fall short

Three separate, real problems, confirmed directly from user reports on the projects' own issue trackers:

- **UX/UI**: Deskflow, Input Leap and Barrier all use aging Qt-widget interfaces originally built for Synergy in the early 2000s. Config is manual (edit a `.conf`/screen-layout grid), no auto-discovery on LAN by default, and error states are cryptic (a persistent complaint across their GitHub issues).
- **Functional gaps beyond video-less KVM**: clipboard sync breaks on folders/multiple files (workaround: zip first — this exact limitation exists in *both* MWB and Deskflow), drag-and-drop is single-file only, and Wayland support is still compositor-dependent (GNOME 45+/KDE Plasma 6.1+ only; wlroots-based compositors like Sway/Hyprland need a separate layer-shell workaround because they don't implement the `libei`/input-capture portal).
- **The login/lock-screen gap** — this is the one you flagged as most important, and it's real: on Linux, Barrier/Input Leap users have been asking for this since at least 2018 (`input-leap/input-leap#177`, `#179`, `#185`, `#1338`) with no working solution, and the maintainers themselves have said screen lockers on X11 hold an exclusive input grab that background apps like Barrier cannot get around, and that pre-login start is architecturally awkward because the app normally only exists as a *logged-in user's* process.

---

## 3. The core mystery, solved: how Mouse Without Borders controls the lock screen {#3-the-core-mystery-solved}

This is not a trick or an undocumented hack — it's a deliberate use of a well-defined Windows privilege boundary. Here's the exact chain of facts.

### 3.1 Windows has multiple "desktops" per session, and one of them is intentionally locked down

Since Windows 2000, every interactive session has a **window station** (`WinSta0`) containing several **desktop objects**. By default there are three (a fourth, the "Secure Desktop," was added in Vista for UAC prompts):

- **Default** — where your normal apps and shell live.
- **Winlogon** — the desktop the credential-entry UI (lock screen / login screen) runs on.
- **Screen-saver** — used when a secure screen saver is active.

Only **one** of these is the "input desktop" at a time — the one actually receiving keyboard/mouse. When you lock your PC, Windows performs a **desktop switch** from `Default` to `Winlogon`. The system automatically switches back to `Winlogon` whenever you press Ctrl+Alt+Del or a UAC prompt appears.

### 3.2 The Winlogon desktop's ACL is the entire answer

Microsoft's own documentation states it plainly: **the Winlogon desktop's security descriptor grants access to a very restricted set of accounts, and the `LocalSystem` account is one of them.** Ordinary applications — even ones running as an Administrator user — do not carry LocalSystem's SID in their access token, so they simply cannot open a handle to the Winlogon desktop or switch to it. This isn't a bug or a missing feature in Barrier/Deskflow; it's the exact security boundary those tools are correctly *not* violating, because they run as a normal logged-in user's process.

The relevant Win32 APIs:
- `OpenInputDesktop(dwFlags, fInherit, dwDesiredAccess)` — get a handle to whichever desktop currently has input focus.
- `SetThreadDesktop(hDesktop)` — associate the *calling thread* with a desktop; all subsequent `SendInput`/`keybd_event`/`mouse_event` calls from that thread act on whatever desktop the thread is attached to.
- `SwitchDesktop(hDesktop)` — actually make a desktop visible/active. Requires `DESKTOP_SWITCHDESKTOP` access — and per Microsoft's docs, this call **fails with access denied** for anything not holding the special Winlogon ACL.

### 3.3 What this means concretely: MWB doesn't "bypass" the lock screen — it runs *as* the account that's allowed to be there

Mouse Without Borders' "Use Service" option installs a genuine **Windows Service running under the LocalSystem account**, but the service is primarily a supervisor. The current PowerToys implementation launches SYSTEM helper processes into both `winsta0\winlogon` and `winsta0\default` using a token duplicated from the session's Winlogon process. Those interactive helpers own the desktop-specific input/UI path; this is more precise than treating Session 0 as a normal interactive desktop.

This is directly confirmed by Microsoft's own PowerToys documentation, which is explicit about the trade-off:

> "To allow Mouse Without Borders to control elevated applications or the lock screen from another computer, it's possible to run Mouse Without Borders as a service under the System account... Running Mouse Without Borders as a service account brings added control and ease of use to the controlled machines, but this also brings some additional security risks."

### 3.4 The full architecture (confirmed from the actual source code)

Mouse Without Borders was open-sourced under the **MIT license** as part of `microsoft/PowerToys` in 2023. You can read the real implementation — this is not reverse-engineering guesswork:

- **Repo path**: `src/modules/MouseWithoutBorders/` in [github.com/microsoft/PowerToys](https://github.com/microsoft/PowerToys)
- `App/Service/MouseWithoutBordersService.csproj` — the actual Windows Service project (LocalSystem).
- `App/Form/frmInputCallback.cs` — installs the low-level keyboard/mouse hooks that capture input on the *sending* machine.
- `Common.cs` contains `ImpersonateLoggedOnUserAndDoSomething(...)` — used throughout for the operations that must run *as the logged-in user* rather than as SYSTEM: clipboard access, per-user storage paths, drag-and-drop staging. This is the standard Windows pattern for a SYSTEM service that needs to touch a specific user's session (`WTSQueryUserToken` + `DuplicateTokenEx` + `ImpersonateLoggedOnUser`).
- `ModuleInterface/generateSecurityDescriptor.h` — generates the SDDL security descriptor used to lock down the service's IPC endpoint so only the right local principals can talk to it.
- Log output confirms two TCP listener ports opened per instance: **15100 and 15101**.
- A DFIR write-up analyzing the tool independently confirms the pairing model: a security key is generated client-side and **stored in plaintext** in `%LOCALAPPDATA%\Microsoft\PowerToys\MouseWithoutBorders\settings.json`, then manually copied to the peer machine — this is a real weakness, discussed in [§7](#7-security-hardening).

So the full picture is: **one per-user tray app** (handles UI, hotkeys, hooks, clipboard, drag-drop — needs a real interactive user token), **one Session 0 LocalSystem service** (starts at boot and supervises privileged coordination), and desktop-specific SYSTEM helpers for `winsta0\winlogon` and `winsta0\default`. The service/helper split is the reason lock-screen control works, and it is a deliberate, documented, opt-in trade-off ("Use Service" toggle) — not something baked in by default, precisely because Microsoft's own docs flag it as a larger attack surface.

---

## 4. Step-by-step: recreating this on Windows {#4-step-by-step-windows}

You can do this for real. Below is the concrete recipe — either study/adapt the MIT-licensed MWB service code directly, or build your own implementation around the same documented Windows primitives.

1. **Create a genuine Windows Service**, not a "run at startup" tray app. In .NET, use the Worker Service template (`dotnet new worker`) with the `Microsoft.Extensions.Hosting.WindowsServices` package, or in native C++ implement a `SERVICE_MAIN_FUNCTION`. This is a structurally different process type from a login-item app — it starts via the Service Control Manager, independent of any user logging in.

2. **Install it to run as `LocalSystem`**, auto-start at boot:
   ```
   sc.exe create MyKvmService binPath= "C:\Program Files\MyKvm\MyKvmService.exe" start= auto obj= LocalSystem
   sc.exe description MyKvmService "Cross-OS KVM privileged input service"
   sc.exe start MyKvmService
   ```
   Auto-start (`start= auto`) is what gives you "connects on startup, before anyone logs in" — the service is running the moment Windows boots, long before Winlogon shows a credential prompt.

3. **Do not rely on the legacy "Allow service to interact with desktop" checkbox** — that mechanism predates Session 0 isolation (Vista+) and no longer grants meaningful desktop access by itself. What grants the helper access is the combination of the trusted service, a token for the target session, the desktop ACL, and launching the helper in the target desktop. LocalSystem alone is not the complete recipe.

4. **Keep desktop-specific helpers alive and monitor session/desktop transitions.** `SetThreadDesktop` is constrained once a thread owns windows or hooks, so repeatedly reassigning a long-lived UI thread is not a complete design; recreate or isolate helpers when the target desktop changes. A simplified API sketch is:
   ```csharp
   IntPtr hDesk = OpenInputDesktop(0, false, DESKTOP_ACCESS_FLAGS);
   SetThreadDesktop(hDesk);
   // ...now SendInput() targets whatever desktop is actually showing
   CloseDesktop(hDesk);
   ```

5. **Subscribe to session-state change notifications** instead of blind polling, so you react immediately to lock/unlock/UAC transitions:
   ```csharp
   WTSRegisterSessionNotification(windowHandle, NOTIFY_FOR_ALL_SESSIONS);
   // Handle WM_WTSSESSION_CHANGE with wParam values
   // WTS_SESSION_LOCK, WTS_SESSION_UNLOCK, WTS_CONSOLE_CONNECT, WTS_CONSOLE_DISCONNECT
   ```

6. **For anything that must run *as* the logged-in user** (clipboard read/write, drag-drop file staging, per-user config), don't try to do it from the SYSTEM context directly — impersonate:
   ```csharp
   WTSQueryUserToken(WTSGetActiveConsoleSessionId(), out IntPtr hUserToken);
   DuplicateTokenEx(hUserToken, TOKEN_ALL_ACCESS, IntPtr.Zero,
       SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenImpersonation, out IntPtr hDup);
   ImpersonateLoggedOnUser(hDup);
   // ...do the user-scoped work...
   RevertToSelf();
   ```
   This is exactly the pattern MWB's `Common.ImpersonateLoggedOnUserAndDoSomething` implements.

7. **Bridge the SYSTEM service and the per-user tray app** with an IPC channel the service locks down explicitly (named pipe or loopback socket with an SDDL descriptor restricting it to your own app's identity) — SYSTEM runs in Session 0, which is isolated from any interactive session and cannot show UI directly, so the tray app remains the thing the user sees and configures, while the service is invisible plumbing.

8. **Open a firewall rule** for your chosen inbound TCP/UDP port(s) at install time (MWB uses 15100/15101 — pick your own, don't collide with those if users might run both):
   ```
   netsh advfirewall firewall add rule name="MyKvm" dir=in action=allow program="C:\Program Files\MyKvm\MyKvmService.exe" enable=yes
   ```

9. **Optional — let the remote peer trigger Ctrl+Alt+Del itself** (needed in some domain-joined environments where the credential box only appears after SAS). Call `SendSAS(FALSE)` from `sas.h`/`Sas.dll`. This requires either running as a service (which you already are) *and* the local policy allowing it:
   ```
   reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v SoftwareSASGeneration /t REG_DWORD /d 1 /f
   ```
   (Values: `0`=None, `1`=Services, `2`=Ease-of-Access apps, `3`=both.)

10. **Ship the pairing-key exchange more securely than MWB does** — see [§7](#7-security-hardening) before you finalize the protocol.

That's the complete, real mechanism — no undocumented APIs, no exploits. It's a documented, intentional Windows extensibility point that Microsoft itself uses for exactly this purpose.

---

## 5. Can Linux do this? Post-boot control is feasible, but not universal {#5-linux-equivalent}

Linux has no single "Winlogon secure desktop" concept, so you can't port the Windows approach 1:1. Post-boot lock/login control is feasible through the kernel's `uinput` subsystem, but the exact behavior depends on the display manager, compositor, seat, udev/libinput policy, and whether the session is X11 or Wayland. It should be described as a supported configuration matrix, not a universal guarantee.

### 5.1 Why Deskflow/Input Leap/Barrier structurally can't reach the greeter or lock screen

- **On X11**: input injection is done via the `XTest` extension, which requires a connection to a specific X display, authenticated via that display's `Xauthority` cookie. The GDM/SDDM/LightDM **greeter** runs its own separate X server as a *different* system account (`gdm`, `sddm`, `lightdm`) with its own Xauthority — a user's Barrier/Input Leap process, running inside their own already-logged-in X session, has no route into that other X server at all. Separately, when a *screen locker* is active within a live session, it typically holds an exclusive input grab, and background apps lose the ability to receive/inject events reliably — this is exactly the behavior reported in `input-leap/input-leap#177`.
- **On Wayland**: this is intentional, not accidental. Modern compositors (GNOME/Mutter, KDE/KWin) only allow synthetic global input through `libei`, brokered by the `xdg-desktop-portal` **RemoteDesktop**/**InputCapture** interfaces — and that portal requires a live, logged-in user session to show a consent dialog. There is no user session at the greeter, so there is nothing to consent, so there is no path in. This is upstream Wayland's security model working as designed, not a missing feature.

### 5.2 The mechanism that actually works: kernel-level `uinput`, run as a system service

Linux's `uinput` subsystem lets a process create a **virtual HID device** directly at the kernel/`evdev` layer — below X11, below Wayland, and below any specific greeter or compositor. Once correctly classified and assigned to the intended seat, its events can be consumed like input from a real keyboard/mouse by the active input stack, whether that is a GDM greeter, an SDDM login box, a locked GNOME session, or a fully unlocked desktop.

This is confirmed directly by the Wayland/`libei` community itself, discussing the trade-off of this exact approach:

> "Kernel-level virtual input may have undesirable side effects because the compositor is being completely bypassed. This most notably means that virtual consoles are no longer isolated as far as input is concerned, so simple lock screens can be easily bypassed if more than one session is active."

That's a warning framed as a downside — but it is *precisely* the behavior you're asking to reproduce as a feature. The property that makes `uinput` "dangerous" (it operates below session/compositor boundaries) is exactly the property that makes it capable of controlling a login/lock screen, the same way LocalSystem's Winlogon-desktop access does on Windows. Both platforms grant this power to a privileged, non-user-session actor for the same underlying reason.

Interesting side note for your protocol design: `Lan Mouse` (the Rust KVM project referenced above) already has a **working `uinput` backend** for its injection side, and its GitHub FAQ explicitly says the Deskflow and Lan Mouse maintainers have discussed interoperability. You would not be starting from zero — you'd be extending an existing, actively maintained, MIT/GPL-licensed Rust `uinput` implementation to run as a boot-time system daemon instead of a per-session user app.

### 5.3 The honest scope boundary

Be precise about what this replicates: the *Windows login/lock screen after boot, before or during credential entry* — the same scope MWB itself covers. It does **not** extend to full-disk-encryption unlock prompts (BitLocker PIN, LUKS passphrase at boot) in the ordinary daemon design. Those prompts run before a normal OS session is available; a separate custom initramfs/boot-agent and early-network design would be required, and that is outside Phase 1. So the parity claim is: *"OS kernel and the normal input stack are up, login/lock screen showing, no user session unlocked yet"* — which is exactly MWB's practical scope, not a superset of it.

---

## 6. Step-by-step: recreating this on Linux {#6-step-by-step-linux}

1. **Write the injection/network daemon as a systemd *system* unit — never a `systemd --user` unit.** A user unit only starts *after* that user logs in, which defeats the entire purpose. A system unit starts at boot, independent of any login:
   ```ini
   # /etc/systemd/system/mykvmd.service
   [Unit]
   Description=Cross-OS KVM privileged input daemon
   After=network.target

   [Service]
   Type=simple
   ExecStart=/usr/bin/mykvmd
   Restart=on-failure
   # Either run as root, or as a dedicated system user in the "input" group (see step 3)

   [Install]
   WantedBy=multi-user.target
   ```
   ```
   systemctl enable --now mykvmd.service
   ```

2. **Open `/dev/uinput` and register a virtual keyboard + mouse device** using the standard ioctl sequence (`UI_SET_EVBIT` for `EV_KEY`/`EV_REL`/`EV_SYN`, `UI_SET_KEYBIT` per key code, `UI_SET_RELBIT` for `REL_X`/`REL_Y`/`REL_WHEEL`, then `UI_DEV_SETUP` + `UI_DEV_CREATE`). Inject events with `write()` calls terminated by an `EV_SYN`/`SYN_REPORT`. Lan Mouse's `input-emulation` crate already implements exactly this in Rust and is a reasonable starting point rather than writing it from scratch.

3. **Permissions**: creating a `uinput` device only needs read/write access to the `/dev/uinput` char device node — it does **not** strictly require root. Add a udev rule so a dedicated system user can do it without running as root:
   ```
   # /etc/udev/rules.d/99-mykvm-uinput.rules
   KERNEL=="uinput", GROUP="input", MODE="0660"
   ```
   Run the daemon as a fixed system account that's a member of the `input` group (`useradd --system --group input mykvm`), or use systemd's `DynamicUser=yes` with `SupplementaryGroups=input`. Running as plain root is simpler but widens your attack surface unnecessarily — prefer the group-membership route.

4. **Verify the udev/libinput classification and seat assignment explicitly.** Defaults commonly target `seat0`, but a production implementation must not assume that every host or multi-seat setup will do so automatically.

5. **Networking**: reuse Lan Mouse's transport layer (mandatory DTLS via `webrtc-dtls`) or roll your own with `rustls`/`quinn` (QUIC) — either way, terminate the encrypted channel *inside the privileged daemon*, since it's the thing writing to `/dev/uinput`; don't split "receive network packet" and "write uinput event" across a trust boundary you'd then have to re-secure.

6. **For the capture side** (grabbing input on the physically-used Linux machine to send elsewhere) inside a normal, already-logged-in Wayland session, use `libei` + the `RemoteDesktop`/`InputCapture` portal — this is what Deskflow and Lan Mouse already do, and it's the *correct*, consent-respecting way to do it. Don't try to route capture through `uinput` too; that direction genuinely should stay inside the compositor's security model. On X11 sessions, `XTest`-based edge capture (Barrier/Deskflow's existing approach) is fine as-is.

7. **Gate the privileged daemon's control input strictly to the authenticated network channel** — never expose a local, unauthenticated control socket that any local process could use to inject input, since that would turn your intentional lock-screen-crossing feature into a real local-privilege-escalation bug (this is exactly the risk the Wayland community's `uinput` warning above is describing).

8. Treat secure-attention integration and display-manager-specific D-Bus features as optional, distro/version-specific extensions. They are not prerequisites for the core `uinput` path and must be verified against the target display manager before being promised.

---

## 7. Security hardening: don't repeat MWB's mistakes {#7-security-hardening}

Since you're explicitly building "more robust" than the existing tools, fix these known weak points from the start:

- **Pairing/key exchange**: MWB's model — a plaintext key generated once, manually copied to the peer, stored unencrypted in a local JSON settings file — is genuinely weak (independently confirmed by a public DFIR write-up on the tool). Replace with public-key device identity and pinning (Syncthing/Tailscale-style): each install generates a keypair on first run; pairing exchanges public keys (via a short numeric code + out-of-band confirmation, or QR code between the two machines) rather than a shared secret; store private keys in the OS credential store (Windows Credential Manager / DPAPI, Linux Secret Service / `libsecret`) instead of a plaintext file.
- **Transport encryption**: make it mandatory and modern by default — TLS 1.3 or a Noise-protocol handshake over QUIC/DTLS, not an optional bolt-on.
- **Privilege minimization**: keep the SYSTEM/root-level component as small and single-purpose as possible (network receive → input inject only); do everything else (UI, clipboard, settings, drag-drop staging) in the unprivileged per-user process, communicating over a tightly-scoped local IPC channel with explicit ACLs — exactly the split MWB itself uses, just with a hardened protocol.
- **Explicit, visible consent for the privileged mode**: make "this machine can be unlocked/controlled from another paired machine even while locked" an unambiguous, separately-toggled setting (as PowerToys already does with its "Use Service" toggle) rather than default-on behavior — users should know precisely when they're expanding the attack surface.
- **Audit logging**: log every lock-screen-level injection event locally (who paired, when, from which peer) so a compromised or lost paired device is forensically visible, not silent.

---

## 8. Recommended architecture for your Phase 1 build {#8-recommended-architecture}

**Two-binary model per OS**, mirroring what actually works today:

| Component | Runs as | Responsibilities |
|---|---|---|
| **User agent** | Normal logged-in user | Settings UI, screen-layout editor, hotkeys, clipboard sync, drag-and-drop staging, pairing UX |
| **Privileged daemon** | Windows: `LocalSystem` service · Linux: root/`input`-group `systemd` system service | Network protocol, encryption, raw input capture/injection, lock-screen/pre-login reach |

**Core engine language**: Rust, for one shared codebase across the capture/inject/network layer on both OSes — this is exactly what Lan Mouse already proves out (X11, Wayland via libei/portal/layer-shell, Windows, and a `uinput` backend, all in one Rust project with per-platform feature flags). Building on or directly extending its crates (`input-capture`, `input-emulation`) saves you from re-solving problems that are already solved and MIT/GPL-licensed.

**UI**: a single cross-platform UI codebase (e.g., Tauri, since it's Rust-native and pairs naturally with the above) instead of separate WinForms/Qt-widget UIs — this directly targets the "smoother, better UI" goal versus Deskflow/Barrier's dated Qt interfaces and MWB's WinForms UI.

**Protocol**: authenticated, encrypted by default (see [§7](#7-security-hardening)); design the wire format so an "elevated/lock-screen-capable" packet class is explicitly distinguished from a normal in-session packet class, so the privileged daemon can enforce policy (e.g., require the extra pairing trust level before it will act on lock-screen-class commands) rather than treating all input events as equally privileged.

**Windows privileged component**: study/adapt the MIT-licensed `MouseWithoutBordersService` code directly rather than reimplementing session/desktop handling from scratch — it's real, working, first-party Microsoft code solving exactly this problem.

**Linux privileged component**: new code, built around `/dev/uinput`, run as a `systemd` system unit (`WantedBy=multi-user.target`), informed by Lan Mouse's existing `uinput` backend.

---

## 9. Packaging plan (Ubuntu/Debian, Fedora/RHEL, Arch — x86_64 + ARM64) {#9-packaging-plan}

Rust makes cross-arch builds substantially simpler than the C++/Qt toolchains Deskflow and Input Leap currently have to wrestle with for ARM packaging:

- **Arch**: ship a proper `PKGBUILD` (Deskflow's own is a good template — it already builds cleanly for `aarch64` on Arch Linux ARM); publish to the AUR and pursue `extra` repo inclusion once stable, as Deskflow has done.
- **Fedora/RHEL**: `.rpm` via `cargo-generate-rpm` or a Fedora COPR repo; Fedora already treats `aarch64` as a primary architecture, so cross-building is well-supported.
- **Ubuntu/Debian**: `.deb` via `cargo-deb`; consider a PPA for faster iteration before targeting Debian's official archive.
- **Cross-compilation**: use `cross` (Rust's Docker-based cross-compilation tool) or native GitHub Actions ARM64 runners to produce `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` builds from one CI pipeline.
- **systemd unit + udev rule** should ship as part of the package's post-install scriptlet, exactly like the `.rpm`/`.deb` packaging conventions already used by tools like `ydotool` that also rely on `/dev/uinput`.
- **Windows**: MSI via WiX (same tooling Deskflow and PowerToys both already use), with the service registered via a custom action calling `sc.exe create ... start= auto obj= LocalSystem` at install time.

---

## 10. References {#10-references}

- Deskflow — https://github.com/deskflow/deskflow
- Deskflow Project FAQ — https://github.com/deskflow/deskflow/wiki/Project-FAQ
- Lan Mouse — https://github.com/feschber/lan-mouse
- Lan Mouse (lib.rs) — https://lib.rs/crates/lan-mouse
- Input Leap — https://github.com/input-leap/input-leap
- Input Leap Wayland tracking discussion — https://github.com/input-leap/input-leap/discussions/1976
- Barrier (status: discontinued) — https://www.alternativeto.net/software/barrier/about/
- Mouse Without Borders source (MIT, in PowerToys) — https://github.com/microsoft/PowerToys/tree/main/src/modules/MouseWithoutBorders
- Mouse Without Borders — official docs — https://learn.microsoft.com/en-us/windows/powertoys/mouse-without-borders
- Windows Desktops (Win32) — window station/desktop model & Winlogon ACL — https://learn.microsoft.com/en-us/windows/win32/winstation/desktops
- `OpenInputDesktop` — https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-openinputdesktop
- `SwitchDesktop` — https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-switchdesktop
- `SendSAS` — https://learn.microsoft.com/en-us/windows/win32/api/sas/nf-sas-sendsas
- Winlogon architecture (Wikipedia, well-sourced) — https://en.wikipedia.org/wiki/Winlogon
- Secure attention key / systemd v257 & GDM 47 SAK — https://en.wikipedia.org/wiki/Secure_attention_key
- libei / Wayland virtual-input security trade-offs discussion — https://www.phoronix.com/forums/forum/linux-graphics-x-org-drivers/wayland-display-server/1387820-libei-1-0-nears-for-emulated-input-on-wayland
- Independent DFIR analysis of MWB's key storage/ports — https://0xsultan.github.io/dfir/Exfiltrate-Without-Borders/
- Input Leap lock-screen/pre-login issue history — https://github.com/input-leap/input-leap/issues/177, /issues/179, /issues/185, /issues/1338
- Synergy 3 (Symless) — https://symless.com/synergy
- ShareMouse — https://www.sharemouse.com/features/
