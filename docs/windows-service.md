# Windows: LocalSystem service (MWB-style lock-screen control)

The implementation follows Mouse Without Borders' documented service/helper
model. `kvm-daemon` has a native SCM entry point and, when running as the
service, launches authenticated SYSTEM helpers in the active console session.
Every accepted input session gets a helper on `winsta0\\default`; a session
that requests the explicit lock-screen capability also gets a helper on
`winsta0\\winlogon`. The service forwards accepted QUIC input over a private
loopback channel. Both helpers receive lifecycle messages, but each input
event is injected only by the helper whose current desktop reports `UOI_IO=true`
(the active input desktop). This avoids duplicating `SendInput` events while
retaining a ready helper across Default ↔ Winlogon transitions. This is an
implementation of the required architecture, not a claim that every Windows
session variant has already passed physical testing.

## Why it works

Windows sessions contain multiple desktops (`Default`, `Winlogon`, `Screen-saver`).
The **Winlogon** desktop's ACL admits only a restricted set of accounts —
**LocalSystem is one of them**. Modern Windows services still run in isolated
Session 0, so the service must supervise a SYSTEM helper launched in the target
interactive session/desktop. The helper can then:

1. open the target input desktop from the correct interactive session
2. attach a helper thread before it owns windows/hooks
3. `SendInput(...)` → events land on Default, Winlogon, or Screen-saver,
   whichever is showing — including the password prompt

No undocumented APIs, no exploits. Microsoft documents this boundary and MWB
(MIT-licensed in PowerToys) uses exactly this mechanism.

## Install steps

```bat
sc.exe create TheKVM binPath= "C:\Program Files\TheKvm\kvm-daemon.exe serve --service" start= auto obj= LocalSystem
sc.exe description TheKVM "TheKVM cross-OS KVM privileged input daemon"
sc.exe failure TheKVM reset= 86400 actions= restart/5000/restart/5000/restart/10000
sc.exe start TheKVM

netsh advfirewall firewall add rule name="TheKVM" dir=in action=allow program="C:\Program Files\TheKvm\kvm-daemon.exe" enable=yes
```

`start= auto` is what gives you "connects on startup, before anyone logs in" —
the service runs the moment Windows boots, before Winlogon shows a prompt.
The service-side receiver is therefore available at boot. In the ordinary
receiver-only installation, physical capture still belongs to an interactive
user-session process; launch `kvm-daemon connect <peer-ip:42110>` from that
user's startup task if the controller should reconnect automatically after a
target reboot or LAN loss. The repository includes
`packaging/windows/install-agent.ps1` to register that interactive,
non-elevated logon task. The optional service-controller mode below is the
separate, explicitly privileged path for capture before login.

For MWB-style boot-time controller capture, configure a fixed paired peer when
installing the service:

```powershell
.\install-service.ps1 -PeerAddress "peer-host:42110" -DeviceName "Office workstation" -EnableLockScreenControl
```

This starts the same LocalSystem service as a receiver and also launches
authenticated SYSTEM capture helpers on `winsta0\\default` and
`winsta0\\winlogon`. The service reconnects to the configured peer while the
network or the interactive session is unavailable. Leave `-PeerAddress` off
for strict receiver-only operation; the installer selects that mode and clears
any previously saved auto-peer in that case. A supplied peer selects
controller-only mode by default; pass `-Mode bidirectional` when both
directions are intended. Changing this setting through the UI or CLI requires
restarting the Windows service, and both paired machines must explicitly allow
lock-screen control.

## Desktop/helper lifecycle (required)

The active desktop switches constantly (Default ↔ Winlogon ↔ Screen-saver).
Do not blindly reattach one long-lived hook/UI thread before every event. Create
or isolate helpers for the target session/desktop and recreate them when the
desktop changes. A simplified sketch is:

```rust
// TheKVM's service-side equivalent is implemented in
// kvm-daemon/src/windows_helper.rs:
// 1. find winlogon.exe in WTSGetActiveConsoleSessionId()
// 2. duplicate its token with DuplicateTokenEx(TokenPrimary)
// 3. CreateProcessAsUserW(..., STARTUPINFO.lpDesktop = "winsta0\\winlogon")
// 4. repeat for "winsta0\\default"
// 5. forward only paired, policy-approved events over authenticated loopback IPC
```

Stale handles silently fail — always re-open per event burst.

## Session notifications

Subscribe instead of polling so lock/unlock/UAC transitions are instant:

```
WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_ALL_SESSIONS);
// WM_WTSSESSION_CHANGE: WTS_SESSION_LOCK / UNLOCK / CONSOLE_CONNECT / DISCONNECT
```

## Ctrl+Alt+Del from remote peer (optional)

Requires running as a service + local policy:

```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v SoftwareSASGeneration /t REG_DWORD /d 1 /f
```

Then call `SendSAS(FALSE)` from `sas.dll`.

## User-scoped work (clipboard, drag-drop staging)

The current text clipboard feature belongs to the logged-in user-session
controller, not the LocalSystem service. It is negotiated only when both peers
opt in and a user-session clipboard exists. Keep richer clipboard and drag/drop
work out of the service until it has an explicit impersonation and consent
design.

Never do this as SYSTEM directly. Impersonate the logged-on user:

```
WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &hTok)
DuplicateTokenEx(hTok, ..., SecurityImpersonation, TokenImpersonation, &hDup)
ImpersonateLoggedOnUser(hDup)
... work ...
RevertToSelf()
```

Same pattern as MWB's `Common.ImpersonateLoggedOnUserAndDoSomething`.

The service state belongs in `%ProgramData%\TheKVM`, not the installing user's
`%APPDATA%`. `packaging/windows/install-service.ps1` configures this directory
explicitly and restricts it to SYSTEM and local Administrators before creating
the service. The private identity key is stored as a machine-bound
DPAPI-protected blob so an elevated CLI and LocalSystem can use the same daemon
identity; raw keys from older development builds are migrated on first load.
