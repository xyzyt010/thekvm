# Local control plane

The desktop UI must not maintain a second authorization database beside the
privileged daemon. The daemon owns the identity, configuration, and trusted
peer book used for QUIC input authorization. The UI is a local client.

## Endpoints

| Platform | Endpoint | Access boundary |
|---|---|---|
| Linux and FreeBSD | `<data-dir>/control.sock` | Unix-domain socket, mode `0660`; deploy the desktop user in the daemon's group |
| Windows | `\\.\pipe\thekvm-control` | Local named pipe; remote clients are rejected |

The protocol is a bounded, four-byte length-prefixed JSON request/response
message. It currently supports:

For isolated development instances only, set `THEKVM_CONTROL_PIPE` to a
different local named-pipe path in both the daemon and its CLI/UI. Installed
production instances use `\\.\pipe\thekvm-control` unless an administrator
deliberately supplies an override.

- `Status` — daemon fingerprint, listen port, mode, lock-screen policy,
  clipboard policy, optional Windows boot-controller peer, peer count, and
  uptime
- `GetConfig` — the effective persisted configuration
- `SetConfig` — mode (`bidirectional`, controller-only `server-client`, or
  receiver-only `receiver-only`), lock-screen policy, text clipboard policy, optional
  Windows boot-controller peer, and optionally the validated screen topology,
  plus an optional bounded friendly device name, applied to the running daemon.
  Omitted mode and lock-screen fields preserve their current values, which makes
  partial CLI/UI updates safe; use `--allow-lock-screen-control` or
  `--disable-lock-screen-control` for an explicit policy change.
- `Pair` — repeat a previously user-confirmed fingerprint exchange using the daemon identity
- `ListPeers` — return the daemon-owned trusted peer names, fingerprints, and
  last paired addresses
- `ListPendingPairings` — return authenticated incoming pairing requests that
  are waiting for local approval, each carrying the shared six-digit pairing
  verification code
- `ApprovePairing` / `RejectPairing` — resolve one pending incoming request by
  certificate fingerprint
- `Unpair` — revoke one trusted fingerprint and persist the change before the
  response is returned

The listener port is intentionally not changed live. A request to change it
returns an error because replacing the QUIC endpoint safely requires a daemon
restart and a firewall/service update.

Mode enforcement is symmetrical: `Bidirectional` permits both directions,
`ServerClient` permits outgoing control only, and `ClientOnly` permits incoming
control only. For a strict one-way relationship, configure the controller as
`server-client` and the controlled node as `receiver-only`.

On Windows, `Applied { restart_required: true }` is returned when the optional
boot-time controller peer is added, removed, or when its mode/lock-screen
policy changes. The LocalSystem controller reads those values when it starts;
restart the service before expecting the new outgoing-session policy to take
effect.

## Pairing flow from the UI

1. The initiating UI connects to the peer only to display and verify the peer
   certificate fingerprint and peer name.
2. Both endpoints derive the same six-digit **pairing verification code** from
   the two certificate fingerprints. The initiator's UI shows its derived code
   next to the fingerprint confirmation; the receiver's pending-pairing entry
   carries the identical code.
3. The initiating user compares the two codes across machines and presses
   **Confirm pairing**.
4. The UI sends `Pair { address, expected_fingerprint_hex }` over local IPC.
5. The daemon connects using its own certificate and verifies that the peer
   certificate still has the expected fingerprint. The receiver's pairing
   challenge also carries its own derivation of the verification code; a
   mismatch between the two derivations aborts the pairing before any trust
   is written, because it indicates the connection may be relayed by a
   machine-in-the-middle presenting different certificates to each side.
6. The receiving daemon displays the authenticated request in its local UI
   and holds the pairing stream without pinning the peer. The receiver user
   compares the displayed code with the initiator's machine and explicitly
   chooses **Approve incoming** or **Reject incoming**, or uses
   `kvm-daemon approve-pairing <fingerprint>` /
   `kvm-daemon reject-pairing <fingerprint>`.
7. Only after approval does the receiver persist the peer and send the final
   acceptance. The initiator then persists its peer record. A request that
   times out or is rejected is never trusted.

The verification code is a numeric-comparison aid in the spirit of Bluetooth
pairing: it is deterministic, derived from the same unordered fingerprint
pair on both endpoints, and never travels as an authorization token. Older
peers that do not send the field keep working; the initiator then relies on
the fingerprint comparison alone. `kvm-daemon pair` prints the code beside
the fingerprint for CLI users.

Use `kvm-daemon pending-pairings` to inspect the receiver's pending queue.
The queue is in memory, capped, and expires after two minutes; it is not a
substitute for the persisted trusted-peer book.
The LAN integration scripts set `THEKVM_AUTO_CONFIRM=1` only on their
disposable daemon processes so the automated transport gate does not require
a human at two machines. Do not set this variable in a production service.

The topology is a JSON `Layout` inside the daemon configuration. The sample in
`docs/layout.example.json` shows the screen geometry and the peer fingerprint
that `kvm-daemon connect` uses to select the next peer. Import it with
`kvm-daemon configure --layout <path>` or the UI's **Import layout** action.

The UI's temporary discovery identity is never enough to authorize privileged
input. If the daemon is offline, the UI reports pairing failure rather than
claiming that a user-only pairing was completed.

Clipboard synchronization is an explicit opt-in on each configured peer. The
daemon negotiates it during each input session, sends text updates only when
both sides accepted it, and limits each update to 48 KiB. The setting does not
grant lock-screen input permission and does not enable image, rich-text, or
file-transfer synchronization.

The configured device name is the daemon-owned identity label shown by LAN
discovery and included in pairing challenges and input-session `Hello` frames.
It is limited to 128 UTF-8 bytes and cannot contain control characters. Older
UI clients may omit the field; omission preserves the current name.

The UI's **Trusted peers** panel uses `ListPeers` and `Unpair`; it does not
edit `peers.json` directly. Revocation affects new sessions immediately and
publishes a daemon-local cancellation signal that terminates an already-
established input stream after releasing held controls. The Windows
LocalSystem auto-controller consumes the same signal, releases its capture,
and stops rather than reconnecting to a revoked peer. A separately launched
user-session controller must reconnect before it can establish another session.

Identity rotation is intentionally an offline CLI operation rather than a
live control request. Stop the daemon, then run
`kvm-daemon rotate-identity --yes`. The daemon replaces its certificate/key
files through flushed replacement writes, reports the old and new fingerprints,
and leaves the peer book intact
because remote peer identities have not changed. Every peer that accepts the
rotated node must be paired again before it will admit the new fingerprint.

## Deployment requirements

On Linux, install the system service's data directory with ownership/group
permissions that allow the intended desktop user to access `control.sock`.
The packaged UI connects to `/var/lib/thekvm/control.sock` by default; use
`THEKVM_CONTROL_DATA_DIR` for a custom control-data location. For example, use
a dedicated `thekvm` group, add the desktop user to it, and restart that
user's session after the group change. Keep the directory and socket out of
world-writable locations. `THEKVM_DATA_DIR` remains a development override
that makes the UI and daemon share one complete state directory.

On Windows, the implementation rejects remote clients and applies an explicit
local named-pipe ACL. The current ACL grants LocalSystem, local administrators,
and interactive users access so that the first-run UI works without elevation.
Before a broad release, replace the interactive-users entry with a dedicated
TheKVM desktop-user group. This is separate from QUIC peer authentication and
is required before enabling an unattended privileged configuration surface.

The installed service owns its identity and peer book in
`%ProgramData%\TheKVM`; the Windows installer configures and ACL-locks that
directory before registering the LocalSystem service. The identity private key
is stored as a machine-bound DPAPI blob so an elevated CLI and LocalSystem can
use the daemon-owned identity, while the directory ACL restricts direct access
to SYSTEM and local administrators. The UI therefore
uses the local control pipe for daemon-owned pairing instead of maintaining a
second privileged identity. A pre-existing raw identity key is migrated once
when the owning daemon next loads it.
