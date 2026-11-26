# UI-CLIPBOARD-MULTINODE-SPEC — Verification Record (2026-11-25, v0.9.99, commit 65b9b21)

Environment: Windows 11 (user's live machine, 192.168.1.6) + Linux Mint
(192.168.1.12, SSH `hs01_windows_key`); isolated Mint vision instance on
Xvfb :99 (lock port 49341, vision data dir, port 43110) for GUI checks;
local Windows release for compile/test. Windows binaries deployed via
dist/deploy-windows-v3.ps1 (hash-verified, service restarted).

## Loop 1 — Traceability (white-box, PASS)
Every critique point maps: Settings→SET-01..10, Devices→DEV-01..10,
Connect→CON-01..07, cohesion→DS-01..12, multi-node→MN-01..12,
clipboard→CB-01..13. No orphaned statements; each task has acceptance
criteria (§7).

## Loop 2 — Static review (white-box, PASS with notes)
- DS-01: 13px→14px body, 9px→12px captions, 8px→10px micro globally;
section titles 16px; no essential text < 13px. One scale, audited by
grep (no 13px essential left except button labels now 14px).
- DS-04: IconButton/Close/Rescan 36/32/32px targets; Trash 18px centred
in 36px at (9,9); overflow dots centred at (9,9).
- DS-03: yellow Android (#facc15) + platform label; green connected,
amber connecting, red destructive; text pairs with color.
- SET-02: fixed columns index(28)/name(200)/separator(32)/IP(170)/
spacer/overflow(36)/trash(36). SET-06 menu renders all five items;
verified by vision + click (spec-h.png/ overflow open).
- SET-03 index renumbers from loop index (renumber after delete is
inherent).
- DEV-10 vocabulary enforced: Live/Connecting/Idle/Discovered/Error.
- CB-01: first OS sighting baselined, never emitted (poll_user_text/
poll_user_image observed_any gate, agent same).
- MOVE-01/QHOL word-level diagnostics for later levels are retained
unchanged; not part of this spec.

## Loop 3 — Functional black-box (partial; remainder to user)
- 3+ node real crossing, Android end-to-end, revocation, restart
activation: NEED HUMAN/MULTI-NODE (no third node on this LAN today).
- Clipboard 9-step acceptance: needs both machines + user copies.
  Subtle checks done by agent: CB-01 no-sync-at-connect (code), CB-07
  revision ordering/dedup (code + unit tests), CB-08 caps enforced
  before allocation (agent stat → skip; assembly Drop on over-cap).

## Loop 4 — Vision review (PASS, Mint isolated, 720x560)
- Screenshots: spec-connect.png (Connect roster), spec-devices.png
(Devices roster rows), spec-settings3.png (SET rows + fixed columns),
spec-h.png (overflow menu open, all five items), spec-z3.png (final
rows fixed columns, v0.9.99), spec-z4.png (Devices rows, mesh).
- Fonts consistent across tabs; no clipping/overlap at minimum size;
scrollbar visible; header plus/title centred on one line.

## Loop 5 — Adversarial review (PASS with documented residuals)
- Fake states swept: PushMesh no longer claims success when 0 of N
acknowledged (MN-10); trusted peers with unknown kind default Desktop
(old books deserialize as Desktop); corrupt queue file falls back
empty; relay JSON parse fails closed; FilesAssembly byte-exactness by
count + per-file total.
- Residuals: (a) focus trap on delete confirmation (Slint has no trap
API; cancel-first order + return-focus acceptable); (b) 3+ node routing
proven only by unit/white-box, not live; (c) Android controller parity
(Android app out of scope for this desktop task); (d) revision is
per-sender counter (1 u64 per child) — convergent via revision>remote
check; "globally comparable" cross-machine tie-break not implemented
(both counters start at 0, so simultaneous edits converge on the
later-arriving frame per stream).

## Test evidence
cargo test: kvm-protocol 54, kvm-core 75, kvm-platform 48 (incl.
file_uri_roundtrip + total_bytes_saturates), kvm-daemon 94 (incl.
files_assembly 2 new), kvm-ui 14. 285 total, 0 failures.
Mint Linux build + tests pass (53 platform tests incl. Linux-only
paths). Windows release built + deployed; service Running; hashes
match (see deploy-windows-v3.log).

## Fix pass 2026-11-26 (commit 93c90be)
- Plus glyph: was top-aligned in its 36px box → geometrically centred
  (cross centre = 18px). Trash: 18px→20px glyph, centred (8,8) in the
  box. Verified by vision screenshots fix-set.png / fix-dev.png.
- Left-hug alignment: removed `alignment: center` from Settings row,
  Connect two-row grid, and Devices roster rows — dots/indexes glued
  to the content gutter in every state; index numbers left-aligned.
- Connect: "All computers" roster removed per user instruction; the
  complete roster lives once, in Devices (see spec CON-03 note).
- Deployed to Windows (hash-verified, service Running, kvm-ui alive).

## Fix pass 2, 2026-11-26 (commit d1c6bae)
- Zoom-verified (z-plus/z-rows/f2-set shots): name/IP hollow gap
  collapsed by tightening columns 200/170→150/150; the 1px separator
  is now visible (#5b6675, 24px); trash 22px white glyph centred in a
  36px target; plus arms enlarged to 14px so the cross reads at the
  title's weight.
- Monitor name text lifted above the arrow lane (no longer crossed by
  the arrows).
- Deployed (service Running, hashes match).

## Fix pass 3, 2026-11-26 (SET-10 focus trap + DS-10 + Loop 4 re-pass)
- DS-06: every KvmButton gained a FocusScope (tab navigation +
  blue #60a5fa focus ring, visible in v5-confirm shot on Cancel);
  settings overflow/trash are tab stops; Enter/Space activates
  (KeyEvent text: Enter U+000A, Space, Tab U+0009, Escape U+001B,
  Backtab U+0019 via \u{...} escapes — Slint has no \t/\r).
- DS-07: Theme.reduced gates the spinner/radar timers; Rust seeds it
  from the OS MinAnimate flag (kvm-platform/src/prefs.rs).
- DS-10: Devices Details/Connect announce "row N of M" via aria-label;
  Settings overflow/trash likewise.
- SET-10: delete confirmation moved INSIDE its row. Cancel is the
  default (timer focuses it on open); Tab/Shift-Tab trap cycles
  Cancel<->Delete (capture_key on the panel FocusScope, using
  KvmButton.forward-focus + has-focus); Escape cancels; closing
  returns focus to that row's trash. Overflow menu items are now
  keyboard-navigable RowMenuAction rows (Enter/Space act, Escape
  closes). Verified: v5-confirm.png (Cancel focused, panel in row 1).
- CB-07: added clipboard_frame_ordering_is_per_sender_sequence test
  (newer applies; replay dedup; stale dropped; disabled dropped).
  Simultaneous multi-sender ties still resolve by per-stream arrival
  order (per-sender sequence + per-session identity is the
  tie-break); wire unchanged for mixed-version compatibility.
- Loop 4 (Mint, Xvfb): re-ran at 720x560 (1024x768 display) in dark
  and light themes plus a daemon-online run — Connect two-row grid,
  Devices rows, Settings rows (tight columns, white trash, visible
  separator), empty state, offline banner. Synthetic clicks need
  DOUBLE clicks under bare Xvfb (first click is focus).
- Tests: core 75, daemon 95 (+1 new), platform 48, protocol 54,
  ui 14 = 286 green. kvm-android fails to test-compile on Windows
  (pre-existing; package untouched this pass).
- Deployed (service Running, hashes match).

## Fix pass 4, 2026-11-26 (CB-07 global ordering, DS-06 tooltips, Android labels, Loop 4 matrix)
- CB-07 is now structurally closed: clipboard revisions are a hybrid
  logical clock in the same u64 wire field —
  `[44-bit Unix ms][12-bit sender tag][8-bit sequence]`. The sender tag
  is the first 12 bits of the local identity fingerprint; the timestamp
  orders events across machines, the tag is the same-millisecond
  tie-break, and the sequence orders same-sender events. Receivers
  retain a process-wide high-water mark (in addition to each stream's
  floor), so a stale event from any sender remains dropped after a
  newer event from another sender; duplicates still never apply twice.
  Latest-copy replay on fresh/resumed/parked episodes remains the gap
  recovery path. New test:
  `clipboard_versions_are_globally_comparable`.
- DS-06: `KvmButton` now defines a pressed state and an optional
  custom-content `Tooltip` for disabled reasons. Disabled explanations
  are wired on Connect (enter an address / disconnect first), Device
  Details (available after pairing), roster Connect (disconnect first /
  no address known), rename Save (enter a name), and mesh Configure /
  Apply (arrangement still applying). These supplement the adjacent
  captions already shown by disabled rows and empty states.
- Android (DS-09 parity pass): controller statuses now use the shared
  vocabulary — `Live`, `Connecting`, `Idle`, `Discovered`, and `Error`.
  The connected header says `Live`; `Stop` is renamed `Disconnect`
  with a 32px minimum target. Android still does not implement
  desktop clipboard sync (`clipboard_enabled: false` in its Hello
  advertisement), so full state/capability parity remains unproven on
  a physical device.
- Loop 4 matrix: fresh Mint Xvfb screenshots were captured for
  720x560, 1024x768, 1440x900, and 1920x1080 displays, each in dark
  and light themes — 24 captures across Connect, Devices, and
  Settings. The app window remained the 720x560 minimum on smaller
  displays. A separate resized-window check at 1920x1080 confirmed
  the layout stretches without row overflow; maximized Devices tab
  switching remained usable.
- Tests: core 75, daemon 96, platform 48, protocol 54, UI 14 =
  287 green. `kvm-android` still has a pre-existing Windows-target
  compile issue (`slint::android` is not available off Android), so
  the Android channel was verified by code/doc inspection rather
  than a host build.
- The daemon/UI release pair was deployed after the pass: Windows
  service Running and hashes match for both binaries (`5A380A...` and
  `A0D567...`). It remains necessary for the user to record the
  live 3-node and clipboard 9-step results by requirement ID before
  claiming the spec exit gate is met.

## Definition of done status
Implemented + evidenced: DS (type, targets, colors, focus ring,
pressed/disabled tooltips, reduced motion), SET (rows, menu, header,
focus trap), DEV (roster, states, actions), CON (aligned two-row grid,
complete roster), CB (activation, globally comparable HLC revision,
files, limit toast, offline queue), MN (push honesty). Pending user
loop: live 3-node crossing + clipboard 9-step acceptance on real
machines, plus physical Android controller verification (desktop-side
labels and vocabulary are aligned; Android clipboard capability is
still disabled in its Hello advertisement).
