# TheKVM — Problem Handoff (human language + exact technical detail)

This file describes the remaining problems in plain language, plus the
exact technical facts another agent needs to fix them. No code has been
changed based on this file; it is a diagnosis + reproduction guide.

## Environment (facts, verified)

- Two machines on one LAN:
  - **Windows** laptop `LAPTOP-A1JUOKI0` at `192.168.1.6` (the "Windows hardware").
  - **Linux Mint** desktop `hs01` at `192.168.1.7` (the "Mint hardware"), X11 (`DISPLAY=:0`), 1536x864 @ 96dpi, Yoga 730 touchpad `MSFT0001:02 06CB:7F8F`.
- Repo: `xyzyt010/thekvm`. Last installed: **v0.9.58 on Mint** (`thekvmd.service` active, UDP ports 42110/42111/42112 listening). **Windows must run the exact same release** or nothing below is comparable — mixed versions behave differently by design.
  - Windows installer: `https://github.com/xyzyt010/thekvm/releases/download/v0.9.58/thekvm-0.9.58-setup.exe`
- What v0.9.58 already tried (per its commit `9c1090b`): edge-return
  hysteresis, fresh-input drive arbitration, machine-level clipboard
  relay, login auto-start + auto-reconnect. Every problem below is the
  **residual symptom on top of those fixes** — do not re-apply them,
  find why they are insufficient.
- Transport is UDP-always for mouse motion (encrypted UDP datagrams + per-packet stream fallback). There is no QUIC/plain switch anywhere; do not add one.
- SSH into Mint: user `hs01`, key `~/.ssh/hs01_windows_key` (from the Windows host).
- Mint log locations (strip ANSI color codes before grepping):
  - `~/.config/thekvm/link-*.log` (per-link daemon/child logs — the main evidence)
  - `~/.config/thekvm/ui.log` (UI log, includes lines starting `clipboard relay:`)
  - `journalctl -u thekvmd.service` (service journal)
- Key log lines to search:
  - `topology handoff activated` — has `open_ms=` (crossing cost) and `resumed=` (true = instant park reuse, false = slow cold dial).
  - `topology episode ended` — has `motion_captured / motion_forwarded / udp_packets_sent / motion_dropped_stall`.
  - `yielding to the inbound drive` / `peer is driving us while we drive them` — auto-yield firing (control yanked home).
  - `crossing_refused:` — why an edge push was rejected (cooldown / veto / failed-episode gate).
  - `X11 local suppression engaged` / `released` — grab on/off on Mint (hourglass correlate).
  - `episode caps negotiated` — has `clipboard=true/false`.
  - `peer clipboard transfer complete`, `peer clipboard image received`, `stashed for UI take`, `clipboard relay: applied peer …` — clipboard path evidence.
  - `THEKVM_STATUS dialing|edge-ready|driving|local` — link state machine on stderr.

## Problem 1 — Hourglass cursor (STILL not fixed on v0.9.58)

**Plain language:** While using the link, the mouse pointer flickers and
settles on an hourglass/wait cursor instead of the normal arrow. It
happens around crossings and flaky moments. A stable link should mean a
stable, normal cursor — that is not what happens.

**What is known:** The cursor shape flickers in sync with the drive grab
engaging and releasing several times per second (see `X11 local
suppression engaged grab=Xi` / `released` lines clustered tightly).
Each flap is a full episode teardown: suppression on → drive → yield →
suppression off → cold re-dial → suppression on again. The hourglass is
the visible symptom of this flap loop, plus possibly the OS showing a
busy cursor while the grab/cage warps the pointer.

**What the other agent must do:**
1. Reproduce on demand and capture a 60-second window of `link-*.log` with timestamps.
2. Count grab engage/release pairs per second during the flicker. If they cluster (>2/sec), the flap is still the cause — fix the flap (Problem 2), not the cursor.
3. If the cursor is wrong while the link is provably stable (no yields, one long episode in `episode ended` lines), it is an isolated cursor-shape bug: check what sets the OS cursor on entry on each platform (`kvm-platform/src/capture.rs` Windows hooks, `kvm-platform/src/x11_capture.rs` grab/cage/cursor-hide) and make entry leave the cursor shape alone.

## Problem 2 — Crossing: works, but not super fast/smooth; exits on inactivity; delay after rest

Direction matters: **Windows-hardware-driving-Mint is the good
direction** (strict edge exit, smooth). **Mint-hardware-driving-Windows
improved in v0.9.58** (entering, exiting and moving are smoother) **but
is still broken.** Any fix must not be hardcoded to one machine — same
code paths drive both sides.

### 2a. Not super fast/smooth on both sides + first-time crossing delay

**Plain language:** Crossing works now, but it is not instant and not
buttery on either side — there is a beat of hesitation/lag on every
transfer, and the very first crossing after Connect is noticeably
slower even though the "warming up" spinner showed. The target feel is:
push at the edge and you are there, zero perceptible delay, glide
immediately — every time, both directions.

**What to check:** `topology handoff activated` lines — `open_ms=`
(first vs later crossings) and `resumed=` (true = instant park reuse,
false = cold dial). If the first crossing is still cold, the pre-warm
(pre-warm dial + caps + UDP arming before edge-ready) is failing or
racing the first push — check whether the first push lands before
`THEKVM_STATUS edge-ready`. If later crossings still cost hundreds of
ms, suspects are: parked-stream liveness wait (`take_parked_for`),
yield/failed-episode cooldowns eating the push (`crossing_refused:`
lines), the phantom-handoff veto demanding a second push, and motion
starting on the stream fallback before UDP arms. Measure each stage;
the budget is ~0ms for a resumed cross on LAN.

Relevant knobs (all in `kvm-daemon/src/service.rs` unless noted):
`ENTRY_INSET_PX=32` / `EDGE_PUSH_PX=24` (`kvm-core/src/layout.rs`),
yield cooldown, `park_inside`, `phantom_handoff_veto`, edge-return
hysteresis (new in v0.9.58 — verify it is not adding the hesitation).

### 2b. Mint drive EXITS on inactivity / suddenly, and lags after resting

**Plain language:** While the Mint mouse is driving the Windows screen,
control drops back to Mint by itself: sometimes after I stop moving and
rest, sometimes out of nowhere mid-use. And when I rest and then try to
move again, there is a big delay before anything responds. Expected:
the drive holds as long as the cursor is on the Windows screen no
matter how long I rest, and motion resumes instantly.

**What this means technically — three faces, likely three timers:**
1. **Exit on inactivity:** the idle-dual arbitration (both sides quiet
   for N seconds → yield to local) is firing while the user simply
   rests. Resting is not abandonment: an idle-but-live drive must hold
   indefinitely until the cursor actually returns past the facing edge
   or the peer genuinely takes over. Check the idle thresholds and what
   counts as "activity" (does a held-still drive with zero deltas look
   dead?).
2. **Sudden exits mid-use:** same family as the old mid-screen
   snap-back — virtual remote cursor hitting an edge (`ReturnHome`) or
   receiver hop logic (`hop_edge`/`hop_accum` ≥ `EDGE_PUSH_PX`) while
   the visible cursor is mid-screen, or a yield on stray inbound input
   that survived the v0.9.57 desensitization (`inbound_yield_fires`,
   divert baselines). At the exact snap-back timestamp, determine
   `ReturnHome` vs `yield` vs stall-breaker teardown — different code
   paths, different fixes. Also re-check geometry suspects from before:
   `adopt_peer_geometry`, per-stream Hello geometry, `truth_gap` lines.
3. **High delay after rest:** the parked episode likely died during the
   rest (parked-episode lease/timeout, keep-alive gap, dead association
   detected late), so the first motion after rest pays a full cold
   redial — possibly plus a cooldown refusal first. Check how long a
   park survives idle, whether keep-alive Pings hold it, and what
   `open_ms` reads on the first post-rest push.

### 2c. Sometimes the first clicks do nothing after crossing

**Plain language:** Right after control transfers, the first mouse
clicks are swallowed — I click and nothing happens. Moving more or
clicking again eventually works.

**Candidate causes (unverified — the agent must determine which):**
- Button events arriving before the receiver finishes provisioning
  (injector `ensure_session`, uinput/helper setup) and getting dropped.
- The parked-resume path dropping the first events via `event_barrier`
  (`resume_parked_session` sets `session.event_barrier` then sends
  Handoff + StateSync — a click in that window may be discarded).
- The Windows hook holding `BLOCK_LOCAL` suppression a beat too long
  after drive start, swallowing the first clicks locally.
- StateSync ordering: held-button state applied one frame late.

**How to pin it:** reproduce with timestamps, then check whether the
clicks appear as `motion_captured`-style census at all (capture dead)
or are forwarded but not injected (receiver dropped them). Fix the
losing side, keep the other untouched.

## Problem 3 — FEATURE: auto-start and auto-connect on login (LANDED in v0.9.58 — verify)

**Plain language:** Every reboot/logoff I must manually start TheKVM and
press Connect on both machines. I want: the app starts by itself when I
log in, and it automatically reconnects to the last linked computer
without me pressing anything.

**Status:** v0.9.58 added login auto-start + auto-reconnect (see
`kvm-platform/src/autostart.rs`, UI changes in `kvm-ui/src/main.rs` /
`app.slint`, installer changes in `packaging/windows/thekvm.iss`).
The agent must VERIFY, not re-implement:

**Required behavior:**
1. **Auto-start on login**, per OS conventions:
   - Windows: launch the UI at user logon (Startup folder entry or
     Task Scheduler logon task — no admin prompt, no console flash).
   - Mint: XDG autostart `.desktop` entry installed by the `.deb`.
   - There must be a visible Settings checkbox to turn it on/off on
     each machine independently.
2. **Auto-connect (re-link) on startup:** the app remembers the last
   linked peer (fingerprint + address + link epoch handling) and
   re-establishes the link by itself, showing the same "warming up"
   spinner as a manual Connect. It must respect deliberate Disconnects:
   auto-connect only the last *live-at-shutdown* link, never resurrect
   a link the user ended (the epoch-ban system already distinguishes
   these — reuse it, do not bypass it).
3. Both machines do this independently, so after a power cut the link
   comes back with zero clicks once both are logged in.

## Problem 4 — Clipboard sync: works ONCE, ONE WAY. Must be continuous + bidirectional

**Plain language, exact expectation:** I copy text from any textbox in
any app on computer 1 (Ctrl+C / right-click Copy). Then I drive with
computer 1's own mouse/trackpad across into computer 2, click into any
textbox in any app there, and Paste (Ctrl+V) — and what I copied on
computer 1 appears. It must work identically in reverse (copy on 2,
paste on 1). "Clipboard syncing" means exactly this and nothing else.
Same for screenshots/images: copy an image on 1, paste it on 2.

**The actual contract (read carefully — this is the definition of
done):** after the first copy on ANY machine after connecting, **both
machines hold the same clipboard text**, and from then on **the latest
copy on EITHER machine wins everywhere, continuously, both directions,
fast and fluid**. Concretely: copy text-1 on machine 1 → paste on
machine 2 gives text-1; then copy text-2 on machine 2 → paste on
machine 1 MUST give text-2 (this reverse leg is what fails today), and
paste on machine 2 must also still give text-2. No direction may go
stale, ever. The Mint machine was machine 2 in the failing example.

**Observed symptom on v0.9.58:** the first transfer (machine 1 → 2)
works; the very next copy on machine 2 never arrives on machine 1.
So the pipe works once and then sticks one-way — this smells like
**stale revision/state gating**, not a dead pipe. Suspects, in order:
1. **Revision gate stuck:** the receiver drops pastes whose revision is
   not newer (`revision <= remote_clipboard_revision`). If the first
   paste (or its echo) advanced the receiver's stored revision past
   what the second sender emits — e.g. both sides numbering from the
   same counter, or an echo of text-1 back to machine 1 consuming the
   "new" slot — text-2 is silently discarded. Log both sides'
   revisions at send and at receive-gate time.
2. **Relay `last_seen` stuck:** the UI relay advanced
   `last_seen_revision` to text-1's revision and the take logic never
   reports text-2 as new (slot overwritten? poll answering the old
   chunk? `ClipboardPoll` empty because revisions compare equal?).
3. **Sender-side dedup suppressing the copy:** the Mint agent's
   `last_text` (or image fingerprint) already equals text-2 from its
   own earlier observation — e.g. it saw text-2 when the UI applied an
   echo — so the genuine user copy never emits. Check the agent's
   poll/apply bookkeeping around applied-then-recopied content.
4. **One-shot send path only:** the copy is observed but only forwarded
   when an episode is live at that instant (or only as initial paste on
   the next open), and the second copy falls in a gap — verify the
   stash-for-next-open + live-send both actually fire on the Mint side
   for text-2 (look for the send/skip log lines with byte counts).

**Current architecture (v0.9.58, must be verified live, not assumed):**
- Text rides the episode stream as `ClipboardText` / chunked
  `ClipboardStart/Chunk/End`; images ride `ClipboardImage` /
  `ClipboardImageStart/Chunk/End` (PNG bytes as base64) — see
  `kvm-protocol/src/wire.rs`.
- The sending side's user-session agent (`ClipboardAgent` in
  `kvm-daemon/src/service.rs`, OS touch in
  `kvm-platform/src/clipboard.rs`) observes copies and sends on the
  live episode, or stashes them as the initial paste for the next open
  (copy-then-cross). v0.9.58 moved to a machine-level relay — check
  what that changed about who observes and who sends.
- The receiving side is usually a **headless service with no desktop
  session**, so it cannot touch the OS clipboard. It stashes pastes in
  a relay slot (`stash_inbound_clipboard`) and the logged-in UI takes
  them via `ControlRequest::ClipboardPoll` and applies them
  (`spawn_clipboard_relay` / `apply_relay_paste` in `kvm-ui/src/main.rs`).

**What the other agent must do:**
1. Reproduce the exact two-step sequence (text-1 on machine 1 →
   paste on 2 OK → text-2 on machine 2 → paste on 1 FAILS) with
   timestamps, then walk the chain for text-2 and name the first
   missing link:
   - Was text-2 ever observed on Mint (agent poll log / send-attempt
     line)? If not → sender dedup/observer bug (suspect 3).
   - Was it sent on the wire (`send_clipboard_text` / chunk frames)?
     If not → send gating / cap / no-live-episode bug (suspect 4).
   - Did Windows log `peer clipboard transfer complete`? If not →
     caps (`episode caps negotiated … clipboard=true` both sides) or
     transport.
   - Completed but no `stashed for UI take` → apply/stash threw it
     away (revision gate? suspect 1).
   - Stashed but no `clipboard relay: applied peer …` in the Windows
     UI log → relay take stuck (suspect 2).
2. Then prove continuity, not just one round trip: alternate copies
   5+ times back and forth, and confirm every paste matches the latest
   copy on both machines. A fix that works once is not a fix.
3. Only then test images, same walk (`peer clipboard image received`,
   `transfer complete`, relay applied) — image sync inherits the same
   revision/relay machinery, so fix text continuity first.
4. Speed requirement: from Ctrl+C to pastable-on-peer must feel
   instant (well under a second on LAN). If the relay polls slowly,
   tighten the poll/take cadence — do not accept multi-second lag.

## Problem 5 — WATCH: long-session freeze where clicks stop registering

**Plain language:** After using the link for a long time, clicks stop
doing anything (motion may or may not still work). This happened on old
versions, has NOT been seen on the new ones yet — possibly only because
sessions have not run long enough. Keep it as a regression watch; do
not consider the product stable until a multi-hour session survives it.

**What the agent must do:** run a multi-hour session on v0.9.58+ and,
if clicks die, capture logs at the moment of death and determine which
of these stuck:
- The capture channel filled and button events are being dropped
  (bounded channel + flood — check for coalescing/dedup swallowing
  non-motion events, and release-vs-press barrier handling).
- The injector session died (uinput torn down / helper gone) so sends
  fail silently while the episode looks alive.
- Suppression stuck engaged (grab held with no live drive) so local
  clicks die AND forwarded ones misroute — cross-check
  `suppression_requested` state vs `active` episode.
- The drive task wedged on a write with suppression held (the old
  freeze class: unbounded or long-bounded sends, teardown awaits) —
  check the watchdog/heartbeat lines and any multi-second gaps.
- `event_barrier` / `discarded_event_barrier` grew past live event ids
  and every click is barrier-dropped as "stale".

## Map of the code (where everything lives)

- `kvm-daemon/src/service.rs` — drive router, episodes, yields, parked
  streams, stall breaker, clipboard send/receive/relay, UDP arming.
- `kvm-core/src/layout.rs` — `ENTRY_INSET_PX`, push/yield/return gates.
- `kvm-platform/src/capture.rs` — Windows hooks, echo tag, suppression.
- `kvm-platform/src/x11_capture.rs` — Mint capture, grab/cage.
- `kvm-platform/src/inject.rs` — per-OS injection (clicks land here).
- `kvm-platform/src/clipboard.rs` — arboard wrapper, PNG helpers.
- `kvm-protocol/src/control.rs` — daemon↔UI verbs incl. `ClipboardPoll`.
- `kvm-protocol/src/wire.rs` — episode frames incl. clipboard variants.
- `kvm-ui/src/main.rs`, `kvm-ui/ui/app.slint` — window, spinner,
  clipboard relay thread, session display.
- `.github/workflows/release.yml` — tag-triggered Linux/Windows builds.

## Acceptance checklist (all must be true before calling anything fixed)

1. One 60s+ drive per direction with zero unexpected `yielding` lines
   and zero mid-screen snap-backs; `resumed=true` on re-crosses;
   crossing feels instant both ways including the first push.
2. Rest 60s+ mid-drive without touching anything: the drive holds, and
   the first motion after rest responds instantly (no cold redial lag).
3. First clicks after every crossing work; a multi-hour session never
   loses clicks.
4. Cursor shape stays normal for the whole session on both machines.
5. Clipboard: alternate copies 5+ times back and forth (text, then
   images) — every paste on both machines matches the latest copy
   within a second.
6. Reboot both machines: app starts, link re-establishes itself, 1–5
   still hold with no clicks.
