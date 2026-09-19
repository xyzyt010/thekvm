# PINCH-ZOOM — parked viewport-pinch work (revisit later)

Date parked: 2026-09-19. Live code at tag `v0.9.48` (commit `f131e5d`).
Reason: native viewport pinch via uinput touchscreen proved too big/impossible
for now (Chromium XI2 touch handling produced malformed viewport-only zoom).
Default rendering is now **page-layout zoom** (Ctrl+wheel); this folder holds
everything needed to resume the viewport track.

## What viewport pinch was

Render an inbound `InputEvent::Pinch` as a real two-finger touch gesture on a
lazily created uinput touchscreen (`TheKVM Virtual Touchscreen`) anchored at
the session cursor, so Chromium's own XI2 touch recognizer performs its
viewport pinch (optical scale at cursor, no reflow, no widget, no Ctrl).

## Files (snapshots in this folder; live originals still in tree)

- `inject.rs.viewport-snapshot` — snapshot of `kvm-platform/src/inject.rs`:
  `UinputTouch` module (~line 429+), `UinputDevice::touch`,
  `inject_pinch` / `end_pinch`, `session_touch_anchor`, per-gesture
  `touchscreen pinch gesture started/ended` logging.
- `mt_pinch.rs.viewport-snapshot` — snapshot of `kvm-platform/src/mt_pinch.rs`:
  read-only Linux multitouch tap (pinch-spread recognition for X11
  trackpads; recognition, stays live — only the *rendering* is parked).

## Recognition (stays live, shared with page zoom)

- Windows: `PtpPinch` in `kvm-platform/src/capture.rs` — excursion-based
  unengaged veto (0.9.48 fix: drifty closes engage zoom-out; traveling
  scrolls veto+slide), engaged fast takeover, per-gesture
  `precision-touchpad pinch engaged/ended` logging.
- Linux: `PinchState` in `kvm-platform/src/mt_pinch.rs` (same gate).
- Wire: `InputEvent::Pinch { delta }` / `PinchEnd` (`kvm-core/src/event.rs`).

## Routing (flipped by the parking commit — invert to resume)

- `handle_inbound_pinch` (`kvm-daemon/src/service.rs`): default is now
  `pinch_expansion` (synthetic Ctrl + SmoothWheel = page zoom); native
  touch runs only under `THEKVM_LINUX_PINCH_VIEWPORT=1`.
- To resume: set touch first again (revert that hunk), fix Chromium's
  malformed XI2-touch zoom, keep the excursion-veto recognition as-is.

## Evidence / open problems for the revisit

- xev spies on Brave showed `XI_Touch=0` while raw `RawTouchBegin/End`
  flowed (xi2 trap: 22 begins + 22 ends, zero cooked TouchBegin) — Xorg
  1.21.1.11 + libinput delivered raw but no cooked touch to the client.
- After zoom-in, Chromium showed a stuck zoomed-in viewport-only view
  (not page-layout zoom); `Ctrl+0` reset it.
- Yoga touchscreen produced no Brave response at all (baseline).
- Env flags: `THEKVM_LINUX_PINCH_VIEWPORT=1` restores touch rendering;
  `THEKVM_LINUX_PINCH_PAGE_ZOOM=1` is legacy (now the default behavior);
  `THEKVM_WHEEL_PINCH=1` is the Windows page-zoom opt-out of touch.
