## TheKVM Android controller

Controller-only Android client for TheKVM. An Android phone can drive Windows or Linux computers; Android devices are hidden from discovery, so Android cannot control Android.

### Install
Download `TheKVM-Android.apk` and install it on your phone (allow installing unknown apps). Requires Android 8.0 (API 26) or newer, arm64.

### First connection — Allow/Deny, no code
Pick the computer in the dropdown and press Connect. An approval card appears on the computer; click **Allow**. No code is typed anywhere. The computer is remembered and reconnects automatically until **Forget** in Settings.

### Multiple computers
Up to 10 can stay connected. The Devices page lists live sessions with **Control** and **Stop**; switching routes input without re-pairing.

### Trackpad gestures
| Gesture | Action |
|---|---|
| One-finger drag | Move cursor |
| Tap | Left click |
| Two quick taps | Double click |
| Press and hold, then drag | Drag (button held) |
| Two-finger tap | Right click |
| Two-finger drag | Scroll (both axes) |
| Two-finger pinch | Zoom |

The **↻ Flat / ↻ Side** button in the top bar rotates the trackpad axis mapping 90° for landscape use. The device dropdown and settings bars stay where they are; the typing bar becomes a single-line horizontal strip in Side mode.

A small `touch N · sent N · last dx,dy` counter on the trackpad shows live input health.

### Typing
The bottom bar grows 1→5 lines, then scrolls. **Send text** injects real Unicode keystrokes; Settings can switch to clipboard paste.

### Display
The interface fills the screen and scales to device width, respects system bars/cutouts, and keeps the typing bar above the software keyboard.

### Notes
- Desktop side must be 0.9.94 or newer.
- Signed with the self-signed development key included in the source tree.
