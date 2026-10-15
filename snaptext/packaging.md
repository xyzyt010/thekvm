# Packaging (v1: Windows x86_64 + Linux x86_64)

## Windows
- Bundle `snaptext-ui.exe` + `tesseract/` binaries. Startup shortcut runs listener (Win+S then C).
- ARM64 gated to v2 (rebuild ONNX + Tesseract ARM64).

## Debian/Ubuntu
- Deps: `tesseract-ocr`, `grim`, `slurp` (Wayland), `xdotool` (X11), fonts.
- XDG autostart `snaptext-listen.desktop` for X11/XFCE; Wayland/Hyprland use compositor binds (see `linux-hotkeys.conf` pattern: `bind=SUPER+S, exec, snaptext-ui`).

## Fedora / Arch
- Same deps via `dnf` / `pacman` (`tesseract`, `grim`, `slurp`, `xdotool`).

## Displays
X11 ✓ · Wayland (portal consent) ✓ · Hyprland (grim+slurp) ✓ · XFCE4 ✓ · Windows ✓.
