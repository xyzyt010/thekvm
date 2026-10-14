# Packaging — v1 Windows x86_64 + Linux x86_64 (ARM64 next)

## Debian/Ubuntu (`packaging/debian/`)
- `snaptext_0.1.0_amd64.deb`: depends `python3, python3-tk, tesseract-ocr, grim, slurp` (Wayland) `xdotool` (X11).
- X11 hotkey: XDG autostart `~/.config/autostart/snaptext-listen.desktop` → `snaptext listen`.
- Wayland/Hyprland: do NOT rely on listener (Super swallowed). Ship
  `hyprland.conf` snippet: `bind=SUPER+S, exec, snaptext capture --interactive --mode auto --copy`.
- GNOME/KDE: Settings → Keyboard → Custom `Super+S` → same command.
- XFCE4: `xfconf-query -c xfce4-keyboard-shortcuts -p /commands/custom/Super+s -s "snaptext capture --interactive"`.

## Fedora (`packaging/fedora/snaptext.spec` notes)
- Same, `dnf install tesseract grim slurp xdotool python3-tkinter`.

## Arch (`packaging/arch/PKGBUILD` notes)
- `pacman -S tesseract tesseract-data-eng grim slurp xdotool tk`.

## Windows (`packaging/windows/`)
- Inno Setup: installs Python venv + `snaptext.exe` (pyinstaller), Tesseract
  binary bundled (`tesseract/`), Startup shortcut `snaptext listen` (Win+S then C).
- No admin needed except installer. ARM64: same spec, rebuild ONNX Runtime ARM64
  wheels + Tesseract ARM64 binary (gated to v2).

## Display coverage
X11 ✓ (mss+xdotool) · Wayland GNOME/KDE ✓ (portal via grim / screencast) ·
Hyprland ✓ (grim+slurp bind) · XFCE4 ✓ (X11 path) · Windows 10/11 ✓ (mss+ImageGrab).
