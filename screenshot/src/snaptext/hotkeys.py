"""Global hotkeys + OS registration notes.

- Windows: Win+Shift+S style. RegisterHotKey needs a window; here we run a
  pynput listener for <cmd>+shift+s then c? Spec asks Super(=Win)+S+C.
  Sequence: hold Win, press S, then C. Implemented as sequence detector.
- Linux X11/XFCE: pynput listener for <super>+s then c.
- Linux Wayland/Hyprland: compositors swallow Super; register in compositor
  config to exec `snaptext capture --interactive` (see packaging notes).
XFCE: xfce4-keyboard-shortcuts maps Super+S+C similarly.
"""
from __future__ import annotations


SEQUENCE = ["super+s", "c"]  # press Super+S, release, press C — avoids Win conflicts


def listen_and_capture(callback):
    """Block listening for Super+S then C; calls callback() each trigger."""
    try:
        from pynput import keyboard
    except ImportError:
        raise RuntimeError("pynput not installed (pip install pynput)")
    pressed: set[str] = set()
    armed = {"s": False}

    def name(k):
        try:
            return k.char.lower() if hasattr(k, "char") and k.char else str(k).lower()
        except Exception:
            return ""

    def on_press(key):
        nonlocal armed
        n = name(key)
        ks = str(key).lower()
        super_held = any(x in ks for x in ("cmd", "super", "win")) or \
            any("cmd" in p or "super" in p or "win" in p for p in pressed)
        if n == "s" and super_held:
            armed["s"] = True
            return
        if n == "c" and armed["s"]:
            armed["s"] = False
            callback()
        pressed.add(ks)

    def on_release(key):
        try:
            pressed.discard(str(key).lower())
        except Exception:
            pass

    from pynput.keyboard import Listener
    with Listener(on_press=on_press, on_release=on_release) as l:
        l.join()


def windows_register_hint() -> str:
    return ("Windows: run `snaptext listen` at login (Startup shortcut created by "
            "installer). Sequence Win+S then C avoids clashing with Win+Shift+S snip.")


def linux_register_hint(display: str) -> str:
    if display == "hyprland":
        return "Hyprland: bind=SUPER+S, exec snaptext capture --interactive; then C confirms. See packaging/arch-hyprland.conf"
    if display.startswith("xfce"):
        return "XFCE: Settings>Keyboard>Shortcuts: Super+s -> snaptext capture --interactive"
    if display == "x11":
        return "X11: `snaptext listen` or map Super+S+C in Settings>Keyboard."
    return "Wayland: add Custom Shortcut (Super+S) -> `snaptext capture --interactive` in GNOME/KDE settings."
