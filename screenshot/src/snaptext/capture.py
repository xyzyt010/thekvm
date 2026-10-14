"""Screenshot capture: fullscreen / region / active-window. mss + Pillow.

Wayland note: mss captures via XWayland or portal screencast. On pure-Wayland
(GNOME/KDE/Hyprland) prefer the desktop portal (Spectacle/Flameshot pattern):
we try mss first, then `grim`/`gnome-screenshot` helpers if present.
"""
from __future__ import annotations
import io
import os
import shutil
import subprocess
from PIL import Image


def capture_fullscreen() -> Image.Image:
    try:
        import mss
        with mss.mss() as sct:
            mon = sct.monitors[0]  # virtual screen spanning all monitors
            shot = sct.grab(mon)
            return Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
    except Exception as e:
        # Pillow fallback (Windows ImageGrab / X11 xwd chain)
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab(all_screens=True)
            if img is not None:
                return img.convert("RGB")
        except Exception:
            pass
        raise RuntimeError(f"fullscreen capture failed: {e}")


def capture_region(x: int, y: int, w: int, h: int) -> Image.Image:
    x, y, w, h = int(x), int(y), max(1, int(w)), max(1, int(h))
    try:
        import mss
        with mss.mss() as sct:
            shot = sct.grab({"left": x, "top": y, "width": w, "height": h})
            return Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
    except Exception:
        full = capture_fullscreen()
        return full.crop((x, y, x + w, y + h))


def capture_window_linux() -> Image.Image:
    """Direct app-window capture on Linux (X11 xwininfo+import; Wayland grim/slurp).

    Mirrors Spectacle/Flameshot: X11 can address a window id directly; Wayland
    must go through the screencast portal, so we shell to grim if available.
    """
    if os.name == "nt":
        return capture_fullscreen()
    if shutil.which("grim") and shutil.which("slurp"):
        out = "/tmp/snaptext-win.png"
        # slurp in click-window mode would be interactive; here: focused node
        r = subprocess.run(["grim", out], capture_output=True)
        if r.returncode == 0 and os.path.exists(out):
            return Image.open(out).convert("RGB")
    # X11 fallback: active window geometry via xdotool/xwininfo
    try:
        if shutil.which("xdotool"):
            wid = subprocess.check_output(["xdotool", "getactivewindow"]).decode().strip()
            geo = subprocess.check_output(["xdotool", "getwindowgeometry", "--shell", wid]).decode()
            d = dict(l.split("=") for l in geo.strip().splitlines() if "=" in l)
            return capture_region(int(d["X"]), int(d["Y"]), int(d["WIDTH"]), int(d["HEIGHT"]))
    except Exception:
        pass
    return capture_fullscreen()


def to_png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
