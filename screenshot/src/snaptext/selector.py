"""Freeze-pane selector: fullscreen borderless window, drag rect, pencil overlay.

Pattern learned from Flameshot / ShareX / Spectacle / GNOME Screenshot:
 1. capture fullscreen FIRST (freeze the viewpane),
 2. show it in a borderless topmost window (frozen frame, live desktop hidden),
 3. drag = rectangular screenshot; B or right-drag = pencil annotation;
 4. Enter/Space confirm, Esc cancel; magnifier label follows cursor.
Loading animation: indeterminate ttk.Progressbar + status text during OCR/VLM.

Headless/test: returns None when no display ($DISPLAY unset on Linux and no
Wayland socket) instead of crashing — CLI then falls back to --window/full.
"""
from __future__ import annotations
import os
from PIL import Image


def can_show_gui() -> bool:
    if os.name == "nt":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def select_region(frozen: Image.Image):
    """Interactive rect select. Returns (x,y,w,h, annotated_image) or None."""
    if not can_show_gui():
        return None
    import tkinter as tk
    from PIL import ImageTk

    result: dict = {}
    strokes: list[list[tuple[int, int]]] = []
    cur: list[tuple[int, int]] = []

    root = tk.Tk()
    root.title("SnapText — drag to select, B=pencil, Enter=confirm, Esc=cancel")
    root.attributes("-fullscreen", True)
    root.attributes("-topmost", True)
    root.configure(cursor="crosshair")

    vw, vh = frozen.size
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    scale = min(sw / max(1, vw), sh / max(1, vh), 1.0)
    disp = frozen if scale >= 1.0 else frozen.resize((int(vw * scale), int(vh * scale)), Image.LANCZOS)
    photo = ImageTk.PhotoImage(disp)

    canvas = tk.Canvas(root, width=sw, height=sh, highlightthickness=0, cursor="crosshair")
    canvas.pack(fill="both", expand=True)
    canvas.create_image(sw // 2, sh // 2, image=photo)
    ox, oy = sw // 2 - disp.size[0] // 2, sh // 2 - disp.size[1] // 2
    dim = canvas.create_rectangle(0, 0, sw, sh, fill="black", stipple="gray50")
    sel = canvas.create_rectangle(0, 0, 0, 0, outline="#00e5ff", width=2)
    mag = canvas.create_text(0, 0, text="", fill="white", font=("TkDefaultFont", 9),
                             anchor="nw")
    state = {"x0": 0, "y0": 0, "x1": 0, "y1": 0, "drag": False, "pencil": False}

    def to_img(px, py):
        return (px - ox) / scale, (py - oy) / scale

    def on_down(e):
        if state["pencil"] or e.num == 3:
            strokes.append([(e.x, e.y)])
        else:
            state.update(x0=e.x, y0=e.y, x1=e.x, y1=e.y, drag=True)

    def on_move(e):
        ix, iy = to_img(e.x, e.y)
        canvas.itemconfig(mag, text=f"{int(ix)}x{int(iy)}")
        canvas.coords(mag, e.x + 14, e.y + 12)
        if strokes and (state["pencil"]):
            strokes[-1].append((e.x, e.y))
            if len(strokes[-1]) >= 2:
                x0, y0 = strokes[-1][-2]
                canvas.create_line(x0, y0, e.x, e.y, fill="#ffea00", width=3,
                                   capstyle="round", smooth=True)
        if state["drag"]:
            state.update(x1=e.x, y1=e.y)
            canvas.coords(sel, state["x0"], state["y0"], state["x1"], state["y1"])
            canvas.coords(dim, 0, 0, sw, sh)

    def on_up(e):
        state["drag"] = False
        if strokes and state["pencil"]:
            return
        x0, y0, x1, y1 = state["x0"], state["y0"], e.x, e.y
        if abs(x1 - x0) < 5 or abs(y1 - y0) < 5:
            return
        confirm()

    def confirm():
        x0, y0, x1, y1 = sorted([state["x0"], state["x1"]])[0], sorted([state["y0"], state["y1"]])[0], \
            sorted([state["x0"], state["x1"]])[1], sorted([state["y0"], state["y1"]])[1]
        ix0, iy0 = to_img(x0, y0)
        ix1, iy1 = to_img(x1, y1)
        ix0, iy0 = max(0, int(ix0)), max(0, int(iy0))
        ix1, iy1 = min(vw, int(ix1)), min(vh, int(iy1))
        result["rect"] = (ix0, iy0, max(1, ix1 - ix0), max(1, iy1 - iy0))
        root.destroy()

    def cancel(_=None):
        result["rect"] = None
        root.destroy()

    def toggle_pencil(_=None):
        state["pencil"] = not state["pencil"]
        root.configure(cursor="pencil" if state["pencil"] else "crosshair")

    root.bind("<ButtonPress>", on_down)
    root.bind("<B1-Motion>", on_move)
    root.bind("<Motion>", on_move)
    root.bind("<ButtonRelease-1>", on_up)
    root.bind("<Return>", lambda _e: confirm())
    root.bind("<space>", lambda _e: confirm())
    root.bind("<Escape>", cancel)
    root.bind("b", toggle_pencil)
    root.bind("B", toggle_pencil)
    # keep a ref or Tk GCs the image
    canvas.image = photo  # type: ignore[attr-defined]
    root.mainloop()

    rect = result.get("rect")
    if not rect:
        return None
    x, y, w, h = rect
    crop = frozen.crop((x, y, x + w, y + h))
    return (x, y, w, h, crop)


def show_loading(parent, text: str = "Recognising text…"):
    """Small indeterminate progress popup; caller must .destroy() it."""
    import tkinter as tk
    from tkinter import ttk
    win = tk.Toplevel(parent) if parent else tk.Tk()
    win.title("SnapText")
    tk.Label(win, text=text, padx=18, pady=8).pack()
    bar = ttk.Progressbar(win, mode="indeterminate", length=260)
    bar.pack(padx=18, pady=(0, 12))
    bar.start(12)
    win.update()
    return win
