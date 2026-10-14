"""Settings window: supported-models only, accuracy/speed bars.

Uses tkinter Canvas bars (no extra deps). Lab numbers come from
models_catalog.json; `snaptext bench` writes measured ms into
~/.config/snaptext/bench.json which overrides speed bars on this machine.
"""
from __future__ import annotations
import json
import os


def _bench_overrides() -> dict:
    p = os.path.expanduser("~/.config/snaptext/bench.json")
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def show_settings(profile: dict, recommendation: dict):
    import tkinter as tk
    ov = _bench_overrides()
    sup = recommendation.get("supported", [])
    rec_id = recommendation.get("model")

    root = tk.Tk()
    root.title("SnapText settings — models for this device")
    tk.Label(root, text=f"{profile['os']} {profile['arch']}  "
             f"{profile['cores_logical']} cores  {profile['ram_gb']}GB  [{profile['display']}]",
             font=("TkDefaultFont", 10, "bold")).pack(padx=12, pady=(10, 2))
    tk.Label(root, text=f"Recommended: {rec_id} ({recommendation.get('mode')}) — {recommendation.get('reason')}",
             wraplength=560, justify="left").pack(padx=12, pady=4)

    cv = tk.Canvas(root, width=600, height=max(220, 60 + 64 * max(1, len(sup))))
    cv.pack(padx=12, pady=8, fill="both", expand=True)
    y = 10
    max_ms = max([(m.get("speed_ms_ref", 1000)) for m in sup] + [1])
    for m in sorted(sup, key=lambda m: -m["accuracy_gui"]):
        mid = m["id"]
        ms = ov.get(mid, m["speed_ms_ref"])
        acc_w = int(m["accuracy_gui"] * 220)
        spd_w = int(220 * (1 - min(1.0, ms / (max_ms * 1.2))))
        mark = "  <-- recommended" if mid == rec_id else ""
        cv.create_text(8, y, anchor="nw", text=f"{mid}{mark}", font=("TkDefaultFont", 9, "bold"))
        y += 16
        cv.create_text(8, y, anchor="nw", text="accuracy", font=("TkDefaultFont", 8))
        cv.create_rectangle(80, y, 80 + 220, y + 12, outline="gray")
        cv.create_rectangle(80, y, 80 + acc_w, y + 12, fill="#2ecc71", outline="")
        cv.create_text(306, y, anchor="nw", text=f"{m['accuracy_gui']:.0%}", font=("TkDefaultFont", 8))
        y += 16
        cv.create_text(8, y, anchor="nw", text=f"speed {ms}ms", font=("TkDefaultFont", 8))
        cv.create_rectangle(80, y, 80 + 220, y + 12, outline="gray")
        cv.create_rectangle(80, y, 80 + spd_w, y + 12, fill="#3498db", outline="")
        y += 22
    tk.Label(root, text="Unsupported models (RAM/cores/arch) are hidden by design.",
             fg="gray").pack(pady=(0, 10))
    root.mainloop()
