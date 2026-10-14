"""SnapText CLI (v1: windows/linux x86_64)."""
from __future__ import annotations
import argparse
import json
import os
import sys
import time

from .device import get_device_profile
from .recommender import load_catalog, recommend


def cmd_recommend(_a):
    p = get_device_profile()
    r = recommend(p)
    print(json.dumps({"profile": p, "recommendation": {k: v for k, v in r.items() if k != "supported"},
                      "supported": [m["id"] for m in r["supported"]]}, indent=2))
    print(f"\nRecommended: {r['model']} [{r['mode']}/{r['engine']}] — {r['reason']}")
    return 0


def cmd_capture(a):
    from PIL import Image
    from . import capture as cap
    from . import pipeline as pl
    from . import overlay_pdf as ov
    from . import clipboard as cb

    # 1. acquire image
    if a.image:
        img = Image.open(a.image).convert("RGB")
    elif a.window:
        img = cap.capture_window_linux()
    elif a.interactive:
        full = cap.capture_fullscreen()
        from . import selector as sel
        if not sel.can_show_gui():
            print("no GUI display; using fullscreen")
            img = full
        else:
            picked = sel.select_region(full)
            if picked is None:
                print("selection cancelled")
                return 2
            _x, _y, _w, _h, img = picked
    else:
        if a.region:
            x, y, w, h = (int(v) for v in a.region.split(","))
            img = cap.capture_region(x, y, w, h)
        else:
            img = cap.capture_fullscreen()

    # 2. recognise
    t0 = time.time()
    mode = a.mode
    if mode == "auto":
        res, trace = pl.run_auto(img, engine=a.engine, model=a.model, vlm_model=a.vlm_model)
    elif mode == "vlm":
        res = pl.run_vlm(img, a.vlm_model or "paddleocr-vl-0.9b")
        trace = {"mode": "vlm"}
    else:
        res = pl.run_ocr(img, a.engine, a.model)
        trace = {"mode": "ocr"}
    dt = int((time.time() - t0) * 1000)
    trace["elapsed_ms"] = dt

    # 3. outputs
    print(f"engine={res.engine} conf={res.mean_conf:.2f} boxes={len(res.boxes)} {dt}ms")
    print("---- text ----")
    print(res.text)
    print("--------------")
    if a.copy or a.auto_copy:
        ok = cb.copy_text(res.text)
        print(f"clipboard: {'copied' if ok else 'FAILED'}")
    if a.pdf:
        data = ov.searchable_pdf(img, res)
        open(a.pdf, "wb").write(data)
        print(f"searchable PDF -> {a.pdf} ({len(data)} bytes)")
    if a.overlay_png:
        out = ov.image_with_overlay(img, res)
        out.save(a.overlay_png)
        print(f"overlay image -> {a.overlay_png}")
    if a.save_png:
        img.save(a.save_png)
        print(f"screenshot -> {a.save_png}")
    if a.trace:
        print(json.dumps(trace))
    return 0


def cmd_bench(a):
    import time
    from PIL import Image, ImageDraw
    # synthetic GUI-like image so bench works with zero fixtures
    img = Image.new("RGB", (900, 360), "white")
    d = ImageDraw.Draw(img)
    d.text((30, 30), "SnapText benchmark  File  Edit  View  Settings", fill="black")
    d.text((30, 90), "Terminal: sudo apt install thekvm  # tiny 12px UI text", fill=(40, 40, 40))
    d.text((30, 150), "Browser address bar  https://example.com/search?q=ocr", fill=(60, 60, 60))
    d.rectangle([28, 28, 870, 200], outline="gray")
    if a.image and os.path.exists(a.image):
        img = Image.open(a.image).convert("RGB")
    from . import pipeline as pl
    for engine, model in (("tesseract", "fast"), ("ppocr", "v5-mobile")):
        try:
            t0 = time.time()
            r = pl.run_ocr(img, engine, model if engine == "ppocr" else "")
            dt = int((time.time() - t0) * 1000)
            print(f"{engine}/{model}: conf={r.mean_conf:.2f} boxes={len(r.boxes)} {dt}ms text={r.text[:80]!r}")
        except Exception as e:
            print(f"{engine}/{model}: SKIP ({e})")
    return 0


def cmd_settings(_a):
    p = get_device_profile()
    r = recommend(p)
    from . import settings_ui as sui
    sui.show_settings(p, r)
    return 0


def cmd_listen(_a):
    from . import hotkeys as hk
    from .device import detect_display_server
    print("listening for Super+S then C ... Ctrl+C to stop")
    print(hk.linux_register_hint(detect_display_server()))
    import subprocess
    hk.listen_and_capture(lambda: subprocess.Popen(
        [sys.executable, "-m", "snaptext", "capture", "--interactive",
         "--mode", "auto", "--copy"]))
    return 0


def build_parser():
    ap = argparse.ArgumentParser("snaptext")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("recommend", help="show best OCR/VLM for this device")
    s.set_defaults(fn=cmd_recommend)
    c = sub.add_parser("capture", help="screenshot -> overlay PDF + auto-copy text")
    c.add_argument("--mode", default="auto", choices=["ocr", "vlm", "auto"])
    c.add_argument("--engine", default="ppocr", choices=["ppocr", "tesseract", "docling"])
    c.add_argument("--model", default="")
    c.add_argument("--vlm-model", default="paddleocr-vl-0.9b")
    c.add_argument("--image", default="")
    c.add_argument("--region", default="", help="x,y,w,h")
    c.add_argument("--window", action="store_true", help="Linux direct app-window capture")
    c.add_argument("--interactive", action="store_true", help="freeze + rect + pencil selector")
    c.add_argument("--copy", action="store_true")
    c.add_argument("--auto-copy", action="store_true")
    c.add_argument("--pdf", default="")
    c.add_argument("--overlay-png", default="")
    c.add_argument("--save-png", default="")
    c.add_argument("--trace", action="store_true")
    c.set_defaults(fn=cmd_capture)
    b = sub.add_parser("bench", help="synthetic GUI bench (no fixtures needed)")
    b.add_argument("--image", default="")
    b.set_defaults(fn=cmd_bench)
    st = sub.add_parser("settings", help="accuracy/speed bars for supported models")
    st.set_defaults(fn=cmd_settings)
    li = sub.add_parser("listen", help="Super+S then C hotkey listener")
    li.set_defaults(fn=cmd_listen)
    return ap


def main(argv=None):
    ap = build_parser()
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
