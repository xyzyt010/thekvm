# SnapText — on-device screenshot OCR/VLM (v1: Windows x86_64 + Linux x86_64)

Local-first screenshot → text app. No cloud. All OCR/VLM runs on device.

## Engines (v1)

OCR (GUI-optimised presets in `src/snaptext/preprocess.py` + per-engine files):
- **Tesseract** (`ocr_tesseract.py`) — `--oem 1 --psm 6` (+ PSM 11 fallback), 300 DPI upscale, `preserve_interword_spaces=1`. Fast on low RAM.
- **PP-OCRv5/v6** (`ocr_ppocr.py`) — via `rapidocr` / `paddleocr` / `paddlex` if installed, else ONNX stub. Tuned for small UI text: `det_db_thresh 0.3`, `unclip_ratio 1.8`, `limit_side_len 960-1536`, cls on.
- **Docling** (`ocr_docling.py`) — `do_ocr=True`, image scale 2.0, tables off for screenshots.

VLM:
- **PaddleOCR-VL** (`vlm_paddleocr_vl.py`) — latest local VLM, dense OCR with 0-1000 normalised boxes. Two outputs: (1) image with overlayed text as searchable **PDF**, (2) extract + auto-copy all text.
- Generic local VLM (`vlm_generic.py`) — Ollama / llama.cpp / transformers fallback.

## Pipeline

```
capture (mss) → freeze overlay (tkinter, rect + pencil) → preprocess (GUI) → OCR and/or VLM → overlay PDF + image → auto-copy clipboard
```

`pipeline.py` runs OCR→VLM fallback: fast OCR first, VLM only if confidence low or user forces `--mode vlm`.

## Hotkeys

- Linux: `Super+S` then `C` (also single `Super+Shift+S` fallback). X11 via `pynput`, Wayland/Hyprland via compositor keybind → `snaptext capture`, XFCE via `xfce4-keyboard-shortcuts`.
- Windows: `Win+Shift+S`-style hook via `RegisterHotKey` + `pynput` listener → `snaptext capture`. No admin needed for user session.
- See `hotkeys.py` + `packaging/` notes.

## Displays

Windows 10/11, Linux: X11, Wayland (GNOME/KDE), Hyprland, XFCE4 (+ Sway/Wlroots via portal). Detection in `device.py`.

## Smart recommender

`device.py` (CPU/RAM/arch/OS/display) + `recommender.py` filters `models_catalog.json` to only supported models, recommends OCR vs VLM, shows accuracy/speed bars in `settings_ui.py`.

## Quickstart (Windows x86_64 / Linux x86_64)

```sh
pip install -r requirements.txt
python -m snaptext recommend        # what runs best on this machine?
python -m snaptext capture --help
python -m snaptext capture --mode ocr --engine ppocr --copy --pdf out.pdf
python -m snaptext settings         # accuracy/speed bars
python -m snaptext bench --image docs/demo.png
```

Linux window-direct: `python -m snaptext capture --window --mode ocr`.
Interactive rect: `python -m snaptext capture --interactive` (freeze + drag + pencil with `B`, `Enter` confirm, `Esc` cancel).

## Layout

```
src/snaptext/  device.py recommender.py capture.py selector.py preprocess.py
               ocr_base.py ocr_tesseract.py ocr_ppocr.py ocr_docling.py
               vlm_paddleocr_vl.py vlm_generic.py pipeline.py overlay_pdf.py
               clipboard.py hotkeys.py settings_ui.py cli.py models_catalog.json
tests/  packaging/ (debian/ fedora/ arch/ windows notes)
```

## Accuracy/speed source

`models_catalog.json` ships with lab numbers on GUI screenshots (IDE, browser, terminal @ 1080p). Run `bench` on your machine to overwrite with measured ms + confidence — settings UI then shows your bars, not lab bars.

## Roadmap (post-v1)

ARM64 (Windows on ARM, Linux aarch64), .deb/.rpm/pacman + Win ARM64 installer, portal screencast for Wayland secure capture, parked VLM quant (Q4/Q5_K_M).
