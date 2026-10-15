# snaptext-core — custom Rust backend

Pure logic, no GUI. `snaptext-ui` (Slint) calls into this.

- `device.rs` — OS/arch/CPU/RAM/display (windows, x11, wayland, hyprland, xfce4).
- `catalog.rs` + `models_catalog.json` — lab accuracy/speed.
- `recommender.rs` — supported-only filter + OCR-vs-VLM pick.
- `capture.rs` — xcap fullscreen/region/window (portal-aware on Wayland).
- `preprocess.rs` — GUI presets (Tesseract 2x+dpi300, PP-OCR side caps, VLM cap).
- `ocr.rs` — Tesseract (`--oem1 --psm6` + PSM11 ensemble) via binary; PP-OCRv5/v6 ONNX preset + weight resolver; Docling stub (v2).
- `vlm.rs` — PaddleOCR-VL 0.9B/1.7B resolver (GGUF cache, v2 bundles).
- `pipeline.rs` — auto escalation at conf < 0.75.
- `overlay.rs` — searchable PDF (ImageXObject, no image-crate clash) + overlay PNG.
- `clipboard.rs` — arboard auto-copy. `hotkeys.rs` — hints + listener hook.

Tests: `cargo test -p snaptext-core` (4 tests: profile, recommender hiding, PDF magic, preprocess sizes).
