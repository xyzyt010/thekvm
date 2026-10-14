# SnapText (Rust) — on-device screenshot OCR/VLM

Isolated sub-workspace. Nothing here mixes with the top-level TheKVM
workspace (`kvm-*` crates stay untouched). v1 targets: Windows x86_64 +
Linux x86_64. ARM64 + Fedora/Arch packaging gated to v2.

- `core/` — `snaptext-core`: custom Rust backend (device profiler,
  model catalog + recommender, capture, GUI-optimised OCR/VLM traits,
  pipeline, searchable-PDF overlay, clipboard, hotkeys).
- `ui/` — `snaptext-ui`: Slint frontend with proper buttons, engine
  selection, processing spinner, settings accuracy/speed bars.

Engines: Tesseract (fast/best presets), PP-OCRv5-mobile / PP-OCRv6-server,
Docling, PaddleOCR-VL 0.9B / 1.7B. Hotkey: Super+S then C (Linux X11/XFCE
listener; Wayland/Hyprland via compositor bind). Displays: X11, Wayland,
Hyprland, XFCE4, Windows.

Build: `cargo build -p snaptext-ui` (from `snaptext/` or workspace root
with `--manifest-path snaptext/Cargo.toml`).
