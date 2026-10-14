"""GUI-optimised preprocessing. Each engine gets its own preset.

Why GUI screens need this (vs scanned docs): tiny 9-13px fonts, subpixel
antialiasing, low-contrast grey-on-white, emoji/icons, dark mode. Pipeline:
2x LANCZOS upscale -> grayscale -> bilateral denoise -> adaptive threshold
(Tesseract) / keep RGB for neural det/rec (PP-OCR, VLM).
"""
from __future__ import annotations
from PIL import Image, ImageOps


def upscale(img: Image.Image, scale: float = 2.0, dpi: int = 300) -> Image.Image:
    w, h = img.size
    img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
    img.info["dpi"] = (dpi, dpi)
    return img


def for_tesseract(img: Image.Image) -> Image.Image:
    """Grayscale + autocontrast + 2x. Thresholding left to Tesseract's LSTM
    (Otsu here hurts subpixel text); caller may apply .point() if binary wanted."""
    g = upscale(img.convert("L"))
    g = ImageOps.autocontrast(g, cutoff=1)
    return g


def for_ppocr(img: Image.Image) -> Image.Image:
    """Neural detectors want RGB at native-ish res capped to limit_side_len."""
    w, h = img.size
    m = max(w, h)
    if m > 1536:  # PP-OCR limit_side_len 960..1536 for UI text
        s = 1536.0 / m
        img = img.resize((int(w * s), int(h * s)), Image.LANCZOS)
    return img.convert("RGB")


def for_docling(img: Image.Image) -> Image.Image:
    return upscale(img.convert("RGB"), scale=2.0)


def for_vlm(img: Image.Image, max_side: int = 1536) -> Image.Image:
    w, h = img.size
    m = max(w, h)
    if m > max_side:
        s = max_side / m
        img = img.resize((int(w * s), int(h * s)), Image.LANCZOS)
    return img.convert("RGB")
