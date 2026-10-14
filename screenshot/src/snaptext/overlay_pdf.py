"""Searchable PDF (invisible text layer) + visible-overlay PNG.

overlay_pdf(): reportlab PDF, page size = image pixels @72dpi, each OcrBox
rendered as invisible selectable text at its rect (Flameshot/ShareX-style
'copyable screenshot'). image_with_overlay(): PIL copy with optional
semi-transparent boxes + text labels for the 'image with overlayed text' mode.
"""
from __future__ import annotations
import io
from PIL import Image, ImageDraw, ImageFont
from .ocr_base import OcrResult


def searchable_pdf(img: Image.Image, result: OcrResult) -> bytes:
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
    buf = io.BytesIO()
    w, h = img.size
    c = canvas.Canvas(buf, pagesize=(w, h))
    c.drawImage(ImageReader(img.convert("RGB")), 0, 0, width=w, height=h)
    c.setFillColorRGB(1, 1, 1, alpha=0)
    for b in result.boxes:
        if not b.text.strip():
            continue
        size = max(6, min(48, int(b.h * 0.9) or 12))
        try:
            c.setFont("Helvetica", size)
        except Exception:
            pass
        # PDF origin bottom-left: flip y
        c.drawString(b.x, h - b.y - b.h, b.text)
    # Full text also in metadata-adjacent invisible block for naive extractors
    c.setFillColorRGB(1, 1, 1, alpha=0)
    c.setFont("Helvetica", 1)
    y = h - 2
    for line in result.text.splitlines()[:200]:
        c.drawString(2, y, line[:300])
        y -= 2
        if y < 0:
            break
    c.showPage()
    c.save()
    return buf.getvalue()


def image_with_overlay(img: Image.Image, result: OcrResult,
                       box_color=(255, 0, 0), alpha: int = 70) -> Image.Image:
    base = img.convert("RGBA")
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for b in result.boxes:
        d.rectangle([b.x, b.y, b.x + b.w, b.y + b.h],
                    outline=box_color + (255,), width=2,
                    fill=box_color + (alpha,))
    out = Image.alpha_composite(base, layer).convert("RGB")
    d2 = ImageDraw.Draw(out)
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
    for b in result.boxes:
        if b.text.strip():
            d2.text((b.x + 3, b.y + 2), b.text, fill=(255, 255, 0), font=font)
    return out
