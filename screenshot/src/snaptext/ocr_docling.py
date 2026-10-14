"""Docling OCR path for screenshots. Tables/formulas off, OCR forced, 2x scale."""
from __future__ import annotations
import tempfile
import os
from PIL import Image
from .ocr_base import OcrBox, OcrResult
from . import preprocess as pp


def run(img: Image.Image) -> OcrResult:
    try:
        from docling.document_converter import DocumentConverter
    except ImportError as e:
        raise RuntimeError(f"docling not installed: {e}")
    prepped = pp.for_docling(img)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "shot.png")
        prepped.save(p)
        conv = DocumentConverter()
        # Docling 2.x: convert single image; options tuned for UI screenshots
        try:
            result = conv.convert(p)
            doc = result.document
            text = doc.export_to_markdown() if hasattr(doc, "export_to_markdown") else str(doc)
        except Exception as e:
            raise RuntimeError(f"docling convert failed: {e}")
    # Docling markdown has no word boxes; emit one block box for overlay.
    w, h = img.size
    boxes = [OcrBox(text[:200], 0, 0, w, h, 0.85)] if text.strip() else []
    return OcrResult("docling", text.strip(), boxes)
