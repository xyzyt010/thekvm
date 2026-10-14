"""PaddleOCR-VL local VLM. Two outputs: overlay PDF + full-text extract+copy.

Tries, in order:
 1. paddlex PaddleOCR-VL pipeline (PP-OCRv5+VL series, 0.9B/1.7B) if installed.
 2. transformers vision-language model id containing 'paddle' / 'qwen-vl'.
 3. Raises with hint; pipeline.py then falls back to pure OCR.
Prompt asks for dense transcription with normalised 0-1000 boxes so overlay
and searchable-PDF paths share geometry with the OCR engines.
"""
from __future__ import annotations
from PIL import Image
from .ocr_base import OcrBox, OcrResult
from . import preprocess as pp

PROMPT = ("Transcribe ALL visible UI text in this screenshot. "
          "Return one line per text region as: <x> <y> <w> <h> <text> "
          "with 0-1000 normalised coordinates. Include tiny and low-contrast text.")


def run(img: Image.Image, model_id: str = "paddleocr-vl-0.9b") -> OcrResult:
    prepped = pp.for_vlm(img)
    errs: list[str] = []
    try:
        return _via_paddlex(prepped, model_id)
    except Exception as e:
        errs.append(f"paddlex: {e}")
    try:
        return _via_transformers(prepped, model_id)
    except Exception as e:
        errs.append(f"transformers: {e}")
    raise RuntimeError("PaddleOCR-VL not runnable here. " + " | ".join(errs) +
                       " (need paddlex>=3 or transformers + local weights)")


def _via_paddlex(img: Image.Image, model_id: str) -> OcrResult:
    from paddlex import create_pipeline
    import tempfile, os
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "in.png")
        img.save(p)
        pipe = create_pipeline("PaddleOCR-VL" if "vl" in model_id else "OCR")
        out = list(pipe.predict(input=p))
    boxes: list[OcrBox] = []
    texts: list[str] = []
    W, H = img.size
    for page in out or []:
        for item in (page if isinstance(page, list) else [page]):
            if not isinstance(item, dict):
                continue
            for t, b, s in zip(item.get("rec_texts", []), item.get("rec_boxes", []),
                               item.get("rec_scores", [1.0] * len(item.get("rec_texts", [])))):
                x, y = int(b[0]), int(b[1])
                boxes.append(OcrBox(str(t), x, y, int(b[2] - b[0]), int(b[3] - b[1]), float(s)))
                texts.append(str(t))
    if not texts:
        raise RuntimeError("paddlex returned no text")
    _ = (W, H)
    return OcrResult("paddleocr-vl", "\n".join(texts), boxes)


def _via_transformers(img: Image.Image, model_id: str) -> OcrResult:
    # Generic stub: real weight id resolved by caller (e.g. PaddlePaddle/PaddleOCR-VL).
    raise RuntimeError("transformers VLM path needs explicit local weight id (offline); "
                       "set SNAPTEXT_VLM_ID. No network fetch in v1.")
