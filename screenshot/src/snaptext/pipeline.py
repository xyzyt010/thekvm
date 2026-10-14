"""OCR/VLM pipeline: fast OCR first, VLM fallback/escalation.

Modes:
  ocr  — single engine (tesseract | ppocr | docling), GUI presets.
  vlm  — PaddleOCR-VL directly (overlay PDF + extract+copy).
  auto — OCR, escalate to VLM when mean_conf < threshold (default 0.75)
         or boxes empty. Returns (result, trace).
"""
from __future__ import annotations
from PIL import Image
from .ocr_base import OcrResult


def run_ocr(img: Image.Image, engine: str = "ppocr", model: str = "") -> OcrResult:
    if engine == "tesseract":
        from . import ocr_tesseract as e
        return e.run(img, best=("best" in model or not model))
    if engine == "docling":
        from . import ocr_docling as e
        return e.run(img)
    # default ppocr
    from . import ocr_ppocr as e
    variant = "v6-server" if ("v6" in model or "server" in model or not model) else "v5-mobile"
    return e.run(img, variant=variant)


def run_vlm(img: Image.Image, model: str = "paddleocr-vl-0.9b") -> OcrResult:
    from . import vlm_paddleocr_vl as v
    return v.run(img, model_id=model or "paddleocr-vl-0.9b")


def run_auto(img: Image.Image, engine: str = "ppocr", model: str = "",
             vlm_model: str = "paddleocr-vl-0.9b", conf_threshold: float = 0.75) -> tuple[OcrResult, dict]:
    trace = {"escalated": False}
    try:
        ocr = run_ocr(img, engine, model)
    except Exception as e:
        trace["ocr_error"] = str(e)
        ocr = OcrResult(engine, "", [])
    trace.update({"ocr_engine": ocr.engine, "ocr_conf": round(ocr.mean_conf, 3),
                  "ocr_boxes": len(ocr.boxes)})
    if ocr.mean_conf >= conf_threshold and ocr.boxes:
        return ocr, trace
    try:
        vlm = run_vlm(img, vlm_model)
        trace.update({"escalated": True, "vlm_conf": round(vlm.mean_conf, 3),
                      "vlm_boxes": len(vlm.boxes)})
        # Keep OCR boxes where VLM found nothing overlapping? v1: prefer VLM.
        return vlm, trace
    except Exception as e:
        trace.update({"escalated": False, "vlm_error": str(e)})
        return ocr, trace
