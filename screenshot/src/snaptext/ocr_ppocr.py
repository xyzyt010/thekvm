"""PP-OCRv5/v6, GUI-optimised. Uses rapidocr -> paddleocr -> paddlex, first wins.

GUI tuning (small UI fonts, dense labels):
  det_db_thresh=0.3 det_db_box_thresh=0.5 det_db_unclip_ratio=1.8
  rec_batch_num=6, cls=True, limit_side_len=960 (mobile) / 1536 (server).
If no backend installed, raises RuntimeError with install hint (recommender
hides the model in that case only if user forces it).
"""
from __future__ import annotations
from PIL import Image
import numpy as np
from .ocr_base import OcrBox, OcrResult
from . import preprocess as pp


def _rapidocr(img: Image.Image, server: bool) -> OcrResult:
    from rapidocr import RapidOCR
    eng = RapidOCR(params={
        "Det.det_db_thresh": 0.3,
        "Det.det_db_box_thresh": 0.5,
        "Det.det_db_unclip_ratio": 1.8,
        "Det.det_limit_side_len": 1536 if server else 960,
        "Det.det_limit_type": "max",
        "Cls.cls": True,
        "Rec.rec_batch_num": 6,
    })
    arr = np.array(pp.for_ppocr(img))
    out = eng(arr)
    boxes: list[OcrBox] = []
    texts: list[str] = []
    # rapidocr>=3 returns RapidOCROutput with .boxes/.txts/.scores
    try:
        rboxes = getattr(out, "boxes", None)
        rtxts = getattr(out, "txts", None)
        rscores = getattr(out, "scores", None)
        if rboxes is not None and rtxts is not None:
            for b, t, s in zip(rboxes, rtxts, rscores or [1.0] * len(rtxts)):
                xs = [float(p[0]) for p in b]
                ys = [float(p[1]) for p in b]
                x, y = int(min(xs)), int(min(ys))
                boxes.append(OcrBox(str(t), x, y,
                                    int(max(xs) - x), int(max(ys) - y), float(s)))
                texts.append(str(t))
            return OcrResult("ppocr", "\n".join(texts), boxes)
    except Exception:
        pass
    if out:
        # legacy: (boxes, txts, scores) tuple or list of [box, txt, score]
        try:
            result = out[0] if isinstance(out, tuple) else out
            if isinstance(result, (list, tuple)) and result and isinstance(result[0], (list, tuple)):
                # list of [box, txt, score]
                for item in result:
                    if len(item) < 3:
                        continue
                    pts, txt, score = item[0], str(item[1]), float(item[2])
                    xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
                    x, y = int(min(xs)), int(min(ys))
                    boxes.append(OcrBox(txt, x, y, int(max(xs) - x), int(max(ys) - y), score))
                    texts.append(txt)
            else:
                boxes_, txts, scores = out
                for b, t, s in zip(boxes_ or [], txts or [], scores or []):
                    xs = [p[0] for p in b]; ys = [p[1] for p in b]
                    x, y = int(min(xs)), int(min(ys))
                    boxes.append(OcrBox(str(t), x, y, int(max(xs) - x), int(max(ys) - y), float(s)))
                    texts.append(str(t))
        except Exception:
            pass
    return OcrResult("ppocr", "\n".join(texts), boxes)


def _paddleocr(img: Image.Image, server: bool) -> OcrResult:
    from paddleocr import PaddleOCR
    ocr = PaddleOCR(use_doc_orientation_classify=False, use_doc_unwarping=False,
                    use_textline_orientation=server)
    prepped = pp.for_ppocr(img)
    res = ocr.predict(str(_save_tmp(prepped)))
    boxes: list[OcrBox] = []
    texts: list[str] = []
    for page in res or []:
        for t, b, s in zip(page.get("rec_texts", []), page.get("rec_boxes", []), page.get("rec_scores", [])):
            x, y = int(b[0]), int(b[1])
            boxes.append(OcrBox(str(t), x, y, int(b[2] - b[0]), int(b[3] - b[1]), float(s)))
            texts.append(str(t))
    return OcrResult("ppocr", "\n".join(texts), boxes)


def _save_tmp(img: Image.Image) -> str:
    import tempfile, os
    d = tempfile.mkdtemp(prefix="snaptext-ppocr-")
    p = os.path.join(d, "in.png")
    img.save(p)
    return p


def run(img: Image.Image, variant: str = "v6-server") -> OcrResult:
    server = "server" in variant or "v6" in variant
    errs = []
    for name, fn in (("rapidocr", _rapidocr), ("paddleocr", _paddleocr)):
        try:
            return fn(img, server)
        except ImportError as e:
            errs.append(f"{name}: {e}")
        except Exception as e:
            errs.append(f"{name}: {e}")
    raise RuntimeError("No PP-OCR backend available (tried rapidocr, paddleocr). "
                       "pip install rapidocr paddleocr paddlex. Details: " + " | ".join(errs))
