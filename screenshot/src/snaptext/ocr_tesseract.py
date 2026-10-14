"""Tesseract OCR, GUI-optimised.

Preset: --oem 1 (LSTM) --psm 6 (uniform block) with PSM 11 (sparse text /
scattered UI labels) fallback; user_defined_dpi 300; preserve_interword_spaces.
Merges both passes by mean confidence.
"""
from __future__ import annotations
import shutil
import subprocess
import tempfile
import os
from PIL import Image
from .ocr_base import OcrBox, OcrResult
from . import preprocess as pp


def tesseract_available() -> bool:
    if shutil.which("tesseract"):
        return True
    try:
        import pytesseract  # noqa
        return True
    except Exception:
        return False


def _run_tesseract(img: Image.Image, psm: int) -> OcrResult:
    cfg = (f"--oem 1 --psm {psm} -c user_defined_dpi=300 "
           f"-c preserve_interword_spaces=1")
    # Prefer pytesseract (parses TSV boxes); else CLI.
    try:
        import pytesseract
        data = pytesseract.image_to_data(img, config=cfg, output_type=pytesseract.Output.DICT)
        boxes: list[OcrBox] = []
        words: list[str] = []
        n = len(data["text"])
        for i in range(n):
            t = (data["text"][i] or "").strip()
            try:
                c = float(data["conf"][i])
            except Exception:
                c = -1.0
            if not t or c < 0:
                continue
            boxes.append(OcrBox(t, int(data["left"][i]), int(data["top"][i]),
                                int(data["width"][i]), int(data["height"][i]), c / 100.0))
            words.append(t)
        return OcrResult("tesseract", " ".join(words), boxes)
    except Exception:
        pass
    # CLI fallback -> TSV
    with tempfile.TemporaryDirectory() as d:
        ip = os.path.join(d, "in.png")
        op = os.path.join(d, "out")
        img.save(ip)
        subprocess.run(["tesseract", ip, op, "--oem", "1", "--psm", str(psm),
                        "-c", "user_defined_dpi=300",
                        "-c", "preserve_interword_spaces=1", "tsv"],
                       capture_output=True, check=False)
        boxes = []
        words = []
        try:
            import csv
            with open(op + ".tsv", encoding="utf-8") as f:
                for row in csv.DictReader(f, delimiter="\t"):
                    if row.get("level") != "5":
                        continue
                    t = (row.get("text") or "").strip()
                    if not t:
                        continue
                    try:
                        c = float(row.get("conf", -1))
                    except Exception:
                        c = -1.0
                    if c < 0:
                        continue
                    boxes.append(OcrBox(t, int(row["left"]), int(row["top"]),
                                        int(row["width"]), int(row["height"]), c / 100.0))
                    words.append(t)
        except FileNotFoundError:
            pass
        return OcrResult("tesseract", " ".join(words), boxes)


def run(img: Image.Image, best: bool = True) -> OcrResult:
    """best=True runs PSM6 + PSM11 ensemble (tesseract-best); False = fast PSM6."""
    prepped = pp.for_tesseract(img)
    r6 = _run_tesseract(prepped, 6)
    if not best or not tesseract_available():
        r6.engine = "tesseract"
        return r6
    # Scale boxes back? for_tesseract upscales 2x — divide coords for overlay.
    r11 = _run_tesseract(prepped, 11)
    pick = r6 if r6.mean_conf >= r11.mean_conf else r11
    # Downscale box coords 2x to original image space.
    for b in pick.boxes:
        b.x //= 2; b.y //= 2; b.w //= 2; b.h //= 2
    if pick is r6:
        for b in pick.boxes:
            pass  # already scaled above
    pick.engine = "tesseract"
    return pick
