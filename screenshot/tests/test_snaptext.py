import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from snaptext.device import get_device_profile, detect_display_server
from snaptext.recommender import recommend, supported_models
from snaptext.ocr_base import OcrBox, OcrResult
from snaptext import preprocess as pp
from snaptext import overlay_pdf as ov
from PIL import Image, ImageDraw


def test_device_profile_shape():
    p = get_device_profile()
    assert p["os"] in ("windows", "linux", p["os"])
    assert p["ram_gb"] > 0 and p["cores_logical"] >= 1
    assert isinstance(detect_display_server(), str)


def test_recommender_hides_unsupported():
    tiny = {"os": "linux", "arch": "x86_64", "cores_logical": 1, "ram_gb": 1.0,
            "display": "x11", "cpu": "t", "os_version": "", "python": "", "supported_v1": True}
    r = recommend(tiny)
    assert r["model"] == "tesseract-fast", r
    assert all(m["id"] != "paddleocr-vl-1.7b" for m in r["supported"])
    big = dict(tiny, ram_gb=32.0, cores_logical=8)
    r2 = recommend(big)
    assert r2["model"] == "paddleocr-vl-1.7b", r2


def test_preprocess_sizes():
    img = Image.new("RGB", (320, 200), "white")
    assert pp.for_tesseract(img).size == (640, 400)
    assert pp.for_ppocr(img).mode == "RGB"
    assert pp.for_vlm(img).size[0] <= 1536


def test_overlay_pdf_searchable():
    img = Image.new("RGB", (400, 200), "white")
    d = ImageDraw.Draw(img)
    d.text((20, 40), "Hello GUI", fill="black")
    res = OcrResult("test", "Hello GUI", [OcrBox("Hello GUI", 20, 40, 120, 20, 0.99)])
    pdf = ov.searchable_pdf(img, res)
    assert pdf[:5] == b"%PDF-", pdf[:16]
    assert len(pdf) > 2000
    out = ov.image_with_overlay(img, res)
    assert out.size == img.size
