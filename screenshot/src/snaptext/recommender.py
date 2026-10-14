"""Smart recommender: filter catalog to what this device can run, rank OCR vs VLM."""
from __future__ import annotations
import json
import os
from .device import arch_key

_CATALOG = os.path.join(os.path.dirname(__file__), "models_catalog.json")


def load_catalog(path: str = _CATALOG) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _arch_ok(entry_arches, machine: str) -> bool:
    norm = {a.lower() for a in entry_arches}
    mk = arch_key(machine)
    ml = machine.lower()
    return mk in {a.lower() for a in norm} or ml in norm or "x86_64" in norm and mk == "x86_64"


def supported_models(profile: dict, catalog: dict | None = None) -> list[dict]:
    catalog = catalog or load_catalog()
    out = []
    for m in catalog["models"]:
        if profile["os"] not in [o.lower() for o in m["os"]]:
            continue
        if not _arch_ok(m["arch"], profile["arch"]):
            continue
        if profile["ram_gb"] + 1e-9 < float(m["min_ram_gb"]):
            continue
        if profile["cores_logical"] < int(m["min_cores"]):
            continue
        out.append(m)
    return out


def recommend(profile: dict, catalog: dict | None = None) -> dict:
    """Return {mode, engine, model, reason, supported[]}.

    Policy (v1, CPU-only, on-device):
    - <4GB or <=2 cores -> tesseract-fast (ocr).
    - 4-8GB -> ppocrv5-mobile if present else tesseract-best.
    - 8GB+ & >=4 cores -> ppocrv6-server for pure text; paddleocr-vl-0.9b if
      user wants max accuracy / tiny text / handwriting-ish UI.
    - 16GB+ & >=6 cores -> paddleocr-vl-1.7b becomes default VLM option.
    """
    sup = supported_models(profile, catalog)
    by_id = {m["id"]: m for m in sup}
    ram = profile["ram_gb"]
    cores = profile["cores_logical"]

    if "paddleocr-vl-1.7b" in by_id and ram >= 16 and cores >= 6:
        rec, mode = by_id["paddleocr-vl-1.7b"], "vlm"
        reason = "16GB+ / 6+ cores: VLM top accuracy fits in RAM."
    elif "paddleocr-vl-0.9b" in by_id and ram >= 8 and cores >= 4:
        # default OCR pick is still PP-OCRv6 for speed; VLM is alt for hard cases
        rec = by_id.get("ppocrv6-server") or by_id["paddleocr-vl-0.9b"]
        mode = "ocr" if rec["family"] == "ocr" else "vlm"
        reason = "8GB+: PP-OCRv6 fastest accurate OCR; VLM 0.9B for tiny/low-contrast text."
    elif "ppocrv5-mobile" in by_id:
        rec, mode = by_id["ppocrv5-mobile"], "ocr"
        reason = "4GB+: PP-OCRv5 mobile balances GUI accuracy and CPU speed."
    elif "tesseract-best" in by_id:
        rec, mode = by_id["tesseract-best"], "ocr"
        reason = "Mid device: Tesseract best-preset ensemble."
    elif "tesseract-fast" in by_id:
        rec, mode = by_id["tesseract-fast"], "ocr"
        reason = "Low RAM/cores: Tesseract fast only viable on-device option."
    elif sup:
        rec, mode = sorted(sup, key=lambda m: -m["accuracy_gui"])[0], sup[0]["family"]
        reason = "Fallback: highest-accuracy supported model."
    else:
        return {"mode": "ocr", "engine": "tesseract", "model": "tesseract-fast",
                "reason": "No catalog model fits; install Tesseract binary (works everywhere).",
                "supported": []}
    return {"mode": mode, "engine": rec["engine"], "model": rec["id"],
            "reason": reason, "supported": sup}
