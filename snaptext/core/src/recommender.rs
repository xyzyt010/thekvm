//! Recommender: only supported models shown; OCR vs VLM pick by RAM/cores.
use crate::catalog::ModelEntry;
use crate::device::{arch_key, DeviceProfile};

pub struct Recommendation {
    pub mode: String,
    pub engine: String,
    pub model: String,
    pub reason: String,
    pub supported: Vec<ModelEntry>,
}

fn arch_ok(entry: &[String], machine: &str) -> bool {
    let want = arch_key(machine);
    entry.iter().any(|a| a.to_lowercase() == want || a.to_lowercase() == machine.to_lowercase())
}

pub fn supported(profile: &DeviceProfile, all: &[ModelEntry]) -> Vec<ModelEntry> {
    all.iter()
        .filter(|m| m.os.iter().any(|o| o == &profile.os))
        .filter(|m| arch_ok(&m.arch, &profile.arch))
        .filter(|m| profile.ram_gb + 1e-9 >= m.min_ram_gb)
        .filter(|m| profile.cores_logical >= m.min_cores)
        .cloned()
        .collect()
}

pub fn recommend(profile: &DeviceProfile) -> Recommendation {
    let all = crate::catalog::load();
    let sup = supported(profile, &all);
    let by = |id: &str| sup.iter().find(|m| m.id == id).cloned();
    let (model, mode, reason) = if let Some(m) = by("paddleocr-vl-1.7b") {
        if profile.ram_gb >= 16.0 && profile.cores_logical >= 6 {
            (m, "vlm", "16GB+ / 6+ cores: VLM top accuracy fits in RAM.")
        } else if let Some(o) = by("ppocrv6-server") {
            (o, "ocr", "8GB+: PP-OCRv6 fastest accurate OCR; VLM 0.9B for tiny text.")
        } else {
            (m, "vlm", "Fallback to highest-accuracy supported model.")
        }
    } else if let Some(m) = by("ppocrv6-server") {
        let _ = by("paddleocr-vl-0.9b");
        (m, "ocr", "8GB+: PP-OCRv6 fastest accurate OCR; VLM 0.9B for tiny/low-contrast text.")
    } else if let Some(m) = by("ppocrv5-mobile") {
        (m, "ocr", "4GB+: PP-OCRv5 mobile balances GUI accuracy and CPU speed.")
    } else if let Some(m) = by("tesseract-best") {
        (m, "ocr", "Mid device: Tesseract best-preset ensemble.")
    } else if let Some(m) = by("tesseract-fast") {
        (m, "ocr", "Low RAM/cores: Tesseract fast only viable on-device option.")
    } else if let Some(m) = sup.iter().max_by(|a, b| a.accuracy_gui.partial_cmp(&b.accuracy_gui).unwrap()).cloned() {
        let mode = m.family.clone();
        (m, mode, "Fallback: highest-accuracy supported model.")
    } else {
        return Recommendation {
            mode: "ocr".into(),
            engine: "tesseract".into(),
            model: "tesseract-fast".into(),
            reason: "No catalog model fits; install Tesseract binary.".into(),
            supported: vec![],
        };
    };
    let engine = model.engine.clone();
    let id = model.id.clone();
    Recommendation { mode: mode.to_string(), engine, model: id, reason: reason.to_string(), supported: sup }
}
