//! OCR/VLM pipeline: fast OCR first, VLM escalation on low confidence.
use crate::ocr::{OcrEngine, OcrResult};
use crate::vlm::VlmModel;

#[derive(Debug, Clone)]
pub struct Trace {
    pub mode: String,
    pub ocr_engine: String,
    pub ocr_conf: f32,
    pub ocr_boxes: usize,
    pub escalated: bool,
    pub elapsed_ms: u64,
    pub note: String,
}

pub fn run_ocr(img: &image::RgbaImage, engine: OcrEngine) -> Result<(OcrResult, Trace), crate::ocr::OcrError> {
    let t0 = std::time::Instant::now();
    let r = crate::ocr::run(img, engine)?;
    Ok((
        r.clone(),
        Trace {
            mode: "ocr".into(),
            ocr_engine: r.engine.clone(),
            ocr_conf: r.mean_conf,
            ocr_boxes: r.boxes.len(),
            escalated: false,
            elapsed_ms: t0.elapsed().as_millis() as u64,
            note: String::new(),
        },
    ))
}

pub fn run_auto(
    img: &image::RgbaImage,
    engine: OcrEngine,
    vlm: VlmModel,
    threshold: f32,
) -> (OcrResult, Trace) {
    let t0 = std::time::Instant::now();
    match crate::ocr::run(img, engine) {
        Ok(r) if r.mean_conf >= threshold && !r.boxes.is_empty() => (
            r.clone(),
            Trace {
                mode: "ocr".into(),
                ocr_engine: r.engine,
                ocr_conf: r.mean_conf,
                ocr_boxes: r.boxes.len(),
                escalated: false,
                elapsed_ms: t0.elapsed().as_millis() as u64,
                note: String::new(),
            },
        ),
        Ok(r) => match crate::vlm::run(img, vlm) {
            Ok(v) => (
                v.clone(),
                Trace {
                    mode: "vlm".into(),
                    ocr_engine: r.engine,
                    ocr_conf: r.mean_conf,
                    ocr_boxes: r.boxes.len(),
                    escalated: true,
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                    note: format!("escalated: OCR conf {:.2} < {threshold:.2}", r.mean_conf),
                },
            ),
            Err(e) => (
                r.clone(),
                Trace {
                    mode: "ocr".into(),
                    ocr_engine: r.engine,
                    ocr_conf: r.mean_conf,
                    ocr_boxes: r.boxes.len(),
                    escalated: false,
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                    note: format!("VLM unavailable, kept OCR: {e}"),
                },
            ),
        },
        Err(e) => (
            OcrResult::empty("none"),
            Trace {
                mode: "ocr".into(),
                ocr_engine: "none".into(),
                ocr_conf: 0.0,
                ocr_boxes: 0,
                escalated: false,
                elapsed_ms: t0.elapsed().as_millis() as u64,
                note: format!("OCR failed: {e}"),
            },
        ),
    }
}
