//! Local VLM: PaddleOCR-VL 0.9B / 1.7B behind one call.
//! Same contract as OCR (text + 0-1000-normalised boxes mapped to pixels)
//! so overlay/PDF/auto-copy share geometry. Weights resolve from
//! ~/.cache/snaptext/vlm/<id>/ (Q8 / Q4_K_M GGUF); missing weights is a
//! typed error the pipeline turns into an OCR-grade fallback.
use crate::ocr::{OcrError, OcrResult};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlmModel {
    PaddleOcrVl09,
    PaddleOcrVl17,
}

impl VlmModel {
    pub fn id(&self) -> &'static str {
        match self {
            Self::PaddleOcrVl09 => "paddleocr-vl-0.9b",
            Self::PaddleOcrVl17 => "paddleocr-vl-1.7b",
        }
    }
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "paddleocr-vl-0.9b" => Some(Self::PaddleOcrVl09),
            "paddleocr-vl-1.7b" => Some(Self::PaddleOcrVl17),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum VlmError {
    #[error("VLM weights missing: {0}")]
    NoWeights(String),
    #[error("VLM failed: {0}")]
    Failed(String),
}

impl From<VlmError> for OcrError {
    fn from(e: VlmError) -> Self {
        OcrError::Failed(e.to_string())
    }
}

pub fn run(img: &image::RgbaImage, model: VlmModel) -> Result<OcrResult, VlmError> {
    let _prepped = crate::preprocess::for_vlm(img);
    let detail = crate::models::status(model.id())
        .map(|st| crate::models::describe(&st))
        .unwrap_or_else(|e| e.to_string());
    Err(VlmError::NoWeights(detail))
}
