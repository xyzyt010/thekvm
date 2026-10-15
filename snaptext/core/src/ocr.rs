//! OCR backends behind one trait. GUI presets live here.
//!
//! - Tesseract: `--oem 1 --psm 6` (+PSM 11 fallback for `best`), dpi 300,
//!   `preserve_interword_spaces=1`. Calls the `tesseract` binary (bundled by
//!   the installer); parses TSV word boxes.
//! - PP-OCRv5/v6: ONNX (`ort`) det+rec+cls with
//!   `det_db_thresh 0.3 / box_thresh 0.5 / unclip 1.8 / limit_side 960-1536`.
//!   v1 ships the preset + model loader; weights download on first use.
//! - Docling: layout+OCR pass for docs/mixed screenshots.
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcrBox {
    pub text: String,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub conf: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcrResult {
    pub engine: String,
    pub text: String,
    pub boxes: Vec<OcrBox>,
    pub mean_conf: f32,
}

impl OcrResult {
    pub fn empty(engine: &str) -> Self {
        Self { engine: engine.into(), text: String::new(), boxes: vec![], mean_conf: 0.0 }
    }
    pub fn with_boxes(engine: &str, boxes: Vec<OcrBox>) -> Self {
        let text = boxes.iter().map(|b| b.text.clone()).collect::<Vec<_>>().join("\n");
        let mean_conf = if boxes.is_empty() {
            0.0
        } else {
            boxes.iter().map(|b| b.conf).sum::<f32>() / boxes.len() as f32
        };
        Self { engine: engine.into(), text, boxes, mean_conf }
    }
}

#[derive(Debug, Error)]
pub enum OcrError {
    #[error("tesseract binary not found ({0})")]
    NoTesseract(String),
    #[error("PP-OCR weights missing: {0}")]
    NoWeights(String),
    #[error("docling backend unavailable: {0}")]
    NoDocling(String),
    #[error("ocr failed: {0}")]
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcrEngine {
    TesseractFast,
    TesseractBest,
    PpOcrV5Mobile,
    PpOcrV6Server,
    Docling,
}

impl OcrEngine {
    pub fn id(&self) -> &'static str {
        match self {
            Self::TesseractFast => "tesseract-fast",
            Self::TesseractBest => "tesseract-best",
            Self::PpOcrV5Mobile => "ppocrv5-mobile",
            Self::PpOcrV6Server => "ppocrv6-server",
            Self::Docling => "docling-doc",
        }
    }
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "tesseract-fast" => Some(Self::TesseractFast),
            "tesseract-best" => Some(Self::TesseractBest),
            "ppocrv5-mobile" => Some(Self::PpOcrV5Mobile),
            "ppocrv6-server" => Some(Self::PpOcrV6Server),
            "docling-doc" => Some(Self::Docling),
            _ => None,
        }
    }
}

/// Run one OCR engine on an RGBA screenshot (already cropped to selection).
pub fn run(img: &image::RgbaImage, engine: OcrEngine) -> Result<OcrResult, OcrError> {
    match engine {
        OcrEngine::TesseractFast => tesseract(img, false),
        OcrEngine::TesseractBest => tesseract(img, true),
        OcrEngine::PpOcrV5Mobile => ppocr(img, false),
        OcrEngine::PpOcrV6Server => ppocr(img, true),
        OcrEngine::Docling => docling(img),
    }
}

fn tesseract(img: &image::RgbaImage, best: bool) -> Result<OcrResult, OcrError> {
    let prepped = crate::preprocess::for_tesseract(img);
    let dir = std::env::temp_dir().join(format!("snaptext-tess-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| OcrError::Failed(e.to_string()))?;
    let input = dir.join("in.png");
    prepped.save(&input).map_err(|e| OcrError::Failed(e.to_string()))?;
    let run_psm = |psm: u8| -> Result<OcrResult, OcrError> {
        let out_base = dir.join(format!("out{psm}"));
        let status = std::process::Command::new("tesseract")
            .arg(&input)
            .arg(&out_base)
            .arg("--oem")
            .arg("1")
            .arg("--psm")
            .arg(psm.to_string())
            .arg("-c")
            .arg("user_defined_dpi=300")
            .arg("-c")
            .arg("preserve_interword_spaces=1")
            .arg("tsv")
            .output()
            .map_err(|_| {
                let found = crate::models::probe_binary("tesseract");
                OcrError::NoTesseract(match found {
                    Some(p) => format!("found at {} but failed to run", p.display()),
                    None => format!(
                        "not on PATH. Install tesseract or bundle it. {}",
                        crate::models::path_hint("tesseract")
                    ),
                })
            })?;
        if !status.status.success() {
            return Err(OcrError::Failed(
                String::from_utf8_lossy(&status.stderr).into_owned(),
            ));
        }
        parse_tsv(&out_base.with_extension("tsv"))
    };
    let r6 = run_psm(6)?;
    if !best {
        return Ok(r6);
    }
    let r11 = run_psm(11).unwrap_or_else(|_| OcrResult::empty("tesseract"));
    // PSM6+PSM11 ensemble: keep higher-confidence pass, boxes already 2x
    // (for_tesseract upscales) so halve back to selection space.
    let mut pick = if r6.mean_conf >= r11.mean_conf { r6 } else { r11 };
    for b in &mut pick.boxes {
        b.x /= 2;
        b.y /= 2;
        b.w = (b.w / 2).max(1);
        b.h = (b.h / 2).max(1);
    }
    pick.engine = "tesseract".into();
    Ok(pick)
}

fn parse_tsv(path: &std::path::Path) -> Result<OcrResult, OcrError> {
    let text = std::fs::read_to_string(path).map_err(|e| OcrError::Failed(e.to_string()))?;
    let mut boxes = vec![];
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() < 12 || c[0] != "5" {
            continue;
        }
        let word = c[11].trim();
        if word.is_empty() {
            continue;
        }
        let conf: f32 = c[10].parse().unwrap_or(-1.0);
        if conf < 0.0 {
            continue;
        }
        boxes.push(OcrBox {
            text: word.into(),
            x: c[6].parse().unwrap_or(0),
            y: c[7].parse().unwrap_or(0),
            w: c[8].parse().unwrap_or(0),
            h: c[9].parse().unwrap_or(0),
            conf: conf / 100.0,
        });
    }
    Ok(OcrResult::with_boxes("tesseract", boxes))
}

fn ppocr(img: &image::RgbaImage, server: bool) -> Result<OcrResult, OcrError> {
    // Resolve weights across install config → cache → exe-side → device
    // roots (rapidocr/paddle site-packages, HF hub). Found paths feed the
    // ort sessions directly — no copy needed, no download when present.
    let id = if server { "ppocrv6-server" } else { "ppocrv5-mobile" };
    let s = crate::models::spec(id).ok_or_else(|| OcrError::Failed(format!("unknown {id}")))?;
    let r = crate::models::resolve(&s);
    if !r.present {
        let st = crate::models::status(id).map_err(|e| OcrError::Failed(e.to_string()))?;
        return Err(OcrError::NoWeights(crate::models::describe(&st)));
    }
    let mut w = crate::ppocr_onnx::load(&r, server).map_err(|e| OcrError::Failed(e.to_string()))?;
    let boxes = crate::ppocr_onnx::run_all(&mut w, img).map_err(|e| OcrError::Failed(e.to_string()))?;
    Ok(OcrResult::with_boxes("ppocr", boxes))
}

fn docling(img: &image::RgbaImage) -> Result<OcrResult, OcrError> {
    let _prepped = crate::preprocess::for_docling(img);
    let detail = crate::models::status("docling-doc")
        .map(|st| crate::models::describe(&st))
        .unwrap_or_else(|e| e.to_string());
    Err(OcrError::NoDocling(detail))
}

#[allow(dead_code)]
fn dirs_cache(a: &str, b: &str) -> std::path::PathBuf {
    let _ = (a, b);
    crate::models::cache_root()
}
