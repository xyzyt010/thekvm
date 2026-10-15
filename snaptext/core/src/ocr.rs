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
    // Use the detected binary path (PATH, well-known dirs, or the app-local
    // bin dir) — never a bare name that misses app-local installs.
    let bin = crate::models::probe_binary("tesseract").ok_or_else(|| {
        OcrError::NoTesseract(format!(
            "not on PATH. Install tesseract or bundle it. {}",
            crate::models::path_hint("tesseract")
        ))
    })?;
    let prepped = crate::preprocess::for_tesseract(img);
    let dir = std::env::temp_dir().join(format!("snaptext-tess-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| OcrError::Failed(e.to_string()))?;
    let input = dir.join("in.png");
    prepped.save(&input).map_err(|e| OcrError::Failed(e.to_string()))?;
    let run_psm = |psm: u8| -> Result<OcrResult, OcrError> {
        let out_base = dir.join(format!("out{psm}"));
        let status = std::process::Command::new(&bin)
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
            .map_err(|e| OcrError::Failed(format!("tesseract failed to run: {e}")))?;
        if !status.status.success() {
            return Err(OcrError::Failed(
                String::from_utf8_lossy(&status.stderr).into_owned(),
            ));
        }
        parse_tsv(&out_base.with_extension("tsv"))
    };
    // Boxes come back in 2x space (for_tesseract upscales); halve to the
    // selection space on EVERY path, not just the ensemble.
    let scale_down = |mut r: OcrResult| {
        for b in &mut r.boxes {
            b.x /= 2;
            b.y /= 2;
            b.w = (b.w / 2).max(1);
            b.h = (b.h / 2).max(1);
        }
        r.engine = "tesseract".into();
        r
    };
    let r6 = scale_down(run_psm(6)?);
    if !best {
        return Ok(r6);
    }
    let r11 = run_psm(11)
        .map(scale_down)
        .unwrap_or_else(|_| OcrResult::empty("tesseract"));
    // PSM6+PSM11 ensemble: keep the higher-confidence pass.
    Ok(if r6.mean_conf >= r11.mean_conf { r6 } else { r11 })
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
    // Docling runs as a sidecar CLI (detected on PATH, e.g. the pip install).
    // Screenshot-tuned flags: image input, markdown out, no table model.
    let bin = crate::models::probe_binary("docling").ok_or_else(|| {
        OcrError::NoDocling(format!(
            "docling CLI not on PATH. pip install docling. {}",
            crate::models::path_hint("docling")
        ))
    })?;
    let prepped = crate::preprocess::for_docling(img);
    let dir = std::env::temp_dir().join(format!("snaptext-docling-{}", std::process::id()));
    let outdir = dir.join("out");
    std::fs::create_dir_all(&outdir).map_err(|e| OcrError::Failed(e.to_string()))?;
    let input = dir.join("shot.png");
    prepped.save(&input).map_err(|e| OcrError::Failed(e.to_string()))?;
    let status = std::process::Command::new(&bin)
        .arg("--from")
        .arg("image")
        .arg("--to")
        .arg("md")
        .arg("--no-tables")
        .arg("--no-show-layout")
        .arg("--output")
        .arg(&outdir)
        .arg(&input)
        .output()
        .map_err(|e| OcrError::Failed(format!("docling failed to run: {e}")))?;
    if !status.status.success() {
        return Err(OcrError::Failed(
            String::from_utf8_lossy(&status.stderr).into_owned(),
        ));
    }
    let md = find_first(&outdir, "md").ok_or_else(|| {
        OcrError::Failed(format!("docling produced no .md in {}", outdir.display()))
    })?;
    let text = std::fs::read_to_string(&md).map_err(|e| OcrError::Failed(e.to_string()))?;
    // Markdown has no word boxes: emit one block box per non-empty line so
    // the overlay PDF and preview stay geometrically honest.
    let (w, h) = (img.width(), img.height());
    let lines: Vec<&str> = text
        .lines()
        .map(strip_md)
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return Ok(OcrResult::empty("docling"));
    }
    let n = lines.len() as u32;
    let boxes = lines
        .iter()
        .enumerate()
        .map(|(i, l)| OcrBox {
            text: l.to_string(),
            x: 0,
            y: (i as u32 * h / n).min(h.saturating_sub(1)),
            w,
            h: (h / n).max(1),
            conf: 0.85,
        })
        .collect();
    Ok(OcrResult::with_boxes("docling", boxes))
}

/// Depth-first search for the first file with the given extension.
fn find_first(dir: &std::path::Path, ext: &str) -> Option<std::path::PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).ok()?;
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|x| x.to_str()) == Some(ext) {
                return Some(p);
            }
        }
    }
    None
}

/// Strip common markdown wrappers so clipboard text is clean prose.
fn strip_md(line: &str) -> &str {
    let l = line.trim();
    let l = l.strip_prefix('#').map(|s| s.trim_start_matches('#').trim()).unwrap_or(l);
    let l = l.trim_start_matches(['>', '-', '*', '+', ' ']);
    let l = l.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.');
    l.trim()
}

#[allow(dead_code)]
fn dirs_cache(a: &str, b: &str) -> std::path::PathBuf {
    let _ = (a, b);
    crate::models::cache_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TSV: &str = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n\
        1\t1\t0\t0\t0\t0\t0\t0\t100\t20\t-1\t\n\
        5\t1\t1\t1\t1\t1\t10\t5\t40\t12\t95.5\tHello\n\
        5\t1\t1\t1\t1\t2\t55\t5\t30\t12\t-1\t\n\
        5\t1\t1\t1\t1\t3\t90\t5\t25\t12\t80\tGUI\n";

    #[test]
    fn tsv_parses_word_rows_only() {
        let dir = std::env::temp_dir().join(format!("snaptext-tsv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("out.tsv");
        std::fs::write(&p, TSV).unwrap();
        let r = parse_tsv(&p).unwrap();
        assert_eq!(r.engine, "tesseract");
        assert_eq!(r.boxes.len(), 2);
        assert_eq!(r.boxes[0].text, "Hello");
        assert!((r.boxes[0].conf - 0.955).abs() < 1e-6);
        assert_eq!((r.boxes[0].x, r.boxes[0].y), (10, 5));
        assert_eq!(r.text, "Hello\nGUI");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strip_md_cleans_prose() {
        assert_eq!(strip_md("## Title"), "Title");
        assert_eq!(strip_md("1. item"), "item");
        assert_eq!(strip_md("- dash"), "dash");
        assert_eq!(strip_md("> quote"), "quote");
        assert_eq!(strip_md("plain"), "plain");
    }

    #[test]
    fn find_first_locates_nested_md() {
        let dir = std::env::temp_dir().join(format!("snaptext-ff-{}", std::process::id()));
        let sub = dir.join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("doc.md"), b"x").unwrap();
        std::fs::write(dir.join("img.png"), b"y").unwrap();
        let found = find_first(&dir, "md").unwrap();
        assert!(found.ends_with("doc.md"));
        assert!(find_first(&dir, "zzz").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
