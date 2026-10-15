//! PP-OCR ONNX inference (det → cls → rec) over `ort`.
//!
//! Faithful to rapidocr defaults (see its `config.yaml` on-device):
//! det limit_side 736 / limit_type min / mean+std 0.5 / thresh 0.3 /
//! box_thresh 0.5 / unclip 1.6; cls 48x192 / thresh 0.9; rec 48x320-span.
//! Boxes are axis-aligned (DB polygon step simplified for horizontal GUI
//! text); each stage's mean confidence feeds the pipeline escalator.

use std::collections::VecDeque;
use std::path::Path;

use crate::models::{Resolved, Role};

#[derive(Debug, thiserror::Error)]
pub enum OnnxError {
    #[error("ort: {0}")]
    Ort(String),
    #[error("dict: {0}")]
    Dict(String),
    #[error("shape: {0}")]
    Shape(String),
}

pub struct Weights {
    pub det: Session,
    pub rec: Session,
    pub cls: Session,
    pub dict: Vec<String>,
    pub det_size: u32,
}

use ort::session::Session;

pub fn load(resolved: &Resolved, server: bool) -> Result<Weights, OnnxError> {
    let get = |role: Role| {
        resolved
            .found_paths
            .get(&role)
            .cloned()
            .ok_or_else(|| OnnxError::Ort(format!("{} not resolved", role.as_str())))
    };
    let det_path = get(Role::Det)?;
    let rec_path = get(Role::Rec)?;
    let cls_path = get(Role::Cls)?;
    let dict_path = get(Role::Dict)?;
    Ok(Weights {
        det: open(&det_path)?,
        rec: open(&rec_path)?,
        cls: open(&cls_path)?,
        dict: load_dict(&dict_path)?,
        // rapidocr parity: det limit_side_len 736 (min-type). Larger scales
        // smear activations and overshoot boxes, starving word gaps in rec.
        det_size: if server { 960 } else { 736 },
    })
}

fn open(path: &Path) -> Result<Session, OnnxError> {
    // ort allows exactly one environment per process: share a leaked global.
    static ENV: std::sync::OnceLock<&'static ort::environment::Environment> = std::sync::OnceLock::new();
    let env = ENV.get_or_init(|| {
        Box::leak(Box::new(
            ort::environment::init()
                .with_name("snaptext")
                .build()
                .expect("ort environment"),
        ))
    });
    Session::builder(env)
        .map_err(|e| OnnxError::Ort(e.to_string()))?
        .with_intra_threads(4)
        .map_err(|e| OnnxError::Ort(e.to_string()))?
        .commit_from_file(path)
        .map_err(|e| OnnxError::Ort(format!("{}: {e}", path.display())))
}

/// ppocr_keys convention: file lines, then " " appended, "blank" at index 0.
/// Output classes = lines + 2 (verified: 6623 + 2 = 6625 on-device).
fn load_dict(path: &Path) -> Result<Vec<String>, OnnxError> {
    let text = std::fs::read_to_string(path).map_err(|e| OnnxError::Dict(e.to_string()))?;
    let mut chars: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    chars.push(" ".to_string());
    chars.insert(0, "blank".to_string());
    if chars.is_empty() {
        return Err(OnnxError::Dict("empty dict".into()));
    }
    Ok(chars)
}

// --- tensor helpers ---------------------------------------------------------

/// RGBA → NCHW float32 with (x/255 - mean)/std per channel.
fn to_nchw(
    img: &image::RgbaImage,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    tw: u32,
    th: u32,
    mean: [f32; 3],
    std: [f32; 3],
) -> (Vec<usize>, Vec<f32>) {
    let crop = image::imageops::crop_imm(img, x, y, w.max(1), h.max(1)).to_image();
    let resized = image::imageops::resize(&crop, tw, th, image::imageops::FilterType::Triangle);
    let mut data = vec![0f32; (3 * tw * th) as usize];
    for (i, p) in resized.pixels().enumerate() {
        let px = [p[0] as f32 / 255.0, p[1] as f32 / 255.0, p[2] as f32 / 255.0];
        for c in 0..3 {
            data[c * (tw * th) as usize + i] = (px[c] - mean[c]) / std[c];
        }
    }
    (vec![1, 3, th as usize, tw as usize], data)
}

fn run_chw(
    session: &mut Session,
    shape: Vec<usize>,
    data: Vec<f32>,
) -> Result<(Vec<usize>, Vec<f32>), OnnxError> {
    use ort::value::Tensor;
    let tensor = Tensor::from_array((shape, data)).map_err(|e| OnnxError::Ort(e.to_string()))?;
    let outputs = session
        .run(ort::inputs![tensor])
        .map_err(|e| OnnxError::Ort(e.to_string()))?;
    let (shape, slice) = outputs[0]
        .try_extract_tensor::<f32>()
        .map_err(|e| OnnxError::Ort(e.to_string()))?;
    Ok((shape.iter().map(|d| *d as usize).collect(), slice.to_vec()))
}

// --- detector ---------------------------------------------------------------

/// Resize so the SMALLER side == limit (rapidocr limit_type min), then pad to
/// multiples of 32 for the FPN backbone.
fn det_input(img: &image::RgbaImage, limit: u32) -> (u32, u32, u32, u32) {
    let (w, h) = (img.width().max(1), img.height().max(1));
    let s = limit as f32 / w.min(h) as f32;
    let (mut nw, mut nh) = ((w as f32 * s).round() as u32, (h as f32 * s).round() as u32);
    nw = nw.max(32);
    nh = nh.max(32);
    let (pw, ph) = ((nw + 31) / 32 * 32, (nh + 31) / 32 * 32);
    (nw, nh, pw, ph)
}

fn pad_nchw(img: &image::RgbaImage, nw: u32, nh: u32, pw: u32, ph: u32) -> (Vec<usize>, Vec<f32>) {
    let resized = image::imageops::resize(img, nw, nh, image::imageops::FilterType::Triangle);
    let mut data = vec![0f32; (3 * pw * ph) as usize];
    for y in 0..nh {
        for x in 0..nw {
            let p = resized.get_pixel(x, y);
            let px = [p[0] as f32 / 255.0, p[1] as f32 / 255.0, p[2] as f32 / 255.0];
            for c in 0..3 {
                data[c * (pw * ph) as usize + (y * pw + x) as usize] = (px[c] - 0.5) / 0.5;
            }
        }
    }
    (vec![1, 3, ph as usize, pw as usize], data)
}

/// Threshold 0.3 → connected components (BFS) → axis bbox on the prob map →
/// scale back → unclip expand ×1.6 → box score = mean prob inside.
pub fn detect(
    weights: &mut Weights,
    img: &image::RgbaImage,
) -> Result<Vec<(u32, u32, u32, u32, f32)>, OnnxError> {
    let (nw, nh, pw, ph) = det_input(img, weights.det_size);
    let (shape, data) = pad_nchw(img, nw, nh, pw, ph);
    let (oshape, out) = run_chw(&mut weights.det, shape, data)?;
    // out: [1,1,oh,ow]
    if oshape.len() != 4 || out.is_empty() {
        return Err(OnnxError::Shape(format!("det output {oshape:?}")));
    }
    let (oh, ow) = (oshape[2], oshape[3]);
    // Measured stride (input px per map cell): v4-det upsamples to full
    // input resolution (stride 1); never assume stride 4.
    let sh = pw as f32 / ow.max(1) as f32;
    let sv = ph as f32 / oh.max(1) as f32;
    let sx = img.width() as f32 / pw as f32;
    let sy = img.height() as f32 / ph as f32;
    // Valid map region = the unpadded nw×nh area expressed in cells.
    let mw = ((nw as f32 / sh).ceil() as usize).min(ow);
    let mh = ((nh as f32 / sv).ceil() as usize).min(oh);
    let mask: Vec<bool> = out
        .iter()
        .take(mh * ow)
        .enumerate()
        .filter(|(i, _)| i % ow < mw)
        .map(|(_, &v)| v > 0.3)
        .collect();
    if std::env::var("SNAPTEXT_DEBUG").is_ok() {
        let max = out.iter().fold(0f32, |a, &b| a.max(b));
        let mean = out.iter().sum::<f32>() / out.len().max(1) as f32;
        eprintln!("det: out {oshape:?} max={max:.3} mean={mean:.4} above0.3={} valid={}x{mw}", mask.iter().filter(|&&m| m).count(), mh);
    }
    debug_assert_eq!(mask.len(), mh * mw);
    // Single 3x3 dilation (rapidocr use_dilation): restores eroded glyph
    // extents without merging neighbouring lines.
    let mut dil = mask;
    for _ in 0..1 {
        let mut next = dil.clone();
        for y in 0..mh {
            for x in 0..mw {
                if dil[y * mw + x] {
                    continue;
                }
                'win: for dy in -1i32..=1 {
                    for dx in -1i32..=1 {
                        let (nx, ny) = (x as i32 + dx, y as i32 + dy);
                        if nx >= 0
                            && ny >= 0
                            && (nx as usize) < mw
                            && (ny as usize) < mh
                            && dil[ny as usize * mw + nx as usize]
                        {
                            next[y * mw + x] = true;
                            break 'win;
                        }
                    }
                }
            }
        }
        dil = next;
    }
    let mask = dil;
    let mut seen = vec![false; mh * mw];
    let mut boxes = vec![];
    for i in 0..mh * mw {
        if !mask[i] || seen[i] {
            continue;
        }
        // BFS component.
        let mut q = VecDeque::from([i]);
        seen[i] = true;
        let (mut x0, mut y0, mut x1, mut y1) = (mw, mh, 0usize, 0usize);
        let (mut sum, mut cnt) = (0f64, 0usize);
        while let Some(cur) = q.pop_front() {
            let (cx, cy) = (cur % mw, cur / mw);
            x0 = x0.min(cx);
            y0 = y0.min(cy);
            x1 = x1.max(cx);
            y1 = y1.max(cy);
            // NOTE: `out` is row-major over the full padded width `ow`;
            // index with ow stride, not mw.
            sum += out[cy * ow + cx] as f64;
            cnt += 1;
            for (nx, ny) in [(cx.wrapping_sub(1), cy), (cx + 1, cy), (cx, cy.wrapping_sub(1)), (cx, cy + 1)] {
                if nx < mw && ny < mh && mask[ny * mw + nx] && !seen[ny * mw + nx] {
                    seen[ny * mw + nx] = true;
                    q.push_back(ny * mw + nx);
                }
            }
        }
        if cnt < 9 {
            continue;
        }
        let score = (sum / cnt as f64) as f32;
        if score < 0.5 {
            continue;
        }
        // Map cells → padded-input pixels (measured stride), then unclip
        // expand, then scale to original pixels.
        let mut bx0 = (x0 as f32 * sh * sx) as i32;
        let mut by0 = (y0 as f32 * sv * sy) as i32;
        let mut bx1 = ((x1 + 1) as f32 * sh * sx) as i32;
        let mut by1 = ((y1 + 1) as f32 * sv * sy) as i32;
        let (cw, ch) = ((bx1 - bx0).max(1) as f32, (by1 - by0).max(1) as f32);
        // Gentle unclip: 12% per side (thin UI lines overshoot badly with
        // area-style factors); never bleed to the image edge on the left.
        let ex = ((cw * 0.12) as i32).max(2);
        let ey = ((ch * 0.12) as i32).max(2);
        bx0 = (bx0 - ex).max(0);
        by0 = (by0 - ey).max(0);
        bx1 = (bx1 + ex).min(img.width() as i32);
        by1 = (by1 + ey).min(img.height() as i32);
        if bx1 > bx0 && by1 > by0 {
            boxes.push((bx0 as u32, by0 as u32, (bx1 - bx0) as u32, (by1 - by0) as u32, score));
        }
    }
    // Reading order: top-to-bottom, left-to-right.
    boxes.sort_by(|a, b| (a.1 / 10, a.0).cmp(&(b.1 / 10, b.0)));
    boxes.truncate(200);
    Ok(boxes)
}

// --- classifier / recognizer -------------------------------------------------

fn classify(weights: &mut Weights, img: &image::RgbaImage, b: (u32, u32, u32, u32)) -> bool {
    // Tall thin boxes are never rotated text; skip the session.
    if b.2 * 2 < b.3 {
        return false;
    }
    let (shape, data) = to_nchw(img, b.0, b.1, b.2, b.3, 192, 48, [0.5, 0.5, 0.5], [0.5, 0.5, 0.5]);
    let Ok((_, out)) = run_chw(&mut weights.cls, shape, data) else { return false };
    if out.len() < 2 {
        return false;
    }
    // argmax==1 → 180°, needs flip; require 0.9 confidence (rapidocr default).
    let (m, tot) = (out[0].max(out[1]), out[0] + out[1]);
    out[1] > out[0] && m / tot.max(1e-6) > 0.9
}

fn recognize(
    weights: &mut Weights,
    img: &image::RgbaImage,
    b: (u32, u32, u32, u32),
    rotate180: bool,
) -> (String, f32) {
    let (mut x, mut y, w, h) = (b.0, b.1, b.2.max(2), b.3.max(2));
    x = x.min(img.width().saturating_sub(1));
    y = y.min(img.height().saturating_sub(1));
    let mut crop = image::imageops::crop_imm(img, x, y, w.min(img.width() - x), h.min(img.height() - y)).to_image();
    if rotate180 {
        crop = image::imageops::rotate180(&crop);
    }
    // rapidocr parity: width = ceil(48 * aspect), floored at 320 (the
    // batch width), zero-padded right; never squash wide lines.
    let ratio = w as f32 / h.max(1) as f32;
    let tw = ((48.0 * ratio).ceil() as u32).clamp(320, 2000);
    let (shape, data) = to_nchw(&pad_to(&crop, tw), 0, 0, tw, 48, tw, 48, [0.5, 0.5, 0.5], [0.5, 0.5, 0.5]);
    let Ok((oshape, out)) = run_chw(&mut weights.rec, shape, data) else {
        return (String::new(), 0.0);
    };
    // Accept [N,T,C] or [T,N,C].
    let (t, c, batch_first) = if oshape.len() == 3 {
        if oshape[2] == weights.dict.len() {
            (oshape[1], oshape[2], true)
        } else if oshape[0] > 4 && oshape[1] <= 4 {
            (oshape[0], oshape[2], false)
        } else {
            return (String::new(), 0.0);
        }
    } else {
        return (String::new(), 0.0);
    };
    if c != weights.dict.len() {
        return (String::new(), 0.0);
    }
    // CTC greedy: argmax per step, drop blank(0) + repeats.
    let (mut text, mut conf_sum, mut conf_n, mut prev) = (String::new(), 0f32, 0usize, usize::MAX);
    for ti in 0..t {
        let mut best = 0usize;
        let mut best_v = f32::MIN;
        for ci in 0..c {
            let v = out[if batch_first { ti * c + ci } else { ti * oshape[1] * c + ci }];
            if v > best_v {
                best_v = v;
                best = ci;
            }
        }
        if best != 0 && best != prev {
            if let Some(ch) = weights.dict.get(best) {
                text.push_str(ch);
                conf_sum += best_v;
                conf_n += 1;
            }
        }
        prev = best;
    }
    let conf = if conf_n == 0 { 0.0 } else { conf_sum / conf_n as f32 };
    (text, conf)
}

fn pad_to(crop: &image::RgbaImage, tw: u32) -> image::RgbaImage {
    // crop is already (w,h); ensure exact width tw by resize (rec handles it).
    if crop.width() == tw {
        return crop.clone();
    }
    image::imageops::resize(crop, tw, 48, image::imageops::FilterType::Triangle)
}

// --- full pass ----------------------------------------------------------------

pub fn run_all(
    weights: &mut Weights,
    img: &image::RgbaImage,
) -> Result<Vec<crate::ocr::OcrBox>, OnnxError> {
    let mut out = vec![];
    for (x, y, w, h, dconf) in detect(weights, img)? {
        if w < 4 || h < 4 {
            continue;
        }
        let flip = classify(weights, img, (x, y, w, h));
        let (text, rconf) = recognize(weights, img, (x, y, w, h), flip);
        if text.trim().is_empty() {
            continue;
        }
        out.push(crate::ocr::OcrBox { text, x, y, w, h, conf: (dconf + rconf) / 2.0 });
    }
    Ok(out)
}
