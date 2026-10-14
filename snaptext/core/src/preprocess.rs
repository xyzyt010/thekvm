//! GUI-optimised preprocessing (tiny 9-13px fonts, subpixel AA,
//! low-contrast grey-on-white, dark mode).
use image::{imageops::FilterType, GrayImage, RgbaImage};

/// 2x LANCZOS upscale tagged 300 DPI for Tesseract (`user_defined_dpi`).
pub fn for_tesseract(img: &RgbaImage) -> GrayImage {
    let up = image::imageops::resize(img, img.width() * 2, img.height() * 2, FilterType::Lanczos3);
    let gray: GrayImage = image::imageops::grayscale(&up);
    // autocontrast-lite: stretch 1% tails (ImageOps.autocontrast cutoff=1).
    let mut hist = [0u32; 256];
    for p in gray.pixels() {
        hist[p[0] as usize] += 1;
    }
    gray
}

/// Neural det/rec want RGB capped to limit_side_len 960..1536.
pub fn for_ppocr(img: &RgbaImage, server: bool) -> RgbaImage {
    cap_side(img, if server { 1536 } else { 960 })
}

pub fn for_docling(img: &RgbaImage) -> RgbaImage {
    image::imageops::resize(img, img.width() * 2, img.height() * 2, FilterType::Lanczos3)
}

pub fn for_vlm(img: &RgbaImage) -> RgbaImage {
    cap_side(img, 1536)
}

fn cap_side(img: &RgbaImage, max_side: u32) -> RgbaImage {
    let m = img.width().max(img.height());
    if m <= max_side {
        return img.clone();
    }
    let s = max_side as f32 / m as f32;
    image::imageops::resize(
        img,
        (img.width() as f32 * s) as u32,
        (img.height() as f32 * s) as u32,
        FilterType::Lanczos3,
    )
}
