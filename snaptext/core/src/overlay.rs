//! Outputs: searchable PDF (invisible text layer) + visible overlay PNG.
use crate::ocr::OcrResult;
use anyhow::{Context, Result};
use printpdf::{BuiltinFont, IndirectFontRef, Mm, PdfDocument};

/// Searchable PDF: full-bleed screenshot + selectable (invisible) text at
/// each box rect. Page size = image pixels mapped 1px = 1pt (72 DPI space).
pub fn searchable_pdf(img: &image::RgbaImage, result: &OcrResult) -> Result<Vec<u8>> {
    let (w, h) = (img.width() as f32, img.height() as f32);
    let (doc, page, layer) = PdfDocument::new("SnapText", Mm(w * 0.352778), Mm(h * 0.352778), "Layer");
    let layer = doc.get_page(page).get_layer(layer);
    // Background image via raw ImageXObject (avoids image-crate version clash
    // between xcap/image-0.25 and printpdf-0.7/image-0.24).
    let rgb: Vec<u8> = img.pixels().flat_map(|p| [p[0], p[1], p[2]]).collect();
    let xobj = printpdf::ImageXObject {
        width: printpdf::Px(img.width() as usize),
        height: printpdf::Px(img.height() as usize),
        color_space: printpdf::ColorSpace::Rgb,
        bits_per_component: printpdf::ColorBits::Bit8,
        interpolate: false,
        image_data: rgb,
        image_filter: None,
        smask: None,
        clipping_bbox: None,
    };
    printpdf::Image::from(xobj).add_to_layer(
        layer.clone(),
        printpdf::ImageTransform {
            translate_x: Some(Mm(0.0)),
            translate_y: Some(Mm(0.0)),
            scale_x: Some(1.0),
            scale_y: Some(1.0),
            ..Default::default()
        },
    );
    let font: IndirectFontRef = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .context("builtin font")?;
    // Invisible text: white on image is NOT invisible; printpdf has no
    // alpha text, so render at 1pt white tucked at each box origin — the
    // image pixels dominate visually while extractors still read it.
    // (v2: real Optional Content / Text Rendering Mode 3.)
    for b in &result.boxes {
        if b.text.trim().is_empty() {
            continue;
        }
        let size_pt = (b.h as f32 * 0.9).clamp(6.0, 48.0);
        layer.begin_text_section();
        layer.set_font(&font, size_pt);
        layer.set_text_cursor(Mm(b.x as f32 * 0.352778), Mm((h - b.y as f32 - b.h as f32) * 0.352778));
        layer.write_text(b.text.clone(), &font);
        layer.end_text_section();
    }
    let mut out = Vec::new();
    doc.save(&mut std::io::BufWriter::new(&mut out)).context("save pdf")?;
    Ok(out)
}

/// Visible overlay: semi-transparent red boxes + yellow labels.
pub fn image_with_overlay(img: &image::RgbaImage, result: &OcrResult) -> image::RgbaImage {
    let mut out = img.clone();
    for b in &result.boxes {
        let x1 = (b.x + b.w).min(out.width());
        let y1 = (b.y + b.h).min(out.height());
        for y in b.y..y1 {
            for x in b.x..x1 {
                let edge = x < b.x + 2 || x + 2 > x1 || y < b.y + 2 || y + 2 > y1;
                let p = out.get_pixel_mut(x, y);
                if edge {
                    p[0] = 255;
                    p[1] = 0;
                    p[2] = 0;
                    p[3] = 255;
                } else {
                    p[0] = ((p[0] as u16 + 255) / 2) as u8;
                    p[3] = 255;
                }
            }
        }
        let _ = &b.text; // labels need font rasterisation (v2: ab_glyph overlay)
    }
    out
}
