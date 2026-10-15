//! Smoke: resolve on-device PP-OCR weights and run det→cls→rec on a given
//! PNG. Skips (no failure) when weights are absent.
//! Usage: ppocr_smoke <image.png>
use image::RgbaImage;

fn main() {
    let path = std::env::args().nth(1).expect("usage: ppocr_smoke <image.png>");
    let Some(spec) = snaptext_core::models::spec("ppocrv5-mobile") else { return };
    let r = snaptext_core::models::resolve(&spec);
    if !r.present {
        println!("SKIP: {}", snaptext_core::models::status("ppocrv5-mobile").map(|s| s.detail).unwrap_or_default());
        return;
    }
    let mut paths: Vec<_> = r.found_paths.iter().collect();
    paths.sort_by_key(|(role, _)| role.as_str());
    for (role, p) in &paths {
        println!("  {} -> {}", role.as_str(), p.display());
    }
    let t0 = std::time::Instant::now();
    let mut w = snaptext_core::ppocr_onnx::load(&r, false).expect("load sessions");
    println!("sessions loaded in {}ms", t0.elapsed().as_millis());
    let img: RgbaImage = image::open(&path).expect("open image").to_rgba8();
    let t0 = std::time::Instant::now();
    let boxes = snaptext_core::ppocr_onnx::run_all(&mut w, &img).expect("infer");
    println!("rust-ppocr: {} boxes in {}ms", boxes.len(), t0.elapsed().as_millis());
    for b in &boxes {
        println!("  [{},{},{}x{} conf={:.2}] {}", b.x, b.y, b.w, b.h, b.conf, b.text);
    }
}
