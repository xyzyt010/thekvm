//! Backend self-test: every OCR engine through `ocr::run` on one synthetic
//! GUI image. Prints text/conf/boxes per engine or the exact missing-piece
//! error (binary/PATH/URLs). No downloads, no network.
fn main() {
    use snaptext_core::ocr::{run, OcrEngine};
    let arg = std::env::args().nth(1).unwrap_or_else(|| "/tmp/gui-compare.png".into());
    let img = image::open(&arg)
        .unwrap_or_else(|_| image::DynamicImage::ImageRgba8(synth()))
        .to_rgba8();
    println!("image: {arg} {}x{}", img.width(), img.height());
    for e in [
        OcrEngine::TesseractFast,
        OcrEngine::TesseractBest,
        OcrEngine::PpOcrV5Mobile,
        OcrEngine::PpOcrV6Server,
        OcrEngine::Docling,
    ] {
        let t0 = std::time::Instant::now();
        match run(&img, e) {
            Ok(r) => println!(
                "{:16} OK conf={:.2} boxes={} {}ms text={:?}",
                e.id(),
                r.mean_conf,
                r.boxes.len(),
                t0.elapsed().as_millis(),
                first_line(&r.text),
            ),
            Err(err) => println!("{:16} MISSING {err}", e.id()),
        }
    }
}

fn first_line(t: &str) -> String {
    t.lines().next().unwrap_or("").chars().take(72).collect()
}

fn synth() -> image::RgbaImage {
    image::RgbaImage::from_pixel(600, 200, image::Rgba([255, 255, 255, 255]))
}
