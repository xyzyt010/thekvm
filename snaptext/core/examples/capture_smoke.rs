//! Capture smoke: fullscreen + region + window, saved to %TEMP%/CWD.
//! Prints sizes or the exact backend error.
fn main() {
    let dir = std::env::temp_dir().join("snaptext-smoke");
    std::fs::create_dir_all(&dir).unwrap();
    match snaptext_core::capture::fullscreen() {
        Ok(img) => {
            let p = dir.join("full.png");
            img.save(&p).unwrap();
            println!("fullscreen OK {}x{} -> {}", img.width(), img.height(), p.display());
            let w = img.width().min(400);
            let h = img.height().min(300);
            match snaptext_core::capture::region(10, 10, w, h) {
                Ok(r) => println!("region OK {}x{}", r.width(), r.height()),
                Err(e) => println!("region FAIL: {e:#}"),
            }
        }
        Err(e) => println!("fullscreen FAIL: {e:#}"),
    }
    match snaptext_core::capture::active_window() {
        Ok(img) => println!("window OK {}x{}", img.width(), img.height()),
        Err(e) => println!("window FAIL: {e:#}"),
    }
}
