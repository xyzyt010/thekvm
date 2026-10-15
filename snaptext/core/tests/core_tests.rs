use snaptext_core::{device, models, ocr, overlay, preprocess, recommender};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_shape() {
        let p = device::profile();
        assert!(p.ram_gb > 0.0);
        assert!(p.cores_logical >= 1);
        assert!(!p.display.is_empty());
    }

    #[test]
    fn tiny_device_gets_tesseract_fast_only() {
        let tiny = device::DeviceProfile {
            os: "linux".into(),
            os_version: String::new(),
            arch: "x86_64".into(),
            cpu: "t".into(),
            cores_logical: 1,
            cores_physical: 1,
            ram_gb: 1.0,
            display: "x11".into(),
            supported_v1: true,
        };
        let rec = recommender::recommend(&tiny);
        assert_eq!(rec.model, "tesseract-fast");
        assert!(!rec.supported.iter().any(|m| m.id == "paddleocr-vl-1.7b"));
    }

    #[test]
    fn overlay_pdf_starts_with_magic() {
        let img = image::RgbaImage::new(400, 200);
        let r = ocr::OcrResult::with_boxes(
            "test",
            vec![ocr::OcrBox { text: "Hello GUI".into(), x: 20, y: 40, w: 120, h: 20, conf: 0.99 }],
        );
        let pdf = overlay::searchable_pdf(&img, &r).expect("pdf builds");
        assert!(pdf.starts_with(b"%PDF-"));
        assert!(pdf.len() > 500);
        let out = overlay::image_with_overlay(&img, &r);
        assert_eq!((out.width(), out.height()), (400, 200));
    }

    #[test]
    fn overlay_rect_maps_logical_to_pixels() {
        use snaptext_core::capture::map_logical_rect;
        // 1:1 at scale 1.
        assert_eq!(map_logical_rect(10.0, 20.0, 100.0, 50.0, 1.0, 800, 600), (10, 20, 100, 50));
        // HiDPI scale 1.5.
        assert_eq!(map_logical_rect(10.0, 20.0, 100.0, 50.0, 1.5, 800, 600), (15, 30, 150, 75));
        // Clamped to the image, never zero-sized, never out of bounds.
        assert_eq!(map_logical_rect(-50.0, -50.0, 2000.0, 2000.0, 1.0, 800, 600), (0, 0, 800, 600));
        assert_eq!(map_logical_rect(799.0, 599.0, 1.0, 1.0, 1.0, 800, 600), (799, 599, 1, 1));
    }

    #[test]
    fn preprocess_sizes() {
        let img = image::RgbaImage::new(320, 200);
        assert_eq!(preprocess::for_tesseract(&img).dimensions(), (640, 400));
        assert_eq!(preprocess::for_vlm(&img).dimensions(), (320, 200));
    }

    /// Device-dependent: exercises the same path the UI capture button uses
    /// (`ocr::run` → ppocr → resolve → ort sessions). Skips when the device
    /// has no PP-OCR weights, so CI stays green.
    #[test]
    fn ocr_runs_resolved_onnx_weights() {
        let Some(spec) = models::spec("ppocrv5-mobile") else { panic!("spec") };
        if !models::resolve(&spec).present {
            eprintln!("SKIP: no on-device PP-OCR weights");
            return;
        }
        // Synthetic GUI text image (same content as the python comparison).
        let mut img = image::RgbaImage::from_pixel(600, 200, image::Rgba([255, 255, 255, 255]));
        for x in 20..120 {
            for y in 40..60 {
                img.put_pixel(x, y, image::Rgba([0, 0, 0, 255]));
            }
        }
        let r = ocr::run(&img, ocr::OcrEngine::PpOcrV5Mobile).expect("ocr runs with resolved weights");
        assert_eq!(r.engine, "ppocr");
        assert!(r.mean_conf >= 0.0);
    }

    #[test]
    fn model_specs_have_direct_urls() {
        for id in models::all_ids() {
            let s = models::spec(id).unwrap_or_else(|| panic!("spec for {id}"));
            for (_role, opts) in &s.roles {
                for o in opts {
                    assert!(o.url.starts_with("https://"), "{id}/{} url must be direct https", o.filename);
                    assert!(!o.filename.is_empty());
                }
            }
        }
        assert!(models::spec("nope").is_none());
    }

    #[test]
    fn model_status_detects_files_without_network() {
        // Pure detection against a temp dir: create all options -> present,
        // remove one role's files -> that role missing. No downloads, no env.
        let dir = std::env::temp_dir().join(format!("snaptext-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let s = models::spec("ppocrv5-mobile").unwrap();
        for (_role, opts) in &s.roles {
            std::fs::write(dir.join(opts[0].filename), b"stub").unwrap();
        }
        let st = models::status_in(&dir, &s);
        assert!(st.present && st.missing_roles.is_empty());
        let first = s.roles[0].1[0].filename;
        std::fs::remove_file(dir.join(first)).unwrap();
        let st2 = models::status_in(&dir, &s);
        assert!(!st2.present);
        assert_eq!(st2.missing_roles, vec![s.roles[0].0]);
        let _ = std::fs::remove_dir_all(&dir);    }

    #[test]
    fn model_empty_dir_reports_all_roles_missing() {
        let s = models::spec("ppocrv5-mobile").unwrap();
        let dir = std::env::temp_dir().join(format!("snaptext-empty-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let st = models::resolve_in(&[dir.clone()], &s, false);
        assert!(!st.present);
        assert_eq!(st.missing_roles.len(), s.roles.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn binary_probe_finds_path_entries() {
        // Hermetic: fake PATH with a temp bin dir containing a stub file.
        let bin = std::env::temp_dir().join(format!("snaptext-bin-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&bin);
        let name = if cfg!(windows) { "snaptext-fake-bin.exe" } else { "snaptext-fake-bin" };
        std::fs::write(bin.join(name), b"x").unwrap();
        let fake_path = bin.to_string_lossy().to_string();
        let stem = name.trim_end_matches(".exe");
        let found = models::probe_binary_on_path(stem, &fake_path);
        assert!(found.is_some(), "must detect binary placed on PATH");
        assert!(models::probe_binary_on_path("snaptext-definitely-missing-xyz", &fake_path).is_none());
        assert!(!models::path_hint(stem).is_empty(), "must tell user what to add to PATH");
        let _ = std::fs::remove_dir_all(&bin);
    }
}
