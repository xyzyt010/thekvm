//! snaptext-ui: Slint frontend + snaptext-core backend.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

slint::include_modules!();

use slint::{ComponentHandle, SharedString};
use snaptext_core::{device, hotkeys, models, ocr::OcrEngine, recommender, vlm::VlmModel};
use std::sync::{Arc, Mutex};

struct Shot {
    img: image::RgbaImage,
    result: snaptext_core::OcrResult,
}

/// Model ids backing the Capture engine ComboBox (ready-to-run only) and the
/// Settings rows (all supported). Shared because refresh rewrites both lists.
struct ModelLists {
    ready: Vec<String>,
    supported: Vec<String>,
    recommended: String,
}

fn engine_of_id(id: &str) -> OcrEngine {
    match id {
        "tesseract-fast" => OcrEngine::TesseractFast,
        "tesseract-best" => OcrEngine::TesseractBest,
        "ppocrv5-mobile" => OcrEngine::PpOcrV5Mobile,
        "docling-doc" => OcrEngine::Docling,
        _ => OcrEngine::PpOcrV6Server,
    }
}

fn main() -> anyhow::Result<()> {
    let ui = SnapWindow::new()?;
    let prof = device::profile();
    let rec = recommender::recommend(&prof);
    ui.set_recommend_text(SharedString::from(format!(
        "{} {} · {} cores · {:.1}GB · [{}] → {} ({}/{}) — {}",
        prof.os,
        prof.arch,
        prof.cores_logical,
        prof.ram_gb,
        prof.display,
        rec.model,
        rec.mode,
        rec.engine,
        rec.reason
    )));
    ui.set_hotkey_hint(SharedString::from(format!(
        "Hotkey: Super+S then C. {}",
        hotkeys::hint_for(&prof.display)
    )));
    // Preselect recommended engine (lists shared with capture/download).
    let lists: Arc<Mutex<ModelLists>> = Arc::new(Mutex::new(ModelLists {
        ready: vec![],
        supported: vec![],
        recommended: rec.model.clone(),
    }));
    refresh_models(&ui, &rec, &lists);
    ui.set_status_text("Ready — capture, then review in the preview window and press Run OCR.".into());

    let shot: Arc<Mutex<Option<Shot>>> = Arc::new(Mutex::new(None));
    // Captured image awaiting the user's explicit Run OCR (never auto-run).
    let pending: Arc<Mutex<Option<image::RgbaImage>>> = Arc::new(Mutex::new(None));
    // Small preview window (created once, reused, shown per capture).
    let preview = PreviewWindow::new()?;
    let preview_w = preview.as_weak();
    {
        let ui_w = ui.as_weak();
        let shot = shot.clone();
        let pending = pending.clone();
        let lists = lists.clone();
        let preview_w = preview_w.clone();
        preview.on_run_ocr(move || {
            let img = pending.lock().unwrap().clone();
            let Some(img) = img else {
                if let Some(p) = preview_w.upgrade() {
                    p.set_info_text("Nothing captured yet.".into());
                }
                return;
            };
            run_job(ui_w.clone(), preview_w.clone(), shot.clone(), lists.clone(), img);
        });
    }
    {
        let pending = pending.clone();
        let preview_w = preview_w.clone();
        preview.on_save_shot(move || {
            let guard = pending.lock().unwrap();
            let Some(img) = guard.as_ref() else { return };
            let path = std::env::temp_dir().join("snaptext-shot.png");
            let msg = match img.save(&path) {
                Ok(()) => format!("Screenshot → {}", path.display()),
                Err(e) => format!("Save failed: {e}"),
            };
            if let Some(p) = preview_w.upgrade() {
                p.set_info_text(SharedString::from(msg));
            }
        });
    }
    {
        let preview_w = preview_w.clone();
        preview.on_close_preview(move || {
            if let Some(p) = preview_w.upgrade() {
                let _ = p.hide();
            }
        });
    }

    // Persistent freeze overlay (created once, reused per region capture) +
    // the frozen frame it selects from.
    let overlay = RegionWindow::new()?;
    let overlay_w = overlay.as_weak();
    let frozen: Arc<Mutex<Option<Arc<image::RgbaImage>>>> = Arc::new(Mutex::new(None));
    {
        let ui_w = ui.as_weak();
        let pending = pending.clone();
        let preview_w = preview_w.clone();
        let frozen = frozen.clone();
        let overlay_w = overlay_w.clone();
        overlay.on_region_done(move |lx, ly, lw, lh| {
            let (frozen_img, scale) = match (frozen.lock().unwrap().clone(), overlay_w.upgrade()) {
                (Some(f), Some(o)) => (f, o.window().scale_factor()),
                _ => return,
            };
            let (x, y, w, h) = snaptext_core::capture::map_logical_rect(
                lx, ly, lw, lh, scale, frozen_img.width(), frozen_img.height(),
            );
            let crop = snaptext_core::capture::crop(&frozen_img, x, y, w, h);
            if let Some(o) = overlay_w.upgrade() {
                let _ = o.hide();
            }
            let info = format!("Region {w}×{h} at ({x},{y}) — press Run OCR when ready.");
            *pending.lock().unwrap() = Some(crop.clone());
            let _ = ui_w.upgrade_in_event_loop(move |u| {
                u.set_busy(false);
                u.set_status_text("Region selected — review in the preview window.".into());
            });
            let preview_w2 = preview_w.clone();
            let _ = preview_w.upgrade_in_event_loop(move |_| {
                show_preview(&preview_w2, &crop, info);
            });
        });
    }
    {
        let ui_w = ui.as_weak();
        let overlay_w = overlay_w.clone();
        overlay.on_region_cancelled(move || {
            if let Some(o) = overlay_w.upgrade() {
                let _ = o.hide();
            }
            let _ = ui_w.upgrade_in_event_loop(move |u| {
                u.set_busy(false);
                u.set_status_text("Region selection cancelled.".into());
            });
        });
    }

    // Install-time detection: probe the device once in the background and
    // persist resolved paths to models.json so later runs use set paths.
    {
        let ui_w = ui.as_weak();
        let lists = lists.clone();
        std::thread::spawn(move || {
            let _ = models::probe_and_save_config();
            let _ = ui_w.upgrade_in_event_loop(move |u| {
                refresh_models(&u, &recommender::recommend(&device::profile()), &lists);
            });
        });
    }

    // --- Capture Full / Window: capture only, show preview, wait for Run OCR.
    {
        let ui_w = ui.as_weak();
        let pending = pending.clone();
        let preview_w = preview_w.clone();
        let overlay_w = overlay_w.clone();
        let frozen = frozen.clone();
        ui.on_capture_full(move || {
            capture_into(
                ui_w.clone(),
                pending.clone(),
                preview_w.clone(),
                overlay_w.clone(),
                frozen.clone(),
                CaptureKind::Full,
            );
        });
    }
    // --- Select Region: freeze overlay with drag-select, then preview.
    {
        let ui_w = ui.as_weak();
        let pending = pending.clone();
        let preview_w = preview_w.clone();
        let overlay_w = overlay_w.clone();
        let frozen = frozen.clone();
        ui.on_capture_region(move || {
            capture_into(
                ui_w.clone(),
                pending.clone(),
                preview_w.clone(),
                overlay_w.clone(),
                frozen.clone(),
                CaptureKind::Region,
            );
        });
    }
    // --- Capture Window (Linux direct selection / Windows focused window) ---
    {
        let ui_w = ui.as_weak();
        let pending = pending.clone();
        let preview_w = preview_w.clone();
        let overlay_w = overlay_w.clone();
        let frozen = frozen.clone();
        ui.on_capture_window(move || {
            capture_into(
                ui_w.clone(),
                pending.clone(),
                preview_w.clone(),
                overlay_w.clone(),
                frozen.clone(),
                CaptureKind::Window,
            );
        });
    }
    {
        let ui_w = ui.as_weak();
        let shot = shot.clone();
        ui.on_copy_text(move || {
            if let Some(ui) = ui_w.upgrade() {
                let text = ui.get_result_text().to_string();
                match snaptext_core::clipboard::copy_text(&text) {
                    Ok(()) => ui.set_status_text("Copied to clipboard.".into()),
                    Err(e) => ui.set_status_text(SharedString::from(format!("Copy failed: {e}"))),
                }
                let _ = &shot;
            }
        });
    }
    {
        let ui_w = ui.as_weak();
        let shot = shot.clone();
        ui.on_save_pdf(move || {
            let Some(ui) = ui_w.upgrade() else { return };
            let guard = shot.lock().unwrap();
            let Some(s) = guard.as_ref() else {
                ui.set_status_text("Nothing to save yet.".into());
                return;
            };
            match snaptext_core::overlay::searchable_pdf(&s.img, &s.result) {
                Ok(bytes) => {
                    let path = std::env::temp_dir().join("snaptext-out.pdf");
                    match std::fs::write(&path, &bytes) {
                        Ok(()) => ui.set_status_text(SharedString::from(format!(
                            "Searchable PDF → {} ({} bytes)",
                            path.display(),
                            bytes.len()
                        ))),
                        Err(e) => ui.set_status_text(SharedString::from(format!("Save failed: {e}"))),
                    }
                }
                Err(e) => ui.set_status_text(SharedString::from(format!("PDF failed: {e}"))),
            }
        });
    }
    {
        let ui_w = ui.as_weak();
        let shot = shot.clone();
        ui.on_save_overlay(move || {
            let Some(ui) = ui_w.upgrade() else { return };
            let guard = shot.lock().unwrap();
            let Some(s) = guard.as_ref() else {
                ui.set_status_text("Nothing to save yet.".into());
                return;
            };
            let out = snaptext_core::overlay::image_with_overlay(&s.img, &s.result);
            let path = std::env::temp_dir().join("snaptext-overlay.png");
            match out.save(&path) {
                Ok(()) => ui.set_status_text(SharedString::from(format!(
                    "Overlay image → {}",
                    path.display()
                ))),
                Err(e) => ui.set_status_text(SharedString::from(format!("Save failed: {e}"))),
            }
        });
    }
    {
        let ui_w = ui.as_weak();
        let lists = lists.clone();
        ui.on_refresh_models(move || {
            if let Some(ui) = ui_w.upgrade() {
                refresh_models(&ui, &recommender::recommend(&device::profile()), &lists);
            }
        });
    }
    // Downloads = the only network path. After one finishes the lists
    // refresh, so the model appears in the Capture engine list.
    {
        let ui_w = ui.as_weak();
        let lists = lists.clone();
        ui.on_download_model(move |row| {
            let id = lists
                .lock()
                .ok()
                .and_then(|l| l.supported.get(row as usize).cloned())
                .unwrap_or_default();
            if !id.is_empty() {
                download_into(ui_w.clone(), lists.clone(), id);
            }
        });
    }
    {
        let ui_w = ui.as_weak();
        let lists = lists.clone();
        ui.on_download_missing(move || {
            let id = lists.lock().ok().map(|l| l.recommended.clone()).unwrap_or_default();
            if !id.is_empty() {
                if let Some(u) = ui_w.upgrade() {
                    u.set_busy(true);
                    u.set_model_dl_status(SharedString::from(format!("Downloading {id} …")));
                }
                download_into(ui_w.clone(), lists.clone(), id);
            }
        });
    }

    ui.run()?;
    Ok(())
}

fn download_into(
    ui_w: slint::Weak<SnapWindow>,
    lists: Arc<Mutex<ModelLists>>,
    id: String,
) {
    if let Some(u) = ui_w.upgrade() {
        u.set_busy(true);
        u.set_model_dl_status(SharedString::from(format!("Downloading {id} …")));
    }
    std::thread::spawn(move || {
        let msg = match models::ensure(&id, |_| {}) {
            Ok(dir) => format!("{id} ready at {}", dir.display()),
            Err(e) => format!("Download failed for {id}: {e}"),
        };
        let _ = ui_w.upgrade_in_event_loop(move |u| {
            u.set_model_dl_status(SharedString::from(msg));
            u.set_busy(false);
            refresh_models(&u, &recommender::recommend(&device::profile()), &lists);
        });
    });
}

enum CaptureKind {
    Full,
    Region,
    Window,
}

/// RgbaImage → Slint image, thumbnailed for the small preview window.
fn slint_image(img: &image::RgbaImage, max_w: u32) -> slint::Image {
    let (w, h) = (img.width(), img.height());
    let small = if w > max_w {
        let h2 = (h as f32 * max_w as f32 / w as f32) as u32;
        image::imageops::resize(img, max_w, h2.max(1), image::imageops::FilterType::Triangle)
    } else {
        img.clone()
    };
    let (w, h) = (small.width() as u32, small.height() as u32);
    let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
        &small.into_raw(),
        w,
        h,
    );
    slint::Image::from_rgba8(buf)
}

fn show_preview(
    preview: &slint::Weak<PreviewWindow>,
    img: &image::RgbaImage,
    info: String,
) {
    if let Some(p) = preview.upgrade() {
        p.set_shot(slint_image(img, 640));
        p.set_info_text(SharedString::from(info));
        p.set_busy(false);
        let _ = p.show();
    }
}

/// Capture only (no OCR): fullscreen / frozen-overlay region / window, then
/// park the image in `pending` and open the small preview window. The user
/// presses Run OCR explicitly — nothing is recognised automatically.
fn capture_into(
    ui: slint::Weak<SnapWindow>,
    pending: Arc<Mutex<Option<image::RgbaImage>>>,
    preview: slint::Weak<PreviewWindow>,
    overlay: slint::Weak<RegionWindow>,
    frozen: Arc<Mutex<Option<Arc<image::RgbaImage>>>>,
    kind: CaptureKind,
) {
    if let Some(u) = ui.upgrade() {
        u.set_busy(true);
        u.set_status_text("Capturing…".into());
    }
    std::thread::spawn(move || {
        let done_busy = || {
            let ui = ui.clone();
            let preview = preview.clone();
            let _ = ui.upgrade_in_event_loop(|u| u.set_busy(false));
            let _ = preview.upgrade_in_event_loop(|p| p.set_busy(false));
        };
        match kind {
            CaptureKind::Full | CaptureKind::Window => {
                let img = if matches!(kind, CaptureKind::Full) {
                    snaptext_core::capture::fullscreen()
                } else {
                    snaptext_core::capture::active_window()
                        .or_else(|_| snaptext_core::capture::fullscreen())
                };
                match img {
                    Ok(img) => {
                        let info = format!("{}×{} captured — press Run OCR when ready.", img.width(), img.height());
                        *pending.lock().unwrap() = Some(img.clone());
                        let ui = ui.clone();
                        let _ = ui.upgrade_in_event_loop(move |u| {
                            u.set_busy(false);
                            u.set_status_text("Captured — review in the preview window.".into());
                        });
                        let preview2 = preview.clone();
                        let _ = preview.upgrade_in_event_loop(move |_| {
                            show_preview(&preview2, &img, info);
                        });
                    }
                    Err(e) => {
                        let msg = format!("Capture failed: {e}");
                        let ui = ui.clone();
                        let _ = ui.upgrade_in_event_loop(move |u| {
                            u.set_busy(false);
                            u.set_status_text(SharedString::from(msg));
                        });
                        done_busy();
                    }
                }
            }
            CaptureKind::Region => {
                match snaptext_core::capture::fullscreen() {
                    Ok(frozen_img) => {
                        let ui2 = ui.clone();
                        let overlay = overlay.clone();
                        let frozen = frozen.clone();
                        let _ = ui.upgrade_in_event_loop(move |_| {
                            open_region_overlay(&ui2, &overlay, &frozen, frozen_img);
                        });
                    }
                    Err(e) => {
                        let msg = format!("Capture failed: {e}");
                        let ui = ui.clone();
                        let _ = ui.upgrade_in_event_loop(move |u| {
                            u.set_busy(false);
                            u.set_status_text(SharedString::from(msg));
                        });
                    }
                }
            }
        }
    });
}

/// Park the persistent freeze overlay exactly over the captured monitor with
/// the frozen frame 1:1; drag selects, right-click cancels.
fn open_region_overlay(
    ui: &slint::Weak<SnapWindow>,
    overlay: &slint::Weak<RegionWindow>,
    frozen_slot: &Arc<Mutex<Option<Arc<image::RgbaImage>>>>,
    frozen_img: image::RgbaImage,
) {
    let Some(o) = overlay.upgrade() else {
        let _ = ui.upgrade_in_event_loop(|u| {
            u.set_busy(false);
            u.set_status_text("Overlay unavailable.".into());
        });
        return;
    };
    let (fw, fh) = (frozen_img.width(), frozen_img.height());
    o.set_shot(slint_image(&frozen_img, fw));
    // Physical size == image pixels → logical×scale maps back exactly.
    use slint::{PhysicalPosition, PhysicalSize};
    let (ox, oy) = snaptext_core::capture::fullscreen_origin();
    o.window().set_position(PhysicalPosition { x: ox, y: oy });
    o.window().set_size(PhysicalSize { width: fw, height: fh });
    *frozen_slot.lock().unwrap() = Some(Arc::new(frozen_img));
    let _ = o.show();
    if let Some(u) = ui.upgrade() {
        u.set_busy(false);
        u.set_status_text("Drag a rectangle — release to confirm, right-click to cancel.".into());
    }
}

/// Explicit Run OCR on an already-captured image (preview → main results +
/// overlay back into the preview). Never called implicitly after capture.
/// Readiness per supported model; the Capture engine list holds READY ones
/// only, so a capture can never pick a model whose path isn't integrated.
fn readiness(supported: &[snaptext_core::catalog::ModelEntry]) -> Vec<bool> {
    supported
        .iter()
        .map(|m| models::status(&m.id).map(|st| st.present).unwrap_or(false))
        .collect()
}

fn refresh_models(
    ui: &SnapWindow,
    rec: &recommender::Recommendation,
    lists: &Arc<Mutex<ModelLists>>,
) {
    use slint::{ModelRc, VecModel};
    let ready_flags = readiness(&rec.supported);
    {
        let mut l = lists.lock().unwrap();
        l.supported = rec.supported.iter().map(|m| m.id.clone()).collect();
        l.recommended = rec.model.clone();
        l.ready = rec
            .supported
            .iter()
            .zip(&ready_flags)
            .filter(|(_, r)| **r)
            .map(|(m, _)| m.id.clone())
            .collect();
        if l.ready.is_empty() {
            // Nothing integrated yet: keep the recommended entry selectable
            // so its error names the direct URLs + PATH hint.
            l.ready.push(rec.model.clone());
        }
    }
    let l = lists.lock().unwrap();
    let engine_labels: Vec<SharedString> = l
        .ready
        .iter()
        .map(|id| {
            let label = rec
                .supported
                .iter()
                .find(|m| &m.id == id)
                .map(|m| m.label.clone())
                .unwrap_or_else(|| id.clone());
            SharedString::from(format!("{id} — {label}"))
        })
        .collect();
    let sel = l.ready.iter().position(|id| id == &rec.model).unwrap_or(0) as i32;
    let status_lines: Vec<SharedString> = rec
        .supported
        .iter()
        .zip(&ready_flags)
        .map(|(m, ready)| {
            let line = match models::status(&m.id) {
                Ok(st) => models::describe(&st),
                Err(e) => format!("{}: {e}", m.id),
            };
            SharedString::from(format!(
                "[{}] {line}",
                if *ready { "ready" } else { "download" }
            ))
        })
        .collect();
    drop(l);
    let names: Vec<SharedString> = rec
        .supported
        .iter()
        .map(|m| SharedString::from(format!("{}  — {}", m.id, m.label)))
        .collect();
    let acc: Vec<f32> = rec.supported.iter().map(|m| m.accuracy_gui as f32).collect();
    let max_ms = rec.supported.iter().map(|m| m.speed_ms_ref).max().unwrap_or(1).max(1);
    let spd: Vec<f32> = rec
        .supported
        .iter()
        .map(|m| 1.0 - (m.speed_ms_ref as f32 / (max_ms as f32 * 1.2)).min(1.0))
        .collect();
    ui.set_model_names(ModelRc::new(VecModel::from_slice(&names)));
    ui.set_model_acc(ModelRc::new(VecModel::from_slice(&acc)));
    ui.set_model_speed(ModelRc::new(VecModel::from_slice(&spd)));
    ui.set_model_status(ModelRc::new(VecModel::from_slice(&status_lines)));
    ui.set_model_note(SharedString::from(format!(
        "Recommended: {} — {}. Unsupported models (RAM/cores/arch) hidden. Capture lists ready models only.",
        rec.model, rec.reason
    )));
    ui.set_engine_names(ModelRc::new(VecModel::from_slice(&engine_labels)));
    ui.set_engine_index(sel);
    // Detection line: weights presence + binaries on PATH (with add-to-PATH hint).
    let dl = match models::status(&rec.model) {
        Ok(st) => models::describe(&st),
        Err(e) => format!("{}: {e}", rec.model),
    };
    ui.set_model_dl_status(SharedString::from(dl));
}

fn run_job(
    ui: slint::Weak<SnapWindow>,
    preview: slint::Weak<PreviewWindow>,
    shot: Arc<Mutex<Option<Shot>>>,
    lists: Arc<Mutex<ModelLists>>,
    img: image::RgbaImage,
) {
    // Snapshot UI choices on the UI thread, then work in background.
    let (engine_idx, mode_idx, auto_copy) = match ui.upgrade() {
        Some(u) => (u.get_engine_index(), u.get_mode_index(), u.get_auto_copy()),
        None => return,
    };
    let engine_id = lists
        .lock()
        .ok()
        .and_then(|l| l.ready.get(engine_idx as usize).cloned())
        .unwrap_or_else(|| "ppocrv6-server".to_string());
    if let Some(u) = ui.upgrade() {
        u.set_busy(true);
        u.set_status_text("Recognising text…".into());
    }
    if let Some(p) = preview.upgrade() {
        p.set_busy(true);
        p.set_info_text("Recognising text…".into());
    }
    std::thread::spawn(move || {
        let set_status = |msg: String| {
            let _ = ui.upgrade_in_event_loop(move |u| {
                u.set_status_text(SharedString::from(msg));
            });
        };
        let finish = |busy: bool| {
            let _ = ui.upgrade_in_event_loop(move |u| {
                u.set_busy(busy);
            });
            let _ = preview.upgrade_in_event_loop(move |p| {
                p.set_busy(busy);
            });
        };
        // Recognise (paths resolved from install config → cache → device).
        let engine = engine_of_id(&engine_id);
        let id = engine_id.clone();
        let outcome = if mode_idx == 1 {
            // VLM forced.
            let vm = VlmModel::from_id(&id).unwrap_or(VlmModel::PaddleOcrVl09);
            snaptext_core::vlm::run(&img, vm)
                .map(|r| (r, "vlm".to_string()))
                .map_err(|e| snaptext_core::ocr::OcrError::Failed(e.to_string()))
        } else if mode_idx == 2 {
            // Auto: OCR then VLM escalation inside pipeline.
            let vm = VlmModel::PaddleOcrVl09;
            let (r, t) = snaptext_core::pipeline::run_auto(&img, engine, vm, 0.75);
            let _ = &t;
            if r.boxes.is_empty() && !t.note.is_empty() {
                Err(snaptext_core::ocr::OcrError::Failed(t.note.clone()))
            } else {
                Ok((r, t.mode))
            }
        } else {
            snaptext_core::ocr::run(&img, engine)
                .map(|r| (r, "ocr".to_string()))
        };
        match outcome {
            Ok((result, mode)) => {
                let text = result.text.clone();
                let n = result.boxes.len();
                let conf = result.mean_conf;
                // Overlay render for the preview window (boxed view of results).
                let overlaid = snaptext_core::overlay::image_with_overlay(&img, &result);
                *shot.lock().unwrap() = Some(Shot { img, result });
                if auto_copy && !text.is_empty() {
                    let _ = snaptext_core::clipboard::copy_text(&text);
                }
                let msg = format!(
                    "[{mode}/{id}] {n} boxes, conf {conf:.2}{} — {}",
                    if auto_copy { ", auto-copied" } else { "" },
                    if n == 0 { "no text?" } else { "done" },
                );
                let boxes_line = format!("boxes={n} conf={conf:.2} engine={id}");
                let _ = ui.upgrade_in_event_loop(move |u| {
                    u.set_result_text(SharedString::from(text));
                    u.set_status_text(SharedString::from(msg));
                    u.set_boxes_line(SharedString::from(boxes_line));
                    u.set_conf_value(conf);
                    u.set_busy(false);
                });
                // slint::Image is !Send: build it on the event-loop thread.
                let _ = preview.upgrade_in_event_loop(move |p| {
                    p.set_shot(slint_image(&overlaid, 640));
                    p.set_busy(false);
                    p.set_info_text(SharedString::from(format!(
                        "{n} boxes, conf {conf:.2} — overlay shown"
                    )));
                });
            }
            Err(e) => {
                let msg = format!("Recognition failed: {e}. Install the engine (Tesseract binary / PP-OCR ONNX) or pick another.");
                let msg2 = msg.clone();
                let _ = preview.upgrade_in_event_loop(move |p| {
                    p.set_busy(false);
                    p.set_info_text(SharedString::from(msg2));
                });
                set_status(msg);
                finish(false);
            }
        }
    });
}
