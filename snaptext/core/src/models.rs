//! Model manager: direct downloads + device-wide detection, install-time config.
//!
//! Contract:
//! - Every weight has a **direct URL** below (upstream ModelScope/HF,
//!   verified against rapidocr's own `default_models.yaml`), overridable
//!   via `SNAPTEXT_MODEL_BASE` for mirrors.
//! - Detection scans, in order: install config (`models.json`, written by
//!   probe at install/first-run) → `SNAPTEXT_MODEL_DIR` → OS cache →
//!   exe-side `./models` → cwd `./models` → well-known device locations
//!   (rapidocr/paddle site-packages, HF hub, tessdata). Alias filenames
//!   accepted (e.g. PP-OCRv4 files satisfy the mobile tier as compat).
//! - Nothing here touches the network except `ensure()`, called only by an
//!   explicit Download action. Tests use pure `resolve_in()` (no env).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use sha2::Digest;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Det,
    Rec,
    Cls,
    Dict,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Det => "det",
            Role::Rec => "rec",
            Role::Cls => "cls",
            Role::Dict => "dict",
        }
    }
}

/// One download option for a role. First existing file wins; downloads fetch
/// the primary (index 0) option.
#[derive(Debug, Clone)]
pub struct RoleOption {
    pub filename: &'static str,
    pub url: String,
    pub sha256: &'static str,
}

#[derive(Debug, Clone)]
pub struct ModelSpec {
    pub id: String,
    /// Binary names that must be on PATH (tesseract, docling).
    pub binaries: &'static [&'static str],
    /// (role, options) — every role must resolve for the model to be usable.
    pub roles: Vec<(Role, Vec<RoleOption>)>,
    pub note: &'static str,
}

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("unknown model: {0}")]
    Unknown(String),
    #[error("download failed for {0}: {1}")]
    Download(String, String),
    #[error("checksum mismatch for {0}")]
    Checksum(String),
    #[error("io: {0}")]
    Io(String),
}

const MS: &str = "https://www.modelscope.cn/models/RapidAI/RapidOCR/resolve/v3.5.0";

fn ms(path: &str) -> String {
    if let Ok(base) = std::env::var("SNAPTEXT_MODEL_BASE") {
        if !base.trim().is_empty() {
            return format!("{base}/{path}");
        }
    }
    format!("{MS}/{path}")
}

fn opt(filename: &'static str, url: String) -> RoleOption {
    RoleOption { filename, url, sha256: "" }
}

/// Direct-URL table (upstream ModelScope; v3.5.0 tree verified on-device).
pub fn spec(id: &str) -> Option<ModelSpec> {
    match id {
        "tesseract-fast" | "tesseract-best" => Some(ModelSpec {
            id: id.to_string(),
            binaries: &["tesseract"],
            roles: vec![],
            note: "Tesseract binary + tessdata.",
        }),
        "ppocrv5-mobile" => Some(ModelSpec {
            id: id.to_string(),
            binaries: &[],
            roles: vec![
                (Role::Det, vec![
                    opt("ch_PP-OCRv5_mobile_det.onnx", ms("onnx/PP-OCRv5/det/ch_PP-OCRv5_mobile_det.onnx")),
                    opt("ch_PP-OCRv4_det_infer.onnx", ms("onnx/PP-OCRv4/det/ch_PP-OCRv4_det_infer.onnx")),
                ]),
                (Role::Rec, vec![
                    opt("ch_PP-OCRv5_rec_mobile_infer.onnx", ms("onnx/PP-OCRv5/rec/ch_PP-OCRv5_rec_mobile_infer.onnx")),
                    opt("ch_PP-OCRv4_rec_infer.onnx", ms("onnx/PP-OCRv4/rec/ch_PP-OCRv4_rec_infer.onnx")),
                ]),
                (Role::Cls, vec![
                    opt("ch_ppocr_mobile_v2.0_cls_infer.onnx", ms("onnx/PP-OCRv4/cls/ch_ppocr_mobile_v2.0_cls_infer.onnx")),
                ]),
                (Role::Dict, vec![
                    opt("ppocrv5_dict.txt", ms("paddle/PP-OCRv5/rec/ch_PP-OCRv5_rec_mobile_infer/ppocrv5_dict.txt")),
                    opt("ppocr_keys_v1.txt", ms("paddle/PP-OCRv4/rec/ch_PP-OCRv4_rec_infer/ppocr_keys_v1.txt")),
                ]),
            ],
            note: "PP-OCR mobile det+rec+cls ONNX (v5 primary, v4 compat).",
        }),
        "ppocrv6-server" => Some(ModelSpec {
            id: id.to_string(),
            binaries: &[],
            roles: vec![
                (Role::Det, vec![
                    opt("ch_PP-OCRv5_server_det.onnx", ms("onnx/PP-OCRv5/det/ch_PP-OCRv5_server_det.onnx")),
                    opt("ch_PP-OCRv4_det_server_infer.onnx", ms("onnx/PP-OCRv4/det/ch_PP-OCRv4_det_server_infer.onnx")),
                ]),
                (Role::Rec, vec![
                    opt("ch_PP-OCRv5_rec_server_infer.onnx", ms("onnx/PP-OCRv5/rec/ch_PP-OCRv5_rec_server_infer.onnx")),
                    opt("ch_PP-OCRv4_rec_server_infer.onnx", ms("onnx/PP-OCRv4/rec/ch_PP-OCRv4_rec_server_infer.onnx")),
                ]),
                (Role::Cls, vec![
                    opt("ch_ppocr_mobile_v2.0_cls_infer.onnx", ms("onnx/PP-OCRv4/cls/ch_ppocr_mobile_v2.0_cls_infer.onnx")),
                ]),
                (Role::Dict, vec![
                    opt("ppocrv5_dict.txt", ms("paddle/PP-OCRv5/rec/ch_PP-OCRv5_rec_server_infer/ppocrv5_dict.txt")),
                    opt("ppocr_keys_v1.txt", ms("paddle/PP-OCRv4/rec/ch_PP-OCRv4_rec_infer/ppocr_keys_v1.txt")),
                ]),
            ],
            // Server weights track the v5-server line (best verified upstream
            // tier); relabelled v6 when RapidAI publishes v6 ONNX.
            note: "PP-OCR server det+rec+cls ONNX (v5-server primary, v4-server compat).",
        }),
        "docling-doc" => Some(ModelSpec {
            id: id.to_string(),
            binaries: &["docling"],
            roles: vec![],
            note: "Docling sidecar binary (v2 bundles it).",
        }),
        "paddleocr-vl-0.9b" => Some(ModelSpec {
            id: id.to_string(),
            binaries: &[],
            roles: vec![(Role::Rec, vec![
                opt("model_q8.gguf", "https://huggingface.co/PaddlePaddle/PaddleOCR-VL-0.9B/resolve/main/model_q8.gguf".into()),
            ])],
            note: "PaddleOCR-VL 0.9B Q8 GGUF.",
        }),
        "paddleocr-vl-1.7b" => Some(ModelSpec {
            id: id.to_string(),
            binaries: &[],
            roles: vec![(Role::Rec, vec![
                opt("model_q4km.gguf", "https://huggingface.co/PaddlePaddle/PaddleOCR-VL-1.7B/resolve/main/model_Q4_K_M.gguf".into()),
            ])],
            note: "PaddleOCR-VL 1.7B Q4_K_M GGUF.",
        }),
        _ => None,
    }
}

pub fn all_ids() -> &'static [&'static str] {
    &[
        "tesseract-fast",
        "tesseract-best",
        "ppocrv5-mobile",
        "ppocrv6-server",
        "docling-doc",
        "paddleocr-vl-0.9b",
        "paddleocr-vl-1.7b",
    ]
}

// --- directories -----------------------------------------------------------

pub fn cache_root() -> PathBuf {
    if let Ok(dir) = std::env::var("SNAPTEXT_MODEL_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    #[cfg(target_os = "windows")]
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    #[cfg(not(target_os = "windows"))]
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".cache"))
                .unwrap_or_else(|_| std::env::temp_dir())
        });
    base.join("snaptext")
}

pub fn config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| cache_root());
    #[cfg(not(target_os = "windows"))]
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .unwrap_or_else(|_| std::env::temp_dir())
        });
    base.join("snaptext").join("models.json")
}

/// Well-known device locations scanned for already-downloaded weights
/// (rapidocr/paddle site-packages, HF hub, tessdata roots).
fn device_roots() -> Vec<PathBuf> {
    let mut roots = vec![];
    #[cfg(target_os = "windows")]
    {
        if let Ok(programs) = std::env::var("LOCALAPPDATA") {
            let py = PathBuf::from(&programs).join("Programs").join("Python");
            if let Ok(entries) = std::fs::read_dir(&py) {
                for e in entries.flatten() {
                    roots.push(e.path().join("Lib").join("site-packages").join("rapidocr").join("models"));
                    roots.push(e.path().join("Lib").join("site-packages").join("paddleocr"));
                }
            }
        }
        roots.push(PathBuf::from("C:\\Program Files\\Tesseract-OCR\\tessdata"));
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let h = PathBuf::from(&home);
            roots.push(h.join(".cache").join("huggingface").join("hub"));
            if let Ok(lib) = std::fs::read_dir(h.join(".local").join("lib")) {
                for e in entries_flatten(lib) {
                    roots.push(e.join("site-packages").join("rapidocr").join("models"));
                }
            }
            roots.push(h.join(".paddleocr"));
            roots.push(h.join(".cache").join("paddle"));
        }
        for base in ["/usr/lib", "/usr/local/lib", "/opt"] {
            if let Ok(entries) = std::fs::read_dir(base) {
                for e in entries.flatten() {
                    let p = e.path();
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name.starts_with("python3") || name == "python3" {
                        roots.push(p.join("site-packages").join("rapidocr").join("models"));
                    }
                }
            }
        }
        roots.push(PathBuf::from("/usr/share/tesseract-ocr/5/tessdata"));
        roots.push(PathBuf::from("/usr/share/tessdata"));
    }
    roots.into_iter().filter(|p| p.is_dir()).collect()
}

#[cfg(not(target_os = "windows"))]
fn entries_flatten(rd: std::fs::ReadDir) -> Vec<PathBuf> {
    rd.flatten().map(|e| e.path()).collect()
}

/// Ordered search dirs for `<id>/` weights (writable first).
pub fn search_dirs(id: &str) -> Vec<PathBuf> {
    let mut dirs = vec![cache_root().join(id)];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            dirs.push(d.join("models").join(id));
        }
    }
    dirs.push(PathBuf::from("models").join(id));
    dirs.extend(device_roots());
    dirs
}

// --- install config (paths set at install/first-run) ------------------------

/// `models.json`: `{ "<id>": { "<role>": "<abs path>", ... } }`.
pub fn load_config() -> HashMap<String, HashMap<String, String>> {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_config(map: &HashMap<String, HashMap<String, String>>) -> Result<(), String> {
    let p = config_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(map).map_err(|e| e.to_string())?;
    std::fs::write(&p, text).map_err(|e| e.to_string())?;
    Ok(())
}

/// Probe the device and persist resolved role paths. Called at install and on
/// first UI run so later runs use set paths without rescanning. Pure search,
/// no downloads.
pub fn probe_and_save_config() -> Result<HashMap<String, HashMap<String, String>>, String> {
    let mut map: HashMap<String, HashMap<String, String>> = HashMap::new();
    for id in all_ids() {
        let Some(s) = spec(id) else { continue };
        let r = resolve(&s);
        if r.present {
            let mut inner = HashMap::new();
            for (role, path) in &r.found_paths {
                inner.insert(role.as_str().to_string(), path.display().to_string());
            }
            map.insert(id.to_string(), inner);
        }
    }
    save_config(&map)?;
    Ok(map)
}

// --- resolution (pure search, no network) ------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub id: String,
    pub present: bool,
    pub found_paths: HashMap<Role, PathBuf>,
    pub missing_roles: Vec<Role>,
    pub binaries: Vec<(String, Option<PathBuf>)>,
}

pub fn status(id: &str) -> Result<ModelStatus, ModelError> {
    let s = spec(id).ok_or_else(|| ModelError::Unknown(id.into()))?;
    let r = resolve(&s);
    let missing_files: Vec<String> = r
        .missing_roles
        .iter()
        .map(|role| format!("{} ({})", role.as_str(), primary_filename(&s, *role)))
        .collect();
    let detail = describe_resolved(&s, &r);
    Ok(ModelStatus {
        id: s.id.clone(),
        present: r.present,
        found_dir: r.found_paths.values().next().and_then(|p| p.parent().map(|d| d.to_path_buf())),
        missing_files,
        binaries: r.binaries,
        detail,
    })
}

fn primary_filename(s: &ModelSpec, role: Role) -> &'static str {
    s.roles
        .iter()
        .find(|(r, _)| *r == role)
        .and_then(|(_, opts)| opts.first().map(|o| o.filename))
        .unwrap_or("?")
}

/// Backwards-compatible status view for callers/tests.
#[derive(Debug, Clone)]
pub struct ModelStatus {
    pub id: String,
    pub present: bool,
    pub found_dir: Option<PathBuf>,
    pub missing_files: Vec<String>,
    pub binaries: Vec<(String, Option<PathBuf>)>,
    pub detail: String,
}

/// Resolver over explicit dirs. `use_config: true` (production) lets the
/// install-time `models.json` paths win when the files still exist; tests
/// pass `false` so temp-dir assertions stay hermetic on a machine that
/// already has a config file.
pub fn resolve_in(dirs: &[PathBuf], s: &ModelSpec, use_config: bool) -> Resolved {
    let cfg = if use_config { load_config() } else { HashMap::new() };
    let mut found: HashMap<Role, PathBuf> = HashMap::new();
    // 1. Config paths first (install-time detection).
    if let Some(entry) = cfg.get(&s.id) {
        for role in s.roles.iter().map(|(r, _)| *r) {
            if let Some(p) = entry.get(role.as_str()).map(PathBuf::from) {
                if p.is_file() {
                    found.insert(role, p);
                }
            }
        }
    }
    // 2. Directory scan: first dir holding ANY option per role wins.
    // Rec resolves FIRST: Dict pairs with the rec family (v4 rec <->
    // keys_v1, v5 rec <-> v5 dict); class counts must match for CTC.
    let mut ordered_roles: Vec<usize> = (0..s.roles.len()).collect();
    ordered_roles.sort_by_key(|&i| if s.roles[i].0 == Role::Rec { 0 } else { 1 });
    for &i in &ordered_roles {
        let (role, opts) = &s.roles[i];
        if found.contains_key(role) {
            continue;
        }
        let rec_is_v4 = found.get(&Role::Rec).and_then(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.contains("PP-OCRv4") || n.contains("v4"))
        });
        let ordered: Vec<&RoleOption> = if *role == Role::Dict {
            let mut v: Vec<&RoleOption> = opts.iter().collect();
            v.sort_by_key(|o| {
                let is_keys = o.filename.contains("keys_v1");
                match rec_is_v4 {
                    Some(true) => !is_keys,
                    Some(false) => is_keys,
                    None => false,
                }
            });
            v
        } else {
            opts.iter().collect()
        };
        'dirs: for d in dirs {
            for o in &ordered {
                let p = d.join(o.filename);
                if p.is_file() {
                    found.insert(*role, p);
                    break 'dirs;
                }
            }
        }
    }
    let missing_roles: Vec<Role> = s
        .roles
        .iter()
        .map(|(r, _)| *r)
        .filter(|r| !found.contains_key(r))
        .collect();
    let binaries: Vec<(String, Option<PathBuf>)> =
        s.binaries.iter().map(|b| (b.to_string(), probe_binary(b))).collect();
    // Binary-gated specs (tesseract/docling) are usable only when the binary
    // is on PATH; weight specs need every role file. Either way the engine
    // list only shows models whose `present` is true.
    let present =
        missing_roles.is_empty() && binaries.iter().all(|(_, f)| f.is_some());
    Resolved {
        id: s.id.clone(),
        present,
        found_paths: found,
        missing_roles,
        binaries,
    }
}

/// Test helper: resolve inside ONE dir, ignoring install config.
pub fn status_in(dir: &Path, s: &ModelSpec) -> Resolved {
    resolve_in(std::slice::from_ref(&dir.to_path_buf()), s, false)
}

pub fn resolve(s: &ModelSpec) -> Resolved {
    resolve_in(&search_dirs(&s.id), s, true)
}

pub fn describe(st: &ModelStatus) -> String {
    st.detail.clone()
}

fn describe_resolved(s: &ModelSpec, r: &Resolved) -> String {
    let mut out = String::new();
    if r.present {
        if r.found_paths.is_empty() {
            out.push_str(&format!("{} ready (binary-gated)", s.id));
        } else {
            let dirs: Vec<String> = {
                let mut v: Vec<String> = r
                    .found_paths
                    .values()
                    .filter_map(|p| p.parent().map(|d| d.display().to_string()))
                    .collect();
                v.sort();
                v.dedup();
                v
            };
            out.push_str(&format!("{} ready at {}", s.id, dirs.join(" + ")));
        }
    } else {
        out.push_str(&format!("{} missing", s.id));
        for role in &r.missing_roles {
            if let Some((_, opts)) = s.roles.iter().find(|(rr, _)| rr == role) {
                if let Some(o) = opts.first() {
                    out.push_str(&format!(" | {} <- {}", o.filename, o.url));
                }
            }
        }
        out.push_str(&format!(" | dir: {}", cache_root().join(&s.id).display()));
    }
    for (bin, found) in &r.binaries {
        match found {
            Some(p) => out.push_str(&format!(" | {bin}: {} ", p.display())),
            None => out.push_str(&format!(" | {bin}: NOT on PATH ({})", path_hint(bin))),
        }
    }
    out
}

// --- PATH detection ----------------------------------------------------------

pub fn probe_binary_on_path(name: &str, path_env: &str) -> Option<PathBuf> {
    let sep = if cfg!(windows) { ';' } else { ':' };
    let mut cands: Vec<PathBuf> = path_env
        .split(sep)
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            let p = Path::new(s).join(name);
            #[cfg(windows)]
            return if p.extension().is_some() { p } else { p.with_extension("exe") };
            #[cfg(not(windows))]
            return p;
        })
        .collect();
    cands.extend(well_known(name));
    cands.into_iter().find(|p| p.is_file())
}

pub fn probe_binary(name: &str) -> Option<PathBuf> {
    probe_binary_on_path(name, &std::env::var("PATH").unwrap_or_default())
}

fn well_known(name: &str) -> Vec<PathBuf> {
    let mut v = vec![];
    #[cfg(windows)]
    {
        for base in [
            "C:\\Program Files\\Tesseract-OCR",
            "C:\\Program Files (x86)\\Tesseract-OCR",
        ] {
            v.push(PathBuf::from(base).join(format!("{name}.exe")));
        }
    }
    #[cfg(not(windows))]
    {
        for base in ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/snap/bin"] {
            v.push(PathBuf::from(base).join(name));
        }
    }
    let _ = name;
    v
}

pub fn path_hint(bin: &str) -> String {
    #[cfg(windows)]
    return format!("add its folder to PATH: setx PATH \"%PATH%;C:\\path\\to\\{bin}\" (new terminal)");
    #[cfg(not(windows))]
    return format!("add its folder to PATH: export PATH=\"$PATH:/path/to/{bin}\" (or symlink into /usr/local/bin)");
}

// --- download (only via explicit Download action) ----------------------------

pub fn ensure(id: &str, mut on_progress: impl FnMut(&str)) -> Result<PathBuf, ModelError> {
    let s = spec(id).ok_or_else(|| ModelError::Unknown(id.into()))?;
    let dir = cache_root().join(id);
    std::fs::create_dir_all(&dir).map_err(|e| ModelError::Io(e.to_string()))?;
    let current = resolve(&s);
    for (role, opts) in &s.roles {
        if current.found_paths.contains_key(role) {
            continue;
        }
        let primary = opts.first().ok_or_else(|| ModelError::Unknown(id.into()))?;
        let dest = dir.join(primary.filename);
        if dest.is_file() {
            continue;
        }
        on_progress(&format!("downloading {} ...", primary.filename));
        download_file(&primary.url, &dest, primary.sha256)?;
        on_progress(&format!("saved {}", dest.display()));
    }
    let _ = probe_and_save_config();
    Ok(dir)
}

fn download_file(url: &str, dest: &Path, sha256: &str) -> Result<(), ModelError> {
    let part = dest.with_extension("part");
    let resp = ureq::get(url)
        .call()
        .map_err(|e| ModelError::Download(url.into(), e.to_string()))?;
    let mut out = std::fs::File::create(&part).map_err(|e| ModelError::Io(e.to_string()))?;
    std::io::copy(&mut resp.into_reader(), &mut out).map_err(|e| ModelError::Io(e.to_string()))?;
    drop(out);
    if !sha256.trim().is_empty() {
        let bytes = std::fs::read(&part).map_err(|e| ModelError::Io(e.to_string()))?;
        let sum = sha2::Sha256::digest(&bytes);
        if hex::encode(sum).to_lowercase() != sha256.to_lowercase() {
            let _ = std::fs::remove_file(&part);
            return Err(ModelError::Checksum(dest.display().to_string()));
        }
    }
    std::fs::rename(&part, dest).map_err(|e| ModelError::Io(e.to_string()))?;
    Ok(())
}
