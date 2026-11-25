//! Text clipboard access for normal logged-in sessions.
//!
//! Clipboard ownership is inherently session-scoped. This adapter is
//! deliberately separate from the privileged input injector: a system daemon
//! at a greeter may create `/dev/uinput`, but it must not pretend that it can
//! read or modify an arbitrary user's clipboard.

use crate::PlatformError;
use std::time::Duration;

/// Cross-platform text clipboard handle. The daemon's user-session agent
/// polls this handle and updates it when a negotiated peer sends new text.
pub struct SystemClipboard {
    clipboard: arboard::Clipboard,
    last_text: Option<String>,
    last_image_hash: Option<(usize, usize, u64)>,
    /// Owner-change events still owed to our own `set_text` /
    /// `set_image_data`. Those writes wake the OS watcher; absorbing
    /// them here is what stops a peer paste from being offered back.
    /// A later real copy, even of the same bytes, still emits.
    ignore_owner_events: u8,
    // Text/image live next to this handle; the file list (CB-04) is the
    // separate fingerprint below. The last observed file list (echo guard).
    last_files_fingerprint: Option<Vec<(String, u64)>>,
    /// CB-01: false until the first successful observation of either
    /// flavor. The first sighting is a baseline only, never emitted.
    observed_any: bool,
}

impl SystemClipboard {
    pub fn create() -> Result<Self, PlatformError> {
        let clipboard = arboard::Clipboard::new()
            .map_err(|error| PlatformError::Clipboard(format!("open system clipboard: {error}")))?;
        Ok(Self {
            clipboard,
            last_text: None,
            last_image_hash: None,
            last_files_fingerprint: None,
            ignore_owner_events: 0,
            observed_any: false,
        })
    }

    /// True when this handle already remembers `text` (no OS read).
    pub fn same_text(&self, text: &str) -> bool {
        self.last_text.as_deref() == Some(text)
    }

    /// True when this handle already remembers these pixels (no OS read).
    pub fn same_image(&self, width: usize, height: usize, rgba: &[u8]) -> bool {
        self.last_image_hash == Some(Self::image_fingerprint(width, height, rgba))
    }

    /// Consume one owner-change that our own write is about to generate.
    fn absorb_own_owner_event(&mut self, ownership_changed: bool) -> bool {
        if ownership_changed && self.ignore_owner_events > 0 {
            self.ignore_owner_events -= 1;
            true
        } else {
            false
        }
    }

    /// Like [`poll_changed`], but a real ownership change emits the
    /// current text even when it equals the last paste. That is a user
    /// re-copy; equality suppression would swallow it. `ownership_changed`
    /// is the OS watcher's notice. Our own `set_text` arms a short ignore
    /// so the notice it generates is not offered back to the peer.
    /// CB-01 activation: the FIRST observation after the agent starts is a
    /// baseline only, never an emitted change. Whatever was on the
    /// clipboard before the link existed must not sync on connect —
    /// sync begins with the first user copy made after that.
    pub fn poll_user_text(
        &mut self,
        ownership_changed: bool,
    ) -> Result<Option<String>, PlatformError> {
        if self.absorb_own_owner_event(ownership_changed) {
            if let Ok(text) = self.clipboard.get_text() {
                self.last_text = Some(text);
                self.last_image_hash = None;
                self.observed_any = true;
            }
            return Ok(None);
        }
        let text = match self.clipboard.get_text() {
            Ok(text) => text,
            Err(_) => return Ok(None),
        };
        // Unseen-before baseline: record it, emit nothing (CB-01). Only the
        // very first sighting baselines; a later copy of a different flavor
        // must still emit (CB-02), so the flag is shared, not per-flavor.
        if !self.observed_any {
            self.observed_any = true;
            self.last_text = Some(text);
            self.last_image_hash = None;
            return Ok(None);
        }
        let same = self.last_text.as_deref() == Some(text.as_str());
        if same {
            return Ok(None);
        }
        self.last_text = Some(text.clone());
        self.last_image_hash = None;
        Ok(Some(text))
    }

    /// Image half of [`poll_user_text`].
    /// CB-01 activation: like the text half, the first image sighting is a
    /// baseline only — a screenshot copied before the link existed must
    /// not sync on connect.
    pub fn poll_user_image(
        &mut self,
        ownership_changed: bool,
    ) -> Result<Option<(usize, usize, Vec<u8>)>, PlatformError> {
        if self.absorb_own_owner_event(ownership_changed) {
            if let Ok(image) = self.clipboard.get_image() {
                let rgba = image.bytes.to_vec();
                self.last_image_hash =
                    Some(Self::image_fingerprint(image.width, image.height, &rgba));
                self.last_text = None;
                self.observed_any = true;
            }
            return Ok(None);
        }
        let image = match self.clipboard.get_image() {
            Ok(image) => image,
            Err(_) => return Ok(None),
        };
        let rgba = image.bytes.to_vec();
        let fingerprint = Self::image_fingerprint(image.width, image.height, &rgba);
        if !self.observed_any {
            // First sighting of any flavor: baseline only (CB-01).
            self.observed_any = true;
            self.last_image_hash = Some(fingerprint);
            return Ok(None);
        }
        let same = self.last_image_hash == Some(fingerprint);
        if same {
            return Ok(None);
        }
        self.last_image_hash = Some(fingerprint);
        self.last_text = None;
        Ok(Some((image.width, image.height, rgba)))
    }

    /// Cheap fingerprint for image dedup: dimensions plus a hash of the
    /// raw pixels. Full multi-megabyte compares on every poll would
    /// stall the agent thread; a hash collision merely re-sends one
    /// paste, never corrupts one.
    fn image_fingerprint(width: usize, height: usize, rgba: &[u8]) -> (usize, usize, u64) {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        rgba.hash(&mut hasher);
        (width, height, hasher.finish())
    }

    /// Return the current text once when it differs from the last observed
    /// value. A clipboard containing only an image or another non-text format
    /// is ignored; it is not an error for synchronization purposes.
    pub fn poll_changed(&mut self) -> Result<Option<String>, PlatformError> {
        let text = match self.clipboard.get_text() {
            Ok(text) => text,
            Err(_) => return Ok(None),
        };
        if self.last_text.as_deref() == Some(text.as_str()) {
            return Ok(None);
        }
        self.last_text = Some(text.clone());
        // The clipboard now holds text: a re-copied older image must
        // fire again instead of matching a stale image fingerprint.
        self.last_image_hash = None;
        self.observed_any = true;
        Ok(Some(text))
    }

    /// Return the current image once when it differs from the last
    /// observed value: dimensions plus raw RGBA pixels. Text coexistence
    /// is OS-defined (most clipboards hold one flavor at a time); a
    /// text-only clipboard is ignored here, never an error.
    pub fn poll_changed_image(&mut self) -> Result<Option<(usize, usize, Vec<u8>)>, PlatformError> {
        let image = match self.clipboard.get_image() {
            Ok(image) => image,
            Err(_) => return Ok(None),
        };
        let rgba = image.bytes.to_vec();
        let fingerprint = Self::image_fingerprint(image.width, image.height, &rgba);
        if self.last_image_hash == Some(fingerprint) {
            return Ok(None);
        }
        self.last_image_hash = Some(fingerprint);
        // The clipboard now holds an image: a re-copied older text must
        // fire again instead of matching stale text.
        self.last_text = None;
        Ok(Some((image.width, image.height, rgba)))
    }

    /// Set text received from a peer and remember it as locally observed so
    /// the polling loop does not immediately echo it back.
    pub fn set_text(&mut self, text: String) -> Result<(), PlatformError> {
        self.last_text = Some(text.clone());
        self.last_image_hash = None;
        self.observed_any = true;
        self.ignore_owner_events = 4;
        let mut last_err = None;
        for attempt in 0..4 {
            match self.clipboard.set_text(text.clone()) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last_err = Some(error);
                    if attempt < 3 {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
        Err(PlatformError::Clipboard(format!(
            "set system clipboard: {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )))
    }

    /// Set image pixels received from a peer (decoded RGBA) and remember
    /// them as locally observed so the polling loop does not immediately
    /// echo the paste back.
    pub fn set_image_data(
        &mut self,
        width: usize,
        height: usize,
        rgba: Vec<u8>,
    ) -> Result<(), PlatformError> {
        if rgba.len() != width.saturating_mul(height).saturating_mul(4) {
            return Err(PlatformError::Clipboard(
                "peer image pixels do not match their dimensions".into(),
            ));
        }
        self.last_image_hash = Some(Self::image_fingerprint(width, height, &rgba));
        self.last_text = None;
        self.observed_any = true;
        self.ignore_owner_events = 4;
        let mut last_err = None;
        for attempt in 0..4 {
            match self.clipboard.set_image(arboard::ImageData {
                width,
                height,
                bytes: std::borrow::Cow::Borrowed(&rgba),
            }) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last_err = Some(error);
                    if attempt < 3 {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
        Err(PlatformError::Clipboard(format!(
            "set system clipboard image: {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )))
    }
}

/// A file-list clipboard paste (CB-04): one entry per file, basename plus
/// decoded bytes. The wire never carries a past the link cap; the agent
/// stats sizes first and refuses over-limit lists before ever loading
/// bytes (CB-08), so this struct is small by construction.
pub struct ClipboardFilesPaste {
    pub files: Vec<(String, Vec<u8>)>,
}

/// Sum of regular-file lengths (directories and missing files count 0).
/// Saturating: a hostile file list cannot overflow the total.
pub fn file_list_total_bytes(paths: &[std::path::PathBuf]) -> u64 {
    paths
        .iter()
        .map(|path| std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0))
        .fold(0u64, |acc, len| acc.saturating_add(len))
}

/// Load one file list's bytes (caller caps the aggregate first, and the
/// wire validator re-caps it on the far side). Directories are refused:
/// a folder copy degenerates to the paste-path adaptation (CB-11), never
/// to a silent recursive archive.
pub fn load_file_list(paths: &[std::path::PathBuf]) -> Result<Vec<(String, Vec<u8>)>, PlatformError> {
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let meta = std::fs::metadata(path)
            .map_err(|error| PlatformError::Clipboard(format!("stat copied file: {error}")))?;
        if !meta.is_file() {
            return Err(PlatformError::Clipboard(
                "copied path is not a regular file".into(),
            ));
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
            .to_owned();
        let bytes = std::fs::read(path).map_err(|error| {
            PlatformError::Clipboard(format!("read copied file {name}: {error}"))
        })?;
        files.push((name, bytes));
    }
    Ok(files)
}

impl SystemClipboard {
    /// Read the OS file list when it changed since the last sighting. The
    /// first sighting after creation is a baseline only (CB-01): whatever
    /// was copied before the link existed never syncs on connect. Applying
    /// a peer list first (see [`SystemClipboard::set_files`]) arms the
    /// echo guard so the peer paste is never offered back (CB-06).
    pub fn poll_user_files(
        &mut self,
        ownership_changed: bool,
    ) -> Result<Option<Vec<std::path::PathBuf>>, PlatformError> {
        if self.absorb_own_owner_event(ownership_changed) {
            if let Some(paths) = read_file_list_os() {
                self.last_files_fingerprint = Some(files_fingerprint(&paths));
            }
            return Ok(None);
        }
        let paths = match read_file_list_os() {
            Some(paths) if !paths.is_empty() => paths,
            _ => return Ok(None),
        };
        let fingerprint = files_fingerprint(&paths);
        if !self.observed_any {
            self.observed_any = true;
            self.last_files_fingerprint = Some(fingerprint);
            return Ok(None);
        }
        if self.last_files_fingerprint.as_ref() == Some(&fingerprint) {
            return Ok(None);
        }
        self.last_files_fingerprint = Some(fingerprint);
        Ok(Some(paths))
    }

    /// Offer a locally staged file list to the OS clipboard so the user
    /// can paste it into a file manager (CB-04). The caller materialized
    /// the bytes first; this only publishes the paths.
    pub fn set_files(&mut self, paths: &[std::path::PathBuf]) -> Result<(), PlatformError> {
        if paths.is_empty() {
            return Err(PlatformError::Clipboard("no files to offer".into()));
        }
        self.last_files_fingerprint = Some(files_fingerprint(paths));
        self.observed_any = true;
        self.ignore_owner_events = 4;
        set_file_list_os(paths)
    }
}

/// Order-sensitive fingerprint of one sighting: file paths with sizes,
/// so replacing a file in place still counts as a new copy.
fn files_fingerprint(paths: &[std::path::PathBuf]) -> Vec<(String, u64)> {
    paths
        .iter()
        .map(|path| {
            (
                path.to_string_lossy().into_owned(),
                std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0),
            )
        })
        .collect()
}

/// Percent-encode one filesystem path into a file:// URI body (the part
/// after `file://`), per RFC 8089: unreserved bytes pass through.
fn file_uri_encode(path: &std::path::Path) -> String {
    let mut out = String::with_capacity(path.as_os_str().len() + 8);
    for &b in path.as_os_str().as_encoded_bytes() {
        match char::from(b) {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' | '/' | ':' => {
                out.push(char::from(b))
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode one file:// URI back into a path (percent-decode the UTF-8
/// path bytes; malformed escapes fail closed to None).
fn file_uri_decode(uri: &str) -> Option<std::path::PathBuf> {
    let bytes = uri.as_bytes();
    let mut raw = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            let byte = u8::from_str_radix(hex, 16).ok()?;
            raw.push(byte);
            index += 3;
        } else {
            raw.push(bytes[index]);
            index += 1;
        }
    }
    let text = String::from_utf8(raw).ok()?;
    Some(std::path::PathBuf::from(text))
}

#[cfg(target_os = "windows")]
fn read_file_list_os() -> Option<Vec<std::path::PathBuf>> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows::Win32::UI::Shell::{DragQueryFileW, HDROP};
    // CF_HDROP is clipboard format 15; the windows crate does not always
    // surface the named constant, so the numeric value is used.
    const CF_HDROP: u32 = 15;
    unsafe {
        if OpenClipboard(HWND(std::ptr::null_mut())).is_err() {
            return None;
        }
        let mut paths = Vec::new();
        if let Ok(handle) = GetClipboardData(CF_HDROP) {
            let hdrop = HDROP(handle.0);
            let count = DragQueryFileW(hdrop, u32::MAX, None);
            for index in 0..count {
                let len = DragQueryFileW(hdrop, index, None);
                if len == 0 {
                    continue;
                }
                let mut buffer = vec![0u16; (len + 1) as usize];
                let got = DragQueryFileW(hdrop, index, Some(&mut buffer[..]));
                if got == 0 {
                    continue;
                }
                let name = String::from_utf16_lossy(&buffer[..got as usize]);
                paths.push(std::path::PathBuf::from(name));
            }
        }
        let _ = CloseClipboard();
        if paths.is_empty() {
            None
        } else {
            Some(paths)
        }
    }
}

#[cfg(target_os = "windows")]
fn set_file_list_os(paths: &[std::path::PathBuf]) -> Result<(), PlatformError> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    // CF_HDROP (see the reader above).
    const CF_HDROP: u32 = 15;

    #[repr(C)]
    struct DropFiles {
        p_files: u32,
        x: i32,
        y: i32,
        f_nc: u32,
        f_wide: u32,
    }
    let wide: Vec<u16> = paths
        .iter()
        .flat_map(|path| {
            path.to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        })
        .chain(std::iter::once(0))
        .collect();
    let header = std::mem::size_of::<DropFiles>();
    let total = header + wide.len() * std::mem::size_of::<u16>();
    unsafe {
        let memory = GlobalAlloc(GMEM_MOVEABLE, total).map_err(|error| {
            PlatformError::Clipboard(format!("allocate file clipboard: {error}"))
        })?;
        let ptr = GlobalLock(memory);
        if ptr.is_null() {
            return Err(PlatformError::Clipboard(
                "lock file clipboard".into(),
            ));
        }
        let drop = DropFiles {
            p_files: header as u32,
            x: 0,
            y: 0,
            f_nc: 0,
            f_wide: 1,
        };
        std::ptr::copy_nonoverlapping(
            &drop as *const DropFiles as *const u8,
            ptr as *mut u8,
            header,
        );
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            ptr.add(header) as *mut u16,
            wide.len(),
        );
        let _ = GlobalUnlock(memory);
        if OpenClipboard(HWND(std::ptr::null_mut())).is_err() {
            return Err(PlatformError::Clipboard("open clipboard for file paste".into()));
        }
        let _ = EmptyClipboard();
        let offered = SetClipboardData(CF_HDROP, windows::Win32::Foundation::HANDLE(memory.0));
        let _ = CloseClipboard();
        if offered.is_err() {
            return Err(PlatformError::Clipboard("offer files to OS clipboard".into()));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_file_list_os() -> Option<Vec<std::path::PathBuf>> {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::ConnectionExt as _;
    if std::env::var_os("DISPLAY").is_none() {
        return None;
    }
    let (connection, screen) = x11rb::connect(None).ok()?;
    // Two-step request/reply (the repo's established pattern for this
    // x11rb Connection flavour): cookie first, then the reply.
    let intern = |name: &[u8]| -> Option<u32> {
        let cookie = connection.intern_atom(false, name).ok()?;
        let reply = cookie.reply().ok()?;
        Some(reply.atom)
    };
    let clipboard = intern(b"CLIPBOARD")?;
    let uri_list = intern(b"text/uri-list")?;
    let owner = connection.get_selection_owner(clipboard).ok()?.reply().ok()?.owner;
    if owner == 0 {
        return None;
    }
    let root = connection.setup().roots.get(screen)?.root;
    let window = connection.generate_id().ok()?;
    let property = connection.generate_id().ok()?;
    connection
        .create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            window,
            root,
            0,
            0,
            1,
            1,
            0,
            x11rb::protocol::xproto::WindowClass::INPUT_ONLY,
            x11rb::COPY_FROM_PARENT,
            &x11rb::protocol::xproto::CreateWindowAux::new(),
        )
        .ok()?
        .check()
        .ok()?;
    connection
        .convert_selection(window, clipboard, uri_list, property, x11rb::CURRENT_TIME)
        .ok()?
        .check()
        .ok()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut converted = false;
    while std::time::Instant::now() < deadline {
        match connection.poll_for_event() {
            Ok(Some(x11rb::protocol::Event::SelectionNotify(event)))
                if event.requestor == window && event.property == property =>
            {
                converted = event.selection == clipboard;
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => break,
        }
    }
    if !converted {
        return None;
    }
    let reply = connection
        .get_property(false, window, property, x11rb::NONE, 0, 65536)
        .ok()?
        .reply()
        .ok()?;
    if reply.format != 8 {
        return None;
    }
    let bytes: Vec<u8> = reply.value;
    let text = String::from_utf8_lossy(&bytes);
    let mut paths = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("file://") {
            if let Some(path) = file_uri_decode(rest) {
                paths.push(path);
            }
        }
    }
    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

static FILES_OWNER_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Publish `paths` as the X11 CLIPBOARD selection (text/uri-list). The
/// selection owner must keep serving pastes until another app takes
/// ownership, so this spawns a dedicated thread per apply; the previous
/// owner hears SelectionClear and exits, and a generation counter makes
/// superseded owners exit too (CB-11 documented adaptation).
#[cfg(target_os = "linux")]
fn set_file_list_os(paths: &[std::path::PathBuf]) -> Result<(), PlatformError> {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::ConnectionExt as _;
    if std::env::var_os("DISPLAY").is_none() {
        return Err(PlatformError::Clipboard(
            "no X display for file clipboard".into(),
        ));
    }
    let generation = FILES_OWNER_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let paths = paths.to_vec();
    std::thread::Builder::new()
        .name("thekvm-clipboard-file-owner".into())
        .spawn(move || {
            let _ = serve_file_selection(paths, generation);
        })
        .map_err(|error| {
            PlatformError::Clipboard(format!("spawn file clipboard owner: {error}"))
        })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn serve_file_selection(paths: Vec<std::path::PathBuf>, generation: u64) -> Result<(), PlatformError> {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::ConnectionExt as _;
    let (connection, screen) = x11rb::connect(None).map_err(|error| {
        PlatformError::Clipboard(format!("open X connection for file clipboard: {error}"))
    })?;
    let intern = |name: &[u8]| -> Result<u32, PlatformError> {
        let cookie = connection
            .intern_atom(false, name)
            .map_err(|error| PlatformError::Clipboard(format!("intern atom: {error}")))?;
        let reply = cookie
            .reply()
            .map_err(|error| PlatformError::Clipboard(format!("intern atom: {error}")))?;
        Ok(reply.atom)
    };
    let clipboard = intern(b"CLIPBOARD")?;
    let uri_list = intern(b"text/uri-list")?;
    let utf8_string = intern(b"UTF8_STRING")?;
    let targets = intern(b"TARGETS")?;
    let timestamp_atom = intern(b"TIMESTAMP")?;
    let root = connection
        .setup()
        .roots
        .get(screen)
        .ok_or_else(|| PlatformError::Clipboard("no X screen for file clipboard".into()))?
        .root;
    let window = connection
        .generate_id()
        .map_err(|error| PlatformError::Clipboard(format!("allocate file window: {error}")))?;
    connection
        .create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            window,
            root,
            0,
            0,
            1,
            1,
            0,
            x11rb::protocol::xproto::WindowClass::INPUT_ONLY,
            x11rb::COPY_FROM_PARENT,
            &x11rb::protocol::xproto::CreateWindowAux::new(),
        )
        .map_err(|error| PlatformError::Clipboard(format!("create file window: {error}")))?
        .check()
        .map_err(|error| PlatformError::Clipboard(format!("create file window: {error}")))?;
    connection
        .set_selection_owner(window, clipboard, x11rb::CURRENT_TIME)
        .map_err(|error| PlatformError::Clipboard(format!("own file clipboard: {error}")))?
        .check()
        .map_err(|error| PlatformError::Clipboard(format!("own file clipboard: {error}")))?;
    let uri_payload: Vec<u8> = paths
        .iter()
        .map(|path| format!("file://{}\r\n", file_uri_encode(path)))
        .collect::<String>()
        .into_bytes();
    use x11rb::protocol::xproto::{
        EventMask, SelectionNotifyEvent, SELECTION_NOTIFY_EVENT,
    };
    fn send_selection_notify(
        connection: &x11rb::rust_connection::RustConnection,
        requestor: u32,
        event: &x11rb::protocol::xproto::SelectionRequestEvent,
    ) {
        use x11rb::connection::Connection;
        let notify = SelectionNotifyEvent {
            response_type: SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: event.time,
            requestor,
            selection: event.selection,
            target: event.target,
            property: event.property,
        };
        let raw: [u8; 32] = notify.into();
        let _ = connection
            .send_event(false, requestor, EventMask::NO_EVENT, raw);
    }
    fn send_selection_notify_fail(
        connection: &x11rb::rust_connection::RustConnection,
        requestor: u32,
        event: &x11rb::protocol::xproto::SelectionRequestEvent,
    ) {
        use x11rb::connection::Connection;
        let raw: [u8; 32] = SelectionNotifyEvent {
            response_type: SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: event.time,
            requestor,
            selection: event.selection,
            target: event.target,
            property: 0,
        }
        .into();
        let _ = connection
            .send_event(false, requestor, EventMask::NO_EVENT, raw);
    }
    loop {
        if generation != FILES_OWNER_GENERATION.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let event = connection
            .wait_for_event()
            .map_err(|error| PlatformError::Clipboard(format!("file clipboard events: {error}")))?;
        match event {
            x11rb::protocol::Event::SelectionRequest(event) => {
                use x11rb::protocol::xproto::{EventMask, PropMode, SelectionNotifyEvent};
                let ok = event.target == uri_list || event.target == utf8_string;
                if event.target == targets {
                    let list = [targets, uri_list, utf8_string, timestamp_atom];
                    let bytes: Vec<u8> = list
                        .iter()
                        .flat_map(|atom| atom.to_le_bytes())
                        .collect();
                    let _ = connection.change_property(
                        PropMode::REPLACE,
                        event.requestor,
                        event.property,
                        4u32,
                        32,
                        list.len() as u32,
                        &bytes,
                    );
                    let _ = send_selection_notify(&connection, event.requestor, &event);
                } else if ok {
                    let _ = connection.change_property(
                        PropMode::REPLACE,
                        event.requestor,
                        event.property,
                        event.target,
                        8,
                        uri_payload.len() as u32,
                        &uri_payload,
                    );
                    let _ = send_selection_notify(&connection, event.requestor, &event);
                } else {
                    let _ = send_selection_notify_fail(&connection, event.requestor, &event);
                }
                let _ = connection.flush();
            }
            x11rb::protocol::Event::SelectionClear(event) => {
                if event.selection == clipboard {
                    break;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn read_file_list_os() -> Option<Vec<std::path::PathBuf>> {
    None
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn set_file_list_os(_paths: &[std::path::PathBuf]) -> Result<(), PlatformError> {
    Err(PlatformError::Clipboard(
        "file clipboard unsupported on this OS".into(),
    ))
}

/// Largest image dimension the clipboard path accepts, in pixels per
/// side. Matches the wire validator so the OS touch never attempts a
/// paste the validator would have refused on the wire.
pub const MAX_CLIPBOARD_IMAGE_DIM: usize = 16384;

/// Encode raw RGBA pixels as a PNG (the clipboard wire format: JSON
/// carries only UTF-8, so these bytes travel base64). Always RGBA8 —
/// the decoder below accepts exactly what this produces.
pub fn encode_image_png(
    width: usize,
    height: usize,
    rgba: &[u8],
) -> Result<Vec<u8>, PlatformError> {
    if width == 0
        || height == 0
        || width > MAX_CLIPBOARD_IMAGE_DIM
        || height > MAX_CLIPBOARD_IMAGE_DIM
    {
        return Err(PlatformError::Clipboard(
            "clipboard image dimensions are empty or exceed maximum size".into(),
        ));
    }
    if rgba.len() != width.saturating_mul(height).saturating_mul(4) {
        return Err(PlatformError::Clipboard(
            "clipboard image pixels do not match their dimensions".into(),
        ));
    }
    let mut encoded = Vec::new();
    let mut encoder = png::Encoder::new(&mut encoded, width as u32, height as u32);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder
        .write_header()
        .map_err(|error| PlatformError::Clipboard(format!("encode clipboard PNG: {error}")))?;
    writer
        .write_image_data(rgba)
        .map_err(|error| PlatformError::Clipboard(format!("encode clipboard PNG: {error}")))?;
    drop(writer);
    Ok(encoded)
}

/// PNG bytes, base64-encoded, ready for a clipboard offer or wire frame.
pub fn encode_image_png_base64(
    width: usize,
    height: usize,
    rgba: &[u8],
) -> Result<String, PlatformError> {
    let png = encode_image_png(width, height, rgba)?;
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::STANDARD.encode(png))
}

/// Decode a wire image paste (base64 PNG, exactly what the agent's
/// encode path produces) back to dimensions plus raw RGBA pixels for
/// [`SystemClipboard::set_image_data`]. The UI relay's single decode
/// step: base64 and PNG failures both surface as clipboard errors.
pub fn decode_base64_png(encoded: &str) -> Result<(usize, usize, Vec<u8>), PlatformError> {
    use base64::Engine as _;
    let png_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|error| {
            PlatformError::Clipboard(format!("decode clipboard image text: {error}"))
        })?;
    decode_image_png(&png_bytes)
}

/// Decode a clipboard PNG (exactly what [`encode_image_png`] produces)
/// back to dimensions plus raw RGBA pixels. Foreign PNG flavors never
/// reach here — the OS hands us RGBA via arboard, and only our own
/// encoder output travels the wire — so non-RGBA8 input is refused
/// instead of expensively converted.
pub fn decode_image_png(png_bytes: &[u8]) -> Result<(usize, usize, Vec<u8>), PlatformError> {
    let decoder = png::Decoder::new(png_bytes);
    let mut reader = decoder
        .read_info()
        .map_err(|error| PlatformError::Clipboard(format!("decode clipboard PNG: {error}")))?;
    // Copy the header out before the frame read: the reader borrows the
    // info, so the dims check must not hold it across next_frame.
    let (width, height, color_type, bit_depth) = {
        let info = reader.info();
        (info.width, info.height, info.color_type, info.bit_depth)
    };
    if color_type != png::ColorType::Rgba || bit_depth != png::BitDepth::Eight {
        return Err(PlatformError::Clipboard(
            "clipboard PNG is not 8-bit RGBA".into(),
        ));
    }
    if width == 0
        || height == 0
        || width > MAX_CLIPBOARD_IMAGE_DIM as u32
        || height > MAX_CLIPBOARD_IMAGE_DIM as u32
    {
        return Err(PlatformError::Clipboard(
            "clipboard image dimensions are empty or exceed maximum size".into(),
        ));
    }
    let mut pixels = vec![0u8; reader.output_buffer_size()];
    let frame = reader
        .next_frame(&mut pixels)
        .map_err(|error| PlatformError::Clipboard(format!("decode clipboard PNG: {error}")))?;
    pixels.truncate(frame.buffer_size());
    Ok((width as usize, height as usize, pixels))
}

/// Deep-OS clipboard change notifier: the OS wakes the agent the moment
/// the user copies, instead of the agent discovering it on the next timed
/// poll. Linux watches XFixes selection-owner events; Windows listens for
/// `WM_CLIPBOARDUPDATE`. Where the OS cannot deliver events here (headless
/// service, unsupported compositor), `create` fails and the caller keeps
/// the timed poll — events are a latency fast path, never a dependency.
#[cfg(target_os = "linux")]
pub struct ClipboardWatcher {
    connection: x11rb::rust_connection::RustConnection,
    clipboard: u32,
}

#[cfg(target_os = "linux")]
impl ClipboardWatcher {
    pub fn create() -> Result<Self, PlatformError> {
        use x11rb::connection::Connection;
        use x11rb::protocol::xfixes::ConnectionExt as _;
        use x11rb::protocol::xproto::ConnectionExt as _;
        if std::env::var_os("DISPLAY").is_none() {
            return Err(PlatformError::Clipboard(
                "no X display for clipboard change events".into(),
            ));
        }
        let (connection, screen) = x11rb::connect(None).map_err(|error| {
            PlatformError::Clipboard(format!("open X connection for clipboard events: {error}"))
        })?;
        connection
            .xfixes_query_version(5, 0)
            .map_err(|error| PlatformError::Clipboard(format!("XFixes unavailable: {error}")))?
            .reply()
            .map_err(|error| PlatformError::Clipboard(format!("XFixes unavailable: {error}")))?;
        let clipboard = connection
            .intern_atom(false, b"CLIPBOARD")
            .map_err(|error| PlatformError::Clipboard(format!("intern CLIPBOARD atom: {error}")))?
            .reply()
            .map_err(|error| PlatformError::Clipboard(format!("intern CLIPBOARD atom: {error}")))?
            .atom;
        let root = connection
            .setup()
            .roots
            .get(screen)
            .ok_or_else(|| PlatformError::Clipboard("no X screen for clipboard events".into()))?
            .root;
        // Unmapped 1x1 input-only window: exists only to receive the
        // XFixes events, never visible, never focusable.
        let window = connection.generate_id().map_err(|error| {
            PlatformError::Clipboard(format!("allocate clipboard event window: {error}"))
        })?;
        connection
            .create_window(
                x11rb::COPY_DEPTH_FROM_PARENT,
                window,
                root,
                0,
                0,
                1,
                1,
                0,
                x11rb::protocol::xproto::WindowClass::INPUT_ONLY,
                x11rb::COPY_FROM_PARENT,
                &x11rb::protocol::xproto::CreateWindowAux::new(),
            )
            .map_err(|error| {
                PlatformError::Clipboard(format!("create clipboard event window: {error}"))
            })?
            .check()
            .map_err(|error| {
                PlatformError::Clipboard(format!("create clipboard event window: {error}"))
            })?;
        connection
            .xfixes_select_selection_input(
                window,
                clipboard,
                x11rb::protocol::xfixes::SelectionEventMask::SET_SELECTION_OWNER,
            )
            .map_err(|error| {
                PlatformError::Clipboard(format!("subscribe to clipboard ownership: {error}"))
            })?
            .check()
            .map_err(|error| {
                PlatformError::Clipboard(format!("subscribe to clipboard ownership: {error}"))
            })?;
        Ok(Self {
            connection,
            clipboard,
        })
    }

    /// Block up to `timeout` for an ownership change of the CLIPBOARD
    /// selection. True means "re-read now"; false is just the timeout —
    /// the caller still does its safety re-read.
    pub fn wait_notice(&self, timeout: Duration) -> bool {
        use std::os::fd::AsRawFd;
        use x11rb::connection::Connection;
        use x11rb::protocol::Event;
        let deadline = std::time::Instant::now() + timeout;
        let mut notified = false;
        loop {
            loop {
                match self.connection.poll_for_event() {
                    Ok(Some(Event::XfixesSelectionNotify(event)))
                        if event.selection == self.clipboard =>
                    {
                        notified = true;
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => return notified,
                }
            }
            if notified {
                return true;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let mut pfd = libc::pollfd {
                fd: self.connection.stream().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let wait_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            let rc = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
            if rc <= 0 {
                return false;
            }
        }
    }
}

/// Deep-OS clipboard change notifier (Windows): a message-only window
/// with `AddClipboardFormatListener` turns every user copy into a
/// `WM_CLIPBOARDUPDATE` within milliseconds.
#[cfg(target_os = "windows")]
pub struct ClipboardWatcher {
    hwnd: windows::Win32::Foundation::HWND,
}

#[cfg(target_os = "windows")]
static CLIPBOARD_NOTIFIED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "windows")]
unsafe extern "system" fn clipboard_watcher_proc(
    hwnd: windows::Win32::Foundation::HWND,
    message: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::UI::WindowsAndMessaging::{DefWindowProcW, WM_CLIPBOARDUPDATE};
    if message == WM_CLIPBOARDUPDATE {
        CLIPBOARD_NOTIFIED.store(true, std::sync::atomic::Ordering::Release);
        return windows::Win32::Foundation::LRESULT(0);
    }
    DefWindowProcW(hwnd, message, wparam, lparam)
}

#[cfg(target_os = "windows")]
impl ClipboardWatcher {
    pub fn create() -> Result<Self, PlatformError> {
        use windows::core::PCWSTR;
        use windows::Win32::System::DataExchange::AddClipboardFormatListener;
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, RegisterClassW, HMENU, HWND_MESSAGE, WINDOW_EX_STYLE, WINDOW_STYLE,
            WNDCLASSW,
        };

        unsafe {
            let instance = GetModuleHandleW(None).map_err(|error| {
                PlatformError::Clipboard(format!("clipboard listener module: {error}"))
            })?;
            let class_name: Vec<u16> = "TheKVMClipboardWatch\0".encode_utf16().collect();
            let wc = WNDCLASSW {
                lpfnWndProc: Some(clipboard_watcher_proc),
                hInstance: instance.into(),
                lpszClassName: PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };
            // A repeat agent in this process finds the class already
            // registered: that is fine, creation below still works.
            let _ = RegisterClassW(&wc);
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(class_name.as_ptr()),
                PCWSTR::null(),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                HMENU::default(),
                instance,
                None,
            )
            .map_err(|error| {
                PlatformError::Clipboard(format!("create clipboard listener window: {error}"))
            })?;
            AddClipboardFormatListener(hwnd).map_err(|error| {
                PlatformError::Clipboard(format!("listen for clipboard updates: {error}"))
            })?;
            CLIPBOARD_NOTIFIED.store(false, std::sync::atomic::Ordering::Release);
            Ok(Self { hwnd })
        }
    }

    /// Pump the listener's messages up to `timeout`. True means the OS
    /// reported a copy: re-read now. False is just the timeout.
    pub fn wait_notice(&self, timeout: Duration) -> bool {
        use windows::Win32::UI::WindowsAndMessaging::{
            DispatchMessageW, MsgWaitForMultipleObjectsEx, PeekMessageW, TranslateMessage, MSG,
            MWMO_INPUTAVAILABLE, PM_REMOVE, QS_ALLINPUT,
        };
        let deadline = std::time::Instant::now() + timeout;
        loop {
            unsafe {
                let mut message = MSG::default();
                while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
            if CLIPBOARD_NOTIFIED.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return true;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let wait_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
            unsafe {
                let _ = MsgWaitForMultipleObjectsEx(
                    None,
                    wait_ms,
                    QS_ALLINPUT,
                    MWMO_INPUTAVAILABLE,
                );
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for ClipboardWatcher {
    fn drop(&mut self) {
        use windows::Win32::System::DataExchange::RemoveClipboardFormatListener;
        use windows::Win32::UI::WindowsAndMessaging::DestroyWindow;
        unsafe {
            let _ = RemoveClipboardFormatListener(self.hwnd);
            let _ = DestroyWindow(self.hwnd);
        }
    }
}

/// Stub for platforms without an OS change feed: creation always fails
/// so the caller keeps the timed poll.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub struct ClipboardWatcher {
    _private: (),
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
impl ClipboardWatcher {
    pub fn create() -> Result<Self, PlatformError> {
        Err(PlatformError::Clipboard(
            "clipboard change events unsupported on this OS".into(),
        ))
    }

    pub fn wait_notice(&self, _timeout: Duration) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn file_uri_roundtrip_with_special_bytes() {
        let path = std::path::PathBuf::from("/tmp/some file #1 (copy).pdf");
        let encoded = super::file_uri_encode(&path);
        assert!(encoded.contains("%20"));
        assert!(encoded.contains("%23"));
        let decoded = super::file_uri_decode(&encoded).expect("decode");
        assert_eq!(decoded, path);
        // Malformed escapes fail closed.
        assert!(super::file_uri_decode("%zz").is_none());
        assert!(super::file_uri_decode("%1").is_none());
    }

    #[test]
    fn file_clipboard_total_bytes_saturates() {
        let paths = vec![std::path::PathBuf::from("/definitely/missing")];
        assert_eq!(super::file_list_total_bytes(&paths), 0);
    }

    #[test]
    fn clipboard_module_compiles_for_supported_platforms() {
        // The actual desktop clipboard requires a live user session and is
        // therefore covered by manual/platform acceptance tests.
        let _type_name = std::any::type_name::<super::SystemClipboard>();
    }

    #[test]
    fn png_helpers_roundtrip_rgba_exactly() {
        let (width, height) = (7, 5);
        let mut rgba = vec![0u8; width * height * 4];
        for (index, byte) in rgba.iter_mut().enumerate() {
            *byte = (index * 37) as u8;
        }
        let encoded = super::encode_image_png(width, height, &rgba).unwrap();
        // A real PNG, not a container rename: magic header first.
        assert!(encoded.starts_with(&[137, 80, 78, 71, 13, 10, 26, 10]));
        let (decoded_w, decoded_h, decoded) = super::decode_image_png(&encoded).unwrap();
        assert_eq!((decoded_w, decoded_h), (width, height));
        assert_eq!(decoded, rgba);
    }

    #[test]
    fn png_helpers_refuse_nonsense() {
        // Dimension/pixel mismatch.
        assert!(super::encode_image_png(2, 2, &[0u8; 15]).is_err());
        assert!(super::encode_image_png(0, 2, &[]).is_err());
        // Not a PNG at all.
        assert!(super::decode_image_png(b"definitely not a png").is_err());
        // Truncated PNG.
        let encoded = super::encode_image_png(3, 3, &[9u8; 3 * 3 * 4]).unwrap();
        assert!(super::decode_image_png(&encoded[..20]).is_err());
    }
}
