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
}

impl SystemClipboard {
    pub fn create() -> Result<Self, PlatformError> {
        let clipboard = arboard::Clipboard::new()
            .map_err(|error| PlatformError::Clipboard(format!("open system clipboard: {error}")))?;
        Ok(Self {
            clipboard,
            last_text: None,
            last_image_hash: None,
        })
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
        Ok(Some(text))
    }

    /// Return the current image once when it differs from the last
    /// observed value: dimensions plus raw RGBA pixels. Text coexistence
    /// is OS-defined (most clipboards hold one flavor at a time); a
    /// text-only clipboard is ignored here, never an error.
    pub fn poll_changed_image(
        &mut self,
    ) -> Result<Option<(usize, usize, Vec<u8>)>, PlatformError> {
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
        self.clipboard
            .set_text(text.clone())
            .map_err(|error| PlatformError::Clipboard(format!("set system clipboard: {error}")))?;
        self.last_text = Some(text);
        self.last_image_hash = None;
        Ok(())
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
        self.clipboard
            .set_image(arboard::ImageData {
                width,
                height,
                bytes: std::borrow::Cow::Owned(rgba),
            })
            .map_err(|error| {
                PlatformError::Clipboard(format!("set system clipboard image: {error}"))
            })?;
        Ok(())
    }
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
    let mut writer = encoder.write_header().map_err(|error| {
        PlatformError::Clipboard(format!("encode clipboard PNG: {error}"))
    })?;
    writer.write_image_data(rgba).map_err(|error| {
        PlatformError::Clipboard(format!("encode clipboard PNG: {error}"))
    })?;
    drop(writer);
    Ok(encoded)
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
    let mut reader = decoder.read_info().map_err(|error| {
        PlatformError::Clipboard(format!("decode clipboard PNG: {error}"))
    })?;
    // Copy the header out before the frame read: the reader borrows the
    // info, so the dims check must not hold it across next_frame.
    let (width, height, color_type, bit_depth) = {
        let info = reader.info();
        (
            info.width,
            info.height,
            info.color_type,
            info.bit_depth,
        )
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
    let frame = reader.next_frame(&mut pixels).map_err(|error| {
        PlatformError::Clipboard(format!("decode clipboard PNG: {error}"))
    })?;
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
        let window = connection
            .generate_id()
            .map_err(|error| {
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
        use x11rb::connection::Connection;
        use x11rb::protocol::Event;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match self.connection.poll_for_event() {
                Ok(Some(Event::XfixesSelectionNotify(event)))
                    if event.selection == self.clipboard =>
                {
                    return true
                }
                Ok(_) => {}
                Err(_) => return false,
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
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
        use windows::Win32::System::DataExchange::AddClipboardFormatListener;
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, RegisterClassW, HMENU, HWND_MESSAGE, WINDOW_EX_STYLE, WINDOW_STYLE,
            WNDCLASSW,
        };
        use windows::core::PCWSTR;

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
            DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
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
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
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
        let encoded =
            super::encode_image_png(3, 3, &vec![9u8; 3 * 3 * 4]).unwrap();
        assert!(super::decode_image_png(&encoded[..20]).is_err());
    }
}
