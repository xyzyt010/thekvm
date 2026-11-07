//! System tray icon with a right-click menu (Show, Disconnect, Open
//! logs, Quit).
//!
//! The window close button hides to the tray instead of exiting (see
//! main.rs `on_close_requested`); only the tray Quit fully terminates the
//! app: every link banned/notified, supervised children killed, the
//! UI-spawned user daemon killed, process exit. The installed system
//! service (thekvmd / TheKVM) is never touched — it belongs to the
//! machine, not the app.
//!
//! Platform event dispatch differs and is the whole point of this module:
//! libappindicator (Linux) dispatches menu-item activation INSIDE the
//! GTK/GLib main loop, so Linux must own the TrayIcon and iterate a real
//! GTK loop on one dedicated thread. The Win32 backend delivers clicks and
//! menu commands through the tray window's thread message queue, so
//! Windows pumps the Win32 message loop on that same dedicated thread.
//! Neither platform can rely on the Slint/winit main loop: its queue is a
//! different thread's.
//!
//! Menu events arrive on tray-icon's global receivers; both pumps forward
//! them to the UI over one channel drained by a watcher thread in main.rs,
//! so clicks act immediately instead of waiting for the 1s status poll.
//!
//! Dark menus (Windows): the popup menu is painted by comctl32, and left
//! alone it follows the LIGHT system theme — which clashed with the app's
//! dark window. The tray window is therefore subclassed here and every
//! menu row converted to owner-draw: `#121212` background, white text, a
//! slightly lighter row only under the cursor. Linux AppIndicator menus
//! follow the desktop theme (Mint dark = dark), so nothing is painted
//! there.

use std::sync::mpsc::{channel, Receiver, Sender};
use tray_icon::icon::Icon;
use tray_icon::menu::{menu_event_receiver, Menu, MenuItem};
use tray_icon::{tray_event_receiver, ClickEvent, TrayIcon, TrayIconBuilder};

/// Commands the tray thread delivers to the UI thread.
pub enum TrayCommand {
    Show,
    Disconnect,
    OpenLogs,
    Quit,
}

type MenuIds = (u32, u32, u32, u32);

/// Tray menu labels, in menu order (Windows owner-draw indexes into it).
#[cfg(target_os = "windows")]
const TRAY_LABELS: [&str; 4] = ["Show TheKVM", "Disconnect", "Open logs", "Quit TheKVM"];
/// Requested menu background: near-black charcoal.
#[cfg(target_os = "windows")]
const MENU_BG_RGB: u32 = 0x0012_1212;
/// Row highlight while the cursor is over an item.
#[cfg(target_os = "windows")]
const MENU_HIGHLIGHT_RGB: u32 = 0x0033_3333;
/// Menu item text colour.
#[cfg(target_os = "windows")]
const MENU_TEXT_RGB: u32 = 0x00ff_ffff;

/// Everything the pump needs, owned by the thread that built the tray so
/// the `!Send` TrayIcon never crosses threads.
struct TrayHandles {
    _tray: TrayIcon,
    show_id: u32,
    disconnect_id: u32,
    logs_id: u32,
    quit_id: u32,
}

impl TrayHandles {
    fn ids(&self) -> MenuIds {
        (self.show_id, self.disconnect_id, self.logs_id, self.quit_id)
    }
}

/// Build the tray icon + menu and pump its events on a dedicated thread.
/// Returns the command channel, or None when no system tray is available
/// (the app keeps working window-only). Never panics out of the UI: a
/// backend that cannot initialize (no GTK display, no watcher) degrades to
/// window-only instead of taking the whole UI down.
pub fn spawn_tray() -> Option<Receiver<TrayCommand>> {
    let (tx, rx) = channel::<TrayCommand>();

    // Linux: libappindicator's menu activation callbacks are dispatched by
    // the GTK main loop. Creating the tray without iterating that loop
    // leaves a visible but completely inert icon (Show/Disconnect/Quit
    // never arrive), which strands a close-to-tray app with no way back.
    #[cfg(target_os = "linux")]
    {
        std::thread::Builder::new()
            .name("thekvm-tray".into())
            .spawn(move || {
                // GTK must be initialized on, and pumped by, this thread;
                // no other thread touches it afterwards.
                if gtk::init().is_err() {
                    return;
                }
                let built = std::panic::catch_unwind(build_tray_handles);
                let Ok(Some(handles)) = built else {
                    return;
                };
                let (show_id, disconnect_id, logs_id, quit_id) = handles.ids();
                // The timeout runs inside the very loop that dispatches the
                // menu callbacks, so receiver events are always delivered.
                gtk::glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
                    match drain_events(show_id, disconnect_id, logs_id, quit_id, &tx) {
                        Ok(false) => gtk::glib::Continue(true),
                        Ok(true) | Err(()) => {
                            gtk::main_quit();
                            gtk::glib::Continue(false)
                        }
                    }
                });
                // Owned by this thread for the whole loop; dropping it would
                // remove the icon.
                let _handles = handles;
                gtk::main();
            })
            .ok()?;
    }

    // Windows delivers tray clicks and menu commands to the hidden tray
    // window's thread queue, so this thread must run the Win32 message
    // loop. Events reach tray-icon's receivers from inside that dispatch;
    // draining after each message forwards them to the UI immediately.
    #[cfg(target_os = "windows")]
    {
        std::thread::Builder::new()
            .name("thekvm-tray".into())
            .spawn(move || {
                let built = std::panic::catch_unwind(build_tray_handles);
                let Ok(Some(handles)) = built else {
                    return;
                };
                // Dark owner-draw menu must be installed before the first
                // right-click can show it.
                install_windows_dark_menu();
                let (show_id, disconnect_id, logs_id, quit_id) = handles.ids();
                let _handles = handles;
                let mut msg = windows::Win32::UI::WindowsAndMessaging::MSG::default();
                loop {
                    // Blocks until a tray/queue message arrives; zero CPU
                    // while idle. 0 = WM_QUIT, -1 = error.
                    let ret = unsafe {
                        windows::Win32::UI::WindowsAndMessaging::GetMessageW(&mut msg, None, 0, 0)
                    };
                    if ret.0 <= 0 {
                        return;
                    }
                    unsafe {
                        let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
                        windows::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
                    }
                    match drain_events(show_id, disconnect_id, logs_id, quit_id, &tx) {
                        Ok(false) => {}
                        Ok(true) | Err(()) => return,
                    }
                }
            })
            .ok()?;
    }

    // Other backends pump their own message loop; the icon can live on a
    // plain thread that only moves the global events.
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        std::thread::Builder::new()
            .name("thekvm-tray".into())
            .spawn(move || {
                let built = std::panic::catch_unwind(build_tray_handles);
                let Ok(Some(handles)) = built else {
                    return;
                };
                loop {
                    let (show_id, disconnect_id, logs_id, quit_id) = handles.ids();
                    match drain_events(show_id, disconnect_id, logs_id, quit_id, &tx) {
                        Ok(quit) => {
                            if quit {
                                return;
                            }
                        }
                        Err(()) => return,
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            })
            .ok()?;
    }

    Some(rx)
}

/// Drain both global receivers once. `Ok(true)` means Quit was delivered
/// (the caller must stop pumping); `Err(())` means the UI is gone.
fn drain_events(
    show_id: u32,
    disconnect_id: u32,
    logs_id: u32,
    quit_id: u32,
    tx: &Sender<TrayCommand>,
) -> Result<bool, ()> {
    let menu_rx = menu_event_receiver();
    while let Ok(event) = menu_rx.try_recv() {
        let command = if event.id == show_id {
            Some(TrayCommand::Show)
        } else if event.id == disconnect_id {
            Some(TrayCommand::Disconnect)
        } else if event.id == logs_id {
            Some(TrayCommand::OpenLogs)
        } else if event.id == quit_id {
            Some(TrayCommand::Quit)
        } else {
            None
        };
        if let Some(command) = command {
            let quit = matches!(command, TrayCommand::Quit);
            tx.send(command).map_err(|_| ())?;
            if quit {
                return Ok(true);
            }
        }
    }
    let tray_rx = tray_event_receiver();
    while let Ok(event) = tray_rx.try_recv() {
        // Left-click shows the window (standard tray UX); anything else is
        // ignored.
        if matches!(event.event, ClickEvent::Left) {
            tx.send(TrayCommand::Show).map_err(|_| ())?;
        }
    }
    Ok(false)
}

/// Menu labels shared by every platform's menu builder (the Windows
/// owner-draw handler indexes the same order).
const TRAY_MENU_LABELS: [&str; 4] = ["Show TheKVM", "Disconnect", "Open logs", "Quit TheKVM"];

fn build_tray_handles() -> Option<TrayHandles> {
    let menu = Menu::new();
    let show = MenuItem::new(TRAY_MENU_LABELS[0], true, None);
    let disconnect = MenuItem::new(TRAY_MENU_LABELS[1], true, None);
    let logs = MenuItem::new(TRAY_MENU_LABELS[2], true, None);
    let quit = MenuItem::new(TRAY_MENU_LABELS[3], true, None);
    let show_id = show.id();
    let disconnect_id = disconnect.id();
    let logs_id = logs.id();
    let quit_id = quit.id();
    menu.append_items(&[&show, &disconnect, &logs, &quit]);
    // Code-drawn glyph (see build_icon below).
    let icon = build_icon();
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("TheKVM")
        .with_icon(icon)
        .build()
        .ok()?;
    Some(TrayHandles {
        _tray: tray,
        show_id,
        disconnect_id,
        logs_id,
        quit_id,
    })
}

fn build_icon() -> Icon {
    const W: usize = 64;
    const H: usize = 64;
    let mut rgba = vec![0u8; W * H * 4];
    let mut px = |x: usize, y: usize, r: u8, g: u8, b: u8, a: u8| {
        if x < W && y < H {
            let i = (y * W + x) * 4;
            rgba[i] = r;
            rgba[i + 1] = g;
            rgba[i + 2] = b;
            rgba[i + 3] = a;
        }
    };
    // Dark rounded backdrop.
    for y in 0..H {
        for x in 0..W {
            let dx = (x as i32 - 32).abs();
            let dy = (y as i32 - 32).abs();
            if dx.max(dy) <= 30 && dx + dy <= 56 {
                px(x, y, 0x11, 0x11, 0x11, 0xff);
            }
        }
    }
    let mut frame = |x0: usize, y0: usize, x1: usize, y1: usize, r: u8, g: u8, b: u8| {
        for x in x0..=x1 {
            px(x, y0, r, g, b, 0xff);
            px(x, y1, r, g, b, 0xff);
        }
        for y in y0..=y1 {
            px(x0, y, r, g, b, 0xff);
            px(x1, y, r, g, b, 0xff);
        }
    };
    // Local screen (grey) left, peer screen (green) right.
    frame(10, 20, 26, 42, 0xd1, 0xd5, 0xdb);
    frame(38, 20, 54, 42, 0x22, 0xc5, 0x5e);
    // Link arrow between them.
    for x in 28..38 {
        px(x, 31, 0x22, 0xc5, 0x5e, 0xff);
    }
    for y in 26..37 {
        px(32, y, 0x22, 0xc5, 0x5e, 0xff);
    }
    match Icon::from_rgba(rgba, W as u32, H as u32) {
        Ok(icon) => icon,
        // 64x64 RGBA always satisfies Icon's invariants; a None here can
        // only mean a platform backend refused the buffer, and the tray is
        // optional anyway (build_tray_handles bails).
        Err(_) => return Icon::from_rgba(vec![0u8; 64 * 64 * 4], 64, 64)
            .unwrap_or_else(|_| unreachable!("1x1 RGBA icon is always valid")),
    }
}

// ---------------------------------------------------------------------------
// Windows: dark owner-draw tray menu + window focus helper
// ---------------------------------------------------------------------------

/// Bring this app's main window to the foreground (tray "Show TheKVM" and
/// left-click). Slint exposes no focus API, so the titled top-level window
/// owned by this process is located and foregrounded directly.
#[cfg(target_os = "windows")]
pub fn focus_main_window() {
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, EnumWindows, GetWindowTextLengthW, GetWindowThreadProcessId,
        IsWindowVisible, IsIconic, SetForegroundWindow, ShowWindow, SW_RESTORE,
    };

    let target_pid = std::process::id();
    unsafe extern "system" fn enum_proc(hwnd: HWND, param: LPARAM) -> BOOL {
        let target_pid = param.0 as u32;
        let mut window_pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut window_pid));
        if window_pid != target_pid {
            return true.into();
        }
        // The tray window and hidden helper windows carry no title; the
        // Slint main window does.
        if GetWindowTextLengthW(hwnd) == 0 || !IsWindowVisible(hwnd).as_bool() {
            return true.into();
        }
        if IsIconic(hwnd).as_bool() {
            let _ = ShowWindow(hwnd, SW_RESTORE);
        }
        let _ = BringWindowToTop(hwnd);
        let _ = SetForegroundWindow(hwnd);
        // Stop at the first match: one main window.
        false.into()
    }

    unsafe {
        let _ = EnumWindows(Some(enum_proc), LPARAM(target_pid as isize));
    }
}

#[cfg(not(target_os = "windows"))]
pub fn focus_main_window() {}

/// Subclass the tray-icon window so its popup menu paints dark (`#121212`
/// background, white text) instead of following the light system theme.
/// Runs on the tray thread right after the tray is built, before the
/// message loop starts.
#[cfg(target_os = "windows")]
fn install_windows_dark_menu() {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Shell::{SetWindowSubclass, SUBCLASSPROC};
    use windows::Win32::UI::WindowsAndMessaging::FindWindowW;

    const SUBCLASS_ID: usize = 0x0BAD_C0DE;
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(|| {
        let class: Vec<u16> = "tray_icon_app\0".encode_utf16().collect();
        let hwnd: HWND =
            unsafe { FindWindowW(windows::core::PCWSTR(class.as_ptr()), None) }
                .unwrap_or_default();
        if hwnd.0.is_null() {
            return;
        }
        unsafe {
            set_dark_theme_globals(hwnd);
            let proc: SUBCLASSPROC = Some(tray_menu_subclass_proc);
            let _ = SetWindowSubclass(hwnd, proc, SUBCLASS_ID, 0);
        }
    });
}

/// Ask comctl32/DWM to treat this window (and the process) as dark. Best
/// effort: the undocumented ordinals simply do not exist on older builds,
/// and the owner-draw handler below carries the exact palette regardless.
#[cfg(target_os = "windows")]
unsafe fn set_dark_theme_globals(hwnd: windows::Win32::Foundation::HWND) {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE,
    };
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows::Win32::UI::Controls::SetWindowTheme;

    let explorer: Vec<u16> = "DarkMode_Explorer\0".encode_utf16().collect();
    let sub: Vec<u16> = "DarkMode_CFD\0".encode_utf16().collect();
    let _ = SetWindowTheme(
        hwnd,
        windows::core::PCWSTR(explorer.as_ptr()),
        windows::core::PCWSTR(sub.as_ptr()),
    );
    let dark: windows::Win32::Foundation::BOOL = true.into();
    let _ = DwmSetWindowAttribute(
        hwnd,
        DWMWA_USE_IMMERSIVE_DARK_MODE,
        &dark as *const _ as *const _,
        std::mem::size_of::<windows::Win32::Foundation::BOOL>() as u32,
    );

    type BoolFn = unsafe extern "system" fn(usize, bool) -> bool;
    type ModeFn = unsafe extern "system" fn(i32);
    type FlushFn = unsafe extern "system" fn ();
    let module: HMODULE = GetModuleHandleW(windows::core::w!("uxtheme.dll")).unwrap_or_default();
    if module.0.is_null() {
        return;
    }
    let ordinal = |slot: Option<&[u8]>, number: usize| -> Option<usize> {
        let proc = match slot {
            Some(bytes) => GetProcAddress(module, windows::core::PCSTR(bytes.as_ptr())),
            None => GetProcAddress(module, windows::core::PCSTR(number as *const u8)),
        };
        proc.map(|proc| proc as usize)
    };
    // AllowDarkModeForWindow(hwnd, true)
    if let Some(address) = ordinal(Some(b"AllowDarkModeForWindow\0"), 133)
        .or_else(|| ordinal(None, 133))
    {
        let func: BoolFn = std::mem::transmute(address);
        func(hwnd.0 as usize, true);
    }
    // SetPreferredAppMode(2 /* AllowDark */)
    if let Some(address) = ordinal(None, 135) {
        let func: ModeFn = std::mem::transmute(address);
        func(2);
    }
    // FlushMenuThemes()
    if let Some(address) = ordinal(None, 136) {
        let func: FlushFn = std::mem::transmute(address);
        func();
    }
}

/// System menu font handle (cached for the process) used to measure and
/// paint menu rows.
#[cfg(target_os = "windows")]
fn menu_font() -> usize {
    use windows::Win32::Graphics::Gdi::{
        CreateFontIndirectW, GetStockObject, DEFAULT_GUI_FONT, LOGFONTW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        NONCLIENTMETRICSW, SPI_GETNONCLIENTMETRICS, SystemParametersInfoW,
    };

    static FONT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *FONT.get_or_init(|| unsafe {
        let mut metrics = NONCLIENTMETRICSW::default();
        metrics.cbSize = std::mem::size_of::<NONCLIENTMETRICSW>() as u32;
        let ok = SystemParametersInfoW(
            SPI_GETNONCLIENTMETRICS,
            metrics.cbSize,
            Some(&mut metrics as *mut NONCLIENTMETRICSW as *mut std::ffi::c_void),
            Default::default(),
        );
        let logfont: LOGFONTW = if ok.is_ok() {
            metrics.lfMenuFont
        } else {
            LOGFONTW::default()
        };
        let font = CreateFontIndirectW(&logfont);
        if font.is_invalid() {
            // Fallback: stock GUI font (never destroyed).
            let stock = GetStockObject(DEFAULT_GUI_FONT);
            stock.0 as usize
        } else {
            // Deliberately leaked: one font for the process lifetime.
            font.0 as usize
        }
    })
}

/// Convert every command row of `menu` to owner-draw, tagging it with its
/// label index so the drawing handler knows which text to paint.
#[cfg(target_os = "windows")]
unsafe fn owner_draw_menu_items(menu: windows::Win32::UI::WindowsAndMessaging::HMENU) {
    use windows::Win32::UI::WindowsAndMessaging::{
        GetMenuItemCount, GetMenuItemInfoW, MENUITEMINFOW, MFT_OWNERDRAW, MIIM_SUBMENU, MIIM_TYPE,
        SetMenuItemInfoW,
    };

    let count = GetMenuItemCount(menu);
    for position in 0..count {
        let mut info = MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: MIIM_SUBMENU | MIIM_TYPE,
            ..Default::default()
        };
        if GetMenuItemInfoW(menu, position as u32, true, &mut info).is_err() {
            continue;
        }
        if !info.hSubMenu.is_invalid() {
            owner_draw_menu_items(info.hSubMenu);
            continue;
        }
        if (info.fType & MFT_OWNERDRAW) == MFT_OWNERDRAW {
            continue;
        }
        // The menu is built in TRAY_LABELS order, so the row index is the
        // label index.
        let mut update = MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: MIIM_TYPE,
            fType: MFT_OWNERDRAW,
            dwItemData: position as usize,
            ..Default::default()
        };
        let _ = SetMenuItemInfoW(menu, position as u32, true, &mut update);
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn tray_menu_subclass_proc(
    hwnd: windows::Win32::Foundation::HWND,
    message: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
    _id: usize,
    _data: usize,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::Foundation::{LRESULT, COLORREF, SIZE};
    use windows::Win32::Graphics::Gdi::{
        CreateSolidBrush, DeleteObject, DrawTextW, DT_LEFT, DT_SINGLELINE, DT_VCENTER, FillRect,
        GetTextExtentPoint32W, GetWindowDC, ReleaseDC, SelectObject, SetBkMode, SetTextColor,
        HBRUSH, HDC, HGDIOBJ, TRANSPARENT,
    };
    use windows::Win32::UI::Controls::{DRAWITEMSTRUCT, MEASUREITEMSTRUCT, ODT_MENU};
    use windows::Win32::UI::Shell::DefSubclassProc;
    use windows::Win32::UI::WindowsAndMessaging::{
        HMENU, MENUINFO, MIM_BACKGROUND, SetMenuInfo, WM_DRAWITEM, WM_INITMENUPOPUP,
        WM_MEASUREITEM,
    };

    match message {
        WM_INITMENUPOPUP => {
            let menu = HMENU(wparam.0 as *mut _);
            owner_draw_menu_items(menu);
            // Surface brush: everything the rows do not cover is #121212
            // too, not the light system colour.
            let brush: HBRUSH = CreateSolidBrush(COLORREF(MENU_BG_RGB));
            let info = MENUINFO {
                cbSize: std::mem::size_of::<MENUINFO>() as u32,
                fMask: MIM_BACKGROUND,
                dwStyle: Default::default(),
                cyMax: 0,
                hbrBack: brush,
                dwContextHelpID: 0,
                dwMenuData: 0,
            };
            let _ = SetMenuInfo(menu, &info);
            return DefSubclassProc(hwnd, message, wparam, lparam);
        }
        WM_MEASUREITEM => {
            let measure = &mut *(lparam.0 as *mut MEASUREITEMSTRUCT);
            if measure.CtlType != ODT_MENU {
                return DefSubclassProc(hwnd, message, wparam, lparam);
            }
            let label = TRAY_LABELS
                .get(measure.itemData)
                .copied()
                .unwrap_or("TheKVM");
            let wide: Vec<u16> = label.encode_utf16().collect();
            let font = HGDIOBJ(menu_font() as *mut _);
            let screen_dc: HDC = GetWindowDC(hwnd);
            if !screen_dc.is_invalid() {
                let mut size = SIZE::default();
                let old = SelectObject(screen_dc, font);
                let _ = GetTextExtentPoint32W(screen_dc, &wide, &mut size);
                SelectObject(screen_dc, old);
                let _ = ReleaseDC(hwnd, screen_dc);
                measure.itemWidth = (size.cx + 44) as u32;
                measure.itemHeight = (size.cy + 12) as u32;
            } else {
                measure.itemWidth = 200;
                measure.itemHeight = 28;
            }
            return LRESULT(1);
        }
        WM_DRAWITEM => {
            let draw = &mut *(lparam.0 as *mut DRAWITEMSTRUCT);
            if draw.CtlType != ODT_MENU {
                return DefSubclassProc(hwnd, message, wparam, lparam);
            }
            let label = TRAY_LABELS
                .get(draw.itemData)
                .copied()
                .unwrap_or("TheKVM");
            let mut wide: Vec<u16> = label.encode_utf16().collect();
            // ODS_SELECTED = 0x0001
            let selected = draw.itemState.0 & 0x1 != 0;
            let background = CreateSolidBrush(COLORREF(if selected {
                MENU_HIGHLIGHT_RGB
            } else {
                MENU_BG_RGB
            }));
            FillRect(draw.hDC, &draw.rcItem, background);
            let _ = DeleteObject(background);
            let font = HGDIOBJ(menu_font() as *mut _);
            let old_font = SelectObject(draw.hDC, font);
            let _ = SetBkMode(draw.hDC, TRANSPARENT);
            let _ = SetTextColor(draw.hDC, COLORREF(MENU_TEXT_RGB));
            let mut rect = draw.rcItem;
            rect.left += 22;
            rect.right -= 12;
            let _ = DrawTextW(
                draw.hDC,
                &mut wide,
                &mut rect,
                DT_LEFT | DT_SINGLELINE | DT_VCENTER,
            );
            SelectObject(draw.hDC, old_font);
            return LRESULT(1);
        }
        _ => {}
    }
    DefSubclassProc(hwnd, message, wparam, lparam)
}
