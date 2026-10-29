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
//! NOTE on dark menus: the popup menu is drawn by the OS from the same
//! native theme as every other tray app (Windows dark mode → dark menu,
//! Mint likewise) — Win32/AppIndicator HMENUs expose no per-app paint,
//! so there is deliberately no custom styling here to fight the
//! desktop. The glyph itself is dark glass (see build_icon) on both.

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

fn build_tray_handles() -> Option<TrayHandles> {
    let menu = Menu::new();
    let show = MenuItem::new("Show TheKVM", true, None);
    let disconnect = MenuItem::new("Disconnect", true, None);
    let logs = MenuItem::new("Open logs", true, None);
    let quit = MenuItem::new("Quit TheKVM", true, None);
    let show_id = show.id();
    let disconnect_id = disconnect.id();
    let logs_id = logs.id();
    let quit_id = quit.id();
    menu.append_items(&[&show, &disconnect, &logs, &quit]);
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

/// Code-drawn 64x64 tray glyph: two linked screens on dark glass, the
/// peer screen in TheKVM green. No asset files, identical on Windows and
/// Linux, always in sync with the binary.
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
    px(36, 30, 0x22, 0xc5, 0x5e, 0xff);
    px(36, 32, 0x22, 0xc5, 0x5e, 0xff);
    px(35, 29, 0x22, 0xc5, 0x5e, 0xff);
    px(35, 33, 0x22, 0xc5, 0x5e, 0xff);
    Icon::from_rgba(rgba, W as u32, H as u32).expect("tray icon dimensions are valid")
}
