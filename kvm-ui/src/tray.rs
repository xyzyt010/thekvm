//! System tray icon with a right-click menu (Show, Open logs, Quit).
//!
//! The window close button hides to the tray instead of exiting (see
//! main.rs `on_close_requested`); only the tray Quit fully terminates the
//! app: link banned both sides, supervised child killed, UI-spawned user
//! daemon killed, process exit. The installed system service (thekvmd /
//! TheKVM) is never touched — it belongs to the machine, not the app.
//!
//! Menu events arrive on tray-icon's global receivers, pumped on a
//! background thread here, and cross to the UI over a channel drained by
//! a watcher thread in main.rs, so clicks act immediately instead of
//! waiting for the 1s status poll. The TrayIcon itself is owned by that
//! pump thread (it is neither Send nor Sync); nothing else touches it.

use std::sync::mpsc::{channel, Receiver};
use tray_icon::icon::Icon;
use tray_icon::menu::{menu_event_receiver, Menu, MenuItem};
use tray_icon::{tray_event_receiver, ClickEvent, TrayIconBuilder};

/// Commands the tray thread delivers to the UI thread.
pub enum TrayCommand {
    Show,
    OpenLogs,
    Quit,
}

/// Build the tray icon + menu and pump its events on a background thread.
/// Returns the command channel, or None when no system tray is available
/// (the app keeps working window-only).
pub fn spawn_tray() -> Option<Receiver<TrayCommand>> {
    let (tx, rx) = channel::<TrayCommand>();
    let menu = Menu::new();
    let show = MenuItem::new("Show TheKVM", true, None);
    let logs = MenuItem::new("Open logs", true, None);
    let quit = MenuItem::new("Quit TheKVM", true, None);
    let show_id = show.id().clone();
    let logs_id = logs.id().clone();
    let quit_id = quit.id().clone();
    menu.append_items(&[&show, &logs, &quit]);
    let icon = build_icon();
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("TheKVM")
        .with_icon(icon)
        .build()
        .ok()?;
    // Process-lifetime singleton: the glyph lives exactly as long as the
    // app, and the TrayIcon is neither Send nor Sync, so it stays on the
    // thread that built it. Events pump off the global receivers below.
    std::mem::forget(tray);
    std::thread::Builder::new()
        .name("thekvm-tray-events".into())
        .spawn(move || {
            let menu_rx = menu_event_receiver();
            let tray_rx = tray_event_receiver();
            loop {
                let mut idle = true;
                while let Ok(event) = menu_rx.try_recv() {
                    idle = false;
                    let command = if event.id == show_id {
                        Some(TrayCommand::Show)
                    } else if event.id == logs_id {
                        Some(TrayCommand::OpenLogs)
                    } else if event.id == quit_id {
                        Some(TrayCommand::Quit)
                    } else {
                        None
                    };
                    if let Some(command) = command {
                        let quit = matches!(command, TrayCommand::Quit);
                        if tx.send(command).is_err() || quit {
                            return;
                        }
                    }
                }
                while let Ok(event) = tray_rx.try_recv() {
                    idle = false;
                    // Left-click shows the window (standard tray UX);
                    // anything else is ignored.
                    if matches!(event.event, ClickEvent::Left)
                        && tx.send(TrayCommand::Show).is_err()
                    {
                        return;
                    }
                }
                if idle {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        })
        .ok()?;
    Some(rx)
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
