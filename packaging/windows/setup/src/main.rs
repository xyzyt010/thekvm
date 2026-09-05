//! TheKVM Windows setup wizard.
//!
//! One self-contained GUI setup.exe that embeds kvm-daemon.exe and kvm-ui.exe:
//! - No console window, ever (windows_subsystem) — step-by-step wizard with
//!   the project logo, live progress, and a launch button at the end.
//! - Elevates once through the ShellExecuteW "runas" verb; a relaunched copy
//!   that is somehow still unelevated refuses to loop UAC prompts.
//! - Installs to %ProgramFiles%\TheKVM (binaries plus a copy of this setup
//!   for Add/Remove Programs), configures state in %ProgramData%\TheKVM,
//!   registers the LocalSystem service, adds the firewall rule, and creates
//!   a Start-menu shortcut.
//! - `--uninstall` (used by Add/Remove Programs) runs silently with elevation
//!   and only shows a message box on failure. `--uninstall-ui` opens the
//!   wizard on the uninstall page. `--install-ui` opens the wizard on the
//!   options page after the UAC relaunch.
//!
//! Only documented Win32 surface area is used; service registration goes
//! through sc.exe and the firewall through netsh, matching the audited
//! install-service.ps1 behavior.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

slint::include_modules!();

use slint::{ComponentHandle, SharedString};
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

const SERVICE_NAME: &str = "TheKVM";
const DISPLAY_NAME: &str = "TheKVM privileged receiver service";
const FIREWALL_RULE: &str = "TheKVM QUIC and discovery";
const SETUP_EXE_NAME: &str = "thekvm-setup.exe";
const DAEMON_EXE: &[u8] = include_bytes!("../../../../target/release/kvm-daemon.exe");
const UI_EXE: &[u8] = include_bytes!("../../../../target/release/kvm-ui.exe");

fn install_dir() -> PathBuf {
    std::env::var("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Program Files"))
        .join("TheKVM")
}

fn data_dir() -> PathBuf {
    std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
        .join("TheKVM")
}

/// Progress sink shared by install/uninstall. Always appends to the setup
/// log file; forwards to the wizard window when one is attached.
#[derive(Clone)]
struct Reporter {
    weak: Option<slint::Weak<SetupWindow>>,
    log: Arc<Mutex<String>>,
}

impl Reporter {
    fn headless() -> Self {
        Self {
            weak: None,
            log: Arc::new(Mutex::new(String::new())),
        }
    }

    fn window(weak: slint::Weak<SetupWindow>) -> Self {
        Self {
            weak: Some(weak),
            log: Arc::new(Mutex::new(String::new())),
        }
    }

    fn report(&self, message: &str, progress: f32) {
        let _ = fs::create_dir_all(data_dir());
        let mut guard = self.log.lock().expect("setup log lock");
        guard.push_str(message);
        guard.push('\n');
        // Keep the on-screen log readable: last ~25 lines only.
        let lines: Vec<&str> = guard.lines().collect();
        let start = lines.len().saturating_sub(25);
        let visible = lines[start..].join("\n");
        let _ = fs::write(data_dir().join("setup.log"), guard.as_str());
        if let Some(weak) = &self.weak {
            let weak = weak.clone();
            let visible = SharedString::from(visible);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_log_text(visible.clone());
                    ui.set_progress(progress);
                }
            });
        }
    }
}

/// Detect elevation through the process token's mandatory integrity level:
/// an elevated process carries the "High Mandatory Level" group
/// (S-1-16-12288). Falls back to true when the check cannot run so we
/// never loop the UAC relaunch.
fn is_elevated() -> bool {
    let output = Command::new("whoami").args(["/groups"]).output();
    let Ok(output) = output else {
        return true;
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if text.contains("S-1-16-12288") {
        return true;
    }
    if text.contains("High Mandatory Level") {
        return true;
    }
    text.lines().any(|line| line.contains("Mandatory Level")) && !text.contains("S-1-16-")
}

fn quote_arg(arg: &str) -> String {
    if arg.chars().all(|c| c.is_alphanumeric() || "-_.".contains(c)) {
        return arg.to_owned();
    }
    format!("\"{}\"", arg.replace('"', "\"\""))
}

fn relaunch_elevated(extra: &[String]) -> ! {
    let Ok(exe) = std::env::current_exe() else {
        fatal_message("Setup cannot locate its own executable for elevation.");
    };
    let mut parameters: Vec<String> = std::env::args().skip(1).collect();
    parameters.extend(extra.iter().cloned());
    // Marker so a relaunched copy that is somehow still unelevated refuses
    // to relaunch again instead of looping UAC prompts forever.
    parameters.push("--elevated".to_owned());
    let joined = parameters
        .iter()
        .map(|arg| quote_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let file: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let param_wide: Vec<u16> = joined.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        #[link(name = "Shell32")]
        unsafe extern "system" {
            fn ShellExecuteW(
                hwnd: isize,
                verb: *const u16,
                file: *const u16,
                parameters: *const u16,
                directory: *const u16,
                show: i32,
            ) -> isize;
        }
        const SW_SHOWNORMAL: i32 = 1;
        let result = ShellExecuteW(
            0,
            verb.as_ptr(),
            file.as_ptr(),
            param_wide.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
        if result as usize <= 32 {
            fatal_message("This installer requires administrator approval.");
        }
    }
    std::process::exit(0);
}

fn fatal_message(message: &str) -> ! {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MB_ICONERROR, MB_OK, MessageBoxW,
    };
    let title: Vec<u16> = "TheKVM Setup\0".encode_utf16().collect();
    let text: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
    std::process::exit(1);
}

fn extract(path: &Path, payload: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    fs::write(path, payload).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("run {program}: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(format!("{program} {:?} failed: {text}", args));
    }
    Ok(text)
}

fn install(report: &Reporter, device_name: Option<&str>, lock_screen: bool) -> Result<(), String> {
    let install_dir = install_dir();
    let data_dir = data_dir();
    let daemon = install_dir.join("kvm-daemon.exe");
    let ui = install_dir.join("kvm-ui.exe");

    report.report("Extracting TheKVM binaries…", 0.05);
    extract(&daemon, DAEMON_EXE)?;
    extract(&ui, UI_EXE)?;
    // Keep a copy of this setup so Add/Remove Programs can uninstall later
    // even if the downloaded installer is gone.
    if let Ok(exe) = std::env::current_exe() {
        if exe.file_name().is_some_and(|name| name != SETUP_EXE_NAME)
            || exe.parent() != Some(install_dir.as_path())
        {
            let _ = fs::copy(&exe, install_dir.join(SETUP_EXE_NAME));
        }
    }
    report.report("Binaries extracted.", 0.15);

    report.report("Configuring receiver identity…", 0.25);
    fs::create_dir_all(&data_dir).map_err(|e| format!("create {}: {e}", data_dir.display()))?;
    let mut configure: Vec<String> = vec![
        "configure".into(),
        "--mode".into(),
        "receiver-only".into(),
    ];
    if let Some(name) = device_name.filter(|name| !name.trim().is_empty()) {
        configure.push("--device-name".into());
        configure.push(name.trim().to_owned());
    }
    configure.push(
        if lock_screen {
            "--allow-lock-screen-control"
        } else {
            "--disable-lock-screen-control"
        }
        .into(),
    );
    configure.push("--clear-auto-connect".into());
    let configure_args: Vec<&str> = configure.iter().map(String::as_str).collect();
    run(&daemon.display().to_string(), &configure_args)?;
    report.report("Identity configured.", 0.35);

    report.report("Registering the LocalSystem service…", 0.45);
    soft(report, "sc", &["stop", SERVICE_NAME]);
    soft(report, "sc", &["delete", SERVICE_NAME]);
    // sc.exe parses `binPath= <remainder-of-line>`; the quoted exe path plus
    // the service arguments must arrive as one token after `binPath=`.
    let bin_path = format!("\"{}\" serve --service", daemon.display());
    run(
        "sc",
        &[
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "obj=",
            "LocalSystem",
        ],
    )?;
    soft(report, "sc", &["description", SERVICE_NAME, DISPLAY_NAME]);
    soft(
        report,
        "sc",
        &[
            "failure",
            SERVICE_NAME,
            "reset=",
            "86400",
            "actions=restart/5000/restart/5000/restart/10000",
        ],
    );
    run("sc", &["start", SERVICE_NAME])?;
    report.report("Service running.", 0.6);

    report.report("Adding the firewall rule…", 0.7);
    soft(
        report,
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={FIREWALL_RULE}"),
        ],
    );
    run(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={FIREWALL_RULE}"),
            "dir=in",
            "action=allow",
            "protocol=UDP",
            "localport=42110,42111",
            &format!("program={}", daemon.display()),
            "enable=yes",
        ],
    )?;
    report.report("Firewall rule added.", 0.8);

    report.report("Creating Start-menu shortcut…", 0.85);
    let start_menu = std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
        .join(r"Microsoft\Windows\Start Menu\Programs\TheKVM UI.lnk");
    let vbs = data_dir.join("shortcut.vbs");
    fs::write(
        &vbs,
        format!(
            "Set s = CreateObject(\"WScript.Shell\")\n\
             Set l = s.CreateShortcut(\"{}\")\n\
             l.TargetPath = \"{target}\"\n\
             l.WorkingDirectory = \"{install}\"\n\
             l.Save\n",
            start_menu.display(),
            target = ui.display(),
            install = install_dir.display()
        ),
    )
    .map_err(|e| format!("write shortcut script: {e}"))?;
    soft(report, "wscript", &["//B", "//NOLOGO", &vbs.display().to_string()]);
    let _ = fs::remove_file(&vbs);

    report.report("Registering Add/Remove Programs entry…", 0.92);
    let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TheKVM";
    let version = env!("CARGO_PKG_VERSION");
    let uninstall_string = format!(
        "\"{}\" --uninstall",
        install_dir.join(SETUP_EXE_NAME).display()
    );
    let entries = [
        ("DisplayVersion", version.to_owned()),
        ("Publisher", "TheKVM project".to_owned()),
        ("UninstallString", uninstall_string),
        ("InstallLocation", install_dir.display().to_string()),
        ("NoModify", "1".to_owned()),
    ];
    soft(
        report,
        "reg",
        &["add", key, "/ve", "/t", "REG_SZ", "/d", "TheKVM", "/f"],
    );
    for (name, value) in entries {
        soft(
            report,
            "reg",
            &["add", key, "/v", name, "/t", "REG_SZ", "/d", &value, "/f"],
        );
    }

    report.report("TheKVM installed successfully.", 1.0);
    report.report(&format!("Binaries: {}", install_dir.display()), 1.0);
    report.report("Service TheKVM is running and starts automatically.", 1.0);
    Ok(())
}

fn uninstall(report: &Reporter) -> Result<(), String> {
    report.report("Stopping and removing the service…", 0.2);
    soft(report, "sc", &["stop", SERVICE_NAME]);
    soft(report, "sc", &["delete", SERVICE_NAME]);

    report.report("Removing the firewall rule…", 0.4);
    soft(
        report,
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={FIREWALL_RULE}"),
        ],
    );

    report.report("Removing Add/Remove Programs entry…", 0.6);
    soft(
        report,
        "reg",
        &[
            "delete",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TheKVM",
            "/f",
        ],
    );

    report.report("Removing shortcuts…", 0.75);
    let start_menu = std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
        .join(r"Microsoft\Windows\Start Menu\Programs\TheKVM UI.lnk");
    let _ = fs::remove_file(&start_menu);

    report.report("Removing binaries…", 0.9);
    let install_dir = install_dir();
    for name in ["kvm-daemon.exe", "kvm-ui.exe", SETUP_EXE_NAME] {
        let _ = fs::remove_file(install_dir.join(name));
    }
    let _ = fs::remove_dir(&install_dir);

    report.report("TheKVM uninstalled.", 1.0);
    report.report("Peer/identity state remains in ProgramData\\TheKVM.", 1.0);
    Ok(())
}

/// Best-effort step: report failures but keep going.
fn soft(report: &Reporter, program: &str, args: &[&str]) {
    if let Err(error) = run(program, args) {
        report.report(&format!("(continuing after: {error})"), 0.0);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut device_name: Option<String> = None;
    let mut lock_screen = false;
    let mut silent_uninstall = false;
    let mut uninstall_ui = false;
    let mut already_elevated_relaunch = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--uninstall" => silent_uninstall = true,
            "--uninstall-ui" => uninstall_ui = true,
            "--install-ui" => {}
            "--elevated" => already_elevated_relaunch = true,
            "--device-name" => {
                if let Some(value) = args.get(i + 1) {
                    device_name = Some(value.clone());
                    i += 1;
                }
            }
            "--enable-lock-screen-control" => lock_screen = true,
            "--" => {}
            _ => {}
        }
        i += 1;
    }

    // Silent path for Add/Remove Programs: elevate, run, message box only on
    // failure. Never shows the wizard or a console window.
    if silent_uninstall && !uninstall_ui {
        if !is_elevated() {
            if already_elevated_relaunch {
                fatal_message("Setup could not obtain administrator rights.");
            }
            relaunch_elevated(&[]);
        }
        let report = Reporter::headless();
        if let Err(error) = uninstall(&report) {
            let _ = fs::write(data_dir().join("setup-error.log"), format!("{error}\n"));
            fatal_message(&format!("Uninstall failed: {error}"));
        }
        return;
    }

    // Wizard path.
    let ui = SetupWindow::new().expect("create setup window");
    ui.set_version(SharedString::from(env!("CARGO_PKG_VERSION")));
    let elevated = is_elevated();
    ui.set_elevated(elevated);
    if uninstall_ui {
        ui.set_uninstall_mode(true);
    }
    if let Some(name) = device_name {
        ui.set_device_name(SharedString::from(name));
    }
    ui.set_lock_screen(lock_screen);
    if let Ok(computer) = std::env::var("COMPUTERNAME") {
        if ui.get_device_name().is_empty() && !computer.trim().is_empty() {
            ui.set_device_name(SharedString::from(computer.trim()));
        }
    }

    // Install button: elevate first (keeping the typed options), run when
    // the user confirms again on the elevated copy's options page.
    let weak = ui.as_weak();
    ui.on_install(move |name, lock| {
        if !is_elevated() {
            let mut extra = vec!["--install-ui".to_owned()];
            if !name.trim().is_empty() {
                extra.push("--device-name".to_owned());
                extra.push(name.trim().to_owned());
            }
            if lock {
                extra.push("--enable-lock-screen-control".to_owned());
            }
            relaunch_elevated(&extra);
        }
        run_job(&weak, false, Some(name.to_string()), lock);
    });

    let weak = ui.as_weak();
    ui.on_show_uninstall(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_uninstall_mode(true);
        }
    });

    let weak = ui.as_weak();
    ui.on_show_install(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_uninstall_mode(false);
        }
    });

    // Uninstall button: same elevation dance, then run immediately on the
    // progress page of the elevated copy.
    let weak = ui.as_weak();
    ui.on_uninstall(move || {
        if !is_elevated() {
            relaunch_elevated(&["--uninstall-ui".to_owned()]);
        }
        run_job(&weak, true, None, false);
    });

    // Direct entry as the elevated uninstall copy: go straight to work.
    if uninstall_ui && elevated {
        let weak = ui.as_weak();
        ui.set_page(1);
        ui.set_running(true);
        std::thread::spawn(move || {
            let report = Reporter::window(weak.clone());
            let outcome = uninstall(&report);
            finish_job(&weak, outcome, true);
        });
    }

    let weak = ui.as_weak();
    ui.on_launch_app(move || {
        let app = install_dir().join("kvm-ui.exe");
        if app.is_file() {
            let _ = Command::new(&app)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        } else if let Some(ui) = weak.upgrade() {
            ui.set_finished_text(SharedString::from(
                "TheKVM UI was not found in Program Files; reinstall to repair.",
            ));
            ui.set_finished_ok(false);
        }
    });

    ui.on_close_window(|| {
        std::process::exit(0);
    });

    ui.run().expect("run setup window");
}

fn run_job(
    weak: &slint::Weak<SetupWindow>,
    uninstall_mode: bool,
    device_name: Option<String>,
    lock_screen: bool,
) {
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_uninstall_mode(uninstall_mode);
                ui.set_page(1);
                ui.set_running(true);
                ui.set_log_text(SharedString::new());
                ui.set_progress(0.0);
            }
        }
    });
    std::thread::spawn(move || {
        let report = Reporter::window(weak.clone());
        let outcome = if uninstall_mode {
            uninstall(&report)
        } else {
            install(&report, device_name.as_deref(), lock_screen)
        };
        finish_job(&weak, outcome, uninstall_mode);
    });
}

fn finish_job(
    weak: &slint::Weak<SetupWindow>,
    outcome: Result<(), String>,
    uninstall_mode: bool,
) {
    if let Err(error) = &outcome {
        let _ = fs::write(data_dir().join("setup-error.log"), format!("{error}\n"));
    }
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_running(false);
                ui.set_page(2);
                match outcome {
                    Ok(()) => {
                        ui.set_finished_ok(true);
                        ui.set_progress(1.0);
                        ui.set_finished_text(SharedString::from(if uninstall_mode {
                            "TheKVM was removed. Restart other machines' pairing state if needed."
                        } else {
                            "TheKVM is installed and running. Launch the app, then pair your other machine — compare the six-digit code on both screens."
                        }));
                    }
                    Err(error) => {
                        ui.set_finished_ok(false);
                        ui.set_finished_text(SharedString::from(format!(
                            "Setup failed: {error}. See ProgramData\\TheKVM\\setup.log for details."
                        )));
                    }
                }
            }
        }
    });
}
