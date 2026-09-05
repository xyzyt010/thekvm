//! TheKVM Windows setup.
//!
//! One self-contained setup.exe that embeds kvm-daemon.exe and kvm-ui.exe:
//! - Relaunches itself elevated through the ShellExecuteW "runas" verb when
//!   started without administrator rights.
//! - Installs to %ProgramFiles%\TheKVM, configures receiver-only state in
//!   %ProgramData%\TheKVM, registers the LocalSystem service, adds the
//!   firewall rule, creates a Start-menu shortcut, and an Add/Remove
//!   Programs entry.
//! - `--uninstall` reverses everything except the peer/identity state.
//! - `--device-name NAME` and `--enable-lock-screen-control` are forwarded
//!   to the daemon's configure step.
//!
//! Only documented Win32 surface area is used; service registration goes
//! through sc.exe and the firewall through netsh, matching the audited
//! install-service.ps1 behavior.

use std::fs;
use std::io::Write as _;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SERVICE_NAME: &str = "TheKVM";
const DISPLAY_NAME: &str = "TheKVM privileged receiver service";
const FIREWALL_RULE: &str = "TheKVM QUIC and discovery";
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

fn log(message: &str) {
    println!("{message}");
    let _ = fs::write(data_dir().join("setup.log"), format!("{message}\n"));
}

/// Detect elevation through the process token's mandatory integrity level:
/// an elevated process carries the "High Mandatory Level" group
/// (S-1-16-12288). Falls back to true when the check cannot run so we
/// never loop the UAC relaunch.
fn is_elevated() -> bool {
    let output = Command::new("whoami")
        .args(["/groups"])
        .output()
        .expect("whoami must exist on Windows");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if text.contains("S-1-16-12288") {
        return true;
    }
    // "High Mandatory Level" label appears on localized systems.
    if text.contains("High Mandatory Level") {
        return true;
    }
    // whoami always prints at least one mandatory level line; if neither
    // matched, we are unelevated. If output looks broken, assume elevated
    // to avoid an elevation loop.
    text.lines().any(|line| line.contains("Mandatory Level"))
        && !text.contains("S-1-16-")
}

fn relaunch_elevated() -> ! {
    let Ok(exe) = std::env::current_exe() else {
        eprintln!("Setup cannot locate its own executable for elevation.");
        std::process::exit(1);
    };
    // Pass the original arguments through so --device-name etc. survive
    // the UAC relaunch.
    let mut parameters = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    if !parameters.is_empty() {
        parameters = format!("-- {parameters}");
    }
    // Marker so a relaunched copy that is somehow still unelevated refuses
    // to relaunch again instead of looping UAC prompts forever.
    parameters = format!("{parameters} --elevated");
    let file: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let param_wide: Vec<u16> = parameters.encode_utf16().chain(std::iter::once(0)).collect();
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
            eprintln!("This installer requires administrator approval.");
        }
    }
    std::process::exit(0);
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

/// Best-effort step: log failures but keep installing.
fn soft(program: &str, args: &[&str]) {
    if let Err(error) = run(program, args) {
        log(&format!("warning: {error}"));
    }
}

fn install(device_name: Option<&str>, lock_screen: bool) -> Result<(), String> {
    let install_dir = install_dir();
    let data_dir = data_dir();
    let daemon = install_dir.join("kvm-daemon.exe");
    let ui = install_dir.join("kvm-ui.exe");

    log("Extracting binaries...");
    extract(&daemon, DAEMON_EXE)?;
    extract(&ui, UI_EXE)?;

    log("Configuring receiver identity...");
    fs::create_dir_all(&data_dir).map_err(|e| format!("create {}: {e}", data_dir.display()))?;
    let mut configure: Vec<String> = vec![
        "configure".into(),
        "--mode".into(),
        "receiver-only".into(),
    ];
    if let Some(name) = device_name {
        configure.push("--device-name".into());
        configure.push(name.to_owned());
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
    run(
        &daemon.display().to_string(),
        &configure_args,
    )?;

    log("Registering the LocalSystem service...");
    soft("sc", &["stop", SERVICE_NAME]);
    soft("sc", &["delete", SERVICE_NAME]);
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
    soft("sc", &["description", SERVICE_NAME, DISPLAY_NAME]);
    soft(
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

    log("Adding the firewall rule...");
    soft(
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

    log("Creating Start-menu shortcut...");
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
    soft(
        "wscript",
        &[
            "//B",
            "//NOLOGO",
            &vbs.display().to_string(),
        ],
    );
    let _ = fs::remove_file(&vbs);

    log("Registering Add/Remove Programs entry...");
    let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TheKVM";
    let version = env!("CARGO_PKG_VERSION");
    let uninstall_string = format!("\"{}\" --uninstall", daemon.display());
    let entries = [
        ("DisplayVersion", version.to_owned()),
        ("Publisher", "TheKVM project".to_owned()),
        ("UninstallString", uninstall_string),
        ("InstallLocation", install_dir.display().to_string()),
        ("NoModify", "1".to_owned()),
    ];
    soft(
        "reg",
        &["add", key, "/ve", "/t", "REG_SZ", "/d", "TheKVM", "/f"],
    );
    for (name, value) in entries {
        soft(
            "reg",
            &["add", key, "/v", name, "/t", "REG_SZ", "/d", &value, "/f"],
        );
    }

    log("TheKVM installed successfully.");
    log(&format!("  binaries: {}", install_dir.display()));
    log(&format!("  state:    {}", data_dir.display()));
    log("  service:  TheKVM (running, auto-start)");
    log("Launch TheKVM UI from the Start menu, then pair from the other machine.");
    Ok(())
}

fn uninstall() -> Result<(), String> {
    log("Stopping and removing the service...");
    soft("sc", &["stop", SERVICE_NAME]);
    soft("sc", &["delete", SERVICE_NAME]);

    log("Removing the firewall rule...");
    soft(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={FIREWALL_RULE}"),
        ],
    );

    log("Removing Add/Remove Programs entry...");
    soft(
        "reg",
        &[
            "delete",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TheKVM",
            "/f",
        ],
    );

    log("Removing shortcuts...");
    let start_menu = std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
        .join(r"Microsoft\Windows\Start Menu\Programs\TheKVM UI.lnk");
    let _ = fs::remove_file(&start_menu);

    log("Removing binaries...");
    let install_dir = install_dir();
    let _ = fs::remove_file(install_dir.join("kvm-daemon.exe"));
    let _ = fs::remove_file(install_dir.join("kvm-ui.exe"));
    let _ = fs::remove_dir(&install_dir);

    log("TheKVM uninstalled.");
    log("Peer/identity state remains in ProgramData\\TheKVM; delete it manually");
    log("if you want a fully clean machine.");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut device_name: Option<String> = None;
    let mut lock_screen = false;
    let mut do_uninstall = false;
    let mut no_pause = false;
    let mut already_elevated_relaunch = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--uninstall" => do_uninstall = true,
            "--no-pause" => no_pause = true,
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

    // The setup log lives in ProgramData; create it before elevation too so
    // early failures are still recorded from the unelevated invocation.
    let _ = fs::create_dir_all(data_dir());

    if !is_elevated() {
        if already_elevated_relaunch {
            eprintln!("Setup could not obtain administrator rights; refusing to loop.");
            std::process::exit(1);
        }
        println!("Requesting administrator approval (UAC)...");
        relaunch_elevated();
    }

    let result = if do_uninstall {
        uninstall()
    } else {
        install(device_name.as_deref(), lock_screen)
    };
    if let Err(error) = result {
        eprintln!("Setup failed: {error}");
        let _ = fs::write(data_dir().join("setup-error.log"), format!("{error}\n"));
        std::process::exit(1);
    }
    if !no_pause {
        println!("Press Enter to close...");
        let _ = std::io::stdout().flush();
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}
