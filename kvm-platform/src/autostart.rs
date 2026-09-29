//! Login auto-start for the UI: "the app starts by itself when I log in".
//!
//! Per-OS convention, no elevation, no console window, and reversible from
//! the app's own Settings switch:
//!  * Windows — a shortcut in the per-user Startup folder (no admin, no
//!    UAC, nothing machine-wide). The installer writes the very same
//!    `.lnk` next to the binaries so this module can just copy it; a
//!    PowerShell/COM fallback covers non-installer layouts.
//!  * XDG desktops (Mint et al) — a `thekvm-ui.desktop` entry in the
//!    user's `~/.config/autostart`; turning it OFF either removes that
//!    entry or, when a system-wide one exists, masks it with the XDG
//!    `Hidden=true` override (the documented per-user "no" for a
//!    system "yes"). Both spellings read back as off.
//!
//! The state lives in the OS, not in our config: the switch shows what
//! this machine will actually do at the next logon.

use crate::PlatformError;
use std::path::PathBuf;

/// Basename shared by the system autostart entry and the user override.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const DESKTOP_BASENAME: &str = "thekvm-ui.desktop";
/// Windows shortcut name (in the Startup folder).
#[cfg(target_os = "windows")]
const STARTUP_SHORTCUT: &str = "TheKVM.lnk";

/// Whether this platform can start the app at login at all.
pub const SUPPORTED: bool = cfg!(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd"
));

/// Absolute path of this executable.
fn current_exe() -> Result<PathBuf, PlatformError> {
    std::env::current_exe()
        .map_err(|error| PlatformError::Autostart(format!("locate own executable: {error}")))
}

/// The user's home directory. Mirrors the rest of kvm-platform, which
/// resolves data paths the same way on the XDG desktops we support.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn home_dir() -> Result<PathBuf, PlatformError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| PlatformError::Autostart("HOME is not set".into()))
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn user_autostart_entry() -> Result<PathBuf, PlatformError> {
    Ok(home_dir()?
        .join(".config")
        .join("autostart")
        .join(DESKTOP_BASENAME))
}

/// The desktop entry a system-wide install provides (only consulted to
/// decide whether a masking override is needed at all).
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn system_autostart_entry() -> PathBuf {
    PathBuf::from("/etc/xdg/autostart").join(DESKTOP_BASENAME)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn desktop_entry_text(executable: &std::path::Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=TheKVM\n\
         Comment=Share one mouse and keyboard between computers\n\
         Exec={}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        executable.display()
    )
}

/// Whether an autostart entry is masked off: XDG's `Hidden=true`, or
/// GNOME's vendor spelling of the same thing.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn masked(entry: &str) -> bool {
    entry.lines().any(|line| {
        let line = line.trim().replace(' ', "");
        line.eq_ignore_ascii_case("Hidden=true")
            || line.eq_ignore_ascii_case("X-GNOME-Autostart-enabled=false")
    })
}

/// Auto-start state of this machine right now.
pub fn enabled() -> Result<bool, PlatformError> {
    #[cfg(target_os = "windows")]
    {
        return Ok(startup_shortcut()?.is_file());
    }
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        let entry = user_autostart_entry()?;
        if !entry.exists() {
            // No user entry of our own: a system-wide install still
            // starts us, so that decides. A source install has neither
            // and honestly reports "off" until the user turns it on.
            return Ok(!system_autostart_entry().exists());
        }
        let text = std::fs::read_to_string(&entry).unwrap_or_default();
        return Ok(!masked(&text));
    }
    #[allow(unreachable_code)]
    Err(PlatformError::Autostart(
        "auto-start is not supported on this platform".into(),
    ))
}

/// Turn login auto-start on or off. Best effort but honest: a failure is
/// reported to the caller, so the checkbox can never claim a state the
/// machine does not have.
pub fn set_enabled(enabled: bool) -> Result<(), PlatformError> {
    #[cfg(target_os = "windows")]
    {
        return if enabled {
            install_startup_shortcut()
        } else {
            remove_startup_shortcut()
        };
    }
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        let entry = user_autostart_entry()?;
        if enabled {
            if let Some(parent) = entry.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    PlatformError::Autostart(format!("create {}: {error}", parent.display()))
                })?;
            }
            // Drop an existing mask first, then (re)write the entry so an
            // upgrade that moved the binary refreshes Exec.
            let _ = std::fs::remove_file(&entry);
            return std::fs::write(&entry, desktop_entry_text(&current_exe()?)).map_err(|error| {
                PlatformError::Autostart(format!("write {}: {error}", entry.display()))
            });
        }
        return match std::fs::remove_file(&entry) {
            Ok(()) => Ok(()),
            // Already off: a system-wide install still starts us, so mask
            // it with the XDG override instead of doing nothing.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if system_autostart_entry().exists() {
                    return std::fs::write(
                        &entry,
                        "[Desktop Entry]\nType=Application\nName=TheKVM\nHidden=true\n",
                    )
                    .map_err(|error| {
                        PlatformError::Autostart(format!("write {}: {error}", entry.display()))
                    });
                }
                return Ok(());
            }
            Err(error) => Err(PlatformError::Autostart(format!(
                "remove {}: {error}",
                entry.display()
            ))),
        };
    }
    #[allow(unreachable_code)]
    Err(PlatformError::Autostart(
        "auto-start is not supported on this platform".into(),
    ))
}

#[cfg(target_os = "windows")]
fn startup_dir() -> Result<PathBuf, PlatformError> {
    let appdata = std::env::var_os("APPDATA")
        .ok_or_else(|| PlatformError::Autostart("APPDATA is not set (no user profile?)".into()))?;
    Ok(PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup"))
}

#[cfg(target_os = "windows")]
fn startup_shortcut() -> Result<PathBuf, PlatformError> {
    Ok(startup_dir()?.join(STARTUP_SHORTCUT))
}

#[cfg(target_os = "windows")]
fn remove_startup_shortcut() -> Result<(), PlatformError> {
    let path = startup_shortcut()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PlatformError::Autostart(format!(
            "remove {}: {error}",
            path.display()
        ))),
    }
}

/// Put a Startup-folder shortcut to this UI in place.
///
/// The installer writes the very same `TheKVM.lnk` next to the binaries
/// (`packaging/windows/thekvm.iss`), so the normal path is a plain file
/// copy: no PowerShell, no console flash, no elevation. Only a layout
/// without that template falls back to the shell's own shortcut writer,
/// and even then `output()` always returns, so a wedged shell can never
/// hang the UI thread.
#[cfg(target_os = "windows")]
fn install_startup_shortcut() -> Result<(), PlatformError> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let dir = startup_dir()?;
    std::fs::create_dir_all(&dir)
        .map_err(|error| PlatformError::Autostart(format!("create {}: {error}", dir.display())))?;
    let target = startup_shortcut()?;
    let executable = current_exe()?;

    // 1) The installer's template next to the binaries (preferred).
    if let Some(installed) = executable.parent().map(|dir| dir.join(STARTUP_SHORTCUT)) {
        if installed.is_file() && std::fs::copy(&installed, &target).is_ok() {
            return Ok(());
        }
    }
    // 2) A Startup shortcut already in place is exactly what we want.
    if target.is_file() {
        return Ok(());
    }
    // 3) Fallback: let the shell write the .lnk for us, hidden.
    let script = format!(
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}'); \
         $s.TargetPath='{}'; $s.WorkingDirectory='{}'; $s.Save()",
        target.display(),
        executable.display(),
        executable
            .parent()
            .map(|dir| dir.display().to_string())
            .unwrap_or_default()
    );
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| PlatformError::Autostart(format!("run PowerShell: {error}")))?;
    if !output.status.success() || !target.is_file() {
        return Err(PlatformError::Autostart(format!(
            "Startup shortcut was not created (PowerShell said {})",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[test]
    fn xdg_masking_is_recognized_in_either_spelling() {
        // The XDG override masks with Hidden=true; GNOME's own key says
        // the same thing with a vendor prefix. Both must read as OFF.
        assert!(super::masked("[Desktop Entry]\nHidden=true\n"));
        assert!(super::masked(
            "[Desktop Entry]\nX-GNOME-Autostart-enabled=false\n"
        ));
        assert!(!super::masked("[Desktop Entry]\nExec=/usr/bin/kvm-ui\n"));
        // Case-insensitive, whitespace tolerant.
        assert!(super::masked("  hidden = TRUE "));
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[test]
    fn desktop_entry_is_a_valid_gnome_autostart_file() {
        use std::path::PathBuf;
        let entry = super::desktop_entry_text(&PathBuf::from("/usr/bin/kvm-ui"));
        assert!(entry.starts_with("[Desktop Entry]"));
        assert!(entry.contains("Type=Application"));
        assert!(entry.contains("Exec=/usr/bin/kvm-ui"));
        // Terminal=false is what keeps a launcher from flashing a shell.
        assert!(entry.contains("Terminal=false"));
        // A freshly written entry must read back as ON.
        assert!(!super::masked(&entry));
    }
}
