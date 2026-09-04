//! Read-only platform capability checks used by `kvm-daemon doctor`.

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub name: &'static str,
    pub available: bool,
    pub detail: String,
}

pub fn checks() -> Vec<Diagnostic> {
    let mut checks = vec![Diagnostic {
        name: "target",
        available: true,
        detail: format!("{} / {}", std::env::consts::OS, std::env::consts::ARCH),
    }];

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let _uinput_available = {
        let uinput = readable_check("virtual input device", Path::new("/dev/uinput"));
        let uinput_available = uinput.available;
        checks.push(uinput);
        checks.push(directory_check(
            "physical input directory",
            Path::new("/dev/input"),
        ));
        uinput_available
    };

    #[cfg(target_os = "linux")]
    {
        checks.push(environment_check("WAYLAND_DISPLAY"));
        checks.push(environment_check("DISPLAY"));
        checks.push(environment_check("XDG_RUNTIME_DIR"));
        checks.push(environment_check("DBUS_SESSION_BUS_ADDRESS"));
        checks.push(Diagnostic {
            name: "topology capture order",
            available: true,
            detail: "Wayland portal/libei, then XInput2, then evdev".into(),
        });
        checks.push(Diagnostic {
            name: "pre-login receiver",
            available: _uinput_available,
            detail: "requires a boot-start daemon with writable /dev/uinput".into(),
        });
    }

    #[cfg(target_os = "windows")]
    {
        let service_mode = std::env::args().any(|argument| argument == "--service");
        checks.push(Diagnostic {
            name: "Windows service mode",
            available: service_mode,
            detail: if service_mode {
                "this process was started with the LocalSystem service flag".into()
            } else {
                "ordinary user process; Winlogon input requires the installed service".into()
            },
        });
    }

    #[cfg(target_os = "freebsd")]
    checks.push(Diagnostic {
        name: "FreeBSD receiver",
        available: Path::new("/dev/uinput").exists(),
        detail: "requires evdev/uinput kernel modules and devfs permissions".into(),
    });

    checks
}

#[cfg(target_os = "linux")]
fn environment_check(name: &'static str) -> Diagnostic {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Diagnostic {
            name,
            available: true,
            detail: "set".into(),
        },
        _ => Diagnostic {
            name,
            available: false,
            detail: "not set in this process environment".into(),
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn readable_check(name: &'static str, path: &Path) -> Diagnostic {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(_) => Diagnostic {
            name,
            available: true,
            detail: format!("{} is present and writable", path.display()),
        },
        Err(error) => Diagnostic {
            name,
            available: false,
            detail: format!("cannot open {} read/write: {error}", path.display()),
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn directory_check(name: &'static str, path: &Path) -> Diagnostic {
    match std::fs::read_dir(path) {
        Ok(entries) => Diagnostic {
            name,
            available: true,
            detail: format!(
                "{} is present ({} entries visible)",
                path.display(),
                entries.count()
            ),
        },
        Err(error) => Diagnostic {
            name,
            available: false,
            detail: format!("cannot read {}: {error}", path.display()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::checks;

    #[test]
    fn diagnostics_have_stable_nonempty_names() {
        let checks = checks();
        assert!(!checks.is_empty());
        assert!(checks.iter().all(|check| !check.name.trim().is_empty()));
    }
}
