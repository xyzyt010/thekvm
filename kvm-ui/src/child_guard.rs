//! Parent-death guards for every process this app spawns.
//!
//! The supervised `connect` child and the optional user-session daemon
//! must never outlive the app: a child that survives a Task Manager kill
//! keeps driving the peer (and keeps the machine listed) with no window
//! left to stop it. Normal exits already kill children explicitly; these
//! guards cover the paths that run NO cleanup code at all:
//!
//! * Windows: one process-wide job object with KILL_ON_JOB_CLOSE. The OS
//!   closes the handle when this process dies for any reason and reaps
//!   every member with it.
//! * Linux: a process-lifetime liveness pipe. The write end lives in a
//!   static (so it belongs to the PROCESS, not to whichever thread called
//!   spawn), the child inherits the read end and exits on EOF. Linux
//!   PR_SET_PDEATHSIG is thread-scoped — tying it to a short-lived pairing
//!   thread SIGKILLed connect children milliseconds after spawn — so it is
//!   deliberately not used here.

#[cfg(target_os = "windows")]
pub fn configure(_command: &mut std::process::Command) {}

/// Windows: assign the spawned child to the kill-on-close job. Returns the
/// failure text so callers can log it; Linux needs nothing here.
#[cfg(target_os = "windows")]
pub fn adopt(child: &std::process::Child) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::AssignProcessToJobObject;

    let job = job_handle();
    if job.is_invalid() {
        return Some("parent-death job unavailable".into());
    }
    let process = HANDLE(child.as_raw_handle() as _);
    unsafe { AssignProcessToJobObject(job, process) }
        .err()
        .map(|error| format!("join parent-death job: {error}"))
}

/// The process-wide job, created once with KILL_ON_JOB_CLOSE. Stored as a
/// raw isize because HANDLE is not Send/Sync; it is never closed by us —
/// process death must be the thing that closes it.
#[cfg(target_os = "windows")]
fn job_handle() -> windows::Win32::Foundation::HANDLE {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    static JOB: std::sync::OnceLock<isize> = std::sync::OnceLock::new();
    let raw = *JOB.get_or_init(|| unsafe {
        let job = match CreateJobObjectW(None, None) {
            Ok(job) => job,
            Err(error) => {
                log_line(&format!("child guard: create job object failed: {error}"));
                return 0;
            }
        };
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Err(error) = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) {
            log_line(&format!(
                "child guard: configure job object failed: {error}"
            ));
            return 0;
        }
        job.0 as isize
    });
    HANDLE(raw as _)
}

#[cfg(target_os = "windows")]
fn log_line(message: &str) {
    use std::io::Write as _;
    let dir = crate::data_dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("ui.log"))
    {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let _ = writeln!(file, "{millis}\t{message}");
    }
}

#[cfg(target_os = "linux")]
pub const GUARD_FD_ENV: &str = "THEKVM_GUARD_FD";

#[cfg(target_os = "linux")]
struct GuardPipe {
    read: std::os::fd::RawFd,
    /// Kept open for the life of this process. Leaking it is the point:
    /// process death closes every copy, which is exactly the EOF the child
    /// watches for. It is O_CLOEXEC so no child ever inherits it.
    write: std::os::fd::RawFd,
}

#[cfg(target_os = "linux")]
fn guard_pipe() -> Option<&'static GuardPipe> {
    static PIPE: std::sync::OnceLock<Option<GuardPipe>> = std::sync::OnceLock::new();
    PIPE.get_or_init(|| {
        let mut fds = [0 as libc::c_int; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            crate::ui_log(&format!(
                "child guard: liveness pipe unavailable: {}",
                std::io::Error::last_os_error()
            ));
            return None;
        }
        Some(GuardPipe {
            read: fds[0],
            write: fds[1],
        })
    })
    .as_ref()
}

#[cfg(target_os = "linux")]
pub fn configure(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    let Some(pipe) = guard_pipe() else {
        return;
    };
    command.env(GUARD_FD_ENV, pipe.read.to_string());
    let read = pipe.read;
    let write = pipe.write;
    unsafe {
        command.pre_exec(move || {
            // Keep the read end open across exec, but never the write end
            // (O_CLOEXEC): a child holding a write copy would keep its own
            // guard alive forever.
            let _ = write;
            if libc::fcntl(read, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(target_os = "linux")]
pub fn adopt(_child: &std::process::Child) -> Option<String> {
    None
}
