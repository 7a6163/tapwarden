//! Who is on the other end of an agent connection, so the presence prompt can
//! name the process asking for a signature instead of only the key.
//!
//! Advisory, not an access check. A same-uid process can name its binary
//! anything, and a pid can be reused between the lookup and the prompt. What
//! it buys is a prompt that reads differently when the request did not come
//! from the `ssh` or `git` the user just started — the Authorizer remains the
//! gate.

use std::path::PathBuf;

/// One process, as far as the kernel will say.
struct Process {
    pid: libc::pid_t,
    path: Option<PathBuf>,
}

impl Process {
    fn lookup(pid: libc::pid_t) -> Self {
        Self {
            pid,
            path: executable_path(pid),
        }
    }
}

impl std::fmt::Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{} (pid {})", path.display(), self.pid),
            None => write!(f, "pid {}", self.pid),
        }
    }
}

/// Describe the process `pid` and the one that started it, e.g.
/// `/usr/bin/ssh (pid 812), started by /opt/homebrew/bin/git (pid 790)`.
/// The parent is what tells a user-started `ssh` from one a script spawned.
/// launchd (pid 1) is left out: it parents every orphan and says nothing.
pub fn describe(pid: libc::pid_t) -> String {
    describe_with(Process::lookup(pid), parent_pid(pid).map(Process::lookup))
}

fn describe_with(requester: Process, parent: Option<Process>) -> String {
    match parent.filter(|p| p.pid > 1) {
        Some(parent) => format!("{requester}, started by {parent}"),
        None => requester.to_string(),
    }
}

#[cfg(target_os = "macos")]
fn executable_path(pid: libc::pid_t) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is writable for exactly the length passed; the kernel
    // writes at most that many bytes and returns how many it wrote.
    let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if len <= 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

#[cfg(target_os = "macos")]
fn parent_pid(pid: libc::pid_t) -> Option<libc::pid_t> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is writable for `size` bytes, and a zeroed proc_bsdinfo
    // (plain integers and byte arrays) is a valid value.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    // Anything short of the full struct is a failure, not a partial answer.
    // SAFETY: zero-initialized above, so it is valid even if the call wrote nothing.
    (written == size).then(|| unsafe { info.assume_init() }.pbi_ppid as libc::pid_t)
}

#[cfg(not(target_os = "macos"))]
fn executable_path(_pid: libc::pid_t) -> Option<PathBuf> {
    None
}

#[cfg(not(target_os = "macos"))]
fn parent_pid(_pid: libc::pid_t) -> Option<libc::pid_t> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: libc::pid_t, path: Option<&str>) -> Process {
        Process {
            pid,
            path: path.map(PathBuf::from),
        }
    }

    #[test]
    fn names_the_requester_and_its_parent() {
        assert_eq!(
            describe_with(
                process(812, Some("/usr/bin/ssh")),
                Some(process(790, Some("/opt/homebrew/bin/git")))
            ),
            "/usr/bin/ssh (pid 812), started by /opt/homebrew/bin/git (pid 790)"
        );
    }

    #[test]
    fn falls_back_to_the_pid_when_the_path_is_unknown() {
        assert_eq!(
            describe_with(process(812, None), Some(process(790, None))),
            "pid 812, started by pid 790"
        );
    }

    #[test]
    fn leaves_out_launchd_and_a_missing_parent() {
        let ssh = || process(812, Some("/usr/bin/ssh"));
        let expected = "/usr/bin/ssh (pid 812)";
        assert_eq!(
            describe_with(ssh(), Some(process(1, Some("/sbin/launchd")))),
            expected
        );
        assert_eq!(describe_with(ssh(), Some(process(0, None))), expected);
        assert_eq!(describe_with(ssh(), None), expected);
    }

    /// The real kernel lookups, against the one process certain to exist.
    #[test]
    fn looks_up_this_process_and_its_parent() {
        let pid = std::process::id() as libc::pid_t;
        assert_eq!(
            executable_path(pid).as_deref(),
            Some(
                std::env::current_exe()
                    .unwrap()
                    .canonicalize()
                    .unwrap()
                    .as_path()
            )
        );
        assert_eq!(
            parent_pid(pid),
            Some(std::os::unix::process::parent_id() as libc::pid_t)
        );

        let described = describe(pid);
        assert!(
            described.starts_with(&format!(
                "{} (pid {pid})",
                executable_path(pid).unwrap().display()
            )),
            "{described}"
        );
    }

    #[test]
    fn a_pid_that_does_not_exist_resolves_to_nothing() {
        assert_eq!(executable_path(-1), None);
        assert_eq!(parent_pid(-1), None);
        assert_eq!(describe(-1), "pid -1");
    }
}
