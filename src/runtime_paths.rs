use anyhow::{Context, Result, bail};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

pub(crate) fn uid() -> u32 {
    // SAFETY: getuid() is always safe; it never fails and touches no memory.
    unsafe { libc::getuid() }
}

/// Refuse to write through a pre-planted symlink (or any non-regular file)
/// at `path`. A missing path is fine — the caller is about to create it.
pub(crate) fn reject_symlink(path: &std::path::Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() => bail!(
            "refusing to use {}: not a regular file (pre-planted symlink?)",
            path.display()
        ),
        _ => Ok(()),
    }
}

/// A per-user, 0700 runtime directory that holds the agent socket:
/// `~/Library/Application Support/tapwarden`.
///
/// Not `$TMPDIR`: macOS purges entries there that nobody touched for a few
/// days, unlinking a long-lived agent's socket while the agent keeps running.
/// Not `$XDG_RUNTIME_DIR` either: the shell and launchd disagree on it. Access
/// control comes from the *directory* being 0700 — never rely on the socket
/// file's own mode bits (portability: some BSDs historically ignore them).
pub fn runtime_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("unable to determine home directory")?;
    runtime_dir_at(home.join("Library/Application Support/tapwarden"))
}

fn runtime_dir_at(dir: PathBuf) -> Result<PathBuf> {
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create runtime dir {}", dir.display()))?;
    // Reject a pre-planted path BEFORE touching permissions: chmod(2) follows
    // symlinks, so validating afterwards would first chmod an attacker-chosen
    // target (e.g. `ln -s ~victim/dir /tmp/tapwarden-<uid>`). symlink_metadata
    // catches symlinks; a swap between this stat and the chmod would require
    // deleting a dir we own, which the sticky bit on shared temp dirs prevents.
    let meta = std::fs::symlink_metadata(&dir)
        .with_context(|| format!("failed to stat runtime dir {}", dir.display()))?;
    if !meta.is_dir() || meta.uid() != uid() {
        bail!(
            "runtime dir {} is not a directory owned by uid {}",
            dir.display(),
            uid()
        );
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to chmod 0700 {}", dir.display()))?;
    Ok(dir)
}

pub fn socket_path() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("agent.sock"))
}

/// The `~/.ssh/config` line that points ssh at `socket`, quoted because the
/// default path contains a space.
pub fn identity_agent_line(socket: &std::path::Path) -> String {
    format!("IdentityAgent \"{}\"", socket.display())
}

/// The shell line that points `SSH_AUTH_SOCK` at `socket`, single-quoted.
pub fn export_line(socket: &std::path::Path) -> String {
    let quoted = socket.display().to_string().replace('\'', r"'\''");
    format!("export SSH_AUTH_SOCK='{quoted}'")
}

/// Give an explicitly chosen socket path the same private parent directory
/// `runtime_dir` would have built — the LaunchAgent is started with the path
/// `start` printed, and that dir may have been purged since.
pub fn ensure_socket_dir(socket: &std::path::Path) -> Result<()> {
    let parent = socket
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .with_context(|| format!("socket path {} has no parent directory", socket.display()))?;
    runtime_dir_at(parent.to_path_buf()).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_dir_is_private_and_ours() {
        let dir = runtime_dir().expect("runtime_dir should succeed");
        let meta = std::fs::metadata(&dir).expect("stat");
        assert!(meta.is_dir());
        assert_eq!(meta.uid(), uid());
        assert_eq!(meta.mode() & 0o777, 0o700);
    }

    /// macOS purges $TMPDIR entries nobody touched for a few days, which
    /// unlinks a long-lived agent's socket out from under it. The socket must
    /// live somewhere the system leaves alone, and must not move with the
    /// caller's environment.
    #[test]
    fn socket_lives_outside_the_purged_temp_dir() {
        let socket = socket_path().unwrap();
        assert!(
            socket.ends_with("Library/Application Support/tapwarden/agent.sock"),
            "{}",
            socket.display()
        );
        assert!(!socket.starts_with(std::env::temp_dir()));
    }

    /// The socket path has a space in it ("Application Support"); a snippet
    /// the user pastes unquoted would split it into two arguments.
    #[test]
    fn printed_snippets_quote_the_socket_path() {
        let socket =
            std::path::Path::new("/Users/z/Library/Application Support/tapwarden/agent.sock");
        assert_eq!(
            identity_agent_line(socket),
            r#"IdentityAgent "/Users/z/Library/Application Support/tapwarden/agent.sock""#
        );
        assert_eq!(
            export_line(socket),
            "export SSH_AUTH_SOCK='/Users/z/Library/Application Support/tapwarden/agent.sock'"
        );
        assert_eq!(
            export_line(std::path::Path::new("/tmp/it's/agent.sock")),
            r"export SSH_AUTH_SOCK='/tmp/it'\''s/agent.sock'"
        );
    }

    #[test]
    fn socket_lives_in_the_private_runtime_dir() {
        let socket = socket_path().expect("socket_path should succeed");
        assert!(socket.ends_with("agent.sock"));
        assert_eq!(socket.parent(), Some(runtime_dir().unwrap().as_path()));
    }

    /// An explicit socket path (the one the LaunchAgent is started with) gets
    /// the same 0700 directory treatment as the derived one: the dir may have
    /// been purged since `start` created it.
    #[test]
    fn an_explicit_socket_path_gets_a_private_parent_dir() {
        let tmp = crate::test_support::TmpDir::new("runtime");
        let socket = tmp.join("sub/agent.sock");
        ensure_socket_dir(&socket).expect("the parent dir is created");
        let meta = std::fs::metadata(tmp.join("sub")).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.mode() & 0o777, 0o700);
        ensure_socket_dir(std::path::Path::new("agent.sock"))
            .expect_err("a socket path with no parent has nowhere to be private");
    }

    /// The attack the ordering in `runtime_dir_at` exists for: `create_dir_all`
    /// happily follows a planted symlink to a directory, so the check that
    /// refuses it has to be a `symlink_metadata` *before* the chmod.
    #[test]
    fn a_symlinked_runtime_dir_is_refused_before_it_is_chmodded() {
        let tmp = crate::test_support::TmpDir::new("runtime");
        let target = tmp.join("target");
        std::fs::create_dir(&target).unwrap();
        let planted = tmp.join("planted");
        std::os::unix::fs::symlink(&target, &planted).unwrap();

        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().mode() & 0o777;
        let before = mode(&target);

        let err = format!(
            "{:#}",
            runtime_dir_at(planted).expect_err("a symlinked runtime dir must be refused")
        );
        assert!(err.contains("not a directory owned by uid"), "{err}");
        assert_eq!(
            mode(&target),
            before,
            "the symlink target must not have been chmodded"
        );
    }

    #[test]
    fn symlinks_and_non_regular_files_are_refused() {
        let dir = crate::test_support::TmpDir::new("paths");

        let missing = dir.join("not-there");
        reject_symlink(&missing).expect("a path we are about to create is fine");

        let regular = dir.join("regular");
        std::fs::write(&regular, b"x").unwrap();
        reject_symlink(&regular).expect("a regular file is fine");

        let planted = dir.join("planted");
        std::os::unix::fs::symlink(&regular, &planted).unwrap();
        let err = format!(
            "{:#}",
            reject_symlink(&planted).expect_err("a symlink must be refused")
        );
        assert!(err.contains("regular file"), "{err}");

        reject_symlink(&dir.0).expect_err("a directory is not a regular file either");
    }
}
