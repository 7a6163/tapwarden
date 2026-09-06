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

/// A per-user, 0700 runtime directory that holds the agent socket.
///
/// Uses `$XDG_RUNTIME_DIR` (already 0700 and owned by the user) when available;
/// otherwise a uid-suffixed dir under the temp dir. Access control comes from
/// the *directory* being 0700 — never rely on the socket file's own mode bits
/// (portability: some BSDs historically ignore them).
pub fn runtime_dir() -> Result<PathBuf> {
    let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(base) => PathBuf::from(base).join("tapwarden"),
        None => std::env::temp_dir().join(format!("tapwarden-{}", uid())),
    };
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

    #[test]
    fn socket_lives_in_the_private_runtime_dir() {
        let socket = socket_path().expect("socket_path should succeed");
        assert!(socket.ends_with("agent.sock"));
        assert_eq!(socket.parent(), Some(runtime_dir().unwrap().as_path()));
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
