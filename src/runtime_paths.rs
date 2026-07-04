use anyhow::{bail, Context, Result};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

pub(crate) fn uid() -> u32 {
    // SAFETY: getuid() is always safe; it never fails and touches no memory.
    unsafe { libc::getuid() }
}

/// A per-user, 0700 runtime directory that holds the agent socket.
///
/// Uses `$XDG_RUNTIME_DIR` (already 0700 and owned by the user) when available;
/// otherwise a uid-suffixed dir under the temp dir. Access control comes from
/// the *directory* being 0700 — never rely on the socket file's own mode bits
/// (portability: some BSDs historically ignore them).
pub fn runtime_dir() -> Result<PathBuf> {
    let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(base) => PathBuf::from(base).join("sigilo"),
        None => std::env::temp_dir().join(format!("sigilo-{}", uid())),
    };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create runtime dir {}", dir.display()))?;
    // Reject a pre-planted path BEFORE touching permissions: chmod(2) follows
    // symlinks, so validating afterwards would first chmod an attacker-chosen
    // target (e.g. `ln -s ~victim/dir /tmp/sigilo-<uid>`). symlink_metadata
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
}
