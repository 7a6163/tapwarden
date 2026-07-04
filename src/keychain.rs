//! macOS Keychain storage for the Vaultwarden backend credentials
//! (`credentials: keychain`). Thin wrapper over the `keyring` crate
//! (apple-native store only).
//!
//! Error messages are static on purpose — the underlying `keyring::Error` is
//! deliberately discarded because `Error::BadEncoding`'s Display embeds the
//! raw stored bytes, which would leak the secret into a printed error chain.

use anyhow::{anyhow, Result};

const SERVICE: &str = "sigilo";

/// Keychain account names for the three Vaultwarden credentials.
pub(crate) const VW_CLIENT_ID: &str = "vw_client_id";
pub(crate) const VW_CLIENT_SECRET: &str = "vw_client_secret";
pub(crate) const VW_MASTER_PASSWORD: &str = "vw_master_password";

fn entry(account: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, account)
        .map_err(|_| anyhow!("failed to open keychain entry `{account}`"))
}

pub(crate) fn store(account: &str, value: &str) -> Result<()> {
    entry(account)?
        .set_password(value)
        .map_err(|_| anyhow!("failed to store `{account}` in the keychain"))
}

pub(crate) fn read(account: &str) -> Result<String> {
    match entry(account)?.get_password() {
        Ok(value) => Ok(value),
        Err(keyring::Error::NoEntry) => Err(anyhow!(
            "keychain entry `{account}` not found — run `sigilo setup` to store it"
        )),
        Err(_) => Err(anyhow!("failed to read `{account}` from the keychain")),
    }
}

/// Best-effort removal, for re-running `sigilo setup` over existing entries.
pub(crate) fn delete(account: &str) {
    if let Ok(entry) = entry(account) {
        let _ = entry.delete_credential();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real-Keychain round trip on a dummy account. May raise a system
    /// keychain dialog, so it never runs in the default suite:
    /// `cargo test keychain_roundtrip_manual -- --ignored --nocapture`
    #[test]
    #[ignore = "touches the real macOS Keychain and may raise a dialog"]
    fn keychain_roundtrip_manual() {
        let account = "test_roundtrip";
        store(account, "dummy-value").expect("store");
        assert_eq!(read(account).expect("read"), "dummy-value");
        delete(account);
        let err = read(account).expect_err("deleted entry must be gone");
        assert!(err.to_string().contains("sigilo setup"), "{err:#}");
    }
}
