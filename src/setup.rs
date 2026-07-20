//! `tapwarden setup` — interactive wizard for the Vaultwarden backend. Logs in
//! with the master password once, obtains the personal API key
//! (client_id/client_secret) so the user never clicks through the web vault,
//! lists the account's SSH-key items, and writes `~/.config/tapwarden/config.yaml`.
//!
//! Protocol verified against vaultwarden `src/api/identity.rs` (password
//! grant, 2FA error shape) and `src/api/core/accounts.rs` (prelogin,
//! api-key, profile). The master password and derived keys live in memory
//! only for the duration of the wizard and are never echoed, stored, or
//! embedded in error messages.

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::io::Write;
use std::path::PathBuf;
use uuid::Uuid;

use crate::config::{CONFIG_REL, CredentialSource};
use crate::keychain;
use crate::secret_source::{
    EncString, MAX_SYNC_RESPONSE_BYTES, SymKey, http_client, json_capped, json_capped_limit,
};
use crate::vaultwarden::{
    CIPHER_TYPE_SSH_KEY, CLIENT_VERSION, CLIENT_VERSION_HEADER, DEVICE_IDENTIFIER, DEVICE_NAME,
    DEVICE_TYPE, KdfParams, derive_master_key, resolve_cipher_key, server_auth_hash,
    stretch_master_key, validate_server_url,
};

/// TwoFactorType::Authenticator (TOTP) in vaultwarden's `TwoFactorType`.
const TOTP_PROVIDER: &str = "0";

/// `POST /identity/accounts/prelogin` response (vaultwarden `prelogin()`).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreloginResponse {
    kdf: u32,
    kdf_iterations: u32,
    #[serde(default)]
    kdf_memory: Option<u32>,
    #[serde(default)]
    kdf_parallelism: Option<u32>,
}

impl From<PreloginResponse> for KdfParams {
    fn from(p: PreloginResponse) -> Self {
        KdfParams {
            kdf: p.kdf,
            iterations: p.kdf_iterations,
            memory: p.kdf_memory,
            parallelism: p.kdf_parallelism,
        }
    }
}

/// Successful password-grant response. No Debug on purpose: bearer + user key.
#[derive(Deserialize)]
struct TokenSuccess {
    access_token: String,
    /// The user key (EncString) wrapped by the stretched master key.
    #[serde(rename = "Key")]
    key: String,
}

/// The 2FA-required error body (vaultwarden `json_err_twofactor()`): HTTP 400
/// with `TwoFactorProviders` as an array of provider ids as *strings*.
#[derive(Deserialize)]
struct TwoFactorError {
    #[serde(rename = "TwoFactorProviders", default)]
    two_factor_providers: Vec<String>,
}

/// `POST /api/accounts/api-key` response (vaultwarden `update_api_key()`).
/// No Debug on purpose: the api key is the client_secret.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeyResponse {
    api_key: String,
}

/// `GET /api/accounts/profile` (vaultwarden `User::to_json`): `id` is the
/// user uuid, which forms the personal-API-key client_id `user.<uuid>`.
#[derive(Deserialize)]
struct ProfileResponse {
    id: Uuid,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncResponse {
    ciphers: Vec<SyncCipher>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncCipher {
    id: Uuid,
    #[serde(rename = "type")]
    atype: u32,
    #[serde(default)]
    organization_id: Option<String>,
    /// Cipher-key encryption: item key wrapped by the user key.
    #[serde(default)]
    key: Option<String>,
    /// EncString.
    name: String,
}

enum LoginOutcome {
    Success(TokenSuccess),
    TwoFactorRequired(Vec<String>),
}

pub async fn run() -> Result<()> {
    println!("tapwarden setup — Vaultwarden backend");
    println!("Use the DEDICATED account that holds only tapwarden's SSH keys.\n");

    let server_url = {
        let url = prompt("Server URL (https://...): ")?;
        validate_server_url(&url)?;
        url.trim_end_matches('/').to_string()
    };
    let email = prompt("Account email: ")?;
    validate_email(&email)?;
    let master_password = rpassword::prompt_password("Master password (hidden): ")
        .context("failed to read the master password")?;

    let http = http_client()?;

    let kdf: KdfParams = prelogin(&http, &server_url, &email).await?.into();
    let master_key = derive_master_key(&master_password, &email, &kdf)
        .context("setup failed: master key derivation")?;
    let password_hash = server_auth_hash(&master_key, &master_password);
    // master_password is kept (memory only) until the storage decision below:
    // the keychain path stores it so the agent can run without env vars.

    let token = password_login(&http, &server_url, &email, &password_hash).await?;
    println!("Logged in.");

    let user_key = EncString::parse(&token.key)
        .context("login failed: bad user key EncString")?
        .decrypt(&stretch_master_key(&master_key))
        .context("login failed: user key decryption")
        .and_then(|bytes| SymKey::from_bytes(&bytes))
        .context("login failed: bad user key")?;

    let client_secret = fetch_api_key(&http, &server_url, &token.access_token, &password_hash)
        .await?
        .api_key;
    let client_id = format!(
        "user.{}",
        fetch_profile(&http, &server_url, &token.access_token)
            .await?
            .id
    );
    println!("Obtained the personal API key.");

    let answer = prompt("Store credentials in the macOS Keychain? [Y/n]: ")?;
    let credentials = if answer.is_empty() || answer.eq_ignore_ascii_case("y") {
        CredentialSource::Keychain
    } else {
        CredentialSource::Env
    };

    let ciphers = fetch_sync(&http, &server_url, &token.access_token)
        .await?
        .ciphers;
    let items = ssh_key_items(ciphers, &user_key)?;
    if items.is_empty() {
        bail!(
            "no SSH-key items (type 5) found in this account's personal vault; create one in the \
             web vault (the server needs EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item)"
        );
    }
    println!("\nSSH keys in this account:");
    for (i, (_, name)) in items.iter().enumerate() {
        println!("  {}. {name}", i + 1);
    }
    let selection = prompt("Keys tapwarden should serve (comma-separated numbers, empty = all): ")?;
    let chosen: Vec<Uuid> = select_indices(&selection, items.len())?
        .into_iter()
        .map(|i| items[i].0)
        .collect();

    // Keychain stores happen BEFORE the config write: a mid-loop failure must
    // not leave a config on disk that points at keychain entries that were
    // never stored. (The reverse leftover — entries stored but no config —
    // is harmless and overwritten by the next setup run.)
    if credentials == CredentialSource::Keychain {
        for (account, value) in [
            (keychain::VW_CLIENT_ID, client_id.as_str()),
            (keychain::VW_CLIENT_SECRET, client_secret.as_str()),
            (keychain::VW_MASTER_PASSWORD, master_password.as_str()),
        ] {
            keychain::delete(account);
            keychain::store(account, value)?;
        }
    }

    let path = config_path()?;
    write_config_file(
        &path,
        &render_config(&server_url, &email, &chosen, credentials)?,
    )?;
    println!("\nWrote {} (mode 0600, no secrets inside).", path.display());

    match credentials {
        CredentialSource::Keychain => {
            println!("\nStored the credentials in the macOS Keychain (service \"tapwarden\").");
            println!("Every agent read of them is gated by a Touch ID prompt; no env vars needed.");
        }
        CredentialSource::Env => {
            println!(
                "\nAdd these to your environment (e.g. ~/.zshenv — keep them out of anything world-readable):\n"
            );
            println!("  export TAPWARDEN_VW_CLIENT_ID='{client_id}'");
            println!("  export TAPWARDEN_VW_CLIENT_SECRET='{client_secret}'");
            println!("  export TAPWARDEN_VW_MASTER_PASSWORD='<type your master password here>'");
            println!(
                "\ntapwarden never stores or prints the master password; fill it in yourself."
            );
        }
    }
    Ok(())
}

async fn prelogin(
    http: &reqwest::Client,
    server_url: &str,
    email: &str,
) -> Result<PreloginResponse> {
    let response = http
        .post(format!("{server_url}/identity/accounts/prelogin"))
        .header(reqwest::header::ACCEPT, "application/json")
        .header(CLIENT_VERSION_HEADER, CLIENT_VERSION)
        .json(&serde_json::json!({ "email": email }))
        .send()
        .await
        .context("prelogin failed: request error")?;
    let status = response.status();
    if !status.is_success() {
        bail!("prelogin failed: HTTP {status}");
    }
    json_capped(response).await.context("prelogin failed")
}

/// Password-grant login with a single TOTP retry. Fields verified against
/// vaultwarden `ConnectData` / `password_login()`: grant_type, username,
/// password (= the server auth hash), scope `api offline_access`, client_id,
/// deviceIdentifier/deviceName/deviceType, and for 2FA twoFactorProvider /
/// twoFactorToken. Vaultwarden does not require an auth-email header.
async fn password_login(
    http: &reqwest::Client,
    server_url: &str,
    email: &str,
    password_hash: &str,
) -> Result<TokenSuccess> {
    match login_attempt(http, server_url, email, password_hash, None).await? {
        LoginOutcome::Success(token) => Ok(token),
        LoginOutcome::TwoFactorRequired(providers) => {
            if !providers.iter().any(|p| p == TOTP_PROVIDER) {
                bail!(
                    "this account requires a two-factor method tapwarden setup does not support; \
                     use an account with TOTP (authenticator app) or no 2FA"
                );
            }
            let code = prompt("Two-factor TOTP code: ")?;
            match login_attempt(http, server_url, email, password_hash, Some(&code)).await? {
                LoginOutcome::Success(token) => Ok(token),
                LoginOutcome::TwoFactorRequired(_) => {
                    bail!("login failed: two-factor code rejected")
                }
            }
        }
    }
}

async fn login_attempt(
    http: &reqwest::Client,
    server_url: &str,
    email: &str,
    password_hash: &str,
    totp: Option<&str>,
) -> Result<LoginOutcome> {
    let mut form = vec![
        ("grant_type", "password"),
        ("username", email),
        ("password", password_hash),
        ("scope", "api offline_access"),
        ("client_id", "cli"),
        ("deviceIdentifier", DEVICE_IDENTIFIER),
        ("deviceName", DEVICE_NAME),
        ("deviceType", DEVICE_TYPE),
    ];
    if let Some(code) = totp {
        form.push(("twoFactorProvider", TOTP_PROVIDER));
        form.push(("twoFactorToken", code));
    }
    let response = http
        .post(format!("{server_url}/identity/connect/token"))
        .header(reqwest::header::ACCEPT, "application/json")
        .header(CLIENT_VERSION_HEADER, CLIENT_VERSION)
        .form(&form)
        .send()
        .await
        .context("login failed: request error")?;

    let status = response.status();
    if status.is_success() {
        return Ok(LoginOutcome::Success(
            json_capped(response).await.context("login failed")?,
        ));
    }
    // The error body is parsed only to detect the 2FA case; it is never
    // echoed (vaultwarden error bodies can contain request parameters).
    if let Ok(err) = json_capped::<TwoFactorError>(response).await {
        if !err.two_factor_providers.is_empty() {
            return Ok(LoginOutcome::TwoFactorRequired(err.two_factor_providers));
        }
    }
    bail!(
        "login failed: HTTP {status} (wrong email/master password or two-factor code; if the \
         server requires new-device email verification, complete it and retry)"
    );
}

async fn fetch_api_key(
    http: &reqwest::Client,
    server_url: &str,
    bearer: &str,
    password_hash: &str,
) -> Result<ApiKeyResponse> {
    let response = http
        .post(format!("{server_url}/api/accounts/api-key"))
        .bearer_auth(bearer)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(CLIENT_VERSION_HEADER, CLIENT_VERSION)
        .json(&serde_json::json!({ "masterPasswordHash": password_hash }))
        .send()
        .await
        .context("api-key request failed: request error")?;
    let status = response.status();
    if !status.is_success() {
        bail!("api-key request failed: HTTP {status}");
    }
    json_capped(response)
        .await
        .context("api-key request failed")
}

async fn fetch_profile(
    http: &reqwest::Client,
    server_url: &str,
    bearer: &str,
) -> Result<ProfileResponse> {
    let response = http
        .get(format!("{server_url}/api/accounts/profile"))
        .bearer_auth(bearer)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(CLIENT_VERSION_HEADER, CLIENT_VERSION)
        .send()
        .await
        .context("profile fetch failed: request error")?;
    let status = response.status();
    if !status.is_success() {
        bail!("profile fetch failed: HTTP {status}");
    }
    json_capped(response).await.context("profile fetch failed")
}

async fn fetch_sync(
    http: &reqwest::Client,
    server_url: &str,
    bearer: &str,
) -> Result<SyncResponse> {
    let response = http
        .get(format!("{server_url}/api/sync"))
        .bearer_auth(bearer)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(CLIENT_VERSION_HEADER, CLIENT_VERSION)
        .send()
        .await
        .context("sync failed: request error")?;
    let status = response.status();
    if !status.is_success() {
        bail!("sync failed: HTTP {status}");
    }
    // The sync payload is the entire vault — needs the larger (still hard) cap.
    json_capped_limit(response, MAX_SYNC_RESPONSE_BYTES)
        .await
        .context("sync failed")
}

/// Personal-vault SSH-key items (type 5, not org-owned) with decrypted names.
fn ssh_key_items(ciphers: Vec<SyncCipher>, user_key: &SymKey) -> Result<Vec<(Uuid, String)>> {
    ciphers
        .into_iter()
        .filter(|c| c.atype == CIPHER_TYPE_SSH_KEY && c.organization_id.is_none())
        .map(|c| {
            let item_key = resolve_cipher_key(c.key.as_deref(), user_key)?;
            let key = item_key.as_ref().unwrap_or(user_key);
            let name = EncString::parse(&c.name)?
                .decrypt_to_string(key)
                .context("cipher name decryption")?;
            Ok((c.id, name))
        })
        .collect()
}

/// Parse a 1-based comma-separated selection; empty input selects everything.
fn select_indices(input: &str, len: usize) -> Result<Vec<usize>> {
    let input = input.trim();
    if input.is_empty() {
        return Ok((0..len).collect());
    }
    let mut indices = Vec::new();
    for part in input.split(',') {
        let n: usize = part
            .trim()
            .parse()
            .map_err(|_| anyhow!("invalid selection: expected comma-separated numbers"))?;
        if n == 0 || n > len {
            bail!("invalid selection: numbers must be between 1 and {len}");
        }
        if !indices.contains(&(n - 1)) {
            indices.push(n - 1);
        }
    }
    Ok(indices)
}

fn validate_email(email: &str) -> Result<()> {
    if !email.contains('@')
        || email
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\\')
    {
        bail!("email must look like user@host");
    }
    Ok(())
}

/// Render the config. No secrets in either variant: `keychain` points at the
/// macOS Keychain entries, `env` implies only env var *names* (the defaults
/// TAPWARDEN_VW_* are baked into the config schema).
fn render_config(
    server_url: &str,
    email: &str,
    secret_ids: &[Uuid],
    credentials: CredentialSource,
) -> Result<String> {
    let (comment, source) = match credentials {
        CredentialSource::Keychain => (
            "# Written by `tapwarden setup`. Credentials live ONLY in the macOS Keychain\n\
             # (service \"tapwarden\"); every read is gated by a Touch ID prompt.\n",
            "keychain",
        ),
        CredentialSource::Env => (
            "# Written by `tapwarden setup`. Credentials live ONLY in the env vars\n\
             # TAPWARDEN_VW_CLIENT_ID / TAPWARDEN_VW_CLIENT_SECRET / TAPWARDEN_VW_MASTER_PASSWORD.\n",
            "env",
        ),
    };
    let mut cfg = format!(
        "{comment}\
         backend: vaultwarden\n\
         vaultwarden:\n\
         \x20 server_url: {}\n\
         \x20 email: {}\n\
         \x20 credentials: {source}\n\
         secret_ids:\n",
        yaml_quoted(server_url)?,
        yaml_quoted(email)?,
    );
    for id in secret_ids {
        cfg.push_str(&format!("  - {id}\n"));
    }
    cfg.push_str("authorization:\n  mode: per_use\n  grace_seconds: 60\n");
    Ok(cfg)
}

fn yaml_quoted(value: &str) -> Result<String> {
    if value
        .chars()
        .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        bail!("value contains characters that cannot be written to the config");
    }
    Ok(format!("\"{value}\""))
}

fn config_path() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("unable to determine home directory")?
        .join(CONFIG_REL))
}

/// Write the config with mode 0600; an existing file requires an explicit
/// y/N confirmation before being overwritten.
fn write_config_file(path: &std::path::Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    crate::runtime_paths::reject_symlink(path)?;
    if path.exists() {
        println!("Config file {} already exists.", path.display());
        let answer = prompt("Overwrite it? [y/N]: ")?;
        if !answer.eq_ignore_ascii_case("y") {
            bail!("aborted: the existing config file was left untouched");
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("failed to create the config directory")?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .context("failed to open the config file for writing")?;
    file.write_all(contents.as_bytes())
        .context("failed to write the config file")?;
    // mode() only applies at creation; tighten a pre-existing file too.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .context("failed to set config file permissions")?;
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    std::io::stdout()
        .flush()
        .context("failed to flush stdout")?;
    let mut line = String::new();
    if std::io::stdin()
        .read_line(&mut line)
        .context("failed to read input")?
        == 0
    {
        bail!("input closed");
    }
    Ok(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_source::make_enc_string;
    use serde_json::json;

    // SDK vector (bitwarden-crypto master_key.rs `test_password_hash_pbkdf2`):
    // the hoisted server_auth_hash must reproduce the published hash.
    #[test]
    fn server_auth_hash_matches_sdk_vector() {
        let kdf = KdfParams {
            kdf: 0,
            iterations: 100_000,
            memory: None,
            parallelism: None,
        };
        let key = derive_master_key("asdfasdf", "test@bitwarden.com", &kdf).unwrap();
        assert_eq!(
            server_auth_hash(&key, "asdfasdf"),
            "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw="
        );
    }

    // Shape from vaultwarden accounts.rs `prelogin()` (camelCase keys).
    #[test]
    fn parses_prelogin_response() {
        let argon: PreloginResponse = serde_json::from_value(json!({
            "kdf": 1, "kdfIterations": 4, "kdfMemory": 64, "kdfParallelism": 4
        }))
        .unwrap();
        let kdf: KdfParams = argon.into();
        assert_eq!((kdf.kdf, kdf.iterations), (1, 4));
        assert_eq!((kdf.memory, kdf.parallelism), (Some(64), Some(4)));

        let pbkdf2: PreloginResponse = serde_json::from_value(json!({
            "kdf": 0, "kdfIterations": 600_000, "kdfMemory": null, "kdfParallelism": null
        }))
        .unwrap();
        let kdf: KdfParams = pbkdf2.into();
        assert_eq!((kdf.kdf, kdf.iterations), (0, 600_000));
        assert_eq!((kdf.memory, kdf.parallelism), (None, None));
    }

    // Shape from vaultwarden identity.rs `json_err_twofactor()`.
    #[test]
    fn parses_two_factor_error_and_detects_totp() {
        let err: TwoFactorError = serde_json::from_value(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0", "3"],
            "TwoFactorProviders2": {"0": null, "3": {"Nfc": true}},
            "MasterPasswordPolicy": {"Object": "masterPasswordPolicy"}
        }))
        .unwrap();
        assert_eq!(err.two_factor_providers, vec!["0", "3"]);
        assert!(err.two_factor_providers.iter().any(|p| p == TOTP_PROVIDER));

        // A plain error body (no providers) must not look like a 2FA error.
        let plain: TwoFactorError =
            serde_json::from_value(json!({"error": "invalid_grant"})).unwrap();
        assert!(plain.two_factor_providers.is_empty());
    }

    // Shape from vaultwarden accounts.rs `update_api_key()`.
    #[test]
    fn parses_api_key_response() {
        let resp: ApiKeyResponse = serde_json::from_value(json!({
            "apiKey": "abc123secret",
            "revisionDate": "2026-07-04T00:00:00.000000Z",
            "object": "apiKey"
        }))
        .unwrap();
        assert_eq!(resp.api_key, "abc123secret");
    }

    // Shape from vaultwarden user.rs `User::to_json()` (profile endpoint).
    #[test]
    fn parses_profile_response() {
        let resp: ProfileResponse = serde_json::from_value(json!({
            "_status": 0,
            "id": "b9b64ee8-0000-0000-0000-000000000000",
            "name": "tapwarden",
            "email": "tapwarden@example.com",
            "object": "profile"
        }))
        .unwrap();
        assert_eq!(resp.id.to_string(), "b9b64ee8-0000-0000-0000-000000000000");
    }

    fn user_key() -> SymKey {
        SymKey {
            enc: [0x11; 32],
            mac: [0x22; 32],
        }
    }

    #[test]
    fn filters_sync_ciphers_to_personal_type5_and_decrypts_names() {
        let user = user_key();
        let item = SymKey {
            enc: [0x55; 32],
            mac: [0x66; 32],
        };
        let mut wrapped_item_key = item.enc.to_vec();
        wrapped_item_key.extend_from_slice(&item.mac);
        let ciphers: SyncResponse = serde_json::from_value(json!({
            "ciphers": [
                // type 5 under the user key: kept.
                {"id": "11111111-0000-0000-0000-000000000000", "type": 5,
                 "organizationId": null, "key": null,
                 "name": make_enc_string(b"deploy-key", &user, [0x01; 16])},
                // type 1 (Login): filtered out.
                {"id": "22222222-0000-0000-0000-000000000000", "type": 1,
                 "organizationId": null, "key": null,
                 "name": make_enc_string(b"a-login", &user, [0x02; 16])},
                // org-owned type 5: filtered out.
                {"id": "33333333-0000-0000-0000-000000000000", "type": 5,
                 "organizationId": "0a0a0a0a-0000-0000-0000-000000000000", "key": null,
                 "name": make_enc_string(b"org-key", &user, [0x03; 16])},
                // type 5 with an individual item key: kept, name under item key.
                {"id": "44444444-0000-0000-0000-000000000000", "type": 5,
                 "organizationId": null,
                 "key": make_enc_string(&wrapped_item_key, &user, [0x04; 16]),
                 "name": make_enc_string(b"backup-key", &item, [0x05; 16])},
            ]
        }))
        .unwrap();

        let items = ssh_key_items(ciphers.ciphers, &user).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].1, "deploy-key");
        assert_eq!(items[1].1, "backup-key");
        assert_eq!(
            items[1].0.to_string(),
            "44444444-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn selects_indices_from_user_input() {
        assert_eq!(select_indices("", 3).unwrap(), vec![0, 1, 2]);
        assert_eq!(select_indices("2", 3).unwrap(), vec![1]);
        assert_eq!(select_indices(" 3 , 1 ", 3).unwrap(), vec![2, 0]);
        assert_eq!(select_indices("1,1,2", 3).unwrap(), vec![0, 1]); // deduped
        assert!(select_indices("0", 3).is_err());
        assert!(select_indices("4", 3).is_err());
        assert!(select_indices("a", 3).is_err());
    }

    #[test]
    fn rendered_config_round_trips_through_the_config_parser() {
        let ids = [
            Uuid::parse_str("11111111-0000-0000-0000-000000000000").unwrap(),
            Uuid::parse_str("44444444-0000-0000-0000-000000000000").unwrap(),
        ];
        for credentials in [CredentialSource::Keychain, CredentialSource::Env] {
            let yaml = render_config(
                "https://vault.example.com",
                "tapwarden@example.com",
                &ids,
                credentials,
            )
            .unwrap();
            // No credential material may ever appear in the file.
            assert!(!yaml.to_lowercase().contains("password:"));
            assert!(!yaml.contains("client_secret:"));

            let cfg: crate::config::Config = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(cfg.backend, crate::config::Backend::Vaultwarden);
            let vw = cfg.vaultwarden.expect("vaultwarden section");
            assert_eq!(vw.credentials, credentials);
            assert_eq!(vw.server_url, "https://vault.example.com");
            assert_eq!(vw.email, "tapwarden@example.com");
            assert_eq!(vw.client_id_env, "TAPWARDEN_VW_CLIENT_ID");
            assert_eq!(
                cfg.secret_ids,
                vec![
                    "11111111-0000-0000-0000-000000000000",
                    "44444444-0000-0000-0000-000000000000"
                ]
            );
            assert_eq!(cfg.authorization.mode, crate::config::AuthMode::PerUse);
        }
    }

    #[test]
    fn rejects_unwritable_values_and_bad_emails() {
        assert!(yaml_quoted("has\"quote").is_err());
        assert!(yaml_quoted("has\nnewline").is_err());
        assert!(validate_email("no-at-sign").is_err());
        assert!(validate_email("spaced @example.com").is_err());
        assert!(validate_email("tapwarden@example.com").is_ok());
    }
}
