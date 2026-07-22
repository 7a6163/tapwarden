use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::path::PathBuf;

pub const CONFIG_REL: &str = ".config/tapwarden/config.yaml";

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Which secret backend serves the keys. Defaults to BWS so existing
    /// configs parse unchanged.
    #[serde(default)]
    pub backend: Backend,
    /// Name of the env var holding the BWS access token (never store the token in the file).
    #[serde(default = "default_token_env")]
    pub access_token_env: String,
    /// Where the BWS access token comes from: `env` (default, read from the
    /// var named by `access_token_env`) or `keychain` (stored in the macOS
    /// Keychain by `tapwarden store-token`, so the background LaunchAgent can
    /// fetch keys without inheriting shell env). Unused when `backend:
    /// vaultwarden` (that backend has its own `vaultwarden.credentials`).
    #[serde(default)]
    pub credentials: CredentialSource,
    /// UUIDs of the secrets that each hold one OpenSSH private key
    /// (BWS secret UUIDs or Vaultwarden cipher UUIDs, per `backend`).
    pub secret_ids: Vec<String>,
    /// Bitwarden host (e.g. `bitwarden.eu`, or a self-hosted host). Defaults to bitwarden.com.
    #[serde(default)]
    pub server_endpoint: Option<String>,
    /// Required when `backend: vaultwarden`.
    #[serde(default)]
    pub vaultwarden: Option<VaultwardenConfig>,
    #[serde(default)]
    pub authorization: Authorization,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// Bitwarden Secrets Manager (machine access token).
    #[default]
    Bws,
    /// Dedicated Vaultwarden account holding SSH-key vault items.
    Vaultwarden,
}

/// Vaultwarden backend settings. No credential values live here — either only
/// env var *names* (`credentials: env`, resolved at use time) or nothing at
/// all (`credentials: keychain`, read from the macOS Keychain behind Touch ID).
#[derive(Debug, Deserialize)]
pub struct VaultwardenConfig {
    /// Full base URL; Vaultwarden serves /identity and /api under one host.
    pub server_url: String,
    /// Account email (part of the master key KDF salt).
    pub email: String,
    /// Where the client id/secret and master password come from. Defaults to
    /// `env` so existing configs behave unchanged; when `keychain`, the three
    /// `*_env` names below are unused.
    #[serde(default)]
    pub credentials: CredentialSource,
    #[serde(default = "default_vw_client_id_env")]
    pub client_id_env: String,
    #[serde(default = "default_vw_client_secret_env")]
    pub client_secret_env: String,
    #[serde(default = "default_vw_master_password_env")]
    pub master_password_env: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// Resolve from the configured env vars at use time (CI / Linux).
    #[default]
    Env,
    /// Read from the macOS Keychain, behind a Touch ID prompt on every read.
    Keychain,
}

impl VaultwardenConfig {
    pub fn client_id(&self) -> Result<String> {
        env_var(&self.client_id_env)
    }
    pub fn client_secret(&self) -> Result<String> {
        env_var(&self.client_secret_env)
    }
    pub fn master_password(&self) -> Result<String> {
        env_var(&self.master_password_env)
    }
}

/// Resolve a secret from the named env var. The error names the variable
/// only — never a value. The source error is deliberately discarded:
/// `VarError::NotUnicode`'s Display embeds the raw value bytes, which would
/// leak the secret into any printed error chain.
fn env_var(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| anyhow!("env var `{name}` is not set or not valid unicode"))
}

#[derive(Debug, Deserialize)]
pub struct Authorization {
    #[serde(default)]
    pub mode: AuthMode,
    /// Presence factor gating every signature: `touch_id` (default) or
    /// `yubikey` (a FIDO2 security-key touch; requires a registered credential).
    #[serde(default)]
    pub factor: AuthFactor,
    /// Required when `factor: yubikey`; written by `tapwarden register-yubikey`.
    #[serde(default)]
    pub yubikey: Option<YubikeyConfig>,
    /// In `grace` mode: seconds a signature stays authorized before re-prompting.
    #[serde(default = "default_grace")]
    pub grace_seconds: u64,
}

impl Default for Authorization {
    fn default() -> Self {
        Self {
            mode: AuthMode::default(),
            factor: AuthFactor::default(),
            yubikey: None,
            grace_seconds: default_grace(),
        }
    }
}

/// Which presence factor authorizes each signature.
#[derive(Debug, Default, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFactor {
    /// macOS Touch ID (LocalAuthentication).
    #[default]
    TouchId,
    /// A FIDO2 security key (e.g. YubiKey): a physical touch per signature.
    Yubikey,
}

/// FIDO2 credential registered by `tapwarden register-yubikey`. The credential
/// id is only a handle — useless without the physical key — so it lives in the
/// config file, not a secret store.
#[derive(Debug, Deserialize)]
pub struct YubikeyConfig {
    /// Base64 credential id returned at registration.
    pub credential_id: String,
    /// Public key needed to verify every assertion from the registered key.
    /// Optional only so legacy configs produce a clear re-registration error.
    #[serde(default)]
    pub public_key: Option<YubikeyPublicKey>,
}

#[derive(Debug, Deserialize)]
pub struct YubikeyPublicKey {
    pub algorithm: YubikeyPublicKeyAlgorithm,
    /// Base64 verifier key bytes returned at registration.
    pub bytes: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum YubikeyPublicKeyAlgorithm {
    Es256,
    Ed25519,
}

impl YubikeyConfig {
    pub(crate) fn verifier(&self) -> Result<(Vec<u8>, ctap_hid_fido2::public_key::PublicKey)> {
        let credential_id = STANDARD
            .decode(&self.credential_id)
            .context("authorization.yubikey.credential_id is not valid base64")?;
        if credential_id.is_empty() {
            bail!("authorization.yubikey.credential_id must not be empty");
        }

        let public_key = self.public_key.as_ref().context(
            "authorization.yubikey.public_key is missing — run `tapwarden register-yubikey` again",
        )?;
        let public_key_bytes = STANDARD
            .decode(&public_key.bytes)
            .context("authorization.yubikey.public_key.bytes is not valid base64")?;
        let public_key_type = match public_key.algorithm {
            YubikeyPublicKeyAlgorithm::Es256 => {
                if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
                    bail!("authorization.yubikey.public_key.bytes is not a valid ES256 public key");
                }
                ctap_hid_fido2::public_key::PublicKeyType::Ecdsa256
            }
            YubikeyPublicKeyAlgorithm::Ed25519 => {
                if public_key_bytes.len() != 32 {
                    bail!(
                        "authorization.yubikey.public_key.bytes is not a valid Ed25519 public key"
                    );
                }
                ctap_hid_fido2::public_key::PublicKeyType::Ed25519
            }
        };
        Ok((
            credential_id,
            ctap_hid_fido2::public_key::PublicKey::with_der(&public_key_bytes, public_key_type),
        ))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Prompt for biometric approval on every signature.
    #[default]
    PerUse,
    /// Approve once, then skip prompts for `grace_seconds`.
    Grace,
}

fn default_token_env() -> String {
    "BWS_ACCESS_TOKEN".to_string()
}
fn default_vw_client_id_env() -> String {
    "TAPWARDEN_VW_CLIENT_ID".to_string()
}
fn default_vw_client_secret_env() -> String {
    "TAPWARDEN_VW_CLIENT_SECRET".to_string()
}
fn default_vw_master_password_env() -> String {
    "TAPWARDEN_VW_MASTER_PASSWORD".to_string()
}
fn default_grace() -> u64 {
    60
}

impl Config {
    pub fn load(path: Option<&str>) -> Result<Self> {
        let explicit = path.is_some();
        let path = match path {
            Some(p) => PathBuf::from(p),
            None => default_path()?,
        };
        // The env fallback is only for the *default* path being absent; an
        // explicitly requested config file that doesn't exist is a hard error,
        // never a silent switch to a different configuration.
        if explicit && !path.exists() {
            bail!("config file {} does not exist", path.display());
        }

        let cfg: Config = if path.exists() {
            let s = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read config file: {}", path.display()))?;
            serde_yaml::from_str(&s)
                .with_context(|| format!("failed to parse {} as YAML", path.display()))?
        } else {
            // Env fallback (CI / containers): TAPWARDEN_SECRET_IDS is comma-separated.
            let ids = std::env::var("TAPWARDEN_SECRET_IDS").unwrap_or_default();
            Config {
                backend: Backend::default(),
                vaultwarden: None,
                access_token_env: default_token_env(),
                credentials: CredentialSource::default(),
                secret_ids: ids
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                server_endpoint: std::env::var("TAPWARDEN_SERVER_ENDPOINT").ok(),
                authorization: Authorization::default(),
            }
        };

        cfg.validate()?;
        Ok(cfg)
    }

    /// Resolve the actual access token from the configured env var at use time.
    pub fn access_token(&self) -> Result<String> {
        env_var(&self.access_token_env)
    }

    fn validate(&self) -> Result<()> {
        if self.secret_ids.is_empty() {
            bail!(
                "no secret_ids configured (set them in the config file or via TAPWARDEN_SECRET_IDS)"
            );
        }
        if self.backend == Backend::Vaultwarden && self.vaultwarden.is_none() {
            bail!("backend is vaultwarden but the `vaultwarden` config section is missing");
        }
        if self.backend == Backend::Bws {
            crate::secret_source::validate_bws_server_endpoint(self.server_endpoint.as_deref())?;
        }
        if self.authorization.factor == AuthFactor::Yubikey {
            let yubikey = self.authorization.yubikey.as_ref().context(
                "authorization.factor is yubikey but no credential is registered — run `tapwarden register-yubikey`",
            )?;
            yubikey.verifier()?;
        }
        Ok(())
    }
}

fn default_path() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("unable to determine home directory")?
        .join(CONFIG_REL))
}

/// The path `load` would read for the given optional `--config` override.
pub fn resolved_path(explicit: Option<&str>) -> Result<PathBuf> {
    match explicit {
        Some(p) => Ok(PathBuf::from(p)),
        None => default_path(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_YAML: &str = "secret_ids: [00000000-0000-0000-0000-000000000000]\n";

    #[test]
    fn backend_defaults_to_bws() {
        let cfg: Config = serde_yaml::from_str(MINIMAL_YAML).unwrap();
        assert_eq!(cfg.backend, Backend::Bws);
        cfg.validate()
            .expect("bws config needs no vaultwarden section");
    }

    #[test]
    fn vaultwarden_backend_requires_its_section() {
        let yaml = format!("{MINIMAL_YAML}backend: vaultwarden\n");
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg
            .validate()
            .expect_err("must require the vaultwarden section");
        assert!(
            err.to_string().contains("vaultwarden"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn vaultwarden_section_parses_with_default_env_names() {
        let yaml = format!(
            "{MINIMAL_YAML}backend: vaultwarden\nvaultwarden:\n  server_url: https://vault.example.com\n  email: tapwarden@example.com\n"
        );
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let vw = cfg.vaultwarden.unwrap();
        assert_eq!(vw.credentials, CredentialSource::Env, "must default to env");
        assert_eq!(vw.client_id_env, "TAPWARDEN_VW_CLIENT_ID");
        assert_eq!(vw.client_secret_env, "TAPWARDEN_VW_CLIENT_SECRET");
        assert_eq!(vw.master_password_env, "TAPWARDEN_VW_MASTER_PASSWORD");
    }

    #[test]
    fn vaultwarden_keychain_credentials_parse() {
        let yaml = format!(
            "{MINIMAL_YAML}backend: vaultwarden\nvaultwarden:\n  server_url: https://vault.example.com\n  email: tapwarden@example.com\n  credentials: keychain\n"
        );
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.vaultwarden.unwrap().credentials,
            CredentialSource::Keychain
        );
    }

    #[test]
    fn missing_env_var_error_names_the_var_and_no_value() {
        let vw = VaultwardenConfig {
            server_url: "https://vault.example.com".into(),
            email: "tapwarden@example.com".into(),
            credentials: CredentialSource::default(),
            client_id_env: default_vw_client_id_env(),
            client_secret_env: "TAPWARDEN_TEST_DEFINITELY_UNSET_VW_SECRET".into(),
            master_password_env: default_vw_master_password_env(),
        };
        let err = vw
            .client_secret()
            .expect_err("unset env var must be an error");
        let msg = format!("{err:#}");
        // The error may only name the env var; there is no value to echo and
        // none must ever appear.
        assert!(
            msg.contains("TAPWARDEN_TEST_DEFINITELY_UNSET_VW_SECRET"),
            "error must name the env var: {msg}"
        );
    }

    #[test]
    fn non_unicode_env_value_never_leaks_into_the_error() {
        use std::os::unix::ffi::OsStrExt;
        let name = "TAPWARDEN_TEST_NON_UNICODE_SECRET";
        // Invalid UTF-8 wrapped around a recognizable marker.
        // SAFETY: test-only, single-threaded `cargo test` process; no other
        // thread reads/writes the environment concurrently with this call.
        unsafe {
            std::env::set_var(
                name,
                std::ffi::OsStr::from_bytes(b"\xffSUPERSECRETVALUE\xfe"),
            );
        }
        let err = env_var(name).expect_err("non-unicode value must be an error");
        // SAFETY: same as above.
        unsafe {
            std::env::remove_var(name);
        }
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("SUPERSECRETVALUE"),
            "error leaked the env value: {msg}"
        );
        assert!(msg.contains(name), "error must still name the var: {msg}");
    }

    #[test]
    fn explicit_missing_config_path_is_a_hard_error() {
        let err = Config::load(Some("/nonexistent/tapwarden-config.yaml"))
            .expect_err("a missing explicit --config path must not fall back to env");
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn legacy_yubikey_config_without_public_key_fails_closed() {
        let yaml = format!(
            "{MINIMAL_YAML}authorization:\n  factor: yubikey\n  yubikey:\n    credential_id: AA==\n"
        );
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg
            .validate()
            .expect_err("assertions cannot be verified without the registered public key");
        assert!(err.to_string().contains("register-yubikey"), "{err:#}");
    }

    #[test]
    fn yubikey_public_key_config_parses() {
        for algorithm in ["es256", "ed25519"] {
            let mut key = vec![0; if algorithm == "es256" { 65 } else { 32 }];
            if algorithm == "es256" {
                key[0] = 0x04;
            }
            let key = STANDARD.encode(key);
            let yaml = format!(
                "{MINIMAL_YAML}authorization:\n  factor: yubikey\n  yubikey:\n    credential_id: AA==\n    public_key:\n      algorithm: {algorithm}\n      bytes: {key}\n"
            );
            let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
            cfg.validate().unwrap();
        }
    }

    #[test]
    fn malformed_yubikey_verifier_fails_before_agent_installation() {
        for (credential_id, key) in [
            ("not-base64", STANDARD.encode([0x04; 65])),
            ("AA==", "not-base64".into()),
            ("AA==", STANDARD.encode([0x04; 64])),
        ] {
            let yaml = format!(
                "{MINIMAL_YAML}authorization:\n  factor: yubikey\n  yubikey:\n    credential_id: {credential_id}\n    public_key:\n      algorithm: es256\n      bytes: {key}\n"
            );
            let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
            cfg.validate()
                .expect_err("malformed verifier material must fail config validation");
        }
    }

    #[test]
    fn bws_remote_http_endpoint_fails_before_agent_installation() {
        let yaml = format!("{MINIMAL_YAML}server_endpoint: http://vault.example.com\n");
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg
            .validate()
            .expect_err("remote BWS endpoints must never use cleartext HTTP");
        assert!(err.to_string().contains("https://"), "{err:#}");
    }

    #[test]
    fn empty_bws_endpoint_fails_before_agent_installation() {
        let yaml = format!("{MINIMAL_YAML}server_endpoint: ''\n");
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate()
            .expect_err("empty BWS endpoint must fail config validation");
    }
}
