//! Vaultwarden backend: fetches SSH-key vault items (cipher
//! type 5) from a **dedicated** Vaultwarden account via the vault API, using a
//! personal API key (`client_credentials`) login plus the master password for
//! decryption. Requires `EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item`
//! server-side to create such items.
//!
//! Protocol verified against vaultwarden `src/api/identity.rs` /
//! `src/db/models/cipher.rs` and bitwarden `sdk-internal`
//! `crates/bitwarden-crypto` (kdf.rs, keys/utils.rs, master_key.rs).

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64_PAD;
use base64::Engine;
use hkdf::Hkdf;
use hmac::Hmac;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::authorizer::{AuthContext, Authorizer};
use crate::keychain;
use crate::secret_source::{
    http_client, json_capped, EncString, SecretData, SecretFetcher, SymKey,
};

/// Vaultwarden's `login()` rejects `password`/`client_credentials` requests
/// without deviceIdentifier/deviceName/deviceType. A stable identifier avoids
/// creating a new device row (and a "new device logged in" mail) on every
/// agent start; `sigilo setup` reuses it for the same reason.
pub(crate) const DEVICE_IDENTIFIER: &str = "6c11ea63-9b34-4c73-b9ca-8f8b74dd6d10";
pub(crate) const DEVICE_NAME: &str = "sigilo";
/// 14 = "Unknown Browser" — the value vaultwarden itself falls back to.
pub(crate) const DEVICE_TYPE: &str = "14";
/// Vaultwarden hides SSH-key ciphers (type 5) from clients that do not declare
/// a version >= 2024.12.0 via this header (see its api/core/ciphers.rs sync()).
pub(crate) const CLIENT_VERSION_HEADER: &str = "Bitwarden-Client-Version";
pub(crate) const CLIENT_VERSION: &str = "2025.6.0";

/// KDF ids as reported by the server (vaultwarden `UserKdfType`).
const KDF_PBKDF2: u32 = 0;
const KDF_ARGON2ID: u32 = 1;

/// Bounds on server-supplied KDF parameters. A malicious server must be able
/// neither to downgrade the KDF (offline master-password brute-force) nor to
/// DoS the agent with huge cost parameters. 5k is the historical Bitwarden
/// PBKDF2 minimum — old accounts still use it.
const PBKDF2_MIN_ITERATIONS: u32 = 5_000;
const PBKDF2_MAX_ITERATIONS: u32 = 10_000_000;
const ARGON2_MIN_ITERATIONS: u32 = 1;
const ARGON2_MAX_ITERATIONS: u32 = 100;
const ARGON2_MIN_MEMORY_MIB: u32 = 8;
const ARGON2_MAX_MEMORY_MIB: u32 = 2_048;
const ARGON2_MIN_PARALLELISM: u32 = 1;
const ARGON2_MAX_PARALLELISM: u32 = 16;

/// Vault item type 5 = SshKey.
pub(crate) const CIPHER_TYPE_SSH_KEY: u32 = 5;

/// KDF parameters reported by the server (prelogin / token response).
pub(crate) struct KdfParams {
    pub(crate) kdf: u32,
    pub(crate) iterations: u32,
    /// Argon2id memory in MiB.
    pub(crate) memory: Option<u32>,
    pub(crate) parallelism: Option<u32>,
}

/// Master key derivation, mirroring the SDK's `KdfDerivedKeyMaterial::derive`:
/// salt is the trimmed + lowercased email; PBKDF2-SHA256 uses it directly,
/// Argon2id (v0x13) uses SHA-256(salt) and takes memory in MiB.
pub(crate) fn derive_master_key(password: &str, email: &str, kdf: &KdfParams) -> Result<[u8; 32]> {
    let salt = email.trim().to_lowercase();
    match kdf.kdf {
        KDF_PBKDF2 => {
            if !(PBKDF2_MIN_ITERATIONS..=PBKDF2_MAX_ITERATIONS).contains(&kdf.iterations) {
                bail!("server reported PBKDF2 iterations outside the accepted range");
            }
            Ok(pbkdf2::pbkdf2_array::<Hmac<Sha256>, 32>(
                password.as_bytes(),
                salt.as_bytes(),
                kdf.iterations,
            )
            .expect("32 bytes is a valid PBKDF2 output length"))
        }
        KDF_ARGON2ID => {
            if !(ARGON2_MIN_ITERATIONS..=ARGON2_MAX_ITERATIONS).contains(&kdf.iterations) {
                bail!("server reported Argon2id iterations outside the accepted range");
            }
            let memory_mib = kdf
                .memory
                .context("server reported Argon2id without a memory parameter")?;
            if !(ARGON2_MIN_MEMORY_MIB..=ARGON2_MAX_MEMORY_MIB).contains(&memory_mib) {
                bail!("server reported Argon2id memory outside the accepted range");
            }
            let parallelism = kdf
                .parallelism
                .context("server reported Argon2id without a parallelism parameter")?;
            if !(ARGON2_MIN_PARALLELISM..=ARGON2_MAX_PARALLELISM).contains(&parallelism) {
                bail!("server reported Argon2id parallelism outside the accepted range");
            }
            let memory_kib = memory_mib
                .checked_mul(1024)
                .context("Argon2id memory size overflows")?;
            let salt_sha = Sha256::digest(salt.as_bytes());
            let params = argon2::Params::new(memory_kib, kdf.iterations, parallelism, Some(32))
                .map_err(|_| anyhow!("invalid Argon2 parameters"))?;
            let argon =
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            let mut key = [0u8; 32];
            argon
                .hash_password_into(password.as_bytes(), &salt_sha, &mut key)
                .map_err(|_| anyhow!("Argon2 derivation failed"))?;
            Ok(key)
        }
        other => bail!("unsupported KDF type {other}"),
    }
}

/// Key stretching, mirroring the SDK's `stretch_key`: HKDF-SHA256-expand the
/// 32-byte master key (used directly as the PRK, no extract step) with info
/// `"enc"` and `"mac"` into the two 32-byte halves.
pub(crate) fn stretch_master_key(master_key: &[u8; 32]) -> SymKey {
    let hkdf = Hkdf::<Sha256>::from_prk(master_key).expect("PRK is exactly 32 bytes");
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    hkdf.expand(b"enc", &mut enc)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    hkdf.expand(b"mac", &mut mac)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SymKey { enc, mac }
}

/// The server authorization hash sent as `password` / `masterPasswordHash`:
/// PBKDF2-SHA256(master_key, password as salt, 1 iteration), base64. Mirrors
/// the SDK's `MasterKey::derive_master_key_hash(ServerAuthorization)`; the
/// SDK's published KDF test vectors assert on exactly this value.
pub(crate) fn server_auth_hash(master_key: &[u8; 32], password: &str) -> String {
    B64_PAD.encode(
        pbkdf2::pbkdf2_array::<Hmac<Sha256>, 32>(master_key, password.as_bytes(), 1)
            .expect("32 bytes is a valid PBKDF2 output length"),
    )
}

/// `GET /api/ciphers/{id}` response, camelCase per vaultwarden's
/// `Cipher::to_json`. Only the fields sigilo needs.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CipherResponse {
    #[serde(rename = "type")]
    atype: u32,
    #[serde(default)]
    organization_id: Option<String>,
    /// Cipher-key encryption: an individual item key wrapped by the user key.
    #[serde(default)]
    key: Option<String>,
    /// EncString.
    name: String,
    /// Null unless type 5 (or when the server nulls an invalid ssh entry).
    #[serde(default)]
    ssh_key: Option<SshKeyJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshKeyJson {
    /// EncString of the OpenSSH-format private key.
    private_key: String,
}

/// Cipher-key encryption: decrypt the individual item key (wrapped by the
/// user key) when present; the cipher's fields are then under that key,
/// otherwise under the user key directly.
pub(crate) fn resolve_cipher_key(
    wrapped: Option<&str>,
    user_key: &SymKey,
) -> Result<Option<SymKey>> {
    wrapped
        .map(|k| {
            EncString::parse(k)?
                .decrypt(user_key)
                .and_then(|bytes| SymKey::from_bytes(&bytes))
                .context("cipher item key decryption")
        })
        .transpose()
}

/// Validate + decrypt a fetched cipher into a `SecretData`.
fn extract_secret(cipher: CipherResponse, user_key: &SymKey) -> Result<SecretData> {
    if cipher.organization_id.is_some() {
        bail!("org-owned items unsupported; put the key in the dedicated account's personal vault");
    }
    if cipher.atype != CIPHER_TYPE_SSH_KEY {
        bail!("cipher is not an SSH key item (expected type 5)");
    }
    let ssh_key = cipher
        .ssh_key
        .context("cipher has no usable sshKey data (server nulls invalid ssh entries)")?;
    let item_key = resolve_cipher_key(cipher.key.as_deref(), user_key)?;
    let key = item_key.as_ref().unwrap_or(user_key);
    Ok(SecretData {
        name: EncString::parse(&cipher.name)?
            .decrypt_to_string(key)
            .context("cipher name decryption")?,
        openssh_private_key: EncString::parse(&ssh_key.private_key)?
            .decrypt_to_string(key)
            .context("cipher privateKey decryption")?,
    })
}

/// An authenticated Vaultwarden session: bearer + decrypted 64-byte user key.
struct Session {
    bearer: String,
    user_key: SymKey,
}

/// Where the fetcher gets its credentials on the first `authenticate()`
/// (`vaultwarden.credentials` in the config). No Debug on purpose.
pub enum VwCredentials {
    /// Values already resolved from env vars at construction.
    Env {
        client_id: String,
        client_secret: String,
        master_password: String,
    },
    /// Read from the macOS Keychain at first use, behind a Touch ID prompt.
    Keychain,
}

/// `SecretFetcher` impl for a dedicated Vaultwarden account. One host serves
/// both `/identity` and `/api`.
pub struct VaultwardenFetcher {
    server_url: String,
    email: String,
    http: reqwest::Client,
    /// Gate in front of every keychain read. This may be the same instance
    /// that gates signatures; `Grace` never applies its window to
    /// `AuthContext::UnlockCredentials`, so credential reads always prompt.
    gate: Arc<dyn Authorizer>,
    /// Lazily-established session, shared across `get` calls. Env credentials
    /// live only in `Pending` and are dropped from memory on the first
    /// successful authenticate; keychain credentials are read, used, and
    /// dropped inside that same first authenticate.
    // ponytail: bearer expiry ignored — same rationale as BwsRest; add re-auth
    // on HTTP 401 if long-lived refetch appears.
    state: tokio::sync::Mutex<AuthState>,
}

enum AuthState {
    /// Credential source held only until the first successful login; a failed
    /// attempt (or a denied unlock) leaves it in place so a later `get` can
    /// retry.
    Pending(VwCredentials),
    Ready(Session),
}

/// Dev-only exception to the https requirement: plain http is acceptable only
/// when the traffic never leaves the local machine.
fn is_localhost_http(url: &str) -> bool {
    ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|prefix| {
            url.strip_prefix(prefix).is_some_and(|rest| {
                rest.is_empty() || rest.starts_with(':') || rest.starts_with('/')
            })
        })
}

/// Cleartext http would put credentials and decrypted private keys on the
/// wire; only a loopback host may skip TLS. Shared with `sigilo setup`.
pub(crate) fn validate_server_url(url: &str) -> Result<()> {
    if !url.starts_with("https://") && !is_localhost_http(url) {
        bail!(
            "vaultwarden server_url must be an https:// URL (http:// is allowed for localhost only)"
        );
    }
    Ok(())
}

// No Debug impl on purpose: the struct holds the master password, client
// secret, and (in the session) the user key.

/// Personal-API-key client ids have the form `user.<uuid>`.
fn validate_client_id(client_id: &str) -> Result<()> {
    // Error message is static on purpose: never echo credential values.
    if !client_id.starts_with("user.") {
        bail!("vaultwarden client_id must have the form user.<uuid> (personal API key)");
    }
    Ok(())
}

impl VaultwardenFetcher {
    pub fn new(
        server_url: &str,
        email: &str,
        credentials: VwCredentials,
        gate: Arc<dyn Authorizer>,
    ) -> Result<Self> {
        validate_server_url(server_url)?;
        if let VwCredentials::Env { client_id, .. } = &credentials {
            validate_client_id(client_id)?;
        }
        Ok(Self {
            server_url: server_url.trim_end_matches('/').to_string(),
            email: email.to_string(),
            http: http_client()?,
            gate,
            state: tokio::sync::Mutex::new(AuthState::Pending(credentials)),
        })
    }

    /// Resolve the three credential values from the pending source. For the
    /// keychain the Touch ID gate must approve BEFORE anything is read.
    async fn acquire_credentials(
        &self,
        pending: &VwCredentials,
    ) -> Result<(String, String, String)> {
        match pending {
            VwCredentials::Env {
                client_id,
                client_secret,
                master_password,
            } => Ok((
                client_id.clone(),
                client_secret.clone(),
                master_password.clone(),
            )),
            VwCredentials::Keychain => {
                let ctx = AuthContext::UnlockCredentials {
                    reason: "unlock backend credentials for Vaultwarden",
                };
                let approved = self
                    .gate
                    .approve(&ctx)
                    .await
                    .context("failed to evaluate the credential-unlock authorization")?;
                if !approved {
                    // Static message; state stays Pending so the next request
                    // can raise the prompt again.
                    bail!("credential unlock denied — the keychain was not read");
                }
                let client_id = keychain::read(keychain::VW_CLIENT_ID)?;
                validate_client_id(&client_id)?;
                Ok((
                    client_id,
                    keychain::read(keychain::VW_CLIENT_SECRET)?,
                    keychain::read(keychain::VW_MASTER_PASSWORD)?,
                ))
            }
        }
    }

    /// Personal-API-key login + user-key decryption. HTTP error bodies are
    /// deliberately dropped: they can echo request parameters.
    async fn authenticate(
        &self,
        client_id: &str,
        client_secret: &str,
        master_password: &str,
    ) -> Result<Session> {
        let response = self
            .http
            .post(format!("{}/identity/connect/token", self.server_url))
            .header(reqwest::header::ACCEPT, "application/json")
            .header(CLIENT_VERSION_HEADER, CLIENT_VERSION)
            .form(&[
                ("grant_type", "client_credentials"),
                ("scope", "api"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("deviceIdentifier", DEVICE_IDENTIFIER),
                ("deviceName", DEVICE_NAME),
                ("deviceType", DEVICE_TYPE),
            ])
            .send()
            .await
            .context("token exchange failed: request error")?;

        let status = response.status();
        if !status.is_success() {
            bail!("token exchange failed: HTTP {status}");
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(rename = "Key")]
            key: String,
            #[serde(rename = "Kdf")]
            kdf: u32,
            #[serde(rename = "KdfIterations")]
            kdf_iterations: u32,
            #[serde(rename = "KdfMemory", default)]
            kdf_memory: Option<u32>,
            #[serde(rename = "KdfParallelism", default)]
            kdf_parallelism: Option<u32>,
        }
        let token_response: TokenResponse = json_capped(response)
            .await
            .context("token exchange failed")?;

        let master_key = derive_master_key(
            master_password,
            &self.email,
            &KdfParams {
                kdf: token_response.kdf,
                iterations: token_response.kdf_iterations,
                memory: token_response.kdf_memory,
                parallelism: token_response.kdf_parallelism,
            },
        )
        .context("login failed: master key derivation")?;
        let stretched = stretch_master_key(&master_key);

        let user_key = EncString::parse(&token_response.key)
            .context("login failed: bad user key EncString")?
            .decrypt(&stretched)
            .context("login failed: user key decryption (wrong master password?)")
            .and_then(|bytes| SymKey::from_bytes(&bytes))
            .context("login failed: bad user key")?;

        Ok(Session {
            bearer: token_response.access_token,
            user_key,
        })
    }
}

#[async_trait]
impl SecretFetcher for VaultwardenFetcher {
    async fn get(&self, id: Uuid) -> Result<SecretData> {
        let mut state = self.state.lock().await;
        if let AuthState::Pending(pending) = &*state {
            let (client_id, client_secret, master_password) =
                self.acquire_credentials(pending).await?;
            let session = self
                .authenticate(&client_id, &client_secret, &master_password)
                .await?;
            // Success: replacing the state drops the credentials from memory
            // (the keychain-read copies go out of scope right here too).
            *state = AuthState::Ready(session);
        }
        let AuthState::Ready(session) = &*state else {
            bail!("credentials already consumed but no session established");
        };

        let response = self
            .http
            .get(format!("{}/api/ciphers/{}", self.server_url, id))
            .bearer_auth(&session.bearer)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(CLIENT_VERSION_HEADER, CLIENT_VERSION)
            .send()
            .await
            .context("cipher fetch failed: request error")?;

        let status = response.status();
        if !status.is_success() {
            bail!("cipher fetch failed: HTTP {status}");
        }

        let cipher: CipherResponse = json_capped(response).await.context("cipher fetch failed")?;
        extract_secret(cipher, &session.user_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_source::make_enc_string;
    use serde_json::json;

    // Vector from sdk-internal bitwarden-crypto master_key.rs
    // `test_password_hash_pbkdf2` (also proves email trim + lowercase).
    #[test]
    fn derives_pbkdf2_master_key_matching_sdk_vector() {
        let kdf = KdfParams {
            kdf: KDF_PBKDF2,
            iterations: 100_000,
            memory: None,
            parallelism: None,
        };
        for email in [
            "test@bitwarden.com",
            "TEST@bitwarden.com",
            " test@bitwarden.com",
        ] {
            let key = derive_master_key("asdfasdf", email, &kdf).unwrap();
            assert_eq!(
                server_auth_hash(&key, "asdfasdf"),
                "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw="
            );
        }
    }

    // Vector from sdk-internal bitwarden-crypto master_key.rs
    // `test_password_hash_argon2id`.
    #[test]
    fn derives_argon2id_master_key_matching_sdk_vector() {
        let kdf = KdfParams {
            kdf: KDF_ARGON2ID,
            iterations: 4,
            memory: Some(32),
            parallelism: Some(2),
        };
        let key = derive_master_key("asdfasdf", "test_salt", &kdf).unwrap();
        assert_eq!(
            server_auth_hash(&key, "asdfasdf"),
            "PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ="
        );
    }

    #[test]
    fn rejects_bad_kdf_parameters() {
        let zero_iter = KdfParams {
            kdf: KDF_PBKDF2,
            iterations: 0,
            memory: None,
            parallelism: None,
        };
        assert!(derive_master_key("pw", "a@b.c", &zero_iter).is_err());
        let unknown = KdfParams {
            kdf: 9,
            iterations: 1,
            memory: None,
            parallelism: None,
        };
        assert!(derive_master_key("pw", "a@b.c", &unknown).is_err());
        let argon_missing_memory = KdfParams {
            kdf: KDF_ARGON2ID,
            iterations: 4,
            memory: None,
            parallelism: Some(2),
        };
        assert!(derive_master_key("pw", "a@b.c", &argon_missing_memory).is_err());
    }

    #[test]
    fn enforces_pbkdf2_iteration_bounds() {
        let pbkdf2 = |iterations| KdfParams {
            kdf: KDF_PBKDF2,
            iterations,
            memory: None,
            parallelism: None,
        };
        assert!(derive_master_key("pw", "a@b.c", &pbkdf2(PBKDF2_MIN_ITERATIONS - 1)).is_err());
        assert!(derive_master_key("pw", "a@b.c", &pbkdf2(PBKDF2_MIN_ITERATIONS)).is_ok());
        assert!(derive_master_key("pw", "a@b.c", &pbkdf2(PBKDF2_MAX_ITERATIONS + 1)).is_err());
        // Acceptance at PBKDF2_MAX_ITERATIONS is deliberately not run: 10M
        // real iterations is far too slow for a unit test.
    }

    #[test]
    fn enforces_argon2id_parameter_bounds() {
        let argon = |iterations, memory, parallelism| KdfParams {
            kdf: KDF_ARGON2ID,
            iterations,
            memory: Some(memory),
            parallelism: Some(parallelism),
        };
        let cheap_mem = ARGON2_MIN_MEMORY_MIB;
        // Iterations.
        assert!(derive_master_key("pw", "a@b.c", &argon(0, cheap_mem, 1)).is_err());
        assert!(derive_master_key(
            "pw",
            "a@b.c",
            &argon(ARGON2_MAX_ITERATIONS + 1, cheap_mem, 1)
        )
        .is_err());
        // Memory.
        assert!(derive_master_key("pw", "a@b.c", &argon(1, ARGON2_MIN_MEMORY_MIB - 1, 1)).is_err());
        assert!(derive_master_key("pw", "a@b.c", &argon(1, ARGON2_MAX_MEMORY_MIB + 1, 1)).is_err());
        // Parallelism.
        assert!(derive_master_key("pw", "a@b.c", &argon(1, cheap_mem, 0)).is_err());
        assert!(derive_master_key(
            "pw",
            "a@b.c",
            &argon(1, cheap_mem, ARGON2_MAX_PARALLELISM + 1)
        )
        .is_err());
        // Cheap accepted edges (max iterations / max memory acceptance would
        // actually run an expensive derivation, so only the cheap edges run).
        assert!(derive_master_key(
            "pw",
            "a@b.c",
            &argon(
                ARGON2_MIN_ITERATIONS,
                ARGON2_MIN_MEMORY_MIB,
                ARGON2_MIN_PARALLELISM
            )
        )
        .is_ok());
        assert!(
            derive_master_key("pw", "a@b.c", &argon(1, cheap_mem, ARGON2_MAX_PARALLELISM)).is_ok()
        );
    }

    // Vector from sdk-internal bitwarden-crypto keys/utils.rs
    // `test_stretch_kdf_key` — proves the "enc"/"mac" HKDF info strings.
    #[test]
    fn stretches_master_key_matching_sdk_vector() {
        let master_key = [
            31u8, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167,
            69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
        ];
        let stretched = stretch_master_key(&master_key);
        assert_eq!(
            stretched.enc,
            [
                111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142,
                134, 120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96
            ]
        );
        assert_eq!(
            stretched.mac,
            [
                221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28, 185, 16, 48, 61, 127,
                166, 209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155
            ]
        );
    }

    /// Round trip the token-response `Key` path: a 64-byte user key encrypted
    /// under the stretched master key decrypts back to the same key.
    #[test]
    fn user_key_decrypts_under_stretched_master_key() {
        let master_key = [0x42u8; 32];
        let stretched = stretch_master_key(&master_key);
        let mut user_key_bytes = vec![0x11u8; 32];
        user_key_bytes.extend_from_slice(&[0x22u8; 32]);
        let enc = make_enc_string(&user_key_bytes, &stretched, [0x33; 16]);

        let user_key = EncString::parse(&enc)
            .unwrap()
            .decrypt(&stretched)
            .and_then(|b| SymKey::from_bytes(&b))
            .unwrap();
        assert_eq!(user_key.enc, [0x11; 32]);
        assert_eq!(user_key.mac, [0x22; 32]);
    }

    fn user_key() -> SymKey {
        SymKey {
            enc: [0x11; 32],
            mac: [0x22; 32],
        }
    }

    fn cipher_json(atype: u32, org: Option<&str>, key: &SymKey) -> serde_json::Value {
        json!({
            "object": "cipherDetails",
            "id": "b9b64ee8-0000-0000-0000-000000000000",
            "type": atype,
            "organizationId": org,
            "key": null,
            "name": make_enc_string(b"deploy-key", key, [0x01; 16]),
            "sshKey": {
                "privateKey": make_enc_string(b"-----BEGIN OPENSSH PRIVATE KEY-----", key, [0x02; 16]),
                "publicKey": make_enc_string(b"ssh-ed25519 AAAA", key, [0x03; 16]),
                "keyFingerprint": make_enc_string(b"SHA256:abc", key, [0x04; 16]),
            },
        })
    }

    #[test]
    fn extracts_type5_cipher_under_user_key() {
        let key = user_key();
        let cipher: CipherResponse =
            serde_json::from_value(cipher_json(CIPHER_TYPE_SSH_KEY, None, &key)).unwrap();
        let secret = extract_secret(cipher, &key).unwrap();
        assert_eq!(secret.name, "deploy-key");
        assert_eq!(
            secret.openssh_private_key,
            "-----BEGIN OPENSSH PRIVATE KEY-----"
        );
    }

    #[test]
    fn extracts_cipher_with_individual_item_key() {
        let user = user_key();
        let item = SymKey {
            enc: [0x55; 32],
            mac: [0x66; 32],
        };
        // Fields are under the item key; the item key is wrapped by the user key.
        let mut json = cipher_json(CIPHER_TYPE_SSH_KEY, None, &item);
        let mut item_bytes = item.enc.to_vec();
        item_bytes.extend_from_slice(&item.mac);
        json["key"] = json!(make_enc_string(&item_bytes, &user, [0x07; 16]));

        let cipher: CipherResponse = serde_json::from_value(json).unwrap();
        let secret = extract_secret(cipher, &user).unwrap();
        assert_eq!(secret.name, "deploy-key");
    }

    #[test]
    fn rejects_org_owned_cipher() {
        let key = user_key();
        let cipher: CipherResponse = serde_json::from_value(cipher_json(
            CIPHER_TYPE_SSH_KEY,
            Some("0a0a0a0a-0000-0000-0000-000000000000"),
            &key,
        ))
        .unwrap();
        let err = extract_secret(cipher, &key)
            .err()
            .expect("org-owned cipher must be rejected");
        assert!(
            err.to_string().contains("org-owned"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn rejects_non_sshkey_cipher() {
        let key = user_key();
        // type 1 = Login
        let cipher: CipherResponse = serde_json::from_value(cipher_json(1, None, &key)).unwrap();
        let err = extract_secret(cipher, &key)
            .err()
            .expect("non-sshkey cipher must be rejected");
        assert!(
            err.to_string().contains("type 5"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn rejects_cipher_with_nulled_sshkey_data() {
        let key = user_key();
        let mut json = cipher_json(CIPHER_TYPE_SSH_KEY, None, &key);
        json["sshKey"] = serde_json::Value::Null;
        let cipher: CipherResponse = serde_json::from_value(json).unwrap();
        assert!(extract_secret(cipher, &key).is_err());
    }

    fn env_creds(client_id: &str, secret: &str) -> VwCredentials {
        VwCredentials::Env {
            client_id: client_id.to_string(),
            client_secret: secret.to_string(),
            master_password: secret.to_string(),
        }
    }

    #[test]
    fn constructor_requires_https_except_for_localhost() {
        let mk = |url: &str| {
            VaultwardenFetcher::new(
                url,
                "a@b.c",
                env_creds("user.x", "s"),
                Arc::new(crate::authorizer::AlwaysAllow),
            )
        };
        assert!(mk("https://vault.example.com").is_ok());
        assert!(mk("http://localhost:8080").is_ok());
        assert!(mk("http://127.0.0.1").is_ok());
        assert!(mk("http://[::1]:8080/vw").is_ok());
        assert!(mk("http://vault.example.com").is_err());
        assert!(mk("http://localhost.example.com").is_err());
        assert!(mk("ftp://vault.example.com").is_err());
        assert!(mk("vault.example.com").is_err());
    }

    #[test]
    fn constructor_rejects_bad_inputs_with_static_errors() {
        let secret_marker = "SUPERSECRETVALUE";
        for (server, client_id) in [
            ("vault.example.com", format!("user.{secret_marker}")), // no scheme
            ("https://vault.example.com", secret_marker.to_string()), // no user. prefix
        ] {
            let err = VaultwardenFetcher::new(
                server,
                "sigilo@example.com",
                env_creds(&client_id, secret_marker),
                Arc::new(crate::authorizer::AlwaysAllow),
            )
            .err()
            .expect("constructor must reject");
            assert!(
                !format!("{err:#}").contains(secret_marker),
                "error leaked a credential: {err:#}"
            );
        }
    }

    /// A denied credential unlock must fail with a static message, never
    /// touch the keychain, and leave the fetcher able to prompt again on the
    /// next request (agent keeps running).
    #[tokio::test]
    async fn denied_unlock_bails_before_the_keychain_and_can_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Denying(Arc<AtomicUsize>);
        #[async_trait]
        impl Authorizer for Denying {
            async fn approve(&self, ctx: &AuthContext<'_>) -> Result<bool> {
                assert!(matches!(ctx, AuthContext::UnlockCredentials { .. }));
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(false)
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = VaultwardenFetcher::new(
            "https://vault.example.com",
            "a@b.c",
            VwCredentials::Keychain,
            Arc::new(Denying(calls.clone())),
        )
        .unwrap();

        let id = Uuid::from_u128(1);
        for expected_calls in [1, 2] {
            // No `.expect_err()`: SecretData holds a private key and must
            // never derive Debug, so extract the error without printing Ok.
            let result = fetcher.get(id).await;
            assert!(result.is_err(), "denied unlock must fail");
            let err = result.err().expect("checked is_err above");
            assert!(
                format!("{err:#}").contains("denied"),
                "unexpected error: {err:#}"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                expected_calls,
                "every retry must prompt again"
            );
        }
    }

    /// Real-Vaultwarden integration test. Run explicitly with:
    /// `SIGILO_VW_SERVER=... SIGILO_VW_EMAIL=... SIGILO_VW_CLIENT_ID=...
    ///  SIGILO_VW_CLIENT_SECRET=... SIGILO_VW_MASTER_PASSWORD=...
    ///  SIGILO_TEST_CIPHER_ID=... cargo test -- --ignored`
    #[tokio::test]
    #[ignore = "hits a real Vaultwarden server; needs SIGILO_VW_* + SIGILO_TEST_CIPHER_ID"]
    async fn fetches_real_sshkey_from_vaultwarden() {
        let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} not set"));
        let id: Uuid = var("SIGILO_TEST_CIPHER_ID")
            .parse()
            .expect("SIGILO_TEST_CIPHER_ID is not a UUID");
        let fetcher = VaultwardenFetcher::new(
            &var("SIGILO_VW_SERVER"),
            &var("SIGILO_VW_EMAIL"),
            VwCredentials::Env {
                client_id: var("SIGILO_VW_CLIENT_ID"),
                client_secret: var("SIGILO_VW_CLIENT_SECRET"),
                master_password: var("SIGILO_VW_MASTER_PASSWORD"),
            },
            Arc::new(crate::authorizer::AlwaysAllow),
        )
        .unwrap();
        let secret = fetcher.get(id).await.unwrap();
        assert!(!secret.name.is_empty());
        assert!(secret.openssh_private_key.contains("OPENSSH PRIVATE KEY"));
    }
}
