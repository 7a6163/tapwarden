use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::{Engine, alphabet};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::authorizer::{AuthContext, Authorizer};
use crate::keychain;

/// Bound every backend request: a stalled connection must never wedge the
/// agent. Each fetcher holds its own session mutex across the request, and a
/// loading pass holds the agent's loading lock, so an unbounded request would
/// block every identity listing (and every sign with a not-yet-loaded key)
/// forever.
// ponytail: fixed timeouts; make configurable if a slow self-hosted server appears.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// After a failed backend login (offline, server down, unlock prompt denied),
/// how long both fetchers fail fast before trying — and prompting — again.
/// Every `ssh` lists keys first, so without it each one raises a prompt that
/// cannot succeed, once per configured key.
pub(crate) const LOGIN_RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// The fail-fast error while a failed login's backoff is still running.
/// Static on purpose: it carries no server output.
pub(crate) fn check_login_backoff(
    failed_at: Option<std::time::Instant>,
    backoff: Duration,
) -> Result<()> {
    let wait = failed_at.map_or(Duration::ZERO, |at| backoff.saturating_sub(at.elapsed()));
    if !wait.is_zero() {
        bail!(
            "the last backend login failed; retrying in {}s",
            wait.as_secs().max(1)
        );
    }
    Ok(())
}
const HTTP_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared backend HTTP client: bounded timeouts, and redirects are never
/// followed — a 307/308 would forward a credential-bearing POST body to
/// whatever origin a compromised server names.
pub(crate) fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_TOTAL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build the HTTP client")
}

/// Standard base64, but tolerant of missing padding on decode — Bitwarden
/// access tokens are sometimes distributed without trailing `=`.
const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// One secret fetched from the backend: a named OpenSSH private key.
pub struct SecretData {
    pub name: String,
    pub openssh_private_key: String,
}

/// Abstracts the secret backend so the agent and tests don't depend on a
/// concrete client. Impls: `BwsRest` (Secrets Manager) and
/// `vaultwarden::VaultwardenFetcher` (SSH-key vault items).
#[async_trait]
pub trait SecretFetcher: Send + Sync {
    async fn get(&self, id: Uuid) -> Result<SecretData>;
}

/// A Bitwarden AES-256-CBC + HMAC-SHA256 symmetric key pair (enc + mac halves
/// of a 64-byte key), i.e. the SDK's `Aes256CbcHmacKey`.
pub(crate) struct SymKey {
    pub(crate) enc: [u8; 32],
    pub(crate) mac: [u8; 32],
}

impl SymKey {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            bail!("symmetric key has wrong length (expected 64 bytes)");
        }
        Ok(Self {
            enc: bytes[..32].try_into().expect("32-byte slice"),
            mac: bytes[32..].try_into().expect("32-byte slice"),
        })
    }

    /// Mirrors the SDK's `derive_shareable_key(seed, "accesstoken",
    /// Some("sm-access-token"))`: PRK = HMAC-SHA256(key = "bitwarden-accesstoken",
    /// msg = seed), then HKDF-expand(PRK, info = "sm-access-token") to 64 bytes.
    fn derive_access_token_key(seed: &[u8; 16]) -> Self {
        let prk = HmacSha256::new_from_slice(b"bitwarden-accesstoken")
            .expect("HMAC accepts any key length")
            .chain_update(seed)
            .finalize()
            .into_bytes();
        let hkdf = Hkdf::<Sha256>::from_prk(&prk).expect("PRK is exactly 32 bytes");
        let mut okm = [0u8; 64];
        hkdf.expand(b"sm-access-token", &mut okm)
            .expect("64 bytes is a valid HKDF-SHA256 output length");
        Self::from_bytes(&okm).expect("okm is 64 bytes")
    }
}

/// A Bitwarden `EncString` of type 2 (`AesCbc256_HmacSha256_B64`):
/// `2.<iv_b64>|<ciphertext_b64>|<mac_b64>`.
pub(crate) struct EncString {
    iv: [u8; 16],
    data: Vec<u8>,
    mac: [u8; 32],
}

impl EncString {
    pub(crate) fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix("2.")
            .context("unsupported EncString (expected type 2, AesCbc256_HmacSha256_B64)")?;
        let mut parts = rest.split('|');
        let (Some(iv), Some(data), Some(mac), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            bail!("malformed EncString: expected 3 '|'-separated parts");
        };
        let iv: [u8; 16] = B64
            .decode(iv)
            .context("malformed EncString: iv is not base64")?
            .try_into()
            .map_err(|_| anyhow!("malformed EncString: iv is not 16 bytes"))?;
        let data = B64
            .decode(data)
            .context("malformed EncString: data is not base64")?;
        let mac: [u8; 32] = B64
            .decode(mac)
            .context("malformed EncString: mac is not base64")?
            .try_into()
            .map_err(|_| anyhow!("malformed EncString: mac is not 32 bytes"))?;
        Ok(Self { iv, data, mac })
    }

    /// MAC-verify (constant-time, over iv || ciphertext) *before* decrypting.
    pub(crate) fn decrypt(&self, key: &SymKey) -> Result<Vec<u8>> {
        let mut hmac = HmacSha256::new_from_slice(&key.mac).expect("HMAC accepts any key length");
        hmac.update(&self.iv);
        hmac.update(&self.data);
        // `verify_slice` compares in constant time via the hmac crate.
        hmac.verify_slice(&self.mac)
            .map_err(|_| anyhow!("EncString MAC verification failed"))?;

        Aes256CbcDec::new(&key.enc.into(), &self.iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&self.data)
            .map_err(|_| anyhow!("EncString decryption failed (bad padding)"))
    }

    pub(crate) fn decrypt_to_string(&self, key: &SymKey) -> Result<String> {
        String::from_utf8(self.decrypt(key)?).context("decrypted value is not valid UTF-8")
    }
}

/// Test-only helper: build a valid type-2 EncString for `plaintext` under
/// `key`, computing the ciphertext and MAC independently of `EncString`.
#[cfg(test)]
pub(crate) fn make_enc_string(plaintext: &[u8], key: &SymKey, iv: [u8; 16]) -> String {
    use aes::cipher::BlockEncryptMut;
    use base64::engine::general_purpose::STANDARD as B64_PAD;

    let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&key.enc.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let mut hmac = HmacSha256::new_from_slice(&key.mac).expect("HMAC accepts any key length");
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();
    format!(
        "2.{}|{}|{}",
        B64_PAD.encode(iv),
        B64_PAD.encode(&ciphertext),
        B64_PAD.encode(mac)
    )
}

/// Hard cap on any backend HTTP response body: a malicious or compromised
/// server must not be able to OOM the agent with an unbounded body.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024; // 1 MiB
/// Higher cap for `/api/sync` only: it returns the whole vault, which for a
/// well-populated account easily exceeds 1 MiB. Setup-time only, still bounded.
pub(crate) const MAX_SYNC_RESPONSE_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Read a JSON response body incrementally with a hard size cap, then
/// deserialize. Error messages are static: response content is never echoed.
pub(crate) async fn json_capped<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T> {
    json_capped_limit(response, MAX_RESPONSE_BYTES).await
}

pub(crate) async fn json_capped_limit<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<T> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("failed to read the response body"))?
    {
        if body.len() + chunk.len() > limit {
            bail!("response body exceeds the size limit");
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| anyhow!("unexpected response shape"))
}

/// The parsed pieces of a BWS machine access token
/// (`0.<client_id>.<client_secret>:<base64 16-byte key seed>`).
struct AccessToken {
    client_id: Uuid,
    client_secret: String,
    /// Key derived from the seed; decrypts the identity `encrypted_payload`.
    encryption_key: SymKey,
}

impl AccessToken {
    // Error messages are static on purpose: never echo any part of the token.
    fn parse(token: &str) -> Result<Self> {
        let (first, key_b64) = token
            .split_once(':')
            .context("malformed access token: missing encryption key part")?;
        let parts: Vec<&str> = first.split('.').collect();
        let [version, client_id, client_secret] = parts[..] else {
            bail!("malformed access token: wrong number of '.'-separated parts");
        };
        if version != "0" {
            bail!("unsupported access token version (expected 0)");
        }
        let client_id = Uuid::parse_str(client_id)
            .context("malformed access token: client id is not a UUID")?;
        let seed: [u8; 16] = B64
            .decode(key_b64)
            .context("malformed access token: encryption key is not base64")?
            .try_into()
            .map_err(|_| anyhow!("malformed access token: encryption key is not 16 bytes"))?;
        Ok(Self {
            client_id,
            client_secret: client_secret.to_string(),
            encryption_key: SymKey::derive_access_token_key(&seed),
        })
    }
}

/// An authenticated BWS session: bearer token + decrypted org symmetric key.
struct Session {
    bearer: String,
    org_key: SymKey,
}

/// Talks to the Bitwarden Secrets Manager REST API directly with
/// `reqwest` + `rustls`, instead of the heavyweight official SDK (the SDK is
/// what dragged in every CVE found during the vault-conductor review).
///
/// Flow (mirrors bitwarden-core `login_access_token`):
/// 1. POST `{identity}/connect/token` (client_credentials, scope api.secrets)
/// 2. decrypt `encrypted_payload` with the access-token-derived key → org key
/// 3. GET `{api}/secrets/{id}` with the bearer; decrypt key/value EncStrings
pub struct BwsRest {
    identity_url: String,
    api_url: String,
    http: reqwest::Client,
    /// Gate in front of a keychain-sourced token read; unused for env tokens.
    /// `Grace` never applies its window to `AuthContext::UnlockCredentials`,
    /// so a keychain read always prompts.
    gate: Arc<dyn Authorizer>,
    /// Lazily-established session, shared across `get` calls, renewed when
    /// the server answers 401 (the bearer expires after about an hour).
    state: tokio::sync::Mutex<AuthState>,
    /// `LOGIN_RETRY_BACKOFF`; a field so tests need not wait it out.
    login_backoff: Duration,
}

/// Where the BWS access token comes from, resolved on the first fetch.
pub enum BwsCredentials {
    /// Already resolved from the configured env var.
    Env(String),
    /// Read from the macOS Keychain on first use, behind a Touch ID prompt.
    Keychain,
}

/// Validate an access token's format without retaining it — used by
/// `tapwarden store-token` to reject a typo before writing the Keychain.
pub(crate) fn validate_access_token(token: &str) -> Result<()> {
    AccessToken::parse(token).map(|_| ())
}

/// Where to log in from, plus the current session if there is one.
struct AuthState {
    source: TokenSource,
    session: Option<Session>,
    /// When the last login failed, for `LOGIN_RETRY_BACKOFF`.
    failed_at: Option<std::time::Instant>,
}

/// An env token is parsed at construction (fail fast) and kept so an expired
/// session can be renewed. Keeping it adds no exposure: the same token stays
/// in the process environment for the agent's whole life anyway. A keychain
/// token is never kept — each login re-reads it behind the presence gate.
enum TokenSource {
    Parsed(AccessToken),
    Keychain,
}

// No Debug impl on purpose: the struct holds the client secret and key material.

/// `bitwarden.com` (default) / `bitwarden.eu` / bare self-hosted host →
/// `https://identity.<host>` + `https://api.<host>`. A full URL (self-hosted
/// behind one origin) mirrors the bws CLI's `server_base`: `<base>/identity` +
/// `<base>/api`. Cleartext HTTP is accepted only for loopback development.
fn service_urls(server_endpoint: Option<&str>) -> Result<(String, String)> {
    let endpoint = server_endpoint
        .unwrap_or("bitwarden.com")
        .trim_end_matches('/');
    if endpoint.contains("://") {
        validate_base_url(endpoint, "BWS server_endpoint")?;
        Ok((format!("{endpoint}/identity"), format!("{endpoint}/api")))
    } else {
        let host_url = reqwest::Url::parse(&format!("https://{endpoint}"))
            .context("BWS server_endpoint is not a valid host")?;
        if host_url.host_str().is_none()
            || host_url.path() != "/"
            || !host_url.username().is_empty()
            || host_url.password().is_some()
            || host_url.query().is_some()
            || host_url.fragment().is_some()
        {
            bail!("BWS server_endpoint must be a bare host or full base URL");
        }
        Ok((
            format!("https://identity.{endpoint}"),
            format!("https://api.{endpoint}"),
        ))
    }
}

/// A backend base URL: a real host, https (or http to a loopback host only —
/// cleartext would put credentials and decrypted keys on the wire), and no
/// userinfo, query, or fragment. Userinfo matters most: reqwest turns it into
/// a Basic-auth header on every request, putting a credential somewhere
/// nothing else in tapwarden expects one. Shared by both backends.
pub(crate) fn validate_base_url(url: &str, what: &str) -> Result<()> {
    let url = reqwest::Url::parse(url).with_context(|| format!("{what} is not a valid URL"))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("{what} must be a base URL without credentials, query, or fragment");
    }
    let secure = url.scheme() == "https";
    let loopback_http = url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]"));
    if !secure && !loopback_http {
        bail!("{what} must use https:// (http:// is allowed for localhost only)");
    }
    Ok(())
}

pub(crate) fn validate_bws_server_endpoint(server_endpoint: Option<&str>) -> Result<()> {
    service_urls(server_endpoint).map(|_| ())
}

impl BwsRest {
    pub fn new(
        credentials: BwsCredentials,
        server_endpoint: Option<&str>,
        gate: Arc<dyn Authorizer>,
    ) -> Result<Self> {
        let (identity_url, api_url) = service_urls(server_endpoint)?;
        let pending = match credentials {
            BwsCredentials::Env(token) => TokenSource::Parsed(AccessToken::parse(&token)?),
            BwsCredentials::Keychain => TokenSource::Keychain,
        };
        Ok(Self {
            identity_url,
            api_url,
            http: http_client()?,
            gate,
            state: tokio::sync::Mutex::new(AuthState {
                source: pending,
                session: None,
                failed_at: None,
            }),
            login_backoff: LOGIN_RETRY_BACKOFF,
        })
    }

    /// Read and parse a keychain-stored token. The Touch ID gate must approve
    /// BEFORE anything is read from the Keychain.
    async fn resolve_keychain_token(&self) -> Result<AccessToken> {
        let ctx = AuthContext::UnlockCredentials {
            reason: "unlock the Bitwarden Secrets Manager access token",
        };
        let approved = self
            .gate
            .approve(&ctx)
            .await
            .context("failed to evaluate the credential-unlock authorization")?;
        if !approved {
            bail!("credential unlock denied — the keychain was not read");
        }
        let token = keychain::read(keychain::BWS_ACCESS_TOKEN)?;
        AccessToken::parse(&token)
    }

    /// `connect/token` exchange + org-key decryption. HTTP error bodies are
    /// deliberately dropped: they can echo request parameters.
    async fn authenticate(&self, token: &AccessToken) -> Result<Session> {
        let response = self
            .http
            .post(format!("{}/connect/token", self.identity_url))
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("scope", "api.secrets"),
                ("client_id", &token.client_id.to_string()),
                ("client_secret", &token.client_secret),
                ("grant_type", "client_credentials"),
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
            encrypted_payload: String,
        }
        let token_response: TokenResponse = json_capped(response)
            .await
            .context("token exchange failed")?;

        let payload = EncString::parse(&token_response.encrypted_payload)
            .context("token exchange failed: bad encrypted_payload")?
            .decrypt(&token.encryption_key)
            .context("token exchange failed: payload decryption")?;

        #[derive(Deserialize)]
        struct Payload {
            #[serde(rename = "encryptionKey")]
            encryption_key: String,
        }
        let payload: Payload = serde_json::from_slice(&payload)
            .context("token exchange failed: payload is not the expected JSON")?;
        let org_key = B64
            .decode(&payload.encryption_key)
            .context("token exchange failed: organization key is not base64")
            .and_then(|k| SymKey::from_bytes(&k))
            .context("token exchange failed: bad organization key")?;

        Ok(Session {
            bearer: token_response.access_token,
            org_key,
        })
    }
}

#[async_trait]
impl SecretFetcher for BwsRest {
    async fn get(&self, id: Uuid) -> Result<SecretData> {
        let mut state = self.state.lock().await;
        // At most two attempts: the second runs only after a 401, on a fresh
        // login. Bounded by the range, so no change to the condition below can
        // turn it into an endless loop.
        let mut response = None;
        for attempt in 0..2 {
            if state.session.is_none() {
                check_login_backoff(state.failed_at, self.login_backoff)?;
                let login = match &state.source {
                    TokenSource::Parsed(token) => self.authenticate(token).await,
                    TokenSource::Keychain => match self.resolve_keychain_token().await {
                        Ok(token) => self.authenticate(&token).await,
                        Err(e) => Err(e),
                    },
                };
                match login {
                    Ok(session) => {
                        state.session = Some(session);
                        state.failed_at = None;
                    }
                    Err(e) => {
                        state.failed_at = Some(std::time::Instant::now());
                        return Err(e);
                    }
                }
            }
            let Some(session) = &state.session else {
                bail!("no session established");
            };
            let fetched = self
                .http
                .get(format!("{}/secrets/{}", self.api_url, id))
                .bearer_auth(&session.bearer)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .context("secret fetch failed: request error")?;
            if fetched.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                state.session = None;
                continue;
            }
            response = Some(fetched);
            break;
        }
        let Some(response) = response else {
            bail!("no session established");
        };
        let Some(session) = &state.session else {
            bail!("no session established");
        };

        let status = response.status();
        if !status.is_success() {
            bail!("secret fetch failed: HTTP {status}");
        }

        #[derive(Deserialize)]
        struct SecretResponse {
            key: String,
            value: String,
        }
        let secret: SecretResponse = json_capped(response).await.context("secret fetch failed")?;

        Ok(SecretData {
            name: EncString::parse(&secret.key)?
                .decrypt_to_string(&session.org_key)
                .context("secret fetch failed: key decryption")?,
            openssh_private_key: EncString::parse(&secret.value)?
                .decrypt_to_string(&session.org_key)
                .context("secret fetch failed: value decryption")?,
        })
    }
}

/// Public test fixture from the official SDK's access_token.rs tests — not a
/// real credential.
#[cfg(test)]
pub(crate) const SDK_TEST_TOKEN: &str = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

/// Test fixture: the stub-server routes that let a `BwsRest` built from
/// `SDK_TEST_TOKEN` complete the token exchange and resolve `id` to
/// `(name, private_key)`. Shared with the `doctor --check-backend` tests.
#[cfg(test)]
pub(crate) fn bws_stub_routes(
    id: Uuid,
    name: &str,
    private_key: &str,
) -> Vec<(String, u16, String)> {
    use base64::engine::general_purpose::STANDARD as B64_PAD;

    let token_key = AccessToken::parse(SDK_TEST_TOKEN)
        .expect("fixture token parses")
        .encryption_key;
    let org_key = SymKey {
        enc: [0x33; 32],
        mac: [0x44; 32],
    };
    let mut org_bytes = org_key.enc.to_vec();
    org_bytes.extend_from_slice(&org_key.mac);
    let payload = format!(r#"{{"encryptionKey":"{}"}}"#, B64_PAD.encode(&org_bytes));
    vec![
        (
            "/identity/connect/token".to_string(),
            200,
            format!(
                r#"{{"access_token":"stub-bearer","encrypted_payload":"{}"}}"#,
                make_enc_string(payload.as_bytes(), &token_key, [0x01; 16])
            ),
        ),
        (
            format!("/api/secrets/{id}"),
            200,
            format!(
                r#"{{"key":"{}","value":"{}"}}"#,
                make_enc_string(name.as_bytes(), &org_key, [0x02; 16]),
                make_enc_string(private_key.as_bytes(), &org_key, [0x03; 16])
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64_PAD;

    #[test]
    fn parses_access_token_and_derives_sdk_known_key() {
        let token = AccessToken::parse(SDK_TEST_TOKEN).unwrap();
        assert_eq!(
            token.client_id.to_string(),
            "ec2c1d46-6a4b-4751-a310-af9601317f2d"
        );
        assert_eq!(token.client_secret, "C2IgxjjLF7qSshsbwe8JGcbM075YXw");
        // Expected enc||mac key from the SDK's own test vector.
        let mut key = token.encryption_key.enc.to_vec();
        key.extend_from_slice(&token.encryption_key.mac);
        assert_eq!(
            B64_PAD.encode(&key),
            "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg=="
        );
    }

    #[test]
    fn accepts_access_token_without_base64_padding() {
        let unpadded = SDK_TEST_TOKEN.trim_end_matches('=');
        assert!(AccessToken::parse(unpadded).is_ok());
    }

    #[test]
    fn rejects_malformed_access_tokens() {
        for bad in [
            // wrong version
            "1.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:X8vbvA0bduihIDe/qrzIQQ==",
            // missing key part
            "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret",
            // wrong number of '.' parts
            "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.a.b:X8vbvA0bduihIDe/qrzIQQ==",
            // client id not a uuid
            "0.not-a-uuid.secret:X8vbvA0bduihIDe/qrzIQQ==",
            // key not base64
            "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:!!!!",
            // key wrong length (12 bytes)
            "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:aGVsbG8gd29ybGQh",
            "",
        ] {
            assert!(AccessToken::parse(bad).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn a_symmetric_key_of_the_wrong_length_is_refused() {
        // SymKey has no Debug (it is key material), so no expect_err here.
        let err = match SymKey::from_bytes(&[0u8; 32]) {
            Ok(_) => panic!("a 32-byte key must not pass as an enc+mac pair"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("64 bytes"), "{err}");
    }

    #[test]
    fn access_token_errors_never_echo_the_token() {
        let secret_marker = "SUPERSECRETVALUE";
        let bad = format!("9.{secret_marker}.{secret_marker}:{secret_marker}");
        let err = match AccessToken::parse(&bad) {
            Ok(_) => panic!("parse should fail"),
            Err(e) => format!("{e:#}"),
        };
        assert!(!err.contains(secret_marker), "error leaked token: {err}");
    }

    fn test_key() -> SymKey {
        SymKey {
            enc: [0x11; 32],
            mac: [0x22; 32],
        }
    }

    #[test]
    fn enc_string_round_trips() {
        let key = test_key();
        let s = make_enc_string(b"-----BEGIN OPENSSH PRIVATE KEY-----", &key, [0x33; 16]);
        let out = EncString::parse(&s).unwrap().decrypt(&key).unwrap();
        assert_eq!(out, b"-----BEGIN OPENSSH PRIVATE KEY-----");
    }

    #[test]
    fn enc_string_rejects_mac_mismatch() {
        let key = test_key();
        let s = make_enc_string(b"payload", &key, [0x33; 16]);
        // Corrupt one ciphertext byte: MAC check must fail before decryption.
        let mut parsed = EncString::parse(&s).unwrap();
        parsed.data[0] ^= 0x01;
        let err = parsed.decrypt(&key).unwrap_err();
        assert!(err.to_string().contains("MAC"), "unexpected error: {err}");
    }

    #[test]
    fn enc_string_rejects_wrong_key() {
        let key = test_key();
        let s = make_enc_string(b"payload", &key, [0x33; 16]);
        let other = SymKey {
            enc: [0x44; 32],
            mac: [0x55; 32],
        };
        assert!(EncString::parse(&s).unwrap().decrypt(&other).is_err());
    }

    #[test]
    fn enc_string_rejects_malformed_input() {
        for bad in [
            "not an encstring",
            "3.AAAA|BBBB|CCCC",      // unsupported type
            "2.AAAA|BBBB",           // too few parts
            "2.AAAA|BBBB|CCCC|DDDD", // too many parts
            "2.!!|BBBB|CCCC",        // bad base64
        ] {
            assert!(EncString::parse(bad).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn derives_service_urls() {
        assert_eq!(
            service_urls(None).unwrap(),
            (
                "https://identity.bitwarden.com".into(),
                "https://api.bitwarden.com".into()
            )
        );
        assert_eq!(
            service_urls(Some("bitwarden.eu")).unwrap(),
            (
                "https://identity.bitwarden.eu".into(),
                "https://api.bitwarden.eu".into()
            )
        );
        // Full URL → bws-CLI-style path-based routing.
        assert_eq!(
            service_urls(Some("https://vault.example.com/")).unwrap(),
            (
                "https://vault.example.com/identity".into(),
                "https://vault.example.com/api".into()
            )
        );
        assert!(service_urls(Some("http://vault.example.com")).is_err());
        assert!(service_urls(Some("ftp://vault.example.com")).is_err());
        assert!(service_urls(Some("http://localhost:8080")).is_ok());
        assert!(service_urls(Some("http://127.0.0.1:8080")).is_ok());
        assert!(service_urls(Some("http://[::1]:8080")).is_ok());
        assert!(service_urls(Some("")).is_err());
        assert!(service_urls(Some("vault.example.com/path")).is_err());
        assert!(service_urls(Some("https://vault.example.com?query")).is_err());
        // Userinfo must be refused in both branches: reqwest would send it as
        // a Basic-auth header on every request.
        assert!(service_urls(Some("https://user:pass@vault.example.com")).is_err());
        assert!(service_urls(Some("https://user@vault.example.com")).is_err());
        assert!(service_urls(Some("user:pass@vault.example.com")).is_err());
        // Each bare-host rejection stands on its own: a password with no
        // username, a query, or a fragment is enough to refuse the endpoint.
        assert!(service_urls(Some(":pass@vault.example.com")).is_err());
        assert!(service_urls(Some("vault.example.com?query")).is_err());
        assert!(service_urls(Some("vault.example.com#fragment")).is_err());
    }

    /// Real-BWS integration test. Run explicitly with:
    /// `BWS_ACCESS_TOKEN=... TAPWARDEN_TEST_SECRET_ID=... cargo test -- --ignored`
    #[tokio::test]
    #[ignore = "hits real Bitwarden Secrets Manager; needs BWS_ACCESS_TOKEN + TAPWARDEN_TEST_SECRET_ID"]
    async fn fetches_real_secret_from_bws() {
        let token = std::env::var("BWS_ACCESS_TOKEN").expect("BWS_ACCESS_TOKEN not set");
        let id: Uuid = std::env::var("TAPWARDEN_TEST_SECRET_ID")
            .expect("TAPWARDEN_TEST_SECRET_ID not set")
            .parse()
            .expect("TAPWARDEN_TEST_SECRET_ID is not a UUID");
        let endpoint = std::env::var("TAPWARDEN_SERVER_ENDPOINT").ok();
        let fetcher = BwsRest::new(
            BwsCredentials::Env(token),
            endpoint.as_deref(),
            Arc::new(crate::authorizer::AlwaysAllow),
        )
        .unwrap();
        let secret = fetcher.get(id).await.unwrap();
        assert!(!secret.name.is_empty());
        assert!(!secret.openssh_private_key.is_empty());
    }

    // ---- Protocol paths against a loopback stub (no network leaves the box).

    /// Denies every request; `Grace` never covers credential unlocks, so this
    /// is what a user pressing Cancel on the keychain prompt looks like.
    struct DenyAll;

    #[async_trait]
    impl Authorizer for DenyAll {
        async fn approve(&self, _ctx: &AuthContext<'_>) -> Result<bool> {
            Ok(false)
        }
    }

    /// `SecretData` has no `Debug` on purpose (it holds a private key), so
    /// error assertions cannot go through `expect_err`.
    fn err_of(result: Result<SecretData>) -> String {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => format!("{e:#}"),
        }
    }

    fn stub_fetcher(base_url: &str) -> BwsRest {
        BwsRest::new(
            BwsCredentials::Env(SDK_TEST_TOKEN.to_string()),
            Some(base_url),
            Arc::new(crate::authorizer::AlwaysAllow),
        )
        .expect("loopback http endpoint is accepted")
    }

    #[tokio::test]
    async fn authenticates_and_decrypts_a_fetched_secret() {
        let id = Uuid::from_u128(7);
        let server = crate::test_support::StubServer::start(bws_stub_routes(
            id,
            "deploy-key",
            "PRIVATE-KEY-MATERIAL",
        ))
        .await;
        let fetcher = stub_fetcher(&server.base_url);

        let secret = fetcher.get(id).await.expect("stub secret must decrypt");
        assert_eq!(secret.name, "deploy-key");
        assert_eq!(secret.openssh_private_key, "PRIVATE-KEY-MATERIAL");

        // The session is cached: a second fetch must not re-authenticate.
        assert_eq!(fetcher.get(id).await.unwrap().name, "deploy-key");
        assert_eq!(
            server.hits("/identity/connect/token"),
            1,
            "one login, reused"
        );
    }

    /// Counts prompts; always says no.
    struct DenyingGate(std::sync::atomic::AtomicUsize);

    #[async_trait]
    impl Authorizer for DenyingGate {
        async fn approve(&self, _ctx: &AuthContext<'_>) -> Result<bool> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(false)
        }
    }

    /// Listing keys is the first thing every `ssh` does. When the login
    /// cannot succeed (offline, prompt dismissed), each one used to raise a
    /// fresh Touch ID prompt — and one per configured key. After a failure
    /// the fetcher waits out a short backoff before prompting again.
    #[tokio::test]
    async fn a_failed_login_is_not_retried_until_the_backoff_passes() {
        let gate = Arc::new(DenyingGate(Default::default()));
        let mut fetcher = BwsRest::new(BwsCredentials::Keychain, None, gate.clone()).unwrap();
        fetcher.login_backoff = Duration::from_millis(200);
        let prompts = || gate.0.load(std::sync::atomic::Ordering::SeqCst);

        err_of(fetcher.get(Uuid::from_u128(1)).await);
        assert_eq!(prompts(), 1);
        let err = err_of(fetcher.get(Uuid::from_u128(2)).await);
        assert_eq!(
            prompts(),
            1,
            "a second key within the backoff must not prompt"
        );
        assert!(err.contains("retrying"), "{err}");

        tokio::time::sleep(Duration::from_millis(250)).await;
        err_of(fetcher.get(Uuid::from_u128(1)).await);
        assert_eq!(prompts(), 2, "after the backoff the login is tried again");
    }

    /// The bearer expires after about an hour, and a key whose first fetch
    /// failed is retried later. A 401 on the fetch must re-authenticate and
    /// retry once instead of failing until the agent restarts.
    #[tokio::test]
    async fn an_expired_bearer_is_renewed_on_401() {
        let id = Uuid::from_u128(7);
        let secret_path = format!("/api/secrets/{id}");
        let mut routes = vec![(secret_path.clone(), 401, "{}".to_string())];
        routes.extend(bws_stub_routes(id, "deploy-key", "PRIVATE-KEY-MATERIAL"));
        let server = crate::test_support::StubServer::start(routes).await;
        let fetcher = stub_fetcher(&server.base_url);

        let secret = fetcher
            .get(id)
            .await
            .expect("a renewed session must fetch the secret");
        assert_eq!(secret.name, "deploy-key");
        assert_eq!(
            server.hits("/identity/connect/token"),
            2,
            "401 must re-authenticate"
        );
        assert_eq!(server.hits(&secret_path), 2, "and retry the fetch once");
    }

    /// A 401 that survives a fresh login is a real authorization failure,
    /// not an expired bearer: report it, do not loop.
    #[tokio::test]
    async fn a_401_after_renewal_is_reported_not_retried_forever() {
        let id = Uuid::from_u128(7);
        let secret_path = format!("/api/secrets/{id}");
        let mut routes = vec![(secret_path.clone(), 401, "{}".to_string())];
        routes.extend(bws_stub_routes(id, "deploy-key", "k"));
        routes.retain(|(path, status, _)| path != &secret_path || *status == 401);
        let server = crate::test_support::StubServer::start(routes).await;

        let err = err_of(stub_fetcher(&server.base_url).get(id).await);
        assert!(err.contains("401"), "{err}");
        assert_eq!(server.hits(&secret_path), 2);
    }

    #[tokio::test]
    async fn token_exchange_failure_reports_status_without_a_body() {
        let server = crate::test_support::StubServer::start(vec![(
            "/identity/connect/token".to_string(),
            401,
            r#"{"error":"invalid_client","hint":"SUPERSECRETVALUE"}"#.to_string(),
        )])
        .await;
        let err = err_of(stub_fetcher(&server.base_url).get(Uuid::from_u128(7)).await);
        assert!(err.contains("401"), "{err}");
        assert!(
            !err.contains("SUPERSECRETVALUE"),
            "error echoed the body: {err}"
        );
    }

    #[tokio::test]
    async fn secret_fetch_failure_reports_status_without_a_body() {
        let id = Uuid::from_u128(7);
        let mut routes = bws_stub_routes(id, "n", "k");
        routes.pop(); // leave only the token exchange; the secret 404s
        let server = crate::test_support::StubServer::start(routes).await;
        let err = err_of(stub_fetcher(&server.base_url).get(id).await);
        assert!(err.contains("404"), "{err}");
    }

    #[tokio::test]
    async fn keychain_token_is_never_read_when_the_gate_denies() {
        let server = crate::test_support::StubServer::start(vec![]).await;
        let fetcher = BwsRest::new(
            BwsCredentials::Keychain,
            Some(&server.base_url),
            Arc::new(DenyAll),
        )
        .unwrap();
        let err = err_of(fetcher.get(Uuid::from_u128(7)).await);
        assert!(err.contains("denied"), "{err}");
        assert!(
            err.contains("keychain was not read"),
            "the denial must happen before any keychain read: {err}"
        );
    }

    /// One GET against a stub server through the real client. The server is
    /// returned with the response because the body is still being streamed:
    /// the cap logic must run over real chunked reads.
    async fn stub_get(
        routes: Vec<(String, u16, String)>,
        path: &str,
    ) -> (crate::test_support::StubServer, reqwest::Response) {
        let server = crate::test_support::StubServer::start(routes).await;
        let response = http_client()
            .unwrap()
            .get(format!("{}{path}", server.base_url))
            .send()
            .await
            .unwrap();
        (server, response)
    }

    fn padded_body(bytes: usize) -> String {
        format!(r#"{{"pad":"{}"}}"#, "x".repeat(bytes))
    }

    #[tokio::test]
    async fn the_backend_client_never_follows_a_redirect() {
        // A 307/308 would replay a credential-bearing POST at whatever origin
        // a compromised server names, so a redirect is data, never an
        // instruction.
        let (_server, response) = stub_get(
            vec![
                ("/bounce".to_string(), 302, "/followed".to_string()),
                (
                    "/followed".to_string(),
                    200,
                    r#"{"followed":true}"#.to_string(),
                ),
            ],
            "/bounce",
        )
        .await;
        assert_eq!(
            response.status(),
            302,
            "the redirect must come back to the caller, not be followed"
        );
    }

    #[tokio::test]
    async fn oversized_response_bodies_are_refused() {
        let big = padded_body(MAX_RESPONSE_BYTES);
        let (_server, response) = stub_get(vec![("/big".to_string(), 200, big)], "/big").await;
        let err = format!(
            "{:#}",
            json_capped::<serde_json::Value>(response)
                .await
                .expect_err("a body over the cap must be refused")
        );
        assert!(err.contains("size limit"), "{err}");
    }

    #[tokio::test]
    async fn the_response_cap_still_admits_an_ordinary_payload() {
        // A private key plus metadata is kilobytes; the cap exists to stop a
        // malicious server from OOMing the agent, not to clip real secrets.
        let (_server, response) = stub_get(
            vec![("/ok".to_string(), 200, padded_body(64 * 1024))],
            "/ok",
        )
        .await;
        let value: serde_json::Value = json_capped(response)
            .await
            .expect("a 64 KiB body is well within the cap");
        assert_eq!(value["pad"].as_str().map(str::len), Some(64 * 1024));
    }

    #[tokio::test]
    async fn the_sync_cap_admits_a_vault_the_default_cap_would_refuse() {
        // `/api/sync` returns the whole vault: multi-MiB accounts are normal,
        // and only that one call gets the bigger ceiling.
        const VAULT: usize = 3 * 1024 * 1024;
        let body = padded_body(VAULT);
        let (_server, response) =
            stub_get(vec![("/sync".to_string(), 200, body.clone())], "/sync").await;
        let value: serde_json::Value = json_capped_limit(response, MAX_SYNC_RESPONSE_BYTES)
            .await
            .expect("a 3 MiB vault must survive the sync cap");
        assert_eq!(value["pad"].as_str().map(str::len), Some(VAULT));

        let (_server, response) = stub_get(vec![("/sync".to_string(), 200, body)], "/sync").await;
        json_capped::<serde_json::Value>(response)
            .await
            .expect_err("the ordinary per-request cap is much lower");
    }

    #[tokio::test]
    async fn the_cap_admits_a_body_of_exactly_the_limit_and_nothing_past_it() {
        let body = r#"{"pad":"exact"}"#.to_string();
        let limit = body.len();

        let (_server, response) = stub_get(vec![("/x".to_string(), 200, body.clone())], "/x").await;
        json_capped_limit::<serde_json::Value>(response, limit)
            .await
            .expect("a body of exactly the limit fits");

        let (_server, response) = stub_get(vec![("/x".to_string(), 200, body)], "/x").await;
        let err = format!(
            "{:#}",
            json_capped_limit::<serde_json::Value>(response, limit - 1)
                .await
                .expect_err("one byte over the limit is refused")
        );
        assert!(err.contains("size limit"), "{err}");
    }

    #[test]
    fn store_token_validation_accepts_only_well_formed_tokens() {
        assert!(validate_access_token(SDK_TEST_TOKEN).is_ok());
        assert!(validate_access_token("nonsense").is_err());
    }
}
