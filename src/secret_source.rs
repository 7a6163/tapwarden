use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::{alphabet, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::time::Duration;
use uuid::Uuid;

/// Bound every backend request: a stalled connection must never wedge the
/// agent (the key cache mutex is held across fetches, so an unbounded request
/// would block all signing and identity listing forever).
// ponytail: fixed timeouts; make configurable if a slow self-hosted server appears.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
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
    /// Lazily-established session, shared across `get` calls. The parsed
    /// access token lives only in `Pending` and is dropped from memory on the
    /// first successful authenticate.
    // ponytail: bearer expiry ignored — the agent fetches each secret once and
    // caches it in memory; add re-auth on HTTP 401 if long-lived refetch appears.
    state: tokio::sync::Mutex<AuthState>,
}

enum AuthState {
    /// Credentials held only until the first successful login; a failed
    /// attempt leaves them in place so a later `get` can retry.
    Pending(AccessToken),
    Ready(Session),
}

// No Debug impl on purpose: the struct holds the client secret and key material.

/// `bitwarden.com` (default) / `bitwarden.eu` / bare self-hosted host →
/// `https://identity.<host>` + `https://api.<host>`. A full URL (self-hosted
/// behind one origin) mirrors the bws CLI's `server_base`: `<base>/identity` +
/// `<base>/api`.
fn service_urls(server_endpoint: Option<&str>) -> (String, String) {
    let endpoint = server_endpoint
        .unwrap_or("bitwarden.com")
        .trim_end_matches('/');
    if endpoint.contains("://") {
        (format!("{endpoint}/identity"), format!("{endpoint}/api"))
    } else {
        (
            format!("https://identity.{endpoint}"),
            format!("https://api.{endpoint}"),
        )
    }
}

impl BwsRest {
    pub fn new(access_token: &str, server_endpoint: Option<&str>) -> Result<Self> {
        let (identity_url, api_url) = service_urls(server_endpoint);
        Ok(Self {
            identity_url,
            api_url,
            http: http_client()?,
            state: tokio::sync::Mutex::new(AuthState::Pending(AccessToken::parse(access_token)?)),
        })
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
        if let AuthState::Pending(token) = &*state {
            let session = self.authenticate(token).await?;
            // Success: replacing the state drops the access token from memory.
            *state = AuthState::Ready(session);
        }
        let AuthState::Ready(session) = &*state else {
            bail!("access token already consumed but no session established");
        };

        let response = self
            .http
            .get(format!("{}/secrets/{}", self.api_url, id))
            .bearer_auth(&session.bearer)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("secret fetch failed: request error")?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64_PAD;

    // Public test fixture from the official SDK's access_token.rs tests —
    // not a real credential.
    const SDK_TEST_TOKEN: &str =
        "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

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
            service_urls(None),
            (
                "https://identity.bitwarden.com".into(),
                "https://api.bitwarden.com".into()
            )
        );
        assert_eq!(
            service_urls(Some("bitwarden.eu")),
            (
                "https://identity.bitwarden.eu".into(),
                "https://api.bitwarden.eu".into()
            )
        );
        // Full URL → bws-CLI-style path-based routing.
        assert_eq!(
            service_urls(Some("https://vault.example.com/")),
            (
                "https://vault.example.com/identity".into(),
                "https://vault.example.com/api".into()
            )
        );
    }

    /// Real-BWS integration test. Run explicitly with:
    /// `BWS_ACCESS_TOKEN=... SIGILO_TEST_SECRET_ID=... cargo test -- --ignored`
    #[tokio::test]
    #[ignore = "hits real Bitwarden Secrets Manager; needs BWS_ACCESS_TOKEN + SIGILO_TEST_SECRET_ID"]
    async fn fetches_real_secret_from_bws() {
        let token = std::env::var("BWS_ACCESS_TOKEN").expect("BWS_ACCESS_TOKEN not set");
        let id: Uuid = std::env::var("SIGILO_TEST_SECRET_ID")
            .expect("SIGILO_TEST_SECRET_ID not set")
            .parse()
            .expect("SIGILO_TEST_SECRET_ID is not a UUID");
        let endpoint = std::env::var("SIGILO_SERVER_ENDPOINT").ok();
        let fetcher = BwsRest::new(&token, endpoint.as_deref()).unwrap();
        let secret = fetcher.get(id).await.unwrap();
        assert!(!secret.name.is_empty());
        assert!(!secret.openssh_private_key.is_empty());
    }
}
