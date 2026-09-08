use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use signature::Signer as _;
use ssh_agent_lib::agent::{Session, listen};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

use crate::authorizer::{AuthContext, Authorizer, Biometric, Grace, YubikeyTouch};
use crate::config::{AuthFactor, AuthMode, Backend, Config, CredentialSource};
use crate::runtime_paths;
use crate::secret_source::{BwsCredentials, BwsRest, SecretFetcher};
use crate::vaultwarden::{VaultwardenFetcher, VwCredentials};

struct LoadedKey {
    key: PrivateKey,
    comment: String,
    fingerprint: String,
}

/// Fetch one secret, decode it as an Ed25519 OpenSSH key, and derive its
/// display comment. Shared by the running agent and `doctor --check-backend`.
async fn load_key(fetcher: &dyn SecretFetcher, id: Uuid) -> Result<LoadedKey> {
    let secret = fetcher.get(id).await?;
    let key = PrivateKey::from_openssh(&secret.openssh_private_key)
        .context("secret value is not an OpenSSH private key")?;
    if key.algorithm() != Algorithm::Ed25519 {
        bail!(
            "secret \"{}\" holds a {} key — tapwarden serves Ed25519 keys only",
            secret.name,
            key.algorithm()
        );
    }
    let comment = if key.comment().is_empty() {
        secret.name
    } else {
        key.comment().to_string()
    };
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    Ok(LoadedKey {
        key,
        comment,
        fingerprint,
    })
}

/// Doctor helper: build the real backend fetcher and try to load every
/// configured key, returning the resolved comment on success or the per-id
/// error. With the keychain credential source this reads credentials behind
/// the authorizer, so it may raise a Touch ID prompt.
pub async fn probe_keys(config: &Config) -> Result<Vec<(Uuid, Result<String>)>> {
    let secret_ids = config
        .secret_ids
        .iter()
        .map(|s| Uuid::parse_str(s).with_context(|| format!("secret id `{s}` is not a UUID")))
        .collect::<Result<Vec<_>>>()?;
    let authorizer = build_authorizer(config)?;
    let fetcher = build_fetcher(config, authorizer)?;
    let mut out = Vec::with_capacity(secret_ids.len());
    for id in secret_ids {
        let comment = load_key(fetcher.as_ref(), id).await.map(|k| k.comment);
        out.push((id, comment));
    }
    Ok(out)
}

/// Shared agent state: lazy in-memory key cache plus the two injected traits.
/// Private keys live only in this struct — never on disk, in logs, or errors.
struct KeyService {
    secret_ids: Vec<Uuid>,
    fetcher: Box<dyn SecretFetcher>,
    authorizer: Arc<dyn Authorizer>,
    keys: tokio::sync::Mutex<HashMap<Uuid, LoadedKey>>,
}

impl KeyService {
    fn new(
        secret_ids: Vec<Uuid>,
        fetcher: Box<dyn SecretFetcher>,
        authorizer: Arc<dyn Authorizer>,
    ) -> Self {
        Self {
            secret_ids,
            fetcher,
            authorizer,
            keys: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    async fn load_one(&self, id: Uuid) -> Result<LoadedKey> {
        load_key(self.fetcher.as_ref(), id).await
    }

    /// Lazily fetch any not-yet-loaded secrets. A failure for one id is
    /// reported to stderr (no secret material in the message) and skipped, so
    /// it never poisons the other keys.
    // ponytail: failed ids are refetched on every request; cache permanent
    // failures (e.g. non-Ed25519) if the extra BWS round-trips ever matter.
    async fn loaded_keys(&self) -> tokio::sync::MutexGuard<'_, HashMap<Uuid, LoadedKey>> {
        let mut keys = self.keys.lock().await;
        for id in &self.secret_ids {
            if keys.contains_key(id) {
                continue;
            }
            match self.load_one(*id).await {
                Ok(loaded) => {
                    keys.insert(*id, loaded);
                }
                Err(e) => eprintln!("tapwarden: skipping secret {id}: {e:#}"),
            }
        }
        keys
    }

    /// Public keys + comments only; no authorization prompt (matches
    /// 1Password's agent behavior — listing is not signing).
    async fn identities(&self) -> Vec<Identity> {
        self.loaded_keys()
            .await
            .values()
            .map(|k| Identity {
                credential: PublicCredential::Key(k.key.public_key().key_data().clone()),
                comment: k.comment.clone(),
            })
            .collect()
    }

    async fn sign(&self, request: SignRequest) -> Result<Signature, AgentError> {
        // Clone the key out and drop the lock so a pending Touch ID prompt
        // doesn't block identity listing from other clients.
        let (key, comment, fingerprint) = {
            let keys = self.loaded_keys().await;
            let entry = keys
                .values()
                .find(|k| k.key.public_key().key_data() == request.credential.key_data())
                .ok_or(AgentError::Failure)?;
            (
                entry.key.clone(),
                entry.comment.clone(),
                entry.fingerprint.clone(),
            )
        };

        // INVARIANT: every sign passes through the Authorizer before the key
        // is used — this gate is tapwarden's whole point.
        let ctx = AuthContext::Sign {
            key_comment: &comment,
            key_fingerprint: &fingerprint,
        };
        let approved = self
            .authorizer
            .approve(&ctx)
            .await
            .map_err(|e| AgentError::Other(e.into()))?;
        if !approved {
            return Err(AgentError::Failure); // SSH_AGENT_FAILURE; key untouched
        }

        key.try_sign(&request.data).map_err(AgentError::other)
    }
}

/// One session per client connection; all sessions share the `KeyService`.
#[derive(Clone)]
struct TapwardenSession(Arc<KeyService>);

#[ssh_agent_lib::async_trait]
impl Session for TapwardenSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(self.0.identities().await)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        self.0.sign(request).await
    }
}

/// Backend selection. Env-sourced secrets are resolved here, at use time, and
/// immediately move into the fetcher (memory only); keychain-sourced ones are
/// read at first authenticate, behind the authorizer.
fn build_fetcher(
    config: &Config,
    authorizer: Arc<dyn Authorizer>,
) -> Result<Box<dyn SecretFetcher>> {
    match config.backend {
        Backend::Bws => {
            let credentials = match config.credentials {
                CredentialSource::Env => BwsCredentials::Env(config.access_token()?),
                CredentialSource::Keychain => BwsCredentials::Keychain,
            };
            Ok(Box::new(
                BwsRest::new(credentials, config.server_endpoint.as_deref(), authorizer)
                    .context("failed to initialize the Bitwarden Secrets Manager client")?,
            ))
        }
        Backend::Vaultwarden => {
            // Config::validate() guarantees the section exists; keep a real
            // error anyway rather than a panic path.
            let vw = config.vaultwarden.as_ref().context(
                "backend is vaultwarden but the `vaultwarden` config section is missing",
            )?;
            let credentials = match vw.credentials {
                CredentialSource::Env => VwCredentials::Env {
                    client_id: vw.client_id()?,
                    client_secret: vw.client_secret()?,
                    master_password: vw.master_password()?,
                },
                CredentialSource::Keychain => VwCredentials::Keychain,
            };
            Ok(Box::new(
                VaultwardenFetcher::new(&vw.server_url, &vw.email, credentials, authorizer)
                    .context("failed to initialize the Vaultwarden client")?,
            ))
        }
    }
}

fn build_authorizer(config: &Config) -> Result<Arc<dyn Authorizer>> {
    let factor: Box<dyn Authorizer> = match config.authorization.factor {
        AuthFactor::TouchId => Box::new(Biometric),
        AuthFactor::Yubikey => {
            let yk = config.authorization.yubikey.as_ref().context(
                "factor is yubikey but no credential is registered — run `tapwarden register-yubikey`",
            )?;
            let (credential_id, public_key) = yk.verifier()?;
            Box::new(YubikeyTouch::new(credential_id, public_key))
        }
    };
    Ok(match config.authorization.mode {
        AuthMode::PerUse => Arc::from(factor),
        AuthMode::Grace => Arc::new(Grace::new(
            factor,
            Duration::from_secs(config.authorization.grace_seconds),
        )),
    })
}

pub async fn run_foreground(config: Config) -> Result<()> {
    let socket = runtime_paths::socket_path()?;
    serve(config, socket).await
}

/// Serve the agent protocol on `socket` until a shutdown signal. Takes the
/// path rather than resolving it so tests can drive a real agent on a
/// throwaway socket instead of the one the user's SSH is pointed at.
async fn serve(config: Config, socket: std::path::PathBuf) -> Result<()> {
    let secret_ids = config
        .secret_ids
        .iter()
        .map(|s| Uuid::parse_str(s).with_context(|| format!("secret id `{s}` is not a UUID")))
        .collect::<Result<Vec<_>>>()?;

    // One authorizer instance gates both signatures and (for the keychain
    // credential source) backend credential reads — the latter always prompt.
    let authorizer = build_authorizer(&config)?;
    let service = Arc::new(KeyService::new(
        secret_ids,
        build_fetcher(&config, authorizer.clone())?,
        authorizer,
    ));

    let listener = claim_socket(&socket).await?;

    println!("export SSH_AUTH_SOCK={}", socket.display());

    let result = tokio::select! {
        r = listen(listener, TapwardenSession(service)) => {
            r.context("agent listener failed")
        }
        _ = shutdown_signal() => Ok(()),
    };
    // Cleanup is best-effort and must never mask the listener result.
    if let Err(e) = release_socket(&socket) {
        eprintln!(
            "tapwarden: failed to remove socket {}: {e}",
            socket.display()
        );
    }
    result
}

/// Remove the socket we bound. An already-gone socket is success — the point
/// is that the path is free, not that we were the one to free it.
fn release_socket(socket: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(socket) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Claim `socket` for a fresh listener.
///
/// Never hijacks a live instance — an answering socket is an error, not
/// something to replace. A socket that refuses the connection was left by a
/// dead instance and is cleared. The umask is tightened *before* the bind so
/// the socket is never briefly accessible (no bind-then-chmod race); real
/// access control is still the 0700 runtime dir.
async fn claim_socket(socket: &std::path::Path) -> Result<UnixListener> {
    match UnixStream::connect(socket).await {
        Ok(_) => bail!(
            "another tapwarden instance is already listening on {}",
            socket.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        // Stale socket (connection refused): the previous instance is gone.
        Err(_) => match std::fs::remove_file(socket) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to remove stale socket {}", socket.display())
                });
            }
        },
    }

    // SAFETY: umask() only swaps the process file-mode creation mask; it
    // cannot fail and touches no memory.
    let old_umask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(socket);
    // SAFETY: same as above; restores the mask captured before bind.
    unsafe { libc::umask(old_umask) };
    listener.with_context(|| format!("failed to bind socket {}", socket.display()))
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => {
            eprintln!("tapwarden: cannot install SIGTERM handler: {e}");
            // Fall back to SIGINT only.
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_source::SecretData;
    use anyhow::anyhow;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::test_support::TEST_ED25519_KEY as TEST_KEY;

    struct FakeFetcher(HashMap<Uuid, String>);

    #[async_trait]
    impl SecretFetcher for FakeFetcher {
        async fn get(&self, id: Uuid) -> Result<SecretData> {
            self.0
                .get(&id)
                .cloned()
                .map(|k| SecretData {
                    name: format!("secret-{id}"),
                    openssh_private_key: k,
                })
                .ok_or_else(|| anyhow!("no such secret"))
        }
    }

    /// Counts approve() calls; answers with a fixed verdict.
    struct Counting {
        allow: bool,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Authorizer for Counting {
        async fn approve(&self, _ctx: &AuthContext<'_>) -> Result<bool> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.allow)
        }
    }

    fn service_with(allow: bool) -> (KeyService, Arc<AtomicUsize>, SignRequest) {
        let calls = Arc::new(AtomicUsize::new(0));
        let authorizer = Arc::new(Counting {
            allow,
            calls: calls.clone(),
        });
        let (service, request) = service_with_authorizer(authorizer);
        (service, calls, request)
    }

    fn service_with_authorizer(authorizer: Arc<dyn Authorizer>) -> (KeyService, SignRequest) {
        let id = Uuid::from_u128(1);
        let fetcher = FakeFetcher(HashMap::from([(id, TEST_KEY.to_string())]));
        let key_data = PrivateKey::from_openssh(TEST_KEY)
            .unwrap()
            .public_key()
            .key_data()
            .clone();
        let request = SignRequest {
            credential: PublicCredential::Key(key_data),
            data: b"data-to-sign".to_vec(),
            flags: 0,
        };
        (
            KeyService::new(vec![id], Box::new(fetcher), authorizer),
            request,
        )
    }

    #[test]
    fn yubikey_authorizer_rejects_malformed_public_key() {
        let config: Config = serde_yaml::from_str(
            r#"
secret_ids: [00000000-0000-0000-0000-000000000000]
authorization:
  factor: yubikey
  yubikey:
    credential_id: AA==
    public_key:
      algorithm: es256
      bytes: AA==
"#,
        )
        .unwrap();
        let err = build_authorizer(&config)
            .err()
            .expect("malformed verifier public key must fail closed");
        assert!(err.to_string().contains("valid ES256"), "{err:#}");
    }

    #[tokio::test]
    async fn sign_approved_produces_signature() {
        let (service, calls, request) = service_with(true);
        let sig = service
            .sign(request)
            .await
            .expect("approved sign must succeed");
        assert_eq!(sig.algorithm(), Algorithm::Ed25519);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sign_denied_returns_failure_without_signing() {
        let (service, calls, request) = service_with(false);
        let err = service
            .sign(request)
            .await
            .expect_err("denied sign must fail");
        assert!(
            matches!(err, AgentError::Failure),
            "denial must be SSH_AGENT_FAILURE"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "authorizer must have been consulted"
        );
    }

    #[tokio::test]
    async fn per_use_prompts_on_every_sign() {
        let (service, calls, request) = service_with(true);
        service.sign(request.clone()).await.unwrap();
        service.sign(request).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "per_use must prompt every time"
        );
    }

    #[tokio::test]
    async fn grace_within_window_skips_prompt() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = Box::new(Counting {
            allow: true,
            calls: calls.clone(),
        });
        let grace = Arc::new(Grace::new(inner, Duration::from_secs(3600)));
        let (service, request) = service_with_authorizer(grace);

        service.sign(request.clone()).await.unwrap();
        service.sign(request).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second sign inside the window must not prompt"
        );
    }

    #[tokio::test]
    async fn request_identities_lists_keys_without_prompting() {
        let (service, calls, _request) = service_with(true);
        let ids = service.identities().await;
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].comment, "unit-test@tapwarden");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "listing must never prompt");
    }

    #[tokio::test]
    async fn one_failing_secret_does_not_poison_others() {
        let good = Uuid::from_u128(1);
        let missing = Uuid::from_u128(2);
        let fetcher = FakeFetcher(HashMap::from([(good, TEST_KEY.to_string())]));
        let service = KeyService::new(
            vec![missing, good],
            Box::new(fetcher),
            Arc::new(crate::authorizer::AlwaysAllow),
        );
        let ids = service.identities().await;
        assert_eq!(
            ids.len(),
            1,
            "the good key must load despite the failing one"
        );
    }

    #[tokio::test]
    async fn sign_with_unknown_key_fails_without_prompting() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (_, _, request) = service_with(true);
        // An agent holding no keys cannot match the requested pubkey.
        let empty = KeyService::new(
            vec![],
            Box::new(FakeFetcher(HashMap::new())),
            Arc::new(Counting {
                allow: true,
                calls: calls.clone(),
            }),
        );
        let err = empty
            .sign(request)
            .await
            .expect_err("unknown key must fail");
        assert!(matches!(err, AgentError::Failure));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "no key match → no prompt");
    }

    // ---- Wiring: config -> concrete fetcher / authorizer.

    fn parse_config(yaml: &str) -> Config {
        serde_yaml::from_str(yaml).expect("test config parses")
    }

    const KEY_ID: &str = "00000000-0000-0000-0000-000000000000";

    #[test]
    fn every_backend_and_credential_source_builds_a_fetcher() {
        // Both are set by .cargo/config.toml: writing them here would race
        // every concurrent getenv in the suite.
        let token = "TAPWARDEN_TEST_BWS_TOKEN";
        let vw = "TAPWARDEN_TEST_VW_CLIENT_ID";

        for yaml in [
            format!("secret_ids: [{KEY_ID}]\naccess_token_env: {token}\n"),
            format!("secret_ids: [{KEY_ID}]\ncredentials: keychain\n"),
            format!(
                "secret_ids: [{KEY_ID}]\nbackend: vaultwarden\nvaultwarden:\n  server_url: https://vault.example.com\n  email: t@example.com\n  client_id_env: {vw}\n  client_secret_env: {vw}\n  master_password_env: {vw}\n"
            ),
            format!(
                "secret_ids: [{KEY_ID}]\nbackend: vaultwarden\nvaultwarden:\n  server_url: https://vault.example.com\n  email: t@example.com\n  credentials: keychain\n"
            ),
        ] {
            let config = parse_config(&yaml);
            build_fetcher(&config, Arc::new(crate::authorizer::AlwaysAllow))
                .unwrap_or_else(|e| panic!("must build a fetcher for:\n{yaml}\n{e:#}"));
        }
    }

    #[test]
    fn a_vaultwarden_config_without_its_section_fails_to_build() {
        let config = parse_config(&format!("secret_ids: [{KEY_ID}]\nbackend: vaultwarden\n"));
        let err = build_fetcher(&config, Arc::new(crate::authorizer::AlwaysAllow))
            .err()
            .expect("no vaultwarden section means no fetcher");
        assert!(err.to_string().contains("vaultwarden"), "{err:#}");
    }

    #[test]
    fn a_malformed_bws_token_fails_before_the_agent_starts() {
        let token = "TAPWARDEN_TEST_BWS_BAD_TOKEN"; // set by .cargo/config.toml
        let config = parse_config(&format!(
            "secret_ids: [{KEY_ID}]\naccess_token_env: {token}\n"
        ));
        assert!(
            build_fetcher(&config, Arc::new(crate::authorizer::AlwaysAllow)).is_err(),
            "a typo'd access token must fail at construction, not at first signature"
        );
    }

    #[test]
    fn authorization_mode_and_factor_select_the_authorizer() {
        let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, {
            let mut k = [0u8; 65];
            k[0] = 0x04;
            k
        });
        for yaml in [
            format!("secret_ids: [{KEY_ID}]\n"),
            format!("secret_ids: [{KEY_ID}]\nauthorization:\n  mode: grace\n  grace_seconds: 5\n"),
            format!(
                "secret_ids: [{KEY_ID}]\nauthorization:\n  mode: grace\n  factor: yubikey\n  yubikey:\n    credential_id: AA==\n    public_key:\n      algorithm: es256\n      bytes: {key}\n"
            ),
        ] {
            let config = parse_config(&yaml);
            build_authorizer(&config)
                .unwrap_or_else(|e| panic!("must build an authorizer for:\n{yaml}\n{e:#}"));
        }
    }

    #[test]
    fn yubikey_factor_without_a_registered_credential_fails_closed() {
        let config = parse_config(&format!(
            "secret_ids: [{KEY_ID}]\nauthorization:\n  factor: yubikey\n"
        ));
        let err = build_authorizer(&config)
            .err()
            .expect("no credential means no authorizer");
        assert!(err.to_string().contains("register-yubikey"), "{err:#}");
    }

    #[tokio::test]
    async fn a_key_with_no_comment_falls_back_to_the_secret_name() {
        let mut key = PrivateKey::from_openssh(TEST_KEY).unwrap();
        key.set_comment("");
        let id = Uuid::from_u128(5);
        let fetcher = FakeFetcher(HashMap::from([(
            id,
            key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
        )]));
        let loaded = load_key(&fetcher, id)
            .await
            .expect("comment-less key loads");
        assert_eq!(loaded.comment, format!("secret-{id}"));
        assert!(!loaded.fingerprint.is_empty());
    }

    #[tokio::test]
    async fn probe_keys_rejects_a_secret_id_that_is_not_a_uuid() {
        let config = parse_config("secret_ids: [not-a-uuid]\n");
        let err = probe_keys(&config)
            .await
            .expect_err("a malformed id must fail the probe");
        assert!(err.to_string().contains("not a UUID"), "{err:#}");
    }

    // ---- Socket lifecycle. Uses a temp path, never the real agent socket.

    /// No assertion on the socket's own mode bits: `umask` is process-global,
    /// so concurrent tests interleave the save/restore and the observed mode is
    /// not deterministic. That is also why the design does not rely on those
    /// bits — access control is the 0700 runtime dir, covered in
    /// `runtime_paths::tests::runtime_dir_is_private_and_ours`.
    #[tokio::test]
    async fn claims_a_free_socket_path() {
        let dir = crate::test_support::TmpDir::new("agent");
        let socket = dir.join("agent.sock");

        let listener = claim_socket(&socket).await.expect("a free path must bind");
        assert!(socket.exists());
        drop(listener);
    }

    /// A just-dropped listener's socket is not deterministically refused under
    /// load, so this plants a non-socket file instead: it reaches the same
    /// branch (connect fails with something that is not NotFound) every time.
    #[tokio::test]
    async fn a_path_that_no_agent_answers_is_cleared_and_rebound() {
        let dir = crate::test_support::TmpDir::new("agent");
        let socket = dir.join("agent.sock");
        std::fs::write(&socket, b"left behind by a dead instance").unwrap();

        let listener = claim_socket(&socket)
            .await
            .expect("a path nobody answers is stale, not a live agent");
        drop(listener);
    }

    #[tokio::test]
    async fn a_live_agent_is_never_hijacked() {
        let dir = crate::test_support::TmpDir::new("agent");
        let socket = dir.join("agent.sock");
        let live = UnixListener::bind(&socket).unwrap();

        let err = format!(
            "{:#}",
            claim_socket(&socket)
                .await
                .expect_err("an answering socket must never be taken over")
        );
        assert!(err.contains("already listening"), "{err}");
        drop(live);
    }

    #[tokio::test]
    async fn an_unbindable_path_reports_the_socket_it_could_not_take() {
        let dir = crate::test_support::TmpDir::new("agent");
        let socket = dir.join("no-such-dir/agent.sock");
        let err = format!(
            "{:#}",
            claim_socket(&socket)
                .await
                .expect_err("a bad path cannot bind")
        );
        assert!(err.contains("failed to bind socket"), "{err}");
    }

    /// End-to-end: a real agent on a throwaway socket, driven with the raw
    /// ssh-agent wire protocol. The only test that exercises the actual
    /// listener wiring rather than `KeyService` in isolation.
    #[tokio::test]
    async fn serves_identities_over_a_real_unix_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const REQUEST_IDENTITIES: u8 = 11;
        const IDENTITIES_ANSWER: u8 = 12;

        let id = Uuid::from_u128(77);
        let backend = crate::test_support::StubServer::start(
            crate::secret_source::bws_stub_routes(id, "deploy-key", TEST_KEY),
        )
        .await;
        let dir = crate::test_support::TmpDir::new("agent-e2e");
        let socket = dir.join("agent.sock");
        let config = parse_config(&format!(
            "secret_ids: [{id}]\naccess_token_env: TAPWARDEN_TEST_BWS_TOKEN\nserver_endpoint: {}\n",
            backend.base_url
        ));

        let agent = tokio::spawn(serve(config, socket.clone()));
        // Bounded: if serve() never binds, fail rather than hang the suite.
        let mut client = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match UnixStream::connect(&socket).await {
                    Ok(stream) => break stream,
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .expect("the agent must bind its socket");

        client
            .write_all(&[0, 0, 0, 1, REQUEST_IDENTITIES])
            .await
            .unwrap();
        let mut len = [0u8; 4];
        client.read_exact(&mut len).await.unwrap();
        let mut payload = vec![0u8; u32::from_be_bytes(len) as usize];
        client.read_exact(&mut payload).await.unwrap();

        assert_eq!(payload[0], IDENTITIES_ANSWER);
        let keys = u32::from_be_bytes(payload[1..5].try_into().unwrap());
        assert_eq!(keys, 1, "the agent must serve the configured key");
        // `load_key` prefers the key's own embedded comment over the secret
        // name, so this is the comment baked into TEST_KEY.
        let comment = b"unit-test@tapwarden";
        assert!(
            payload.windows(comment.len()).any(|w| w == comment),
            "the identity must carry the key comment"
        );

        agent.abort();
    }

    #[test]
    fn releasing_a_socket_reports_only_the_failures_that_matter() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_support::TmpDir::new("agent");
        let socket = dir.join("agent.sock");

        release_socket(&socket).expect("a socket that was never there is already released");
        std::fs::write(&socket, b"x").unwrap();
        release_socket(&socket).expect("our own socket is removed");
        assert!(!socket.exists());

        // A failure that is not "already gone" must surface to the caller.
        let locked = crate::test_support::TmpDir::new("agent-locked");
        let trapped = locked.join("agent.sock");
        std::fs::write(&trapped, b"x").unwrap();
        std::fs::set_permissions(&locked.0, std::fs::Permissions::from_mode(0o555)).unwrap();
        let err = release_socket(&trapped).expect_err("an undeletable socket is an error");
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound);
        std::fs::set_permissions(&locked.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}
