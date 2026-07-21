use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use signature::Signer as _;
use ssh_agent_lib::agent::{Session, listen};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::{Algorithm, PrivateKey, Signature};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

use crate::authorizer::{AuthContext, Authorizer, Biometric, Grace};
use crate::config::{AuthMode, Backend, Config, CredentialSource};
use crate::runtime_paths;
use crate::secret_source::{BwsRest, SecretFetcher};
use crate::vaultwarden::{VaultwardenFetcher, VwCredentials};

struct LoadedKey {
    key: PrivateKey,
    comment: String,
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
    Ok(LoadedKey { key, comment })
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
    let authorizer = build_authorizer(config);
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
        let (key, comment) = {
            let keys = self.loaded_keys().await;
            let entry = keys
                .values()
                .find(|k| k.key.public_key().key_data() == request.credential.key_data())
                .ok_or(AgentError::Failure)?;
            (entry.key.clone(), entry.comment.clone())
        };

        // INVARIANT: every sign passes through the Authorizer before the key
        // is used — this gate is tapwarden's whole point.
        let ctx = AuthContext::Sign {
            key_comment: &comment,
            data_len: request.data.len(),
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
            let token = config.access_token()?;
            Ok(Box::new(
                BwsRest::new(&token, config.server_endpoint.as_deref())
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

fn build_authorizer(config: &Config) -> Arc<dyn Authorizer> {
    match config.authorization.mode {
        AuthMode::PerUse => Arc::new(Biometric),
        AuthMode::Grace => Arc::new(Grace::new(
            Box::new(Biometric),
            Duration::from_secs(config.authorization.grace_seconds),
        )),
    }
}

pub async fn run_foreground(config: Config) -> Result<()> {
    let secret_ids = config
        .secret_ids
        .iter()
        .map(|s| Uuid::parse_str(s).with_context(|| format!("secret id `{s}` is not a UUID")))
        .collect::<Result<Vec<_>>>()?;

    // One authorizer instance gates both signatures and (for the keychain
    // credential source) backend credential reads — the latter always prompt.
    let authorizer = build_authorizer(&config);
    let service = Arc::new(KeyService::new(
        secret_ids,
        build_fetcher(&config, authorizer.clone())?,
        authorizer,
    ));

    let socket = runtime_paths::socket_path()?;
    // Never hijack a live instance: only remove the socket if nothing answers.
    match UnixStream::connect(&socket).await {
        Ok(_) => bail!(
            "another tapwarden instance is already listening on {}",
            socket.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        // Stale socket (connection refused): the previous instance is gone.
        Err(_) => match std::fs::remove_file(&socket) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to remove stale socket {}", socket.display())
                });
            }
        },
    }

    // Tighten umask BEFORE binding so the socket is never briefly accessible
    // (no bind-then-chmod race). Real access control is the 0700 runtime dir.
    // SAFETY: umask() only swaps the process file-mode creation mask; it
    // cannot fail and touches no memory.
    let old_umask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(&socket);
    // SAFETY: same as above; restores the mask captured before bind.
    unsafe { libc::umask(old_umask) };
    let listener =
        listener.with_context(|| format!("failed to bind socket {}", socket.display()))?;

    println!("export SSH_AUTH_SOCK={}", socket.display());

    let result = tokio::select! {
        r = listen(listener, TapwardenSession(service)) => {
            r.context("agent listener failed")
        }
        _ = shutdown_signal() => Ok(()),
    };
    // Best-effort cleanup: tolerate an already-gone socket and never let a
    // cleanup failure mask the listener result.
    if let Err(e) = std::fs::remove_file(&socket) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "tapwarden: failed to remove socket {}: {e}",
                socket.display()
            );
        }
    }
    result
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

    /// Throwaway key generated for these tests only — never used anywhere real.
    const TEST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCchMvXfB6t0MgCDWTEX3BFd3ryJu7qUK+i+YOxqMDgkQAAAJgrZITGK2SE
xgAAAAtzc2gtZWQyNTUxOQAAACCchMvXfB6t0MgCDWTEX3BFd3ryJu7qUK+i+YOxqMDgkQ
AAAEAm+GqINSVahnMAQlWg2nq5Hv32qMRXAMb2+tLQm/aQvZyEy9d8Hq3QyAINZMRfcEV3
evIm7upQr6L5g7GowOCRAAAAE3VuaXQtdGVzdEB0YXB3YXJkZW4BAg==
-----END OPENSSH PRIVATE KEY-----
";

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
}
