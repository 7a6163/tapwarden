use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result, anyhow};
use async_trait::async_trait;

/// What the user is being asked to approve. The variant matters for `Grace`:
/// only signatures participate in the grace window — credential unlocks always
/// reach the real prompt, so a recent signature never silently unlocks the
/// backend credentials.
pub enum AuthContext<'a> {
    /// One SSH signature with the named key.
    Sign {
        key_comment: &'a str,
        /// Length of the data being signed; not shown in the prompt yet.
        #[allow(dead_code)]
        data_len: usize,
    },
    /// Reading stored backend credentials (e.g. from the macOS Keychain).
    UnlockCredentials { reason: &'a str },
}

/// Gate that must pass before a private key produces a signature.
/// This is tapwarden's core value-add over other Bitwarden SSH agents.
#[async_trait]
pub trait Authorizer: Send + Sync {
    async fn approve(&self, ctx: &AuthContext<'_>) -> Result<bool>;
}

/// Test-only: approves everything. `#[cfg(test)]` enforces that it can never
/// be wired into a release build path.
#[cfg(test)]
pub struct AlwaysAllow;

#[cfg(test)]
#[async_trait]
impl Authorizer for AlwaysAllow {
    async fn approve(&self, _ctx: &AuthContext<'_>) -> Result<bool> {
        Ok(true)
    }
}

/// Whether this platform can build the biometric policy tapwarden uses. This
/// is a capability probe for `doctor` — it constructs the policy but never
/// authenticates, so it raises no prompt. It confirms LocalAuthentication is
/// available, not that a fingerprint is enrolled.
pub fn biometrics_available() -> bool {
    use robius_authentication::{BiometricStrength, PolicyBuilder};
    PolicyBuilder::new()
        .biometrics(Some(BiometricStrength::Strong))
        .password(true)
        .watch(true)
        .build()
        .is_some()
}

/// Biometric (Touch ID) approval via `robius-authentication` / LocalAuthentication.
///
/// Uses `DeviceOwnerAuthentication` (biometrics + password + watch), so a failed
/// fingerprint read falls back to the account password instead of a hard lockout.
pub struct Biometric;

#[async_trait]
impl Authorizer for Biometric {
    async fn approve(&self, ctx: &AuthContext<'_>) -> Result<bool> {
        use robius_authentication::{
            AndroidText, BiometricStrength, Context, Error, PolicyBuilder, Text, WindowsText,
        };

        // Prompt reads "tapwarden is trying to <reason>" on macOS.
        // Only the key comment goes in — never key material or the data to sign.
        let reason = match ctx {
            AuthContext::Sign { key_comment, .. } => {
                format!("sign an SSH request with key \"{key_comment}\"")
            }
            AuthContext::UnlockCredentials { reason } => reason.to_string(),
        };

        // blocking_authenticate blocks until the user responds; keep it off the
        // async runtime. Context/policy are built inside the closure because the
        // underlying LAContext is not Send.
        let outcome = tokio::task::spawn_blocking(move || {
            let policy = PolicyBuilder::new()
                .biometrics(Some(BiometricStrength::Strong))
                .password(true) // DeviceOwnerAuthentication: password fallback allowed
                .watch(true)
                .build()
                .ok_or_else(|| anyhow!("biometric policy not supported on this platform"))?;
            let text = Text {
                android: AndroidText {
                    title: "tapwarden",
                    subtitle: None,
                    description: None,
                },
                apple: &reason,
                windows: WindowsText::new_truncated("tapwarden", &reason),
            };
            match Context::new(()).blocking_authenticate(text, &policy) {
                Ok(()) => Ok(true),
                // User said no (or failed to authenticate): a denial, not an error.
                Err(Error::UserCanceled | Error::Authentication) => Ok(false),
                // robius Error implements neither Display nor std::error::Error.
                Err(e) => Err(anyhow!("biometric authentication failed: {e:?}")),
            }
        })
        .await
        .context("biometric prompt task panicked")?;

        outcome.context("failed to evaluate biometric authorization")
    }
}

/// One successful approval, timestamped on both clocks. `Instant` does not
/// advance during system sleep (CLOCK_UPTIME_RAW on macOS), so alone it would
/// keep a 60s window open across an overnight suspend; `SystemTime` alone can
/// be stepped backwards. Requiring BOTH inside the window covers each gap.
#[derive(Clone, Copy)]
struct Approval {
    instant: Instant,
    wall: SystemTime,
}

impl Approval {
    fn now() -> Self {
        Self {
            instant: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    fn within(&self, window: Duration) -> bool {
        // A backwards wall-clock jump makes elapsed() Err → treated as expired.
        self.instant.elapsed() < window && self.wall.elapsed().is_ok_and(|d| d < window)
    }
}

/// `AuthMode::Grace`: skip re-prompting if the last *successful* approval was
/// within `window`; otherwise delegate to `inner`. Denials are never cached.
/// Approvals are scoped per key: approving key A never authorizes key B.
pub struct Grace {
    inner: Box<dyn Authorizer>,
    window: Duration,
    last: Mutex<HashMap<String, Approval>>,
}

impl Grace {
    pub fn new(inner: Box<dyn Authorizer>, window: Duration) -> Self {
        Self {
            inner,
            window,
            last: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Authorizer for Grace {
    async fn approve(&self, ctx: &AuthContext<'_>) -> Result<bool> {
        // INVARIANT: only signatures ride the grace window. A credential
        // unlock always reaches the inner prompt and is never cached.
        let AuthContext::Sign { key_comment, .. } = ctx else {
            return self.inner.approve(ctx).await;
        };

        // ponytail: std Mutex, never held across an await; poisoning is unreachable
        // because the critical sections cannot panic.
        let within_window = self
            .last
            .lock()
            .expect("grace lock poisoned")
            .get(*key_comment)
            .is_some_and(|approval| approval.within(self.window));
        if within_window {
            return Ok(true);
        }

        let approved = self.inner.approve(ctx).await?;
        if approved {
            self.last
                .lock()
                .expect("grace lock poisoned")
                .insert(key_comment.to_string(), Approval::now());
        }
        Ok(approved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts prompts; answers with a fixed verdict.
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

    fn ctx() -> AuthContext<'static> {
        AuthContext::Sign {
            key_comment: "test@key",
            data_len: 32,
        }
    }

    fn unlock_ctx() -> AuthContext<'static> {
        AuthContext::UnlockCredentials {
            reason: "unlock backend credentials for Vaultwarden",
        }
    }

    fn counting(allow: bool) -> (Box<Counting>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Box::new(Counting {
                allow,
                calls: calls.clone(),
            }),
            calls,
        )
    }

    #[tokio::test]
    async fn grace_skips_prompt_within_window() {
        let (inner, calls) = counting(true);
        let grace = Grace::new(inner, Duration::from_secs(3600));

        assert!(grace.approve(&ctx()).await.unwrap());
        assert!(grace.approve(&ctx()).await.unwrap());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second call must not re-prompt"
        );
    }

    #[tokio::test]
    async fn grace_reprompts_after_window_expiry() {
        let (inner, calls) = counting(true);
        // Zero window: every approval is already expired.
        let grace = Grace::new(inner, Duration::ZERO);

        assert!(grace.approve(&ctx()).await.unwrap());
        assert!(grace.approve(&ctx()).await.unwrap());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "expired window must re-prompt"
        );
    }

    #[tokio::test]
    async fn grace_approval_does_not_unlock_other_keys() {
        let (inner, calls) = counting(true);
        let grace = Grace::new(inner, Duration::from_secs(3600));

        assert!(grace.approve(&ctx()).await.unwrap());
        let other = AuthContext::Sign {
            key_comment: "other@key",
            data_len: 32,
        };
        assert!(grace.approve(&other).await.unwrap());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a different key must re-prompt even inside the window"
        );
        // The original key is still within its own window.
        assert!(grace.approve(&ctx()).await.unwrap());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn approval_expires_when_wall_clock_advances_past_window() {
        // Simulates waking from sleep: Instant barely moved (it pauses during
        // suspend) but wall-clock time is far past the window.
        let approval = Approval {
            instant: Instant::now(),
            wall: SystemTime::now() - Duration::from_secs(120),
        };
        assert!(!approval.within(Duration::from_secs(60)));
    }

    #[test]
    fn approval_expires_when_wall_clock_steps_backwards() {
        let approval = Approval {
            instant: Instant::now(),
            wall: SystemTime::now() + Duration::from_secs(120),
        };
        assert!(!approval.within(Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn grace_window_from_a_signature_never_unlocks_credentials() {
        let (inner, calls) = counting(true);
        let grace = Grace::new(inner, Duration::from_secs(3600));

        // A signature opens a fresh grace window...
        assert!(grace.approve(&ctx()).await.unwrap());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // ...but a credential unlock must still reach the real prompt.
        assert!(grace.approve(&unlock_ctx()).await.unwrap());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "credential unlock must never ride a signature's grace window"
        );
    }

    #[tokio::test]
    async fn credential_unlock_approval_is_never_cached() {
        let (inner, calls) = counting(true);
        let grace = Grace::new(inner, Duration::from_secs(3600));

        assert!(grace.approve(&unlock_ctx()).await.unwrap());
        assert!(grace.approve(&unlock_ctx()).await.unwrap());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "every credential unlock must prompt"
        );
    }

    #[tokio::test]
    async fn grace_does_not_cache_denial() {
        let (inner, calls) = counting(false);
        let grace = Grace::new(inner, Duration::from_secs(3600));

        assert!(!grace.approve(&ctx()).await.unwrap());
        assert!(!grace.approve(&ctx()).await.unwrap());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a denial must never start the grace window"
        );
    }

    /// M0 PoC: does an *unsigned* test binary raise Touch ID at all?
    /// Run manually: `cargo test touch_id_prompt_manual -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn touch_id_prompt_manual() {
        let result = Biometric
            .approve(&AuthContext::Sign {
                key_comment: "m0-poc@tapwarden",
                data_len: 0,
            })
            .await;
        println!("Biometric::approve returned: {result:?}");
        result.expect("platform error raising the Touch ID / LocalAuthentication prompt");
    }
}
