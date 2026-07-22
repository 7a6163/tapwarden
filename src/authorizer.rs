use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result, anyhow, bail};
use async_trait::async_trait;

/// What the user is being asked to approve. The variant matters for `Grace`:
/// only signatures participate in the grace window — credential unlocks always
/// reach the real prompt, so a recent signature never silently unlocks the
/// backend credentials.
pub enum AuthContext<'a> {
    /// One SSH signature with the named key.
    Sign {
        key_comment: &'a str,
        /// Stable SHA-256 public-key fingerprint used to scope grace windows.
        key_fingerprint: &'a str,
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

/// RP id used for both registration and per-signature assertions. Constant so
/// a credential registered once keeps working across upgrades.
pub const YUBIKEY_RP_ID: &str = "tapwarden";

/// Presence factor backed by a FIDO2 security key (e.g. YubiKey). Each
/// approval runs a `get_assertion` against the credential registered by
/// `register_yubikey`; the hardware only completes it after a physical touch,
/// so every signature (and every credential unlock) needs the key present and
/// tapped — the YubiKey analog of the Touch ID gate.
pub struct YubikeyTouch {
    credential_id: Vec<u8>,
    public_key: ctap_hid_fido2::public_key::PublicKey,
}

impl YubikeyTouch {
    pub fn new(credential_id: Vec<u8>, public_key: ctap_hid_fido2::public_key::PublicKey) -> Self {
        Self {
            credential_id,
            public_key,
        }
    }
}

fn yubikey_credential_matches(expected: &[u8], returned: &[u8]) -> bool {
    // CTAP allows omitting the descriptor when the allow-list has one entry.
    // The verified signature still binds the response to the registered key.
    returned.is_empty() || returned == expected
}

fn yubikey_assertion_is_valid(
    credential_id: &[u8],
    public_key: &ctap_hid_fido2::public_key::PublicKey,
    challenge: &[u8],
    assertion: &ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Assertion,
) -> bool {
    yubikey_credential_matches(credential_id, &assertion.credential_id)
        && assertion.flags.user_present_result
        && !assertion.flags.attested_credential_data_included
        && ctap_hid_fido2::verifier::verify_assertion(
            YUBIKEY_RP_ID,
            public_key,
            challenge,
            assertion,
        )
}

#[async_trait]
impl Authorizer for YubikeyTouch {
    async fn approve(&self, _ctx: &AuthContext<'_>) -> Result<bool> {
        let credential_id = self.credential_id.clone();
        let public_key = self.public_key.clone();
        // Blocking HID I/O: keep it off the async runtime, like Biometric.
        tokio::task::spawn_blocking(move || -> Result<bool> {
            use ctap_hid_fido2::{
                Cfg, FidoKeyHidFactory, fidokey::GetAssertionArgsBuilder, verifier,
            };
            let device = FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| {
                anyhow!("no FIDO2 security key found (or more than one connected): {e:?}")
            })?;
            let challenge = verifier::create_challenge();
            let args = GetAssertionArgsBuilder::new(YUBIKEY_RP_ID, &challenge)
                .without_pin_and_uv()
                .credential_id(&credential_id)
                .build();
            match device.get_assertion_with_args(&args) {
                Ok(assertions) => Ok(matches!(
                    assertions.as_slice(),
                    [assertion]
                        if yubikey_assertion_is_valid(
                            &credential_id,
                            &public_key,
                            &challenge,
                            assertion
                        )
                )),
                // A timeout, wrong key, or no touch is a denial, not a crash:
                // the signature simply fails, like a canceled Touch ID prompt.
                Err(_) => Ok(false),
            }
        })
        .await
        .context("yubikey authorization task panicked")?
    }
}

/// True when a FIDO2 security key is reachable over HID. For `doctor`.
pub fn yubikey_present() -> bool {
    use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
    FidoKeyHidFactory::create(&Cfg::init()).is_ok()
}

pub struct RegisteredYubikey {
    pub credential_id: String,
    pub public_key_algorithm: &'static str,
    pub public_key_bytes: String,
}

/// Register a (non-resident) credential on the connected security key and
/// return its credential id and verifier public key for the config. Requires
/// a physical touch, and the key's PIN if one is set.
pub fn register_yubikey() -> Result<RegisteredYubikey> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ctap_hid_fido2::{
        Cfg, FidoKeyHidFactory, fidokey::MakeCredentialArgsBuilder, public_key::PublicKeyType,
        verifier,
    };

    let device = FidoKeyHidFactory::create(&Cfg::init())
        .map_err(|e| anyhow!("no FIDO2 security key found (or more than one connected): {e:?}"))?;

    let pin = rpassword::prompt_password("YubiKey PIN (leave empty if the key has none): ")
        .context("failed to read the PIN")?;
    let pin = pin.trim();

    let challenge = verifier::create_challenge();
    let args = if pin.is_empty() {
        MakeCredentialArgsBuilder::new(YUBIKEY_RP_ID, &challenge).build()
    } else {
        MakeCredentialArgsBuilder::new(YUBIKEY_RP_ID, &challenge)
            .pin(pin)
            .build()
    };

    println!("Touch your YubiKey to register...");
    let attestation = device
        .make_credential_with_args(&args)
        .map_err(|e| anyhow!("registration failed (touch timed out or wrong PIN?): {e:?}"))?;

    let verify = verifier::verify_attestation(YUBIKEY_RP_ID, &challenge, &attestation);
    if !verify.is_success {
        bail!("attestation verification failed");
    }
    let public_key_algorithm = match verify.credential_public_key.key_type {
        PublicKeyType::Ecdsa256 => "es256",
        PublicKeyType::Ed25519 => "ed25519",
        _ => bail!("registered credential uses an unsupported public-key algorithm"),
    };
    if verify.credential_public_key.der.is_empty() {
        bail!("registered credential returned an empty public key");
    }
    Ok(RegisteredYubikey {
        credential_id: STANDARD.encode(verify.credential_id),
        public_key_algorithm,
        public_key_bytes: STANDARD.encode(verify.credential_public_key.der),
    })
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
        let AuthContext::Sign {
            key_fingerprint, ..
        } = ctx
        else {
            return self.inner.approve(ctx).await;
        };

        // ponytail: std Mutex, never held across an await; poisoning is unreachable
        // because the critical sections cannot panic.
        let within_window = self
            .last
            .lock()
            .expect("grace lock poisoned")
            .get(*key_fingerprint)
            .is_some_and(|approval| approval.within(self.window));
        if within_window {
            return Ok(true);
        }

        let approved = self.inner.approve(ctx).await?;
        if approved {
            self.last
                .lock()
                .expect("grace lock poisoned")
                .insert(key_fingerprint.to_string(), Approval::now());
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
            key_fingerprint: "SHA256:key-a",
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

    #[test]
    fn yubikey_assertion_requires_matching_credential_and_user_presence() {
        use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Assertion;
        use ctap_hid_fido2::public_key::PublicKey;

        let credential_id = b"registered";
        let public_key = PublicKey::default();
        let challenge = [0u8; 32];

        let mut assertion = Assertion {
            credential_id: b"different".to_vec(),
            ..Default::default()
        };
        assert!(!yubikey_assertion_is_valid(
            credential_id,
            &public_key,
            &challenge,
            &assertion
        ));

        assertion.credential_id = credential_id.to_vec();
        assert!(!yubikey_assertion_is_valid(
            credential_id,
            &public_key,
            &challenge,
            &assertion
        ));
    }

    #[test]
    fn yubikey_credential_descriptor_may_be_omitted() {
        assert!(yubikey_credential_matches(b"registered", b"registered"));
        assert!(yubikey_credential_matches(b"registered", b""));
        assert!(!yubikey_credential_matches(b"registered", b"different"));
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
            key_comment: "test@key",
            key_fingerprint: "SHA256:key-b",
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
                key_fingerprint: "SHA256:m0-poc",
                data_len: 0,
            })
            .await;
        println!("Biometric::approve returned: {result:?}");
        result.expect("platform error raising the Touch ID / LocalAuthentication prompt");
    }
}
