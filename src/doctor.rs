//! `tapwarden doctor` — read-only diagnostics across the layers that make the
//! agent work: config, backend credentials, the LaunchAgent, the socket, the
//! SSH wiring, and Touch ID availability. Nothing here mutates state. Local
//! checks never raise a prompt; the optional `--check-backend` pass talks to
//! the backend and, for the keychain credential source, may prompt Touch ID.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Result, bail};

use crate::config::{AuthFactor, Backend, Config, CredentialSource};
use crate::{agent, authorizer, config, daemon, runtime_paths};

#[derive(Clone, Copy)]
enum Status {
    Ok,
    Warn,
    Fail,
}

struct Report {
    fails: usize,
    warns: usize,
}

impl Report {
    fn new() -> Self {
        Self { fails: 0, warns: 0 }
    }

    fn line(&mut self, status: Status, label: &str, detail: &str) {
        let tag = match status {
            Status::Ok => "[ ok ]",
            Status::Warn => {
                self.warns += 1;
                "[warn]"
            }
            Status::Fail => {
                self.fails += 1;
                "[fail]"
            }
        };
        if detail.is_empty() {
            println!("{tag} {label}");
        } else {
            println!("{tag} {label}: {detail}");
        }
    }

    fn hint(&self, text: &str) {
        println!("       hint: {text}");
    }
}

pub async fn run(config_path: Option<&str>, check_backend: bool) -> Result<()> {
    let mut r = Report::new();
    println!("tapwarden doctor\n");

    let cfg = check_config(&mut r, config_path);
    if let Some(cfg) = cfg.as_ref() {
        check_credentials(&mut r, cfg);
    }
    check_presence(&mut r, cfg.as_ref());
    check_agent(&mut r);
    check_ssh_wiring(&mut r);

    if check_backend {
        match cfg.as_ref() {
            Some(cfg) => check_backend_keys(&mut r, cfg).await,
            None => r.line(Status::Warn, "backend", "skipped (config did not load)"),
        }
    } else {
        println!("\n(run with --check-backend to fetch keys from the backend end-to-end)");
    }

    println!();
    if r.fails > 0 {
        bail!(
            "doctor found {} problem(s) and {} warning(s) — see the [fail] lines above",
            r.fails,
            r.warns
        );
    }
    if r.warns > 0 {
        println!("doctor: no failures, {} warning(s).", r.warns);
    } else {
        println!("doctor: all checks passed.");
    }
    Ok(())
}

fn check_config(r: &mut Report, config_path: Option<&str>) -> Option<Config> {
    let path = config::resolved_path(config_path).ok();

    match Config::load(config_path) {
        Ok(cfg) => {
            let backend = match cfg.backend {
                Backend::Bws => "bitwarden secrets manager",
                Backend::Vaultwarden => "vaultwarden",
            };
            r.line(
                Status::Ok,
                "config",
                &format!(
                    "loaded, {} key id(s), backend: {backend}",
                    cfg.secret_ids.len()
                ),
            );
            if let Some(path) = path.as_deref() {
                check_config_perms(r, path);
            }
            Some(cfg)
        }
        Err(e) => {
            r.line(Status::Fail, "config", &format!("{e:#}"));
            r.hint("run `tapwarden setup`, or copy config.yaml.example to ~/.config/tapwarden/config.yaml");
            None
        }
    }
}

fn check_config_perms(r: &mut Report, path: &Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        r.line(
            Status::Warn,
            "config perms",
            &format!("{} is {mode:04o}, expected 0600", path.display()),
        );
        r.hint(&format!("chmod 600 {}", path.display()));
    } else {
        r.line(Status::Ok, "config perms", "0600");
    }
}

fn check_credentials(r: &mut Report, cfg: &Config) {
    match cfg.backend {
        Backend::Bws => match cfg.credentials {
            CredentialSource::Env => {
                if cfg.access_token().is_ok() {
                    r.line(
                        Status::Ok,
                        "credentials",
                        &format!("${} is set", cfg.access_token_env),
                    );
                } else {
                    r.line(
                        Status::Warn,
                        "credentials",
                        &format!("${} is not set in this shell", cfg.access_token_env),
                    );
                    r.hint("export the token, or run `tapwarden store-token` and set `credentials: keychain` so the background agent can read it");
                }
            }
            CredentialSource::Keychain => {
                r.line(
                    Status::Ok,
                    "credentials",
                    "BWS token stored in the macOS Keychain (verified end-to-end with --check-backend)",
                );
            }
        },
        Backend::Vaultwarden => {
            let Some(vw) = cfg.vaultwarden.as_ref() else {
                return;
            };
            match vw.credentials {
                CredentialSource::Env => {
                    let missing: Vec<&str> = [
                        (vw.client_id().is_err(), vw.client_id_env.as_str()),
                        (vw.client_secret().is_err(), vw.client_secret_env.as_str()),
                        (
                            vw.master_password().is_err(),
                            vw.master_password_env.as_str(),
                        ),
                    ]
                    .into_iter()
                    .filter_map(|(missing, name)| missing.then_some(name))
                    .collect();
                    if missing.is_empty() {
                        r.line(
                            Status::Ok,
                            "credentials",
                            "vaultwarden env vars are all set",
                        );
                    } else {
                        r.line(
                            Status::Warn,
                            "credentials",
                            &format!("unset env var(s): {}", missing.join(", ")),
                        );
                    }
                }
                CredentialSource::Keychain => {
                    r.line(
                        Status::Ok,
                        "credentials",
                        "stored in the macOS Keychain (verified end-to-end with --check-backend)",
                    );
                }
            }
        }
    }
}

fn check_presence(r: &mut Report, cfg: Option<&Config>) {
    let factor = cfg.map(|c| c.authorization.factor).unwrap_or_default();
    match factor {
        AuthFactor::TouchId => {
            if authorizer::biometrics_available() {
                r.line(
                    Status::Ok,
                    "touch id",
                    "LocalAuthentication policy available",
                );
            } else {
                r.line(
                    Status::Warn,
                    "touch id",
                    "biometric policy unavailable on this platform",
                );
                r.hint("signing falls back to the account password prompt");
            }
        }
        AuthFactor::Yubikey => {
            if authorizer::yubikey_present() {
                r.line(Status::Ok, "yubikey", "a FIDO2 security key is connected");
            } else {
                r.line(Status::Warn, "yubikey", "no FIDO2 security key detected");
                r.hint("insert your YubiKey — a touch is required for every signature");
            }
        }
    }
}

fn check_agent(r: &mut Report) {
    if daemon::is_loaded() {
        r.line(
            Status::Ok,
            "launchagent",
            &format!("{} is loaded in launchd", daemon::label()),
        );
    } else {
        r.line(Status::Warn, "launchagent", "not loaded in launchd");
        r.hint("start the background agent with `tapwarden start`");
    }

    match runtime_paths::socket_path() {
        Ok(socket) => {
            if !socket.exists() {
                r.line(
                    Status::Warn,
                    "socket",
                    &format!("{} does not exist (agent not running?)", socket.display()),
                );
            } else if UnixStream::connect(&socket).is_ok() {
                r.line(
                    Status::Ok,
                    "socket",
                    &format!("{} is live", socket.display()),
                );
            } else {
                r.line(
                    Status::Warn,
                    "socket",
                    &format!("{} exists but nothing answers (stale?)", socket.display()),
                );
                r.hint("restart with `tapwarden start`");
            }
        }
        Err(e) => r.line(Status::Fail, "socket", &format!("{e:#}")),
    }
}

fn check_ssh_wiring(r: &mut Report) {
    let Ok(socket) = runtime_paths::socket_path() else {
        return;
    };
    match std::env::var_os("SSH_AUTH_SOCK") {
        Some(val) if Path::new(&val) == socket => {
            r.line(
                Status::Ok,
                "ssh_auth_sock",
                "points at the tapwarden socket",
            );
        }
        Some(_) => {
            r.line(
                Status::Warn,
                "ssh_auth_sock",
                "set, but not to the tapwarden socket",
            );
            r.hint(&format!(
                "set `IdentityAgent {}` under `Host *` in ~/.ssh/config",
                socket.display()
            ));
        }
        None => {
            r.line(Status::Warn, "ssh_auth_sock", "not set in this shell");
            r.hint(&format!(
                "set `IdentityAgent {}` under `Host *` in ~/.ssh/config",
                socket.display()
            ));
        }
    }
}

async fn check_backend_keys(r: &mut Report, cfg: &Config) {
    match agent::probe_keys(cfg).await {
        Ok(results) => {
            let ok = results.iter().filter(|(_, res)| res.is_ok()).count();
            for (id, res) in &results {
                match res {
                    Ok(comment) => r.line(Status::Ok, "key", &format!("{id} -> {comment}")),
                    Err(e) => r.line(Status::Fail, "key", &format!("{id}: {e:#}")),
                }
            }
            let status = if ok == results.len() {
                Status::Ok
            } else {
                Status::Fail
            };
            r.line(
                status,
                "backend",
                &format!("fetched {ok}/{} configured key(s)", results.len()),
            );
        }
        Err(e) => {
            r.line(Status::Fail, "backend", &format!("{e:#}"));
            r.hint("check credentials, server_endpoint, and network reachability");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_source::bws_stub_routes;
    use crate::test_support::{StubServer, TEST_ED25519_KEY, TmpDir};
    use uuid::Uuid;

    const KEY_ID: &str = "00000000-0000-0000-0000-000000000000";

    fn parse(yaml: &str) -> Config {
        serde_yaml::from_str(yaml).expect("test config parses")
    }

    fn write_config(dir: &TmpDir, yaml: &str, mode: u32) -> std::path::PathBuf {
        let path = dir.join("config.yaml");
        std::fs::write(&path, yaml).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn report_counts_warnings_and_failures_separately() {
        let mut r = Report::new();
        r.line(Status::Ok, "ok-with-detail", "detail");
        r.line(Status::Ok, "ok-bare", "");
        r.line(Status::Warn, "warn", "detail");
        r.line(Status::Fail, "fail", "detail");
        r.hint("a hint never changes the counts");
        assert_eq!((r.fails, r.warns), (1, 1));
    }

    #[test]
    fn config_check_passes_on_a_readable_0600_file() {
        let dir = TmpDir::new("doctor");
        let path = write_config(&dir, &format!("secret_ids: [{KEY_ID}]\n"), 0o600);
        let mut r = Report::new();
        let cfg = check_config(&mut r, path.to_str());
        assert_eq!(cfg.expect("config must load").secret_ids.len(), 1);
        assert_eq!((r.fails, r.warns), (0, 0));
    }

    #[test]
    fn loose_config_permissions_warn_but_do_not_fail() {
        let dir = TmpDir::new("doctor");
        let path = write_config(&dir, &format!("secret_ids: [{KEY_ID}]\n"), 0o644);
        let mut r = Report::new();
        check_config(&mut r, path.to_str());
        assert_eq!(
            (r.fails, r.warns),
            (0, 1),
            "a world-readable config is a warning, not a hard failure"
        );
    }

    #[test]
    fn vaultwarden_backend_is_named_in_the_config_line() {
        let dir = TmpDir::new("doctor");
        let yaml = format!(
            "secret_ids: [{KEY_ID}]\nbackend: vaultwarden\nvaultwarden:\n  server_url: https://vault.example.com\n  email: t@example.com\n"
        );
        let path = write_config(&dir, &yaml, 0o600);
        let mut r = Report::new();
        let cfg = check_config(&mut r, path.to_str()).expect("config must load");
        assert_eq!(cfg.backend, Backend::Vaultwarden);
        assert_eq!(r.fails, 0);
    }

    #[test]
    fn missing_config_fails_the_report() {
        let mut r = Report::new();
        assert!(check_config(&mut r, Some("/nonexistent/tapwarden.yaml")).is_none());
        assert_eq!(r.fails, 1);
    }

    #[test]
    fn permission_check_ignores_a_path_that_is_not_there() {
        let mut r = Report::new();
        check_config_perms(&mut r, Path::new("/nonexistent/tapwarden.yaml"));
        assert_eq!((r.fails, r.warns), (0, 0), "a missing file emits no line");
    }

    #[test]
    fn credential_check_covers_every_backend_and_source() {
        // BWS reading an env var that is not set: a warning with a hint.
        let mut r = Report::new();
        check_credentials(
            &mut r,
            &parse(&format!(
                "secret_ids: [{KEY_ID}]\naccess_token_env: TAPWARDEN_TEST_DOCTOR_UNSET\n"
            )),
        );
        assert_eq!((r.fails, r.warns), (0, 1));

        // BWS from the keychain: verified end-to-end only by --check-backend.
        let mut r = Report::new();
        check_credentials(
            &mut r,
            &parse(&format!("secret_ids: [{KEY_ID}]\ncredentials: keychain\n")),
        );
        assert_eq!((r.fails, r.warns), (0, 0));

        // Vaultwarden env vars, none of them set.
        let mut r = Report::new();
        check_credentials(
            &mut r,
            &parse(&format!(
                "secret_ids: [{KEY_ID}]\nbackend: vaultwarden\nvaultwarden:\n  server_url: https://vault.example.com\n  email: t@example.com\n  client_id_env: TAPWARDEN_TEST_DOCTOR_UNSET_ID\n  client_secret_env: TAPWARDEN_TEST_DOCTOR_UNSET_SECRET\n  master_password_env: TAPWARDEN_TEST_DOCTOR_UNSET_PW\n"
            )),
        );
        assert_eq!((r.fails, r.warns), (0, 1));

        // Vaultwarden from the keychain.
        let mut r = Report::new();
        check_credentials(
            &mut r,
            &parse(&format!(
                "secret_ids: [{KEY_ID}]\nbackend: vaultwarden\nvaultwarden:\n  server_url: https://vault.example.com\n  email: t@example.com\n  credentials: keychain\n"
            )),
        );
        assert_eq!((r.fails, r.warns), (0, 0));

        // A vaultwarden config with no section cannot reach validate(), but
        // the check must still not panic on it.
        let mut r = Report::new();
        check_credentials(
            &mut r,
            &parse(&format!("secret_ids: [{KEY_ID}]\nbackend: vaultwarden\n")),
        );
        assert_eq!((r.fails, r.warns), (0, 0));
    }

    #[test]
    fn vaultwarden_env_credentials_that_are_set_report_ok() {
        let name = "TAPWARDEN_TEST_VW_VALUE"; // set by .cargo/config.toml
        let mut r = Report::new();
        check_credentials(
            &mut r,
            &parse(&format!(
                "secret_ids: [{KEY_ID}]\nbackend: vaultwarden\nvaultwarden:\n  server_url: https://vault.example.com\n  email: t@example.com\n  client_id_env: {name}\n  client_secret_env: {name}\n  master_password_env: {name}\n"
            )),
        );
        assert_eq!((r.fails, r.warns), (0, 0));
    }

    #[test]
    fn presence_check_reports_one_line_per_factor_and_never_fails() {
        // Both probes are capability checks only — neither raises a prompt.
        for yaml in [
            format!("secret_ids: [{KEY_ID}]\n"),
            format!(
                "secret_ids: [{KEY_ID}]\nauthorization:\n  factor: yubikey\n  yubikey:\n    credential_id: AA==\n"
            ),
        ] {
            let cfg = parse(&yaml);
            let mut r = Report::new();
            check_presence(&mut r, Some(&cfg));
            assert_eq!(r.fails, 0, "a missing presence factor is a warning");
            assert!(r.warns <= 1);
        }

        // No config at all falls back to the default factor.
        let mut r = Report::new();
        check_presence(&mut r, None);
        assert_eq!(r.fails, 0);
    }

    #[test]
    fn agent_check_inspects_launchd_and_the_socket_without_failing() {
        let mut r = Report::new();
        check_agent(&mut r);
        assert_eq!(
            r.fails, 0,
            "launchd/socket state is reported as warnings, never failures"
        );
    }

    #[test]
    fn ssh_wiring_check_never_fails_whatever_the_shell_has_set() {
        // SSH_AUTH_SOCK cannot be rewritten from a test thread without racing
        // every concurrent getenv, so all three branches are covered by the
        // one the ambient environment happens to take. None of them may fail.
        let mut r = Report::new();
        check_ssh_wiring(&mut r);
        assert_eq!(r.fails, 0, "ssh wiring is advice, never a hard failure");
        assert!(r.warns <= 1);
    }

    #[tokio::test]
    async fn backend_check_fails_when_credentials_cannot_be_resolved() {
        let mut r = Report::new();
        check_backend_keys(
            &mut r,
            &parse(&format!(
                "secret_ids: [{KEY_ID}]\naccess_token_env: TAPWARDEN_TEST_DOCTOR_UNSET\n"
            )),
        )
        .await;
        assert_eq!(r.fails, 1);
    }

    #[tokio::test]
    async fn backend_check_fails_on_a_key_that_cannot_be_fetched() {
        let name = "TAPWARDEN_TEST_BWS_TOKEN"; // set by .cargo/config.toml
        // Token exchange works; the secret itself is not served.
        let id = Uuid::from_u128(42);
        let mut routes = bws_stub_routes(id, "n", "k");
        routes.pop();
        let server = StubServer::start(routes).await;
        let mut r = Report::new();
        check_backend_keys(
            &mut r,
            &parse(&format!(
                "secret_ids: [{id}]\naccess_token_env: {name}\nserver_endpoint: {}\n",
                server.base_url
            )),
        )
        .await;
        assert_eq!(r.fails, 2, "one per-key failure plus the summary line");
    }

    #[tokio::test]
    async fn run_reports_every_layer_and_fetches_keys_end_to_end() {
        let name = "TAPWARDEN_TEST_BWS_TOKEN"; // set by .cargo/config.toml
        let id = Uuid::from_u128(43);
        let server = StubServer::start(bws_stub_routes(id, "deploy-key", TEST_ED25519_KEY)).await;
        let dir = TmpDir::new("doctor-run");
        let path = write_config(
            &dir,
            &format!(
                "secret_ids: [{id}]\naccess_token_env: {name}\nserver_endpoint: {}\n",
                server.base_url
            ),
            0o600,
        );

        run(path.to_str(), true)
            .await
            .expect("every check must pass against the stub backend");
        // The local-only pass takes the other branch of the --check-backend arm.
        run(path.to_str(), false).await.expect("local checks pass");
    }

    #[tokio::test]
    async fn run_fails_when_the_config_does_not_load() {
        let err = run(Some("/nonexistent/tapwarden.yaml"), true)
            .await
            .expect_err("a config that does not load must exit non-zero");
        assert!(err.to_string().contains("problem"), "{err:#}");
    }
}
