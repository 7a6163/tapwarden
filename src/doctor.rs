//! `tapwarden doctor` — read-only diagnostics across the layers that make the
//! agent work: config, backend credentials, the LaunchAgent, the socket, the
//! SSH wiring, and Touch ID availability. Nothing here mutates state. Local
//! checks never raise a prompt; the optional `--check-backend` pass talks to
//! the backend and, for the keychain credential source, may prompt Touch ID.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Result, bail};

use crate::config::{Backend, Config, CredentialSource};
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
    check_touch_id(&mut r);
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
        Backend::Bws => {
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
                r.hint("export the BWS access token; note launchd does not inherit shell env, so the background agent needs `tapwarden start --fg` from a shell that exports it");
            }
        }
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

fn check_touch_id(r: &mut Report) {
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
