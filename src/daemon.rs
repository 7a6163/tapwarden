//! M2 daemon lifecycle: a launchd-managed background agent on macOS.
//!
//! The agent runs as a per-user **LaunchAgent** (not a LaunchDaemon — Touch ID
//! prompts need a GUI session). The process lifecycle belongs entirely to
//! launchd: tapwarden never signals a PID itself, which is how the PLAN §6
//! "verify the process before signalling" rule is satisfied — there is no
//! direct-PID path at all, and therefore no PID file.
//!
//! The plist contains only the executable path and the log file path — never
//! credentials, env values, or config contents.

use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::config::{Backend, Config, CredentialSource};
use crate::runtime_paths;

const LABEL: &str = "com.tapwarden.agent";
const LOG_TAIL_LINES: usize = 50;

/// `stop` when launchd has nothing loaded under our label. Static by design:
/// launchctl's non-zero exits don't distinguish "not loaded" from much else,
/// and the message must never carry process output.
const STOP_NOT_LOADED: &str = "tapwarden is not running under launchd (nothing to stop) — if you started it with `tapwarden start --fg`, stop it with Ctrl-C in that shell";

fn home() -> Result<PathBuf> {
    dirs::home_dir().context("unable to determine home directory")
}

pub(crate) fn plist_path() -> Result<PathBuf> {
    Ok(home()?
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

/// Logs live in `~/Library/Logs`, not the runtime dir — the runtime dir is
/// tmpfs-ish and vanishes across reboots.
pub(crate) fn log_path() -> Result<PathBuf> {
    Ok(home()?.join("Library/Logs/tapwarden.log"))
}

/// The LaunchAgent label, for diagnostics.
pub(crate) fn label() -> &'static str {
    LABEL
}

/// True when launchd currently has our service loaded (running or scheduled).
/// `launchctl print <target>` exits non-zero when nothing is loaded there.
pub(crate) fn is_loaded() -> bool {
    launchctl(&["print", &service_target()])
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn gui_domain() -> String {
    format!("gui/{}", runtime_paths::uid())
}

fn service_target() -> String {
    format!("gui/{}/{LABEL}", runtime_paths::uid())
}

/// Minimal XML escaping for plist text nodes. The exe path is the only
/// caller-controlled value and may contain `&`, `<`, `>`; spaces need no
/// escaping in XML.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// `KeepAlive.SuccessfulExit = false`: restart on crash, but a clean exit
/// (e.g. the SIGTERM launchd sends on `bootout`) stays down.
///
/// No `EnvironmentVariables` on purpose: launchd never sees the user's shell
/// env, and credentials must not live in the plist. Env-credential configs
/// (backend `bws`, or `credentials: env`) need `tapwarden start --fg` from a
/// shell that exports them — or a hand-added EnvironmentVariables dict.
fn render_plist(exe: &str, log: &str, config_path: Option<&str>) -> String {
    let exe = xml_escape(exe);
    let log = xml_escape(log);
    let config_args = config_path
        .map(|path| {
            format!(
                "\n\t\t<string>--config</string>\n\t\t<string>{}</string>",
                xml_escape(path)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exe}</string>
		<string>start</string>
		<string>--fg</string>
		{config_args}
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>StandardOutPath</key>
	<string>{log}</string>
	<key>StandardErrorPath</key>
	<string>{log}</string>
</dict>
</plist>
"#
    )
}

/// True when fetching keys will need env vars that launchd won't provide.
fn uses_env_credentials(config: &Config) -> bool {
    match config.backend {
        Backend::Bws => config.credentials == CredentialSource::Env,
        Backend::Vaultwarden => config
            .vaultwarden
            .as_ref()
            .is_none_or(|vw| vw.credentials == CredentialSource::Env),
    }
}

fn launchctl(args: &[&str]) -> Result<std::process::Output> {
    Command::new("launchctl")
        .args(args)
        .output()
        .context("failed to run launchctl")
}

/// Install the LaunchAgent plist and (re)start the agent under launchd.
pub fn start(config: &Config, config_path: Option<&str>) -> Result<()> {
    if uses_env_credentials(config) {
        eprintln!(
            "warning: this config resolves credentials from env vars, which launchd does not \
             provide — the background agent will fail to fetch keys. Either run `tapwarden start \
             --fg` from a shell that exports them, switch to `credentials: keychain` (`tapwarden \
             setup`), or add an EnvironmentVariables dict to the plist yourself."
        );
    }

    let exe = std::env::current_exe().context("failed to resolve the tapwarden executable path")?;
    let exe = exe
        .to_str()
        .context("the tapwarden executable path is not valid UTF-8")?;
    let config_path = config_path
        .map(std::fs::canonicalize)
        .transpose()
        .context("failed to resolve the config file path")?;
    let config_path = config_path
        .as_deref()
        .map(|path| {
            path.to_str()
                .context("the config file path is not valid UTF-8")
        })
        .transpose()?;
    let plist = plist_path()?;
    let log = log_path()?;
    let log = log
        .to_str()
        .context("the log file path is not valid UTF-8")?;

    let dir = plist
        .parent()
        .context("the LaunchAgent plist path has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    // Neither target may be a pre-planted symlink: launchd would append the
    // agent's stdout/stderr through the log path, and we write the plist.
    crate::runtime_paths::reject_symlink(&plist)?;
    crate::runtime_paths::reject_symlink(log_path()?.as_path())?;
    // 0644 is fine: the plist holds only the exe path, nothing sensitive.
    std::fs::write(&plist, render_plist(exe, log, config_path))
        .with_context(|| format!("failed to write {}", plist.display()))?;
    std::fs::set_permissions(&plist, {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o644)
    })
    .with_context(|| format!("failed to set permissions on {}", plist.display()))?;

    // bootstrap refuses to replace an already-loaded service. bootout returns
    // before launchd always finishes removing it, so retry that transition.
    let booted_out =
        launchctl(&["bootout", &service_target()]).is_ok_and(|out| out.status.success());

    let plist_str = plist
        .to_str()
        .context("the LaunchAgent plist path is not valid UTF-8")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let out = loop {
        let out = launchctl(&["bootstrap", &gui_domain(), plist_str])?;
        if out.status.success() || is_loaded() || !booted_out || Instant::now() >= deadline {
            break out;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if !out.status.success() && !is_loaded() {
        bail!(
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // RunAtLoad already started it; kickstart -k guarantees a fresh instance.
    let out = launchctl(&["kickstart", "-k", &service_target()])?;
    if !out.status.success() {
        bail!(
            "launchctl kickstart failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let socket = runtime_paths::socket_path()?;
    println!("tapwarden is running in the background (LaunchAgent {LABEL}, starts at login).");
    println!("socket: {}", socket.display());
    println!();
    println!("Point SSH at it permanently — add to ~/.ssh/config:");
    println!("  Host *");
    println!("    IdentityAgent {}", socket.display());
    println!();
    println!("Logs: `tapwarden logs` — stop: `tapwarden stop` — remove: `tapwarden uninstall`");
    Ok(())
}

/// Stop the running agent. The LaunchAgent stays installed (it will start
/// again at login); `uninstall` removes it for good.
pub fn stop() -> Result<()> {
    let out = launchctl(&["bootout", &service_target()])?;
    if !out.status.success() {
        bail!("{STOP_NOT_LOADED}");
    }
    println!("tapwarden stopped.");
    Ok(())
}

/// Boot the agent out of launchd (best-effort) and remove the plist.
pub fn uninstall() -> Result<()> {
    let _ = launchctl(&["bootout", &service_target()]); // may simply not be loaded
    let plist = plist_path()?;
    match std::fs::remove_file(&plist) {
        Ok(()) => println!(
            "tapwarden stopped and LaunchAgent removed ({}).",
            plist.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("no LaunchAgent installed ({} not found).", plist.display())
        }
        Err(e) => return Err(e).with_context(|| format!("failed to remove {}", plist.display())),
    }
    Ok(())
}

/// How much of the log file `tapwarden logs` will read, from the end.
const LOG_READ_CAP: u64 = 1024 * 1024; // 1 MiB

/// Print the last `LOG_TAIL_LINES` lines of the agent log.
pub fn logs() -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let path = log_path()?;
    // Never print through a swapped-in symlink, and never slurp an unbounded
    // file — read at most the last LOG_READ_CAP bytes.
    crate::runtime_paths::reject_symlink(&path)?;
    let mut file = std::fs::File::open(&path).with_context(|| {
        format!(
            "no log file at {} — has the agent been started with `tapwarden start`?",
            path.display()
        )
    })?;
    let len = file
        .metadata()
        .context("failed to stat the log file")?
        .len();
    if len > LOG_READ_CAP {
        file.seek(SeekFrom::End(-(LOG_READ_CAP as i64)))
            .context("failed to seek in the log file")?;
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .context("failed to read the log file")?;
    for line in tail(&contents, LOG_TAIL_LINES) {
        println!("{line}");
    }
    println!();
    println!("Follow live: tail -f {}", path.display());
    Ok(())
}

fn tail(contents: &str, n: usize) -> Vec<&str> {
    let lines: Vec<&str> = contents.lines().collect();
    lines[lines.len().saturating_sub(n)..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_escapes_the_exe_path_and_keeps_spaces() {
        let plist = render_plist(
            "/Users/z a/dev & test/<tapwarden>",
            "/Users/z a/Library/Logs/tapwarden.log",
            None,
        );
        assert!(
            plist.contains("<string>/Users/z a/dev &amp; test/&lt;tapwarden&gt;</string>"),
            "exe path must be XML-escaped with spaces intact:\n{plist}"
        );
        assert!(plist.contains("<string>/Users/z a/Library/Logs/tapwarden.log</string>"));
    }

    #[test]
    fn plist_has_label_args_restart_policy_and_no_env() {
        let plist = render_plist("/usr/local/bin/tapwarden", "/tmp/tapwarden.log", None);
        assert!(plist.contains("<string>com.tapwarden.agent</string>"));
        assert!(plist.contains("<string>start</string>"));
        assert!(plist.contains("<string>--fg</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        // Restart on crash only — a clean stop must stay stopped.
        assert!(plist.contains("<key>SuccessfulExit</key>"));
        assert!(plist.contains("<false/>"));
        assert!(
            !plist.contains("EnvironmentVariables"),
            "the plist must never carry env values or credentials"
        );
    }

    #[test]
    fn plist_preserves_and_escapes_explicit_config_path() {
        let plist = render_plist(
            "/usr/local/bin/tapwarden",
            "/tmp/tapwarden.log",
            Some("/Users/z a/config & test.yaml"),
        );
        assert!(plist.contains("<string>--config</string>"));
        assert!(plist.contains("<string>/Users/z a/config &amp; test.yaml</string>"));
    }

    #[test]
    fn log_path_is_under_library_logs() {
        assert!(log_path().unwrap().ends_with("Library/Logs/tapwarden.log"));
    }

    #[test]
    fn plist_path_is_under_launch_agents() {
        assert!(
            plist_path()
                .unwrap()
                .ends_with("Library/LaunchAgents/com.tapwarden.agent.plist")
        );
    }

    #[test]
    fn stop_error_names_the_state_and_the_fg_alternative() {
        assert!(STOP_NOT_LOADED.contains("nothing to stop"));
        assert!(STOP_NOT_LOADED.contains("--fg"));
    }

    #[test]
    fn tail_returns_at_most_the_last_n_lines() {
        let text = (1..=60)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let t = tail(&text, 50);
        assert_eq!(t.len(), 50);
        assert_eq!(t.first(), Some(&"11"));
        assert_eq!(t.last(), Some(&"60"));
        assert_eq!(tail("a\nb", 50), vec!["a", "b"], "short logs print whole");
        assert!(tail("", 50).is_empty());
    }

    #[test]
    fn env_credential_configs_are_detected() {
        // bws always resolves its access token from an env var
        let cfg: Config = serde_yaml::from_str("secret_ids: [x]\n").unwrap();
        assert!(uses_env_credentials(&cfg));

        let keychain = "secret_ids: [x]\nbackend: vaultwarden\nvaultwarden:\n  server_url: u\n  email: e\n  credentials: keychain\n";
        let cfg: Config = serde_yaml::from_str(keychain).unwrap();
        assert!(!uses_env_credentials(&cfg));

        let env =
            "secret_ids: [x]\nbackend: vaultwarden\nvaultwarden:\n  server_url: u\n  email: e\n";
        let cfg: Config = serde_yaml::from_str(env).unwrap();
        assert!(uses_env_credentials(&cfg));
    }

    #[test]
    #[ignore = "manual: talks to the real launchctl"]
    fn launchctl_supports_modern_subcommands_manual() {
        for sub in ["bootstrap", "bootout", "kickstart"] {
            let out = Command::new("launchctl")
                .args(["help", sub])
                .output()
                .expect("launchctl must be runnable");
            assert!(out.status.success(), "`launchctl help {sub}` failed");
        }
    }
}
