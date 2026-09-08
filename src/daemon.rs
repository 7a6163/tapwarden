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
/// How long `start` retries `bootstrap` while launchd finishes a `bootout`.
const BOOTSTRAP_RETRY_BUDGET: Duration = Duration::from_secs(5);

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

/// Everything the lifecycle commands touch outside their own logic: the plist
/// they write, the log they read, and the `launchctl` invocation. Injected so
/// the bootstrap retry — the logic behind the 0.2.2 fix — can be exercised
/// without installing a real LaunchAgent or booting out the running one.
pub(crate) struct Launchd<'a> {
    plist: PathBuf,
    log: PathBuf,
    run: &'a dyn Fn(&[&str]) -> Result<std::process::Output>,
    /// How long `start` keeps retrying `bootstrap` while launchd finishes a
    /// `bootout`. A field so the give-up path can be tested in milliseconds
    /// instead of making the suite wait out the real budget.
    retry_budget: Duration,
}

impl Launchd<'_> {
    fn real() -> Result<Self> {
        Ok(Self {
            plist: plist_path()?,
            log: log_path()?,
            run: &launchctl,
            retry_budget: BOOTSTRAP_RETRY_BUDGET,
        })
    }

    /// True when launchd currently has our service loaded (running or
    /// scheduled). `launchctl print <target>` exits non-zero when nothing is
    /// loaded there.
    fn is_loaded(&self) -> bool {
        (self.run)(&["print", &service_target()])
            .map(|out| out.status.success())
            .unwrap_or(false)
    }
}

/// True when launchd currently has our service loaded. For `doctor`.
pub(crate) fn is_loaded() -> bool {
    Launchd::real().is_ok_and(|launchd| launchd.is_loaded())
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
    start_in(&Launchd::real()?, config, config_path)
}

fn start_in(launchd: &Launchd<'_>, config: &Config, config_path: Option<&str>) -> Result<()> {
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
    let plist = launchd.plist.as_path();
    let log = launchd
        .log
        .to_str()
        .context("the log file path is not valid UTF-8")?;

    let dir = plist
        .parent()
        .context("the LaunchAgent plist path has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    // Neither target may be a pre-planted symlink: launchd would append the
    // agent's stdout/stderr through the log path, and we write the plist.
    crate::runtime_paths::reject_symlink(plist)?;
    crate::runtime_paths::reject_symlink(&launchd.log)?;
    // 0644 is fine: the plist holds only the exe path, nothing sensitive.
    std::fs::write(plist, render_plist(exe, log, config_path))
        .with_context(|| format!("failed to write {}", plist.display()))?;
    std::fs::set_permissions(plist, {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o644)
    })
    .with_context(|| format!("failed to set permissions on {}", plist.display()))?;

    // bootstrap refuses to replace an already-loaded service. bootout returns
    // before launchd always finishes removing it, so retry that transition.
    let booted_out =
        (launchd.run)(&["bootout", &service_target()]).is_ok_and(|out| out.status.success());

    let plist_str = plist
        .to_str()
        .context("the LaunchAgent plist path is not valid UTF-8")?;
    let deadline = Instant::now() + launchd.retry_budget;
    let out = loop {
        let out = (launchd.run)(&["bootstrap", &gui_domain(), plist_str])?;
        if out.status.success() || launchd.is_loaded() || !booted_out {
            break out;
        }
        // The budget is checked on its own, not as another `||` term: that way
        // the loop still terminates however the condition above is broken.
        if Instant::now() >= deadline {
            break out;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if !out.status.success() && !launchd.is_loaded() {
        bail!(
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // RunAtLoad already started it; kickstart -k guarantees a fresh instance.
    let out = (launchd.run)(&["kickstart", "-k", &service_target()])?;
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
    stop_in(&Launchd::real()?)
}

fn stop_in(launchd: &Launchd<'_>) -> Result<()> {
    let out = (launchd.run)(&["bootout", &service_target()])?;
    if !out.status.success() {
        bail!("{STOP_NOT_LOADED}");
    }
    println!("tapwarden stopped.");
    Ok(())
}

/// Boot the agent out of launchd (best-effort) and remove the plist.
pub fn uninstall() -> Result<()> {
    uninstall_in(&Launchd::real()?)
}

fn uninstall_in(launchd: &Launchd<'_>) -> Result<()> {
    let _ = (launchd.run)(&["bootout", &service_target()]); // may simply not be loaded
    let plist = launchd.plist.as_path();
    match std::fs::remove_file(plist) {
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
    logs_in(&Launchd::real()?)
}

fn logs_in(launchd: &Launchd<'_>) -> Result<()> {
    let path = launchd.log.as_path();
    // Never print through a swapped-in symlink.
    crate::runtime_paths::reject_symlink(path)?;
    let contents = read_tail(path, LOG_READ_CAP)?;
    for line in tail(&contents, LOG_TAIL_LINES) {
        println!("{line}");
    }
    println!();
    println!("Follow live: tail -f {}", path.display());
    Ok(())
}

/// Read at most the last `cap` bytes of `path`, decoding lossily.
///
/// The log is whatever the agent wrote to stdout/stderr, so it is not
/// guaranteed to be valid UTF-8 — and the seek to the last `cap` bytes lands
/// at an arbitrary byte offset, very likely mid-character on a large file.
/// `read_to_string` would reject the whole file for either, which would cost
/// the user their entire log at exactly the moment they are debugging.
fn read_tail(path: &std::path::Path, cap: u64) -> Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).with_context(|| {
        format!(
            "no log file at {} — has the agent been started with `tapwarden start`?",
            path.display()
        )
    })?;
    let len = file
        .metadata()
        .context("failed to stat the log file")?
        .len();
    file.seek(SeekFrom::Start(len.saturating_sub(cap)))
        .context("failed to seek in the log file")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .context("failed to read the log file")?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
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

    // ---- Lifecycle against a fake launchctl. Nothing here touches the real
    // launchd or the real ~/Library paths.

    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    fn output(code: i32, stderr: &str) -> std::process::Output {
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    /// Records every launchctl invocation and answers from `replies`, which
    /// maps the subcommand to its exit code. A subcommand with no entry
    /// succeeds.
    struct FakeLaunchctl {
        calls: RefCell<Vec<String>>,
        replies: Vec<(&'static str, i32)>,
    }

    impl FakeLaunchctl {
        fn new(replies: Vec<(&'static str, i32)>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                replies,
            }
        }

        fn respond(&self, args: &[&str]) -> Result<std::process::Output> {
            let sub = args[0];
            self.calls.borrow_mut().push(sub.to_string());
            let code = self
                .replies
                .iter()
                .find(|(name, _)| *name == sub)
                .map_or(0, |(_, code)| *code);
            Ok(output(code, "launchctl said no"))
        }

        fn subcommands(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    fn minimal_config() -> Config {
        serde_yaml::from_str("secret_ids: [x]\nbackend: vaultwarden\nvaultwarden:\n  server_url: https://vault.example.com\n  email: e\n  credentials: keychain\n").unwrap()
    }

    /// Builds a `Launchd` over a temp dir so no real plist or log is touched.
    fn fake_launchd<'a>(
        dir: &crate::test_support::TmpDir,
        run: &'a dyn Fn(&[&str]) -> Result<std::process::Output>,
    ) -> Launchd<'a> {
        Launchd {
            plist: dir.join("com.tapwarden.agent.plist"),
            log: dir.join("tapwarden.log"),
            run,
            retry_budget: Duration::from_millis(50),
        }
    }

    #[test]
    fn start_writes_a_0644_plist_and_bootstraps_then_kickstarts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_support::TmpDir::new("daemon");
        let fake = FakeLaunchctl::new(vec![]);
        let run = |args: &[&str]| fake.respond(args);
        let launchd = fake_launchd(&dir, &run);

        start_in(&launchd, &minimal_config(), None).expect("a cooperative launchctl must succeed");

        let plist = std::fs::read_to_string(&launchd.plist).expect("plist must be written");
        assert!(plist.contains("<string>com.tapwarden.agent</string>"));
        assert!(plist.contains(launchd.log.to_str().unwrap()));
        let mode = std::fs::metadata(&launchd.plist)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
        assert_eq!(
            fake.subcommands(),
            vec!["bootout", "bootstrap", "kickstart"]
        );
    }

    #[test]
    fn start_retries_bootstrap_while_launchd_finishes_the_bootout() {
        // The 0.2.2 bug: bootout returns before launchd has finished removing
        // the service, so the first bootstrap can still fail with "already
        // loaded". Only retry when we actually booted something out.
        let dir = crate::test_support::TmpDir::new("daemon");
        let fake = FakeLaunchctl::new(vec![]);
        let attempts = RefCell::new(0);
        let run = |args: &[&str]| {
            if args[0] == "bootstrap" {
                *attempts.borrow_mut() += 1;
                if *attempts.borrow() < 3 {
                    fake.calls.borrow_mut().push("bootstrap".to_string());
                    return Ok(output(5, "Bootstrap failed: 5"));
                }
            }
            if args[0] == "print" {
                fake.calls.borrow_mut().push("print".to_string());
                return Ok(output(1, "")); // not loaded yet
            }
            fake.respond(args)
        };
        let mut launchd = fake_launchd(&dir, &run);
        // Three attempts at a 50ms interval need more than the give-up budget
        // the other tests use.
        launchd.retry_budget = Duration::from_secs(2);

        start_in(&launchd, &minimal_config(), None).expect("the retry must ride out the race");
        assert_eq!(*attempts.borrow(), 3, "bootstrap must have been retried");
    }

    #[test]
    fn start_accepts_a_failed_bootstrap_when_the_service_is_loaded_anyway() {
        let dir = crate::test_support::TmpDir::new("daemon");
        let fake = FakeLaunchctl::new(vec![("bootstrap", 5)]); // print succeeds => loaded
        let run = |args: &[&str]| fake.respond(args);
        let launchd = fake_launchd(&dir, &run);

        start_in(&launchd, &minimal_config(), None)
            .expect("a service that is loaded is started, whatever bootstrap said");
    }

    #[test]
    fn start_fails_when_bootstrap_fails_and_nothing_is_loaded() {
        let dir = crate::test_support::TmpDir::new("daemon");
        // bootout fails => booted_out is false => no retry, straight to the error.
        let fake = FakeLaunchctl::new(vec![("bootout", 1), ("bootstrap", 5), ("print", 1)]);
        let run = |args: &[&str]| fake.respond(args);
        let launchd = fake_launchd(&dir, &run);

        let err = format!(
            "{:#}",
            start_in(&launchd, &minimal_config(), None)
                .expect_err("bootstrap failure must surface")
        );
        assert!(err.contains("bootstrap failed"), "{err}");
        assert!(
            !fake.subcommands().contains(&"kickstart".to_string()),
            "kickstart must not run after a failed bootstrap"
        );
        assert_eq!(
            fake.subcommands()
                .iter()
                .filter(|s| *s == "bootstrap")
                .count(),
            1,
            "nothing was booted out, so there is no launchd race to wait for"
        );
    }

    #[test]
    fn start_gives_up_once_the_retry_budget_is_spent() {
        let dir = crate::test_support::TmpDir::new("daemon");
        // We booted something out, so retries are warranted — but bootstrap
        // never recovers and the service never shows up as loaded.
        let fake = FakeLaunchctl::new(vec![("bootstrap", 5), ("print", 1)]);
        let run = |args: &[&str]| fake.respond(args);
        let launchd = fake_launchd(&dir, &run);

        let started = Instant::now();
        let err = format!(
            "{:#}",
            start_in(&launchd, &minimal_config(), None).expect_err("the retry must not be forever")
        );
        assert!(err.contains("bootstrap failed"), "{err}");
        assert!(
            started.elapsed() >= launchd.retry_budget,
            "it must actually have waited out the budget"
        );
        assert!(
            fake.subcommands()
                .iter()
                .filter(|s| *s == "bootstrap")
                .count()
                > 1,
            "a booted-out service must be retried"
        );
    }

    #[test]
    fn start_fails_when_kickstart_fails() {
        let dir = crate::test_support::TmpDir::new("daemon");
        let fake = FakeLaunchctl::new(vec![("kickstart", 1)]);
        let run = |args: &[&str]| fake.respond(args);
        let launchd = fake_launchd(&dir, &run);

        let err = format!(
            "{:#}",
            start_in(&launchd, &minimal_config(), None)
                .expect_err("kickstart failure must surface")
        );
        assert!(err.contains("kickstart failed"), "{err}");
    }

    #[test]
    fn start_refuses_a_pre_planted_plist_symlink() {
        let dir = crate::test_support::TmpDir::new("daemon");
        let fake = FakeLaunchctl::new(vec![]);
        let run = |args: &[&str]| fake.respond(args);
        let launchd = fake_launchd(&dir, &run);
        let elsewhere = dir.join("attacker-owned");
        std::os::unix::fs::symlink(&elsewhere, &launchd.plist).unwrap();

        start_in(&launchd, &minimal_config(), None)
            .expect_err("launchd must never be pointed through a planted symlink");
        assert!(
            !elsewhere.exists(),
            "nothing may be written through the link"
        );
        assert!(
            fake.subcommands().is_empty(),
            "launchctl must not be reached"
        );
    }

    #[test]
    fn stop_reports_the_not_loaded_case_without_process_output() {
        let dir = crate::test_support::TmpDir::new("daemon");
        let fake = FakeLaunchctl::new(vec![]);
        let run = |args: &[&str]| fake.respond(args);
        stop_in(&fake_launchd(&dir, &run)).expect("a loaded service stops");

        let fake = FakeLaunchctl::new(vec![("bootout", 1)]);
        let run = |args: &[&str]| fake.respond(args);
        let err = format!(
            "{:#}",
            stop_in(&fake_launchd(&dir, &run)).expect_err("nothing to stop is an error")
        );
        assert_eq!(err, STOP_NOT_LOADED);
        assert!(
            !err.contains("launchctl said no"),
            "launchctl output must never reach the user: {err}"
        );
    }

    #[test]
    fn uninstall_removes_the_plist_and_tolerates_a_missing_one() {
        let dir = crate::test_support::TmpDir::new("daemon");
        let fake = FakeLaunchctl::new(vec![("bootout", 1)]); // not loaded: still fine
        let run = |args: &[&str]| fake.respond(args);
        let launchd = fake_launchd(&dir, &run);

        std::fs::write(&launchd.plist, "plist").unwrap();
        uninstall_in(&launchd).expect("an installed agent uninstalls");
        assert!(!launchd.plist.exists());

        uninstall_in(&launchd).expect("uninstalling twice must not be an error");
    }

    #[test]
    fn logs_prints_from_the_configured_log_path() {
        let dir = crate::test_support::TmpDir::new("daemon");
        let fake = FakeLaunchctl::new(vec![]);
        let run = |args: &[&str]| fake.respond(args);
        let launchd = fake_launchd(&dir, &run);

        std::fs::write(&launchd.log, "line one\nline two\n").unwrap();
        logs_in(&launchd).expect("an existing log prints");

        std::fs::remove_file(&launchd.log).unwrap();
        logs_in(&launchd).expect_err("a missing log is an error");
    }

    #[test]
    fn a_log_that_is_not_valid_utf8_still_prints() {
        // The agent's stdout/stderr is not guaranteed to be UTF-8; a mangled
        // byte must not cost the user the whole log.
        let dir = crate::test_support::TmpDir::new("logs");
        let path = dir.join("tapwarden.log");
        let mut bytes = b"first line\n".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        bytes.extend_from_slice(b"\nlast line\n");
        std::fs::write(&path, &bytes).unwrap();

        let contents = read_tail(&path, LOG_READ_CAP).expect("invalid UTF-8 must not fail");
        assert!(contents.contains("first line"));
        assert!(contents.contains("last line"));
    }

    #[test]
    fn an_oversized_log_is_read_from_the_end_even_mid_character() {
        let dir = crate::test_support::TmpDir::new("logs");
        let path = dir.join("tapwarden.log");
        // A multi-byte character straddles every plausible cap, so the seek
        // lands mid-character whatever the exact offset.
        let mut bytes = "日".repeat(200).into_bytes();
        bytes.extend_from_slice(b"\ntail marker\n");
        std::fs::write(&path, &bytes).unwrap();

        let contents = read_tail(&path, 64).expect("a mid-character seek must not fail");
        assert!(contents.len() <= 64 + 1, "must not read the whole file");
        assert!(contents.contains("tail marker"));
    }

    #[test]
    fn a_missing_log_names_the_path_and_the_command_that_creates_it() {
        let err = format!(
            "{:#}",
            read_tail(
                std::path::Path::new("/nonexistent/tapwarden.log"),
                LOG_READ_CAP
            )
            .expect_err("a missing log must be an error")
        );
        assert!(err.contains("tapwarden start"), "{err}");
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
    fn launchd_targets_are_scoped_to_the_gui_session_of_this_uid() {
        let uid = runtime_paths::uid();
        assert_eq!(label(), LABEL);
        assert_eq!(gui_domain(), format!("gui/{uid}"));
        assert_eq!(service_target(), format!("gui/{uid}/{LABEL}"));
    }

    #[test]
    fn is_loaded_answers_without_mutating_launchd() {
        // Read-only probe: whichever way it answers, it must not panic and the
        // plist must still be exactly as it was.
        let before = plist_path().unwrap().exists();
        let _ = is_loaded();
        assert_eq!(plist_path().unwrap().exists(), before);
    }

    #[test]
    fn launchctl_surfaces_a_usable_output_for_an_unknown_subcommand() {
        let out = launchctl(&[
            "print",
            "gui/4294967294/com.tapwarden.definitely-not-loaded",
        ])
        .expect("launchctl must be runnable");
        assert!(
            !out.status.success(),
            "an unloaded target must exit non-zero"
        );
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
