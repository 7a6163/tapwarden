use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod agent;
mod authorizer;
mod config;
mod daemon;
mod doctor;
mod keychain;
mod runtime_paths;
mod secret_source;
mod setup;
#[cfg(test)]
mod test_support;
mod vaultwarden;

use config::Config;

#[derive(Parser)]
#[command(
    name = "tapwarden",
    version,
    about = "SSH agent backed by Bitwarden Secrets Manager with per-use biometric authorization"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the agent (background LaunchAgent; --fg for foreground)
    Start {
        /// Run in the foreground of this shell instead of under launchd
        #[arg(long)]
        fg: bool,
        /// Path to the config file
        #[arg(long)]
        config: Option<String>,
    },
    /// Interactive wizard: log in to Vaultwarden once, obtain the personal
    /// API key, pick the SSH keys to serve, and write the config file
    Setup,
    /// Store the Bitwarden Secrets Manager access token in the macOS Keychain
    /// (needed for `credentials: keychain`, so the background agent can fetch
    /// keys without an inherited env var)
    StoreToken,
    /// Register a FIDO2 security key (e.g. YubiKey) as the presence factor;
    /// prints the config to add for `authorization.factor: yubikey`
    RegisterYubikey,
    /// Read-only diagnostics: config, credentials, LaunchAgent, socket, SSH
    /// wiring, and Touch ID. Exits non-zero if any check fails.
    Doctor {
        /// Path to the config file
        #[arg(long)]
        config: Option<String>,
        /// Also fetch the configured keys from the backend end-to-end
        /// (needs network + credentials; keychain creds may prompt Touch ID)
        #[arg(long)]
        check_backend: bool,
    },
    /// Stop the background agent (the LaunchAgent stays installed)
    Stop,
    /// Show the last lines of the agent log
    Logs,
    /// Stop the agent and remove the LaunchAgent
    Uninstall,
    /// Print the agent socket path
    SocketPath,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Start { fg, config } => {
            // Load the config in both paths: an invalid config must fail here,
            // not crash-loop inside a freshly installed LaunchAgent.
            let cfg = Config::load(config.as_deref()).context("failed to load configuration")?;
            if fg {
                agent::run_foreground(cfg).await?;
            } else {
                daemon::start(&cfg, config.as_deref())?;
            }
        }
        Commands::Setup => setup::run().await?,
        Commands::StoreToken => setup::store_bws_token()?,
        Commands::RegisterYubikey => {
            let registered = authorizer::register_yubikey()?;
            println!("\nRegistered. Add this to ~/.config/tapwarden/config.yaml:\n");
            println!("authorization:");
            println!("  factor: yubikey");
            println!("  yubikey:");
            println!("    credential_id: {}", registered.credential_id);
            println!("    public_key:");
            println!("      algorithm: {}", registered.public_key_algorithm);
            println!("      bytes: {}", registered.public_key_bytes);
        }
        Commands::Doctor {
            config,
            check_backend,
        } => doctor::run(config.as_deref(), check_backend).await?,
        Commands::Stop => daemon::stop()?,
        Commands::Logs => daemon::logs()?,
        Commands::Uninstall => daemon::uninstall()?,
        Commands::SocketPath => println!("{}", runtime_paths::socket_path()?.display()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn subcommands_and_their_flags_parse() {
        assert!(matches!(
            Cli::parse_from(["tapwarden", "start", "--fg", "--config", "/tmp/c.yaml"]).command,
            Commands::Start { fg: true, config: Some(path) } if path == "/tmp/c.yaml"
        ));
        assert!(matches!(
            Cli::parse_from(["tapwarden", "doctor", "--check-backend"]).command,
            Commands::Doctor {
                check_backend: true,
                ..
            }
        ));
        for (args, expected) in [
            (["tapwarden", "stop"], "Stop"),
            (["tapwarden", "logs"], "Logs"),
            (["tapwarden", "uninstall"], "Uninstall"),
            (["tapwarden", "socket-path"], "SocketPath"),
            (["tapwarden", "setup"], "Setup"),
            (["tapwarden", "store-token"], "StoreToken"),
            (["tapwarden", "register-yubikey"], "RegisterYubikey"),
        ] {
            let parsed = Cli::parse_from(args).command;
            let name = match parsed {
                Commands::Stop => "Stop",
                Commands::Logs => "Logs",
                Commands::Uninstall => "Uninstall",
                Commands::SocketPath => "SocketPath",
                Commands::Setup => "Setup",
                Commands::StoreToken => "StoreToken",
                Commands::RegisterYubikey => "RegisterYubikey",
                _ => "other",
            };
            assert_eq!(name, expected, "for {args:?}");
        }
    }

    #[test]
    fn an_unknown_subcommand_is_rejected() {
        assert!(Cli::try_parse_from(["tapwarden", "definitely-not-a-command"]).is_err());
    }
}
