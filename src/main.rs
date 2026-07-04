use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod agent;
mod authorizer;
mod config;
mod daemon;
mod keychain;
mod runtime_paths;
mod secret_source;
mod setup;
mod vaultwarden;

use config::Config;

#[derive(Parser)]
#[command(
    name = "sigilo",
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
                daemon::start(&cfg)?;
            }
        }
        Commands::Setup => setup::run().await?,
        Commands::Stop => daemon::stop()?,
        Commands::Logs => daemon::logs()?,
        Commands::Uninstall => daemon::uninstall()?,
        Commands::SocketPath => println!("{}", runtime_paths::socket_path()?.display()),
    }
    Ok(())
}
