//! Command-line interface definitions (clap derive).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

const DEFAULT_CONFIG: &str = "/etc/fortibackup/config.toml";

#[derive(Debug, Parser)]
#[command(
    name = "fortibackup",
    version,
    about = "Automated configuration backup for FortiGate devices",
    long_about = None,
)]
pub struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = DEFAULT_CONFIG, global = true)]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the daemon with the cron scheduler active (service mode).
    Run,

    /// Run a single backup pass for one or all devices, then exit.
    Once {
        /// Limit to the given device name. If omitted, backs up every device.
        #[arg(long)]
        device: Option<String>,
    },

    /// List backups present on disk.
    List {
        /// Limit to the given device name.
        #[arg(long)]
        device: Option<String>,
    },

    /// Validate the configuration file and check reachability of devices
    /// (does not download any configuration).
    Verify,

    /// Apply the retention policy now (delete files older than
    /// `retention_days`, always keep at least `retention_min_copies`).
    Prune {
        /// Limit to the given device name.
        #[arg(long)]
        device: Option<String>,

        /// Show what would be deleted without touching the filesystem.
        #[arg(long)]
        dry_run: bool,
    },

    /// Print shell completion script to stdout.
    ///
    /// Example: `fortibackup completions bash | sudo tee /etc/bash_completion.d/fortibackup`
    Completions {
        /// Target shell (bash, zsh, fish, elvish, powershell).
        shell: ShellArg,
    },

    /// Print a roff-format man page to stdout.
    ///
    /// Example: `fortibackup manpage | gzip -9 | sudo tee /usr/share/man/man1/fortibackup.1.gz`
    Manpage,
}

/// Shells supported by clap_complete, surfaced as a clap-native enum so the
/// CLI rejects unknown values at parse time.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ShellArg {
    Bash,
    Zsh,
    Fish,
    Elvish,
    Powershell,
}

impl From<ShellArg> for Shell {
    fn from(s: ShellArg) -> Self {
        match s {
            ShellArg::Bash => Shell::Bash,
            ShellArg::Zsh => Shell::Zsh,
            ShellArg::Fish => Shell::Fish,
            ShellArg::Elvish => Shell::Elvish,
            ShellArg::Powershell => Shell::PowerShell,
        }
    }
}
