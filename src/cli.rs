//! Command-line interface definitions (clap derive).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
}
