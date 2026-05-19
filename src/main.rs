#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

//! `fortibackup` binary entry point. All logic lives in the library crate;
//! this file only wires up the CLI to the modules.

use std::io;

use anyhow::Context;
use clap::{CommandFactory, Parser};
use clap_complete::generate;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use fortibackup::cli::{Cli, Command};
use fortibackup::config::{self, load_config, Config};
use fortibackup::{backup, metrics, notify, scheduler, storage, transport, webui};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // These subcommands never touch the config file or the network.
    // Handle them before doing anything else so they can be used in
    // packaging scripts and CI without a populated /etc/fortibackup.
    match cli.command {
        Command::Completions { shell } => return cmd_completions(shell.into()),
        Command::Manpage => return cmd_manpage(),
        _ => {}
    }

    let cfg = load_config(&cli.config)
        .with_context(|| format!("loading config {}", cli.config.display()))?;

    init_tracing(&cfg.global.log_level);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        devices = cfg.devices.len(),
        "fortibackup starting"
    );

    match cli.command {
        Command::Run => cmd_run(cfg).await,
        Command::Once { device } => cmd_once(cfg, device).await,
        Command::List { device } => cmd_list(&cfg, device.as_deref()),
        Command::Verify => cmd_verify(cfg).await,
        Command::Prune { device, dry_run } => cmd_prune(&cfg, device.as_deref(), dry_run),
        Command::Completions { .. } | Command::Manpage => unreachable!(),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn cmd_completions(shell: clap_complete::Shell) -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_owned();
    generate(shell, &mut cmd, name, &mut io::stdout());
    Ok(())
}

fn cmd_manpage() -> anyhow::Result<()> {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    man.render(&mut io::stdout())?;
    Ok(())
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let want_json =
        std::env::var("FORTIBACKUP_LOG_FORMAT").map_or(true, |v| v.eq_ignore_ascii_case("json"));

    if want_json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .compact()
            .init();
    }
}

async fn cmd_run(cfg: Config) -> anyhow::Result<()> {
    if let Some(listen) = cfg.metrics.listen.clone() {
        metrics::serve(&listen)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    if cfg.webui.listen.is_some() {
        let shared = std::sync::Arc::new(cfg.clone());
        webui::serve(shared).await.map_err(|e| anyhow::anyhow!(e))?;
    }
    scheduler::run(cfg).await.map_err(anyhow::Error::from)
}

async fn cmd_once(cfg: Config, device: Option<String>) -> anyhow::Result<()> {
    let targets: Vec<config::Device> = match device {
        Some(name) => {
            let dev = cfg
                .find_device(&name)
                .with_context(|| format!("device `{name}` not found in config"))?
                .clone();
            vec![dev]
        }
        None => cfg.devices.clone(),
    };
    if targets.is_empty() {
        anyhow::bail!("no devices to back up");
    }

    let mut any_failed = false;
    for device in &targets {
        let report = backup::run_for_device(&cfg, device).await;
        if matches!(report.status, notify::Status::Failed) {
            any_failed = true;
        }
    }
    if any_failed {
        anyhow::bail!("one or more device backups failed");
    }
    Ok(())
}

fn cmd_list(cfg: &Config, device: Option<&str>) -> anyhow::Result<()> {
    let entries = match device {
        Some(name) => storage::list_entries_for_device(&cfg.global.backup_dir, name)?,
        None => storage::list_all_entries(&cfg.global.backup_dir)?,
    };
    if entries.is_empty() {
        println!(
            "(no backups found under {})",
            cfg.global.backup_dir.display()
        );
        return Ok(());
    }
    println!(
        "{:<24}  {:<22}  {:>12}  {:<14}  PATH",
        "DEVICE", "WHEN (UTC)", "SIZE", "HASH"
    );
    for e in entries {
        let short = e.sha256.chars().take(12).collect::<String>();
        println!(
            "{:<24}  {:<22}  {:>12}  {:<14}  {}",
            e.device,
            e.created_at.format("%Y-%m-%d %H:%M:%S"),
            human_size(e.size_bytes),
            short,
            e.path.display()
        );
    }
    Ok(())
}

async fn cmd_verify(cfg: Config) -> anyhow::Result<()> {
    info!("config parsed successfully");
    println!("config OK — {} device(s)", cfg.devices.len());

    let mut any_unreachable = false;
    for device in &cfg.devices {
        let transport_impl = transport::new(device.method);
        match transport_impl.check_reachable(device).await {
            Ok(()) => {
                println!("  ✓ {} ({}) reachable", device.name, device.host);
            }
            Err(err) => {
                any_unreachable = true;
                error!(device = %device.name, error = %err, "device unreachable");
                println!("  ✗ {} ({}): {}", device.name, device.host, err);
            }
        }
    }
    if any_unreachable {
        anyhow::bail!("one or more devices are unreachable");
    }
    Ok(())
}

fn cmd_prune(cfg: &Config, device: Option<&str>, dry_run: bool) -> anyhow::Result<()> {
    let devices: Vec<String> = match device {
        Some(name) => {
            cfg.find_device(name)
                .with_context(|| format!("device `{name}` not found in config"))?;
            vec![name.to_owned()]
        }
        None => cfg.devices.iter().map(|d| d.name.clone()).collect(),
    };
    if devices.is_empty() {
        anyhow::bail!("no devices to prune");
    }

    let mut total = 0_usize;
    for name in &devices {
        let victims = storage::plan_retention(
            &cfg.global.backup_dir,
            name,
            cfg.global.retention_days,
            cfg.global.retention_min_copies,
        )?;
        if victims.is_empty() {
            println!("{name}: nothing to prune");
            continue;
        }
        if dry_run {
            println!("{name}: would delete {} file(s):", victims.len());
            for v in &victims {
                println!("  - {}", v.path.display());
            }
        } else {
            for v in &victims {
                println!("  - removing {}", v.path.display());
            }
            let removed = storage::apply_retention(
                &cfg.global.backup_dir,
                name,
                cfg.global.retention_days,
                cfg.global.retention_min_copies,
            )?;
            println!("{name}: removed {removed} file(s)");
            total += removed;
        }
    }
    if !dry_run {
        info!(total, "prune completed");
    }
    Ok(())
}

#[allow(clippy::cast_precision_loss)]
fn human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    let b = bytes as f64;
    if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}
