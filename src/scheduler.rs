//! Scheduler — spawns a cron job per device. Supports hot config reload
//! via an mpsc channel: when a new `Config` arrives, all current jobs are
//! removed and the new set is installed, all without restarting the
//! daemon process.

use std::sync::Arc;

use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::backup;
use crate::config::Config;
use crate::error::SchedulerError;

/// Shared handle to the live configuration. Cloneable; the daemon, the
/// web UI, and any future consumer hold an `Arc` to it. After a hot
/// reload, the same Arc<Mutex<...>> is updated in place so all readers
/// observe the new value on the next lock.
pub type SharedConfig = Arc<Mutex<Arc<Config>>>;

/// Build and run a scheduler with one job per device. Loops forever,
/// rebuilding all jobs every time a new `Config` arrives via `reload_rx`.
/// Returns when Ctrl-C / SIGTERM is received.
///
/// # Errors
/// Returns [`SchedulerError`] if the underlying scheduler backend fails to
/// initialize or accept a job, or if a job has an invalid cron expression.
pub async fn run(
    initial: Config,
    shared: SharedConfig,
    mut reload_rx: Receiver<Config>,
) -> Result<(), SchedulerError> {
    let mut scheduler = JobScheduler::new()
        .await
        .map_err(|e| SchedulerError::Backend(e.to_string()))?;
    scheduler
        .start()
        .await
        .map_err(|e| SchedulerError::Backend(e.to_string()))?;

    let mut current_ids =
        install_jobs(&scheduler, Arc::clone(&*shared.lock().await), &initial).await?;
    info!(
        devices = initial.devices.len(),
        "scheduler started, awaiting shutdown signal"
    );

    loop {
        tokio::select! {
            () = wait_for_shutdown() => {
                info!("shutdown signal received, stopping scheduler");
                if let Err(err) = scheduler.shutdown().await {
                    error!(error = %err, "error during scheduler shutdown");
                }
                return Ok(());
            }
            maybe = reload_rx.recv() => {
                let Some(new_cfg) = maybe else {
                    info!("reload channel closed, scheduler continues");
                    continue;
                };
                info!(devices = new_cfg.devices.len(), "config reload requested");
                // Swap the shared Arc<Config> first so any backup that
                // fires *during* the swap reads consistent data.
                {
                    let mut guard = shared.lock().await;
                    *guard = Arc::new(new_cfg.clone());
                }
                // Tear down the old job set.
                for id in current_ids.drain(..) {
                    if let Err(err) = scheduler.remove(&id).await {
                        warn!(uuid = %id, error = %err, "failed to remove old job during reload");
                    }
                }
                // Install the new one. If a cron expression is bad we
                // log it and leave the scheduler with no jobs for that
                // device — the daemon stays up.
                match install_jobs(&scheduler, Arc::clone(&*shared.lock().await), &new_cfg).await {
                    Ok(ids) => {
                        current_ids = ids;
                        info!("config reload complete");
                    }
                    Err(err) => {
                        error!(error = %err, "config reload failed to install all jobs");
                    }
                }
            }
        }
    }
}

async fn install_jobs(
    scheduler: &JobScheduler,
    cfg: Arc<Config>,
    snapshot: &Config,
) -> Result<Vec<Uuid>, SchedulerError> {
    let mut ids = Vec::with_capacity(snapshot.devices.len());
    for device in &snapshot.devices {
        let device_name = device.name.clone();
        let schedule = device.schedule.clone();
        let cfg_clone = Arc::clone(&cfg);

        let job = Job::new_async(schedule.as_str(), move |_uuid, _lock| {
            let cfg_inner = Arc::clone(&cfg_clone);
            let device_name = device_name.clone();
            Box::pin(async move {
                let Some(device) = cfg_inner.find_device(&device_name).cloned() else {
                    error!(device = %device_name, "device disappeared from config");
                    return;
                };
                let _ = backup::run_for_device(&cfg_inner, &device).await;
            })
        })
        .map_err(|e| SchedulerError::InvalidCron {
            expr: device.schedule.clone(),
            reason: e.to_string(),
        })?;

        let id = scheduler
            .add(job)
            .await
            .map_err(|e| SchedulerError::Backend(e.to_string()))?;
        ids.push(id);
        info!(device = %device.name, schedule = %device.schedule, "scheduled job");
    }
    Ok(ids)
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to install SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
