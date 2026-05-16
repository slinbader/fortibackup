//! Scheduler — spawns a cron job per device and runs forever until the
//! daemon receives Ctrl-C / SIGTERM.

use std::sync::Arc;

use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info};

use crate::backup;
use crate::config::Config;
use crate::error::SchedulerError;

/// Build and run a scheduler with one job per device.
///
/// Returns when a Ctrl-C / SIGTERM is received.
///
/// # Errors
/// Returns [`SchedulerError`] if the underlying scheduler backend fails to
/// initialize or accept a job.
pub async fn run(cfg: Config) -> Result<(), SchedulerError> {
    let mut scheduler = JobScheduler::new()
        .await
        .map_err(|e| SchedulerError::Backend(e.to_string()))?;

    let cfg = Arc::new(cfg);

    for device in &cfg.devices {
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

        scheduler
            .add(job)
            .await
            .map_err(|e| SchedulerError::Backend(e.to_string()))?;
        info!(device = %device.name, schedule = %device.schedule, "scheduled job");
    }

    scheduler
        .start()
        .await
        .map_err(|e| SchedulerError::Backend(e.to_string()))?;

    info!("scheduler started, awaiting shutdown signal");
    wait_for_shutdown().await;
    info!("shutdown signal received, stopping scheduler");

    if let Err(err) = scheduler.shutdown().await {
        error!(error = %err, "error during scheduler shutdown");
    }
    Ok(())
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
