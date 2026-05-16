//! Backup pipeline: fetch → hash → diff → store → retention → notify.

use std::time::Instant;

use chrono::Utc;
use tracing::{error, info, warn};

use crate::config::{Config, Device, TransportMethod};
use crate::error::BackupError;
use crate::notify::{self, NotificationEvent, Status};
use crate::storage::{self, SaveOutcome};
use crate::transport;

/// Result of running a backup for a single device.
#[derive(Debug, Clone)]
pub struct BackupReport {
    pub device: String,
    pub status: Status,
    pub duration_ms: u128,
    pub bytes: Option<u64>,
    pub hash_short: Option<String>,
    pub changed: bool,
    pub error: Option<String>,
}

/// Run the pipeline for one device, dispatching notifications if configured.
///
/// This function never returns an error. Failures are recorded in the
/// returned [`BackupReport`] and surfaced via tracing + notifications.
pub async fn run_for_device(cfg: &Config, device: &Device) -> BackupReport {
    let start = Instant::now();
    let transport_label = method_label(device.method);

    let result = execute(cfg, device).await;
    let duration_ms = start.elapsed().as_millis();

    let report = match result {
        Ok(outcome) => {
            let status = if outcome.changed {
                Status::Success
            } else {
                Status::NoChange
            };
            info!(
                device = %device.name,
                transport = transport_label,
                duration_ms = duration_ms as u64,
                bytes = outcome.bytes,
                hash_short = %short_hash(&outcome.hash),
                changed = outcome.changed,
                "backup completed"
            );
            BackupReport {
                device: device.name.clone(),
                status,
                duration_ms,
                bytes: Some(outcome.bytes),
                hash_short: Some(short_hash(&outcome.hash)),
                changed: outcome.changed,
                error: None,
            }
        }
        Err(err) => {
            error!(
                device = %device.name,
                transport = transport_label,
                duration_ms = duration_ms as u64,
                error = %err,
                "backup failed"
            );
            BackupReport {
                device: device.name.clone(),
                status: Status::Failed,
                duration_ms,
                bytes: None,
                hash_short: None,
                changed: false,
                error: Some(err.to_string()),
            }
        }
    };

    let status_label = match report.status {
        Status::Success => "success",
        Status::NoChange => "no_change",
        Status::Failed => "failed",
    };
    #[allow(clippy::cast_precision_loss)]
    crate::metrics::record_outcome(
        &report.device,
        status_label,
        (report.duration_ms as f64) / 1000.0,
        report.bytes,
    );

    let event = NotificationEvent {
        device: report.device.clone(),
        status: report.status,
        error: report.error.clone(),
        bytes: report.bytes,
        hash_short: report.hash_short.clone(),
        transport: transport_label.to_owned(),
        timestamp: Utc::now(),
    };
    notify::dispatch(&cfg.notifications, &event).await;

    report
}

struct PipelineOutcome {
    changed: bool,
    bytes: u64,
    hash: String,
}

async fn execute(cfg: &Config, device: &Device) -> Result<PipelineOutcome, BackupError> {
    let transport_impl = transport::new(device.method);
    let artifact = transport_impl.fetch_config(device).await?;
    let bytes = artifact.content.len() as u64;

    let SaveOutcome {
        changed,
        path: _,
        sha256,
    } = storage::save_backup(
        &cfg.global.backup_dir,
        &device.name,
        method_label(device.method),
        &artifact,
        cfg.global.compress,
    )?;

    match storage::apply_retention(
        &cfg.global.backup_dir,
        &device.name,
        cfg.global.retention_days,
        cfg.global.retention_min_copies,
    ) {
        Ok(removed) if removed > 0 => {
            info!(device = %device.name, removed, "retention cleanup");
        }
        Ok(_) => {}
        Err(err) => {
            warn!(device = %device.name, error = %err, "retention cleanup failed");
        }
    }

    Ok(PipelineOutcome {
        changed,
        bytes,
        hash: sha256,
    })
}

#[must_use]
pub fn method_label(method: TransportMethod) -> &'static str {
    match method {
        TransportMethod::Api => "api",
        TransportMethod::Ssh => "ssh",
    }
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hash_is_12_chars() {
        let s = short_hash("abcdef0123456789abcdef0123456789");
        assert_eq!(s.len(), 12);
        assert_eq!(s, "abcdef012345");
    }
}
