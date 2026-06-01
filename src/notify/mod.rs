//! Notification subsystem (email + webhook).
//!
//! Notifications dispatched on backup outcomes run concurrently via
//! `tokio::join!` and never block the backup pipeline. Errors are logged but
//! do not propagate as backup failures.

pub mod email;
pub mod webhook;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::config::NotificationsConfig;

/// Outcome carried by a notification.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Success,
    Failed,
    NoChange,
    /// A device has had no successful backup within the watchdog window.
    Stale,
    /// A previously stale device has backed up successfully again.
    Recovered,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Success => "success",
            Status::Failed => "failed",
            Status::NoChange => "no_change",
            Status::Stale => "stale",
            Status::Recovered => "recovered",
        }
    }
}

/// Event payload published to all notification channels.
#[derive(Debug, Clone, Serialize)]
pub struct NotificationEvent {
    pub device: String,
    pub status: Status,
    pub error: Option<String>,
    pub bytes: Option<u64>,
    pub hash_short: Option<String>,
    pub transport: String,
    pub timestamp: DateTime<Utc>,
}

impl NotificationEvent {
    #[must_use]
    pub fn subject(&self) -> String {
        format!("[fortibackup] {} — {}", self.device, self.status.as_str())
    }

    #[must_use]
    pub fn body(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "Device:    {}", self.device);
        let _ = writeln!(out, "Status:    {}", self.status.as_str());
        let _ = writeln!(out, "Transport: {}", self.transport);
        let _ = writeln!(out, "Time:      {}", self.timestamp.to_rfc3339());
        if let Some(b) = self.bytes {
            let _ = writeln!(out, "Bytes:     {b}");
        }
        if let Some(h) = &self.hash_short {
            let _ = writeln!(out, "Hash:      {h}");
        }
        if let Some(e) = &self.error {
            let _ = write!(out, "\nError:\n{e}\n");
        }
        out
    }
}

/// Dispatch `event` to all configured channels in parallel. Errors are logged
/// and never returned.
pub async fn dispatch(cfg: &NotificationsConfig, event: &NotificationEvent) {
    // Stale/Recovered alerts ride the on_failure channels: they are the
    // attention-worthy events, and that's where the operator is watching.
    let channels: &[String] = match event.status {
        Status::Failed | Status::Stale | Status::Recovered => &cfg.on_failure,
        Status::Success | Status::NoChange => &cfg.on_success,
    };
    if channels.is_empty() {
        return;
    }

    let email_fut = async {
        if !channels.iter().any(|s| s == "email") {
            return;
        }
        let Some(email_cfg) = cfg.email.as_ref() else {
            tracing::warn!(
                "notifications.on_failure includes `email` but no [email] block is configured"
            );
            return;
        };
        if let Err(err) = email::send(email_cfg, event).await {
            tracing::error!(error = %err, "email notification failed");
        }
    };
    let webhook_fut = async {
        if !channels.iter().any(|s| s == "webhook") {
            return;
        }
        let Some(webhook_cfg) = cfg.webhook.as_ref() else {
            tracing::warn!(
                "notifications.on_failure includes `webhook` but no [webhook] block is configured"
            );
            return;
        };
        if let Err(err) = webhook::send(webhook_cfg, event).await {
            tracing::error!(error = %err, "webhook notification failed");
        }
    };

    tokio::join!(email_fut, webhook_fut);
}
