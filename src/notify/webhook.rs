//! Generic webhook notification (JSON body).

use std::time::Duration;

use reqwest::Client;
use serde_json::json;

use crate::config::WebhookConfig;
use crate::error::NotificationError;
use crate::notify::NotificationEvent;

/// Send a webhook notification.
///
/// # Errors
/// Returns [`NotificationError`] if the HTTP request fails to build or send.
pub async fn send(cfg: &WebhookConfig, event: &NotificationEvent) -> Result<(), NotificationError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("fortibackup/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| NotificationError::Webhook(e.to_string()))?;

    let method = cfg.method.to_uppercase();
    let payload = json!({
        "device": event.device,
        "status": match event.status {
            crate::notify::Status::Success => "success",
            crate::notify::Status::Failed => "failed",
            crate::notify::Status::NoChange => "no_change",
            crate::notify::Status::Stale => "stale",
            crate::notify::Status::Recovered => "recovered",
        },
        "error": event.error,
        "bytes": event.bytes,
        "hash_short": event.hash_short,
        "transport": event.transport,
        "timestamp": event.timestamp.to_rfc3339(),
    });

    let req = match method.as_str() {
        "POST" => client.post(&cfg.url),
        "PUT" => client.put(&cfg.url),
        other => {
            return Err(NotificationError::Webhook(format!(
                "unsupported webhook method `{other}`"
            )))
        }
    };

    let resp = req
        .json(&payload)
        .send()
        .await
        .map_err(|e| NotificationError::Webhook(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(NotificationError::Webhook(format!(
            "webhook returned status {}",
            resp.status()
        )));
    }
    Ok(())
}
