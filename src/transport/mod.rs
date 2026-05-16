//! Transport abstractions for fetching FortiGate configuration.
//!
//! Each transport implements [`BackupTransport`] and returns a
//! [`BackupArtifact`] containing the configuration bytes and best-effort
//! metadata about the device.

pub mod api;
pub mod ssh;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::config::{Device, TransportMethod};
use crate::error::TransportError;

/// The configuration payload retrieved from a single device, plus metadata.
#[derive(Debug, Clone)]
pub struct BackupArtifact {
    pub content: Vec<u8>,
    pub hostname: String,
    pub firmware_version: Option<String>,
    pub serial: Option<String>,
    pub fetched_at: DateTime<Utc>,
}

/// Abstraction over the protocol used to retrieve a device configuration.
#[async_trait]
pub trait BackupTransport: Send + Sync {
    /// Fetches the running configuration of the given device.
    ///
    /// # Errors
    /// Returns [`TransportError`] on network, authentication, timeout, or
    /// protocol errors.
    async fn fetch_config(&self, device: &Device) -> Result<BackupArtifact, TransportError>;

    /// Lightweight reachability check. Default returns `Ok(())` if `fetch_config`
    /// succeeds; transports may override with a cheaper check.
    ///
    /// # Errors
    /// Returns [`TransportError`] if the device cannot be reached.
    async fn check_reachable(&self, device: &Device) -> Result<(), TransportError> {
        let _ = self.fetch_config(device).await?;
        Ok(())
    }
}

/// Builds a transport for the given device based on its `method` field.
#[must_use]
pub fn new(method: TransportMethod) -> Box<dyn BackupTransport> {
    match method {
        TransportMethod::Api => Box::new(api::ApiTransport::new()),
        TransportMethod::Ssh => Box::new(ssh::SshTransport::new()),
    }
}

/// Retry an async operation with exponential backoff: 5s, 15s, 45s (3 attempts).
pub(crate) async fn retry_with_backoff<F, Fut, T>(mut op: F) -> Result<T, TransportError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, TransportError>>,
{
    let delays_ms: [u64; 2] = [5_000, 15_000];
    let mut attempt: u32 = 0;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(err) => {
                if attempt as usize >= delays_ms.len() {
                    return Err(err);
                }
                tracing::warn!(
                    attempt = attempt + 1,
                    error = %err,
                    "transport attempt failed, retrying"
                );
                tokio::time::sleep(std::time::Duration::from_millis(
                    delays_ms[attempt as usize],
                ))
                .await;
                attempt += 1;
            }
        }
    }
}
