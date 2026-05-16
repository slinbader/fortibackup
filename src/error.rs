//! Error types for the fortibackup crate.
//!
//! Uses `thiserror` for the library-level error enum. Errors of one device
//! must never propagate out of the scheduler — the daemon logs, notifies, and
//! keeps running.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Top-level error type returned from library functions.
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("notification error: {0}")]
    Notification(#[from] NotificationError),

    #[error("scheduler error: {0}")]
    Scheduler(#[from] SchedulerError),
}

/// Errors raised while loading or validating the TOML configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to parse TOML config: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("environment variable `{0}` is not set")]
    MissingEnv(String),

    #[error("invalid configuration: {0}")]
    Invalid(String),

    #[error("duplicate device name: `{0}`")]
    DuplicateDevice(String),
}

/// Errors raised by transports while fetching a device configuration.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("SSH error: {0}")]
    Ssh(String),

    #[error("authentication failed for `{device}`")]
    Auth { device: String },

    #[error("device `{device}` returned status {status}: {body}")]
    BadStatus {
        device: String,
        status: u16,
        body: String,
    },

    #[error("operation timed out after {secs}s")]
    Timeout { secs: u64 },

    #[error("IO error during transport: {0}")]
    Io(#[from] io::Error),

    #[error("unsupported transport method: `{0}`")]
    Unsupported(String),

    #[error("invalid response from device: {0}")]
    InvalidResponse(String),
}

/// Errors raised while writing backup artifacts to disk or applying retention.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IO error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to serialize sidecar metadata: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("invalid backup filename: {0}")]
    InvalidFilename(String),
}

/// Errors raised by the notification subsystem.
#[derive(Debug, Error)]
pub enum NotificationError {
    #[error("SMTP error: {0}")]
    Smtp(String),

    #[error("email build error: {0}")]
    EmailBuild(String),

    #[error("webhook delivery failed: {0}")]
    Webhook(String),
}

/// Errors raised by the scheduler.
#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("scheduler backend error: {0}")]
    Backend(String),

    #[error("invalid cron expression `{expr}`: {reason}")]
    InvalidCron { expr: String, reason: String },
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, BackupError>;
