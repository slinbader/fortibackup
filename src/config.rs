//! Configuration loader.
//!
//! Parses the TOML configuration file and validates it. Secrets are *never*
//! read from the file: any `*_env` field contains the name of an environment
//! variable that will be resolved at runtime.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub global: GlobalConfig,
    #[serde(default)]
    pub notifications: NotificationsConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub webui: WebUiConfig,
    #[serde(default)]
    pub watchdog: WatchdogConfig,
    #[serde(default)]
    pub report: ReportConfig,
    #[serde(default)]
    pub devices: Vec<Device>,
}

/// Institutional header used by the monthly backup report in the web UI. The
/// report is evidence handed to management, so the organization name and
/// subtitle are configurable here rather than hard-coded in the binary.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReportConfig {
    /// Organization name shown as the report letterhead, e.g. `"RNPN"`.
    #[serde(default = "default_report_org")]
    pub org_name: String,
    /// Second line under the org name, e.g. `"Dirección de TICs"`.
    #[serde(default = "default_report_subtitle")]
    pub subtitle: String,
}

// Manual `Default` (rather than derive) so an absent `[report]` block and a
// present block missing either field both resolve to the same institutional
// defaults.
impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            org_name: default_report_org(),
            subtitle: default_report_subtitle(),
        }
    }
}

fn default_report_org() -> String {
    "RNPN".to_owned()
}
fn default_report_subtitle() -> String {
    "Unidad de Redes y Ciberseguridad".to_owned()
}

/// Backup-overdue watchdog. When enabled, a background task checks each
/// device's last *successful* backup and alerts (via the same channels as
/// `notifications.on_failure`) when one goes stale. This catches the silent
/// failure case: the scheduler stopped firing, the host was down, or a device
/// became unreachable for longer than expected — none of which produce a
/// failed-fetch alert because no fetch was even attempted.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatchdogConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Alert when a device has had no successful backup within this window,
    /// e.g. `"26h"`, `"2d"`. Required when `enabled = true`.
    pub stale_after: Option<String>,
    /// How often the watchdog re-checks. Defaults to `"1h"`.
    #[serde(default = "default_watchdog_interval")]
    pub check_interval: String,
}

// Manual `Default` (rather than derive) so an absent `[watchdog]` block and a
// present block with a missing `check_interval` both resolve to "1h".
impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            stale_after: None,
            check_interval: default_watchdog_interval(),
        }
    }
}

fn default_watchdog_interval() -> String {
    "1h".to_owned()
}

impl WatchdogConfig {
    /// Parse `stale_after` into a [`std::time::Duration`].
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] if the field is unset or not a valid
    /// humantime duration.
    pub fn stale_after_duration(&self) -> Result<std::time::Duration, ConfigError> {
        let raw = self.stale_after.as_deref().ok_or_else(|| {
            ConfigError::Invalid("watchdog.stale_after is required when enabled".to_owned())
        })?;
        humantime::parse_duration(raw).map_err(|e| {
            ConfigError::Invalid(format!("watchdog.stale_after `{raw}` is invalid: {e}"))
        })
    }

    /// Parse `check_interval` into a [`std::time::Duration`].
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] if the field is not a valid humantime
    /// duration.
    pub fn check_interval_duration(&self) -> Result<std::time::Duration, ConfigError> {
        humantime::parse_duration(&self.check_interval).map_err(|e| {
            ConfigError::Invalid(format!(
                "watchdog.check_interval `{}` is invalid: {e}",
                self.check_interval
            ))
        })
    }
}

/// Embedded read-mostly web UI. Active only under the `run` daemon, behind
/// HTTP Basic auth. When `listen` is unset the UI never starts.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WebUiConfig {
    pub listen: Option<String>,
    pub user: Option<String>,
    pub password_env: Option<String>,
}

/// Optional secondary storage destinations. Filesystem is always the
/// primary; these are *mirrors* that receive a copy of each new backup.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StorageConfig {
    pub s3: Option<S3Config>,
}

/// S3 / S3-compatible (MinIO, Wasabi, Backblaze B2) mirror.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3Config {
    pub bucket: String,
    #[serde(default = "default_s3_region")]
    pub region: String,
    /// Optional custom endpoint (e.g. `https://minio.internal:9000`).
    /// Required for non-AWS providers.
    pub endpoint: Option<String>,
    /// Object key prefix; appended before `{device}/{filename}`.
    #[serde(default)]
    pub prefix: String,
    /// Env var holding the AWS access key. If absent, falls back to the
    /// usual AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / role chain.
    pub access_key_env: Option<String>,
    pub secret_key_env: Option<String>,
    /// For MinIO / older providers that need path-style addressing
    /// (`endpoint/bucket/key` instead of `bucket.endpoint/key`).
    #[serde(default)]
    pub force_path_style: bool,
}

fn default_s3_region() -> String {
    "us-east-1".to_owned()
}

/// Prometheus metrics endpoint configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Address to bind the `/metrics` HTTP server on, e.g. `"127.0.0.1:9090"`.
    /// When absent, the endpoint is not started.
    pub listen: Option<String>,
}

/// Global daemon settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalConfig {
    pub backup_dir: PathBuf,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_retention_min_copies")]
    pub retention_min_copies: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// When `true`, stored backups are gzip-compressed on disk (`.conf.gz`).
    /// The hash and metadata sidecar still reflect the *uncompressed*
    /// content, so no_change detection survives compression toggles.
    #[serde(default)]
    pub compress: bool,
}

const fn default_retention_days() -> u32 {
    90
}
const fn default_retention_min_copies() -> u32 {
    7
}
fn default_log_level() -> String {
    "info".to_owned()
}

/// Notification configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NotificationsConfig {
    #[serde(default)]
    pub on_failure: Vec<String>,
    #[serde(default)]
    pub on_success: Vec<String>,
    pub email: Option<EmailConfig>,
    pub webhook: Option<WebhookConfig>,
}

/// SMTP configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password_env: String,
    pub from: String,
    pub to: Vec<String>,
}

/// Webhook configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default = "default_webhook_method")]
    pub method: String,
}

fn default_webhook_method() -> String {
    "POST".to_owned()
}

/// Transport method for a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportMethod {
    Api,
    Ssh,
}

/// A single FortiGate device to back up.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Device {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub method: TransportMethod,

    // API
    pub api_token_env: Option<String>,
    #[serde(default = "default_verify_tls")]
    pub verify_tls: bool,
    /// Optional VDOM scope. When set, the backup is fetched with
    /// `?scope=vdom&vdom=<name>` instead of the default `?scope=global`.
    /// Use this on multi-VDOM FortiGates when you want a per-tenant backup.
    pub vdom: Option<String>,

    // SSH
    pub ssh_username: Option<String>,
    pub ssh_key_path: Option<PathBuf>,
    pub ssh_password_env: Option<String>,

    // Common
    pub schedule: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

const fn default_verify_tls() -> bool {
    false
}
const fn default_timeout() -> u64 {
    60
}

impl Config {
    /// Returns the device with the given name, if any.
    #[must_use]
    pub fn find_device(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }
}

/// Loads, parses, and validates the configuration from the given path.
///
/// # Errors
/// Returns [`ConfigError`] if the file cannot be read, the TOML is malformed,
/// required environment variables are missing, or validation fails.
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let cfg: Config = toml::from_str(&raw)?;
    validate(&cfg)?;
    Ok(cfg)
}

/// Parses a [`Config`] from a TOML string. Validates but does not check
/// environment variables.
///
/// # Errors
/// Returns [`ConfigError`] if the TOML is malformed or validation fails.
pub fn parse_str(raw: &str) -> Result<Config, ConfigError> {
    let cfg: Config = toml::from_str(raw)?;
    validate(&cfg)?;
    Ok(cfg)
}

/// Validates structural correctness of a configuration.
fn validate(cfg: &Config) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for device in &cfg.devices {
        if !seen.insert(device.name.as_str()) {
            return Err(ConfigError::DuplicateDevice(device.name.clone()));
        }
        validate_device(device)?;
    }

    if cfg.notifications.on_failure.iter().any(|s| s == "email")
        && cfg.notifications.email.is_none()
    {
        return Err(ConfigError::Invalid(
            "notifications.on_failure includes `email` but [notifications.email] is missing"
                .to_owned(),
        ));
    }
    if cfg.notifications.on_failure.iter().any(|s| s == "webhook")
        && cfg.notifications.webhook.is_none()
    {
        return Err(ConfigError::Invalid(
            "notifications.on_failure includes `webhook` but [notifications.webhook] is missing"
                .to_owned(),
        ));
    }

    if cfg.watchdog.enabled {
        // Validate both durations up front so a bad value fails at load time
        // rather than silently disabling the watchdog at runtime.
        cfg.watchdog.stale_after_duration()?;
        cfg.watchdog.check_interval_duration()?;
        if cfg.notifications.on_failure.is_empty() {
            return Err(ConfigError::Invalid(
                "watchdog.enabled = true but notifications.on_failure is empty — \
                 overdue alerts would have nowhere to go"
                    .to_owned(),
            ));
        }
    }

    Ok(())
}

fn validate_device(device: &Device) -> Result<(), ConfigError> {
    match device.method {
        TransportMethod::Api => {
            if device.api_token_env.is_none() {
                return Err(ConfigError::Invalid(format!(
                    "device `{}`: api_token_env is required for method=api",
                    device.name
                )));
            }
        }
        TransportMethod::Ssh => {
            if device.ssh_username.is_none() {
                return Err(ConfigError::Invalid(format!(
                    "device `{}`: ssh_username is required for method=ssh",
                    device.name
                )));
            }
            if device.ssh_key_path.is_none() && device.ssh_password_env.is_none() {
                return Err(ConfigError::Invalid(format!(
                    "device `{}`: either ssh_key_path or ssh_password_env is required",
                    device.name
                )));
            }
        }
    }
    if device.schedule.trim().is_empty() {
        return Err(ConfigError::Invalid(format!(
            "device `{}`: schedule must not be empty",
            device.name
        )));
    }
    Ok(())
}

/// Resolves an environment variable, returning a structured error if missing.
///
/// # Errors
/// Returns [`ConfigError::MissingEnv`] if the variable is unset.
pub fn read_env(name: &str) -> Result<String, ConfigError> {
    env::var(name).map_err(|_| ConfigError::MissingEnv(name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_API: &str = r#"
[global]
backup_dir = "/var/lib/fortibackup"

[[devices]]
name = "fgt-a"
host = "10.0.0.1"
port = 443
method = "api"
api_token_env = "FGT_TOKEN_A"
schedule = "0 0 2 * * *"
"#;

    #[test]
    fn parses_minimal_api_config() {
        let cfg = parse_str(MINIMAL_API).expect("parse");
        assert_eq!(cfg.global.retention_days, 90);
        assert_eq!(cfg.global.retention_min_copies, 7);
        assert_eq!(cfg.devices.len(), 1);
        assert_eq!(cfg.devices[0].method, TransportMethod::Api);
        assert_eq!(cfg.devices[0].timeout_secs, 60);
        assert!(!cfg.devices[0].verify_tls);
    }

    #[test]
    fn rejects_duplicate_devices() {
        let raw = r#"
[global]
backup_dir = "/tmp"

[[devices]]
name = "x"
host = "1.1.1.1"
port = 443
method = "api"
api_token_env = "T"
schedule = "0 0 2 * * *"

[[devices]]
name = "x"
host = "2.2.2.2"
port = 443
method = "api"
api_token_env = "T2"
schedule = "0 0 3 * * *"
"#;
        let err = parse_str(raw).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateDevice(_)));
    }

    #[test]
    fn rejects_api_without_token_env() {
        let raw = r#"
[global]
backup_dir = "/tmp"

[[devices]]
name = "x"
host = "1.1.1.1"
port = 443
method = "api"
schedule = "0 0 2 * * *"
"#;
        let err = parse_str(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn rejects_ssh_without_credentials() {
        let raw = r#"
[global]
backup_dir = "/tmp"

[[devices]]
name = "x"
host = "1.1.1.1"
port = 22
method = "ssh"
ssh_username = "u"
schedule = "0 0 2 * * *"
"#;
        let err = parse_str(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn find_device_works() {
        let cfg = parse_str(MINIMAL_API).expect("parse");
        assert!(cfg.find_device("fgt-a").is_some());
        assert!(cfg.find_device("nope").is_none());
    }

    #[test]
    fn rejects_email_failure_without_email_block() {
        let raw = r#"
[global]
backup_dir = "/tmp"

[notifications]
on_failure = ["email"]

[[devices]]
name = "x"
host = "1.1.1.1"
port = 443
method = "api"
api_token_env = "T"
schedule = "0 0 2 * * *"
"#;
        let err = parse_str(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn parses_watchdog_block() {
        let raw = r#"
[global]
backup_dir = "/tmp"

[notifications]
on_failure = ["email"]

[notifications.email]
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_user = "u@x.com"
smtp_password_env = "P"
from = "u@x.com"
to = ["ops@x.com"]

[watchdog]
enabled = true
stale_after = "26h"
check_interval = "30m"

[[devices]]
name = "x"
host = "1.1.1.1"
port = 443
method = "api"
api_token_env = "T"
schedule = "0 0 2 * * *"
"#;
        let cfg = parse_str(raw).expect("parse");
        assert!(cfg.watchdog.enabled);
        assert_eq!(
            cfg.watchdog.stale_after_duration().unwrap(),
            std::time::Duration::from_secs(26 * 3600)
        );
        assert_eq!(
            cfg.watchdog.check_interval_duration().unwrap(),
            std::time::Duration::from_secs(30 * 60)
        );
    }

    #[test]
    fn watchdog_defaults_when_absent() {
        let cfg = parse_str(MINIMAL_API).expect("parse");
        assert!(!cfg.watchdog.enabled);
        assert_eq!(cfg.watchdog.check_interval, "1h");
    }

    #[test]
    fn rejects_watchdog_enabled_without_stale_after() {
        let raw = r#"
[global]
backup_dir = "/tmp"

[notifications]
on_failure = ["webhook"]

[notifications.webhook]
url = "https://example.com/hook"

[watchdog]
enabled = true

[[devices]]
name = "x"
host = "1.1.1.1"
port = 443
method = "api"
api_token_env = "T"
schedule = "0 0 2 * * *"
"#;
        let err = parse_str(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn rejects_watchdog_enabled_without_notification_channel() {
        let raw = r#"
[global]
backup_dir = "/tmp"

[watchdog]
enabled = true
stale_after = "26h"

[[devices]]
name = "x"
host = "1.1.1.1"
port = 443
method = "api"
api_token_env = "T"
schedule = "0 0 2 * * *"
"#;
        let err = parse_str(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn rejects_watchdog_bad_duration() {
        let raw = r#"
[global]
backup_dir = "/tmp"

[notifications]
on_failure = ["webhook"]

[notifications.webhook]
url = "https://example.com/hook"

[watchdog]
enabled = true
stale_after = "soon"

[[devices]]
name = "x"
host = "1.1.1.1"
port = 443
method = "api"
api_token_env = "T"
schedule = "0 0 2 * * *"
"#;
        let err = parse_str(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }
}
