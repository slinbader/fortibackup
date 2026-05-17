//! S3 / S3-compatible (MinIO) mirror destination.
//!
//! Filesystem remains the authoritative store — that is where dedup,
//! retention, and `list` operate. S3 acts as a **mirror**: when a new
//! backup is written locally we also upload the same two files
//! (`.conf[.gz]` and the `.json` sidecar) under the same relative path.
//!
//! Upload errors do not fail the backup; they are logged and surfaced via
//! the existing notification + metrics paths, but the local copy is the
//! source of truth so we keep it regardless.

use std::path::Path;

use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::config::Builder as S3ConfigBuilder;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use tracing::{debug, error, info};

use crate::config::S3Config;
use crate::error::StorageError;

const PROVIDER: &str = "fortibackup-config";

/// Async-constructed S3 mirror. Cheap to keep around; clones share the
/// underlying client.
#[derive(Clone)]
pub struct S3Mirror {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3Mirror {
    /// Build a client from the parsed config. Resolves credentials in this
    /// order:
    /// 1. `access_key_env` / `secret_key_env` (explicit)
    /// 2. Default AWS credential chain (env, IMDS, config file, etc.)
    pub async fn from_config(cfg: &S3Config) -> Result<Self, StorageError> {
        let explicit = explicit_creds(cfg)?;

        let mut loader =
            aws_config::defaults(BehaviorVersion::latest()).region(Region::new(cfg.region.clone()));
        if let Some(creds) = explicit {
            loader = loader.credentials_provider(creds);
        }
        let shared = loader.load().await;

        let mut builder = S3ConfigBuilder::from(&shared);
        if let Some(endpoint) = cfg.endpoint.as_ref() {
            builder = builder.endpoint_url(endpoint);
        }
        if cfg.force_path_style {
            builder = builder.force_path_style(true);
        }
        let s3_cfg = builder.build();
        let client = Client::from_conf(s3_cfg);
        Ok(Self {
            client,
            bucket: cfg.bucket.clone(),
            prefix: cfg.prefix.trim_matches('/').to_owned(),
        })
    }

    fn key_for(&self, device: &str, filename: &str) -> String {
        build_key(&self.prefix, device, filename)
    }

    /// Upload a single file to S3. Used twice per backup (the `.conf[.gz]`
    /// and the `.json` sidecar).
    pub async fn upload_file(
        &self,
        local_path: &Path,
        device: &str,
        content_type: &str,
    ) -> Result<(), StorageError> {
        let filename = local_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| StorageError::InvalidFilename(local_path.display().to_string()))?;
        let key = self.key_for(device, filename);
        // Backups are MB-scale — reading into memory is simpler than wiring
        // tokio streaming and keeps the dependency surface small.
        let raw = tokio::fs::read(local_path)
            .await
            .map_err(|e| StorageError::Io {
                path: local_path.to_path_buf(),
                source: e,
            })?;
        let body = ByteStream::from(raw);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body)
            .content_type(content_type)
            .send()
            .await
            .map_err(|e| StorageError::Io {
                path: local_path.to_path_buf(),
                source: std::io::Error::other(format!("s3 put_object {key}: {e}")),
            })?;
        debug!(bucket = %self.bucket, key = %key, "uploaded to s3");
        Ok(())
    }
}

fn build_key(prefix: &str, device: &str, filename: &str) -> String {
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        format!("{device}/{filename}")
    } else {
        format!("{prefix}/{device}/{filename}")
    }
}

fn explicit_creds(cfg: &S3Config) -> Result<Option<Credentials>, StorageError> {
    match (cfg.access_key_env.as_ref(), cfg.secret_key_env.as_ref()) {
        (Some(a), Some(s)) => {
            let access = std::env::var(a)
                .map_err(|_| StorageError::InvalidFilename(format!("env var `{a}` not set")))?;
            let secret = std::env::var(s)
                .map_err(|_| StorageError::InvalidFilename(format!("env var `{s}` not set")))?;
            Ok(Some(Credentials::new(access, secret, None, None, PROVIDER)))
        }
        (None, None) => Ok(None),
        _ => Err(StorageError::InvalidFilename(
            "S3 config: access_key_env and secret_key_env must both be set or both omitted"
                .to_owned(),
        )),
    }
}

/// Convenience wrapper: upload both files for a new backup. Errors are
/// logged but never propagated — local storage already succeeded.
pub async fn mirror_new_backup(
    mirror: &S3Mirror,
    device: &str,
    conf_path: &Path,
    sidecar_path: &Path,
) {
    let content_type = if conf_path.extension().and_then(|s| s.to_str()) == Some("gz") {
        "application/gzip"
    } else {
        "text/plain; charset=utf-8"
    };
    if let Err(err) = mirror.upload_file(conf_path, device, content_type).await {
        error!(device, error = %err, "s3 mirror upload of backup failed");
        return;
    }
    if let Err(err) = mirror
        .upload_file(sidecar_path, device, "application/json")
        .await
    {
        error!(device, error = %err, "s3 mirror upload of sidecar failed");
        return;
    }
    info!(device, "backup mirrored to s3");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::S3Config;

    #[test]
    fn key_for_with_empty_prefix() {
        assert_eq!(build_key("", "fgt-a", "x.conf"), "fgt-a/x.conf");
    }

    #[test]
    fn key_for_with_prefix_strips_slashes() {
        assert_eq!(
            build_key("backups", "fgt-a", "x.conf"),
            "backups/fgt-a/x.conf"
        );
        assert_eq!(
            build_key("/backups/", "fgt-a", "x.conf"),
            "backups/fgt-a/x.conf"
        );
    }

    #[test]
    fn explicit_creds_pair_required() {
        let cfg = S3Config {
            bucket: "b".into(),
            region: "us-east-1".into(),
            endpoint: None,
            prefix: String::new(),
            access_key_env: Some("A".into()),
            secret_key_env: None,
            force_path_style: false,
        };
        assert!(explicit_creds(&cfg).is_err());
    }
}
