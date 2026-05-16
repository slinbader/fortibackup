//! On-disk storage of backup artifacts and retention policy.
//!
//! Layout:
//! ```text
//! {backup_dir}/
//!   {device_name}/
//!     2026-05-16_020000.conf
//!     2026-05-16_020000.json   # sidecar metadata
//! ```

use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::StorageError;
use crate::transport::BackupArtifact;

/// Sidecar metadata stored alongside each `.conf` backup file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupMetadata {
    pub device: String,
    pub hostname: String,
    pub fetched_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub sha256: String,
    pub firmware_version: Option<String>,
    pub serial: Option<String>,
    pub transport: String,
}

/// Result of saving (or skipping) a backup.
#[derive(Debug, Clone)]
pub struct SaveOutcome {
    /// `true` if a new file was written (i.e. config differed from last).
    pub changed: bool,
    /// Path of the file that represents the current state — either the
    /// newly-written one (when changed) or the previous one.
    pub path: PathBuf,
    /// Hash of the artifact content.
    pub sha256: String,
}

/// Listed view of a stored backup, used by `fortibackup list`.
#[derive(Debug, Clone)]
pub struct BackupEntry {
    pub device: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
    pub sha256: String,
}

/// Compute SHA-256 of a byte slice, returning a lowercase hex string.
#[must_use]
pub fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Returns the directory used to store backups for the given device.
#[must_use]
pub fn device_dir(backup_dir: &Path, device_name: &str) -> PathBuf {
    backup_dir.join(device_name)
}

fn io_err(path: &Path, source: std::io::Error) -> StorageError {
    StorageError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Returns the most recent stored sha256 for a device, if any.
///
/// # Errors
/// Returns [`StorageError`] on IO failures.
pub fn latest_hash(backup_dir: &Path, device_name: &str) -> Result<Option<String>, StorageError> {
    let entries = list_entries_for_device(backup_dir, device_name)?;
    Ok(entries.into_iter().next_back().map(|e| e.sha256))
}

/// Persist a backup artifact under `{backup_dir}/{device_name}/`.
///
/// If the content hash matches the most recently stored backup, no file is
/// written and the returned outcome has `changed = false`.
///
/// # Errors
/// Returns [`StorageError`] if directory creation, file write, or sidecar
/// serialization fail.
pub fn save_backup(
    backup_dir: &Path,
    device_name: &str,
    transport_label: &str,
    artifact: &BackupArtifact,
) -> Result<SaveOutcome, StorageError> {
    let dir = device_dir(backup_dir, device_name);
    std::fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;

    let hash = sha256_hex(&artifact.content);

    if let Some(previous) = latest_hash(backup_dir, device_name)? {
        if previous == hash {
            // Reuse path of the latest file as "current state".
            let entries = list_entries_for_device(backup_dir, device_name)?;
            let path = entries
                .into_iter()
                .next_back()
                .map_or_else(|| dir.clone(), |e| e.path);
            return Ok(SaveOutcome {
                changed: false,
                path,
                sha256: hash,
            });
        }
    }

    let stem = artifact.fetched_at.format("%Y-%m-%d_%H%M%S").to_string();
    let conf_path = dir.join(format!("{stem}.conf"));
    let meta_path = dir.join(format!("{stem}.json"));

    std::fs::write(&conf_path, &artifact.content).map_err(|e| io_err(&conf_path, e))?;

    let metadata = BackupMetadata {
        device: device_name.to_owned(),
        hostname: artifact.hostname.clone(),
        fetched_at: artifact.fetched_at,
        size_bytes: artifact.content.len() as u64,
        sha256: hash.clone(),
        firmware_version: artifact.firmware_version.clone(),
        serial: artifact.serial.clone(),
        transport: transport_label.to_owned(),
    };
    let meta_json = serde_json::to_vec_pretty(&metadata)?;
    std::fs::write(&meta_path, meta_json).map_err(|e| io_err(&meta_path, e))?;

    Ok(SaveOutcome {
        changed: true,
        path: conf_path,
        sha256: hash,
    })
}

/// List backup entries for a single device, oldest first.
///
/// # Errors
/// Returns [`StorageError`] on IO failures while reading the device directory
/// or sidecar files.
pub fn list_entries_for_device(
    backup_dir: &Path,
    device_name: &str,
) -> Result<Vec<BackupEntry>, StorageError> {
    let dir = device_dir(backup_dir, device_name);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    let read = std::fs::read_dir(&dir).map_err(|e| io_err(&dir, e))?;
    for entry in read {
        let entry = entry.map_err(|e| io_err(&dir, e))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| StorageError::InvalidFilename(path.display().to_string()))?;
        let created_at = parse_timestamp_from_stem(stem)
            .ok_or_else(|| StorageError::InvalidFilename(stem.to_owned()))?;
        let size = path.metadata().map_err(|e| io_err(&path, e))?.len();
        let sidecar = path.with_extension("json");
        let sha256 = if sidecar.exists() {
            let raw = std::fs::read(&sidecar).map_err(|e| io_err(&sidecar, e))?;
            let meta: BackupMetadata = serde_json::from_slice(&raw)?;
            meta.sha256
        } else {
            // Recompute hash if sidecar missing.
            let raw = std::fs::read(&path).map_err(|e| io_err(&path, e))?;
            sha256_hex(&raw)
        };
        entries.push(BackupEntry {
            device: device_name.to_owned(),
            path,
            size_bytes: size,
            created_at,
            sha256,
        });
    }
    entries.sort_by_key(|e| e.created_at);
    Ok(entries)
}

/// List backup entries across all device subdirectories under `backup_dir`.
///
/// # Errors
/// Returns [`StorageError`] on IO failures.
pub fn list_all_entries(backup_dir: &Path) -> Result<Vec<BackupEntry>, StorageError> {
    if !backup_dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let read = std::fs::read_dir(backup_dir).map_err(|e| io_err(backup_dir, e))?;
    for entry in read {
        let entry = entry.map_err(|e| io_err(backup_dir, e))?;
        if !entry
            .file_type()
            .map_err(|e| io_err(&entry.path(), e))?
            .is_dir()
        {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|s| StorageError::InvalidFilename(s.to_string_lossy().into_owned()))?;
        out.extend(list_entries_for_device(backup_dir, &name)?);
    }
    Ok(out)
}

fn parse_timestamp_from_stem(stem: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(stem, "%Y-%m-%d_%H%M%S")
        .ok()
        .map(|n| DateTime::<Utc>::from_naive_utc_and_offset(n, Utc))
}

/// Apply retention to a device's directory.
///
/// Deletes files older than `retention_days`, but always keeps at least
/// `min_copies` of the newest backups regardless of age. Returns the number of
/// files removed.
///
/// # Errors
/// Returns [`StorageError`] on IO failures.
pub fn apply_retention(
    backup_dir: &Path,
    device_name: &str,
    retention_days: u32,
    min_copies: u32,
) -> Result<usize, StorageError> {
    let entries = list_entries_for_device(backup_dir, device_name)?;
    decide_and_delete(entries, retention_days, min_copies, Utc::now())
}

fn decide_and_delete(
    mut entries: Vec<BackupEntry>,
    retention_days: u32,
    min_copies: u32,
    now: DateTime<Utc>,
) -> Result<usize, StorageError> {
    // newest first
    entries.sort_by_key(|e| std::cmp::Reverse(e.created_at));

    let cutoff = now - chrono::Duration::days(i64::from(retention_days));
    let mut removed = 0_usize;
    for (idx, entry) in entries.iter().enumerate() {
        if (idx as u32) < min_copies {
            continue;
        }
        if entry.created_at < cutoff {
            let conf = &entry.path;
            let sidecar = conf.with_extension("json");
            std::fs::remove_file(conf).map_err(|e| io_err(conf, e))?;
            if sidecar.exists() {
                std::fs::remove_file(&sidecar).map_err(|e| io_err(&sidecar, e))?;
            }
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn art(content: &[u8], at: DateTime<Utc>) -> BackupArtifact {
        BackupArtifact {
            content: content.to_vec(),
            hostname: "fgt".into(),
            firmware_version: Some("v7.4.4".into()),
            serial: Some("FGT123".into()),
            fetched_at: at,
        }
    }

    #[test]
    fn sha256_hex_is_stable() {
        let h = sha256_hex(b"hello");
        assert_eq!(
            h,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn save_and_skip_when_unchanged() {
        let dir = TempDir::new().unwrap();
        let now = Utc::now();
        let a = art(b"config x\n", now);
        let first = save_backup(dir.path(), "fgt-a", "api", &a).unwrap();
        assert!(first.changed);
        assert!(first.path.exists());
        assert!(first.path.with_extension("json").exists());

        // Same content, slightly later — should be skipped.
        let b = art(b"config x\n", now + chrono::Duration::seconds(5));
        let second = save_backup(dir.path(), "fgt-a", "api", &b).unwrap();
        assert!(!second.changed);
        assert_eq!(first.sha256, second.sha256);
    }

    #[test]
    fn save_when_changed_creates_new_file() {
        let dir = TempDir::new().unwrap();
        let now = Utc::now();
        let a = art(b"v1\n", now);
        save_backup(dir.path(), "fgt-a", "api", &a).unwrap();

        let b = art(b"v2 different\n", now + chrono::Duration::seconds(60));
        let second = save_backup(dir.path(), "fgt-a", "api", &b).unwrap();
        assert!(second.changed);

        let entries = list_entries_for_device(dir.path(), "fgt-a").unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn retention_keeps_min_copies_even_if_old() {
        let dir = TempDir::new().unwrap();
        let device_dir = dir.path().join("fgt-a");
        fs::create_dir_all(&device_dir).unwrap();

        // Create 10 entries, all 200 days old.
        let mut entries = Vec::new();
        let now = Utc::now();
        for i in 0..10 {
            let ts = now - chrono::Duration::days(200) - chrono::Duration::seconds(i);
            let stem = ts.format("%Y-%m-%d_%H%M%S").to_string();
            let path = device_dir.join(format!("{stem}.conf"));
            fs::write(&path, format!("body-{i}")).unwrap();
            entries.push(BackupEntry {
                device: "fgt-a".into(),
                path,
                size_bytes: 6,
                created_at: ts,
                sha256: "abc".into(),
            });
        }
        let removed = decide_and_delete(entries, 90, 7, now).unwrap();
        // 10 entries, all expired, min 7 kept => 3 removed
        assert_eq!(removed, 3);
        let surviving = list_entries_for_device(dir.path(), "fgt-a").unwrap();
        assert_eq!(surviving.len(), 7);
    }

    #[test]
    fn retention_keeps_recent_even_above_min() {
        let dir = TempDir::new().unwrap();
        let device_dir = dir.path().join("fgt-a");
        fs::create_dir_all(&device_dir).unwrap();

        let now = Utc::now();
        let mut entries = Vec::new();
        for i in 0..20 {
            let ts = now - chrono::Duration::days(i);
            let stem = ts.format("%Y-%m-%d_%H%M%S").to_string();
            let path = device_dir.join(format!("{stem}.conf"));
            fs::write(&path, format!("body-{i}")).unwrap();
            entries.push(BackupEntry {
                device: "fgt-a".into(),
                path,
                size_bytes: 6,
                created_at: ts,
                sha256: "h".into(),
            });
        }
        // retention=90 days, all entries within 19 days => none removed
        let removed = decide_and_delete(entries, 90, 7, now).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn latest_hash_returns_most_recent() {
        let dir = TempDir::new().unwrap();
        let base = Utc::now();
        save_backup(
            dir.path(),
            "fgt-a",
            "api",
            &art(b"first", base - chrono::Duration::seconds(100)),
        )
        .unwrap();
        save_backup(dir.path(), "fgt-a", "api", &art(b"second", base)).unwrap();
        let h = latest_hash(dir.path(), "fgt-a").unwrap().unwrap();
        assert_eq!(h, sha256_hex(b"second"));
    }
}
