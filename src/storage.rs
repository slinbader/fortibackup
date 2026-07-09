//! On-disk storage of backup artifacts and retention policy.
//!
//! Layout:
//! ```text
//! {backup_dir}/
//!   {device_name}/
//!     2026-05-16_020000.conf
//!     2026-05-16_020000.json   # sidecar metadata
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::StorageError;
use crate::normalize;
use crate::transport::BackupArtifact;

/// Filename extension used when compression is enabled.
const COMPRESSED_EXT: &str = "conf.gz";
const PLAIN_EXT: &str = "conf";

/// Marker file recording the last *successful* backup for a device. It is a
/// dotfile so it is never picked up by `classify_backup_filename` (and thus
/// never listed or pruned by retention).
const LAST_SUCCESS_FILE: &str = ".last_success";

/// Sidecar metadata stored alongside each `.conf` backup file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupMetadata {
    pub device: String,
    pub hostname: String,
    pub fetched_at: DateTime<Utc>,
    /// Plaintext content size, regardless of on-disk compression.
    pub size_bytes: u64,
    /// SHA-256 of the **normalized** plaintext content (ENC blobs and PEM
    /// private keys replaced with placeholders). This is what `no_change`
    /// detection compares against — FortiOS re-encrypts those blobs on
    /// every fetch with a fresh IV, so the raw bytes always differ.
    pub sha256: String,
    /// SHA-256 of the literal bytes on disk (before any compression).
    /// Useful for integrity audits but never used for dedup.
    #[serde(default)]
    pub raw_sha256: Option<String>,
    pub firmware_version: Option<String>,
    pub serial: Option<String>,
    pub transport: String,
    /// `true` when the `.conf` file is stored gzip-compressed (`.conf.gz`).
    #[serde(default)]
    pub compressed: bool,
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

/// Record the time of a successful backup for a device.
///
/// This is written on *every* successful run — including `no_change` runs
/// where the dedup logic writes no new `.conf` file. The watchdog reads this
/// marker rather than the newest file's timestamp, because under dedup the
/// newest file can be days old even while backups keep succeeding.
///
/// # Errors
/// Returns [`StorageError`] if the device directory cannot be created or the
/// marker cannot be written.
pub fn record_success(
    backup_dir: &Path,
    device_name: &str,
    at: DateTime<Utc>,
) -> Result<(), StorageError> {
    let dir = device_dir(backup_dir, device_name);
    std::fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
    let path = dir.join(LAST_SUCCESS_FILE);
    std::fs::write(&path, at.to_rfc3339()).map_err(|e| io_err(&path, e))
}

/// Read the last successful backup time for a device, if recorded.
///
/// Returns `None` when the marker is absent (a device that has never backed
/// up) or unreadable/corrupt — the watchdog treats `None` as "no baseline yet"
/// and stays quiet rather than alarming on a brand-new device.
#[must_use]
pub fn last_success_at(backup_dir: &Path, device_name: &str) -> Option<DateTime<Utc>> {
    let path = device_dir(backup_dir, device_name).join(LAST_SUCCESS_FILE);
    let raw = std::fs::read_to_string(path).ok()?;
    DateTime::parse_from_rfc3339(raw.trim())
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
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
    compress: bool,
) -> Result<SaveOutcome, StorageError> {
    let dir = device_dir(backup_dir, device_name);
    std::fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;

    // Dedup hash is over the normalized content (ENC blobs / PEM private
    // keys replaced) so that FortiOS re-encrypting on every fetch does not
    // cause a spurious `changed` event.
    let hash = sha256_hex(&normalize::for_hash(&artifact.content));
    let raw_hash = sha256_hex(&artifact.content);

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
    let ext = if compress { COMPRESSED_EXT } else { PLAIN_EXT };
    let conf_path = dir.join(format!("{stem}.{ext}"));
    let meta_path = dir.join(format!("{stem}.json"));

    if compress {
        let bytes = gzip_bytes(&artifact.content)?;
        std::fs::write(&conf_path, &bytes).map_err(|e| io_err(&conf_path, e))?;
    } else {
        std::fs::write(&conf_path, &artifact.content).map_err(|e| io_err(&conf_path, e))?;
    }

    let metadata = BackupMetadata {
        device: device_name.to_owned(),
        hostname: artifact.hostname.clone(),
        fetched_at: artifact.fetched_at,
        size_bytes: artifact.content.len() as u64,
        sha256: hash.clone(),
        raw_sha256: Some(raw_hash),
        firmware_version: artifact.firmware_version.clone(),
        serial: artifact.serial.clone(),
        transport: transport_label.to_owned(),
        compressed: compress,
    };
    let meta_json = serde_json::to_vec_pretty(&metadata)?;
    std::fs::write(&meta_path, meta_json).map_err(|e| io_err(&meta_path, e))?;

    Ok(SaveOutcome {
        changed: true,
        path: conf_path,
        sha256: hash,
    })
}

fn gzip_bytes(content: &[u8]) -> Result<Vec<u8>, StorageError> {
    let mut enc = GzEncoder::new(
        Vec::with_capacity(content.len() / 4),
        Compression::default(),
    );
    enc.write_all(content).map_err(|e| StorageError::Io {
        path: PathBuf::from("<gzip>"),
        source: e,
    })?;
    enc.finish().map_err(|e| StorageError::Io {
        path: PathBuf::from("<gzip>"),
        source: e,
    })
}

/// Path is recognized as a stored backup if its extension is `.conf` or
/// `.conf.gz`. Returns `Some((stem, compressed))` or `None`.
fn classify_backup_filename(path: &Path) -> Option<(String, bool)> {
    let name = path.file_name()?.to_str()?;
    if let Some(stem) = name.strip_suffix(".conf.gz") {
        Some((stem.to_owned(), true))
    } else {
        name.strip_suffix(".conf").map(|s| (s.to_owned(), false))
    }
}

fn sidecar_path_for(backup_path: &Path) -> PathBuf {
    let parent = backup_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = classify_backup_filename(backup_path).map_or_else(
        || {
            backup_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("backup")
                .to_owned()
        },
        |(s, _)| s,
    );
    parent.join(format!("{stem}.json"))
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
        let Some((stem, compressed)) = classify_backup_filename(&path) else {
            continue;
        };
        let created_at = parse_timestamp_from_stem(&stem)
            .ok_or_else(|| StorageError::InvalidFilename(stem.clone()))?;
        let size = path.metadata().map_err(|e| io_err(&path, e))?.len();
        let sidecar = sidecar_path_for(&path);
        let sha256 = if sidecar.exists() {
            let raw = std::fs::read(&sidecar).map_err(|e| io_err(&sidecar, e))?;
            let meta: BackupMetadata = serde_json::from_slice(&raw)?;
            meta.sha256
        } else if compressed {
            // Without a sidecar we cannot decompress and re-normalize cheaply;
            // fall back to the raw compressed bytes. Only hit when sidecars
            // were manually deleted.
            let raw = std::fs::read(&path).map_err(|e| io_err(&path, e))?;
            sha256_hex(&raw)
        } else {
            // Re-derive the dedup hash using the same normalization as on
            // write, so sidecar-less directories still dedup correctly.
            let raw = std::fs::read(&path).map_err(|e| io_err(&path, e))?;
            sha256_hex(&normalize::for_hash(&raw))
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
    let victims = pick_victims(entries, retention_days, min_copies, Utc::now());
    delete_victims(&victims)
}

/// Like [`apply_retention`] but only computes what *would* be deleted.
///
/// # Errors
/// Returns [`StorageError`] on IO failures while reading the directory.
pub fn plan_retention(
    backup_dir: &Path,
    device_name: &str,
    retention_days: u32,
    min_copies: u32,
) -> Result<Vec<BackupEntry>, StorageError> {
    let entries = list_entries_for_device(backup_dir, device_name)?;
    Ok(pick_victims(
        entries,
        retention_days,
        min_copies,
        Utc::now(),
    ))
}

fn pick_victims(
    mut entries: Vec<BackupEntry>,
    retention_days: u32,
    min_copies: u32,
    now: DateTime<Utc>,
) -> Vec<BackupEntry> {
    // newest first
    entries.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    let cutoff = now - chrono::Duration::days(i64::from(retention_days));
    entries
        .into_iter()
        .enumerate()
        .filter_map(|(idx, e)| {
            if (idx as u32) < min_copies {
                None
            } else if e.created_at < cutoff {
                Some(e)
            } else {
                None
            }
        })
        .collect()
}

fn delete_victims(victims: &[BackupEntry]) -> Result<usize, StorageError> {
    for entry in victims {
        let conf = &entry.path;
        let sidecar = sidecar_path_for(conf);
        std::fs::remove_file(conf).map_err(|e| io_err(conf, e))?;
        if sidecar.exists() {
            std::fs::remove_file(&sidecar).map_err(|e| io_err(&sidecar, e))?;
        }
    }
    Ok(victims.len())
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
        let first = save_backup(dir.path(), "fgt-a", "api", &a, false).unwrap();
        assert!(first.changed);
        assert!(first.path.exists());
        assert!(first.path.with_extension("json").exists());

        // Same content, slightly later — should be skipped.
        let b = art(b"config x\n", now + chrono::Duration::seconds(5));
        let second = save_backup(dir.path(), "fgt-a", "api", &b, false).unwrap();
        assert!(!second.changed);
        assert_eq!(first.sha256, second.sha256);
    }

    #[test]
    fn save_when_changed_creates_new_file() {
        let dir = TempDir::new().unwrap();
        let now = Utc::now();
        let a = art(b"v1\n", now);
        save_backup(dir.path(), "fgt-a", "api", &a, false).unwrap();

        let b = art(b"v2 different\n", now + chrono::Duration::seconds(60));
        let second = save_backup(dir.path(), "fgt-a", "api", &b, false).unwrap();
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
        let victims = pick_victims(entries, 90, 7, now);
        assert_eq!(victims.len(), 3);
        let removed = delete_victims(&victims).unwrap();
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
        let victims = pick_victims(entries, 90, 7, now);
        assert!(victims.is_empty());
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
            false,
        )
        .unwrap();
        save_backup(dir.path(), "fgt-a", "api", &art(b"second", base), false).unwrap();
        let h = latest_hash(dir.path(), "fgt-a").unwrap().unwrap();
        // latest_hash now returns the dedup-normalized hash, not the raw one.
        assert_eq!(h, sha256_hex(&normalize::for_hash(b"second")));
    }

    #[test]
    fn last_success_marker_round_trips() {
        let dir = TempDir::new().unwrap();
        assert!(last_success_at(dir.path(), "fgt-a").is_none());

        let at = DateTime::parse_from_rfc3339("2026-05-28T13:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        record_success(dir.path(), "fgt-a", at).unwrap();
        assert_eq!(last_success_at(dir.path(), "fgt-a"), Some(at));
    }

    #[test]
    fn last_success_marker_is_not_listed_as_backup() {
        let dir = TempDir::new().unwrap();
        let now = Utc::now();
        save_backup(dir.path(), "fgt-a", "api", &art(b"config\n", now), false).unwrap();
        record_success(dir.path(), "fgt-a", now).unwrap();

        // The dotfile marker must not appear among backup entries.
        let entries = list_entries_for_device(dir.path(), "fgt-a").unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].path.to_string_lossy().ends_with(".conf"));
    }

    #[test]
    fn compressed_save_writes_gz_file_and_keeps_plaintext_hash() {
        use flate2::read::GzDecoder;
        use std::io::Read as _;

        let dir = TempDir::new().unwrap();
        let now = Utc::now();
        // ~5 KB of repetitive text, gzip should be much smaller.
        let body: Vec<u8> = std::iter::repeat_n(b"config-system global\n", 256)
            .flatten()
            .copied()
            .collect();
        let plaintext_hash = sha256_hex(&body);

        let outcome = save_backup(dir.path(), "fgt-a", "api", &art(&body, now), true).unwrap();
        assert!(outcome.changed);
        assert!(outcome.path.to_string_lossy().ends_with(".conf.gz"));

        // Stored file is smaller than the original.
        let on_disk = std::fs::metadata(&outcome.path).unwrap().len();
        assert!(
            (on_disk as usize) < body.len(),
            "compressed file should shrink"
        );

        // Hash in outcome and sidecar must reflect the plaintext.
        assert_eq!(outcome.sha256, plaintext_hash);
        let sidecar = sidecar_path_for(&outcome.path);
        let meta: BackupMetadata =
            serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert_eq!(meta.sha256, plaintext_hash);
        assert_eq!(meta.size_bytes, body.len() as u64);
        assert!(meta.compressed);

        // Round-trip through gunzip recovers original bytes.
        let raw = std::fs::read(&outcome.path).unwrap();
        let mut dec = GzDecoder::new(&raw[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, body);

        // Second run with identical content is detected as no_change even
        // though gzip output is not deterministic byte-for-byte.
        let again = save_backup(
            dir.path(),
            "fgt-a",
            "api",
            &art(&body, now + chrono::Duration::seconds(60)),
            true,
        )
        .unwrap();
        assert!(!again.changed);
    }
}
