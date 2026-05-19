//! Normalize a FortiGate configuration for deduplication hashing.
//!
//! Each fetch from `/api/v2/monitor/system/config/backup` re-encrypts the
//! `ENC` blobs (admin passwords, preshared keys, certificate private keys)
//! and re-emits PEM-wrapped encrypted private keys with a fresh IV. The
//! logical configuration is identical but the raw bytes differ across
//! runs, which would cause `no_change` detection to never fire and disk
//! usage to balloon.
//!
//! This module produces a normalized representation where the noisy blobs
//! are replaced by stable placeholders. The hash used for dedup is the
//! SHA-256 of this normalized output. The original bytes are still
//! persisted on disk untouched — only the hash differs.

/// Build a normalized form of the config suitable for hashing.
///
/// Non-UTF-8 input is returned unchanged so we still get *some* dedup
/// behavior on weird payloads.
#[must_use]
pub fn for_hash(content: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(content) else {
        return content.to_vec();
    };
    let mut out = String::with_capacity(content.len());
    let mut in_pem = false;
    for line in text.lines() {
        if !in_pem && line_starts_pem(line) {
            in_pem = true;
            out.push_str("<PEM-BLOB>\n");
            // The BEGIN line itself may also contain the END marker (single-
            // line key); handle that here to avoid eating the rest of the
            // config.
            if line.contains("-----END") {
                in_pem = false;
            }
            continue;
        }
        if in_pem {
            if line.contains("-----END") {
                in_pem = false;
            }
            continue;
        }
        if let Some(idx) = line.find(" ENC ") {
            // Keep the prefix (which carries the field name) so logical
            // changes elsewhere on the line are still detected.
            out.push_str(&line[..idx]);
            out.push_str(" ENC <BLOB>\n");
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.into_bytes()
}

fn line_starts_pem(line: &str) -> bool {
    // FortiOS wraps private keys inside `set private-key "..."` multi-line
    // strings, so the BEGIN marker is rarely at column 0. We match it
    // anywhere on the line, and only for PRIVATE KEY variants — public
    // CERTIFICATE blocks are byte-stable across runs.
    line.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || line.contains("-----BEGIN RSA PRIVATE KEY-----")
        || line.contains("-----BEGIN PRIVATE KEY-----")
        || line.contains("-----BEGIN EC PRIVATE KEY-----")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_blob_difference_does_not_affect_normalized_output() {
        let a = b"config system\n    set password ENC AAAAAAAA==\nend\n";
        let b = b"config system\n    set password ENC ZZZZZZZZZZZZ==\nend\n";
        assert_eq!(for_hash(a), for_hash(b));
    }

    #[test]
    fn enc_in_multiple_lines() {
        let a = b"set pwd ENC ABC\nset secret ENC XYZ\n";
        let b = b"set pwd ENC 111\nset secret ENC 222\n";
        assert_eq!(for_hash(a), for_hash(b));
    }

    #[test]
    fn pem_block_collapsed_to_placeholder() {
        let raw = b"config foo\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFXX==\n+/abc/+\n-----END ENCRYPTED PRIVATE KEY-----\nend\n";
        let n = String::from_utf8(for_hash(raw)).unwrap();
        assert!(n.contains("<PEM-BLOB>"), "got {n:?}");
        assert!(!n.contains("MIIFXX"));
        assert!(n.contains("end"));
    }

    #[test]
    fn logical_change_is_still_detected() {
        let a = b"config global\n    set hostname \"a\"\n    set password ENC X\nend\n";
        let b = b"config global\n    set hostname \"b\"\n    set password ENC X\nend\n";
        assert_ne!(for_hash(a), for_hash(b));
    }

    #[test]
    fn enc_change_with_logical_change_still_detected() {
        // Logical bits differ + the ENC blob differs — must register as changed.
        let a = b"set hostname \"a\"\nset password ENC AAA\n";
        let b = b"set hostname \"b\"\nset password ENC BBB\n";
        assert_ne!(for_hash(a), for_hash(b));
    }

    #[test]
    fn fortios_style_set_private_key_block() {
        // The form FortiOS exports: BEGIN/END markers are inside a
        // `set private-key "..."` string, not at column 0.
        let a = b"config certificate local\n    edit \"ssl\"\n        set private-key \"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\nBBBB\n-----END ENCRYPTED PRIVATE KEY-----\"\n    next\nend\n";
        let b = b"config certificate local\n    edit \"ssl\"\n        set private-key \"-----BEGIN ENCRYPTED PRIVATE KEY-----\nZZZZ\nYYYY\n-----END ENCRYPTED PRIVATE KEY-----\"\n    next\nend\n";
        let na = String::from_utf8(for_hash(a)).unwrap();
        let nb = String::from_utf8(for_hash(b)).unwrap();
        assert_eq!(na, nb);
        // And surrounding scaffolding survives.
        assert!(na.contains("config certificate local"));
        assert!(na.contains("    next"));
    }

    #[test]
    fn non_utf8_passes_through() {
        let raw: &[u8] = &[0xff, 0xfe, 0xfd];
        assert_eq!(for_hash(raw), raw);
    }
}
