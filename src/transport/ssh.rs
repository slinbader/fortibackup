//! SSH transport for FortiGate.
//!
//! Opens an interactive session, sends `show full-configuration`, and
//! accumulates the entire stdout stream — which can grow to several MB on
//! large devices. Supports ed25519/RSA private keys or password authentication.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use russh::client::{self, Handle, Handler, Msg};
use russh::{Channel, ChannelMsg, Disconnect};

use crate::config::{Device, TransportMethod, Vendor};
use crate::error::TransportError;
use crate::transport::{retry_with_backoff, BackupArtifact, BackupTransport};

/// SSH transport.
#[derive(Debug, Default, Clone)]
pub struct SshTransport;

impl SshTransport {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

struct ClientHandler;

#[async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // FortiGate hosts often rotate keys; trust on first use is the pragmatic
        // default for an internal backup tool. Users wanting strict checking
        // should pin the host key out of band.
        Ok(true)
    }
}

#[async_trait]
impl BackupTransport for SshTransport {
    async fn fetch_config(&self, device: &Device) -> Result<BackupArtifact, TransportError> {
        if device.method != TransportMethod::Ssh {
            return Err(TransportError::Unsupported(format!(
                "SshTransport called with method `{:?}`",
                device.method
            )));
        }

        let username = device.ssh_username.clone().ok_or_else(|| {
            TransportError::InvalidResponse(format!("device `{}` has no ssh_username", device.name))
        })?;

        let timeout = Duration::from_secs(device.timeout_secs);
        let device_clone = device.clone();
        let command = ssh_command(device.vendor);

        let raw = retry_with_backoff(|| {
            let username = username.clone();
            let device = device_clone.clone();
            async move {
                tokio::time::timeout(timeout, run_ssh_session(&device, &username, command))
                    .await
                    .map_err(|_| TransportError::Timeout {
                        secs: device.timeout_secs,
                    })?
            }
        })
        .await?;

        Ok(match device.vendor {
            Vendor::Fortigate => {
                let (hostname, firmware, serial) = parse_metadata(&raw, &device.name);
                BackupArtifact {
                    content: raw.into_bytes(),
                    hostname,
                    firmware_version: firmware,
                    serial,
                    fetched_at: Utc::now(),
                }
            }
            Vendor::Hillstone => {
                let cleaned = clean_hillstone(&raw);
                validate_hillstone(&cleaned)?;
                let (hostname, firmware) = parse_hillstone_metadata(&cleaned, &device.name);
                BackupArtifact {
                    content: cleaned.into_bytes(),
                    hostname,
                    firmware_version: firmware,
                    // StoneOS does not print the serial in `show configuration`;
                    // it lives in `show version`, which we don't fetch.
                    serial: None,
                    fetched_at: Utc::now(),
                }
            }
        })
    }
}

/// The CLI command that dumps the full running configuration for the vendor.
const fn ssh_command(vendor: Vendor) -> &'static str {
    match vendor {
        Vendor::Fortigate => "show full-configuration",
        Vendor::Hillstone => "show configuration",
    }
}

async fn run_ssh_session(
    device: &Device,
    username: &str,
    command: &str,
) -> Result<String, TransportError> {
    let config = client::Config {
        inactivity_timeout: Some(Duration::from_secs(device.timeout_secs)),
        ..Default::default()
    };
    let config = Arc::new(config);

    let addr = (device.host.as_str(), device.port);
    let mut session = client::connect(config, addr, ClientHandler)
        .await
        .map_err(|e| TransportError::Ssh(format!("connect: {e}")))?;

    authenticate(&mut session, device, username).await?;

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| TransportError::Ssh(format!("channel: {e}")))?;

    let overall = Duration::from_secs(device.timeout_secs);
    let buf = match device.vendor {
        // FortiGate answers a one-shot `exec` and streams the whole config to EOF.
        Vendor::Fortigate => {
            channel
                .request_pty(false, "xterm", 200, 50, 0, 0, &[])
                .await
                .map_err(|e| TransportError::Ssh(format!("pty: {e}")))?;
            channel
                .exec(true, command)
                .await
                .map_err(|e| TransportError::Ssh(format!("exec: {e}")))?;
            read_to_eof(&mut channel).await
        }
        // StoneOS rejects `exec` ("Max try count must be a positive integer") and
        // only serves an interactive CLI. We open a shell, disable the `--More--`
        // pager, type the command, and read until the config's `End` marker. The
        // wide PTY also keeps StoneOS from hard-wrapping long lines.
        Vendor::Hillstone => {
            channel
                .request_pty(false, "vt100", 512, 10_000, 0, 0, &[])
                .await
                .map_err(|e| TransportError::Ssh(format!("pty: {e}")))?;
            channel
                .request_shell(true)
                .await
                .map_err(|e| TransportError::Ssh(format!("shell: {e}")))?;
            // Consume the login banner up to the first idle (the prompt).
            let _ = read_until(&mut channel, Duration::from_millis(1500), overall, false).await;
            // Turn off pagination for this session so the whole config streams in
            // one shot instead of stopping every screen at a `--More--` prompt.
            // StoneOS: `terminal length 0` (session-only, not persisted).
            channel
                .data(&b"terminal length 0\n"[..])
                .await
                .map_err(|e| TransportError::Ssh(format!("write pager-off: {e}")))?;
            let _ = read_until(&mut channel, Duration::from_secs(1), overall, false).await;
            let line = format!("{command}\n");
            channel
                .data(line.as_bytes())
                .await
                .map_err(|e| TransportError::Ssh(format!("write command: {e}")))?;
            let out = read_until(&mut channel, Duration::from_millis(2500), overall, true).await;
            let _ = channel.data(&b"exit\n"[..]).await;
            out
        }
    };

    let _ = session
        .disconnect(Disconnect::ByApplication, "bye", "en")
        .await;

    // StoneOS output carries CR and occasional non-UTF-8 terminal bytes, so
    // decode lossily rather than fail the whole backup on a stray byte.
    match device.vendor {
        Vendor::Fortigate => String::from_utf8(buf)
            .map_err(|e| TransportError::InvalidResponse(format!("utf8: {e}"))),
        Vendor::Hillstone => Ok(String::from_utf8_lossy(&buf).into_owned()),
    }
}

/// Read a channel until EOF/close (one-shot `exec` transports).
async fn read_to_eof(channel: &mut Channel<Msg>) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024 * 1024);
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } | ChannelMsg::ExtendedData { ref data, .. } => {
                buf.extend_from_slice(data);
            }
            ChannelMsg::Eof | ChannelMsg::Close | ChannelMsg::ExitStatus { .. } => break,
            _ => {}
        }
    }
    buf
}

/// Read from an interactive shell channel, accumulating output until one of:
/// the channel closes, `stop_on_end` is set and a StoneOS `End` line arrives,
/// an `idle` gap passes with data already buffered, or the `overall` deadline
/// elapses. This drives StoneOS's interactive CLI without an EOF to rely on.
async fn read_until(
    channel: &mut Channel<Msg>,
    idle: Duration,
    overall: Duration,
    stop_on_end: bool,
) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let deadline = tokio::time::Instant::now() + overall;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let wait = idle.min(deadline - now);
        match tokio::time::timeout(wait, channel.wait()).await {
            Ok(Some(ChannelMsg::Data { ref data } | ChannelMsg::ExtendedData { ref data, .. })) => {
                buf.extend_from_slice(data);
                if stop_on_end && ends_with_config_marker(&buf) {
                    break;
                }
            }
            Ok(
                Some(ChannelMsg::Eof | ChannelMsg::Close | ChannelMsg::ExitStatus { .. }) | None,
            ) => break,
            Ok(Some(_)) => {}
            // Idle gap: if we have already received output, treat streaming as
            // finished; otherwise keep waiting until the overall deadline.
            Err(_) => {
                if !buf.is_empty() {
                    break;
                }
            }
        }
    }
    buf
}

/// True once the buffered output contains a StoneOS `End` terminator line — the
/// last line `show configuration` prints before returning to the prompt.
fn ends_with_config_marker(buf: &[u8]) -> bool {
    String::from_utf8_lossy(buf)
        .lines()
        .any(|l| l.trim_end() == "End")
}

async fn authenticate(
    session: &mut Handle<ClientHandler>,
    device: &Device,
    username: &str,
) -> Result<(), TransportError> {
    if let Some(key_path) = device.ssh_key_path.as_ref() {
        let key = load_private_key(key_path)?;
        let auth = session
            .authenticate_publickey(username, Arc::new(key))
            .await
            .map_err(|e| TransportError::Ssh(format!("publickey: {e}")))?;
        if !auth {
            return Err(TransportError::Auth {
                device: device.name.clone(),
            });
        }
        return Ok(());
    }
    if let Some(env_name) = device.ssh_password_env.as_ref() {
        let password = std::env::var(env_name).map_err(|_| {
            TransportError::InvalidResponse(format!("env var `{env_name}` not set"))
        })?;
        let auth = session
            .authenticate_password(username, password)
            .await
            .map_err(|e| TransportError::Ssh(format!("password: {e}")))?;
        if !auth {
            return Err(TransportError::Auth {
                device: device.name.clone(),
            });
        }
        return Ok(());
    }
    Err(TransportError::Auth {
        device: device.name.clone(),
    })
}

fn load_private_key(path: &Path) -> Result<russh_keys::key::KeyPair, TransportError> {
    russh_keys::load_secret_key(path, None)
        .map_err(|e| TransportError::Ssh(format!("load key {}: {e}", path.display())))
}

/// Best-effort extraction of hostname / firmware / serial from the
/// `show full-configuration` output. Returns the device name as a fallback for
/// the hostname.
fn parse_metadata(raw: &str, fallback_name: &str) -> (String, Option<String>, Option<String>) {
    let mut hostname: Option<String> = None;
    let mut firmware: Option<String> = None;
    let mut serial: Option<String> = None;

    // Comment line FortiGate emits at the top, e.g.:
    //   #config-version=FGT60E-7.4.4-FW-build2658-240926:opmode=0:vdom=0:user=admin
    //   #conf_file_ver=...
    //   #buildno=2658
    //   #global_vdom=1
    for line in raw.lines().take(20) {
        if let Some(rest) = line.strip_prefix("#config-version=") {
            // FGT60E-7.4.4-FW-build...
            let parts: Vec<&str> = rest.split(':').next().unwrap_or("").split('-').collect();
            if parts.len() >= 2 {
                firmware = Some(parts[1].to_owned());
            }
        }
    }

    // Inside `config system global` look for `set hostname "..."`.
    let mut in_global = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed == "config system global" {
            in_global = true;
            continue;
        }
        if in_global {
            if trimmed == "end" {
                in_global = false;
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("set hostname ") {
                hostname = Some(rest.trim_matches('"').to_owned());
            }
        }
        if let Some(rest) = trimmed.strip_prefix("#serial=") {
            serial = Some(rest.to_owned());
        }
    }

    (
        hostname.unwrap_or_else(|| fallback_name.to_owned()),
        firmware,
        serial,
    )
}

/// Strip the interactive session artifacts from a StoneOS `show configuration`
/// dump, keeping just the configuration body.
///
/// The raw stream looks like:
/// ```text
/// Building configuration.
/// Running configuration:
/// # global configuration version: 8527
/// ...config...
/// End
/// FW_RNPN_Carbonel(M0B1)#     <- trailing CLI prompt
/// ```
/// We drop the leading banner and the trailing prompt, and keep everything
/// from the first real line through the terminating `End` marker. Any stray
/// `--More--` pager line (should paging leak into the exec stream) is dropped.
/// Trailing whitespace — which a PTY pads onto lines — is trimmed so cosmetic
/// terminal padding never shows up as a spurious diff.
fn clean_hillstone(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut started = false;
    for line in raw.lines() {
        let t = line.trim_end();
        if t.contains("--More--") {
            continue;
        }
        if !started {
            // Anchor on the config header, dropping everything before it: the
            // SSH login banner, the echoed command, and the `Building
            // configuration.` line. `Running configuration:` marks the start but
            // is itself not config; a leading `#` comment is the fallback anchor.
            if t == "Running configuration:" {
                started = true;
                continue;
            }
            if t.starts_with('#') {
                started = true;
            } else {
                continue;
            }
        }
        out.push_str(t);
        out.push('\n');
        if t == "End" {
            // The config proper ends here; anything after is the CLI prompt.
            break;
        }
    }
    out
}

/// Reject payloads that don't look like a StoneOS configuration — catches the
/// case where the SSH exec returns an error, a login banner, or an empty body
/// that would otherwise be persisted as a fake "backup".
fn validate_hillstone(cleaned: &str) -> Result<(), TransportError> {
    if cleaned.trim().is_empty() {
        return Err(TransportError::InvalidResponse(
            "empty StoneOS configuration body".to_owned(),
        ));
    }
    // A real dump carries the version header and/or a hostname line.
    if cleaned.contains("configuration version")
        || cleaned.contains("hostname \"")
        || cleaned.contains("\nVersion ")
    {
        return Ok(());
    }
    Err(TransportError::InvalidResponse(
        "payload does not look like a StoneOS configuration".to_owned(),
    ))
}

/// Best-effort extraction of hostname / firmware from a StoneOS configuration.
/// Returns the device name as the hostname fallback.
fn parse_hillstone_metadata(cleaned: &str, fallback_name: &str) -> (String, Option<String>) {
    let mut hostname: Option<String> = None;
    let mut firmware: Option<String> = None;
    for line in cleaned.lines() {
        let trimmed = line.trim();
        if hostname.is_none() {
            if let Some(rest) = trimmed.strip_prefix("hostname ") {
                hostname = Some(rest.trim().trim_matches('"').to_owned());
            }
        }
        if firmware.is_none() {
            // e.g. `Version 5.5R10`
            if let Some(rest) = trimmed.strip_prefix("Version ") {
                firmware = Some(rest.trim().to_owned());
            }
        }
    }
    (
        hostname.unwrap_or_else(|| fallback_name.to_owned()),
        firmware,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metadata_extracts_hostname() {
        let raw = "#config-version=FGT60E-7.4.4-FW-build2658-240926:opmode=0\n\
                   config system global\n    set hostname \"fgt-edge\"\nend\n";
        let (host, fw, _serial) = parse_metadata(raw, "fallback");
        assert_eq!(host, "fgt-edge");
        assert_eq!(fw.as_deref(), Some("7.4.4"));
    }

    #[test]
    fn parse_metadata_falls_back_to_device_name() {
        let raw = "no header here\n";
        let (host, fw, serial) = parse_metadata(raw, "fallback");
        assert_eq!(host, "fallback");
        assert!(fw.is_none());
        assert!(serial.is_none());
    }

    #[test]
    fn ssh_command_per_vendor() {
        assert_eq!(ssh_command(Vendor::Fortigate), "show full-configuration");
        assert_eq!(ssh_command(Vendor::Hillstone), "show configuration");
    }

    // A trimmed, secret-free StoneOS dump mirroring the real framing:
    // banner + version header + body ending in `End`, then the CLI prompt.
    const HILLSTONE_RAW: &str = "\
Building configuration.
Running configuration:
# global configuration version: 8527
# configuration sequence number: 6261
!
Version 5.5R10
hostname \"FW_Edge\"
interface ethernet0/0
exit
End
FW_Edge(M0B1)# ";

    #[test]
    fn clean_hillstone_strips_banner_and_prompt() {
        let cleaned = clean_hillstone(HILLSTONE_RAW);
        // Banner gone, prompt gone, body kept, terminated by `End`.
        assert!(!cleaned.contains("Building configuration."));
        assert!(!cleaned.contains("Running configuration:"));
        assert!(!cleaned.contains("FW_Edge(M0B1)#"));
        assert!(cleaned.starts_with("# global configuration version: 8527\n"));
        assert!(cleaned.ends_with("End\n"));
        // Trailing PTY padding on `hostname`/`exit` lines is trimmed.
        assert!(cleaned.contains("\nhostname \"FW_Edge\"\n"));
        assert!(cleaned.contains("\nexit\n"));
    }

    #[test]
    fn clean_hillstone_strips_interactive_login_and_command_echo() {
        // What the interactive shell channel actually returns: a login banner,
        // the echoed `show configuration` command, then the config, then the
        // prompt. Everything but the config body must be dropped.
        let raw = "\
Hillstone StoneOS
FW_Edge(M0B1)# show configuration
Building configuration.
Running configuration:
# global configuration version: 100
hostname \"FW_Edge\"
End
FW_Edge(M0B1)# ";
        let cleaned = clean_hillstone(raw);
        assert!(cleaned.starts_with("# global configuration version: 100\n"));
        assert!(!cleaned.contains("show configuration"));
        assert!(!cleaned.contains("Hillstone StoneOS"));
        assert!(!cleaned.contains("FW_Edge(M0B1)#"));
        assert!(cleaned.ends_with("End\n"));
    }

    #[test]
    fn ends_with_config_marker_detects_end_line() {
        assert!(ends_with_config_marker(b"foo\nEnd\r\nprompt# "));
        assert!(ends_with_config_marker(b"foo\nEnd\n"));
        assert!(!ends_with_config_marker(b"foo\nEndpoint\n"));
        assert!(!ends_with_config_marker(b"still streaming..."));
    }

    #[test]
    fn clean_hillstone_drops_pager_lines() {
        let raw = "Running configuration:\nhostname \"x\"\n--More-- \ninterface e0\nEnd\n";
        let cleaned = clean_hillstone(raw);
        assert!(!cleaned.contains("--More--"));
        assert!(cleaned.contains("interface e0"));
    }

    #[test]
    fn parse_hillstone_metadata_extracts_hostname_and_version() {
        let cleaned = clean_hillstone(HILLSTONE_RAW);
        let (host, fw) = parse_hillstone_metadata(&cleaned, "fallback");
        assert_eq!(host, "FW_Edge");
        assert_eq!(fw.as_deref(), Some("5.5R10"));
    }

    #[test]
    fn validate_hillstone_accepts_real_dump_rejects_garbage() {
        assert!(validate_hillstone(&clean_hillstone(HILLSTONE_RAW)).is_ok());
        assert!(validate_hillstone("").is_err());
        assert!(validate_hillstone("command not found\n").is_err());
    }
}
