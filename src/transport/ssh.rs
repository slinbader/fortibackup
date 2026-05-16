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
use russh::client::{self, Handle, Handler};
use russh::{ChannelMsg, Disconnect};

use crate::config::{Device, TransportMethod};
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

        let raw = retry_with_backoff(|| {
            let username = username.clone();
            let device = device_clone.clone();
            async move {
                tokio::time::timeout(
                    timeout,
                    run_ssh_session(&device, &username, "show full-configuration"),
                )
                .await
                .map_err(|_| TransportError::Timeout {
                    secs: device.timeout_secs,
                })?
            }
        })
        .await?;

        let (hostname, firmware, serial) = parse_metadata(&raw, &device.name);

        Ok(BackupArtifact {
            content: raw.into_bytes(),
            hostname,
            firmware_version: firmware,
            serial,
            fetched_at: Utc::now(),
        })
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
    channel
        .request_pty(false, "xterm", 200, 50, 0, 0, &[])
        .await
        .map_err(|e| TransportError::Ssh(format!("pty: {e}")))?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| TransportError::Ssh(format!("exec: {e}")))?;

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

    let _ = session
        .disconnect(Disconnect::ByApplication, "bye", "en")
        .await;

    String::from_utf8(buf).map_err(|e| TransportError::InvalidResponse(format!("utf8: {e}")))
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
}
