//! REST API transport for FortiGate.
//!
//! Uses the documented monitor endpoints:
//! - `GET /api/v2/monitor/system/config/backup?scope=global` — full config
//! - `GET /api/v2/monitor/system/status` — hostname / serial / firmware
//!
//! Authentication is via a Bearer token issued to a REST API administrator.
//! TLS verification is optional — most FortiGates ship with a self-signed cert.

use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use reqwest::Client;
use serde::Deserialize;

use crate::config::{Device, TransportMethod};
use crate::error::ConfigError;
use crate::error::TransportError;
use crate::transport::{retry_with_backoff, BackupArtifact, BackupTransport};

/// REST API transport.
#[derive(Debug, Default, Clone)]
pub struct ApiTransport {
    /// Optional base URL override (used by tests with wiremock).
    base_url_override: Option<String>,
}

impl ApiTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a transport that targets an arbitrary base URL. Useful for tests.
    #[must_use]
    pub fn with_base_url(url: impl Into<String>) -> Self {
        Self {
            base_url_override: Some(url.into()),
        }
    }

    fn base_url(&self, device: &Device) -> String {
        if let Some(ref url) = self.base_url_override {
            return url.trim_end_matches('/').to_owned();
        }
        format!("https://{}:{}", device.host, device.port)
    }

    fn build_client(device: &Device) -> Result<Client, TransportError> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(device.timeout_secs))
            .user_agent(concat!("fortibackup/", env!("CARGO_PKG_VERSION")));
        if !device.verify_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        builder.build().map_err(TransportError::Http)
    }

    fn token_for(device: &Device) -> Result<String, TransportError> {
        let env_name = device.api_token_env.as_deref().ok_or_else(|| {
            TransportError::InvalidResponse(format!(
                "device `{}` has no api_token_env",
                device.name
            ))
        })?;
        std::env::var(env_name)
            .map_err(|_| TransportError::from(ConfigError::MissingEnv(env_name.to_owned())))
    }
}

impl From<ConfigError> for TransportError {
    fn from(value: ConfigError) -> Self {
        TransportError::InvalidResponse(value.to_string())
    }
}

#[async_trait]
impl BackupTransport for ApiTransport {
    async fn fetch_config(&self, device: &Device) -> Result<BackupArtifact, TransportError> {
        if device.method != TransportMethod::Api {
            return Err(TransportError::Unsupported(format!(
                "ApiTransport called with method `{:?}`",
                device.method
            )));
        }

        let token = Self::token_for(device)?;
        let client = Self::build_client(device)?;
        let base = self.base_url(device);

        let (content, status_meta) = retry_with_backoff(|| async {
            let body = fetch_backup_blob(&client, &base, &token, device).await?;
            let meta = fetch_status(&client, &base, &token, device).await.ok();
            Ok::<_, TransportError>((body, meta))
        })
        .await?;

        let (hostname, firmware, serial) = status_meta.map_or_else(
            || (device.name.clone(), None, None),
            |m| (m.hostname, m.firmware_version, m.serial),
        );

        Ok(BackupArtifact {
            content,
            hostname,
            firmware_version: firmware,
            serial,
            fetched_at: Utc::now(),
        })
    }

    async fn check_reachable(&self, device: &Device) -> Result<(), TransportError> {
        let token = Self::token_for(device)?;
        let client = Self::build_client(device)?;
        let base = self.base_url(device);
        // status endpoint is cheap
        let _ = fetch_status(&client, &base, &token, device).await?;
        Ok(())
    }
}

async fn fetch_backup_blob(
    client: &Client,
    base: &str,
    token: &str,
    device: &Device,
) -> Result<Vec<u8>, TransportError> {
    let url = format!("{base}/api/v2/monitor/system/config/backup?scope=global");
    let resp = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(ACCEPT, "application/octet-stream")
        .send()
        .await
        .map_err(|e| classify_reqwest_error(e, device))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(TransportError::Auth {
            device: device.name.clone(),
        });
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(TransportError::BadStatus {
            device: device.name.clone(),
            status: status.as_u16(),
            body: truncate(&body, 512),
        });
    }
    let bytes = resp.bytes().await.map_err(TransportError::Http)?;
    if bytes.is_empty() {
        return Err(TransportError::InvalidResponse(
            "empty backup body".to_owned(),
        ));
    }
    Ok(bytes.to_vec())
}

#[derive(Debug, Deserialize)]
struct StatusMeta {
    hostname: String,
    firmware_version: Option<String>,
    serial: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StatusResponse {
    results: StatusResults,
}

#[derive(Debug, Deserialize)]
struct StatusResults {
    hostname: Option<String>,
    serial: Option<String>,
    version: Option<String>,
}

async fn fetch_status(
    client: &Client,
    base: &str,
    token: &str,
    device: &Device,
) -> Result<StatusMeta, TransportError> {
    let url = format!("{base}/api/v2/monitor/system/status");
    let resp = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| classify_reqwest_error(e, device))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(TransportError::BadStatus {
            device: device.name.clone(),
            status: status.as_u16(),
            body: truncate(&body, 512),
        });
    }
    let parsed: StatusResponse = resp.json().await.map_err(TransportError::Http)?;
    Ok(StatusMeta {
        hostname: parsed
            .results
            .hostname
            .unwrap_or_else(|| device.name.clone()),
        firmware_version: parsed.results.version,
        serial: parsed.results.serial,
    })
}

fn classify_reqwest_error(err: reqwest::Error, device: &Device) -> TransportError {
    if err.is_timeout() {
        TransportError::Timeout {
            secs: device.timeout_secs,
        }
    } else {
        TransportError::Http(err)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportMethod;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_device(base_port: u16) -> Device {
        Device {
            name: "test-fgt".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: base_port,
            method: TransportMethod::Api,
            api_token_env: Some("FGT_TEST_TOKEN".to_owned()),
            verify_tls: false,
            ssh_username: None,
            ssh_key_path: None,
            ssh_password_env: None,
            schedule: "0 0 2 * * *".to_owned(),
            timeout_secs: 5,
        }
    }

    #[tokio::test]
    async fn api_transport_fetches_backup_and_status() {
        // SAFETY: tests are single-threaded inside this binary; env mutation is fine.
        std::env::set_var("FGT_TEST_TOKEN", "abc123");
        let server = MockServer::start().await;
        let backup_body = b"config-system global\nset hostname fgt-x\nend\n";

        Mock::given(method("GET"))
            .and(path("/api/v2/monitor/system/config/backup"))
            .and(query_param("scope", "global"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(backup_body.as_slice()))
            .mount(&server)
            .await;

        let status_body = serde_json::json!({
            "results": {
                "hostname": "fgt-x",
                "serial": "FGT60E1234567890",
                "version": "v7.4.4"
            }
        });
        Mock::given(method("GET"))
            .and(path("/api/v2/monitor/system/status"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(status_body))
            .mount(&server)
            .await;

        let transport = ApiTransport::with_base_url(server.uri());
        let device = test_device(443);
        let artifact = transport.fetch_config(&device).await.expect("fetch");

        assert_eq!(artifact.content, backup_body);
        assert_eq!(artifact.hostname, "fgt-x");
        assert_eq!(artifact.serial.as_deref(), Some("FGT60E1234567890"));
        assert_eq!(artifact.firmware_version.as_deref(), Some("v7.4.4"));
    }

    #[tokio::test]
    async fn api_transport_returns_auth_error_on_401() {
        std::env::set_var("FGT_TEST_TOKEN", "abc123");
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/monitor/system/config/backup"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let transport = ApiTransport::with_base_url(server.uri());
        let device = test_device(443);
        let err = transport.fetch_config(&device).await.unwrap_err();
        assert!(matches!(err, TransportError::Auth { .. }));
    }
}
