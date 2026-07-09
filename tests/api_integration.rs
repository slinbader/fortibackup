//! Integration test exercising `ApiTransport` against a mock HTTP server.
//!
//! The unit test inside `src/transport/api.rs` covers the happy path against
//! the FortiGate `monitor` endpoints. This integration test focuses on the
//! end-to-end shape: a transport call returns a `BackupArtifact` with the
//! expected metadata, and authentication failures bubble up as
//! `TransportError::Auth`.

use fortibackup::config::{Device, TransportMethod, Vendor};
use fortibackup::transport::api::ApiTransport;
use fortibackup::transport::BackupTransport;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_device(token_env: &str) -> Device {
    Device {
        name: "it-fgt".into(),
        host: "127.0.0.1".into(),
        port: 443,
        method: TransportMethod::Api,
        vendor: Vendor::Fortigate,
        api_token_env: Some(token_env.into()),
        verify_tls: false,
        ssh_username: None,
        ssh_key_path: None,
        ssh_password_env: None,
        vdom: None,
        schedule: "0 0 2 * * *".into(),
        timeout_secs: 5,
    }
}

#[tokio::test]
async fn end_to_end_happy_path() {
    std::env::set_var("FGT_IT_TOKEN_OK", "tok-ok");
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/monitor/system/config/backup"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(b"#config-version=FGT60E-7.4.4\nend\n".to_vec()),
        )
        .mount(&server)
        .await;

    let status_body = serde_json::json!({
        "results": {
            "hostname": "fgt-it",
            "serial": "FGT-IT-0001",
            "version": "v7.4.4"
        }
    });
    Mock::given(method("GET"))
        .and(path("/api/v2/monitor/system/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(status_body))
        .mount(&server)
        .await;

    let transport = ApiTransport::with_base_url(server.uri());
    let device = make_device("FGT_IT_TOKEN_OK");

    let artifact = transport.fetch_config(&device).await.expect("fetch");
    assert!(!artifact.content.is_empty());
    assert_eq!(artifact.hostname, "fgt-it");
    assert_eq!(artifact.firmware_version.as_deref(), Some("v7.4.4"));
}

#[tokio::test]
async fn forbidden_token_surfaces_auth_error() {
    std::env::set_var("FGT_IT_TOKEN_BAD", "tok-bad");
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/monitor/system/config/backup"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let transport = ApiTransport::with_base_url(server.uri());
    let device = make_device("FGT_IT_TOKEN_BAD");
    let err = transport.fetch_config(&device).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("authentication failed"),
        "unexpected error: {msg}"
    );
}
