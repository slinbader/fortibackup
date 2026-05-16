//! Prometheus metrics + minimal `/metrics` HTTP exporter.
//!
//! Disabled by default. Enable by setting `[metrics] listen = "127.0.0.1:9090"`
//! in the config. The exporter only runs under the daemon (`run` subcommand);
//! one-shot subcommands do not bind any port.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::OnceLock;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec, Encoder,
    HistogramVec, IntCounterVec, IntGaugeVec, TextEncoder,
};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

/// Wrapper around the four metrics we expose.
pub struct Metrics {
    pub backup_total: IntCounterVec,
    pub backup_duration: HistogramVec,
    pub backup_bytes: IntGaugeVec,
    pub last_success_ts: IntGaugeVec,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Returns the global metrics registry handle. Lazily initialized on first
/// call. Safe to call from any thread.
pub fn get() -> &'static Metrics {
    METRICS.get_or_init(|| Metrics {
        backup_total: register_int_counter_vec!(
            "fortibackup_backup_total",
            "Total number of backup attempts, partitioned by device and outcome",
            &["device", "status"]
        )
        .expect("register fortibackup_backup_total"),
        backup_duration: register_histogram_vec!(
            "fortibackup_backup_duration_seconds",
            "Duration of each backup attempt in seconds",
            &["device"],
            // Buckets in seconds: tuned for typical FortiGate fetches.
            vec![0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 300.0]
        )
        .expect("register fortibackup_backup_duration_seconds"),
        backup_bytes: register_int_gauge_vec!(
            "fortibackup_backup_bytes",
            "Size in bytes of the most recently fetched configuration",
            &["device"]
        )
        .expect("register fortibackup_backup_bytes"),
        last_success_ts: register_int_gauge_vec!(
            "fortibackup_last_success_timestamp_seconds",
            "Unix timestamp of the last successful backup per device",
            &["device"]
        )
        .expect("register fortibackup_last_success_timestamp_seconds"),
    })
}

/// Update metrics for a completed backup attempt.
pub fn record_outcome(device: &str, status: &str, duration_secs: f64, bytes: Option<u64>) {
    let m = get();
    m.backup_total.with_label_values(&[device, status]).inc();
    m.backup_duration
        .with_label_values(&[device])
        .observe(duration_secs);
    if let Some(b) = bytes {
        m.backup_bytes.with_label_values(&[device]).set(b as i64);
    }
    if status == "success" || status == "no_change" {
        m.last_success_ts
            .with_label_values(&[device])
            .set(chrono::Utc::now().timestamp());
    }
}

/// Spawn the `/metrics` HTTP server. Returns immediately; the server runs
/// for the lifetime of the process.
///
/// # Errors
/// Returns an error string if the listen address cannot be parsed or bound.
pub async fn serve(listen: &str) -> Result<(), String> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| format!("invalid metrics listen address `{listen}`: {e}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind {listen}: {e}"))?;
    // Force registration so /metrics returns the families even before the
    // first backup runs.
    let _ = get();
    info!(listen = %addr, "metrics exporter started");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let io = TokioIo::new(stream);
                    tokio::spawn(async move {
                        let svc = service_fn(handle);
                        if let Err(err) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, svc)
                            .await
                        {
                            warn!(error = %err, "metrics connection error");
                        }
                    });
                }
                Err(err) => {
                    error!(error = %err, "metrics accept error");
                }
            }
        }
    });
    Ok(())
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() != "/metrics" {
        let body = Full::new(Bytes::from_static(b"not found\n"));
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(body)
            .expect("404 response"));
    }
    let encoder = TextEncoder::new();
    let mut buf = Vec::with_capacity(4096);
    if let Err(err) = encoder.encode(&prometheus::gather(), &mut buf) {
        error!(error = %err, "failed to encode metrics");
        let body = Full::new(Bytes::from_static(b"encode error\n"));
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(body)
            .expect("500 response"));
    }
    let body = Full::new(Bytes::from(buf));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", encoder.format_type())
        .body(body)
        .expect("metrics response"))
}
