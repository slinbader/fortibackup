//! Embedded read-mostly Web UI for fortibackup.
//!
//! Only active under the `run` daemon when `[webui] listen = "..."` is set.
//! HTTP Basic Auth on every endpoint; credentials are compared in constant
//! time. Server-side HTML rendering — no JS framework, no SPA, no external
//! assets. The whole UI lives in this file.

use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE, WWW_AUTHENTICATE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::backup;
use crate::config::Config;
use crate::storage;

/// Per-process state shared across all HTTP handlers. Cheap to clone.
struct AppState {
    cfg: Arc<Config>,
    auth_user: String,
    auth_pass: String,
    /// Devices currently being backed up via the web "Run now" button.
    /// Prevents concurrent runs of the same device clashing with the
    /// scheduler or with another browser tab.
    in_flight: Mutex<HashSet<String>>,
}

type SharedState = Arc<AppState>;

/// Spawn the web UI. Returns once the listener is bound; the server runs
/// for the lifetime of the process. Errors are surfaced as strings.
pub async fn serve(cfg: Arc<Config>) -> Result<(), String> {
    let Some(listen) = cfg.webui.listen.clone() else {
        return Ok(());
    };
    let user = cfg
        .webui
        .user
        .clone()
        .ok_or_else(|| "[webui] user is required when listen is set".to_owned())?;
    let env_name = cfg
        .webui
        .password_env
        .clone()
        .ok_or_else(|| "[webui] password_env is required when listen is set".to_owned())?;
    let pass =
        std::env::var(&env_name).map_err(|_| format!("[webui] env var `{env_name}` is not set"))?;
    if pass.is_empty() {
        return Err(format!("[webui] env var `{env_name}` is empty"));
    }

    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| format!("invalid webui listen address `{listen}`: {e}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind {listen}: {e}"))?;

    let user_display = user.clone();
    let state: SharedState = Arc::new(AppState {
        cfg,
        auth_user: user,
        auth_pass: pass,
        in_flight: Mutex::new(HashSet::new()),
    });

    info!(listen = %addr, user = %user_display, "web UI started");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let io = TokioIo::new(stream);
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let svc = service_fn(move |req| {
                            let state = Arc::clone(&state);
                            async move { handle(req, state).await }
                        });
                        if let Err(err) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, svc)
                            .await
                        {
                            warn!(error = %err, "webui connection error");
                        }
                    });
                }
                Err(err) => error!(error = %err, "webui accept error"),
            }
        }
    });
    Ok(())
}

async fn handle(
    req: Request<Incoming>,
    state: SharedState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if !check_auth(&req, &state) {
        return Ok(challenge());
    }
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);

    let result: Result<Response<Full<Bytes>>, Response<Full<Bytes>>> = match (method, path.as_str())
    {
        (Method::GET, "/") => Ok(render_dashboard(&state).await),
        (Method::GET, "/style.css") => Ok(serve_css()),
        (Method::GET, p) if p.starts_with("/device/") => {
            render_device(&state, decode_segment(&p["/device/".len()..]).as_str()).await
        }
        (Method::GET, p) if p.starts_with("/backup/") => {
            serve_backup(&state, &p["/backup/".len()..])
        }
        (Method::GET, p) if p.starts_with("/diff/") => {
            render_diff(&state, &p["/diff/".len()..], query.as_deref())
        }
        (Method::POST, p) if p.starts_with("/run/") => {
            handle_run(&state, decode_segment(&p["/run/".len()..]).as_str()).await
        }
        _ => Err(error_page(StatusCode::NOT_FOUND, "Not found")),
    };
    Ok(result.unwrap_or_else(|e| e))
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

fn check_auth(req: &Request<Incoming>, state: &AppState) -> bool {
    let Some(value) = req.headers().get(AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(b64) = value.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&raw) else {
        return false;
    };
    let Some((user, pass)) = text.split_once(':') else {
        return false;
    };
    let u_eq = user.as_bytes().ct_eq(state.auth_user.as_bytes());
    let p_eq = pass.as_bytes().ct_eq(state.auth_pass.as_bytes());
    (u_eq & p_eq).into()
}

fn challenge() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(WWW_AUTHENTICATE, "Basic realm=\"fortibackup\"")
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(b"authentication required\n")))
        .expect("auth challenge")
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const CSS: &str = r#"
:root { --bg:#0f1419; --fg:#d4d4d4; --muted:#888; --accent:#7aa2f7; --border:#222; --warn:#e0af68; --err:#f7768e; --ok:#9ece6a; }
* { box-sizing: border-box; }
body { font: 14px -apple-system, "Segoe UI", system-ui, sans-serif; background: var(--bg); color: var(--fg); margin: 0; padding: 20px 32px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { font-size: 18px; margin: 0 0 16px; font-weight: 600; }
h2 { font-size: 15px; margin: 24px 0 8px; color: var(--muted); font-weight: 600; }
header { display: flex; justify-content: space-between; align-items: baseline; border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 20px; }
header .version { color: var(--muted); font-size: 12px; }
nav a { margin-right: 12px; }
table { width: 100%; border-collapse: collapse; margin: 0 0 16px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.mono { font-family: ui-monospace, "JetBrains Mono", "Menlo", monospace; font-size: 12px; }
.tag { padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }
.tag.ok    { color: var(--ok);   background: rgba(158,206,106,0.12); }
.tag.warn  { color: var(--warn); background: rgba(224,175,104,0.12); }
.tag.err   { color: var(--err);  background: rgba(247,118,142,0.12); }
.tag.muted { color: var(--muted);background: rgba(136,136,136,0.10); }
form { display: inline; }
button { background: var(--accent); color: #0f1419; border: 0; padding: 6px 14px; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 12px; }
button:hover { filter: brightness(1.1); }
.alert { padding: 12px 16px; border-radius: 4px; margin-bottom: 16px; }
.alert.ok  { background: rgba(158,206,106,0.15); border-left: 3px solid var(--ok); }
.alert.err { background: rgba(247,118,142,0.15); border-left: 3px solid var(--err); }
pre { background: #11161d; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
.diff-body { font-family: ui-monospace, "JetBrains Mono", monospace; font-size: 12px; line-height: 1.4; background: #11161d; padding: 12px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
.diff-add { color: var(--ok); background: rgba(158,206,106,0.08); display: block; }
.diff-del { color: var(--err); background: rgba(247,118,142,0.10); display: block; }
.diff-ctx { color: var(--muted); display: block; }
.diff-sep { color: var(--accent); display: block; padding: 4px 0; opacity: 0.6; }
form.compare { display: flex; align-items: center; gap: 8px; margin: 16px 0; flex-wrap: wrap; }
form.compare label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
form.compare select { background: #11161d; color: var(--fg); border: 1px solid var(--border); border-radius: 4px; padding: 5px 8px; font-size: 12px; font-family: ui-monospace, monospace; }
"#;

fn serve_css() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/css; charset=utf-8")
        .body(Full::new(Bytes::from_static(CSS.as_bytes())))
        .expect("css")
}

fn html_response(body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("html")
}

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{title} — fortibackup</title><link rel="stylesheet" href="/style.css"></head>
<body>
<header><div><a href="/">fortibackup</a> · {title}</div><div class="version">v{ver}</div></header>
{body}
</body></html>"#,
        title = html_escape(title),
        ver = env!("CARGO_PKG_VERSION"),
        body = body
    )
}

#[allow(clippy::unused_async)] // kept symmetric with render_device
async fn render_dashboard(state: &AppState) -> Response<Full<Bytes>> {
    let mut rows = String::new();
    for device in &state.cfg.devices {
        let entries = storage::list_entries_for_device(&state.cfg.global.backup_dir, &device.name)
            .unwrap_or_default();
        let count = entries.len();
        let latest = entries.last();
        let (when, hash_short, size) = match latest {
            Some(e) => (
                e.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
                e.sha256.chars().take(12).collect::<String>(),
                human_size(e.size_bytes),
            ),
            None => ("—".to_owned(), "—".to_owned(), "—".to_owned()),
        };
        let badge = match latest {
            Some(_) => "<span class=\"tag ok\">ok</span>",
            None => "<span class=\"tag muted\">no backup yet</span>",
        };
        let _ = write!(
            rows,
            r#"<tr>
  <td><a href="/device/{name_enc}">{name}</a></td>
  <td>{badge}</td>
  <td>{transport}</td>
  <td>{schedule}</td>
  <td class="num">{count}</td>
  <td>{when}</td>
  <td class="mono">{hash}</td>
  <td class="num">{size}</td>
</tr>"#,
            name_enc = url_escape(&device.name),
            name = html_escape(&device.name),
            badge = badge,
            transport = match device.method {
                crate::config::TransportMethod::Api => "api",
                crate::config::TransportMethod::Ssh => "ssh",
            },
            schedule = html_escape(&device.schedule),
            count = count,
            when = html_escape(&when),
            hash = html_escape(&hash_short),
            size = html_escape(&size),
        );
    }
    let body = format!(
        r#"<h1>Devices</h1>
<table>
<thead><tr>
<th>Name</th><th>Status</th><th>Transport</th><th>Schedule</th><th class="num">Backups</th>
<th>Latest</th><th>Hash</th><th class="num">Size</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
<h2>About</h2>
<p>fortibackup v{ver} · backup dir <span class="mono">{dir}</span></p>"#,
        rows = rows,
        ver = env!("CARGO_PKG_VERSION"),
        dir = html_escape(&state.cfg.global.backup_dir.display().to_string()),
    );
    html_response(page("Dashboard", &body))
}

#[allow(clippy::result_large_err)]
async fn render_device(
    state: &AppState,
    name: &str,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let device = state
        .cfg
        .find_device(name)
        .ok_or_else(|| error_page(StatusCode::NOT_FOUND, &format!("Device `{name}` not found")))?;

    let entries = storage::list_entries_for_device(&state.cfg.global.backup_dir, &device.name)
        .map_err(|e| error_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let mut rows = String::new();
    let total = entries.len();
    for (i, e) in entries.iter().enumerate().rev() {
        let stem = e.path.file_name().and_then(|s| s.to_str()).unwrap_or("?");
        let sidecar_name = match stem
            .strip_suffix(".conf.gz")
            .or_else(|| stem.strip_suffix(".conf"))
        {
            Some(base) => format!("{base}.json"),
            None => format!("{stem}.json"),
        };
        // The oldest backup has no previous one to diff against.
        let diff_link = if i == 0 {
            String::new()
        } else {
            format!(
                r#" · <a href="/diff/{dev_enc}/{file_enc}">diff</a>"#,
                dev_enc = url_escape(&device.name),
                file_enc = url_escape(stem),
            )
        };
        let _ = write!(
            rows,
            r#"<tr>
  <td>{when}</td>
  <td class="num">{size}</td>
  <td class="mono">{hash}</td>
  <td>
    <a href="/backup/{dev_enc}/{file_enc}">conf</a> ·
    <a href="/backup/{dev_enc}/{side_enc}">sidecar</a>{diff_link}
  </td>
</tr>"#,
            when = e.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
            size = human_size(e.size_bytes),
            hash = e.sha256.chars().take(16).collect::<String>(),
            dev_enc = url_escape(&device.name),
            file_enc = url_escape(stem),
            side_enc = url_escape(&sidecar_name),
            diff_link = diff_link,
        );
    }
    let _ = total; // currently unused, kept for symmetry with future "N backups" copy
    if rows.is_empty() {
        rows.push_str(
            r#"<tr><td colspan="4" style="color: var(--muted);">No backups yet.</td></tr>"#,
        );
    }

    let in_flight = state.in_flight.lock().await.contains(&device.name);
    let run_button = if in_flight {
        "<button disabled>Run now (in flight…)</button>".to_owned()
    } else {
        format!(
            r#"<form method="post" action="/run/{}"><button type="submit">Run now</button></form>"#,
            url_escape(&device.name)
        )
    };

    // Build a "compare arbitrary two backups" selector form when there are
    // at least two backups to compare.
    let compare_form = if entries.len() >= 2 {
        let mut a_opts = String::new();
        let mut b_opts = String::new();
        for (i, e) in entries.iter().enumerate() {
            let name = e.path.file_name().and_then(|s| s.to_str()).unwrap_or("?");
            let label = e.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            let selected_a = if i == 0 { " selected" } else { "" };
            let selected_b = if i == entries.len() - 1 {
                " selected"
            } else {
                ""
            };
            let _ = write!(
                a_opts,
                r#"<option value="{name_enc}"{selected_a}>{label}</option>"#,
                name_enc = html_escape(name),
                selected_a = selected_a,
                label = html_escape(&label),
            );
            let _ = write!(
                b_opts,
                r#"<option value="{name_enc}"{selected_b}>{label}</option>"#,
                name_enc = html_escape(name),
                selected_b = selected_b,
                label = html_escape(&label),
            );
        }
        format!(
            r#"<form method="get" action="/diff/{dev_enc}" class="compare">
  <label>Compare</label>
  <select name="a">{a_opts}</select>
  →
  <select name="b">{b_opts}</select>
  <button type="submit">Diff</button>
</form>"#,
            dev_enc = url_escape(&device.name),
            a_opts = a_opts,
            b_opts = b_opts,
        )
    } else {
        String::new()
    };

    let body = format!(
        r#"<h1>{name}</h1>
<p>
  <span class="tag muted">{transport}</span>
  <span class="mono">{host}:{port}</span> ·
  schedule <span class="mono">{schedule}</span> ·
  timeout {timeout}s
</p>
<p>{run_button}</p>
{compare_form}
<h2>Backups ({count})</h2>
<table>
<thead><tr><th>When</th><th class="num">Size</th><th>Hash</th><th>Files</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
        name = html_escape(&device.name),
        transport = match device.method {
            crate::config::TransportMethod::Api => "api",
            crate::config::TransportMethod::Ssh => "ssh",
        },
        host = html_escape(&device.host),
        port = device.port,
        schedule = html_escape(&device.schedule),
        timeout = device.timeout_secs,
        run_button = run_button,
        compare_form = compare_form,
        count = entries.len(),
        rows = rows,
    );
    Ok(html_response(page(&device.name, &body)))
}

fn error_page(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    let body = page(
        "Error",
        &format!(
            r#"<div class="alert err"><strong>{}</strong> — {}</div><p><a href="/">Back to dashboard</a></p>"#,
            status.as_u16(),
            html_escape(msg)
        ),
    );
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("err page")
}

// ---------------------------------------------------------------------------
// Backup download
// ---------------------------------------------------------------------------

#[allow(clippy::result_large_err)] // Response is the Err on purpose so handle() can unify branches
fn serve_backup(
    state: &AppState,
    rest: &str,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let (dev_seg, file_seg) = rest
        .split_once('/')
        .ok_or_else(|| error_page(StatusCode::BAD_REQUEST, "Expected /backup/<device>/<file>"))?;
    let device = decode_segment(dev_seg);
    let file = decode_segment(file_seg);

    if state.cfg.find_device(&device).is_none() {
        return Err(error_page(
            StatusCode::NOT_FOUND,
            &format!("Device `{device}` not found"),
        ));
    }
    // Refuse paths that would escape the device directory.
    if file.contains('/') || file.contains("..") || file.starts_with('.') {
        return Err(error_page(StatusCode::BAD_REQUEST, "Invalid filename"));
    }
    let path = storage::device_dir(&state.cfg.global.backup_dir, &device).join(&file);
    if !path.starts_with(&state.cfg.global.backup_dir) || !path.exists() {
        return Err(error_page(StatusCode::NOT_FOUND, "Backup not found"));
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| error_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let ct = mime_for(&file);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, ct)
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", sanitize_filename(&file)),
        )
        .body(Full::new(Bytes::from(bytes)))
        .expect("backup download"))
}

fn mime_for(filename: &str) -> &'static str {
    let path = std::path::Path::new(filename);
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext.eq_ignore_ascii_case("json") {
        "application/json"
    } else if ext.eq_ignore_ascii_case("gz") {
        "application/gzip"
    } else {
        "text/plain; charset=utf-8"
    }
}

// ---------------------------------------------------------------------------
// Diff between consecutive backups
// ---------------------------------------------------------------------------

/// Diff endpoint, two modes:
/// - `GET /diff/<device>/<file>` — `<file>` vs the previous chronological
///   backup of the same device (shortcut, what each row links to).
/// - `GET /diff/<device>?a=<file_a>&b=<file_b>` — arbitrary comparison;
///   `a` is treated as the "before" side and `b` as the "after". If the
///   filenames come in the wrong chronological order they are swapped so
///   the diff always reads oldest → newest.
///
/// Both sides are decompressed if needed and normalized (ENC blobs / PEM
/// private keys collapsed) so the visible diff reflects *real*
/// configuration changes.
#[allow(clippy::result_large_err)]
fn render_diff(
    state: &AppState,
    rest: &str,
    query: Option<&str>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let (device, prev_idx, curr_idx, entries) =
        if let Some((dev_seg, file_seg)) = rest.split_once('/') {
            // Shortcut mode: /diff/<device>/<file>
            let device = decode_segment(dev_seg);
            let file = decode_segment(file_seg);
            let entries = load_entries(state, &device)?;
            let idx = locate(&entries, &file)?;
            if idx == 0 {
                return Err(error_page(
                    StatusCode::OK,
                    "No previous backup to diff against — this is the oldest one.",
                ));
            }
            (device, idx - 1, idx, entries)
        } else {
            // Arbitrary mode: /diff/<device>?a=<file>&b=<file>
            let device = decode_segment(rest);
            let entries = load_entries(state, &device)?;
            let params = parse_query(query.unwrap_or(""));
            let a = params
                .get("a")
                .ok_or_else(|| error_page(StatusCode::BAD_REQUEST, "missing query param `a`"))?;
            let b = params
                .get("b")
                .ok_or_else(|| error_page(StatusCode::BAD_REQUEST, "missing query param `b`"))?;
            let mut ai = locate(&entries, a)?;
            let mut bi = locate(&entries, b)?;
            if ai == bi {
                return Err(error_page(
                    StatusCode::OK,
                    "Both selections point to the same backup — nothing to diff.",
                ));
            }
            if ai > bi {
                std::mem::swap(&mut ai, &mut bi);
            }
            (device, ai, bi, entries)
        };

    state.cfg.find_device(&device).ok_or_else(|| {
        error_page(
            StatusCode::NOT_FOUND,
            &format!("Device `{device}` not found"),
        )
    })?;

    let prev = &entries[prev_idx];
    let curr = &entries[curr_idx];

    let prev_text = read_normalized(&prev.path)
        .map_err(|e| error_page(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    let curr_text = read_normalized(&curr.path)
        .map_err(|e| error_page(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    let diff_html = build_diff_html(&prev_text, &curr_text);
    let summary = diff_summary(&prev_text, &curr_text);

    let title = format!("Diff · {device}");
    let body = format!(
        r#"<h1>Diff · {device}</h1>
<p>
  <span class="mono">{prev_name}</span>
  →
  <span class="mono">{curr_name}</span>
</p>
<p>{summary}</p>
<p><a href="/device/{dev_enc}">Back to device</a></p>
<div class="diff">{diff_html}</div>"#,
        device = html_escape(&device),
        prev_name = html_escape(
            prev.path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
        ),
        curr_name = html_escape(
            curr.path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
        ),
        summary = html_escape(&summary),
        dev_enc = url_escape(&device),
        diff_html = diff_html,
    );
    Ok(html_response(page(&title, &body)))
}

/// Read a backup file from disk, gunzip if needed, then normalize so the
/// diff reflects logical changes only. Returns the resulting UTF-8 string.
fn read_normalized(path: &std::path::Path) -> Result<String, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let plain = if path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
    {
        gunzip(&raw).map_err(|e| format!("gunzip {}: {e}", path.display()))?
    } else {
        raw
    };
    let normalized = crate::normalize::for_hash(&plain);
    String::from_utf8(normalized).map_err(|e| format!("invalid utf-8: {e}"))
}

#[allow(clippy::result_large_err)]
fn load_entries(
    state: &AppState,
    device: &str,
) -> Result<Vec<storage::BackupEntry>, Response<Full<Bytes>>> {
    storage::list_entries_for_device(&state.cfg.global.backup_dir, device)
        .map_err(|e| error_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

#[allow(clippy::result_large_err)]
fn locate(
    entries: &[storage::BackupEntry],
    filename: &str,
) -> Result<usize, Response<Full<Bytes>>> {
    entries
        .iter()
        .position(|e| {
            e.path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s == filename)
        })
        .ok_or_else(|| {
            error_page(
                StatusCode::NOT_FOUND,
                &format!("Backup `{filename}` not found"),
            )
        })
}

fn parse_query(q: &str) -> std::collections::HashMap<String, String> {
    q.split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (decode_segment(k), decode_segment(v)))
        .collect()
}

fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read as _;
    let mut dec = flate2::read::GzDecoder::new(bytes);
    let mut out = Vec::with_capacity(bytes.len() * 4);
    dec.read_to_end(&mut out)?;
    Ok(out)
}

fn diff_summary(prev: &str, curr: &str) -> String {
    use similar::ChangeTag;
    let diff = similar::TextDiff::from_lines(prev, curr);
    let (mut added, mut removed) = (0_usize, 0_usize);
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Insert => added += 1,
            ChangeTag::Delete => removed += 1,
            ChangeTag::Equal => {}
        }
    }
    if added == 0 && removed == 0 {
        "No logical differences (config bodies are identical after normalization).".to_owned()
    } else {
        format!("{added} line(s) added · {removed} line(s) removed")
    }
}

fn build_diff_html(prev: &str, curr: &str) -> String {
    use similar::ChangeTag;
    let diff = similar::TextDiff::from_lines(prev, curr);
    let mut out = String::from("<pre class=\"diff-body\">");
    let mut any = false;
    // Show grouped hunks with 3 lines of context — same default as
    // `git diff --unified=3`. Avoids dumping the whole file when only
    // a few lines change.
    for (group_idx, group) in diff.grouped_ops(3).iter().enumerate() {
        if group_idx > 0 {
            out.push_str(r#"<span class="diff-sep">···</span>"#);
        }
        for op in group {
            for change in diff.iter_changes(op) {
                any = true;
                let (cls, sign) = match change.tag() {
                    ChangeTag::Delete => ("diff-del", '-'),
                    ChangeTag::Insert => ("diff-add", '+'),
                    ChangeTag::Equal => ("diff-ctx", ' '),
                };
                let line = change.value();
                let _ = write!(
                    out,
                    "<span class=\"{cls}\">{sign} {}</span>",
                    html_escape(line)
                );
            }
        }
    }
    if !any {
        out.push_str("(no changes)");
    }
    out.push_str("</pre>");
    out
}

// ---------------------------------------------------------------------------
// Manual run trigger
// ---------------------------------------------------------------------------

#[allow(clippy::result_large_err)]
async fn handle_run(
    state: &AppState,
    name: &str,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let device =
        state.cfg.find_device(name).cloned().ok_or_else(|| {
            error_page(StatusCode::NOT_FOUND, &format!("Device `{name}` not found"))
        })?;

    // Reserve the device. If it's already in flight, return 409.
    {
        let mut flight = state.in_flight.lock().await;
        if !flight.insert(name.to_owned()) {
            return Err(error_page(
                StatusCode::CONFLICT,
                "A backup for this device is already running",
            ));
        }
    }

    let report = backup::run_for_device(&state.cfg, &device).await;

    state.in_flight.lock().await.remove(name);

    // Render result inline rather than redirecting — keeps the flow simple
    // and avoids cross-request state.
    let (label, css_class) = match report.status {
        crate::notify::Status::Success => ("Backup written (changed)", "ok"),
        crate::notify::Status::NoChange => ("Backup OK (no change)", "ok"),
        crate::notify::Status::Failed => ("Backup failed", "err"),
    };
    let detail = format!(
        "duration {} ms · bytes {} · hash {}",
        report.duration_ms,
        report.bytes.map_or("—".to_owned(), |b| b.to_string()),
        report.hash_short.as_deref().unwrap_or("—"),
    );
    let err_block = report
        .error
        .as_ref()
        .map(|e| format!("<pre>{}</pre>", html_escape(e)))
        .unwrap_or_default();
    let body = page(
        &format!("Run · {}", device.name),
        &format!(
            r#"<div class="alert {cls}"><strong>{label}</strong><br>{detail}</div>
{err_block}
<p><a href="/device/{back}">Back to device</a> · <a href="/">Dashboard</a></p>"#,
            cls = css_class,
            label = html_escape(label),
            detail = html_escape(&detail),
            err_block = err_block,
            back = url_escape(&device.name),
        ),
    );
    Ok(html_response(body))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn url_escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn decode_segment(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect()
}

#[allow(clippy::cast_precision_loss)]
fn human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    let b = bytes as f64;
    if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_basic() {
        assert_eq!(html_escape("<b>&\""), "&lt;b&gt;&amp;&quot;");
    }

    #[test]
    fn url_decode_roundtrip() {
        let original = "edge fgt/01";
        let enc = url_escape(original);
        let dec = decode_segment(&enc);
        assert_eq!(dec, original);
    }

    #[test]
    fn sanitize_filename_rejects_path_chars() {
        assert_eq!(sanitize_filename("../etc/passwd"), "..etcpasswd");
        assert_eq!(
            sanitize_filename("2026-05-19_174204.conf"),
            "2026-05-19_174204.conf"
        );
    }
}
