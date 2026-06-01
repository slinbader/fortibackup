//! Backup-overdue watchdog.
//!
//! Periodically checks each device's last *successful* backup time and alerts
//! when one goes stale. The key subtlety: it reads the `.last_success` marker
//! (written on every successful run, see [`crate::storage::record_success`]),
//! NOT the timestamp of the newest stored file. Under dedup the newest file
//! can be days old even while backups keep succeeding, so measuring against it
//! would produce a false overdue alert every day.
//!
//! Alert behavior, to avoid spamming:
//!   * fire once when a device first crosses the staleness threshold,
//!   * re-fire at most once every 24h while it stays stale,
//!   * send a one-shot recovery notice when it backs up successfully again.
//!
//! Alert state lives in memory for the lifetime of the daemon. After a restart
//! a still-stale device alerts again on the first check, which is the desired
//! behavior — a restart shouldn't silence a real problem.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tracing::{info, warn};

use crate::config::Config;
use crate::notify::{self, NotificationEvent, Status};
use crate::scheduler::SharedConfig;
use crate::storage;

/// How long to wait before re-alerting a device that remains stale.
const REALERT_INTERVAL: chrono::Duration = chrono::Duration::hours(24);

/// Per-device alert bookkeeping.
#[derive(Default)]
struct AlertState {
    /// Whether the device was stale at the last observation.
    stale: bool,
    /// When we last sent a stale alert for this device.
    last_alert: Option<DateTime<Utc>>,
}

/// What the watchdog should do for a device on a given tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// Do nothing.
    Quiet,
    /// Send a stale alert (first crossing or 24h re-alert).
    Alert,
    /// Send a recovery notice (was stale, now fresh).
    Recovered,
}

/// Spawn the watchdog as a detached background task. It reads the live config
/// from `shared` on every tick, so device additions/removals from a hot reload
/// are observed. The check interval is fixed at spawn time.
pub fn spawn(shared: SharedConfig, check_interval: Duration) {
    tokio::spawn(async move {
        run(shared, check_interval).await;
    });
}

async fn run(shared: SharedConfig, check_interval: Duration) {
    info!(
        interval_secs = check_interval.as_secs(),
        "backup-overdue watchdog started"
    );
    let mut states: HashMap<String, AlertState> = HashMap::new();
    let mut ticker = tokio::time::interval(check_interval);

    loop {
        ticker.tick().await;
        let cfg = Arc::clone(&*shared.lock().await);
        // The daemon only spawns the watchdog when enabled, but a hot reload
        // could flip it off; respect that without tearing the task down.
        if !cfg.watchdog.enabled {
            continue;
        }
        let stale_after = match cfg.watchdog.stale_after_duration() {
            Ok(d) => d,
            Err(err) => {
                warn!(error = %err, "watchdog stale_after invalid; skipping check");
                continue;
            }
        };
        check_once(&cfg, stale_after, Utc::now(), &mut states).await;
    }
}

async fn check_once(
    cfg: &Config,
    stale_after: Duration,
    now: DateTime<Utc>,
    states: &mut HashMap<String, AlertState>,
) {
    let stale_after =
        chrono::Duration::from_std(stale_after).unwrap_or_else(|_| chrono::Duration::hours(26));

    for device in &cfg.devices {
        let Some(last) = storage::last_success_at(&cfg.global.backup_dir, &device.name) else {
            // No baseline yet: never alert on a device that has never backed
            // up (e.g. a fresh install before its first scheduled run).
            continue;
        };
        let age = now - last;
        let is_stale = age > stale_after;
        let state = states.entry(device.name.clone()).or_default();

        match decide(is_stale, state.stale, state.last_alert, now) {
            Decision::Alert => {
                warn!(
                    device = %device.name,
                    age_secs = age.num_seconds(),
                    last_success = %last.to_rfc3339(),
                    "backup overdue — sending alert"
                );
                send(
                    cfg,
                    &device.name,
                    Status::Stale,
                    Some(stale_message(last, age)),
                )
                .await;
                state.stale = true;
                state.last_alert = Some(now);
            }
            Decision::Recovered => {
                info!(device = %device.name, "backup recovered — sending notice");
                send(cfg, &device.name, Status::Recovered, None).await;
                state.stale = false;
                state.last_alert = None;
            }
            Decision::Quiet => {
                state.stale = is_stale;
            }
        }
    }
}

/// Pure decision function — no IO, so the state machine is unit-testable.
fn decide(
    is_stale: bool,
    prev_stale: bool,
    last_alert: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Decision {
    if is_stale {
        let due_for_realert = match last_alert {
            None => true,
            Some(t) => now - t >= REALERT_INTERVAL,
        };
        if !prev_stale || due_for_realert {
            Decision::Alert
        } else {
            Decision::Quiet
        }
    } else if prev_stale {
        Decision::Recovered
    } else {
        Decision::Quiet
    }
}

fn stale_message(last: DateTime<Utc>, age: chrono::Duration) -> String {
    let secs = u64::try_from(age.num_seconds()).unwrap_or(0);
    format!(
        "No successful backup in {}. Last success: {}.",
        humantime::format_duration(Duration::from_secs(secs)),
        last.to_rfc3339()
    )
}

async fn send(cfg: &Config, device: &str, status: Status, detail: Option<String>) {
    let event = NotificationEvent {
        device: device.to_owned(),
        status,
        error: detail,
        bytes: None,
        hash_short: None,
        transport: "watchdog".to_owned(),
        timestamp: Utc::now(),
    };
    notify::dispatch(&cfg.notifications, &event).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(rfc: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn fresh_device_stays_quiet() {
        assert_eq!(
            decide(false, false, None, t("2026-05-28T13:00:00Z")),
            Decision::Quiet
        );
    }

    #[test]
    fn first_crossing_alerts() {
        assert_eq!(
            decide(true, false, None, t("2026-05-28T13:00:00Z")),
            Decision::Alert
        );
    }

    #[test]
    fn still_stale_within_24h_is_quiet() {
        let now = t("2026-05-28T13:00:00Z");
        let last_alert = Some(t("2026-05-28T02:00:00Z")); // 11h ago
        assert_eq!(decide(true, true, last_alert, now), Decision::Quiet);
    }

    #[test]
    fn still_stale_past_24h_realerts() {
        let now = t("2026-05-28T13:00:00Z");
        let last_alert = Some(t("2026-05-27T12:00:00Z")); // 25h ago
        assert_eq!(decide(true, true, last_alert, now), Decision::Alert);
    }

    #[test]
    fn recovery_sends_notice_once() {
        let now = t("2026-05-28T13:00:00Z");
        // was stale, now fresh => Recovered
        assert_eq!(decide(false, true, Some(now), now), Decision::Recovered);
        // next tick, already cleared => Quiet
        assert_eq!(decide(false, false, None, now), Decision::Quiet);
    }

    #[test]
    fn stale_message_includes_last_success() {
        let last = t("2026-05-26T07:30:00Z");
        let age = chrono::Duration::hours(30);
        let msg = stale_message(last, age);
        // humantime decomposes 30h as "1day 6h"; assert on the stable parts.
        assert!(msg.starts_with("No successful backup in"));
        assert!(msg.contains("2026-05-26T07:30:00"));
    }
}
