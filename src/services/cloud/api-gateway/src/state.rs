//! Shared application state.

use crate::config::Config;
use crate::detection::BruteForceTracker;
use crate::models::SensorIdentity;
use crate::ratelimit::RateLimiter;
use crate::settings::TenantSettings;
use crate::store::Store;
use crate::threat_intel::ThreatFeed;
use crate::ws::Registry;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

/// (tenant_id, json text) pushed to dashboard WebSocket clients of that tenant.
pub type DashMsg = (String, String);

#[derive(Default)]
pub struct Metrics {
    pub events_ingested: AtomicU64,
    pub events_rejected: AtomicU64,
    pub alerts_total: AtomicU64,
    pub blocks_created: AtomicU64,
    pub blocks_auto: AtomicU64,
    pub enrollments: AtomicU64,
    pub commands_sent: AtomicU64,
}

impl Metrics {
    pub fn inc(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }

    pub fn render(&self, sensors_online: usize, feed_entries: u64) -> String {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let mut out = String::new();
        let mut line = |name: &str, help: &str, kind: &str, v: u64| {
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {v}\n"));
        };
        line(
            "netsentry_events_ingested_total",
            "Events stored",
            "counter",
            g(&self.events_ingested),
        );
        line(
            "netsentry_events_rejected_total",
            "Events rejected as invalid",
            "counter",
            g(&self.events_rejected),
        );
        line(
            "netsentry_alerts_total",
            "Alerts raised",
            "counter",
            g(&self.alerts_total),
        );
        line(
            "netsentry_blocks_created_total",
            "Block records created",
            "counter",
            g(&self.blocks_created),
        );
        line(
            "netsentry_blocks_auto_total",
            "Blocks applied automatically",
            "counter",
            g(&self.blocks_auto),
        );
        line(
            "netsentry_enrollments_total",
            "Sensors enrolled",
            "counter",
            g(&self.enrollments),
        );
        line(
            "netsentry_commands_sent_total",
            "Signed commands sent to sensors",
            "counter",
            g(&self.commands_sent),
        );
        line(
            "netsentry_sensors_online",
            "Connected sensor WebSockets",
            "gauge",
            sensors_online as u64,
        );
        line(
            "netsentry_threat_feed_entries",
            "Entries in the threat-intel feed",
            "gauge",
            feed_entries,
        );
        out
    }
}

pub struct AppState {
    pub cfg: Config,
    pub store: Store,
    pub registry: Registry,
    pub dashboard_tx: broadcast::Sender<DashMsg>,
    pub tracker: BruteForceTracker,
    pub feed: ThreatFeed,
    pub sensor_cache: DashMap<String, (SensorIdentity, Instant)>,
    pub settings_cache: DashMap<String, (TenantSettings, Instant)>,
    pub limiter: RateLimiter,
    pub metrics: Metrics,
    pub http: reqwest::Client,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(cfg: Config, store: Store, limiter: RateLimiter) -> SharedState {
        let (dashboard_tx, _) = broadcast::channel(512);
        Arc::new(Self {
            cfg,
            store,
            registry: Registry::default(),
            dashboard_tx,
            tracker: BruteForceTracker::new(),
            feed: ThreatFeed::new(),
            sensor_cache: DashMap::new(),
            settings_cache: DashMap::new(),
            limiter,
            metrics: Metrics::default(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .user_agent("netsentry-gateway")
                .build()
                .expect("http client"),
        })
    }

    /// Push a JSON message to dashboard clients of one tenant.
    pub fn notify_dashboard(&self, tenant_id: &str, msg: serde_json::Value) {
        let _ = self.dashboard_tx.send((tenant_id.to_string(), msg.to_string()));
    }
}
