//! abuse.ch threat-intelligence feeds (Feodo Tracker / SSLBL IP lists).
//!
//! Feeds are plain text, one IP per line, `#` comments. They are fetched on a
//! timer and held in memory; ingested events whose source or destination
//! matches become `threat_intel` findings.

use crate::state::AppState;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Default)]
pub struct ThreatFeed {
    inner: RwLock<FeedData>,
}

#[derive(Default, Clone)]
struct FeedData {
    ips: HashSet<IpAddr>,
    last_refresh: Option<DateTime<Utc>>,
    sources_ok: usize,
    sources_total: usize,
}

/// Parse a feed body into addresses. Ignores comments, blanks and junk lines;
/// a line may carry trailing fields (`ip,port,...` or `ip # note`).
pub fn parse_feed(body: &str) -> HashSet<IpAddr> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let first = l.split(['#', ',', ' ', '\t', ';']).next()?.trim().trim_matches('"');
            first.parse::<IpAddr>().ok()
        })
        .collect()
}

impl ThreatFeed {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.inner.read().map(|d| d.ips.contains(ip)).unwrap_or(false)
    }

    pub fn replace(&self, ips: HashSet<IpAddr>, ok: usize, total: usize) {
        if let Ok(mut d) = self.inner.write() {
            *d = FeedData {
                ips,
                last_refresh: Some(Utc::now()),
                sources_ok: ok,
                sources_total: total,
            };
        }
    }

    pub fn status(&self) -> serde_json::Value {
        let d = self.inner.read().map(|d| d.clone()).unwrap_or_default();
        serde_json::json!({
            "entries": d.ips.len(),
            "last_refresh": d.last_refresh,
            "sources_ok": d.sources_ok,
            "sources_total": d.sources_total,
        })
    }
}

/// Fetch all configured feeds once. Keeps the previous data if every source fails.
pub async fn refresh(state: &AppState) {
    let urls = &state.cfg.threat_feed_urls;
    if urls.is_empty() {
        return;
    }
    let mut all = HashSet::new();
    let mut ok = 0;
    for url in urls {
        match state.http.get(url).send().await.and_then(|r| r.error_for_status()) {
            Ok(resp) => match resp.text().await {
                Ok(body) => {
                    let ips = parse_feed(&body);
                    tracing::info!("threat feed {url}: {} entries", ips.len());
                    all.extend(ips);
                    ok += 1;
                }
                Err(e) => tracing::warn!("threat feed {url}: read failed: {e}"),
            },
            Err(e) => tracing::warn!("threat feed {url}: fetch failed: {e}"),
        }
    }
    if ok > 0 {
        state.feed.replace(all, ok, urls.len());
    }
}

pub fn spawn_refresh_loop(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(state.cfg.threat_feed_interval_secs.max(300)));
        loop {
            tick.tick().await;
            refresh(&state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "################\n# abuse.ch Feodo Tracker\n################\n#\n# first_seen_utc,dst_ip,dst_port\n\n198.51.100.7\n203.0.113.20 # note\n\"192.0.2.1\",443\nnot-an-ip\n2001:db8::5\n";

    #[test]
    fn parses_ips_and_skips_noise() {
        let ips = parse_feed(SAMPLE);
        assert_eq!(ips.len(), 4);
        assert!(ips.contains(&"198.51.100.7".parse().unwrap()));
        assert!(ips.contains(&"203.0.113.20".parse().unwrap()));
        assert!(ips.contains(&"192.0.2.1".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::5".parse().unwrap()));
    }

    #[test]
    fn feed_membership_and_status() {
        let feed = ThreatFeed::new();
        assert!(!feed.contains(&"198.51.100.7".parse().unwrap()));
        feed.replace(parse_feed(SAMPLE), 1, 2);
        assert!(feed.contains(&"198.51.100.7".parse().unwrap()));
        let s = feed.status();
        assert_eq!(s["entries"], 4);
        assert_eq!(s["sources_total"], 2);
    }
}
