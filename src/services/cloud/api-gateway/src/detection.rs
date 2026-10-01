//! Event analysis: turns ingested traffic events into findings.
//!
//! Everything here is pure (no I/O) apart from the in-memory brute-force
//! tracker, so it can be unit tested without a database.

use crate::models::TrafficEvent;
use crate::settings::TenantSettings;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use regex::Regex;
use serde::Serialize;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    Suricata,
    BruteForce,
    Payload,
    ThreatIntel,
}

impl FindingSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingSource::Suricata => "suricata",
            FindingSource::BruteForce => "brute_force",
            FindingSource::Payload => "payload",
            FindingSource::ThreatIntel => "threat_intel",
        }
    }
}

/// A detection to persist as an alert and (possibly) act on.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub source: FindingSource,
    /// The address we would block.
    pub offender: IpAddr,
    pub signature: String,
    pub category: String,
    /// Suricata scale: 1 critical, 2 high, 3 medium, 4 low.
    pub severity: u8,
    pub signature_id: u64,
    pub action: String,
}

pub fn severity_label(sev: u8) -> &'static str {
    match sev {
        1 => "critical",
        2 => "high",
        3 => "medium",
        _ => "low",
    }
}

/// Map a Suricata severity (1..=255, lower = worse) onto 1..=4.
pub fn normalize_suricata_severity(raw: u64) -> u8 {
    match raw {
        0 | 1 => 1,
        2 => 2,
        3 => 3,
        _ => 4,
    }
}

/// Map the 0-10 `threat_level` used by the payload patterns onto 1..=4.
pub fn severity_from_threat_level(level: u8) -> u8 {
    match level {
        9..=10 => 1,
        7..=8 => 2,
        4..=6 => 3,
        _ => 4,
    }
}

struct ThreatPattern {
    name: &'static str,
    regex: Regex,
    threat_level: u8,
}

static PATTERNS: LazyLock<Vec<ThreatPattern>> = LazyLock::new(|| {
    let mk = |name, re: &str, threat_level| ThreatPattern {
        name,
        regex: Regex::new(re).expect("static regex"),
        threat_level,
    };
    vec![
        mk(
            "SQL Injection",
            r"(?i)(\bunion\b[\s/*+]+(all[\s/*+]+)?select\b|\bselect\b.{1,60}\bfrom\b|\bdrop\s+table\b|\binsert\s+into\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1|;\s*--|/\*.*\*/)",
            8,
        ),
        mk(
            "XSS Attack",
            r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|\beval\s*\()",
            7,
        ),
        mk(
            "Command Injection",
            r"(?i)(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|netcat|bash|sh|powershell|cmd(\.exe)?)\b|/etc/(passwd|shadow)|cmd\.exe",
            9,
        ),
        mk("Path Traversal", r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", 7),
        mk("Shellshock", r"\(\)\s*\{\s*[:;]", 9),
    ]
});

/// Match free text (URL, user agent, ...) against the payload patterns.
/// Returns `(threat_level, pattern_name)` for the most severe match.
pub fn analyse_text(text: &str) -> Option<(u8, &'static str)> {
    // Percent-decode once so encoded probes (%3Cscript) are caught as well.
    let decoded = percent_decode(text);
    PATTERNS
        .iter()
        .filter(|p| p.regex.is_match(text) || p.regex.is_match(&decoded))
        .max_by_key(|p| p.threat_level)
        .map(|p| (p.threat_level, p.name))
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A raw packet streamed by a sensor over `/ws/packets`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StreamedPacket {
    pub src_ip: String,
    #[serde(default)]
    pub dst_ip: String,
    #[serde(default)]
    pub src_port: u16,
    #[serde(default)]
    pub dst_port: u16,
    #[serde(default)]
    pub protocol: String,
    /// First bytes of the IP payload, hex encoded.
    #[serde(default)]
    pub payload_hex: String,
}

/// Decode at most 512 bytes of hex, skipping malformed pairs.
pub fn decode_hex_lossy(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .take(512)
        .filter_map(|c| std::str::from_utf8(c).ok().and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect()
}

/// Inspect a streamed packet's payload for known attack patterns.
pub fn analyse_packet(p: &StreamedPacket) -> Option<Finding> {
    let src: IpAddr = p.src_ip.parse().ok()?;
    let bytes = decode_hex_lossy(&p.payload_hex);
    let text = String::from_utf8_lossy(&bytes);
    let (level, name) = analyse_text(&text)?;
    Some(Finding {
        source: FindingSource::Payload,
        offender: src,
        signature: format!("{name} pattern in packet payload"),
        category: "Web Application Attack".into(),
        severity: severity_from_threat_level(level),
        signature_id: 0,
        action: "alert".into(),
    })
}

/// Sliding-window request counter per (tenant, source ip, path).
#[derive(Default)]
pub struct BruteForceTracker {
    hits: DashMap<(String, IpAddr, String), VecDeque<DateTime<Utc>>>,
}

impl BruteForceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one request. Returns `Some(count)` the moment the threshold is
    /// reached inside the window; the key is then reset so one burst yields
    /// one finding.
    pub fn record(
        &self,
        tenant: &str,
        ip: IpAddr,
        path: &str,
        now: DateTime<Utc>,
        window_secs: u32,
        threshold: u32,
    ) -> Option<u32> {
        let key = (tenant.to_string(), ip, path.to_string());
        let mut q = self.hits.entry(key.clone()).or_default();
        let cutoff = now - Duration::seconds(i64::from(window_secs));
        while q.front().is_some_and(|t| *t < cutoff) {
            q.pop_front();
        }
        q.push_back(now);
        let count = q.len() as u32;
        if count >= threshold {
            drop(q);
            self.hits.remove(&key);
            Some(count)
        } else {
            None
        }
    }

    /// Drop stale entries (called periodically).
    pub fn prune(&self, now: DateTime<Utc>, max_window_secs: u32) {
        let cutoff = now - Duration::seconds(i64::from(max_window_secs));
        self.hits.retain(|_, q| q.back().is_some_and(|t| *t >= cutoff));
    }

    pub fn len(&self) -> usize {
        self.hits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }
}

fn path_of(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

/// Analyse one validated event. `src` is the parsed `source_ip`.
pub fn analyze_event(
    event: &TrafficEvent,
    src: IpAddr,
    tenant_id: &str,
    settings: &TenantSettings,
    tracker: &BruteForceTracker,
    now: DateTime<Utc>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let p = &event.payload;

    match event.event_type.as_str() {
        "alert" => {
            let a = &p["alert"];
            // Sensors report what Suricata did; "allowed" and "blocked" are both alerts.
            let sev = normalize_suricata_severity(a["severity"].as_u64().unwrap_or(3));
            out.push(Finding {
                source: FindingSource::Suricata,
                offender: src,
                signature: a["signature"]
                    .as_str()
                    .unwrap_or("Unknown signature")
                    .chars()
                    .take(256)
                    .collect(),
                category: a["category"].as_str().unwrap_or("").chars().take(128).collect(),
                severity: sev,
                signature_id: a["signature_id"].as_u64().unwrap_or(0),
                action: a["action"].as_str().unwrap_or("alert").chars().take(16).collect(),
            });
        }
        "http" => {
            let url = p["http"]["url"].as_str().unwrap_or("");
            if !url.is_empty() {
                let path = path_of(url);
                if settings.monitored_paths.iter().any(|m| path.starts_with(m.as_str())) {
                    if let Some(count) = tracker.record(
                        tenant_id,
                        src,
                        path,
                        now,
                        settings.brute_force_window_secs,
                        settings.brute_force_threshold,
                    ) {
                        out.push(Finding {
                            source: FindingSource::BruteForce,
                            offender: src,
                            signature: format!(
                                "Brute force: {count} requests to {} in {}s",
                                path.chars().take(100).collect::<String>(),
                                settings.brute_force_window_secs
                            ),
                            category: "Attempted Administrator Privilege Gain".into(),
                            severity: 2,
                            signature_id: 0,
                            action: "alert".into(),
                        });
                    }
                }
                let ua = p["http"]["http_user_agent"].as_str().unwrap_or("");
                if let Some((level, name)) = analyse_text(url).or_else(|| analyse_text(ua)) {
                    out.push(Finding {
                        source: FindingSource::Payload,
                        offender: src,
                        signature: format!("{name} attempt in HTTP request"),
                        category: "Web Application Attack".into(),
                        severity: severity_from_threat_level(level),
                        signature_id: 0,
                        action: "alert".into(),
                    });
                }
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(kind: &str, src: &str, payload: serde_json::Value) -> TrafficEvent {
        serde_json::from_value(json!({
            "source_ip": src, "dest_ip": "198.51.100.1", "event_type": kind, "payload": payload
        }))
        .unwrap()
    }

    fn run(e: &TrafficEvent, s: &TenantSettings, t: &BruteForceTracker) -> Vec<Finding> {
        analyze_event(e, e.source_ip.parse().unwrap(), "t1", s, t, Utc::now())
    }

    #[test]
    fn suricata_alert_becomes_finding_with_normalised_severity() {
        let e = event(
            "alert",
            "203.0.113.9",
            json!({"alert": {"severity": 1, "signature": "ET EXPLOIT x", "category": "Exploit", "signature_id": 2001, "action": "allowed"}}),
        );
        let f = run(&e, &TenantSettings::default(), &BruteForceTracker::new());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, 1);
        assert_eq!(f[0].signature_id, 2001);
        assert_eq!(f[0].source, FindingSource::Suricata);
        assert_eq!(severity_label(f[0].severity), "critical");
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(normalize_suricata_severity(0), 1);
        assert_eq!(normalize_suricata_severity(3), 3);
        assert_eq!(normalize_suricata_severity(7), 4);
        assert_eq!(severity_from_threat_level(9), 1);
        assert_eq!(severity_from_threat_level(7), 2);
        assert_eq!(severity_from_threat_level(1), 4);
    }

    #[test]
    fn non_alert_events_without_signals_yield_nothing() {
        let e = event("dns", "203.0.113.9", json!({"dns": {"rrname": "example.org"}}));
        assert!(run(&e, &TenantSettings::default(), &BruteForceTracker::new()).is_empty());
    }

    #[test]
    fn payload_patterns_detect_common_attacks() {
        assert_eq!(
            analyse_text("/?id=1 UNION SELECT password FROM users").unwrap().1,
            "SQL Injection"
        );
        assert_eq!(analyse_text("/q?x=<script>alert(1)</script>").unwrap().1, "XSS Attack");
        assert_eq!(analyse_text("/q?x=%3Cscript%3E").unwrap().1, "XSS Attack");
        assert_eq!(analyse_text("/download?f=../../etc/passwd").unwrap().0, 9);
        assert_eq!(analyse_text("() { :;}; /bin/bash -c id").unwrap().1, "Shellshock");
    }

    #[test]
    fn benign_text_is_not_flagged() {
        for t in [
            "/index.html",
            "/products?select=blue",
            "/update/profile",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "/api/v1/users/42",
        ] {
            assert!(analyse_text(t).is_none(), "{t} falsely flagged");
        }
    }

    #[test]
    fn http_payload_attack_creates_finding() {
        let e = event("http", "203.0.113.9", json!({"http": {"url": "/x?f=../../etc/passwd"}}));
        let f = run(&e, &TenantSettings::default(), &BruteForceTracker::new());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].source, FindingSource::Payload);
        assert_eq!(f[0].severity, 1);
    }

    #[test]
    fn brute_force_triggers_once_at_threshold() {
        let tracker = BruteForceTracker::new();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let now = Utc::now();
        for i in 0..4 {
            assert!(tracker
                .record("t1", ip, "/login", now + Duration::seconds(i), 60, 5)
                .is_none());
        }
        assert_eq!(
            tracker.record("t1", ip, "/login", now + Duration::seconds(5), 60, 5),
            Some(5)
        );
        // Reset after firing.
        assert!(tracker
            .record("t1", ip, "/login", now + Duration::seconds(6), 60, 5)
            .is_none());
    }

    #[test]
    fn brute_force_window_expires_and_tenants_are_isolated() {
        let tracker = BruteForceTracker::new();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let now = Utc::now();
        for i in 0..4 {
            tracker.record("t1", ip, "/login", now + Duration::seconds(i), 10, 5);
        }
        // Other tenant does not share the counter.
        assert!(tracker
            .record("t2", ip, "/login", now + Duration::seconds(4), 10, 5)
            .is_none());
        // Old hits fall out of the window.
        assert!(tracker
            .record("t1", ip, "/login", now + Duration::seconds(100), 10, 5)
            .is_none());
        tracker.prune(now + Duration::seconds(1000), 60);
        assert!(tracker.is_empty());
    }

    #[test]
    fn http_brute_force_through_analyze_event() {
        let settings = TenantSettings {
            brute_force_threshold: 3,
            ..Default::default()
        };
        let tracker = BruteForceTracker::new();
        let e = event("http", "203.0.113.9", json!({"http": {"url": "/wp-login.php?x=1"}}));
        assert!(run(&e, &settings, &tracker).is_empty());
        assert!(run(&e, &settings, &tracker).is_empty());
        let f = run(&e, &settings, &tracker);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].source, FindingSource::BruteForce);
    }

    #[test]
    fn packet_payload_analysis() {
        let hex = |s: &str| s.bytes().map(|b| format!("{b:02x}")).collect::<String>();
        let p = StreamedPacket {
            src_ip: "203.0.113.9".into(),
            dst_ip: "198.51.100.1".into(),
            src_port: 4444,
            dst_port: 80,
            protocol: "tcp".into(),
            payload_hex: hex("GET /?q=<script>alert(1)</script> HTTP/1.1"),
        };
        let f = analyse_packet(&p).unwrap();
        assert_eq!(f.offender.to_string(), "203.0.113.9");
        assert_eq!(f.severity, 2);
        let benign = StreamedPacket {
            payload_hex: hex("GET /index.html HTTP/1.1"),
            ..p.clone()
        };
        assert!(analyse_packet(&benign).is_none());
        let bad_ip = StreamedPacket {
            src_ip: "nope".into(),
            ..p
        };
        assert!(analyse_packet(&bad_ip).is_none());
        assert_eq!(decode_hex_lossy("4142zz43"), vec![0x41, 0x42, 0x43]);
    }

    #[test]
    fn percent_decode_handles_edges() {
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("%41%zz"), "A%zz");
        assert_eq!(percent_decode("%"), "%");
    }
}
