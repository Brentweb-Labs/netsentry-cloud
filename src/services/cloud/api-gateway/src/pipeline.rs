//! Ingest pipeline: validate -> store -> analyse -> alert -> (maybe) block.

use crate::detection::{analyze_event, severity_label, Finding, FindingSource};
use crate::models::{SensorIdentity, TrafficEvent};
use crate::prevention;
use crate::settings::{self, TenantSettings};
use crate::state::{AppState, Metrics};
use crate::store::{bdt, bdt_now, doc_to_json, ALERTS, EVENTS};
use chrono::Utc;
use mongodb::bson::{self, doc, Bson, Document};
use serde_json::json;
use std::collections::HashSet;
use std::net::IpAddr;

/// Upper bound on alerts raised from one request (flood protection).
const MAX_ALERTS_PER_REQUEST: usize = 500;
pub const MAX_BATCH: usize = 5000;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub received: usize,
    pub stored: usize,
    pub rejected: usize,
    pub alerts: usize,
}

/// Parse and validate raw JSON events; invalid entries are counted, not fatal.
pub fn parse_events(raw: Vec<serde_json::Value>) -> (Vec<(TrafficEvent, IpAddr)>, usize) {
    let mut ok = Vec::with_capacity(raw.len());
    let mut rejected = 0;
    for v in raw {
        match serde_json::from_value::<TrafficEvent>(v) {
            Ok(e) => match e.validate() {
                Ok(src) => ok.push((e, src)),
                Err(_) => rejected += 1,
            },
            Err(_) => rejected += 1,
        }
    }
    (ok, rejected)
}

pub fn event_doc(tenant_id: &str, sensor_id: &str, e: &TrafficEvent) -> Document {
    let payload = bson::to_bson(&e.payload).unwrap_or(Bson::Null);
    doc! {
        "tenant_id": tenant_id,
        "sensor_id": sensor_id,
        "event_id": &e.id,
        "event_type": &e.event_type,
        "ts": bdt(e.timestamp),
        "src_ip": &e.source_ip,
        "src_port": i32::from(e.source_port),
        "dest_ip": &e.dest_ip,
        "dest_port": i32::from(e.dest_port),
        "proto": &e.protocol,
        "threat_level": i32::from(e.threat_level),
        "payload": payload,
        "processed_at": bdt_now(),
    }
}

pub fn alert_doc(tenant_id: &str, sensor_id: &str, e: &TrafficEvent, f: &Finding, decision: &str) -> Document {
    doc! {
        "tenant_id": tenant_id,
        "sensor_id": sensor_id,
        "event_id": &e.id,
        "ts": bdt(e.timestamp),
        "src_ip": &e.source_ip,
        "src_port": i32::from(e.source_port),
        "dest_ip": &e.dest_ip,
        "dest_port": i32::from(e.dest_port),
        "proto": &e.protocol,
        "offender_ip": f.offender.to_string(),
        "signature": &f.signature,
        "signature_id": f.signature_id as i64,
        "category": &f.category,
        "severity": i32::from(f.severity),
        "severity_label": severity_label(f.severity),
        "source": f.source.as_str(),
        "action": &f.action,
        "decision": decision,
        "processed_at": bdt_now(),
    }
}

fn threat_intel_findings(state: &AppState, e: &TrafficEvent, src: IpAddr, seen: &mut HashSet<IpAddr>) -> Vec<Finding> {
    let mut out = Vec::new();
    let dest = e.dest_ip.parse::<IpAddr>().ok();
    for ip in std::iter::once(src).chain(dest) {
        if state.feed.contains(&ip) && seen.insert(ip) {
            out.push(Finding {
                source: FindingSource::ThreatIntel,
                offender: ip,
                signature: format!("Traffic involving {ip}, listed on an abuse.ch threat feed"),
                category: "Known Malicious Host".into(),
                severity: 2,
                signature_id: 0,
                action: "alert".into(),
            });
        }
    }
    out
}

/// Run detection over a set of validated events (no I/O besides the tracker).
pub fn collect_findings(
    state: &AppState,
    ident: &SensorIdentity,
    settings: &TenantSettings,
    events: &[(TrafficEvent, IpAddr)],
) -> Vec<(usize, Finding)> {
    let now = Utc::now();
    let mut seen_ti = HashSet::new();
    let mut out = Vec::new();
    for (i, (e, src)) in events.iter().enumerate() {
        for f in analyze_event(e, *src, &ident.tenant_id, settings, &state.tracker, now) {
            out.push((i, f));
        }
        if settings.threat_intel_enabled {
            for f in threat_intel_findings(state, e, *src, &mut seen_ti) {
                out.push((i, f));
            }
        }
    }
    out
}

pub async fn process_events(state: &AppState, ident: &SensorIdentity, raw: Vec<serde_json::Value>) -> Summary {
    let received = raw.len();
    let (events, rejected) = parse_events(raw);
    let mut summary = Summary {
        received,
        rejected,
        ..Default::default()
    };
    Metrics::inc(&state.metrics.events_rejected, rejected as u64);
    if events.is_empty() {
        return summary;
    }

    let docs: Vec<Document> = events
        .iter()
        .map(|(e, _)| event_doc(&ident.tenant_id, &ident.sensor_id, e))
        .collect();
    match state.store.coll(EVENTS).insert_many(docs).ordered(false).await {
        Ok(r) => summary.stored = r.inserted_ids.len(),
        Err(err) => tracing::warn!("storing events failed: {err}"),
    }
    Metrics::inc(&state.metrics.events_ingested, summary.stored as u64);

    let tenant_settings = settings::load(state, &ident.tenant_id).await;
    let findings = collect_findings(state, ident, &tenant_settings, &events);

    let mut alert_docs = Vec::new();
    for (idx, finding) in findings.into_iter().take(MAX_ALERTS_PER_REQUEST) {
        let (event, _) = &events[idx];
        let decision = prevention::handle_finding(state, ident, &tenant_settings, &finding).await;
        let label = match decision {
            prevention::Decision::AutoBlock => "auto_blocked",
            prevention::Decision::Propose => "block_proposed",
            prevention::Decision::AlertOnly => "alert_only",
            prevention::Decision::Skip(_) => "protected",
        };
        let d = alert_doc(&ident.tenant_id, &ident.sensor_id, event, &finding, label);
        let mut msg = doc_to_json(&d);
        msg["type"] = json!("alert");
        state.notify_dashboard(&ident.tenant_id, msg);
        alert_docs.push(d);
    }
    summary.alerts = alert_docs.len();
    Metrics::inc(&state.metrics.alerts_total, alert_docs.len() as u64);
    if !alert_docs.is_empty() {
        if let Err(err) = state.store.coll(ALERTS).insert_many(alert_docs).await {
            tracing::warn!("storing alerts failed: {err}");
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_events_counts_invalid_entries() {
        let raw = vec![
            json!({"source_ip": "203.0.113.5", "event_type": "alert"}),
            json!({"source_ip": "bad"}),
            json!({"dest_ip": "1.1.1.1"}),
            json!("not an object"),
            json!({"source_ip": "198.51.100.1", "event_type": "dns", "payload": {"dns": {}}}),
        ];
        let (ok, rejected) = parse_events(raw);
        assert_eq!(ok.len(), 2);
        assert_eq!(rejected, 3);
    }

    #[test]
    fn event_doc_carries_tenant_and_sensor() {
        let e: TrafficEvent = serde_json::from_value(
            json!({"source_ip": "203.0.113.5", "source_port": 4444, "event_type": "alert", "payload": {"a": 1}}),
        )
        .unwrap();
        let d = event_doc("tenant-1", "sensor-9", &e);
        assert_eq!(d.get_str("tenant_id").unwrap(), "tenant-1");
        assert_eq!(d.get_str("sensor_id").unwrap(), "sensor-9");
        assert_eq!(d.get_i32("src_port").unwrap(), 4444);
        assert_eq!(d.get_document("payload").unwrap().get_i64("a").unwrap(), 1);
    }

    #[test]
    fn alert_doc_carries_tenant_and_sensor() {
        let e: TrafficEvent =
            serde_json::from_value(json!({"source_ip": "203.0.113.5", "event_type": "alert"})).unwrap();
        let f = Finding {
            source: FindingSource::Suricata,
            offender: "203.0.113.5".parse().unwrap(),
            signature: "sig".into(),
            category: "c".into(),
            severity: 2,
            signature_id: 5,
            action: "alert".into(),
        };
        let d = alert_doc("t", "s", &e, &f, "block_proposed");
        assert_eq!(d.get_str("tenant_id").unwrap(), "t");
        assert_eq!(d.get_str("sensor_id").unwrap(), "s");
        assert_eq!(d.get_str("severity_label").unwrap(), "high");
        assert_eq!(d.get_str("source").unwrap(), "suricata");
    }
}
