//! Blocking workflow with safety rails.
//!
//! * Detections never block by default: they create **pending** proposals that
//!   an operator approves (`block_mode = manual`).
//! * Automatic blocking is opt-in per tenant, limited to the most severe
//!   findings, rate capped per hour, and never touches allowlisted ranges.
//! * Every block has a TTL and is lifted automatically when it expires.
//! * Loopback/multicast/link-local/unspecified addresses are never blockable.

use crate::detection::{severity_label, Finding};
use crate::error::{ApiError, ApiResult};
use crate::models::SensorIdentity;
use crate::settings::{is_allowlisted, BlockMode, TenantSettings};
use crate::state::{AppState, Metrics};
use crate::store::{bdt, bdt_now, doc_to_json, BLOCKED_IPS};
use chrono::{DateTime, Duration, Utc};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Document};
use mongodb::options::ReturnDocument;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Not actionable (reason given); alert is still stored.
    Skip(&'static str),
    /// Alert only, below the proposal threshold.
    AlertOnly,
    /// Create a pending block awaiting operator approval.
    Propose,
    /// Block immediately.
    AutoBlock,
}

/// Addresses that must never be blocked regardless of settings.
pub fn never_blockable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub fn decide(settings: &TenantSettings, ip: &IpAddr, severity: u8, auto_blocks_last_hour: u32) -> Decision {
    if never_blockable(ip) {
        return Decision::Skip("address is never blockable");
    }
    if is_allowlisted(ip, &settings.allowlist) {
        return Decision::Skip("address is allowlisted");
    }
    if severity > settings.propose_max_severity {
        return Decision::AlertOnly;
    }
    if settings.block_mode == BlockMode::Auto
        && severity <= settings.auto_block_max_severity
        && auto_blocks_last_hour < settings.max_auto_blocks_per_hour
    {
        return Decision::AutoBlock;
    }
    Decision::Propose
}

/// Build a Suricata drop rule for a validated IP. The free-text reason is
/// reduced to a safe character set so it cannot break out of the rule syntax.
pub fn suricata_drop_rule(ip: &IpAddr, reason: &str) -> String {
    let clean: String = reason
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || " .,:_-()".contains(c) {
                c
            } else {
                ' '
            }
        })
        .take(100)
        .collect();
    format!(
        "drop ip {ip} any -> any any (msg:\"NetSentry block: {clean}\"; sid:{sid}; rev:1;)",
        sid = rule_sid(ip)
    )
}

/// Stable SID in a private range (9,000,000 - 9,999,999) derived from the IP.
pub fn rule_sid(ip: &IpAddr) -> u32 {
    let h = Sha256::digest(ip.to_string().as_bytes());
    9_000_000 + (u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000)
}

pub fn rule_id(ip: &IpAddr) -> String {
    format!("ip-block-{ip}")
}

fn block_payload(rec: &Document, ip: &IpAddr) -> Value {
    let now = Utc::now().timestamp();
    let expires = rec
        .get_datetime("expires_at")
        .map(|d| d.timestamp_millis() / 1000)
        .unwrap_or(now + 3600);
    json!({
        "id": rec.get_object_id("_id").map(|o| o.to_hex()).unwrap_or_default(),
        "ip": ip.to_string(),
        "reason": rec.get_str("reason").unwrap_or(""),
        "severity": rec.get_i32("severity").unwrap_or(0),
        "duration_secs": (expires - now).max(1),
        "expires_at": expires,
        "apply_suricata_rule": true,
    })
}

fn send_block(state: &AppState, tenant_id: &str, rec: &Document, ip: &IpAddr, only: Option<&str>) {
    let payload = block_payload(rec, ip);
    let rule = json!({
        "rule_id": rule_id(ip),
        "action": "add",
        "suricata_rule": suricata_drop_rule(ip, rec.get_str("reason").unwrap_or("")),
        "description": rec.get_str("reason").unwrap_or(""),
    });
    match only {
        Some(sensor) => {
            state.registry.send_to_sensor(sensor, "block_command", &payload);
            state.registry.send_to_sensor(sensor, "rule_update", &rule);
        }
        None => {
            state.registry.send_to_tenant(tenant_id, "block_command", &payload);
            state.registry.send_to_tenant(tenant_id, "rule_update", &rule);
        }
    }
}

fn send_unblock(state: &AppState, tenant_id: &str, id: &str, ip: &IpAddr, reason: &str) {
    state.registry.send_to_tenant(
        tenant_id,
        "unblock_command",
        &json!({ "id": id, "ip": ip.to_string(), "reason": reason }),
    );
    state.registry.send_to_tenant(
        tenant_id,
        "rule_update",
        &json!({ "rule_id": rule_id(ip), "action": "remove", "description": reason }),
    );
}

pub struct NewBlock<'a> {
    pub tenant_id: &'a str,
    pub sensor_id: Option<&'a str>,
    pub ip: IpAddr,
    pub reason: String,
    pub severity: u8,
    pub source: &'a str,
    pub actor: Option<&'a str>,
}

/// Insert a block record (pending or active). Returns `None` if an open
/// (pending/active) block for the same tenant+IP already exists.
pub async fn create_block(
    state: &AppState,
    nb: NewBlock<'_>,
    active: bool,
    auto: bool,
    ttl_hours: u32,
) -> ApiResult<Option<Document>> {
    let coll = state.store.coll(BLOCKED_IPS);
    let ip_s = nb.ip.to_string();
    if coll
        .find_one(doc! { "tenant_id": nb.tenant_id, "ip": &ip_s, "status": { "$in": ["pending", "active"] } })
        .await?
        .is_some()
    {
        return Ok(None);
    }
    let now = Utc::now();
    let mut rec = doc! {
        "tenant_id": nb.tenant_id,
        "ip": &ip_s,
        "reason": nb.reason.chars().take(300).collect::<String>(),
        "severity": i32::from(nb.severity),
        "source": nb.source,
        "status": if active { "active" } else { "pending" },
        "auto": auto,
        "ttl_hours": i64::from(ttl_hours),
        "created_at": bdt(now),
        "updated_at": bdt(now),
        "expires_at": bdt(now + Duration::hours(i64::from(ttl_hours))),
    };
    if let Some(s) = nb.sensor_id {
        rec.insert("sensor_id", s);
    }
    if let Some(a) = nb.actor {
        rec.insert("created_by", a);
    }
    let res = coll.insert_one(&rec).await?;
    rec.insert("_id", res.inserted_id);
    Metrics::inc(&state.metrics.blocks_created, 1);
    if active {
        if auto {
            Metrics::inc(&state.metrics.blocks_auto, 1);
        }
        send_block(state, nb.tenant_id, &rec, &nb.ip, None);
        state.notify_dashboard(
            nb.tenant_id,
            json!({ "type": "block_active", "block": doc_to_json(&rec) }),
        );
    } else {
        state.notify_dashboard(
            nb.tenant_id,
            json!({ "type": "block_pending", "block": doc_to_json(&rec) }),
        );
    }
    Ok(Some(rec))
}

pub async fn auto_blocks_last_hour(state: &AppState, tenant_id: &str) -> u32 {
    let since = bdt(Utc::now() - Duration::hours(1));
    state
        .store
        .coll(BLOCKED_IPS)
        .count_documents(doc! { "tenant_id": tenant_id, "auto": true, "created_at": { "$gte": since } })
        .await
        .map(|n| n.min(u64::from(u32::MAX)) as u32)
        .unwrap_or(0)
}

/// Apply the tenant's policy to a finding: store a proposal, auto-block, or do nothing.
pub async fn handle_finding(
    state: &AppState,
    ident: &SensorIdentity,
    settings: &TenantSettings,
    finding: &Finding,
) -> Decision {
    let recent = if settings.block_mode == BlockMode::Auto && finding.severity <= settings.auto_block_max_severity {
        auto_blocks_last_hour(state, &ident.tenant_id).await
    } else {
        0
    };
    let decision = decide(settings, &finding.offender, finding.severity, recent);
    let (active, auto) = match decision {
        Decision::AutoBlock => (true, true),
        Decision::Propose => (false, false),
        _ => return decision,
    };
    let reason = format!("{} [{}]", finding.signature, severity_label(finding.severity));
    let nb = NewBlock {
        tenant_id: &ident.tenant_id,
        sensor_id: Some(&ident.sensor_id),
        ip: finding.offender,
        reason,
        severity: finding.severity,
        source: finding.source.as_str(),
        actor: None,
    };
    if let Err(e) = create_block(state, nb, active, auto, settings.block_ttl_hours).await {
        tracing::warn!("creating block for {} failed: {:?}", finding.offender, e);
    }
    decision
}

fn parse_oid(id: &str) -> ApiResult<ObjectId> {
    ObjectId::parse_str(id).map_err(|_| ApiError::BadRequest("invalid block id".into()))
}

fn rec_ip(rec: &Document) -> ApiResult<IpAddr> {
    rec.get_str("ip")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::internal("stored block has bad ip"))
}

/// Operator approves a pending proposal; TTL restarts from now.
pub async fn approve(state: &AppState, tenant_id: &str, id: &str, actor: &str) -> ApiResult<Document> {
    let oid = parse_oid(id)?;
    let coll = state.store.coll(BLOCKED_IPS);
    let ttl = match coll.find_one(doc! { "_id": oid, "tenant_id": tenant_id }).await? {
        Some(d) => d.get_i64("ttl_hours").unwrap_or(24),
        None => return Err(ApiError::NotFound("block not found")),
    };
    let rec = coll
        .find_one_and_update(
            doc! { "_id": oid, "tenant_id": tenant_id, "status": "pending" },
            doc! { "$set": {
                "status": "active", "approved_by": actor,
                "updated_at": bdt_now(),
                "expires_at": bdt(Utc::now() + Duration::hours(ttl)),
            }},
        )
        .return_document(ReturnDocument::After)
        .await?
        .ok_or_else(|| ApiError::Conflict("block is not pending".into()))?;
    let ip = rec_ip(&rec)?;
    send_block(state, tenant_id, &rec, &ip, None);
    state.notify_dashboard(tenant_id, json!({ "type": "block_active", "block": doc_to_json(&rec) }));
    Ok(rec)
}

pub async fn reject(state: &AppState, tenant_id: &str, id: &str, actor: &str) -> ApiResult<Document> {
    let oid = parse_oid(id)?;
    let rec = state
        .store
        .coll(BLOCKED_IPS)
        .find_one_and_update(
            doc! { "_id": oid, "tenant_id": tenant_id, "status": "pending" },
            doc! { "$set": { "status": "rejected", "rejected_by": actor, "updated_at": bdt_now() } },
        )
        .return_document(ReturnDocument::After)
        .await?
        .ok_or_else(|| ApiError::Conflict("block is not pending".into()))?;
    state.notify_dashboard(
        tenant_id,
        json!({ "type": "block_removed", "block": doc_to_json(&rec) }),
    );
    Ok(rec)
}

/// Operator lifts an active block (or dismisses a pending one).
pub async fn remove(state: &AppState, tenant_id: &str, id: &str, actor: &str) -> ApiResult<Document> {
    let oid = parse_oid(id)?;
    let rec = state
        .store
        .coll(BLOCKED_IPS)
        .find_one_and_update(
            doc! { "_id": oid, "tenant_id": tenant_id, "status": { "$in": ["active", "pending"] } },
            doc! { "$set": { "status": "removed", "removed_by": actor, "updated_at": bdt_now() } },
        )
        .return_document(ReturnDocument::After)
        .await?
        .ok_or(ApiError::NotFound("no open block with that id"))?;
    let ip = rec_ip(&rec)?;
    send_unblock(state, tenant_id, id, &ip, "removed by operator");
    state.notify_dashboard(
        tenant_id,
        json!({ "type": "block_removed", "block": doc_to_json(&rec) }),
    );
    Ok(rec)
}

/// Manual operator block (explicit action): active immediately, but still
/// refuses addresses that are never blockable or allowlisted.
pub async fn manual_block(
    state: &AppState,
    tenant_id: &str,
    settings: &TenantSettings,
    ip: IpAddr,
    reason: String,
    ttl_hours: Option<u32>,
    actor: &str,
) -> ApiResult<Document> {
    if never_blockable(&ip) {
        return Err(ApiError::BadRequest("address is never blockable".into()));
    }
    if is_allowlisted(&ip, &settings.allowlist) {
        return Err(ApiError::Conflict(
            "address is allowlisted; remove it from the allowlist first".into(),
        ));
    }
    let ttl = ttl_hours.unwrap_or(settings.block_ttl_hours).clamp(1, 720);
    let nb = NewBlock {
        tenant_id,
        sensor_id: None,
        ip,
        reason,
        severity: 2,
        source: "manual",
        actor: Some(actor),
    };
    create_block(state, nb, true, false, ttl)
        .await?
        .ok_or_else(|| ApiError::Conflict("an open block for this address already exists".into()))
}

/// Re-send active blocks to a (re)connecting sensor.
pub async fn replay_active(state: &AppState, ident: &SensorIdentity) {
    let filter = doc! { "tenant_id": &ident.tenant_id, "status": "active", "expires_at": { "$gt": bdt_now() } };
    let Ok(cursor) = state.store.coll(BLOCKED_IPS).find(filter).await else {
        return;
    };
    let recs: Vec<Document> = cursor.try_collect().await.unwrap_or_default();
    for rec in recs {
        if let Ok(ip) = rec_ip(&rec) {
            send_block(state, &ident.tenant_id, &rec, &ip, Some(&ident.sensor_id));
        }
    }
}

/// Lift expired blocks every minute.
pub fn spawn_expiry_loop(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            state.tracker.prune(Utc::now(), 3600);
            if let Err(e) = expire_once(&state, Utc::now()).await {
                tracing::warn!("block expiry pass failed: {e:?}");
            }
        }
    });
}

pub async fn expire_once(state: &AppState, now: DateTime<Utc>) -> ApiResult<usize> {
    let coll = state.store.coll(BLOCKED_IPS);
    let filter = doc! { "status": "active", "expires_at": { "$lt": bdt(now) } };
    let expired: Vec<Document> = coll.find(filter.clone()).await?.try_collect().await?;
    if expired.is_empty() {
        return Ok(0);
    }
    coll.update_many(filter, doc! { "$set": { "status": "expired", "updated_at": bdt(now) } })
        .await?;
    for rec in &expired {
        if let (Ok(ip), Ok(tenant)) = (rec_ip(rec), rec.get_str("tenant_id")) {
            let id = rec.get_object_id("_id").map(|o| o.to_hex()).unwrap_or_default();
            send_unblock(state, tenant, &id, &ip, "expired");
            state.notify_dashboard(tenant, json!({ "type": "block_removed", "block": doc_to_json(rec) }));
        }
    }
    Ok(expired.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn auto_settings() -> TenantSettings {
        TenantSettings {
            block_mode: BlockMode::Auto,
            ..Default::default()
        }
    }

    #[test]
    fn default_mode_never_auto_blocks() {
        let s = TenantSettings::default();
        assert_eq!(decide(&s, &ip("203.0.113.9"), 1, 0), Decision::Propose);
        assert_eq!(decide(&s, &ip("203.0.113.9"), 2, 0), Decision::Propose);
        assert_eq!(decide(&s, &ip("203.0.113.9"), 3, 0), Decision::AlertOnly);
    }

    #[test]
    fn auto_mode_only_blocks_critical() {
        let s = auto_settings();
        assert_eq!(decide(&s, &ip("203.0.113.9"), 1, 0), Decision::AutoBlock);
        assert_eq!(decide(&s, &ip("203.0.113.9"), 2, 0), Decision::Propose);
        assert_eq!(decide(&s, &ip("203.0.113.9"), 4, 0), Decision::AlertOnly);
    }

    #[test]
    fn rate_cap_downgrades_to_proposal() {
        let s = TenantSettings {
            max_auto_blocks_per_hour: 5,
            ..auto_settings()
        };
        assert_eq!(decide(&s, &ip("203.0.113.9"), 1, 4), Decision::AutoBlock);
        assert_eq!(decide(&s, &ip("203.0.113.9"), 1, 5), Decision::Propose);
    }

    #[test]
    fn allowlist_and_special_addresses_are_never_blocked() {
        let mut s = auto_settings();
        s.allowlist.push("203.0.113.0/24".into());
        assert!(matches!(decide(&s, &ip("203.0.113.9"), 1, 0), Decision::Skip(_)));
        assert!(matches!(decide(&s, &ip("192.168.1.2"), 1, 0), Decision::Skip(_)));
        // Even with an empty allowlist the special ranges are protected.
        s.allowlist.clear();
        for a in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "169.254.1.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(matches!(decide(&s, &ip(a), 1, 0), Decision::Skip(_)), "{a}");
        }
        assert_eq!(decide(&s, &ip("192.168.1.2"), 1, 0), Decision::AutoBlock);
    }

    #[test]
    fn suricata_rule_is_sanitised() {
        let r = suricata_drop_rule(&ip("203.0.113.9"), "evil\"; sid:1; drop ip any any -> any any (msg:\"x");
        assert!(r.starts_with("drop ip 203.0.113.9 any -> any any (msg:\"NetSentry block: "));
        // exactly one closing quote for msg, no injected quote or semicolon in the reason
        let msg = r.split("msg:\"").nth(1).unwrap().split('"').next().unwrap();
        assert!(!msg.contains(';') && !msg.contains('"'));
        assert_eq!(r.matches('"').count(), 2);
        assert!(rule_sid(&ip("203.0.113.9")) >= 9_000_000);
        assert_eq!(rule_sid(&ip("203.0.113.9")), rule_sid(&ip("203.0.113.9")));
    }

    #[test]
    fn block_payload_has_expected_fields() {
        let exp = Utc::now() + Duration::hours(1);
        let rec = doc! {
            "_id": ObjectId::new(), "reason": "r", "severity": 2i32, "expires_at": bdt(exp),
        };
        let p = block_payload(&rec, &ip("203.0.113.9"));
        assert_eq!(p["ip"], "203.0.113.9");
        let d = p["duration_secs"].as_i64().unwrap();
        assert!((3500..=3601).contains(&d));
        assert_eq!(p["apply_suricata_rule"], true);
    }
}
