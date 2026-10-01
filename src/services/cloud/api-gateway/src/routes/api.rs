//! Dashboard API (Bearer JWT). Every query is scoped to the caller's tenant.

use crate::auth::UserAuth;
use crate::error::{ApiError, ApiResult};
use crate::models::Pagination;
use crate::prevention;
use crate::settings::{self, TenantSettings};
use crate::state::SharedState;
use crate::store::{bdt, doc_to_json, doc_to_json_hiding, ALERTS, BLOCKED_IPS, EVENTS, SENSORS};
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{Duration, Utc};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Document};
use serde::Deserialize;
use serde_json::{json, Value};

const SENSOR_HIDDEN: &[&str] = &["apiKey", "apiKeyHash", "commandHmacSecret", "__v"];

pub async fn overview(State(state): State<SharedState>, UserAuth(c): UserAuth) -> ApiResult<Json<Value>> {
    let t = &c.tenant_id;
    let since = bdt(Utc::now() - Duration::hours(24));
    let alerts = state.store.coll(ALERTS);
    let blocked = state.store.coll(BLOCKED_IPS);

    let events_24h = state
        .store
        .coll(EVENTS)
        .count_documents(doc! { "tenant_id": t, "ts": { "$gte": since } })
        .await?;
    let alerts_24h = alerts
        .count_documents(doc! { "tenant_id": t, "ts": { "$gte": since } })
        .await?;
    let active_blocks = blocked
        .count_documents(doc! { "tenant_id": t, "status": "active" })
        .await?;
    let pending_blocks = blocked
        .count_documents(doc! { "tenant_id": t, "status": "pending" })
        .await?;
    let sensors_total = state
        .store
        .coll(SENSORS)
        .count_documents(doc! { "tenantId": t, "status": { "$ne": "revoked" } })
        .await?;

    let by_severity: Vec<Document> = alerts
        .aggregate([
            doc! { "$match": { "tenant_id": t, "ts": { "$gte": since } } },
            doc! { "$group": { "_id": "$severity", "count": { "$sum": 1 } } },
        ])
        .await?
        .try_collect()
        .await?;
    let top_sources: Vec<Document> = alerts
        .aggregate([
            doc! { "$match": { "tenant_id": t, "ts": { "$gte": since }, "offender_ip": { "$exists": true } } },
            doc! { "$group": { "_id": "$offender_ip", "count": { "$sum": 1 } } },
            doc! { "$sort": { "count": -1 } },
            doc! { "$limit": 10 },
        ])
        .await?
        .try_collect()
        .await?;
    let per_hour: Vec<Document> = alerts
        .aggregate([
            doc! { "$match": { "tenant_id": t, "ts": { "$gte": since } } },
            doc! { "$group": { "_id": { "$dateTrunc": { "date": "$ts", "unit": "hour" } }, "count": { "$sum": 1 } } },
            doc! { "$sort": { "_id": 1 } },
        ])
        .await?
        .try_collect()
        .await?;

    let mut sev = json!({ "critical": 0, "high": 0, "medium": 0, "low": 0 });
    for d in &by_severity {
        let label = crate::detection::severity_label(d.get_i32("_id").unwrap_or(4) as u8);
        sev[label] = json!(d
            .get_i32("count")
            .map(i64::from)
            .or_else(|_| d.get_i64("count"))
            .unwrap_or(0));
    }
    let conv = |docs: &[Document]| -> Vec<Value> {
        docs.iter()
            .map(|d| {
                let mut v = doc_to_json(d);
                v["key"] = v["id"].take();
                v
            })
            .collect()
    };

    Ok(Json(json!({
        "events_24h": events_24h,
        "alerts_24h": alerts_24h,
        "alerts_by_severity": sev,
        "blocked": { "active": active_blocks, "pending": pending_blocks },
        "sensors": { "total": sensors_total, "online": state.registry.online_for_tenant(t) },
        "top_sources": conv(&top_sources),
        "alerts_per_hour": conv(&per_hour),
        "threat_feed": state.feed.status(),
    })))
}

#[derive(Deserialize)]
pub struct AlertsQuery {
    #[serde(flatten)]
    page: Pagination,
    severity: Option<u8>,
    ip: Option<String>,
}

pub async fn alerts(
    State(state): State<SharedState>,
    UserAuth(c): UserAuth,
    Query(q): Query<AlertsQuery>,
) -> ApiResult<Json<Value>> {
    let (page, limit) = q.page.resolve();
    let mut filter = doc! { "tenant_id": &c.tenant_id };
    if let Some(s) = q.severity {
        filter.insert("severity", i32::from(s));
    }
    if let Some(ip) = q.ip.filter(|s| !s.is_empty()) {
        filter.insert(
            "$or",
            vec![
                doc! { "src_ip": &ip },
                doc! { "dest_ip": &ip },
                doc! { "offender_ip": &ip },
            ],
        );
    }
    let coll = state.store.coll(ALERTS);
    let total = coll.count_documents(filter.clone()).await?;
    let items: Vec<Document> = coll
        .find(filter)
        .sort(doc! { "ts": -1 })
        .skip((page - 1) * limit)
        .limit(limit as i64)
        .await?
        .try_collect()
        .await?;
    Ok(Json(json!({
        "items": items.iter().map(doc_to_json).collect::<Vec<_>>(),
        "total": total, "page": page, "limit": limit,
    })))
}

#[derive(Deserialize)]
pub struct BlockedQuery {
    status: Option<String>,
}

pub async fn blocked_list(
    State(state): State<SharedState>,
    UserAuth(c): UserAuth,
    Query(q): Query<BlockedQuery>,
) -> ApiResult<Json<Value>> {
    let mut filter = doc! { "tenant_id": &c.tenant_id };
    match q.status.as_deref() {
        None | Some("open") => {
            filter.insert("status", doc! { "$in": ["pending", "active"] });
        }
        Some("all") => {}
        Some(s @ ("pending" | "active" | "expired" | "rejected" | "removed")) => {
            filter.insert("status", s);
        }
        Some(_) => return Err(ApiError::BadRequest("unknown status".into())),
    }
    let items: Vec<Document> = state
        .store
        .coll(BLOCKED_IPS)
        .find(filter)
        .sort(doc! { "created_at": -1 })
        .limit(500)
        .await?
        .try_collect()
        .await?;
    Ok(Json(
        json!({ "items": items.iter().map(doc_to_json).collect::<Vec<_>>() }),
    ))
}

#[derive(Deserialize)]
pub struct CreateBlock {
    ip: String,
    reason: Option<String>,
    duration_hours: Option<u32>,
}

pub async fn block_create(
    State(state): State<SharedState>,
    auth: UserAuth,
    Json(req): Json<CreateBlock>,
) -> ApiResult<Json<Value>> {
    auth.require_write()?;
    let ip = req
        .ip
        .trim()
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid ip".into()))?;
    let tenant = auth.0.tenant_id.clone();
    let s = settings::load(&state, &tenant).await;
    let reason = req
        .reason
        .filter(|r| !r.trim().is_empty())
        .unwrap_or_else(|| "Manual block".into());
    let rec = prevention::manual_block(&state, &tenant, &s, ip, reason, req.duration_hours, &auth.0.email).await?;
    Ok(Json(doc_to_json(&rec)))
}

pub async fn block_approve(
    State(state): State<SharedState>,
    auth: UserAuth,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    auth.require_write()?;
    let rec = prevention::approve(&state, &auth.0.tenant_id, &id, &auth.0.email).await?;
    Ok(Json(doc_to_json(&rec)))
}

pub async fn block_reject(
    State(state): State<SharedState>,
    auth: UserAuth,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    auth.require_write()?;
    let rec = prevention::reject(&state, &auth.0.tenant_id, &id, &auth.0.email).await?;
    Ok(Json(doc_to_json(&rec)))
}

pub async fn block_remove(
    State(state): State<SharedState>,
    auth: UserAuth,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    auth.require_write()?;
    let rec = prevention::remove(&state, &auth.0.tenant_id, &id, &auth.0.email).await?;
    Ok(Json(doc_to_json(&rec)))
}

pub async fn sensors(State(state): State<SharedState>, UserAuth(c): UserAuth) -> ApiResult<Json<Value>> {
    let docs: Vec<Document> = state
        .store
        .coll(SENSORS)
        .find(doc! { "tenantId": &c.tenant_id, "status": { "$ne": "revoked" } })
        .sort(doc! { "createdAt": -1 })
        .await?
        .try_collect()
        .await?;
    let items: Vec<Value> = docs
        .iter()
        .map(|d| {
            let mut v = doc_to_json_hiding(d, SENSOR_HIDDEN);
            let online = d
                .get_str("sensorId")
                .map(|s| state.registry.is_online(s))
                .unwrap_or(false);
            v["online"] = json!(online);
            v
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

pub async fn settings_get(State(state): State<SharedState>, UserAuth(c): UserAuth) -> Json<TenantSettings> {
    Json(settings::load(&state, &c.tenant_id).await)
}

pub async fn settings_put(
    State(state): State<SharedState>,
    auth: UserAuth,
    Json(new): Json<TenantSettings>,
) -> ApiResult<Json<TenantSettings>> {
    if !auth.0.role.can_admin() {
        return Err(ApiError::Forbidden("tenant admin role required"));
    }
    let saved = settings::save(&state, &auth.0.tenant_id, new)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(saved))
}

pub async fn threat_intel(State(state): State<SharedState>, _auth: UserAuth) -> Json<Value> {
    let mut s = state.feed.status();
    s["sources"] = json!(state.cfg.threat_feed_urls);
    Json(s)
}
