//! Unauthenticated endpoints: health, metrics and sensor enrollment.

use super::client_ip;
use crate::auth::hash_api_key;
use crate::error::{ApiError, ApiResult};
use crate::models::{EnrollRequest, EnrollResponse};
use crate::state::{Metrics, SharedState};
use crate::store::{bdt, bdt_now, ENROLLMENT_TOKENS, SENSORS, TENANTS};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::options::ReturnDocument;
use rand::RngCore;
use serde_json::{json, Value};
use std::time::Duration;

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "netsentry-gateway", "version": env!("CARGO_PKG_VERSION") }))
}

/// Prometheus text format. Not routed publicly by the reverse proxy.
pub async fn metrics(State(state): State<SharedState>) -> String {
    let feed = state.feed.status()["entries"].as_u64().unwrap_or(0);
    state.metrics.render(state.registry.len(), feed)
}

pub(crate) fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub(crate) fn valid_hostname(h: &str) -> bool {
    !h.is_empty() && h.len() <= 128 && h.chars().all(|c| c.is_ascii_alphanumeric() || "-._ ".contains(c))
}

/// `POST /api/v1/sensors/enroll` - exchange a one-time(ish) enrollment token for
/// per-sensor credentials.
pub async fn enroll(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    let ip = client_ip(&headers);
    if !state
        .limiter
        .allow(&format!("enroll:{ip}"), 10, Duration::from_secs(60))
        .await
    {
        return Err(ApiError::TooManyRequests);
    }
    let token = headers
        .get("x-enrollment-token")
        .and_then(|v| v.to_str().ok())
        .filter(|t| !t.is_empty() && t.len() <= 128)
        .ok_or(ApiError::Unauthorized("missing X-Enrollment-Token header"))?;
    if req.mode != "span" && req.mode != "inline" {
        return Err(ApiError::BadRequest("mode must be \"span\" or \"inline\"".into()));
    }
    if !valid_hostname(&req.hostname) {
        return Err(ApiError::BadRequest("invalid hostname".into()));
    }
    if req.arch.len() > 32 {
        return Err(ApiError::BadRequest("invalid arch".into()));
    }

    // Atomically consume one use of a valid, unexpired, unrevoked token.
    let tokens = state.store.coll(ENROLLMENT_TOKENS);
    let token_hash = hash_api_key(token);
    let consumed = tokens
        .find_one_and_update(
            doc! {
                "token_hash": &token_hash,
                "revoked": { "$ne": true },
                "expires_at": { "$gt": bdt_now() },
                "$expr": { "$lt": ["$uses", "$max_uses"] },
            },
            doc! { "$inc": { "uses": 1 }, "$set": { "last_used_at": bdt_now() } },
        )
        .return_document(ReturnDocument::After)
        .await?
        .ok_or(ApiError::Unauthorized("invalid, expired or exhausted enrollment token"))?;
    let tenant_id = consumed.get_str("tenant_id").map_err(ApiError::internal)?.to_string();

    let refund = || async {
        let _ = tokens
            .update_one(doc! { "token_hash": &token_hash }, doc! { "$inc": { "uses": -1 } })
            .await;
    };

    // The tenant must exist, not be suspended, and have sensor capacity.
    let tenant = match ObjectId::parse_str(&tenant_id) {
        Ok(oid) => state.store.coll(TENANTS).find_one(doc! { "_id": oid }).await?,
        Err(_) => None,
    };
    let Some(tenant) = tenant else {
        refund().await;
        return Err(ApiError::Unauthorized("enrollment token tenant no longer exists"));
    };
    if tenant.get_str("status").unwrap_or("active") == "suspended" {
        refund().await;
        return Err(ApiError::Forbidden("tenant is suspended"));
    }
    let max = tenant
        .get_i32("maxSensors")
        .map(i64::from)
        .or_else(|_| tenant.get_i64("maxSensors"))
        .unwrap_or(1);
    let current = state
        .store
        .coll(SENSORS)
        .count_documents(doc! { "tenantId": &tenant_id, "status": { "$ne": "revoked" } })
        .await?;
    if current as i64 >= max {
        refund().await;
        return Err(ApiError::Forbidden("sensor limit reached for this plan"));
    }

    let sensor_id = uuid::Uuid::new_v4().to_string();
    let api_key = format!("nss_{}", random_hex(24));
    let command_secret = random_hex(32);
    let now = Utc::now();
    state
        .store
        .coll(SENSORS)
        .insert_one(doc! {
            "sensorId": &sensor_id,
            "name": &req.hostname,
            "tenantId": &tenant_id,
            "apiKeyHash": hash_api_key(&api_key),
            "commandHmacSecret": &command_secret,
            "status": "pending",
            "hostname": &req.hostname,
            "arch": &req.arch,
            "mode": &req.mode,
            "enrolledAt": bdt(now),
            "enrollmentTokenId": consumed.get_object_id("_id").ok(),
            "createdAt": bdt(now),
            "updatedAt": bdt(now),
            "eventsCount": 0,
            "alertsCount": 0,
        })
        .await?;
    if let Ok(oid) = ObjectId::parse_str(&tenant_id) {
        let _ = state
            .store
            .coll(TENANTS)
            .update_one(doc! { "_id": oid }, doc! { "$inc": { "sensorCount": 1 } })
            .await;
    }
    Metrics::inc(&state.metrics.enrollments, 1);
    tracing::info!(
        "enrolled sensor {sensor_id} for tenant {tenant_id} ({}, {})",
        req.hostname,
        req.mode
    );

    Ok(Json(EnrollResponse {
        sensor_id,
        tenant_id,
        api_key,
        command_hmac_secret: command_secret,
        ingest_url: state.cfg.public_url.clone(),
        ws_url: state.cfg.ws_url(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_validation() {
        assert!(valid_hostname("pi-sensor.local"));
        assert!(valid_hostname("Office Sensor 1"));
        assert!(!valid_hostname(""));
        assert!(!valid_hostname("a;rm -rf"));
        assert!(!valid_hostname(&"a".repeat(129)));
    }

    #[test]
    fn random_hex_is_unique_and_sized() {
        let a = random_hex(24);
        assert_eq!(a.len(), 48);
        assert_ne!(a, random_hex(24));
    }
}
