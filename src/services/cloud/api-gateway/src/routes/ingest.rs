//! Sensor ingest endpoints (X-API-Key authenticated).

use crate::auth::{touch_sensor, SensorAuth};
use crate::error::{ApiError, ApiResult};
use crate::pipeline::{self, MAX_BATCH};
use crate::state::SharedState;
use crate::store::{bdt_now, TELEMETRY};
use axum::extract::State;
use axum::Json;
use mongodb::bson::{self, doc, Bson};
use serde_json::{json, Value};

/// `POST /api/traffic` - one event.
pub async fn traffic(
    State(state): State<SharedState>,
    SensorAuth(ident): SensorAuth,
    Json(event): Json<Value>,
) -> ApiResult<Json<Value>> {
    let event_id = event.get("id").and_then(|v| v.as_str()).map(str::to_string);
    let s = pipeline::process_events(&state, &ident, vec![event]).await;
    if s.received == s.rejected {
        return Err(ApiError::BadRequest("invalid event".into()));
    }
    Ok(Json(
        json!({ "success": true, "event_id": event_id, "stored": s.stored, "alerts": s.alerts }),
    ))
}

/// `POST /api/traffic/batch` - array of events. Invalid entries are skipped and counted.
pub async fn traffic_batch(
    State(state): State<SharedState>,
    SensorAuth(ident): SensorAuth,
    Json(events): Json<Vec<Value>>,
) -> ApiResult<Json<Value>> {
    if events.len() > MAX_BATCH {
        return Err(ApiError::BadRequest(format!("batch too large (max {MAX_BATCH})")));
    }
    if events.is_empty() {
        return Ok(Json(
            json!({ "success": true, "stored": 0, "received": 0, "rejected": 0 }),
        ));
    }
    let s = pipeline::process_events(&state, &ident, events).await;
    Ok(Json(json!({
        "success": true, "received": s.received, "stored": s.stored, "rejected": s.rejected, "alerts": s.alerts
    })))
}

/// `POST /api/telemetry` - sensor health metrics (free-form JSON object).
pub async fn telemetry(
    State(state): State<SharedState>,
    SensorAuth(ident): SensorAuth,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    if !body.is_object() {
        return Err(ApiError::BadRequest("telemetry must be a JSON object".into()));
    }
    let data = bson::to_bson(&body).unwrap_or(Bson::Null);
    state
        .store
        .coll(TELEMETRY)
        .insert_one(doc! {
            "tenant_id": &ident.tenant_id,
            "sensor_id": &ident.sensor_id,
            "data": data,
            "received_at": bdt_now(),
        })
        .await?;
    touch_sensor(&state, &ident.sensor_id).await;
    state.notify_dashboard(
        &ident.tenant_id,
        json!({ "type": "telemetry", "sensor_id": ident.sensor_id, "data": body }),
    );
    Ok(Json(json!({ "success": true, "sensor_id": ident.sensor_id })))
}
