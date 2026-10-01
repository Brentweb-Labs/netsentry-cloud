//! HTTP router.
//!
//! * Sensor-facing: `/api/v1/sensors/enroll`, `/api/traffic`, `/api/traffic/batch`,
//!   `/api/telemetry`, `/ws/raspi` (X-API-Key / enrollment token headers).
//! * Dashboard-facing: `/api/v1/*` (Bearer JWT from console-api) and `/ws`.

mod api;
mod ingest;
mod public;

use crate::state::SharedState;
use crate::ws;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method};
use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

pub fn router(state: SharedState) -> Router {
    let ingest_routes = Router::new()
        .route("/api/traffic", post(ingest::traffic))
        .route("/api/traffic/batch", post(ingest::traffic_batch))
        .route("/api/telemetry", post(ingest::telemetry))
        .route("/api/prevention/blocked", get(ingest::active_blocks))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024));

    let small = Router::new()
        .route("/", get(public::health))
        .route("/health", get(public::health))
        .route("/api/health", get(public::health))
        .route("/metrics", get(public::metrics))
        .route("/api/v1/sensors/enroll", post(public::enroll))
        .route("/api/v1/overview", get(api::overview))
        .route("/api/v1/alerts", get(api::alerts))
        .route("/api/v1/blocked", get(api::blocked_list).post(api::block_create))
        .route("/api/v1/blocked/{id}/approve", post(api::block_approve))
        .route("/api/v1/blocked/{id}/reject", post(api::block_reject))
        .route("/api/v1/blocked/{id}", delete(api::block_remove))
        .route("/api/v1/sensors", get(api::sensors))
        .route("/api/v1/settings", get(api::settings_get).put(api::settings_put))
        .route("/api/v1/threat-intel", get(api::threat_intel))
        .route("/ws", get(ws::dashboard_ws))
        .route("/ws/raspi", get(ws::sensor_ws))
        .route("/ws/packets", get(ws::packets_ws))
        .layer(DefaultBodyLimit::max(64 * 1024));

    let mut app = small
        .merge(ingest_routes)
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http());

    if !state.cfg.cors_origins.is_empty() {
        let origins: Vec<HeaderValue> = state.cfg.cors_origins.iter().filter_map(|o| o.parse().ok()).collect();
        app = app.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE]),
        );
    }
    app
}

/// Best-effort client address behind the reverse proxy.
pub(crate) fn client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
