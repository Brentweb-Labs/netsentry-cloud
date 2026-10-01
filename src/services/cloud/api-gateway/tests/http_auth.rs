//! Router-level auth tests. These never reach MongoDB: every request is
//! rejected (or answered) before a query is issued, so a lazily-connecting
//! client pointing at an unused port is enough.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use jsonwebtoken::{encode, EncodingKey, Header};
use netsentry_gateway::config::Config;
use netsentry_gateway::ratelimit::RateLimiter;
use netsentry_gateway::routes::router;
use netsentry_gateway::state::AppState;
use netsentry_gateway::store::Store;
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";

async fn app() -> axum::Router {
    let cfg = Config {
        mongodb_uri: "mongodb://127.0.0.1:1".into(),
        db_name: "t".into(),
        jwt_secret: SECRET.into(),
        port: 0,
        public_url: "https://gw.example".into(),
        redis_url: None,
        threat_feed_urls: vec![],
        threat_feed_interval_secs: 3600,
        event_retention_days: 1,
        cors_origins: vec![],
    };
    let client = mongodb::Client::with_uri_str(&cfg.mongodb_uri).await.unwrap();
    let state = AppState::new(cfg.clone(), Store::new(client.database("t")), RateLimiter::in_memory());
    router(state)
}

fn jwt(role: &str) -> String {
    let exp = chrono::Utc::now().timestamp() + 600;
    encode(
        &Header::default(),
        &serde_json::json!({"sub": "u", "email": "u@x.y", "role": role, "tenantId": "t1", "exp": exp}),
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap()
}

async fn status(req: Request<Body>) -> StatusCode {
    app().await.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn health_is_public() {
    let r = Request::get("/health").body(Body::empty()).unwrap();
    assert_eq!(status(r).await, StatusCode::OK);
}

#[tokio::test]
async fn ingest_requires_api_key_header() {
    let get = Request::get("/api/prevention/blocked").body(Body::empty()).unwrap();
    assert_eq!(status(get).await, StatusCode::UNAUTHORIZED);
    for path in ["/api/traffic", "/api/traffic/batch", "/api/telemetry"] {
        let r = Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(status(r).await, StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn api_key_in_query_string_is_not_accepted() {
    let r = Request::post("/api/traffic?api_key=nss_abc&apiKey=nss_abc&key=nss_abc")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(status(r).await, StatusCode::UNAUTHORIZED);
    let get = Request::get("/api/prevention/blocked?api_key=nss_abc")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status(get).await, StatusCode::UNAUTHORIZED);
    let ws = Request::get("/ws/raspi?api_key=nss_abc")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status(ws).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn dashboard_api_requires_valid_jwt() {
    for path in [
        "/api/v1/overview",
        "/api/v1/alerts",
        "/api/v1/blocked",
        "/api/v1/sensors",
        "/api/v1/settings",
    ] {
        let r = Request::get(path).body(Body::empty()).unwrap();
        assert_eq!(status(r).await, StatusCode::UNAUTHORIZED, "{path} without token");
        let bad = Request::get(path)
            .header("authorization", "Bearer nope")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(bad).await, StatusCode::UNAUTHORIZED, "{path} bad token");
    }
}

#[tokio::test]
async fn viewers_cannot_change_state() {
    let t = jwt("viewer");
    let block = Request::post("/api/v1/blocked")
        .header("authorization", format!("Bearer {t}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"ip":"203.0.113.9"}"#))
        .unwrap();
    assert_eq!(status(block).await, StatusCode::FORBIDDEN);
    let approve = Request::post("/api/v1/blocked/64b000000000000000000000/approve")
        .header("authorization", format!("Bearer {t}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(status(approve).await, StatusCode::FORBIDDEN);
    let op = jwt("operator");
    let settings = Request::put("/api/v1/settings")
        .header("authorization", format!("Bearer {op}"))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        status(settings).await,
        StatusCode::FORBIDDEN,
        "operators may not change settings"
    );
}

#[tokio::test]
async fn enroll_needs_token_and_valid_body() {
    let no_token = Request::post("/api/v1/sensors/enroll")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"hostname":"pi","arch":"arm64","mode":"span"}"#))
        .unwrap();
    assert_eq!(status(no_token).await, StatusCode::UNAUTHORIZED);
    let bad_mode = Request::post("/api/v1/sensors/enroll")
        .header("content-type", "application/json")
        .header("x-enrollment-token", "nse_x")
        .body(Body::from(r#"{"hostname":"pi","arch":"arm64","mode":"tap"}"#))
        .unwrap();
    assert_eq!(status(bad_mode).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn enroll_is_rate_limited_per_client() {
    let app = app().await;
    let mut last = StatusCode::OK;
    for _ in 0..12 {
        let r = Request::post("/api/v1/sensors/enroll")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "198.51.100.77")
            .body(Body::from(r#"{"hostname":"pi","arch":"arm64","mode":"span"}"#))
            .unwrap();
        last = app.clone().oneshot(r).await.unwrap().status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn dashboard_ws_rejects_missing_or_bad_token() {
    for uri in ["/ws", "/ws?token=bad"] {
        let r = Request::get(uri)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(r).await, StatusCode::UNAUTHORIZED, "{uri}");
    }
}
