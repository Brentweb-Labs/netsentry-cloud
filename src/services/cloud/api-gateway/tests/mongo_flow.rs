//! End-to-end gateway flow against a real MongoDB.
//!
//! Skipped unless `TEST_MONGODB_URI` is set (CI provides a MongoDB service):
//!   TEST_MONGODB_URI=mongodb://localhost:27017 cargo test --test mongo_flow
//!
//! Flow: enrollment token -> enroll -> post a critical Suricata alert ->
//! alert stored + block *proposed* (manual mode) -> operator approves ->
//! sensor sync endpoint lists the block -> another tenant sees nothing.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::bson::{doc, oid::ObjectId, DateTime as BsonDateTime};
use netsentry_gateway::auth::hash_api_key;
use netsentry_gateway::config::Config;
use netsentry_gateway::ratelimit::RateLimiter;
use netsentry_gateway::routes::router;
use netsentry_gateway::state::AppState;
use netsentry_gateway::store::Store;
use serde_json::{json, Value};
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";

fn jwt(tenant: &str, role: &str) -> String {
    let exp = chrono::Utc::now().timestamp() + 600;
    encode(
        &Header::default(),
        &json!({"sub": "u1", "email": "op@example.org", "role": role, "tenantId": tenant, "exp": exp}),
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap()
}

async fn call(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn json_req(method: &str, uri: &str, headers: &[(&str, String)], body: Value) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    for (k, v) in headers {
        b = b.header(*k, v);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn enroll_ingest_approve_and_tenant_isolation() {
    let Ok(uri) = std::env::var("TEST_MONGODB_URI") else {
        eprintln!("TEST_MONGODB_URI not set; skipping");
        return;
    };
    let db_name = format!("nsg_test_{}", uuid::Uuid::new_v4().simple());
    let client = mongodb::Client::with_uri_str(&uri).await.unwrap();
    let db = client.database(&db_name);
    let store = Store::new(db.clone());
    store.ensure_indexes(1).await.unwrap();

    let cfg = Config {
        mongodb_uri: uri,
        db_name: db_name.clone(),
        jwt_secret: SECRET.into(),
        port: 0,
        public_url: "https://gw.example".into(),
        redis_url: None,
        threat_feed_urls: vec![],
        threat_feed_interval_secs: 3600,
        event_retention_days: 1,
        cors_origins: vec![],
    };
    let app = router(AppState::new(cfg, store, RateLimiter::in_memory()));

    // Seed a tenant and a single-use enrollment token (as console-api would).
    let tenant_oid = ObjectId::new();
    let tenant = tenant_oid.to_hex();
    db.collection::<mongodb::bson::Document>("tenants")
        .insert_one(doc! { "_id": tenant_oid, "name": "T", "status": "active", "maxSensors": 5 })
        .await
        .unwrap();
    let token = "nse_testtoken";
    db.collection::<mongodb::bson::Document>("enrollment_tokens")
        .insert_one(doc! {
            "tenant_id": &tenant, "token_hash": hash_api_key(token), "token_prefix": "nse_testto",
            "expires_at": BsonDateTime::from_millis(chrono::Utc::now().timestamp_millis() + 3_600_000),
            "max_uses": 1, "uses": 0, "revoked": false,
        })
        .await
        .unwrap();

    // Enroll.
    let enroll_body = json!({"hostname": "pi-1", "arch": "arm64", "mode": "span"});
    let (st, enrolled) = call(
        &app,
        json_req(
            "POST",
            "/api/v1/sensors/enroll",
            &[("x-enrollment-token", token.into())],
            enroll_body.clone(),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{enrolled}");
    assert_eq!(enrolled["tenant_id"], tenant.as_str());
    assert_eq!(enrolled["ingest_url"], "https://gw.example");
    assert_eq!(enrolled["ws_url"], "wss://gw.example/ws/raspi");
    let api_key = enrolled["api_key"].as_str().unwrap().to_string();
    let sensor_id = enrolled["sensor_id"].as_str().unwrap().to_string();
    assert!(enrolled["command_hmac_secret"].as_str().unwrap().len() >= 32);

    // The token was single use.
    let (st, _) = call(
        &app,
        json_req(
            "POST",
            "/api/v1/sensors/enroll",
            &[("x-enrollment-token", token.into())],
            enroll_body,
        ),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Ingest a critical Suricata alert from a public address.
    let event = json!({
        "source_ip": "203.0.113.50", "dest_ip": "10.0.0.5", "source_port": 4444, "dest_port": 22,
        "protocol": "tcp", "event_type": "alert",
        "payload": {"alert": {"severity": 1, "signature": "ET EXPLOIT test", "category": "Exploit", "signature_id": 2001, "action": "allowed"}}
    });
    let (st, body) = call(
        &app,
        json_req("POST", "/api/traffic", &[("x-api-key", api_key.clone())], event),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["alerts"], 1);

    // Records carry tenant_id and sensor_id.
    let stored = db
        .collection::<mongodb::bson::Document>("events")
        .find_one(doc! { "tenant_id": &tenant, "sensor_id": &sensor_id })
        .await
        .unwrap();
    assert!(stored.is_some(), "event must carry tenant and sensor");

    // Dashboard sees the alert and a *pending* proposal (manual mode is the default).
    let auth = [("authorization", format!("Bearer {}", jwt(&tenant, "operator")))];
    let (st, alerts) = call(
        &app,
        Request::get("/api/v1/alerts")
            .header("authorization", &auth[0].1)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(alerts["total"], 1);
    assert_eq!(alerts["items"][0]["severity_label"], "critical");
    assert_eq!(alerts["items"][0]["sensor_id"], sensor_id.as_str());
    let (_, pending) = call(
        &app,
        Request::get("/api/v1/blocked?status=pending")
            .header("authorization", &auth[0].1)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(pending["items"].as_array().unwrap().len(), 1);
    assert_eq!(pending["items"][0]["ip"], "203.0.113.50");
    let block_id = pending["items"][0]["id"].as_str().unwrap().to_string();

    // Nothing is enforced yet.
    let sync = || {
        Request::get("/api/prevention/blocked")
            .header("x-api-key", &api_key)
            .body(Body::empty())
            .unwrap()
    };
    let (_, before) = call(&app, sync()).await;
    assert_eq!(before["data"].as_array().unwrap().len(), 0);

    // Operator approves; sensor sync now lists it.
    let (st, _) = call(
        &app,
        json_req(
            "POST",
            &format!("/api/v1/blocked/{block_id}/approve"),
            &[("authorization", auth[0].1.clone())],
            json!({}),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (_, after) = call(&app, sync()).await;
    assert_eq!(after["data"][0]["ip"], "203.0.113.50");

    // A different tenant sees none of this.
    let other = format!("Bearer {}", jwt(&ObjectId::new().to_hex(), "tenant_admin"));
    let (_, theirs) = call(
        &app,
        Request::get("/api/v1/alerts")
            .header("authorization", &other)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(theirs["total"], 0);
    let (st, _) = call(
        &app,
        json_req(
            "POST",
            &format!("/api/v1/blocked/{block_id}/reject"),
            &[("authorization", other.clone())],
            json!({}),
        ),
    )
    .await;
    assert_ne!(st, StatusCode::OK, "cross-tenant action must fail");

    // Allowlisted (private) sources never produce a proposal.
    let private = json!({
        "source_ip": "192.168.1.9", "dest_ip": "10.0.0.5", "event_type": "alert",
        "payload": {"alert": {"severity": 1, "signature": "internal scan", "category": "x", "signature_id": 1}}
    });
    let (_, body) = call(
        &app,
        json_req("POST", "/api/traffic", &[("x-api-key", api_key.clone())], private),
    )
    .await;
    assert_eq!(body["alerts"], 1);
    let (_, pending) = call(
        &app,
        Request::get("/api/v1/blocked?status=pending")
            .header("authorization", &auth[0].1)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(pending["items"].as_array().unwrap().len(), 0);

    // Overview aggregates, sensors list, settings and telemetry-borne alerts.
    let get = |uri: &str| {
        Request::get(uri.to_string())
            .header("authorization", &auth[0].1)
            .body(Body::empty())
            .unwrap()
    };
    let (st, ov) = call(&app, get("/api/v1/overview")).await;
    assert_eq!(st, StatusCode::OK, "{ov}");
    assert_eq!(ov["alerts_24h"], 2);
    assert_eq!(ov["events_24h"], 2);
    assert_eq!(ov["blocked"]["active"], 1);
    assert_eq!(ov["alerts_by_severity"]["critical"], 2);
    assert_eq!(ov["top_sources"][0]["count"], 1);
    assert!(!ov["alerts_per_hour"].as_array().unwrap().is_empty());

    let (_, sensors) = call(&app, get("/api/v1/sensors")).await;
    assert_eq!(sensors["items"][0]["sensorId"], sensor_id.as_str());
    assert!(sensors["items"][0].get("apiKeyHash").is_none());
    assert!(sensors["items"][0].get("commandHmacSecret").is_none());

    let (st, tel) = call(
        &app,
        json_req(
            "POST",
            "/api/telemetry",
            &[("x-api-key", api_key.clone())],
            json!({"sensor_id": "spoofed", "tenant_id": "spoofed", "metrics": {"cpu": 1},
                   "alerts": [{"metric": "cpu", "severity": "critical", "message": "CPU 99%"}]}),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{tel}");
    assert_eq!(tel["alerts"], 1);
    let spoofed = db
        .collection::<mongodb::bson::Document>("telemetry")
        .find_one(doc! { "tenant_id": "spoofed" })
        .await
        .unwrap();
    assert!(spoofed.is_none(), "identity must come from the API key, not the body");

    let admin = format!("Bearer {}", jwt(&tenant, "tenant_admin"));
    let (st, cfg) = call(
        &app,
        Request::get("/api/v1/settings")
            .header("authorization", &admin)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(cfg["block_mode"], "manual");
    let mut new_cfg = cfg.clone();
    new_cfg["block_ttl_hours"] = json!(48);
    let (st, saved) = call(
        &app,
        json_req("PUT", "/api/v1/settings", &[("authorization", admin.clone())], new_cfg),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{saved}");
    assert_eq!(saved["block_ttl_hours"], 48);

    // Expiry lifts the block and the sensor sync list empties.
    let future = chrono::Utc::now() + chrono::Duration::days(3);
    let state_for_expiry = AppState::new(
        Config {
            mongodb_uri: String::new(),
            db_name: db_name.clone(),
            jwt_secret: SECRET.into(),
            port: 0,
            public_url: String::new(),
            redis_url: None,
            threat_feed_urls: vec![],
            threat_feed_interval_secs: 1,
            event_retention_days: 1,
            cors_origins: vec![],
        },
        Store::new(db.clone()),
        RateLimiter::in_memory(),
    );
    let n = netsentry_gateway::prevention::expire_once(&state_for_expiry, future)
        .await
        .unwrap();
    assert_eq!(n, 1);
    let (_, synced) = call(&app, sync()).await;
    assert_eq!(synced["data"].as_array().unwrap().len(), 0);

    client.database(&db_name).drop().await.unwrap();
}

/// Sensors receive HMAC-signed commands over the WebSocket, scoped to their tenant.
#[tokio::test]
async fn signed_commands_reach_connected_sensor() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;

    let Ok(uri) = std::env::var("TEST_MONGODB_URI") else {
        eprintln!("TEST_MONGODB_URI not set; skipping");
        return;
    };
    let db_name = format!("nsg_test_{}", uuid::Uuid::new_v4().simple());
    let client = mongodb::Client::with_uri_str(&uri).await.unwrap();
    let db = client.database(&db_name);
    let store = Store::new(db.clone());
    let cfg = Config {
        mongodb_uri: uri,
        db_name: db_name.clone(),
        jwt_secret: SECRET.into(),
        port: 0,
        public_url: "http://x".into(),
        redis_url: None,
        threat_feed_urls: vec![],
        threat_feed_interval_secs: 3600,
        event_retention_days: 1,
        cors_origins: vec![],
    };
    let app = router(AppState::new(cfg, store, RateLimiter::in_memory()));

    let tenant = ObjectId::new().to_hex();
    let secret = "s3cr3t-command-key";
    let api_key = "nss_wstest";
    db.collection::<mongodb::bson::Document>("sensors")
        .insert_one(doc! {
            "sensorId": "sensor-ws", "tenantId": &tenant, "name": "ws", "status": "pending",
            "apiKeyHash": hash_api_key(api_key), "commandHmacSecret": secret,
        })
        .await
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Query-string keys are refused; the header works.
    let bad = format!("ws://{addr}/ws/raspi?api_key={api_key}")
        .into_client_request()
        .unwrap();
    assert!(tokio_tungstenite::connect_async(bad).await.is_err());
    let mut req = format!("ws://{addr}/ws/raspi").into_client_request().unwrap();
    req.headers_mut().insert("X-API-Key", api_key.parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let hello = ws.next().await.unwrap().unwrap();
    assert!(hello.to_text().unwrap().contains("connected"));

    // Operator blocks an address over HTTP; the sensor gets a signed block_command.
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("http://{addr}/api/v1/blocked"))
        .bearer_auth(jwt(&tenant, "operator"))
        .json(&json!({"ip": "198.51.100.23", "reason": "manual test", "duration_hours": 2}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let mut seen = vec![];
    for _ in 0..2 {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Message::Text(t) = msg else {
            panic!("expected text frame")
        };
        seen.push(serde_json::from_str::<Value>(&t).unwrap());
    }
    let block = seen
        .iter()
        .find(|m| m["type"] == "block_command")
        .expect("block_command");
    assert_eq!(block["payload"]["ip"], "198.51.100.23");
    assert!(netsentry_gateway::signing::verify(
        secret,
        block["type"].as_str().unwrap(),
        block["ts"].as_i64().unwrap(),
        &block["payload"],
        block["sig"].as_str().unwrap()
    ));
    assert!(seen.iter().any(|m| m["type"] == "rule_update"
        && m["payload"]["suricata_rule"]
            .as_str()
            .unwrap()
            .contains("198.51.100.23")));

    // Another tenant's operator does not reach this sensor.
    let resp = http
        .post(format!("http://{addr}/api/v1/blocked"))
        .bearer_auth(jwt(&ObjectId::new().to_hex(), "operator"))
        .json(&json!({"ip": "198.51.100.24"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(tokio::time::timeout(std::time::Duration::from_millis(500), ws.next())
        .await
        .is_err());

    client.database(&db_name).drop().await.unwrap();
}
