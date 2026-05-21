use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
// ThreatIntelStore is the lib target of this package
use idps_threat_intel::ThreatIntelStore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tower_http::cors::{CorsLayer, Any};
use axum::http::Method;

#[derive(Clone)]
struct AppState {
    store: Arc<RwLock<ThreatIntelStore>>,
    http_client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct LookupRequest {
    ip: String,
}

#[derive(Debug, Serialize)]
struct LookupResponse {
    ip: String,
    score: f64,
    categories: Vec<String>,
    source: String,
    is_tor_exit: bool,
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    blocked_count: usize,
    tor_count: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("NetSentry-ThreatIntel/1.0")
        .build()?;

    let store = Arc::new(RwLock::new(ThreatIntelStore::new()));

    // Initial blocklist load
    refresh_blocklists(&store, &http_client).await;

    let state = AppState { store: store.clone(), http_client: http_client.clone() };

    // Background refresh task
    let refresh_store = store.clone();
    let refresh_client = http_client.clone();
    let interval_secs: u64 = std::env::var("UPDATE_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await; // skip the first immediate tick (already loaded above)
        loop {
            interval.tick().await;
            refresh_blocklists(&refresh_store, &refresh_client).await;
        }
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/lookup", post(lookup))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/refresh", post(trigger_refresh))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8094").await?;
    tracing::info!("Threat-intel service listening on 0.0.0.0:8094");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn refresh_blocklists(store: &Arc<RwLock<ThreatIntelStore>>, client: &reqwest::Client) {
    let tor_result = client
        .get("https://check.torproject.org/torbulkexitlist")
        .send()
        .await;
    if let Ok(resp) = tor_result {
        if let Ok(text) = resp.text().await {
            let mut s = store.write().await;
            let n = s.load_tor_exits_from_str(&text);
            tracing::info!("Loaded {} Tor exit nodes", n);
        }
    } else {
        tracing::warn!("Failed to fetch Tor exit list");
    }

    let feodo_result = client
        .get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")
        .send()
        .await;
    if let Ok(resp) = feodo_result {
        if let Ok(text) = resp.text().await {
            let mut s = store.write().await;
            let n = s.load_blocklist_from_str(&text);
            tracing::info!("Loaded {} Feodo blocked IPs", n);
        }
    } else {
        tracing::warn!("Failed to fetch Feodo blocklist");
    }
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "healthy", "service": "threat-intel" }))
}

async fn lookup(
    State(state): State<AppState>,
    Json(req): Json<LookupRequest>,
) -> Result<Json<LookupResponse>, StatusCode> {
    let store = state.store.read().await;
    let rep = store.lookup(&req.ip);
    Ok(Json(LookupResponse {
        ip: rep.ip,
        score: rep.score,
        categories: rep.categories.iter().map(|c| format!("{:?}", c)).collect(),
        source: rep.source,
        is_tor_exit: rep.is_tor_exit,
    }))
}

async fn stats(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(StatsResponse {
        blocked_count: store.blocked_count(),
        tor_count: store.tor_count(),
    })
}

async fn trigger_refresh(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.clone();
    let client = state.http_client.clone();
    tokio::spawn(async move {
        refresh_blocklists(&store, &client).await;
    });
    Json(serde_json::json!({ "success": true, "message": "Refresh triggered" }))
}
