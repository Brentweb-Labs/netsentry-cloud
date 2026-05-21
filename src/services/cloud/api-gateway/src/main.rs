use axum::{
    extract::{Path, Query, State},
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::{StatusCode, Request, HeaderValue, Method},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use tower_http::cors::{CorsLayer, Any};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use log::info;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures_util::TryStreamExt;
use idps_rule_generator::{generate_ip_block_rule, generate_ddos_rule};
use mongodb::{
    bson::{doc, DateTime as BsonDateTime},
    options::{ClientOptions, FindOptions},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    mongo_client: mongodb::Client,
    raspi_client: reqwest::Client,
    raspi_endpoint: String,
    eve_json_path: PathBuf,
    /// Cached detection settings (refreshed from MongoDB periodically)
    detection_settings: Arc<RwLock<DetectionSettings>>,
    /// Sliding window tracker: (src_ip, path) -> list of request timestamps
    brute_force_tracker: Arc<DashMap<(String, String), Vec<DateTime<Utc>>>>,
    /// IP → list of domain names seen in DNS events
    ip_domain_map: Arc<DashMap<String, Vec<String>>>,
    /// Broadcast channel: send real-time alert/metric JSON to all connected dashboard WS clients
    dashboard_tx: broadcast::Sender<String>,
    /// Cached Raspi→VPS connection status, refreshed in background every 30 s
    raspi_connection_cache: Arc<RwLock<ConnectionStatus>>,
    /// Broadcast channel: send BlockCommand/RuleUpdate JSON to all connected Raspi WS clients
    raspi_tx: broadcast::Sender<String>,
}

/// Detection / anomaly settings (persisted in MongoDB `detection_settings`)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DetectionSettings {
    pub brute_force_threshold: u32,
    pub brute_force_window_seconds: u32,
    pub block_duration_hours: u64,
    pub monitored_paths: Vec<String>,
    pub auto_block_enabled: bool,
    pub dns_enrichment_enabled: bool,
    /// IPs / CIDR prefixes that are never auto-blocked (school internal ranges, trusted services)
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// Minimum threat level (0-10) before a detection event is elevated to the dashboard as high/critical
    #[serde(default = "default_min_alert_level")]
    pub min_alert_level: u8,
    pub updated_at: DateTime<Utc>,
}

fn default_min_alert_level() -> u8 { 5 }

impl Default for DetectionSettings {
    fn default() -> Self {
        Self {
            // Conservative thresholds for a school network — minimise false positives.
            // auto_block_enabled is off by default: admin must confirm blocks.
            brute_force_threshold: 20,
            brute_force_window_seconds: 60,
            block_duration_hours: 1,
            monitored_paths: vec![
                "/login".to_string(),
                "/api/auth".to_string(),
                "/api/login".to_string(),
                "/admin".to_string(),
                "/wp-admin".to_string(),
                "/signin".to_string(),
            ],
            auto_block_enabled: false,
            dns_enrichment_enabled: true,
            // Whitelist common RFC-1918 school internal ranges by default.
            // Administrators should add their specific school subnets here.
            whitelist: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
                "127.0.0.0/8".to_string(),
            ],
            min_alert_level: 5,
            updated_at: Utc::now(),
        }
    }
}

/// A recorded brute-force / anomaly detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DetectionEvent {
    pub id: String,
    pub src_ip: String,
    pub detected_pattern: String,
    pub path: String,
    pub request_count: u32,
    pub window_seconds: u32,
    pub triggered_block: bool,
    pub timestamp: DateTime<Utc>,
    pub dns_names: Vec<String>,
}

/// Paginated detection events query
#[derive(Debug, Deserialize)]
struct DetectionEventsQuery {
    page: Option<u32>,
    limit: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EveEvent {
    #[serde(rename = "timestamp")]
    pub timestamp: String,
    #[serde(rename = "flow_id")]
    pub flow_id: Option<u64>,
    #[serde(rename = "in_iface")]
    pub in_iface: Option<String>,
    #[serde(rename = "event_type")]
    pub event_type: String,
    #[serde(rename = "src_ip")]
    pub src_ip: Option<String>,
    #[serde(rename = "src_port")]
    pub src_port: Option<u16>,
    #[serde(rename = "dest_ip")]
    pub dest_ip: Option<String>,
    #[serde(rename = "dest_port")]
    pub dest_port: Option<u16>,
    #[serde(rename = "proto")]
    pub proto: Option<String>,
    #[serde(rename = "alert")]
    pub alert: Option<AlertInfo>,
    #[serde(rename = "dns")]
    pub dns: Option<DnsInfo>,
    #[serde(rename = "http")]
    pub http: Option<HttpInfo>,
    #[serde(rename = "tls")]
    pub tls: Option<TlsInfo>,
    #[serde(rename = "fileinfo")]
    pub fileinfo: Option<FileInfo>,
    #[serde(rename = "processed_at")]
    pub processed_at: Option<BsonDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AlertInfo {
    #[serde(rename = "action")]
    pub action: Option<String>,
    #[serde(rename = "gid")]
    pub gid: Option<u32>,
    #[serde(rename = "signature_id")]
    pub signature_id: Option<u32>,
    #[serde(rename = "rev")]
    pub rev: Option<u32>,
    #[serde(rename = "signature")]
    pub signature: Option<String>,
    #[serde(rename = "category")]
    pub category: Option<String>,
    #[serde(rename = "severity")]
    pub severity: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DnsInfo {
    #[serde(rename = "queries")]
    pub queries: Option<Vec<DnsQuery>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DnsQuery {
    #[serde(rename = "rrname")]
    pub rrname: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HttpInfo {
    #[serde(rename = "hostname")]
    pub hostname: Option<String>,
    #[serde(rename = "url")]
    pub url: Option<String>,
    #[serde(rename = "http_user_agent")]
    pub http_user_agent: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TlsInfo {}

#[derive(Debug, Serialize, Deserialize)]
struct FileInfo {}

#[derive(Debug, Deserialize)]
struct PaginationParams {
    page: Option<u32>,
    limit: Option<u32>,
    event_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: T,
}

#[derive(Debug, Serialize)]
struct PaginatedEvents {
    events: Vec<EveEvent>,
    pagination: PaginationInfo,
}

#[derive(Debug, Serialize)]
struct PaginationInfo {
    total_count: u64,
    current_page: u32,
    per_page: u32,
    total_pages: u32,
    has_next: bool,
    has_prev: bool,
}

#[derive(Debug, Serialize)]
struct AlertStatistics {
    total: u64,
    critical: u64,
    high: u64,
    medium: u64,
    low: u64,
    by_type: HashMap<String, u64>,
}

#[derive(Debug, Serialize)]
struct ThreatIntel {
    malicious_ips: Vec<String>,
    suspicious_domains: Vec<String>,
    vulnerabilities: Vec<Vulnerability>,
    total_alerts: u64,
    unique_ips_count: usize,
    unique_domains_count: usize,
}

#[derive(Debug, Serialize)]
struct Vulnerability {
    id: String,
    severity: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct NetworkTopology {
    active_nodes: usize,
    total_connections: usize,
    monitored_ports: usize,
    blocked_ips: usize,
    total_events: u64,
    unique_ips: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SystemMetrics {
    cpu_current: f64,
    cpu_trend: String,
    memory_current: f64,
    memory_trend: String,
    alerts_per_hour: u64,
    alerts_trend: String,
    network_throughput_current: u64,
    network_trend: String,
    events_processed: u64,
    recent_events: u64,
    dns_requests: u64,
    http_requests: u64,
}

#[derive(Debug, Deserialize)]
struct LogSubmission {
    source_ip: String,
    dest_ip: String,
    source_port: u16,
    dest_port: u16,
    protocol: String,
    payload: String,
    severity: u8,
    event_type: String,
}

#[derive(Debug, Serialize)]
struct RaspiStatus {
    status: String,
    events_collected: u64,
    events_sent: u64,
    failed_sends: u64,
    vps_connection: String,
}

#[derive(Debug, Serialize)]
struct VpsStatus {
    status: String,
    events_processed: u64,
    alerts_processed: u64,
    processing_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ConnectionStatus {
    status: String, // "connected", "disconnected", "degraded"
    uptime_duration: u64, // seconds
    uptime_percentage: f64, // 0-100
    last_connected: Option<String>,
    last_disconnected: Option<String>,
    total_checks: u64,
    successful_checks: u64,
    failed_checks: u64,
    average_response_time: f64, // milliseconds
    response_time_last_check: f64, // milliseconds
    consecutive_failures: u64,
    longest_uptime: u64, // seconds
    shortest_downtime: u64, // seconds
}

#[derive(Debug, Deserialize)]
struct ManualBlockRequest {
    ip: String,
    reason: String,
    duration_hours: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ManualUnblockRequest {
    ip: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct PreventionActionResponse {
    success: bool,
    message: String,
    timestamp: String,
}

/// Traffic event forwarded from raspi-collector
#[derive(Debug, Serialize, Deserialize)]
struct TrafficEvent {
    id: String,
    timestamp: DateTime<Utc>,
    source_ip: String,
    dest_ip: String,
    source_port: u16,
    dest_port: u16,
    protocol: String,
    payload: serde_json::Value,
    threat_level: u8,
    event_type: String,
}

/// MongoDB document stored in `idps.blocked_ips` on the VPS.
/// The VPS is the authoritative record of what has been requested to be blocked;
/// actual iptables enforcement happens on the Raspi via WebSocket commands.
#[derive(Debug, Serialize, Deserialize)]
struct BlockedIpRecord {
    ip: String,
    reason: String,
    severity: u8,
    source: String,
    blocked_at: String,
    expires_at: String,
    active: bool,
    blocked_at_dt: Option<mongodb::bson::DateTime>,
    expires_at_dt: Option<mongodb::bson::DateTime>,
    unblocked_at_dt: Option<mongodb::bson::DateTime>,
    unblock_reason: Option<String>,
}

struct MachineMetrics {
    cpu_usage_percent: f64,
    memory_usage_percent: f64,
    memory_used_mb: f64,
}

async fn read_machine_metrics() -> MachineMetrics {
    // Read from /proc/meminfo if available (Linux), fall back to defaults
    let (memory_used_mb, memory_usage_percent) = tokio::task::spawn_blocking(|| {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            let mut total_kb = 0u64;
            let mut available_kb = 0u64;
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    total_kb = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
                } else if line.starts_with("MemAvailable:") {
                    available_kb = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
                }
            }
            if total_kb > 0 {
                let used_kb = total_kb.saturating_sub(available_kb);
                let used_mb = used_kb as f64 / 1024.0;
                let pct = (used_kb as f64 / total_kb as f64) * 100.0;
                return (used_mb, pct);
            }
        }
        (0.0_f64, 0.0_f64)
    })
    .await
    .unwrap_or((0.0, 0.0));

    // /proc/stat CPU usage requires two samples; return a simple estimate
    let cpu_usage_percent = 0.0_f64;

    MachineMetrics {
        cpu_usage_percent,
        memory_usage_percent,
        memory_used_mb,
    }
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mongo_uri =
        std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://mongo:27017/idps".to_string());

    let mut client_options = ClientOptions::parse(&mongo_uri).await?;
    client_options.max_pool_size = Some(10);
    client_options.min_pool_size = Some(2);

    let mongo_client = mongodb::Client::with_options(client_options)?;

    let raspi_client: reqwest::Client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let raspi_endpoint = std::env::var("RASPI_ENDPOINT")
        .unwrap_or_else(|_| "http://raspi-collector:8080".to_string());

    let eve_json_path = std::env::var("EVE_JSON_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/app/logs/eve.json"));

    let initial_settings = load_detection_settings_from_db(&mongo_client).await;
    let detection_settings = Arc::new(RwLock::new(initial_settings));
    let brute_force_tracker: Arc<DashMap<(String, String), Vec<DateTime<Utc>>>> =
        Arc::new(DashMap::new());
    let ip_domain_map: Arc<DashMap<String, Vec<String>>> = Arc::new(DashMap::new());

    // Broadcast channels — 256-message buffers (lagging receivers simply miss old messages)
    let (dashboard_tx, _) = broadcast::channel::<String>(256);
    let (raspi_tx, _) = broadcast::channel::<String>(256);

    let raspi_connection_cache = Arc::new(RwLock::new(ConnectionStatus {
        status: "unknown".to_string(),
        uptime_duration: 0,
        uptime_percentage: 0.0,
        last_connected: None,
        last_disconnected: None,
        total_checks: 0,
        successful_checks: 0,
        failed_checks: 0,
        average_response_time: 0.0,
        response_time_last_check: 0.0,
        consecutive_failures: 0,
        longest_uptime: 0,
        shortest_downtime: 0,
    }));

    println!("Connected to MongoDB successfully");
    println!("Raspi endpoint: {}", raspi_endpoint);

    let state = Arc::new(AppState {
        mongo_client,
        raspi_client,
        raspi_endpoint,
        eve_json_path,
        detection_settings,
        brute_force_tracker,
        ip_domain_map,
        dashboard_tx,
        raspi_tx,
        raspi_connection_cache,
    });

    let detection_state = state.clone();
    tokio::spawn(async move {
        run_detection_loop(detection_state).await;
    });

    let conn_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let url = format!("{}/connection", conn_state.raspi_endpoint);

            // Do all network I/O before touching the lock
            let new_status: Option<ConnectionStatus> = async {
                let resp = conn_state.raspi_client.get(&url).send().await.ok()?;
                if !resp.status().is_success() { return None; }
                let v = resp.json::<serde_json::Value>().await.ok()?;
                Some(ConnectionStatus {
                    status: v["status"].as_str().unwrap_or("unknown").to_string(),
                    uptime_duration: v["uptime_duration"].as_u64().unwrap_or(0),
                    uptime_percentage: v["uptime_percentage"].as_f64().unwrap_or(0.0),
                    last_connected: v["last_connected"].as_str().map(str::to_string),
                    last_disconnected: v["last_disconnected"].as_str().map(str::to_string),
                    total_checks: v["total_checks"].as_u64().unwrap_or(0),
                    successful_checks: v["successful_checks"].as_u64().unwrap_or(0),
                    failed_checks: v["failed_checks"].as_u64().unwrap_or(0),
                    average_response_time: v["average_response_time"].as_f64().unwrap_or(0.0),
                    response_time_last_check: v["response_time_last_check"].as_f64().unwrap_or(0.0),
                    consecutive_failures: v["consecutive_failures"].as_u64().unwrap_or(0),
                    longest_uptime: v["longest_uptime"].as_u64().unwrap_or(0),
                    shortest_downtime: v["shortest_downtime"].as_u64().unwrap_or(0),
                })
            }.await;

            // Lock only for the in-memory write — no I/O inside
            let mut cache = conn_state.raspi_connection_cache.write().await;
            match new_status {
                Some(status) => *cache = status,
                None => {
                    // The VPS could not reach the Pi collector at all.
                    // Keep the Pi-reported VPS metrics untouched; they reflect
                    // the Pi -> VPS link, not the VPS -> Pi poll path.
                    cache.status = "unreachable".to_string();
                }
            }
        }
    });

    let expiry_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let db = expiry_state.mongo_client.database("idps_database");
            let col = db.collection::<serde_json::Value>("blocked_ips");
            let now_ms = Utc::now().timestamp_millis();
            let now_bson = BsonDateTime::from_millis(now_ms);
            let expired_filter = doc! {
                "active": true,
                "expires_at_dt": { "$lt": now_bson }
            };

            let expired_ips: Vec<String> = match col.find(expired_filter.clone()).await {
                Ok(mut cursor) => {
                    let mut ips = Vec::new();
                    while let Ok(Some(doc)) = cursor.try_next().await {
                        if let Some(ip) = doc.get("ip").and_then(|v| v.as_str()) {
                            ips.push(ip.to_string());
                        }
                    }
                    ips
                }
                Err(e) => {
                    tracing::warn!("blocked_ips expiry query failed: {}", e);
                    continue;
                }
            };

            if expired_ips.is_empty() {
                continue;
            }

            let update = doc! {
                "$set": { "active": false, "unblocked_at_dt": now_bson, "unblock_reason": "expired" }
            };
            if let Err(e) = col.update_many(expired_filter, update).await {
                tracing::warn!("blocked_ips expiry update failed: {}", e);
            }

            for ip in &expired_ips {
                broadcast_unblock_command(&expiry_state, ip, "expired", None);
                tracing::info!("Expired block for {}", ip);
            }
        }
    });

    if std::env::var("JWT_SECRET").unwrap_or_default().is_empty() {
        println!("⚠️  JWT_SECRET not set — using insecure default. Set it in .env!");
    }
    println!("🔐 JWT authentication enabled (user: {})",
        std::env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".into()));

    let app = Router::new()
        .route("/", get(health_check))
        .route("/health", get(health_check))
        .route("/api/health", get(health_check))
        .route("/api/v1/packets", post(submit_packet))
        .route("/api/v1/packets", get(query_packets))
        .route("/api/v1/events", post(submit_event))
        .route("/api/v1/events", get(get_events))
        .route("/api/v1/analyze", post(analyze_event))
        .route("/api/status", get(get_status))
        .route("/api/events", get(get_events_paginated))
        .route("/api/alerts/statistics", get(get_alert_statistics))
        .route("/api/threat-intel", get(get_threat_intel))
        .route("/api/network/topology", get(get_network_topology))
        .route("/api/metrics", get(get_metrics))
        // Log collection endpoints
        .route("/api/logs/submit", post(submit_log))
        .route("/api/logs/simulate", post(simulate_logs))
        .route("/api/logs/eve.json", get(get_eve_json_logs))
        // Service status endpoints
        .route("/api/services/raspi", get(get_raspi_status))
        .route("/api/services/vps", get(get_vps_status))
        .route("/api/services/status", get(get_all_services_status))
        .route("/api/debug/edge", get(get_edge_debug))
        .route("/api/connection/raspi-vps", get(get_raspi_vps_connection))
        // Prevention endpoints
        .route("/api/prevention/block", post(block_ip_manual))
        .route("/api/prevention/unblock", post(unblock_ip_manual))
        .route("/api/prevention/blocked", get(get_blocked_ips))
        .route("/api/prevention/stats", get(get_prevention_stats))
        .route("/api/prevention/blocked/{ip}", delete(unblock_ip_by_path))
        // Detection settings endpoints
        .route("/api/settings/detection", get(get_detection_settings))
        .route("/api/settings/detection", put(update_detection_settings))
        // Auto-block specific endpoints
        .route("/api/settings/auto-block", get(get_auto_block_settings))
        .route("/api/settings/auto-block", put(update_auto_block_settings))
        .route("/api/settings/auto-block/enable", post(enable_auto_block))
        .route("/api/settings/auto-block/disable", post(disable_auto_block))
        .route("/api/settings/auto-block/status", get(get_auto_block_status))
        // Detection events endpoints
        .route("/api/detection/events", get(get_detection_events))
        .route("/api/detection/active", get(get_active_detection_events))
        // Telemetry
        .route("/api/telemetry", post(ingest_telemetry))
        .route("/api/telemetry/latest", get(get_latest_telemetry))
        .route("/api/telemetry/alert", post(ingest_telemetry_alert))
        // Suricata alert ingest endpoint (from log-processor)
        .route("/api/alerts/ingest", post(ingest_suricata_alert))
        // Traffic ingest endpoints (from raspi-collector)
        .route("/api/traffic", post(ingest_traffic_event))
        .route("/api/traffic/batch", post(ingest_traffic_batch))
        .route("/metrics", get(prometheus_metrics))
        // Config endpoint — no auth, used by dashboard to discover auth requirements
        .route("/api/config", get(get_config))
        // WebSocket endpoints
        .route("/ws", get(ws_dashboard_handler))
        .route("/ws/raspi", get(ws_raspi_handler))
        .route("/ws/packets", get(ws_packets_handler))
        // Auth endpoint — public (with /api/vps prefix fallback for Traefik strip misconfiguration)
        .route("/api/auth/login", post(login_handler))
        .route("/api/vps/auth/login", post(login_handler))
        .with_state(state)
        .layer(middleware::from_fn(jwt_auth))
        .layer(middleware::from_fn(ip_whitelist_middleware))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
                .allow_headers(Any),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("API Gateway listening on 0.0.0.0:8080");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> Result<Json<Value>, StatusCode> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
        "service": "idps-api-gateway"
    })))
}

async fn submit_packet(
    State(state): State<Arc<AppState>>,
    Json(packet): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<Value>("packets");

    let packet_id = Uuid::new_v4().to_string();
    let stored_packet = serde_json::json!({
        "packet_id": packet_id,
        "received_at": Utc::now().to_rfc3339(),
        "packet": packet
    });

    match collection.insert_one(stored_packet).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "status": "received",
            "packet_id": packet_id
        }))),
        Err(e) => {
            eprintln!("Failed to store packet: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn query_packets(State(state): State<Arc<AppState>>) -> Result<Json<Value>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<Value>("packets");

    let mut cursor = match collection
        .find(doc! {})
        .sort(doc! { "received_at": -1 })
        .limit(100)
        .await
    {
        Ok(cursor) => cursor,
        Err(e) => {
            eprintln!("Failed to query packets: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let mut packets: Vec<Value> = Vec::new();
    while let Some(packet) = cursor.try_next().await.unwrap_or(None) {
        packets.push(packet);
    }

    Ok(Json(serde_json::json!({
        "packets": packets,
        "total": packets.len()
    })))
}

async fn submit_event(
    State(state): State<Arc<AppState>>,
    Json(event): Json<EveEvent>,
) -> Result<Json<Value>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events");

    let mut event_with_timestamp = event;
    event_with_timestamp.processed_at = Some(BsonDateTime::from_millis(Utc::now().timestamp_millis()));

    match collection.insert_one(event_with_timestamp).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Event stored successfully"
        }))),
        Err(e) => {
            eprintln!("Failed to store event: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn analyze_event(
    State(_state): State<Arc<AppState>>,
    Json(event): Json<EveEvent>,
) -> Result<Json<Value>, StatusCode> {
    // Simple analysis logic
    let is_suspicious = match event.event_type.as_str() {
        "alert" => true,
        "http" => {
            if let Some(http) = &event.http {
                if let Some(url) = &http.url {
                    url.contains("admin") || url.contains("login")
                } else {
                    false
                }
            } else {
                false
            }
        }
        _ => false,
    };

    Ok(Json(serde_json::json!({
        "event_id": Uuid::new_v4(),
        "is_suspicious": is_suspicious,
        "threat_level": if is_suspicious { 7 } else { 2 },
        "analysis": "Basic pattern analysis completed"
    })))
}

// Angular Admin API endpoints

async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<Value>>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events");

    let five_minutes_ago = Utc::now() - chrono::Duration::minutes(5);
    let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
    let five_minutes_ago_bson = BsonDateTime::from_millis(five_minutes_ago.timestamp_millis());
    let one_hour_ago_bson = BsonDateTime::from_millis(one_hour_ago.timestamp_millis());

    let recent_count = collection
        .count_documents(doc! { "processed_at": { "$gte": five_minutes_ago_bson } })
        .await
        .unwrap_or(0);

    let hourly_count = collection
        .count_documents(doc! { "processed_at": { "$gte": one_hour_ago_bson } })
        .await
        .unwrap_or(0);

    let total_count = collection.count_documents(doc! {}).await.unwrap_or(0);

    let machine_metrics = read_machine_metrics().await;
    // Suricata runs on the Pi — consider it active when events arrived in the last hour
    let is_running = hourly_count > 0;

    // Calculate real metrics based on event data
    let (alert_count, dns_count, http_count) = if hourly_count > 0 {
        let alert_pipeline = vec![
            doc! { "$match": {
                "processed_at": { "$gte": one_hour_ago_bson },
                "event_type": "alert"
            }},
            doc! { "$count": "count" },
        ];

        let dns_pipeline = vec![
            doc! { "$match": {
                "processed_at": { "$gte": one_hour_ago_bson },
                "event_type": "dns"
            }},
            doc! { "$count": "count" },
        ];

        let http_pipeline = vec![
            doc! { "$match": {
                "processed_at": { "$gte": one_hour_ago_bson },
                "event_type": "http"
            }},
            doc! { "$count": "count" },
        ];

        let alert_count = if let Ok(mut cursor) = collection.aggregate(alert_pipeline).await {
            if let Some(doc) = cursor.try_next().await.unwrap_or(None) {
                doc.get("count").and_then(|b| b.as_i64()).unwrap_or(0) as u64
            } else {
                0
            }
        } else {
            0
        };

        let dns_count = if let Ok(mut cursor) = collection.aggregate(dns_pipeline).await {
            if let Some(doc) = cursor.try_next().await.unwrap_or(None) {
                doc.get("count").and_then(|b| b.as_i64()).unwrap_or(0) as u64
            } else {
                0
            }
        } else {
            0
        };

        let http_count = if let Ok(mut cursor) = collection.aggregate(http_pipeline).await {
            if let Some(doc) = cursor.try_next().await.unwrap_or(None) {
                doc.get("count").and_then(|b| b.as_i64()).unwrap_or(0) as u64
            } else {
                0
            }
        } else {
            0
        };

        (alert_count, dns_count, http_count)
    } else {
        (0, 0, 0)
    };

    Ok(Json(ApiResponse {
        success: true,
        data: serde_json::json!({
            "id": "suricata-pi",
            "name": "Suricata IDS/IPS (Pi)",
            "status": if is_running { "running" } else { "stopped" },
            "state": if is_running { "healthy" } else { "unavailable" },
            "running": is_running,
            "image": "jasonish/suricata:7.0",
            "created": Utc::now(),
            "stats": {
                "cpu_usage": machine_metrics.cpu_usage_percent,
                "memory_usage": machine_metrics.memory_usage_percent,
                "network_throughput": if is_running {
                    (dns_count + http_count) as f64 * 1024.0
                } else { 0.0 },
                "events_processed": total_count,
                "recent_events": recent_count,
                "alerts_per_hour": alert_count,
                "dns_requests": dns_count,
                "http_requests": http_count
            }
        }),
    }))
}

async fn get_events_paginated(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PaginatedEvents>>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events");

    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(100).min(1000); // Cap at 1000
    let skip = (page - 1) * limit;

    let mut filter = doc! {};
    if let Some(event_type) = &params.event_type {
        filter.insert("event_type", event_type);
    }

    let total_count = collection
        .count_documents(filter.clone())
        .await
        .unwrap_or(0);

    let find_options = FindOptions::builder()
        .sort(doc! { "timestamp": -1 })
        .skip(skip as u64)
        .limit(limit as i64)
        .build();

    let mut cursor: mongodb::Cursor<EveEvent> =
        match collection.find(filter).with_options(find_options).await {
            Ok(cursor) => cursor,
            Err(e) => {
                eprintln!("Failed to query events: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

    let mut events = Vec::new();
    while let Some(event) = cursor.try_next().await.unwrap_or(None) {
        events.push(event);
    }

    let total_pages = ((total_count as f64) / (limit as f64)).ceil() as u32;

    Ok(Json(ApiResponse {
        success: true,
        data: PaginatedEvents {
            events,
            pagination: PaginationInfo {
                total_count,
                current_page: page,
                per_page: limit,
                total_pages,
                has_next: page < total_pages,
                has_prev: page > 1,
            },
        },
    }))
}

async fn get_events(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let Json(result) = get_events_paginated(State(state), Query(params)).await?;
    let value = serde_json::to_value(result).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(value))
}

async fn get_alert_statistics(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<AlertStatistics>>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events");

    let alert_filter = doc! { "event_type": "alert" };
    let total_alerts = collection.count_documents(alert_filter).await.unwrap_or(0);

    let mut pipeline = vec![
        doc! { "$match": { "event_type": "alert" } },
        doc! { "$group": {
            "_id": "$alert.severity",
            "count": { "$sum": 1 }
        }},
    ];

    let mut severity_counts = HashMap::new();
    if let Ok(mut cursor) = collection.aggregate(pipeline).await {
        while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
            let severity = doc.get("_id").and_then(|b| b.as_i64()).map(|v| v as i32)
                .or_else(|| doc.get_i32("_id").ok());
            let count = doc.get("count").and_then(|b| b.as_i64()).unwrap_or(0);
            if let Some(sev) = severity {
                severity_counts.insert(sev, count as u64);
            }
        }
    }

    let mut by_type = HashMap::new();
    pipeline = vec![
        doc! { "$match": { "event_type": "alert" } },
        doc! { "$group": {
            "_id": "$alert.category",
            "count": { "$sum": 1 }
        }},
    ];

    if let Ok(mut cursor) = collection.aggregate(pipeline).await {
        while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
            if let Ok(category) = doc.get_str("_id") {
                let count = doc.get("count").and_then(|b| b.as_i64()).unwrap_or(0);
                by_type.insert(category.to_string(), count as u64);
            }
        }
    }

    Ok(Json(ApiResponse {
        success: true,
        data: AlertStatistics {
            total: total_alerts,
            critical: severity_counts.get(&1).copied().unwrap_or(0),
            high: severity_counts.get(&2).copied().unwrap_or(0),
            medium: severity_counts.get(&3).copied().unwrap_or(0),
            low: severity_counts.get(&4).copied().unwrap_or(0)
                + severity_counts.get(&5).copied().unwrap_or(0)
                + severity_counts.get(&6).copied().unwrap_or(0)
                + severity_counts.get(&7).copied().unwrap_or(0),
            by_type,
        },
    }))
}

async fn get_threat_intel(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<ThreatIntel>>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events");

    // Get unique IPs from alerts
    let alert_pipeline = vec![
        doc! { "$match": { "event_type": "alert" } },
        doc! { "$group": {
            "_id": null,
            "src_ips": { "$addToSet": "$src_ip" },
            "dest_ips": { "$addToSet": "$dest_ip" }
        }},
    ];

    let mut unique_ips = std::collections::HashSet::<String>::new();
    if let Ok(mut cursor) = collection.aggregate(alert_pipeline).await {
        while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
            if let Ok(src_ips) = doc.get_array("src_ips") {
                for ip in src_ips {
                    if let Some(ip_str) = ip.as_str() {
                        unique_ips.insert(ip_str.to_string());
                    }
                }
            }
            if let Ok(dest_ips) = doc.get_array("dest_ips") {
                for ip in dest_ips {
                    if let Some(ip_str) = ip.as_str() {
                        unique_ips.insert(ip_str.to_string());
                    }
                }
            }
        }
    }

    // Get unique domains from DNS
    let dns_pipeline = vec![
        doc! { "$match": { "event_type": "dns" } },
        doc! { "$unwind": "$dns.queries" },
        doc! { "$group": {
            "_id": null,
            "domains": { "$addToSet": "$dns.queries.rrname" }
        }},
    ];

    let mut unique_domains = std::collections::HashSet::<String>::new();
    if let Ok(mut cursor) = collection.aggregate(dns_pipeline).await {
        while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
            if let Ok(domains) = doc.get_array("domains") {
                for domain in domains {
                    if let Some(domain_str) = domain.as_str() {
                        unique_domains.insert(domain_str.to_string());
                    }
                }
            }
        }
    }

    let total_alerts = collection
        .count_documents(doc! { "event_type": "alert" })
        .await
        .unwrap_or(0);

    let vulnerabilities_pipeline = vec![
        doc! { "$match": { "event_type": "alert", "alert.signature": { "$exists": true, "$ne": null } } },
        doc! { "$group": {
            "_id": {
                "signature_id": "$alert.signature_id",
                "signature": "$alert.signature",
                "severity": "$alert.severity"
            },
            "count": { "$sum": 1 }
        }},
        doc! { "$sort": { "count": -1 } },
        doc! { "$limit": 10 },
    ];

    let mut vulnerabilities = Vec::new();
    if let Ok(mut cursor) = collection.aggregate(vulnerabilities_pipeline).await {
        while let Some(row) = cursor.try_next().await.unwrap_or(None) {
            if let Ok(id_doc) = row.get_document("_id") {
                let signature = id_doc.get_str("signature").unwrap_or("Unknown signature");
                let signature_id = id_doc
                    .get_i32("signature_id")
                    .map(|sid| sid.to_string())
                    .or_else(|_| id_doc.get_i64("signature_id").map(|sid| sid.to_string()))
                    .unwrap_or_else(|_| "unknown".to_string());
                let severity_number = id_doc
                    .get_i32("severity")
                    .map(|sev| sev as u32)
                    .or_else(|_| id_doc.get_i64("severity").map(|sev| sev as u32))
                    .unwrap_or(0);
                let occurrences = row.get("count").and_then(|b| b.as_i64()).unwrap_or(0);

                vulnerabilities.push(Vulnerability {
                    id: format!("SID-{}", signature_id),
                    severity: severity_label(severity_number).to_string(),
                    description: format!("{} ({} occurrences)", signature, occurrences),
                });
            }
        }
    }

    let malicious_ips: Vec<String> = unique_ips.iter().take(10).cloned().collect();
    let suspicious_domains: Vec<String> = unique_domains.iter().take(10).cloned().collect();

    Ok(Json(ApiResponse {
        success: true,
        data: ThreatIntel {
            malicious_ips,
            suspicious_domains,
            vulnerabilities,
            total_alerts,
            unique_ips_count: unique_ips.len(),
            unique_domains_count: unique_domains.len(),
        },
    }))
}

async fn get_network_topology(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<NetworkTopology>>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events");

    let pipeline = vec![doc! { "$group": {
        "_id": null,
        "unique_src_ips": { "$addToSet": "$src_ip" },
        "unique_dest_ips": { "$addToSet": "$dest_ip" },
        "unique_src_ports": { "$addToSet": "$src_port" },
        "unique_dest_ports": { "$addToSet": "$dest_port" },
        "connections": { "$addToSet": { "$concat": ["$src_ip", "-", "$dest_ip"] } },
        "total_events": { "$sum": 1 }
    }}];

    let mut topology = NetworkTopology {
        active_nodes: 0,
        total_connections: 0,
        monitored_ports: 0,
        blocked_ips: 0,
        total_events: 0,
        unique_ips: vec![],
    };

    if let Ok(mut cursor) = collection.aggregate(pipeline).await {
        while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
            if let Ok(src_ips) = doc.get_array("unique_src_ips") {
                let mut all_ips = std::collections::HashSet::<String>::new();
                for ip in src_ips {
                    if let Some(ip_str) = ip.as_str() {
                        all_ips.insert(ip_str.to_string());
                    }
                }
                if let Ok(dest_ips) = doc.get_array("unique_dest_ips") {
                    for ip in dest_ips {
                        if let Some(ip_str) = ip.as_str() {
                            all_ips.insert(ip_str.to_string());
                        }
                    }
                }
                topology.active_nodes = all_ips.len();
                topology.unique_ips = all_ips.into_iter().take(20).collect();
            }

            if let Ok(connections) = doc.get_array("connections") {
                topology.total_connections = connections.len();
            }

            let mut all_ports = std::collections::HashSet::<i32>::new();
            if let Ok(src_ports) = doc.get_array("unique_src_ports") {
                for port in src_ports {
                    if let Some(port_val) = port.as_i32() {
                        all_ports.insert(port_val);
                    }
                }
            }
            if let Ok(dest_ports) = doc.get_array("unique_dest_ports") {
                for port in dest_ports {
                    if let Some(port_val) = port.as_i32() {
                        all_ports.insert(port_val);
                    }
                }
            }
            topology.monitored_ports = all_ports.len();

            if let Ok(events) = doc.get_i64("total_events") {
                topology.total_events = events as u64;
            }
        }
    }

    Ok(Json(ApiResponse {
        success: true,
        data: topology,
    }))
}

async fn get_metrics(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<SystemMetrics>>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events");

    let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
    let five_minutes_ago = Utc::now() - chrono::Duration::minutes(5);
    let one_hour_ago_bson = BsonDateTime::from_millis(one_hour_ago.timestamp_millis());
    let five_minutes_ago_bson = BsonDateTime::from_millis(five_minutes_ago.timestamp_millis());
    let recent_filter = doc! { "processed_at": { "$gte": one_hour_ago_bson } };

    let total_events = collection
        .count_documents(recent_filter.clone())
        .await
        .unwrap_or(0);

    // Get real event counts by type
    let event_type_pipeline = vec![
        doc! { "$match": recent_filter.clone() },
        doc! { "$group": {
            "_id": "$event_type",
            "count": { "$sum": 1 }
        }},
    ];

    let mut event_counts = HashMap::new();
    if let Ok(mut cursor) = collection.aggregate(event_type_pipeline).await {
        while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
            if let Ok(event_type) = doc.get_str("_id") {
                let count = doc.get("count").and_then(|b| b.as_i64()).unwrap_or(0);
                event_counts.insert(event_type.to_string(), count as u64);
            }
        }
    }

    let alerts_per_hour = event_counts.get("alert").copied().unwrap_or(0);
    let dns_requests = event_counts.get("dns").copied().unwrap_or(0);
    let http_requests = event_counts.get("http").copied().unwrap_or(0);

    // Calculate trends based on previous hour
    let two_hours_ago = Utc::now() - chrono::Duration::hours(2);
    let two_hours_ago_bson = BsonDateTime::from_millis(two_hours_ago.timestamp_millis());
    let previous_hour_filter = doc! {
        "processed_at": {
            "$gte": two_hours_ago_bson,
            "$lt": one_hour_ago_bson
        }
    };

    let previous_alerts = collection
        .count_documents(previous_hour_filter)
        .await
        .unwrap_or(0);

    let alerts_trend = match alerts_per_hour {
        current if current > previous_alerts => "up",
        current if current < previous_alerts => "down",
        _ => "stable",
    };

    let machine_metrics = read_machine_metrics().await;
    let cpu_current = machine_metrics.cpu_usage_percent;
    let memory_current = machine_metrics.memory_usage_percent;

    let network_throughput_current = (dns_requests + http_requests) * 1024;

    // Get recent events for last 5 minutes
    let recent_events_count = collection
        .count_documents(doc! { "processed_at": { "$gte": five_minutes_ago_bson } })
        .await
        .unwrap_or(0);

    Ok(Json(ApiResponse {
        success: true,
        data: SystemMetrics {
            cpu_current,
            cpu_trend: if cpu_current > 50.0 {
                "up".to_string()
            } else {
                "stable".to_string()
            },
            memory_current,
            memory_trend: if memory_current > 300.0 {
                "up".to_string()
            } else {
                "stable".to_string()
            },
            alerts_per_hour,
            alerts_trend: alerts_trend.to_owned(),
            network_throughput_current,
            network_trend: if network_throughput_current > 100_000 {
                "up".to_string()
            } else {
                "stable".to_string()
            },
            events_processed: total_events,
            recent_events: recent_events_count,
            dns_requests,
            http_requests,
        },
    }))
}

// Log collection endpoints

async fn submit_log(
    State(state): State<Arc<AppState>>,
    Json(log_submission): Json<LogSubmission>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let url = format!("{}/collect", state.raspi_endpoint);

    let raw_log_event = serde_json::json!({
        "id": Uuid::new_v4().to_string(),
        "timestamp": Utc::now(),
        "source_ip": log_submission.source_ip,
        "dest_ip": log_submission.dest_ip,
        "source_port": log_submission.source_port,
        "dest_port": log_submission.dest_port,
        "protocol": log_submission.protocol,
        "payload": log_submission.payload,
        "severity": log_submission.severity,
        "event_type": log_submission.event_type
    });

    match state
        .raspi_client
        .post(&url)
        .json(&raw_log_event)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            let result: serde_json::Value = response.json().await.unwrap_or_default();
            Ok(Json(serde_json::json!({
                "success": true,
                "message": "Log submitted to raspi-collector",
                "raspi_response": result
            })))
        }
        Ok(response) => {
            eprintln!("Raspi-collector returned status: {}", response.status());
            Err(StatusCode::BAD_GATEWAY)
        }
        Err(e) => {
            eprintln!("Failed to connect to raspi-collector: {}", e);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

async fn simulate_logs(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let url = format!("{}/simulate", state.raspi_endpoint);

    match state.raspi_client.post(&url).send().await {
        Ok(response) if response.status().is_success() => {
            let result: serde_json::Value = response.json().await.unwrap_or_default();
            Ok(Json(serde_json::json!({
                "success": true,
                "message": "Log simulation triggered",
                "raspi_response": result
            })))
        }
        Ok(response) => {
            eprintln!(
                "Raspi-collector simulation returned status: {}",
                response.status()
            );
            Err(StatusCode::BAD_GATEWAY)
        }
        Err(e) => {
            eprintln!("Failed to trigger simulation: {}", e);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

async fn get_eve_json_logs(State(state): State<Arc<AppState>>) -> Result<String, StatusCode> {
    let data = tokio::fs::read_to_string(&state.eve_json_path)
        .await
        .map_err(|e| {
            eprintln!(
                "Failed to read eve.json at {}: {}",
                state.eve_json_path.display(),
                e
            );
            StatusCode::NOT_FOUND
        })?;

    if data.len() > 2_000_000 {
        let start = data.len().saturating_sub(2_000_000);
        let tail_start = data
            .char_indices()
            .find_map(|(idx, _)| (idx >= start).then_some(idx))
            .unwrap_or(0);
        return Ok(data[tail_start..].to_string());
    }

    Ok(data)
}

// Service status endpoints

async fn get_raspi_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<RaspiStatus>>, StatusCode> {
    let url = format!("{}/status", state.raspi_endpoint);

    match state.raspi_client.get(&url).send().await {
        Ok(response) if response.status().is_success() => {
            let status_response: serde_json::Value = response.json().await.unwrap_or_default();

            let raspi_status = RaspiStatus {
                status: status_response["status"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                events_collected: status_response["metrics"]["events_collected"]
                    .as_u64()
                    .unwrap_or(0),
                events_sent: status_response["metrics"]["events_sent"]
                    .as_u64()
                    .unwrap_or(0),
                failed_sends: status_response["metrics"]["failed_sends"]
                    .as_u64()
                    .unwrap_or(0),
                vps_connection: status_response["vps_connection"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
            };

            Ok(Json(ApiResponse {
                success: true,
                data: raspi_status,
            }))
        }
        _ => Err(StatusCode::BAD_GATEWAY),
    }
}

async fn get_raspi_vps_connection(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<ConnectionStatus>>, StatusCode> {
    let cached = state.raspi_connection_cache.read().await.clone();
    Ok(Json(ApiResponse {
        success: true,
        data: cached,
    }))
}

async fn get_vps_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<VpsStatus>>, StatusCode> {
    let total = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events")
        .count_documents(doc! {})
        .await
        .unwrap_or(0);

    let one_hour_ago = BsonDateTime::from_millis(
        (Utc::now() - chrono::Duration::hours(1)).timestamp_millis(),
    );
    let recent = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events")
        .count_documents(doc! { "processed_at": { "$gte": one_hour_ago } })
        .await
        .unwrap_or(0);

    Ok(Json(ApiResponse {
        success: true,
        data: VpsStatus {
            status: "running".to_string(),
            events_processed: total,
            alerts_processed: recent,
            processing_rate: recent as f64 / 3600.0,
        },
    }))
}

async fn block_ip_manual(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ManualBlockRequest>,
) -> Result<Json<ApiResponse<PreventionActionResponse>>, StatusCode> {
    let duration_hours = request.duration_hours.unwrap_or(1);

    // Persist the block intent to MongoDB on the VPS so it survives restarts and
    // is queryable by the dashboard without needing the Raspi to be online.
    let blocked_at = chrono::Utc::now();
    let expires_at = blocked_at + chrono::Duration::hours(duration_hours as i64);
    let record = BlockedIpRecord {
        ip: request.ip.clone(),
        reason: request.reason.clone(),
        severity: 8,
        source: "manual_dashboard".to_string(),
        blocked_at: blocked_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        active: true,
        blocked_at_dt: Some(mongodb::bson::DateTime::from_millis(blocked_at.timestamp_millis())),
        expires_at_dt: Some(mongodb::bson::DateTime::from_millis(expires_at.timestamp_millis())),
        unblocked_at_dt: None,
        unblock_reason: None,
    };
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<BlockedIpRecord>("blocked_ips");
    if let Err(e) = collection.insert_one(record).await {
        tracing::warn!("Failed to persist block record for {} to MongoDB: {}", request.ip, e);
    }

    // Send the actual enforcement command to all connected Raspi devices via WebSocket.
    // The Raspi sits between the router and the network and will apply iptables rules.
    broadcast_block_command(
        &state,
        &request.ip,
        &request.reason,
        duration_hours * 3600,
        8,
        None,
    );

    Ok(Json(ApiResponse {
        success: true,
        data: PreventionActionResponse {
            success: true,
            message: format!("Block command for {} sent to edge device", request.ip),
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
    }))
}

async fn unblock_ip_manual(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ManualUnblockRequest>,
) -> Result<Json<ApiResponse<PreventionActionResponse>>, StatusCode> {
    // Mark the block record as inactive in VPS MongoDB.
    let now = chrono::Utc::now();
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<BlockedIpRecord>("blocked_ips");
    if let Err(e) = collection
        .update_one(
            mongodb::bson::doc! { "ip": &request.ip, "active": true },
            mongodb::bson::doc! {
                "$set": {
                    "active": false,
                    "unblocked_at_dt": mongodb::bson::DateTime::from_millis(now.timestamp_millis()),
                    "unblock_reason": request.reason.clone()
                }
            },
        )
        .await
    {
        tracing::warn!("Failed to update block record for {} in MongoDB: {}", request.ip, e);
    }

    // Send unblock command to Raspi devices via WebSocket.
    broadcast_unblock_command(&state, &request.ip, &request.reason, None);

    Ok(Json(ApiResponse {
        success: true,
        data: PreventionActionResponse {
            success: true,
            message: format!("Unblock command for {} sent to edge device", request.ip),
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
    }))
}

async fn get_blocked_ips(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<Vec<serde_json::Value>>>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<BlockedIpRecord>("blocked_ips");
    let find_opts = mongodb::options::FindOptions::builder()
        .sort(mongodb::bson::doc! { "blocked_at_dt": -1 })
        .build();
    let mut cursor = collection
        .find(mongodb::bson::doc! { "active": true })
        .with_options(find_opts)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut results: Vec<serde_json::Value> = Vec::new();
    while let Some(record) = cursor
        .try_next()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        results.push(serde_json::json!({
            "ip": record.ip,
            "reason": record.reason,
            "severity": record.severity,
            "threat_level": record.severity,
            "source": record.source,
            "blocked_at": record.blocked_at,
            "expires_at": record.expires_at,
            "active": record.active,
            "dns_names": [],
            "associated_domains": [],
        }));
    }
    Ok(Json(ApiResponse {
        success: true,
        data: results,
    }))
}

async fn get_prevention_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<BlockedIpRecord>("blocked_ips");
    let active_count = collection
        .count_documents(mongodb::bson::doc! { "active": true })
        .await
        .unwrap_or(0);
    let total_count = collection
        .count_documents(mongodb::bson::doc! {})
        .await
        .unwrap_or(0);
    Ok(Json(ApiResponse {
        success: true,
        data: serde_json::json!({
            "active_blocks": active_count,
            "total_blocks_ever": total_count,
            "enforcement": "raspi_edge",
        }),
    }))
}

async fn unblock_ip_by_path(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Result<Json<ApiResponse<PreventionActionResponse>>, StatusCode> {
    let now = chrono::Utc::now();
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<BlockedIpRecord>("blocked_ips");
    if let Err(e) = collection
        .update_one(
            mongodb::bson::doc! { "ip": &ip, "active": true },
            mongodb::bson::doc! {
                "$set": {
                    "active": false,
                    "unblocked_at_dt": mongodb::bson::DateTime::from_millis(now.timestamp_millis()),
                    "unblock_reason": "path_unblock"
                }
            },
        )
        .await
    {
        tracing::warn!("Failed to update block record for {} in MongoDB: {}", ip, e);
    }

    broadcast_unblock_command(&state, &ip, "path_unblock", None);

    Ok(Json(ApiResponse {
        success: true,
        data: PreventionActionResponse {
            success: true,
            message: format!("Unblock command for {} sent to edge device", ip),
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
    }))
}

/// Proxy the raspi-collector's /debug endpoint so the dashboard can read Pi debug state.
async fn get_edge_debug(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let url = format!("{}/debug", state.raspi_endpoint);
    match state.raspi_client.get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
            Ok(Json(body))
        }
        Ok(resp) => {
            Ok(Json(serde_json::json!({
                "error": format!("raspi-collector returned {}", resp.status()),
                "raspi_endpoint": state.raspi_endpoint
            })))
        }
        Err(e) => {
            Ok(Json(serde_json::json!({
                "error": format!("Could not reach raspi-collector: {}", e),
                "raspi_endpoint": state.raspi_endpoint
            })))
        }
    }
}

async fn get_all_services_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let raspi_future = get_raspi_status(State(state.clone()));
    let vps_future = get_vps_status(State(state.clone()));

    let (raspi_result, vps_result) = tokio::join!(raspi_future, vps_future);

    let raspi_ok = raspi_result.is_ok();
    let vps_ok = vps_result.is_ok();

    let overall_status = match (raspi_ok, vps_ok) {
        (true, true) => "healthy",
        (true, false) => "degraded",
        (false, true) => "degraded",
        (false, false) => "critical",
    };

    Ok(Json(serde_json::json!({
        "success": true,
        "overall_status": overall_status,
        "services": {
            "raspi-collector": {
                "status": if raspi_ok { "online" } else { "offline" },
                "endpoint": state.raspi_endpoint
            },
            "api-gateway": {
                "status": "online",
                "endpoint": "0.0.0.0:8080"
            },
            "mongodb": {
                "status": if vps_ok { "online" } else { "degraded" },
                "endpoint": "mongodb:27017"
            }
        },
        "timestamp": Utc::now()
    })))
}

fn severity_label(severity: u32) -> &'static str {
    match severity {
        1 => "critical",
        2 => "high",
        3 => "medium",
        4..=10 => "low",
        _ => "unknown",
    }
}

// ─── Detection Settings helpers ──────────────────────────────────────────────

async fn load_detection_settings_from_db(mongo_client: &mongodb::Client) -> DetectionSettings {
    let coll = mongo_client
        .database("idps_database")
        .collection::<DetectionSettings>("detection_settings");
    match coll.find_one(doc! {}).await {
        Ok(Some(settings)) => settings,
        _ => {
            // Seed defaults into MongoDB
            let defaults = DetectionSettings::default();
            let _ = coll.insert_one(defaults.clone()).await;
            defaults
        }
    }
}

async fn get_detection_settings(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DetectionSettings>, StatusCode> {
    let settings = state.detection_settings.read().await.clone();
    Ok(Json(settings))
}

async fn update_detection_settings(
    State(state): State<Arc<AppState>>,
    Json(mut body): Json<DetectionSettings>,
) -> Result<Json<DetectionSettings>, StatusCode> {
    body.updated_at = Utc::now();

    let coll = state
        .mongo_client
        .database("idps_database")
        .collection::<DetectionSettings>("detection_settings");

    let update = mongodb::bson::to_document(&body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = coll
        .update_one(doc! {}, doc! { "$set": update })
        .upsert(true)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update in-memory cache
    let mut cached = state.detection_settings.write().await;
    *cached = body.clone();

    Ok(Json(body))
}

// ─── Auto-block Settings endpoints ─────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct AutoBlockSettings {
    pub enabled: bool,
    pub block_duration_hours: u64,
    pub min_threat_level: u8,
    pub whitelist: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

impl From<DetectionSettings> for AutoBlockSettings {
    fn from(settings: DetectionSettings) -> Self {
        Self {
            enabled: settings.auto_block_enabled,
            block_duration_hours: settings.block_duration_hours,
            min_threat_level: settings.min_alert_level,
            whitelist: settings.whitelist,
            updated_at: settings.updated_at,
        }
    }
}

async fn get_auto_block_settings(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AutoBlockSettings>, StatusCode> {
    let settings = state.detection_settings.read().await.clone();
    Ok(Json(AutoBlockSettings::from(settings)))
}

#[derive(Debug, Deserialize)]
struct AutoBlockUpdateRequest {
    pub enabled: Option<bool>,
    pub block_duration_hours: Option<u64>,
    pub min_threat_level: Option<u8>,
    pub whitelist: Option<Vec<String>>,
}

async fn update_auto_block_settings(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AutoBlockUpdateRequest>,
) -> Result<Json<AutoBlockSettings>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<DetectionSettings>("detection_settings");

    // Load current settings
    let mut current_settings = load_detection_settings_from_db(&state.mongo_client).await;

    // Update only provided fields
    if let Some(enabled) = request.enabled {
        current_settings.auto_block_enabled = enabled;
    }
    if let Some(duration) = request.block_duration_hours {
        current_settings.block_duration_hours = duration;
    }
    if let Some(level) = request.min_threat_level {
        current_settings.min_alert_level = level;
    }
    if let Some(whitelist) = request.whitelist {
        current_settings.whitelist = whitelist;
    }
    current_settings.updated_at = Utc::now();

    // Update cache
    {
        let mut cached = state.detection_settings.write().await;
        *cached = current_settings.clone();
    }

    // Persist to MongoDB
    if let Err(e) = collection.replace_one(doc! {}, &current_settings).await {
        eprintln!("Failed to persist auto-block settings: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(AutoBlockSettings::from(current_settings)))
}

#[derive(Debug, Deserialize)]
struct EnableAutoBlockRequest {
    pub reason: Option<String>,
    pub duration_hours: Option<u64>,
}

async fn enable_auto_block(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EnableAutoBlockRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<DetectionSettings>("detection_settings");

    let mut current_settings = load_detection_settings_from_db(&state.mongo_client).await;
    
    current_settings.auto_block_enabled = true;
    if let Some(duration) = request.duration_hours {
        current_settings.block_duration_hours = duration;
    }
    current_settings.updated_at = Utc::now();

    // Update cache
    {
        let mut cached = state.detection_settings.write().await;
        *cached = current_settings.clone();
    }

    // Persist to MongoDB
    if let Err(e) = collection.replace_one(doc! {}, &current_settings).await {
        eprintln!("Failed to enable auto-block: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let reason = request.reason.unwrap_or_else(|| "Manual enable via API".to_string());
    info!("Auto-block enabled: {}", reason);

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Auto-block enabled successfully",
        "enabled": true,
        "block_duration_hours": current_settings.block_duration_hours,
        "timestamp": Utc::now().to_rfc3339()
    })))
}

#[derive(Debug, Deserialize)]
struct DisableAutoBlockRequest {
    pub reason: Option<String>,
}

async fn disable_auto_block(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DisableAutoBlockRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<DetectionSettings>("detection_settings");

    let mut current_settings = load_detection_settings_from_db(&state.mongo_client).await;
    
    current_settings.auto_block_enabled = false;
    current_settings.updated_at = Utc::now();

    // Update cache
    {
        let mut cached = state.detection_settings.write().await;
        *cached = current_settings.clone();
    }

    // Persist to MongoDB
    if let Err(e) = collection.replace_one(doc! {}, &current_settings).await {
        eprintln!("Failed to disable auto-block: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let reason = request.reason.unwrap_or_else(|| "Manual disable via API".to_string());
    info!("Auto-block disabled: {}", reason);

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Auto-block disabled successfully",
        "enabled": false,
        "timestamp": Utc::now().to_rfc3339()
    })))
}

#[derive(Debug, Serialize)]
struct AutoBlockStatus {
    pub enabled: bool,
    pub block_duration_hours: u64,
    pub min_threat_level: u8,
    pub whitelist_count: usize,
    pub last_updated: String,
    pub active_blocks: u64,
    pub blocks_today: u64,
    pub blocks_this_week: u64,
}

async fn get_auto_block_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AutoBlockStatus>, StatusCode> {
    let settings = state.detection_settings.read().await.clone();
    
    // Get block statistics from MongoDB
    let collection = state
        .mongo_client
        .database("idps_database")
        .collection::<BlockedIpRecord>("blocked_ips");

    let now = Utc::now();
    let today_start = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
    let week_start = now - chrono::Duration::days(7);

    let active_blocks = collection
        .count_documents(doc! { "active": true })
        .await
        .unwrap_or(0);

    let blocks_today = collection
        .count_documents(doc! {
            "active": true,
            "blocked_at_dt": { "$gte": BsonDateTime::from_millis(today_start.timestamp_millis()) }
        })
        .await
        .unwrap_or(0);

    let blocks_this_week = collection
        .count_documents(doc! {
            "active": true,
            "blocked_at_dt": { "$gte": BsonDateTime::from_millis(week_start.timestamp_millis()) }
        })
        .await
        .unwrap_or(0);

    Ok(Json(AutoBlockStatus {
        enabled: settings.auto_block_enabled,
        block_duration_hours: settings.block_duration_hours,
        min_threat_level: settings.min_alert_level,
        whitelist_count: settings.whitelist.len(),
        last_updated: settings.updated_at.to_rfc3339(),
        active_blocks,
        blocks_today,
        blocks_this_week,
    }))
}

// ─── Detection Events handlers ────────────────────────────────────────────────

async fn get_detection_events(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DetectionEventsQuery>,
) -> Result<Json<Value>, StatusCode> {
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(200);
    let skip = ((page - 1) * limit) as u64;

    let coll = state
        .mongo_client
        .database("idps_database")
        .collection::<DetectionEvent>("detection_events");

    let total = coll.count_documents(doc! {}).await.unwrap_or(0);

    let find_opts = FindOptions::builder()
        .sort(doc! { "timestamp": -1 })
        .skip(skip)
        .limit(limit as i64)
        .build();

    let mut cursor = coll
        .find(doc! {})
        .with_options(find_opts)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut events = Vec::new();
    while let Ok(Some(event)) = cursor.try_next().await {
        events.push(event);
    }

    Ok(Json(serde_json::json!({
        "events": events,
        "pagination": {
            "total_count": total,
            "current_page": page,
            "per_page": limit,
            "total_pages": (total as f64 / limit as f64).ceil() as u64,
        }
    })))
}

async fn get_active_detection_events(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<DetectionEvent>> {
    let since = Utc::now() - chrono::Duration::hours(1);
    let since_bson = BsonDateTime::from_millis(since.timestamp_millis());

    let coll = state
        .mongo_client
        .database("idps_database")
        .collection::<DetectionEvent>("detection_events");

    let find_opts = FindOptions::builder()
        .sort(doc! { "timestamp": -1 })
        .limit(20)
        .build();

    let mut cursor = match coll
        .find(doc! { "timestamp": { "$gte": since_bson } })
        .with_options(find_opts)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("detection/active: MongoDB find failed: {}", e);
            return Json(vec![]);
        }
    };

    let mut events = Vec::new();
    while let Some(result) = cursor.try_next().await.transpose() {
        match result {
            Ok(event) => events.push(event),
            Err(e) => tracing::warn!("detection/active: skipping malformed document: {}", e),
        }
    }

    Json(events)
}

// ─── Brute Force Detection Loop ───────────────────────────────────────────────

/// Background task: polls MongoDB for recent Suricata HTTP/DNS events and
/// detects brute force patterns based on configured thresholds.
async fn run_detection_loop(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    loop {
        interval.tick().await;

        let settings = state.detection_settings.read().await.clone();

        // Update IP→domain map from recent DNS events
        if settings.dns_enrichment_enabled {
            update_ip_domain_map(&state, &settings).await;
        }

        // Check HTTP events for brute force patterns
        if let Err(e) = check_brute_force(&state, &settings).await {
            tracing::warn!("Brute force detection error: {}", e);
        }
    }
}

async fn update_ip_domain_map(state: &Arc<AppState>, _settings: &DetectionSettings) {
    let since = Utc::now() - chrono::Duration::minutes(10);
    let since_bson = BsonDateTime::from_millis(since.timestamp_millis());

    let coll = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events");

    let filter = doc! {
        "event_type": "dns",
        "processed_at": { "$gte": since_bson }
    };

    let Ok(mut cursor) = coll.find(filter).await else { return };

    while let Ok(Some(event)) = cursor.try_next().await {
        let Some(src_ip) = &event.src_ip else { continue };
        let Some(dns) = &event.dns else { continue };
        let Some(queries) = &dns.queries else { continue };
        for query in queries {
            if let Some(rrname) = &query.rrname {
                let mut entry = state.ip_domain_map.entry(src_ip.clone()).or_default();
                if !entry.contains(rrname) {
                    entry.push(rrname.clone());
                }
            }
        }
    }
}

async fn check_brute_force(
    state: &Arc<AppState>,
    settings: &DetectionSettings,
) -> Result<(), anyhow::Error> {
    let window_secs = settings.brute_force_window_seconds as i64;
    let since = Utc::now() - chrono::Duration::seconds(window_secs);
    let since_bson = BsonDateTime::from_millis(since.timestamp_millis());

    let coll = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events");

    let filter = doc! {
        "event_type": "http",
        "processed_at": { "$gte": since_bson }
    };

    let Ok(mut cursor) = coll.find(filter).await else {
        return Ok(());
    };

    // Accumulate request timestamps per (src_ip, path)
    while let Ok(Some(event)) = cursor.try_next().await {
        let Some(src_ip) = &event.src_ip else { continue };
        let Some(http) = &event.http else { continue };
        let Some(url) = &http.url else { continue };

        // Extract path (strip query string)
        let path = url.split('?').next().unwrap_or(url).to_string();

        // Only track monitored paths
        let is_monitored = settings
            .monitored_paths
            .iter()
            .any(|p| path.starts_with(p.as_str()));
        if !is_monitored {
            continue;
        }

        // Parse event timestamp
        let ts = if let Some(processed) = event.processed_at {
            chrono::DateTime::from_timestamp_millis(processed.timestamp_millis())
                .unwrap_or_else(Utc::now)
        } else if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&event.timestamp) {
            t.with_timezone(&Utc)
        } else {
            Utc::now()
        };

        let key = (src_ip.clone(), path.clone());
        let mut timestamps = state.brute_force_tracker.entry(key).or_default();

        // Remove timestamps outside the window
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs);
        timestamps.retain(|t| *t > cutoff);
        timestamps.push(ts);
    }

    // Check thresholds and fire detections
    let mut to_block: Vec<(String, String, u32)> = vec![];

    for entry in state.brute_force_tracker.iter() {
        let (src_ip, path) = entry.key();
        let count = entry.value().len() as u32;
        if count >= settings.brute_force_threshold {
            to_block.push((src_ip.clone(), path.clone(), count));
        }
    }

    for (src_ip, path, count) in to_block {
        // Skip whitelisted IPs — never auto-block internal school ranges
        if is_whitelisted(&src_ip, &settings.whitelist) {
            tracing::debug!("Skipping brute-force detection for whitelisted IP {}", src_ip);
            state.brute_force_tracker.remove(&(src_ip, path));
            continue;
        }

        tracing::warn!(
            "Brute force detected: {} → {} ({} requests in {}s window)",
            src_ip, path, count, window_secs
        );

        let dns_names = state
            .ip_domain_map
            .get(&src_ip)
            .map(|v| v.clone())
            .unwrap_or_default();

        let triggered_block = settings.auto_block_enabled;

        // Persist detection event
        let detection_event = DetectionEvent {
            id: Uuid::new_v4().to_string(),
            src_ip: src_ip.clone(),
            detected_pattern: "BruteForce".to_string(),
            path: path.clone(),
            request_count: count,
            window_seconds: settings.brute_force_window_seconds,
            triggered_block,
            timestamp: Utc::now(),
            dns_names: dns_names.clone(),
        };

        let events_coll = state
            .mongo_client
            .database("idps_database")
            .collection::<DetectionEvent>("detection_events");
        let _ = events_coll.insert_one(detection_event).await;

        // Auto-block: persist intent to VPS MongoDB and send enforcement command to Raspi.
        if triggered_block {
            let blocked_at = chrono::Utc::now();
            let expires_at = blocked_at + chrono::Duration::hours(settings.block_duration_hours as i64);
            let record = BlockedIpRecord {
                ip: src_ip.clone(),
                reason: format!("BruteForce: {} requests on {} in {}s", count, path, window_secs),
                severity: 8,
                source: "auto_detection".to_string(),
                blocked_at: blocked_at.to_rfc3339(),
                expires_at: expires_at.to_rfc3339(),
                active: true,
                blocked_at_dt: Some(mongodb::bson::DateTime::from_millis(blocked_at.timestamp_millis())),
                expires_at_dt: Some(mongodb::bson::DateTime::from_millis(expires_at.timestamp_millis())),
                unblocked_at_dt: None,
                unblock_reason: None,
            };
            let coll = state
                .mongo_client
                .database("idps_database")
                .collection::<BlockedIpRecord>("blocked_ips");
            if let Err(e) = coll.insert_one(record).await {
                tracing::warn!("Failed to persist auto-block record for {}: {}", src_ip, e);
            }
            tracing::info!("Auto-block command sent to Raspi for {} (brute force on {})", src_ip, path);
            broadcast_block_command(
                state,
                &src_ip,
                &format!("BruteForce: {} requests on {} in {}s", count, path, window_secs),
                settings.block_duration_hours * 3600,
                8,
                None,
            );
        }

        // Always broadcast alert to dashboard
        broadcast_dashboard_alert(
            state,
            &src_ip,
            if triggered_block { "critical" } else { "high" },
            "BruteForce",
            &format!("{} requests on {} in {}s window", count, path, window_secs),
            triggered_block,
        );

        // Clear tracker entry after handling
        state
            .brute_force_tracker
            .remove(&(src_ip, path));
    }

    Ok(())
}

// ─── WebSocket Handlers ───────────────────────────────────────────────────────

/// `/ws` — Dashboard real-time feed.
/// Streams `Alert` and `Metrics` messages to connected admin clients.
async fn ws_dashboard_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_dashboard_ws(socket, state))
}

async fn handle_dashboard_ws(mut socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.dashboard_tx.subscribe();
    tracing::info!("Dashboard WebSocket client connected");

    // Send initial heartbeat so the client knows it's connected
    let ping = serde_json::json!({ "type": "ping", "timestamp": Utc::now() });
    if socket.send(Message::Text(ping.to_string().into())).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Dashboard WS client lagged by {} messages", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            // Client may send pings; drain them to keep connection alive
            client_msg = socket.recv() => {
                match client_msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    tracing::info!("Dashboard WebSocket client disconnected");
}

/// `/ws/raspi` — Raspi device command channel.
/// Streams `BlockCommand`, `UnblockCommand`, and `RuleUpdate` messages.
async fn ws_raspi_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_raspi_ws(socket, state))
}

async fn handle_raspi_ws(mut socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.raspi_tx.subscribe();
    tracing::info!("Raspi WebSocket client connected");

    // Acknowledge connection
    let ack = serde_json::json!({ "type": "connected", "timestamp": Utc::now() });
    if socket.send(Message::Text(ack.to_string().into())).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Raspi WS client lagged by {} messages", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            // Receive acks and pings from Raspi
            raspi_msg = socket.recv() => {
                match raspi_msg {
                    Some(Ok(Message::Text(text))) => {
                        tracing::debug!("Raspi WS ack: {}", text);
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    tracing::info!("Raspi WebSocket client disconnected");
}

// ─── Auth Structs ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    exp: usize,
    iat: usize,
}

// ─── Login Handler ────────────────────────────────────────────────────────────

async fn login_handler(Json(req): Json<LoginRequest>) -> Response {
    let expected_user = std::env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".into());
    let expected_pass = std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "changeme".into());
    let jwt_secret    = std::env::var("JWT_SECRET").unwrap_or_else(|_| "change-this-in-production".into());

    let user_ok = req.username == expected_user;
    let pass_ok = if expected_pass.starts_with("$2") {
        bcrypt::verify(&req.password, &expected_pass).unwrap_or(false)
    } else {
        req.password == expected_pass
    };

    if !user_ok || !pass_ok {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Invalid credentials" }))).into_response();
    }

    let now = Utc::now().timestamp() as usize;
    let claims = JwtClaims { sub: req.username, exp: now + 86_400, iat: now };

    match jsonwebtoken::encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret.as_bytes())) {
        Ok(token) => (StatusCode::OK, Json(LoginResponse { token, expires_in: 86_400 })).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Token generation failed" }))).into_response(),
    }
}

// ─── JWT Auth Middleware ──────────────────────────────────────────────────────

const PUBLIC_PATHS: &[&str] = &[
    "/", "/health", "/api/health", "/api/config", "/metrics", "/api/auth/login", "/api/vps/auth/login",
];

/// Paths used exclusively by edge devices — skip JWT, still require IP whitelist.
const INTERNAL_INGEST_PREFIXES: &[&str] = &[
    "/api/alerts/ingest", "/api/traffic", "/api/telemetry", "/api/logs/submit",
];

async fn jwt_auth(request: Request<axum::body::Body>, next: Next) -> Response {
    let path = request.uri().path();

    if PUBLIC_PATHS.contains(&path)
        || INTERNAL_INGEST_PREFIXES.iter().any(|p| path.starts_with(p))
    {
        return next.run(request).await;
    }

    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "change-this-in-production".into());

    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| {
            // WebSocket clients pass token as query param
            request.uri().query().and_then(|q| {
                q.split('&').find_map(|pair| {
                    let (k, v) = pair.split_once('=')?;
                    if k == "token" { Some(v.to_string()) } else { None }
                })
            })
        });

    let Some(token) = token else {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Missing authentication token" }))).into_response();
    };

    match jsonwebtoken::decode::<JwtClaims>(&token, &DecodingKey::from_secret(jwt_secret.as_bytes()), &Validation::default()) {
        Ok(_) => next.run(request).await,
        Err(_) => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Invalid or expired token" }))).into_response(),
    }
}

// ─── IP Whitelist Middleware ──────────────────────────────────────────────────

const ALLOWED_PUBLIC_IPS: &[&str] = &["109.133.17.150", "45.86.200.231"];

async fn ip_whitelist_middleware(request: Request<axum::body::Body>, next: Next) -> Response {
    if PUBLIC_PATHS.contains(&request.uri().path()) {
        return next.run(request).await;
    }

    // Requests with a Bearer token or WS query-param token are authenticated via JWT — skip IP check.
    let has_bearer = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("Bearer "))
        .unwrap_or(false);
    let has_token_param = request
        .uri()
        .query()
        .map(|q| q.split('&').any(|p| p.starts_with("token=")))
        .unwrap_or(false);
    if has_bearer || has_token_param {
        return next.run(request).await;
    }

    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .or_else(|| request.headers().get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .unwrap_or_default();

    let allowed = client_ip.is_empty()
        || client_ip == "127.0.0.1"
        || client_ip == "::1"
        || client_ip.starts_with("192.168.")
        || client_ip.starts_with("10.")
        || (client_ip.starts_with("172.") && {
            let oct: u8 = client_ip.split('.').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            (16..=31).contains(&oct)
        })
        || ALLOWED_PUBLIC_IPS.contains(&client_ip.as_str());

    if allowed {
        next.run(request).await
    } else {
        tracing::warn!("Blocked request from non-whitelisted IP: {}", client_ip);
        (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Access denied: IP not whitelisted" }))).into_response()
    }
}

// ─── Whitelist Helper ─────────────────────────────────────────────────────────

/// Check if an IP address matches any entry in the whitelist.
/// Supports exact IP matches and simple CIDR prefix notation (e.g. "192.168.0.0/16").
fn is_whitelisted(ip: &str, whitelist: &[String]) -> bool {
    for entry in whitelist {
        if entry == ip || idps_utils::is_in_cidr(ip, entry).unwrap_or(false) {
            return true;
        }
    }
    false
}

// ─── Broadcast Helpers ────────────────────────────────────────────────────────

/// Send a BlockCommand JSON message to all connected Raspi WebSocket clients.
fn broadcast_block_command(
    state: &Arc<AppState>,
    ip: &str,
    reason: &str,
    duration_secs: u64,
    severity: u8,
    detection_event_id: Option<String>,
) {
    let msg = serde_json::json!({
        "type": "block_command",
        "id": Uuid::new_v4().to_string(),
        "timestamp": Utc::now(),
        "ip": ip,
        "reason": reason,
        "duration_secs": duration_secs,
        "apply_suricata_rule": true,
        "severity": severity,
        "detection_event_id": detection_event_id
    });
    // Ignore send errors — no receivers just means no Raspi is connected right now
    let _ = state.raspi_tx.send(msg.to_string());
}

/// Send an UnblockCommand JSON message to all connected Raspi WebSocket clients.
fn broadcast_unblock_command(
    state: &Arc<AppState>,
    ip: &str,
    reason: &str,
    unblocked_by: Option<String>,
) {
    let msg = serde_json::json!({
        "type": "unblock_command",
        "id": Uuid::new_v4().to_string(),
        "timestamp": Utc::now(),
        "ip": ip,
        "reason": reason,
        "unblocked_by": unblocked_by
    });
    let _ = state.raspi_tx.send(msg.to_string());
}

/// Broadcast an alert to all connected dashboard WebSocket clients.
fn broadcast_dashboard_alert(
    state: &Arc<AppState>,
    src_ip: &str,
    severity: &str,
    category: &str,
    message: &str,
    auto_blocked: bool,
) {
    let msg = serde_json::json!({
        "type": "alert",
        "id": Uuid::new_v4().to_string(),
        "timestamp": Utc::now(),
        "severity": severity,
        "category": category,
        "message": message,
        "src_ip": src_ip,
        "auto_blocked": auto_blocked
    });
    let _ = state.dashboard_tx.send(msg.to_string());
}

// ─── Packet Streaming WebSocket (/ws/packets) ─────────────────────────────────

/// A raw packet streamed from the Raspberry Pi packet-processor.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct StreamedPacket {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    /// First 256 bytes of IP payload as hex string.
    pub payload_hex: String,
    pub packet_size: usize,
    pub interface: String,
}

/// Threat pattern with threat level and description.
struct ThreatPattern {
    name: &'static str,
    pattern: Regex,
    threat_level: u8,
}

fn build_threat_patterns() -> Vec<ThreatPattern> {
    vec![
        ThreatPattern {
            name: "SQL Injection",
            pattern: Regex::new(r"(?i)(?:union|select|insert|update|delete|drop|exec|script|--\s|/\*)").unwrap(),
            threat_level: 8,
        },
        ThreatPattern {
            name: "XSS Attack",
            pattern: Regex::new(r"(?i)(?:<script|javascript:|onerror=|onload=|eval\()").unwrap(),
            threat_level: 7,
        },
        ThreatPattern {
            name: "Command Injection",
            pattern: Regex::new(r"(?:;|\||\$\(|`|\.\./|/etc/passwd|/etc/shadow|cmd\.exe|powershell)").unwrap(),
            threat_level: 9,
        },
        ThreatPattern {
            name: "Path Traversal",
            pattern: Regex::new(r"(?:\.\./)").unwrap(),
            threat_level: 7,
        },
        ThreatPattern {
            name: "Shellshock",
            pattern: Regex::new(r"\(\)\s*\{").unwrap(),
            threat_level: 9,
        },
    ]
}

/// Analyse a hex-encoded payload string against known threat patterns.
/// Returns `(threat_level, pattern_name)` if a match is found.
fn analyse_payload(payload_hex: &str, patterns: &[ThreatPattern]) -> Option<(u8, &'static str)> {
    // Decode hex to UTF-8 (best-effort; ignore invalid bytes).
    let bytes: Vec<u8> = (0..payload_hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&payload_hex[i..i + 2], 16).ok())
        .collect();
    let text = String::from_utf8_lossy(&bytes);

    for p in patterns {
        if p.pattern.is_match(&text) {
            return Some((p.threat_level, p.name));
        }
    }
    None
}

/// `/ws/packets` — Receive streamed raw packets from the Raspberry Pi,
/// run deep analysis, and push block commands back via `/ws/raspi` when threats
/// are detected.
async fn ws_packets_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_packets_ws(socket, state))
}

async fn handle_packets_ws(mut socket: WebSocket, state: Arc<AppState>) {
    tracing::info!("Raspi packet stream WebSocket connected");

    let patterns = Arc::new(build_threat_patterns());

    // Per-source packet counter for lightweight DDoS/port-scan detection.
    // (src_ip → packet count in current window)
    let pkt_counter: DashMap<String, u64> = DashMap::new();
    // Distinct dest-ports per source IP in current window for port-scan detection.
    let port_tracker: DashMap<String, std::collections::HashSet<u16>> = DashMap::new();

    // Per-connection rate limiting (token bucket)
    let max_pps: u64 = std::env::var("MAX_PACKETS_PER_SECOND")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(10_000);
    let rate_limiting = std::env::var("RATE_LIMITING_ENABLED")
        .map(|v| v == "true" || v == "1").unwrap_or(true);
    let mut tokens: u64 = max_pps;
    let mut last_refill = tokio::time::Instant::now();

    while let Some(msg) = socket.recv().await {
        // Refill token bucket every second
        if rate_limiting {
            let now = tokio::time::Instant::now();
            if now.duration_since(last_refill) >= Duration::from_secs(1) {
                tokens = max_pps;
                last_refill = now;
            }
            if tokens == 0 {
                tracing::warn!("/ws/packets rate limit exceeded — dropping frame");
                continue;
            }
            tokens -= 1;
        }
        let text = match msg {
            Ok(Message::Text(t)) => t,
            Ok(Message::Close(_)) | Err(_) => break,
            _ => continue,
        };

        let pkt: StreamedPacket = match serde_json::from_str(&text) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("Failed to parse StreamedPacket: {}", e);
                continue;
            }
        };

        if pkt.src_ip.is_empty() {
            continue;
        }

        let settings = state.detection_settings.read().await.clone();

        // Skip whitelisted IPs.
        if is_whitelisted(&pkt.src_ip, &settings.whitelist) {
            continue;
        }

        // ── DDoS / flood detection ────────────────────────────────────────────
        let count = {
            let mut entry = pkt_counter.entry(pkt.src_ip.clone()).or_insert(0);
            *entry += 1;
            *entry
        };
        // Simple window: reset every 10 000 packets per IP (crude but cheap)
        if count > 10_000 {
            pkt_counter.insert(pkt.src_ip.clone(), 0);
        }

        if count == 500 {
            // 500 packets in a short burst — treat as DDoS / flood
            let reason = format!("DDoS/flood: {} packets in burst window", count);
            tracing::warn!("DDoS detected from {}: {}", pkt.src_ip, reason);

            if settings.auto_block_enabled {
                let rule = generate_ddos_rule(&pkt.src_ip, 500, settings.block_duration_hours);
                persist_and_broadcast_rule(&state, &pkt.src_ip, &reason, 9, &settings, rule).await;
            }

            broadcast_dashboard_alert(&state, &pkt.src_ip, "critical", "DDoS", &reason, settings.auto_block_enabled);
            continue;
        }

        // ── Port-scan detection ───────────────────────────────────────────────
        {
            let mut ports = port_tracker.entry(pkt.src_ip.clone()).or_default();
            ports.insert(pkt.dst_port);
            if ports.len() >= 30 {
                let reason = format!("Port scan: {} distinct ports contacted", ports.len());
                ports.clear();
                tracing::warn!("Port scan from {}: {}", pkt.src_ip, reason);

                if settings.auto_block_enabled {
                    let rule = generate_ip_block_rule(&pkt.src_ip, &reason, 7, settings.block_duration_hours);
                    persist_and_broadcast_rule(&state, &pkt.src_ip, &reason, 7, &settings, rule).await;
                }

                broadcast_dashboard_alert(&state, &pkt.src_ip, "high", "PortScan", &reason, settings.auto_block_enabled);
                continue;
            }
        }

        // ── Payload threat analysis ───────────────────────────────────────────
        if !pkt.payload_hex.is_empty() {
            if let Some((threat_level, pattern_name)) = analyse_payload(&pkt.payload_hex, &patterns) {
                if threat_level >= settings.min_alert_level {
                    let reason = format!("{} detected in payload (src={} dst={}:{})", pattern_name, pkt.src_ip, pkt.dst_ip, pkt.dst_port);
                    tracing::warn!("{}", reason);

                    if settings.auto_block_enabled && threat_level >= 7 {
                        let rule = generate_ip_block_rule(&pkt.src_ip, &reason, threat_level, settings.block_duration_hours);
                        persist_and_broadcast_rule(&state, &pkt.src_ip, &reason, threat_level, &settings, rule).await;
                    }

                    let sev = if threat_level >= 9 { "critical" } else if threat_level >= 7 { "high" } else { "medium" };
                    broadcast_dashboard_alert(&state, &pkt.src_ip, sev, pattern_name, &reason, settings.auto_block_enabled && threat_level >= 7);
                }
            }
        }
    }

    tracing::info!("Raspi packet stream WebSocket disconnected");
}

/// Persist a generated rule to MongoDB and broadcast it to Raspi via WebSocket.
async fn persist_and_broadcast_rule(
    state: &Arc<AppState>,
    ip: &str,
    reason: &str,
    severity: u8,
    settings: &DetectionSettings,
    rule: idps_rule_generator::GeneratedRule,
) {
    // 1. Store rule in MongoDB.
    let rule_doc = serde_json::json!({
        "rule_id": &rule.rule_id,
        "suricata_rule": &rule.suricata_rule,
        "iptables_rule": &rule.iptables_rule,
        "description": &rule.description,
        "severity": rule.severity,
        "expires_at": rule.expires_at,
        "created_at": Utc::now(),
        "active": true,
        "src_ip": ip,
    });
    let coll = state.mongo_client.database("idps").collection::<serde_json::Value>("security_rules");
    if let Err(e) = coll.insert_one(rule_doc).await {
        tracing::warn!("Failed to persist security rule for {}: {}", ip, e);
    }

    // 2. Persist blocked-IP record.
    let blocked_at = Utc::now();
    let expires_at = blocked_at + chrono::Duration::hours(settings.block_duration_hours as i64);
    let record = serde_json::json!({
        "ip": ip,
        "reason": reason,
        "severity": severity,
        "source": "packet_analysis",
        "blocked_at": blocked_at.to_rfc3339(),
        "expires_at": expires_at.to_rfc3339(),
        "active": true,
    });
    let blocked_coll = state.mongo_client.database("idps").collection::<serde_json::Value>("blocked_ips");
    let _ = blocked_coll.insert_one(record).await;

    // 3. Broadcast block_command to Raspi WebSocket.
    broadcast_block_command(
        state,
        ip,
        reason,
        settings.block_duration_hours * 3600,
        severity,
        None,
    );

    // 4. If a Suricata rule was generated, also send a rule_update message.
    if rule.suricata_rule.is_some() || rule.iptables_rule.is_some() {
        let msg = serde_json::json!({
            "type": "rule_update",
            "id": Uuid::new_v4().to_string(),
            "timestamp": Utc::now(),
            "rule_id": &rule.rule_id,
            "action": "add",
            "suricata_rule": &rule.suricata_rule,
            "iptables_rule": &rule.iptables_rule,
            "description": &rule.description,
        });
        let _ = state.raspi_tx.send(msg.to_string());
    }
}

// ── Telemetry ingest ──────────────────────────────────────────────────────────

/// Hardware metrics payload sent by the edge telemetry service.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EdgeSystemMetrics {
    pub device_id: String,
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub memory_used_mb: f64,
    pub memory_total_mb: f64,
    pub disk_usage_percent: f64,
    pub disk_used_gb: f64,
    pub disk_total_gb: f64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub temperature_celsius: Option<f64>,
    pub uptime_seconds: u64,
    pub load_average_1m: f64,
    pub timestamp: DateTime<Utc>,
}

/// Threshold breach alert emitted by the edge telemetry service.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TelemetryThresholdAlert {
    pub device_id: String,
    pub metric: String,
    pub value: f64,
    pub threshold: f64,
    pub severity: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

/// Full telemetry report (metrics + optional threshold alerts).
#[derive(Debug, Deserialize)]
struct TelemetryReport {
    pub metrics: EdgeSystemMetrics,
    pub alerts: Vec<TelemetryThresholdAlert>,
}

/// `POST /api/telemetry` — Receive hardware metrics from an edge device,
/// store in MongoDB, and broadcast to the dashboard WebSocket channel.
async fn ingest_telemetry(
    State(state): State<Arc<AppState>>,
    Json(report): Json<TelemetryReport>,
) -> Result<Json<Value>, StatusCode> {
    // Store metrics doc in MongoDB
    let coll = state
        .mongo_client
        .database("idps_database")
        .collection::<Value>("telemetry");

    let doc = serde_json::json!({
        "device_id": &report.metrics.device_id,
        "metrics": &report.metrics,
        "alerts": &report.alerts,
        "received_at": Utc::now(),
    });

    if let Err(e) = coll.insert_one(doc).await {
        tracing::warn!("Failed to store telemetry: {}", e);
    }

    // Broadcast to dashboard WebSocket clients
    let ws_msg = serde_json::json!({
        "type": "telemetry_update",
        "device_id": &report.metrics.device_id,
        "metrics": &report.metrics,
        "alerts": &report.alerts,
        "timestamp": Utc::now(),
    });
    let _ = state.dashboard_tx.send(ws_msg.to_string());

    // Log any threshold breaches
    for alert in &report.alerts {
        if alert.severity == "critical" {
            tracing::warn!(
                "Telemetry threshold breach [{}] {}: {}",
                alert.device_id,
                alert.metric,
                alert.message
            );
        }
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Telemetry received",
        "device_id": &report.metrics.device_id,
    })))
}

/// `GET /api/telemetry/latest` — Return the most recent telemetry doc per device.
async fn get_latest_telemetry(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, StatusCode> {
    let coll = state
        .mongo_client
        .database("idps_database")
        .collection::<Value>("telemetry");

    // Aggregate: latest doc per device_id
    let pipeline = vec![
        doc! { "$sort": { "received_at": -1 } },
        doc! { "$group": {
            "_id": "$device_id",
            "latest": { "$first": "$$ROOT" }
        }},
        doc! { "$replaceRoot": { "newRoot": "$latest" } },
    ];

    let mut cursor = coll
        .aggregate(pipeline)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut results: Vec<Value> = Vec::new();
    use futures_util::TryStreamExt;
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        let val: Value = mongodb::bson::from_document(doc).unwrap_or_default();
        results.push(val);
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "devices": results,
        "count": results.len(),
    })))
}

/// `POST /api/telemetry/alert` — Receive a single threshold alert from an edge device.
async fn ingest_telemetry_alert(
    State(state): State<Arc<AppState>>,
    Json(alert): Json<TelemetryThresholdAlert>,
) -> Result<Json<Value>, StatusCode> {
    tracing::warn!(
        "Edge threshold alert [{}] {}: {}",
        alert.device_id,
        alert.metric,
        alert.message
    );

    // Broadcast to dashboard
    let ws_msg = serde_json::json!({
        "type": "telemetry_alert",
        "device_id": &alert.device_id,
        "metric": &alert.metric,
        "value": alert.value,
        "threshold": alert.threshold,
        "severity": &alert.severity,
        "message": &alert.message,
        "timestamp": &alert.timestamp,
    });
    let _ = state.dashboard_tx.send(ws_msg.to_string());

    // Persist in MongoDB
    let coll = state
        .mongo_client
        .database("idps_database")
        .collection::<Value>("telemetry_alerts");
    let doc = serde_json::to_value(&alert).unwrap_or_default();
    let _ = coll.insert_one(doc).await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Threshold alert received",
    })))
}

// ── Suricata alert ingest ─────────────────────────────────────────────────────

/// Normalized Suricata alert forwarded by the log-processor.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SuricataAlertNotification {
    pub timestamp: String,
    pub src_ip: String,
    pub dest_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub proto: Option<String>,
    pub signature: String,
    pub category: String,
    /// Suricata severity scale: 1 (critical) … 7 (informational)
    pub severity: u32,
    pub action: String,
    pub signature_id: u32,
}

/// `POST /api/alerts/ingest` — Receive a Suricata alert from the log-processor,
/// store it in MongoDB, and push it to the dashboard WebSocket channel.
async fn ingest_suricata_alert(
    State(state): State<Arc<AppState>>,
    Json(alert): Json<SuricataAlertNotification>,
) -> Result<Json<Value>, StatusCode> {
    // Map Suricata severity (1=critical … 7=low) to a human label
    let severity_label = match alert.severity {
        1 => "critical",
        2 => "high",
        3 | 4 => "medium",
        _ => "low",
    };

    tracing::info!(
        "Suricata alert [{}] sig={} src={} severity={}",
        alert.action,
        alert.signature,
        alert.src_ip,
        severity_label
    );

    // Persist to dedicated collection
    let coll = state
        .mongo_client
        .database("idps_database")
        .collection::<Value>("suricata_alerts");

    let doc = serde_json::json!({
        "timestamp": &alert.timestamp,
        "src_ip": &alert.src_ip,
        "dest_ip": &alert.dest_ip,
        "src_port": alert.src_port,
        "dest_port": alert.dest_port,
        "proto": &alert.proto,
        "signature": &alert.signature,
        "category": &alert.category,
        "severity": alert.severity,
        "severity_label": severity_label,
        "action": &alert.action,
        "signature_id": alert.signature_id,
        "received_at": Utc::now(),
    });

    if let Err(e) = coll.insert_one(doc).await {
        tracing::warn!("Failed to store Suricata alert: {}", e);
    }

    // Broadcast real-time alert to all dashboard WebSocket clients
    let ws_msg = serde_json::json!({
        "type": "suricata_alert",
        "timestamp": &alert.timestamp,
        "src_ip": &alert.src_ip,
        "dest_ip": &alert.dest_ip,
        "signature": &alert.signature,
        "category": &alert.category,
        "severity": alert.severity,
        "severity_label": severity_label,
        "action": &alert.action,
        "signature_id": alert.signature_id,
    });
    let _ = state.dashboard_tx.send(ws_msg.to_string());

    // If the settings have auto-block enabled and the alert is high severity,
    // trigger a block via the existing pipeline.
    let settings = state.detection_settings.read().await.clone();
    if settings.auto_block_enabled && alert.severity <= 2 && !alert.src_ip.is_empty() {
        if !is_whitelisted(&alert.src_ip, &settings.whitelist) {
            let reason = format!("Suricata: {} (sig_id={})", alert.signature, alert.signature_id);
            let rule = generate_ip_block_rule(
                &alert.src_ip,
                &reason,
                alert.severity as u8,
                settings.block_duration_hours,
            );
            persist_and_broadcast_rule(
                &state,
                &alert.src_ip,
                &reason,
                alert.severity as u8,
                &settings,
                rule,
            )
            .await;
        }
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Suricata alert ingested",
        "severity_label": severity_label,
    })))
}

async fn ingest_traffic_event(
    State(state): State<Arc<AppState>>,
    Json(event): Json<TrafficEvent>,
) -> Result<Json<Value>, StatusCode> {
    let event_id = event.id.clone();
    let p = &event.payload;
    let eve_event = EveEvent {
        timestamp: event.timestamp.to_rfc3339(),
        flow_id: p.get("flow_id").and_then(|v| v.as_u64()),
        in_iface: p.get("in_iface").and_then(|v| v.as_str()).map(str::to_string),
        event_type: event.event_type.clone(),
        src_ip: Some(event.source_ip.clone()),
        src_port: Some(event.source_port),
        dest_ip: Some(event.dest_ip.clone()),
        dest_port: Some(event.dest_port),
        proto: Some(event.protocol.clone()),
        alert: p.get("alert").and_then(|v| serde_json::from_value(v.clone()).ok()),
        dns: p.get("dns").and_then(|v| serde_json::from_value(v.clone()).ok()),
        http: p.get("http").and_then(|v| serde_json::from_value(v.clone()).ok()),
        tls: p.get("tls").and_then(|v| serde_json::from_value(v.clone()).ok()),
        fileinfo: p.get("fileinfo").and_then(|v| serde_json::from_value(v.clone()).ok()),
        processed_at: Some(BsonDateTime::from_millis(Utc::now().timestamp_millis())),
    };

    let _ = state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events")
        .insert_one(eve_event)
        .await;

    // Broadcast to dashboard WebSocket clients
    let ws_msg = serde_json::json!({
        "type": "traffic_event",
        "event_id": &event_id,
        "src_ip": &event.source_ip,
        "dest_ip": &event.dest_ip,
        "event_type": &event.event_type,
        "threat_level": event.threat_level,
        "timestamp": event.timestamp,
    });
    let _ = state.dashboard_tx.send(ws_msg.to_string());

    // Process Suricata alert events through the auto-block pipeline
    {
        let settings = state.detection_settings.read().await.clone();
        process_suricata_alert_from_batch(&state, &event, &settings).await;
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "event_id": event_id,
    })))
}

async fn ingest_traffic_batch(
    State(state): State<Arc<AppState>>,
    Json(events): Json<Vec<TrafficEvent>>,
) -> Result<Json<Value>, StatusCode> {
    let count = events.len();
    if count == 0 {
        return Ok(Json(serde_json::json!({ "success": true, "stored": 0 })));
    }

    let now_bson = BsonDateTime::from_millis(Utc::now().timestamp_millis());
    let eve_events: Vec<EveEvent> = events
        .iter()
        .map(|event| {
            let p = &event.payload;
            EveEvent {
                timestamp: event.timestamp.to_rfc3339(),
                flow_id: p.get("flow_id").and_then(|v| v.as_u64()),
                in_iface: p.get("in_iface").and_then(|v| v.as_str()).map(str::to_string),
                event_type: event.event_type.clone(),
                src_ip: Some(event.source_ip.clone()),
                src_port: Some(event.source_port),
                dest_ip: Some(event.dest_ip.clone()),
                dest_port: Some(event.dest_port),
                proto: Some(event.protocol.clone()),
                alert: p.get("alert").and_then(|v| serde_json::from_value(v.clone()).ok()),
                dns: p.get("dns").and_then(|v| serde_json::from_value(v.clone()).ok()),
                http: p.get("http").and_then(|v| serde_json::from_value(v.clone()).ok()),
                tls: p.get("tls").and_then(|v| serde_json::from_value(v.clone()).ok()),
                fileinfo: p.get("fileinfo").and_then(|v| serde_json::from_value(v.clone()).ok()),
                processed_at: Some(now_bson),
            }
        })
        .collect();

    let stored = match state
        .mongo_client
        .database("idps_database")
        .collection::<EveEvent>("events")
        .insert_many(eve_events)
        .await
    {
        Ok(result) => result.inserted_ids.len(),
        Err(_) => 0,
    };

    // Process alert-type events: broadcast to dashboard and auto-block if enabled
    {
        let settings = state.detection_settings.read().await.clone();
        for event in &events {
            process_suricata_alert_from_batch(&state, event, &settings).await;
        }
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "stored": stored,
        "received": count,
    })))
}

/// Called for every event in an ingested batch.
/// If it is a Suricata `alert` event, broadcast it to the dashboard and
/// optionally trigger an auto-block on the Pi.
async fn process_suricata_alert_from_batch(
    state: &Arc<AppState>,
    event: &TrafficEvent,
    settings: &DetectionSettings,
) {
    if event.event_type != "alert" {
        return;
    }
    let src_ip = &event.source_ip;
    if src_ip.is_empty() || is_whitelisted(src_ip, &settings.whitelist) {
        return;
    }

    let p = &event.payload;
    // Suricata severity: 1=critical, 2=high, 3=medium, 4+=low
    let suricata_severity = p["alert"]["severity"].as_u64().unwrap_or(7);
    let signature = p["alert"]["signature"].as_str().unwrap_or("Unknown signature");
    let sig_id = p["alert"]["signature_id"].as_u64().unwrap_or(0);
    let category = p["alert"]["category"].as_str().unwrap_or("");
    let action = p["alert"]["action"].as_str().unwrap_or("alert");

    let severity_label = match suricata_severity {
        1 => "critical",
        2 => "high",
        3 | 4 => "medium",
        _ => "low",
    };

    // Broadcast every Suricata alert to the dashboard live feed
    let ws_msg = serde_json::json!({
        "type": "suricata_alert",
        "timestamp": event.timestamp,
        "src_ip": src_ip,
        "dest_ip": &event.dest_ip,
        "signature": signature,
        "category": category,
        "severity": suricata_severity,
        "severity_label": severity_label,
        "action": action,
        "signature_id": sig_id,
    });
    let _ = state.dashboard_tx.send(ws_msg.to_string());

    tracing::info!(
        "Suricata alert [{}] src={} sig=\"{}\" sid={} cat=\"{}\"",
        severity_label, src_ip, signature, sig_id, category
    );

    // Auto-block when severity is critical (1) or high (2) and auto-block is enabled
    if settings.auto_block_enabled && suricata_severity <= 2 {
        let severity_u8: u8 = if suricata_severity == 1 { 9 } else { 7 };
        let reason = format!("Suricata: {} [{}] (sid={})", signature, category, sig_id);
        let rule = generate_ip_block_rule(src_ip, &reason, severity_u8, settings.block_duration_hours);
        tracing::warn!("Auto-blocking {} — {}", src_ip, reason);
        persist_and_broadcast_rule(state, src_ip, &reason, severity_u8, settings, rule).await;
    }
}

async fn get_config() -> impl IntoResponse {
    Json(serde_json::json!({
        "auth": "jwt",
        "login_endpoint": "/api/auth/login",
        "service": "idps-api-gateway",
    }))
}

// ─── Prometheus Metrics ───────────────────────────────────────────────────────

async fn prometheus_metrics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let db = state.mongo_client.database("idps");

    let one_hour_ago = BsonDateTime::from_millis(
        (Utc::now() - chrono::Duration::hours(1)).timestamp_millis(),
    );

    let col_events = db.collection::<EveEvent>("events");
    let col_blocked = db.collection::<serde_json::Value>("blocked_ips");
    let col_detections = db.collection::<serde_json::Value>("detection_events");

    let (total_events, recent_events, blocked_ips_active, alerts_critical, alerts_high, alerts_medium, alerts_low) = tokio::join!(
        col_events.count_documents(doc! {}),
        col_events.count_documents(doc! { "processed_at": { "$gte": one_hour_ago } }),
        col_blocked.count_documents(doc! { "active": true }),
        col_detections.count_documents(doc! { "severity": "critical" }),
        col_detections.count_documents(doc! { "severity": "high" }),
        col_detections.count_documents(doc! { "severity": "medium" }),
        col_detections.count_documents(doc! { "severity": "low" }),
    );

    let total_events = total_events.unwrap_or(0);
    let recent_events = recent_events.unwrap_or(0);
    let blocked_ips_active = blocked_ips_active.unwrap_or(0);
    let alerts_critical = alerts_critical.unwrap_or(0);
    let alerts_high = alerts_high.unwrap_or(0);
    let alerts_medium = alerts_medium.unwrap_or(0);
    let alerts_low = alerts_low.unwrap_or(0);
    let alerts_total = alerts_critical + alerts_high + alerts_medium + alerts_low;

    let body = format!(
        "# HELP idps_events_total Total events ingested from Pi\n\
         # TYPE idps_events_total counter\n\
         idps_events_total {total_events}\n\
         # HELP idps_events_recent_1h Events ingested in the last hour\n\
         # TYPE idps_events_recent_1h gauge\n\
         idps_events_recent_1h {recent_events}\n\
         # HELP idps_blocked_ips_active Currently active IP blocks\n\
         # TYPE idps_blocked_ips_active gauge\n\
         idps_blocked_ips_active {blocked_ips_active}\n\
         # HELP idps_alerts_total Detection events by severity\n\
         # TYPE idps_alerts_total counter\n\
         idps_alerts_total{{severity=\"critical\"}} {alerts_critical}\n\
         idps_alerts_total{{severity=\"high\"}} {alerts_high}\n\
         idps_alerts_total{{severity=\"medium\"}} {alerts_medium}\n\
         idps_alerts_total{{severity=\"low\"}} {alerts_low}\n\
         idps_alerts_total{{severity=\"all\"}} {alerts_total}\n",
    );

    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}
