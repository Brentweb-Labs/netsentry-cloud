use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use mongodb::{bson::doc, options::ClientOptions, Client};
use chrono::{DateTime, Utc};
use log::{info, error};

#[derive(Clone)]
struct AppState {
    mongo_client: Client,
    metrics: Arc<RwLock<ProcessingMetrics>>,
}

#[derive(Debug, Default, Clone, Serialize)]
struct ProcessingMetrics {
    events_processed: u64,
    alerts_processed: u64,
    last_processed: Option<DateTime<Utc>>,
    processing_rate: f64,
}

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
    pub processed_at: Option<DateTime<Utc>>,
    #[serde(rename = "threat_level")]
    pub threat_level: Option<u8>,
    #[serde(rename = "raspi_ip")]
    pub raspi_ip: Option<String>,
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

#[derive(Debug, Serialize)]
struct ProcessorResponse {
    success: bool,
    message: String,
    event_id: String,
    processing_time_ms: u64,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: String,
    timestamp: DateTime<Utc>,
    service: String,
    metrics: ProcessingMetrics,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    
    info!("Starting VPS Processor Service");

    // Connect to MongoDB
    let mongo_uri = std::env::var("MONGODB_URI")
        .unwrap_or_else(|_| "mongodb://mongo:27017/idps".to_string());
    
    let mut client_options = ClientOptions::parse(&mongo_uri).await?;
    client_options.max_pool_size = Some(10);
    client_options.min_pool_size = Some(2);
    
    let mongo_client = Client::with_options(client_options)?;
    
    info!("Connected to MongoDB successfully");

    let state = Arc::new(AppState { 
        mongo_client,
        metrics: Arc::new(RwLock::new(ProcessingMetrics::default())),
    });

    let app = Router::new()
        .route("/", get(health_check))
        .route("/health", get(health_check))
        .route("/status", get(get_status))
        .route("/metrics", get(get_metrics))
        .route("/traffic", post(process_traffic))
        .route("/traffic/batch", post(process_batch_traffic))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8090").await?;
    info!("VPS Processor listening on 0.0.0.0:8090");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": Utc::now(),
        "service": "vps-processor"
    }))
}

async fn get_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let metrics = state.metrics.read().await.clone();
    
    Json(StatusResponse {
        status: "running".to_string(),
        timestamp: Utc::now(),
        service: "vps-processor".to_string(),
        metrics,
    })
}

async fn get_metrics(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let metrics = state.metrics.read().await.clone();
    
    Json(serde_json::json!({
        "events_processed": metrics.events_processed,
        "alerts_processed": metrics.alerts_processed,
        "last_processed": metrics.last_processed,
        "processing_rate": metrics.processing_rate,
        "uptime": "running"
    }))
}

async fn process_traffic(
    State(state): State<Arc<AppState>>,
    Json(event): Json<TrafficEvent>,
) -> Result<Json<ProcessorResponse>, StatusCode> {
    let start_time = std::time::Instant::now();
    
    info!("Processing traffic event: {} from {} to {}", 
          event.id, event.source_ip, event.dest_ip);

    // Convert TrafficEvent to EveEvent for storage
    let eve_event = convert_to_eve_event(event).await;
    
    // Store in MongoDB
    let collection = state.mongo_client
        .database("idps")
        .collection::<EveEvent>("events");
    
    match collection.insert_one(&eve_event).await {
        Ok(_) => {
            // Update metrics
            let mut metrics = state.metrics.write().await;
            metrics.events_processed += 1;
            if eve_event.event_type == "alert" {
                metrics.alerts_processed += 1;
            }
            metrics.last_processed = Some(Utc::now());
            metrics.processing_rate = calculate_processing_rate(&metrics).await;
            
            let processing_time = start_time.elapsed().as_millis() as u64;
            
            Ok(Json(ProcessorResponse {
                success: true,
                message: "Event processed successfully".to_string(),
                event_id: eve_event.timestamp,
                processing_time_ms: processing_time,
            }))
        },
        Err(e) => {
            error!("Failed to store event: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn process_batch_traffic(
    State(state): State<Arc<AppState>>,
    Json(events): Json<Vec<TrafficEvent>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let start_time = std::time::Instant::now();
    let batch_size = events.len();
    
    info!("Processing batch of {} traffic events", batch_size);
    
    // Convert events
    let mut eve_events = Vec::new();
    for event in events {
        eve_events.push(convert_to_eve_event(event).await);
    }
    
    // Store in MongoDB using bulk insert
    let collection = state.mongo_client
        .database("idps")
        .collection::<EveEvent>("events");
    
    match collection.insert_many(eve_events).await {
        Ok(_) => {
            // Update metrics
            let mut metrics = state.metrics.write().await;
            metrics.events_processed += batch_size as u64;
            metrics.last_processed = Some(Utc::now());
            metrics.processing_rate = calculate_processing_rate(&metrics).await;
            
            let processing_time = start_time.elapsed().as_millis() as u64;
            
            Ok(Json(serde_json::json!({
                "success": true,
                "message": format!("Batch of {} events processed successfully", batch_size),
                "batch_size": batch_size,
                "processing_time_ms": processing_time
            })))
        },
        Err(e) => {
            error!("Failed to store batch: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn convert_to_eve_event(traffic_event: TrafficEvent) -> EveEvent {
    let mut eve_event = EveEvent {
        timestamp: traffic_event.timestamp.to_rfc3339(),
        flow_id: None,
        in_iface: None,
        event_type: traffic_event.event_type.clone(),
        src_ip: Some(traffic_event.source_ip.clone()),
        src_port: Some(traffic_event.source_port),
        dest_ip: Some(traffic_event.dest_ip.clone()),
        dest_port: Some(traffic_event.dest_port),
        proto: Some(traffic_event.protocol.clone()),
        alert: None,
        dns: None,
        http: None,
        tls: None,
        fileinfo: None,
        processed_at: Some(Utc::now()),
        threat_level: Some(traffic_event.threat_level),
        raspi_ip: Some(traffic_event.source_ip), // Using source IP as raspi IP for now
    };
    
    // Parse additional data from payload if it's an alert
    if traffic_event.event_type == "alert" {
        if let Ok(alert_data) = serde_json::from_value::<AlertInfo>(traffic_event.payload.clone()) {
            eve_event.alert = Some(alert_data);
        }
    }
    
    // Parse DNS data if present
    if traffic_event.event_type == "dns" {
        if let Ok(dns_data) = serde_json::from_value::<DnsInfo>(traffic_event.payload.clone()) {
            eve_event.dns = Some(dns_data);
        }
    }
    
    // Parse HTTP data if present
    if traffic_event.event_type == "http" {
        if let Ok(http_data) = serde_json::from_value::<HttpInfo>(traffic_event.payload.clone()) {
            eve_event.http = Some(http_data);
        }
    }
    
    eve_event
}

async fn calculate_processing_rate(metrics: &ProcessingMetrics) -> f64 {
    if let Some(last_processed) = metrics.last_processed {
        let duration_since_last = Utc::now() - last_processed;
        let seconds = duration_since_last.num_seconds();
        if seconds > 0 {
            metrics.events_processed as f64 / seconds as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}
