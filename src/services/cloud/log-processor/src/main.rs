use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use log::{debug, error, info, warn};
use mongodb::{bson::doc, bson::Document, options::ClientOptions, Client, Collection};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{interval, sleep};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EveEvent {
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
    #[serde(rename = "pkt_src")]
    pub pkt_src: Option<String>,
    #[serde(rename = "ip_v")]
    pub ip_v: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInfo {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    #[serde(rename = "version")]
    pub version: Option<u32>,
    #[serde(rename = "type")]
    pub r#type: Option<String>,
    #[serde(rename = "tx_id")]
    pub tx_id: Option<u32>,
    #[serde(rename = "queries")]
    pub queries: Option<Vec<DnsQuery>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    #[serde(rename = "rrname")]
    pub rrname: Option<String>,
    #[serde(rename = "rrtype")]
    pub rrtype: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    #[serde(rename = "hostname")]
    pub hostname: Option<String>,
    #[serde(rename = "url")]
    pub url: Option<String>,
    #[serde(rename = "http_user_agent")]
    pub http_user_agent: Option<String>,
    #[serde(rename = "http_method")]
    pub http_method: Option<String>,
    #[serde(rename = "protocol")]
    pub protocol: Option<String>,
    #[serde(rename = "status")]
    pub status: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    #[serde(rename = "version")]
    pub version: Option<String>,
    #[serde(rename = "cipher")]
    pub cipher: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    #[serde(rename = "filename")]
    pub filename: Option<String>,
    #[serde(rename = "size")]
    pub size: Option<u64>,
    #[serde(rename = "state")]
    pub state: Option<String>,
}

/// Normalized Suricata alert forwarded to the API gateway's `/api/alerts/ingest` endpoint.
/// Field names must match `SuricataAlertNotification` in the api-gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AlertNotification {
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

struct LogProcessor {
    mongo_client: Client,
    vps_url: String,
    raspi_url: String,
    processed_events: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl LogProcessor {
    async fn new() -> Result<Self> {
        // MongoDB connection
        let mongo_uri = std::env::var("MONGODB_URI")
            .unwrap_or_else(|_| "mongodb://mongo:27017/idps".to_string());

        let mut client_options = ClientOptions::parse(&mongo_uri).await?;
        client_options.max_pool_size = Some(10);
        client_options.min_pool_size = Some(2);

        let mongo_client = Client::with_options(client_options)?;

        let vps_url =
            std::env::var("VPS_URL").unwrap_or_else(|_| "http://packet-analyzer:8090".to_string());

        let raspi_url =
            std::env::var("RASPI_URL").unwrap_or_else(|_| "http://api-gateway:8080".to_string());

        info!("Connected to MongoDB and initialized log processor");

        Ok(Self {
            mongo_client,
            vps_url,
            raspi_url,
            processed_events: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    async fn process_eve_json(&self, file_path: &Path) -> Result<()> {
        debug!("Processing eve.json file: {:?}", file_path);

        let content = tokio::fs::read_to_string(file_path).await?;
        let lines: Vec<&str> = content.lines().collect();

        let collection = self
            .mongo_client
            .database("idps")
            .collection::<EveEvent>("events");

        let mut batch = Vec::new();
        let batch_size = 1000;

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<EveEvent>(line) {
                Ok(event) => {
                    // Add processing timestamp
                    let event_id = format!("{}-{}", event.timestamp, event.flow_id.unwrap_or(0));

                    // Check if already processed
                    if self.processed_events.read().await.contains_key(&event_id) {
                        continue;
                    }

                    // Store in MongoDB
                    batch.push(event.clone());

                    // Forward to VPS for analysis
                    if let Err(e) = self.forward_to_vps(&event).await {
                        warn!("Failed to forward event to VPS: {}", e);
                    }

                    // Forward Suricata alerts to API gateway alert ingest endpoint
                    if event.event_type == "alert" {
                        if let Err(e) = self.forward_alert_to_gateway(&event).await {
                            warn!("Failed to forward alert to gateway: {}", e);
                        }
                    }

                    // Check for automatic prevention
                    if let Err(e) = self.check_automatic_prevention(&event).await {
                        warn!("Failed to check automatic prevention: {}", e);
                    }

                    // Forward to Raspi for storage/processing
                    if let Err(e) = self.forward_to_raspi(&event).await {
                        warn!("Failed to forward event to Raspi: {}", e);
                    }

                    // Mark as processed
                    let mut processed = self.processed_events.write().await;
                    processed.insert(event_id, Utc::now());

                    // Batch insert to MongoDB
                    if batch.len() >= batch_size {
                        if let Err(e) = self.insert_batch(&collection, &batch).await {
                            error!("Failed to insert batch to MongoDB: {}", e);
                        } else {
                            info!("Inserted {} events to MongoDB", batch.len());
                        }
                        batch.clear();
                    }
                }
                Err(e) => {
                    warn!("Failed to parse JSON line: {}", e);
                }
            }
        }

        // Insert remaining events
        if !batch.is_empty() {
            if let Err(e) = self.insert_batch(&collection, &batch).await {
                error!("Failed to insert final batch to MongoDB: {}", e);
            } else {
                info!("Inserted final {} events to MongoDB", batch.len());
            }
        }

        Ok(())
    }

    async fn insert_batch(
        &self,
        collection: &Collection<EveEvent>,
        batch: &[EveEvent],
    ) -> Result<()> {
        collection.insert_many(batch).await?;
        Ok(())
    }

    async fn forward_to_vps(&self, event: &EveEvent) -> Result<()> {
        let client = reqwest::Client::new();

        // Only forward security events to VPS for analysis
        if event.event_type == "alert" || event.event_type == "http" || event.event_type == "dns" {
            let response = client
                .post(&format!("{}/api/v1/analyze", self.vps_url))
                .json(event)
                .timeout(Duration::from_secs(5))
                .send()
                .await?;

            if response.status().is_success() {
                debug!("Event forwarded to VPS successfully");
            } else {
                warn!("VPS returned error: {}", response.status());
            }
        }

        Ok(())
    }

    /// Forward a Suricata alert event to the API gateway's dedicated alert ingest endpoint.
    /// The gateway stores it in `suricata_alerts`, broadcasts it to dashboard WebSocket
    /// clients, and optionally triggers auto-block when severity <= 2.
    async fn forward_alert_to_gateway(&self, event: &EveEvent) -> Result<()> {
        let alert_info = match &event.alert {
            Some(a) => a,
            None => return Ok(()),
        };

        let src_ip = match &event.src_ip {
            Some(ip) => ip.clone(),
            None => return Ok(()),
        };

        let notification = AlertNotification {
            timestamp: event.timestamp.clone(),
            src_ip,
            dest_ip: event.dest_ip.clone(),
            src_port: event.src_port,
            dest_port: event.dest_port,
            proto: event.proto.clone(),
            signature: alert_info
                .signature
                .clone()
                .unwrap_or_else(|| "Unknown".to_string()),
            category: alert_info
                .category
                .clone()
                .unwrap_or_else(|| "Unknown".to_string()),
            severity: alert_info.severity.unwrap_or(3),
            action: alert_info
                .action
                .clone()
                .unwrap_or_else(|| "alert".to_string()),
            signature_id: alert_info.signature_id.unwrap_or(0),
        };

        let client = reqwest::Client::new();
        let response = client
            .post(&format!("{}/api/alerts/ingest", self.raspi_url))
            .json(&notification)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        if response.status().is_success() {
            debug!(
                "Alert forwarded to gateway: sig={} src={} severity={}",
                notification.signature, notification.src_ip, notification.severity
            );
        } else {
            warn!("Gateway returned {} for alert ingest", response.status());
        }

        Ok(())
    }

    async fn forward_to_raspi(&self, event: &EveEvent) -> Result<()> {
        let client = reqwest::Client::new();

        // Forward all events to Raspi for storage
        let response = client
            .post(&format!("{}/api/v1/events", self.raspi_url))
            .json(event)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        if response.status().is_success() {
            debug!("Event forwarded to Raspi successfully");
        } else {
            warn!("Raspi returned error: {}", response.status());
        }

        Ok(())
    }

    async fn check_automatic_prevention(&self, event: &EveEvent) -> Result<()> {
        // Only check prevention for alert events
        if event.event_type != "alert" {
            return Ok(());
        }

        let alert = match &event.alert {
            Some(alert) => alert,
            None => return Ok(()),
        };

        let src_ip = match &event.src_ip {
            Some(ip) => ip,
            None => return Ok(()),
        };

        // Check severity threshold (auto-block for severity 1-2)
        let severity = alert.severity.unwrap_or(3);
        if severity <= 2 {
            info!(
                "Auto-blocking IP {} due to high severity alert (severity: {})",
                src_ip, severity
            );
            self.trigger_automatic_block(
                src_ip,
                &format!(
                    "High severity alert: {}",
                    alert.signature.as_deref().unwrap_or("Unknown")
                ),
                severity,
            )
            .await?;
            return Ok(());
        }

        // Check for specific threat signatures
        if let Some(signature) = &alert.signature {
            let signature_lower = signature.to_lowercase();
            if signature_lower.contains("sql injection")
                || signature_lower.contains("xss")
                || signature_lower.contains("command injection")
                || signature_lower.contains("buffer overflow")
                || signature_lower.contains("malware")
            {
                info!(
                    "Auto-blocking IP {} due to threat signature: {}",
                    src_ip, signature
                );
                self.trigger_automatic_block(
                    src_ip,
                    &format!("Threat signature: {}", signature),
                    1,
                )
                .await?;
                return Ok(());
            }
        }

        // Check for repeated alerts from same IP (rate-based blocking)
        if self.is_repeated_offender(src_ip).await? {
            info!("Auto-blocking IP {} due to repeated offenses", src_ip);
            self.trigger_automatic_block(src_ip, "Repeated security violations", 2)
                .await?;
        }

        Ok(())
    }

    async fn trigger_automatic_block(
        &self,
        ip: &str,
        reason: &str,
        threat_level: u32,
    ) -> Result<()> {
        let client = reqwest::Client::new();

        // Get network filter URL from environment or use default
        let network_filter_url = std::env::var("NETWORK_FILTER_URL")
            .unwrap_or_else(|_| "http://network-filter:8092".to_string());

        let block_request = serde_json::json!({
            "ip": ip,
            "reason": reason,
            "threat_level": threat_level,
            "duration_hours": 24, // Default 24 hour block
            "source": "automatic_prevention"
        });

        let response = client
            .post(&format!("{}/api/v1/block", network_filter_url))
            .json(&block_request)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        if response.status().is_success() {
            info!("Successfully auto-blocked IP {}: {}", ip, reason);
        } else {
            warn!("Failed to auto-block IP {}: {}", ip, response.status());
        }

        Ok(())
    }

    async fn is_repeated_offender(&self, ip: &str) -> Result<bool> {
        let collection = self
            .mongo_client
            .database("idps")
            .collection::<Document>("events");

        // Check for more than 5 alerts from same IP in last hour
        let one_hour_ago = Utc::now() - ChronoDuration::hours(1);
        let filter = doc! {
            "src_ip": ip,
            "event_type": "alert",
            "timestamp": { "$gte": one_hour_ago.to_rfc3339() }
        };

        match collection.count_documents(filter).await {
            Ok(count) => Ok(count > 5),
            Err(_) => Ok(false),
        }
    }

    async fn start_file_watcher(&self) -> Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);

        let eve_json_path = Path::new("/app/logs/eve.json");
        let tx_clone = tx.clone();

        // File watcher
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    if matches!(event.kind, EventKind::Modify(_)) {
                        let _ = tx_clone.blocking_send(());
                    }
                }
                Err(e) => error!("Watch error: {:?}", e),
            },
            Config::default(),
        )?;

        watcher.watch(eve_json_path.parent().unwrap(), RecursiveMode::NonRecursive)?;

        let processor = self.clone();
        tokio::spawn(async move {
            // Initial processing
            if let Err(e) = processor.process_eve_json(eve_json_path).await {
                error!("Initial processing failed: {}", e);
            }

            // Process on file changes
            while rx.recv().await.is_some() {
                sleep(Duration::from_millis(500)).await; // Debounce

                if let Err(e) = processor.process_eve_json(eve_json_path).await {
                    error!("File change processing failed: {}", e);
                }
            }
        });

        Ok(())
    }

    async fn start_cleanup_task(&self) {
        let processed_events = self.processed_events.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // Every 5 minutes

            loop {
                interval.tick().await;

                let now = Utc::now();
                let mut processed = processed_events.write().await;

                // Remove entries older than 1 hour
                processed.retain(|_, timestamp| {
                    now.signed_duration_since(*timestamp).num_minutes() < 60
                });

                debug!("Cleanup completed. {} events in memory", processed.len());
            }
        });
    }
}

impl Clone for LogProcessor {
    fn clone(&self) -> Self {
        Self {
            mongo_client: self.mongo_client.clone(),
            vps_url: self.vps_url.clone(),
            raspi_url: self.raspi_url.clone(),
            processed_events: self.processed_events.clone(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting IDPS Log Processor");

    let processor = LogProcessor::new().await?;

    // Start file watcher
    processor.start_file_watcher().await?;

    // Start cleanup task
    processor.start_cleanup_task().await;

    info!("Log processor started successfully");

    // Keep the service running
    loop {
        sleep(Duration::from_secs(60)).await;
    }
}
