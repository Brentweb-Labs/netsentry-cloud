use anyhow::Result;
use clap::{Arg, Command};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;
use warp::ws::{Message, WebSocket};
use warp::Filter;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamedPacket {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub payload: Vec<u8>,
    pub packet_size: usize,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketDecision {
    pub packet_id: String,
    pub action: String, // "allow", "block", "monitor"
    pub threat_level: u8,
    pub reason: String,
    pub rule_matches: Vec<String>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone)]
struct ThreatPattern {
    name: String,
    pattern: regex::Regex,
    threat_level: u8,
    action: String,
    description: String,
}

struct PacketProcessor {
    threat_patterns: Vec<ThreatPattern>,
    ip_reputation: Arc<RwLock<HashMap<String, (bool, Instant)>>>, // IP -> (is_malicious, last_seen)
    packet_stats: Arc<DashMap<String, usize>>,                    // IP -> packet count
    active_connections: Arc<Mutex<HashMap<String, ()>>>,          // Just track connection IDs
}

impl PacketProcessor {
    fn new() -> Self {
        let threat_patterns = vec![
            ThreatPattern {
                name: "SQL Injection".to_string(),
                pattern: regex::Regex::new(
                    r"(?i)(union|select|insert|update|delete|drop|exec|script)",
                )
                .unwrap(),
                threat_level: 8,
                action: "block".to_string(),
                description: "SQL injection attempt detected".to_string(),
            },
            ThreatPattern {
                name: "XSS Attack".to_string(),
                pattern: regex::Regex::new(r"(?i)(<script|javascript:|onload=|onerror=)").unwrap(),
                threat_level: 7,
                action: "block".to_string(),
                description: "Cross-site scripting attempt".to_string(),
            },
            ThreatPattern {
                name: "Path Traversal".to_string(),
                pattern: regex::Regex::new(r"(?i)(\.\./|\.\.\\|%2e%2e%2f)").unwrap(),
                threat_level: 7,
                action: "block".to_string(),
                description: "Directory traversal attempt".to_string(),
            },
            ThreatPattern {
                name: "Command Injection".to_string(),
                pattern: regex::Regex::new(r"(?i)(;|\||&|`|\$\(|wget|curl|nc|netcat)").unwrap(),
                threat_level: 9,
                action: "block".to_string(),
                description: "Command injection attempt".to_string(),
            },
            ThreatPattern {
                name: "Brute Force".to_string(),
                pattern: regex::Regex::new(r"(?i)(admin|root|login|password)").unwrap(),
                threat_level: 6,
                action: "monitor".to_string(),
                description: "Potential brute force attempt".to_string(),
            },
        ];

        Self {
            threat_patterns,
            ip_reputation: Arc::new(RwLock::new(HashMap::new())),
            packet_stats: Arc::new(DashMap::new()),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn process_packet(&self, packet: StreamedPacket) -> PacketDecision {
        let start_time = Instant::now();

        debug!(
            "Processing packet from {}:{}",
            packet.src_ip, packet.src_port
        );

        // Update packet statistics
        *self.packet_stats.entry(packet.src_ip.clone()).or_insert(0) += 1;

        // Check IP reputation first (fast path)
        if let Some((is_malicious, _)) = self.ip_reputation.read().await.get(&packet.src_ip) {
            if *is_malicious {
                return PacketDecision {
                    packet_id: packet.id.clone(),
                    action: "block".to_string(),
                    threat_level: 9,
                    reason: "Known malicious IP".to_string(),
                    rule_matches: vec!["IP Reputation".to_string()],
                    processing_time_ms: start_time.elapsed().as_millis() as u64,
                };
            }
        }

        // Analyze packet payload for threat patterns
        let payload_str = String::from_utf8_lossy(&packet.payload);
        let mut matched_rules = Vec::new();
        let mut max_threat_level = 0;
        let mut action = "allow".to_string();
        let mut reason = "No threats detected".to_string();

        for pattern in &self.threat_patterns {
            if pattern.pattern.is_match(&payload_str) {
                matched_rules.push(pattern.name.clone());
                if pattern.threat_level > max_threat_level {
                    max_threat_level = pattern.threat_level;
                    action = pattern.action.clone();
                    reason = pattern.description.clone();
                }
            }
        }

        // Additional analysis: Check for port scanning
        if self.is_port_scan(&packet.src_ip).await {
            matched_rules.push("Port Scan".to_string());
            if max_threat_level < 7 {
                max_threat_level = 7;
                action = "block".to_string();
                reason = "Port scanning activity detected".to_string();
            }
        }

        // Additional analysis: Check for DDoS patterns
        if self.is_ddos_source(&packet.src_ip).await {
            matched_rules.push("DDoS".to_string());
            max_threat_level = 9;
            action = "block".to_string();
            reason = "DDoS attack source".to_string();
        }

        // Update IP reputation based on analysis
        {
            let mut reputation = self.ip_reputation.write().await;
            reputation.insert(packet.src_ip.clone(), (action == "block", Instant::now()));
        }

        let processing_time = start_time.elapsed().as_millis() as u64;

        debug!(
            "Packet analysis completed in {}ms: action={}, threat_level={}",
            processing_time, action, max_threat_level
        );

        PacketDecision {
            packet_id: packet.id,
            action,
            threat_level: max_threat_level,
            reason,
            rule_matches: matched_rules,
            processing_time_ms: processing_time,
        }
    }

    async fn is_port_scan(&self, src_ip: &str) -> bool {
        // Check if IP is connecting to multiple ports
        let packet_count = self
            .packet_stats
            .get(src_ip)
            .map(|count| *count)
            .unwrap_or(0);
        packet_count > 50 // Threshold for port scan detection
    }

    async fn is_ddos_source(&self, src_ip: &str) -> bool {
        // Check if IP is sending unusually high traffic
        let packet_count = self
            .packet_stats
            .get(src_ip)
            .map(|count| *count)
            .unwrap_or(0);
        packet_count > 1000 // Threshold for DDoS detection
    }

    async fn handle_websocket_connection(&self, ws: WebSocket) {
        let (mut tx, mut rx) = ws.split();
        let connection_id = Uuid::new_v4().to_string();

        info!("New WebSocket connection: {}", connection_id);

        // Store connection ID
        {
            let mut connections = self.active_connections.lock().await;
            connections.insert(connection_id.clone(), ());
        }

        // Handle messages from client
        while let Some(msg) = rx.next().await {
            match msg {
                Ok(msg) => {
                    if msg.is_text() {
                        if let Ok(text) = msg.to_str() {
                            if let Ok(packet) = serde_json::from_str::<StreamedPacket>(text) {
                                let decision = self.process_packet(packet.clone()).await;

                                // Send decision back to client
                                if let Ok(decision_json) = serde_json::to_string(&decision) {
                                    if let Err(e) = tx.send(Message::text(decision_json)).await {
                                        error!("Failed to send decision: {}", e);
                                        break;
                                    }
                                }

                                // Log high-threat packets
                                if decision.threat_level >= 7 {
                                    warn!(
                                        "High threat detected: {} from {} - {}",
                                        decision.reason, packet.src_ip, decision.action
                                    );
                                }
                            }
                        }
                    } else if msg.is_binary() {
                        if let Ok(packet) = self.parse_binary_packet(&msg.into_bytes()) {
                            let decision = self.process_packet(packet.clone()).await;

                            if let Ok(decision_json) = serde_json::to_string(&decision) {
                                if let Err(e) = tx.send(Message::text(decision_json)).await {
                                    error!("Failed to send decision: {}", e);
                                    break;
                                }
                            }
                        }
                    } else if msg.is_close() {
                        info!("WebSocket connection closed: {}", connection_id);
                        break;
                    }
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
            }
        }

        // Remove connection
        {
            let mut connections = self.active_connections.lock().await;
            connections.remove(&connection_id);
        }
    }

    fn parse_binary_packet(&self, _data: &[u8]) -> Result<StreamedPacket> {
        // Implement binary packet parsing for higher performance
        // This would be a custom binary format instead of JSON
        Err(anyhow::anyhow!("Binary parsing not implemented"))
    }

    async fn start_cleanup_task(&self) {
        let packet_stats = self.packet_stats.clone();
        let ip_reputation = self.ip_reputation.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                let now = Instant::now();

                // Clean up old packet statistics
                packet_stats.retain(|_, _| false); // Reset stats every minute

                // Clean up old IP reputation entries
                let mut reputation = ip_reputation.write().await;
                reputation.retain(|_, (_, last_seen)| {
                    now.duration_since(*last_seen) < Duration::from_secs(3600)
                });
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let matches = Command::new("packet-processor")
        .version("1.0")
        .about("High-performance packet processing for IDPS")
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Port to listen on")
                .default_value("8090"),
        )
        .get_matches();

    let port: u16 = matches.get_one::<String>("port").unwrap().parse()?;
    let processor = Arc::new(PacketProcessor::new());

    // Start cleanup task
    processor.start_cleanup_task().await;

    info!("Starting packet processor on port {}", port);

    // WebSocket route for packet streaming
    let processor_ref = processor.clone();
    let ws_route = warp::path("packets")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let processor = processor_ref.clone();
            ws.on_upgrade(move |websocket| async move {
                processor.handle_websocket_connection(websocket).await;
            })
        });

    // HTTP API routes
    let api_status = warp::path("status").and(warp::get()).and_then({
        let processor = processor.clone();
        move || {
            let processor = processor.clone();
            async move {
                let connections = processor.active_connections.lock().await;
                let active_count = connections.len();
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "status": "running",
                    "active_connections": active_count,
                    "packet_stats": processor.packet_stats.len(),
                    "timestamp": chrono::Utc::now()
                })))
            }
        }
    });

    let api_stats = warp::path("stats").and(warp::get()).and_then({
        let processor = processor.clone();
        move || {
            let processor = processor.clone();
            async move {
                let mut stats = HashMap::new();
                for entry in processor.packet_stats.iter() {
                    stats.insert(entry.key().clone(), *entry.value());
                }

                let blocked_ips = {
                    let reputation = processor.ip_reputation.blocking_read();
                    reputation
                        .iter()
                        .filter_map(|(ip, (is_malicious, _))| {
                            if *is_malicious {
                                Some(ip.clone())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                };

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "packet_stats": stats,
                    "blocked_ips": blocked_ips
                })))
            }
        }
    });

    let routes = ws_route
        .or(api_status)
        .or(api_stats)
        .with(warp::cors().allow_any_origin())
        .with(warp::log("packet_processor"));

    let addr = ([0, 0, 0, 0], port);
    info!("Packet processor listening on 0.0.0.0:{}", port);

    warp::serve(routes).run(addr).await;

    Ok(())
}
