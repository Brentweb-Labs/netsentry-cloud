//! WebSocket endpoints: `/ws/raspi` (sensor command channel, X-API-Key header)
//! and `/ws` (dashboard live feed, JWT in `?token=`).

use crate::auth::{self, SensorAuth, WsUserAuth};
use crate::detection;
use crate::models::{SensorIdentity, TrafficEvent};
use crate::pipeline;
use crate::prevention;
use crate::signing;
use crate::state::{Metrics, SharedState};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use dashmap::DashMap;
use serde_json::Value;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;

pub struct SensorConn {
    pub conn_id: u64,
    pub tenant_id: String,
    pub command_secret: String,
    pub tx: mpsc::UnboundedSender<String>,
}

/// Connected sensors, keyed by sensor_id.
#[derive(Default)]
pub struct Registry {
    conns: DashMap<String, SensorConn>,
    next: std::sync::atomic::AtomicU64,
}

impl Registry {
    pub fn register(&self, ident: &SensorIdentity, tx: mpsc::UnboundedSender<String>) -> u64 {
        let conn_id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.conns.insert(
            ident.sensor_id.clone(),
            SensorConn {
                conn_id,
                tenant_id: ident.tenant_id.clone(),
                command_secret: ident.command_secret.clone(),
                tx,
            },
        );
        conn_id
    }

    /// Remove only if the registration is still ours (a reconnect may have replaced it).
    pub fn unregister(&self, sensor_id: &str, conn_id: u64) {
        self.conns.remove_if(sensor_id, |_, c| c.conn_id == conn_id);
    }

    pub fn is_online(&self, sensor_id: &str) -> bool {
        self.conns.contains_key(sensor_id)
    }

    pub fn len(&self) -> usize {
        self.conns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    pub fn online_for_tenant(&self, tenant_id: &str) -> usize {
        self.conns.iter().filter(|c| c.tenant_id == tenant_id).count()
    }

    /// Sign `payload` with each sensor's own secret and deliver to every
    /// connected sensor of the tenant. Returns the number of sensors reached.
    pub fn send_to_tenant(&self, tenant_id: &str, msg_type: &str, payload: &Value) -> usize {
        let mut n = 0;
        for c in self.conns.iter().filter(|c| c.tenant_id == tenant_id) {
            let env = signing::envelope(&c.command_secret, msg_type, payload.clone());
            if c.tx.send(env.to_string()).is_ok() {
                n += 1;
            }
        }
        n
    }

    pub fn send_to_sensor(&self, sensor_id: &str, msg_type: &str, payload: &Value) -> bool {
        match self.conns.get(sensor_id) {
            Some(c) => {
                let env = signing::envelope(&c.command_secret, msg_type, payload.clone());
                c.tx.send(env.to_string()).is_ok()
            }
            None => false,
        }
    }
}

/// `GET /ws/packets` - raw packet stream from a sensor (X-API-Key header). Payloads are
/// inspected for attack patterns; matches become alerts/block proposals. Packets are not stored.
pub async fn packets_ws(
    State(state): State<SharedState>,
    SensorAuth(ident): SensorAuth,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_packets(socket, state, ident))
}

async fn handle_packets(mut socket: WebSocket, state: SharedState, ident: SensorIdentity) {
    use std::time::{Duration, Instant};
    let mut recent: std::collections::HashMap<(std::net::IpAddr, String), Instant> = std::collections::HashMap::new();
    while let Some(Ok(msg)) = socket.recv().await {
        let text = match msg {
            Message::Text(t) if t.len() <= 16 * 1024 => t,
            Message::Close(_) => break,
            _ => continue,
        };
        let Ok(pkt) = serde_json::from_str::<detection::StreamedPacket>(&text) else {
            continue;
        };
        let Some(finding) = detection::analyse_packet(&pkt) else {
            continue;
        };
        // At most one alert per (offender, signature) per minute per connection.
        recent.retain(|_, t| t.elapsed() < Duration::from_secs(60));
        if recent
            .insert((finding.offender, finding.signature.clone()), Instant::now())
            .is_some()
        {
            continue;
        }
        let event = TrafficEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            source_ip: pkt.src_ip.clone(),
            dest_ip: if pkt.dst_ip.parse::<std::net::IpAddr>().is_ok() {
                pkt.dst_ip.clone()
            } else {
                String::new()
            },
            source_port: pkt.src_port,
            dest_port: pkt.dst_port,
            protocol: pkt.protocol.chars().take(16).collect(),
            payload: serde_json::Value::Null,
            threat_level: 0,
            event_type: "packet".into(),
        };
        let settings = crate::settings::load(&state, &ident.tenant_id).await;
        pipeline::raise_findings(&state, &ident, &settings, vec![(&event, finding)]).await;
    }
}

/// `GET /ws/raspi` - authenticated by the `X-API-Key` header (never a query param).
pub async fn sensor_ws(
    State(state): State<SharedState>,
    SensorAuth(ident): SensorAuth,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_sensor(socket, state, ident))
}

async fn handle_sensor(mut socket: WebSocket, state: SharedState, ident: SensorIdentity) {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let conn_id = state.registry.register(&ident, tx);
    tracing::info!("sensor {} (tenant {}) connected", ident.sensor_id, ident.tenant_id);
    auth::touch_sensor(&state, &ident.sensor_id).await;

    let hello = serde_json::json!({ "type": "connected", "sensor_id": ident.sensor_id, "tenant_id": ident.tenant_id });
    if socket.send(Message::Text(hello.to_string().into())).await.is_err() {
        state.registry.unregister(&ident.sensor_id, conn_id);
        return;
    }
    // Bring a (re)connecting sensor up to date with the blocks that should be active.
    prevention::replay_active(&state, &ident).await;

    loop {
        tokio::select! {
            out = rx.recv() => match out {
                Some(text) => {
                    Metrics::inc(&state.metrics.commands_sent, 1);
                    if socket.send(Message::Text(text.into())).await.is_err() { break; }
                }
                None => break,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Text(t))) => {
                    // Sensors send acks/pings; only keep liveness fresh.
                    tracing::debug!("sensor {} says: {}", ident.sensor_id, t.chars().take(200).collect::<String>());
                    auth::touch_sensor(&state, &ident.sensor_id).await;
                }
                Some(Ok(Message::Ping(p))) => { let _ = socket.send(Message::Pong(p)).await; }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            }
        }
    }
    state.registry.unregister(&ident.sensor_id, conn_id);
    tracing::info!("sensor {} disconnected", ident.sensor_id);
}

/// `GET /ws?token=<jwt>` - live feed for one tenant's dashboard.
/// Browsers cannot set headers on WebSocket requests, so the JWT is accepted
/// as a query parameter here (and only here; sensors use headers).
pub async fn dashboard_ws(
    State(state): State<SharedState>,
    WsUserAuth(claims): WsUserAuth,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_dashboard(socket, state, claims.tenant_id))
}

async fn handle_dashboard(mut socket: WebSocket, state: SharedState, tenant_id: String) {
    let mut rx = state.dashboard_tx.subscribe();
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok((t, json)) if t == tenant_id => {
                    if socket.send(Message::Text(json.into())).await.is_err() { break; }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => break,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(sensor: &str, tenant: &str, secret: &str) -> SensorIdentity {
        SensorIdentity {
            sensor_id: sensor.into(),
            tenant_id: tenant.into(),
            command_secret: secret.into(),
        }
    }

    #[test]
    fn commands_are_signed_per_sensor_and_scoped_to_tenant() {
        let reg = Registry::default();
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let (tx3, mut rx3) = mpsc::unbounded_channel();
        reg.register(&ident("s1", "tenantA", "secret-1"), tx1);
        reg.register(&ident("s2", "tenantA", "secret-2"), tx2);
        reg.register(&ident("s3", "tenantB", "secret-3"), tx3);
        assert_eq!(reg.online_for_tenant("tenantA"), 2);

        let payload = serde_json::json!({"ip": "203.0.113.9", "duration_secs": 3600});
        assert_eq!(reg.send_to_tenant("tenantA", "block_command", &payload), 2);

        let m1: Value = serde_json::from_str(&rx1.try_recv().unwrap()).unwrap();
        let m2: Value = serde_json::from_str(&rx2.try_recv().unwrap()).unwrap();
        assert!(rx3.try_recv().is_err(), "other tenant must not receive the command");
        let check = |m: &Value, secret: &str| {
            signing::verify(
                secret,
                m["type"].as_str().unwrap(),
                m["ts"].as_i64().unwrap(),
                &m["payload"],
                m["sig"].as_str().unwrap(),
            )
        };
        assert!(check(&m1, "secret-1"));
        assert!(check(&m2, "secret-2"));
        assert!(!check(&m1, "secret-2"));
    }

    #[test]
    fn stale_unregister_does_not_remove_new_connection() {
        let reg = Registry::default();
        let (tx1, _r1) = mpsc::unbounded_channel();
        let (tx2, _r2) = mpsc::unbounded_channel();
        let old = reg.register(&ident("s1", "t", "k"), tx1);
        let new = reg.register(&ident("s1", "t", "k"), tx2);
        reg.unregister("s1", old);
        assert!(reg.is_online("s1"));
        reg.unregister("s1", new);
        assert!(!reg.is_online("s1"));
    }
}
