//! Wire and domain types shared across modules.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn default_event_type() -> String {
    "unknown".to_string()
}

/// Event as posted by a sensor to `/api/traffic` and `/api/traffic/batch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEvent {
    #[serde(default = "new_id")]
    pub id: String,
    #[serde(default = "Utc::now")]
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    #[serde(default)]
    pub dest_ip: String,
    #[serde(default)]
    pub source_port: u16,
    #[serde(default)]
    pub dest_port: u16,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub threat_level: u8,
    #[serde(default = "default_event_type")]
    pub event_type: String,
}

impl TrafficEvent {
    /// Reject anything that could later flow into a firewall/Suricata rule or
    /// a query unvalidated. Returns the parsed source address.
    pub fn validate(&self) -> Result<IpAddr, String> {
        let src: IpAddr = self.source_ip.parse().map_err(|_| "invalid source_ip".to_string())?;
        if !self.dest_ip.is_empty() && self.dest_ip.parse::<IpAddr>().is_err() {
            return Err("invalid dest_ip".into());
        }
        if self.event_type.is_empty()
            || self.event_type.len() > 32
            || !self
                .event_type
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("invalid event_type".into());
        }
        if self.protocol.len() > 16 {
            return Err("invalid protocol".into());
        }
        Ok(src)
    }
}

/// Authenticated sensor identity (resolved from the X-API-Key header).
#[derive(Debug, Clone)]
pub struct SensorIdentity {
    pub sensor_id: String,
    pub tenant_id: String,
    pub command_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    pub hostname: String,
    #[serde(default)]
    pub arch: String,
    pub mode: String,
}

#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    pub sensor_id: String,
    pub tenant_id: String,
    pub api_key: String,
    pub command_hmac_secret: String,
    pub ingest_url: String,
    pub ws_url: String,
}

#[derive(Debug, Deserialize)]
pub struct Pagination {
    pub page: Option<u64>,
    pub limit: Option<u64>,
}

impl Pagination {
    pub fn resolve(&self) -> (u64, u64) {
        let limit = self.limit.unwrap_or(50).clamp(1, 200);
        let page = self.page.unwrap_or(1).max(1);
        (page, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(src: &str, dst: &str, ty: &str) -> TrafficEvent {
        serde_json::from_value(serde_json::json!({
            "source_ip": src, "dest_ip": dst, "event_type": ty
        }))
        .unwrap()
    }

    #[test]
    fn defaults_are_filled() {
        let e = ev("203.0.113.5", "", "alert");
        assert!(!e.id.is_empty());
        assert_eq!(e.source_port, 0);
        assert!(e.validate().is_ok());
    }

    #[test]
    fn rejects_bad_addresses_and_types() {
        assert!(ev("not-an-ip", "", "alert").validate().is_err());
        assert!(ev("1.2.3.4", "1.2.3.4; rm -rf /", "alert").validate().is_err());
        assert!(ev("1.2.3.4", "", "a b").validate().is_err());
        assert!(ev("2001:db8::1", "", "http").validate().is_ok());
    }

    #[test]
    fn pagination_clamps() {
        let p = Pagination {
            page: Some(0),
            limit: Some(10_000),
        };
        assert_eq!(p.resolve(), (1, 200));
    }
}
