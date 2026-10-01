//! Per-tenant detection and auto-block settings.

use crate::state::AppState;
use crate::store::{bdt_now, TENANT_SETTINGS};
use anyhow::Result;
use mongodb::bson::{self, doc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockMode {
    /// Detections create pending blocks that an operator must approve (default).
    Manual,
    /// Critical detections are blocked immediately (still subject to allowlist, TTL and rate cap).
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantSettings {
    pub block_mode: BlockMode,
    /// IPs and CIDR ranges that are never blocked.
    pub allowlist: Vec<String>,
    /// Every block expires after this many hours.
    pub block_ttl_hours: u32,
    /// Auto-block only when the Suricata-style severity is `<=` this (1 = critical).
    pub auto_block_max_severity: u8,
    /// Detections with severity `<=` this create a pending block proposal.
    pub propose_max_severity: u8,
    /// Safety valve: at most this many automatic blocks per hour.
    pub max_auto_blocks_per_hour: u32,
    pub brute_force_threshold: u32,
    pub brute_force_window_secs: u32,
    pub monitored_paths: Vec<String>,
    pub threat_intel_enabled: bool,
}

impl Default for TenantSettings {
    fn default() -> Self {
        Self {
            block_mode: BlockMode::Manual,
            allowlist: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "fc00::/7".into(),
            ],
            block_ttl_hours: 24,
            auto_block_max_severity: 1,
            propose_max_severity: 2,
            max_auto_blocks_per_hour: 20,
            brute_force_threshold: 20,
            brute_force_window_secs: 60,
            monitored_paths: [
                "/login",
                "/api/auth",
                "/api/login",
                "/admin",
                "/wp-login.php",
                "/wp-admin",
                "/signin",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            threat_intel_enabled: true,
        }
    }
}

impl TenantSettings {
    /// Clamp values into safe ranges and drop malformed allowlist entries.
    pub fn sanitized(mut self) -> Self {
        self.block_ttl_hours = self.block_ttl_hours.clamp(1, 720);
        self.auto_block_max_severity = self.auto_block_max_severity.clamp(1, 4);
        self.propose_max_severity = self.propose_max_severity.clamp(1, 4).max(self.auto_block_max_severity);
        self.max_auto_blocks_per_hour = self.max_auto_blocks_per_hour.min(1000);
        self.brute_force_threshold = self.brute_force_threshold.clamp(3, 10_000);
        self.brute_force_window_secs = self.brute_force_window_secs.clamp(5, 3600);
        self.allowlist = self
            .allowlist
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| parse_allow_entry(s).is_some())
            .take(500)
            .collect();
        self.monitored_paths = self
            .monitored_paths
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| s.starts_with('/') && s.len() <= 200)
            .take(100)
            .collect();
        self
    }
}

enum AllowEntry {
    Ip(IpAddr),
    Net(ipnetwork::IpNetwork),
}

fn parse_allow_entry(s: &str) -> Option<AllowEntry> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(AllowEntry::Ip(ip));
    }
    s.parse::<ipnetwork::IpNetwork>().ok().map(AllowEntry::Net)
}

/// True if `ip` matches any allowlist entry (exact address or CIDR).
pub fn is_allowlisted(ip: &IpAddr, allowlist: &[String]) -> bool {
    allowlist
        .iter()
        .filter_map(|e| parse_allow_entry(e.trim()))
        .any(|e| match e {
            AllowEntry::Ip(a) => &a == ip,
            AllowEntry::Net(n) => n.contains(*ip),
        })
}

const CACHE_TTL: Duration = Duration::from_secs(15);

pub async fn load(state: &AppState, tenant_id: &str) -> TenantSettings {
    if let Some(entry) = state.settings_cache.get(tenant_id) {
        if entry.1.elapsed() < CACHE_TTL {
            return entry.0.clone();
        }
    }
    let loaded = match state
        .store
        .coll(TENANT_SETTINGS)
        .find_one(doc! { "tenant_id": tenant_id })
        .await
    {
        Ok(Some(d)) => bson::from_document::<TenantSettings>(d).unwrap_or_default().sanitized(),
        Ok(None) => TenantSettings::default(),
        Err(e) => {
            tracing::warn!("loading settings for tenant {tenant_id} failed: {e}");
            TenantSettings::default()
        }
    };
    state
        .settings_cache
        .insert(tenant_id.to_string(), (loaded.clone(), Instant::now()));
    loaded
}

pub async fn save(state: &AppState, tenant_id: &str, settings: TenantSettings) -> Result<TenantSettings> {
    let settings = settings.sanitized();
    let mut d = bson::to_document(&settings)?;
    d.insert("tenant_id", tenant_id);
    d.insert("updated_at", bdt_now());
    state
        .store
        .coll(TENANT_SETTINGS)
        .update_one(doc! { "tenant_id": tenant_id }, doc! { "$set": d })
        .upsert(true)
        .await?;
    state
        .settings_cache
        .insert(tenant_id.to_string(), (settings.clone(), Instant::now()));
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_manual_with_private_allowlist() {
        let s = TenantSettings::default();
        assert_eq!(s.block_mode, BlockMode::Manual);
        assert!(is_allowlisted(&"192.168.1.10".parse().unwrap(), &s.allowlist));
        assert!(is_allowlisted(&"172.20.0.5".parse().unwrap(), &s.allowlist));
        assert!(!is_allowlisted(&"172.32.0.5".parse().unwrap(), &s.allowlist));
        assert!(!is_allowlisted(&"203.0.113.5".parse().unwrap(), &s.allowlist));
    }

    #[test]
    fn allowlist_supports_exact_and_v6() {
        let list = vec!["203.0.113.7".to_string(), "2001:db8::/32".to_string()];
        assert!(is_allowlisted(&"203.0.113.7".parse().unwrap(), &list));
        assert!(!is_allowlisted(&"203.0.113.8".parse().unwrap(), &list));
        assert!(is_allowlisted(&"2001:db8::1".parse().unwrap(), &list));
    }

    #[test]
    fn sanitize_clamps_and_filters() {
        let s = TenantSettings {
            block_ttl_hours: 0,
            auto_block_max_severity: 9,
            propose_max_severity: 1,
            brute_force_threshold: 0,
            allowlist: vec!["bogus".into(), "10.1.2.3".into(), "10.0.0.0/99".into()],
            monitored_paths: vec!["nope".into(), "/ok".into()],
            ..Default::default()
        }
        .sanitized();
        assert_eq!(s.block_ttl_hours, 1);
        assert_eq!(s.auto_block_max_severity, 4);
        assert!(s.propose_max_severity >= s.auto_block_max_severity);
        assert_eq!(s.brute_force_threshold, 3);
        assert_eq!(s.allowlist, vec!["10.1.2.3".to_string()]);
        assert_eq!(s.monitored_paths, vec!["/ok".to_string()]);
    }

    #[test]
    fn partial_json_uses_defaults() {
        let s: TenantSettings = serde_json::from_str(r#"{"block_mode":"auto"}"#).unwrap();
        assert_eq!(s.block_mode, BlockMode::Auto);
        assert_eq!(s.block_ttl_hours, 24);
    }
}
