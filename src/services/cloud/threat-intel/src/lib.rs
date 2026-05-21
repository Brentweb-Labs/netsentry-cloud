//! IDPS Threat Intelligence
//!
//! IP reputation scoring using local blocklists and optional external feeds.
//! Designed for offline-first operation (school networks may restrict outbound).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    Malware,
    Botnet,
    Scanner,
    Brute,
    Ddos,
    Proxy,
    Known,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputation {
    pub ip: String,
    pub score: f64, // 0.0 (clean) … 1.0 (definitely malicious)
    pub categories: Vec<ThreatCategory>,
    pub source: String,
    pub is_tor_exit: bool,
}

impl IpReputation {
    pub fn clean(ip: &str) -> Self {
        Self {
            ip: ip.to_string(),
            score: 0.0,
            categories: vec![],
            source: "default".to_string(),
            is_tor_exit: false,
        }
    }

    pub fn malicious(ip: &str, score: f64, categories: Vec<ThreatCategory>, source: &str) -> Self {
        Self {
            ip: ip.to_string(),
            score: score.clamp(0.0, 1.0),
            categories,
            source: source.to_string(),
            is_tor_exit: false,
        }
    }
}

/// In-memory threat intelligence store backed by flat blocklist files.
/// Files should contain one IP per line; comments with `#` are ignored.
pub struct ThreatIntelStore {
    blocked: HashSet<String>,
    tor_exits: HashSet<String>,
}

impl ThreatIntelStore {
    pub fn new() -> Self {
        Self {
            blocked: HashSet::new(),
            tor_exits: HashSet::new(),
        }
    }

    /// Load blocklist IPs from a text file (one IP per line, `#` comments ignored).
    pub fn load_blocklist(&mut self, path: &Path) -> std::io::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let before = self.blocked.len();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            self.blocked.insert(trimmed.to_string());
        }
        Ok(self.blocked.len() - before)
    }

    /// Load a Tor exit node list (same format as blocklist).
    pub fn load_tor_exits(&mut self, path: &Path) -> std::io::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let before = self.tor_exits.len();
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                self.tor_exits.insert(trimmed.to_string());
            }
        }
        Ok(self.tor_exits.len() - before)
    }

    /// Add an IP directly (e.g., from AbuseIPDB API or manual feeds).
    pub fn add_ip(&mut self, ip: &str) {
        self.blocked.insert(ip.to_string());
    }

    /// Query the reputation of an IP.
    pub fn lookup(&self, ip: &str) -> IpReputation {
        let is_blocked = self.blocked.contains(ip);
        let is_tor = self.tor_exits.contains(ip);

        if is_blocked && is_tor {
            IpReputation {
                ip: ip.to_string(),
                score: 0.95,
                categories: vec![ThreatCategory::Known, ThreatCategory::Proxy],
                source: "blocklist+tor".to_string(),
                is_tor_exit: true,
            }
        } else if is_blocked {
            IpReputation::malicious(ip, 0.85, vec![ThreatCategory::Known], "blocklist")
        } else if is_tor {
            IpReputation {
                ip: ip.to_string(),
                score: 0.5,
                categories: vec![ThreatCategory::Proxy],
                source: "tor_exits".to_string(),
                is_tor_exit: true,
            }
        } else {
            IpReputation::clean(ip)
        }
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }
    pub fn tor_count(&self) -> usize {
        self.tor_exits.len()
    }
}

impl Default for ThreatIntelStore {
    fn default() -> Self {
        Self::new()
    }
}
