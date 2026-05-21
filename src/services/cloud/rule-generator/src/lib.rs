//! IDPS Rule Generator
//!
//! Generates Suricata rules and iptables commands from security detection events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedRule {
    pub rule_id: String,
    pub suricata_rule: Option<String>,
    pub iptables_rule: Option<String>,
    pub description: String,
    pub severity: u8,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Generate an IP-based block rule for a detected threat.
pub fn generate_ip_block_rule(
    ip: &str,
    reason: &str,
    severity: u8,
    duration_hours: u64,
) -> GeneratedRule {
    let sid = ip_to_sid(ip);
    let suricata_rule = Some(format!(
        r#"drop ip {ip} any -> any any (msg:"IDPS Block: {clean_reason}"; sid:{sid}; rev:1;)"#,
        ip = ip,
        clean_reason = reason.replace('"', "'"),
        sid = sid,
    ));
    let iptables_rule = Some(format!(
        "-I INPUT 1 -s {ip} -j DROP -m comment --comment idps-block-{ip}",
        ip = ip,
    ));
    let expires_at = if duration_hours > 0 {
        Some(Utc::now() + chrono::Duration::hours(duration_hours as i64))
    } else {
        None
    };
    GeneratedRule {
        rule_id: format!("ip-block-{ip}"),
        suricata_rule,
        iptables_rule,
        description: reason.to_string(),
        severity,
        expires_at,
    }
}

/// Generate rules for DDoS mitigation: rate-limit a source IP.
pub fn generate_ddos_rule(ip: &str, pps_threshold: u32, duration_hours: u64) -> GeneratedRule {
    let sid = ip_to_sid(ip) + 1_000_000;
    let suricata_rule = Some(format!(
        r#"drop ip {ip} any -> any any (msg:"IDPS DDoS Mitigation"; detection_filter:track by_src, count {pps}, seconds 1; sid:{sid}; rev:1;)"#,
        ip = ip,
        pps = pps_threshold,
        sid = sid,
    ));
    // Rate-limit with iptables hashlimit
    let iptables_rule = Some(format!(
        "-I INPUT 1 -s {ip} -m hashlimit --hashlimit-above {pps}/sec --hashlimit-mode srcip --hashlimit-name ddos_{ip_clean} -j DROP",
        ip = ip,
        pps = pps_threshold,
        ip_clean = ip.replace('.', "_").replace(':', "_"),
    ));
    GeneratedRule {
        rule_id: format!("ddos-{ip}"),
        suricata_rule,
        iptables_rule,
        description: format!("DDoS mitigation for {ip}"),
        severity: 9,
        expires_at: if duration_hours > 0 {
            Some(Utc::now() + chrono::Duration::hours(duration_hours as i64))
        } else {
            None
        },
    }
}

/// Generate a Suricata rule for brute-force detection on a path.
pub fn generate_brute_force_rule(
    ip: &str,
    path: &str,
    threshold: u32,
    window_secs: u32,
) -> GeneratedRule {
    let sid = ip_to_sid(ip) + 2_000_000;
    let suricata_rule = Some(format!(
        r#"alert http {ip} any -> any any (msg:"IDPS BruteForce: {ip} on {path}"; content:"{path}"; http_uri; detection_filter:track by_src, count {threshold}, seconds {window}; sid:{sid}; rev:1;)"#,
        ip = ip,
        path = path,
        threshold = threshold,
        window = window_secs,
        sid = sid,
    ));
    GeneratedRule {
        rule_id: format!("brute-{ip}"),
        suricata_rule,
        iptables_rule: None,
        description: format!("Brute force detection for {ip} on {path}"),
        severity: 7,
        expires_at: None,
    }
}

/// Generate a port-scan detection rule.
pub fn generate_port_scan_rule(ip: &str, duration_hours: u64) -> GeneratedRule {
    let sid = ip_to_sid(ip) + 3_000_000;
    let suricata_rule = Some(format!(
        r#"drop tcp {ip} any -> any any (msg:"IDPS Port Scan: {ip}"; flags:S; detection_filter:track by_src, count 20, seconds 5; sid:{sid}; rev:1;)"#,
        ip = ip,
        sid = sid,
    ));
    GeneratedRule {
        rule_id: format!("scan-{ip}"),
        suricata_rule,
        iptables_rule: None,
        description: format!("Port scan from {ip}"),
        severity: 7,
        expires_at: if duration_hours > 0 {
            Some(Utc::now() + chrono::Duration::hours(duration_hours as i64))
        } else {
            None
        },
    }
}

/// Derive a stable Suricata SID from an IP address.
/// Uses range 9_000_000+ to avoid conflicts with community rules.
fn ip_to_sid(ip: &str) -> u64 {
    9_000_000 + ip.bytes().fold(0u64, |acc, b| acc.wrapping_add(b as u64))
}
