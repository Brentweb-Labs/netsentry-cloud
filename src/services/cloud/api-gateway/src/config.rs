//! Runtime configuration, read once from the environment.

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub mongodb_uri: String,
    pub db_name: String,
    pub jwt_secret: String,
    pub port: u16,
    /// Public base URL sensors use to reach this gateway (no trailing slash).
    pub public_url: String,
    pub redis_url: Option<String>,
    pub threat_feed_urls: Vec<String>,
    pub threat_feed_interval_secs: u64,
    pub event_retention_days: u32,
    /// Allowed CORS origins; empty means same-origin only (no CORS headers).
    pub cors_origins: Vec<String>,
}

pub const DEFAULT_THREAT_FEEDS: &[&str] = &[
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
];

fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let jwt_secret = env_opt("JWT_SECRET").context("JWT_SECRET must be set")?;
        if jwt_secret.len() < 32 {
            bail!("JWT_SECRET must be at least 32 characters");
        }
        let public_url = env_opt("PUBLIC_URL")
            .or_else(|| env_opt("DOMAIN").map(|d| format!("https://{d}")))
            .unwrap_or_else(|| "http://localhost:8080".to_string());
        let threat_feed_urls = match env_opt("THREAT_FEED_URLS") {
            Some(v) if v.eq_ignore_ascii_case("none") => vec![],
            Some(v) => v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            None => DEFAULT_THREAT_FEEDS.iter().map(|s| s.to_string()).collect(),
        };
        Ok(Self {
            mongodb_uri: env_opt("MONGODB_URI").context("MONGODB_URI must be set")?,
            db_name: env_opt("MONGODB_DB").unwrap_or_else(|| "idps_database".into()),
            jwt_secret,
            port: env_opt("PORT").and_then(|p| p.parse().ok()).unwrap_or(8080),
            public_url: public_url.trim_end_matches('/').to_string(),
            redis_url: env_opt("REDIS_URL"),
            threat_feed_urls,
            threat_feed_interval_secs: env_opt("THREAT_FEED_INTERVAL_SECS")
                .and_then(|p| p.parse().ok())
                .unwrap_or(6 * 3600),
            event_retention_days: env_opt("EVENT_RETENTION_DAYS")
                .and_then(|p| p.parse().ok())
                .unwrap_or(30),
            cors_origins: env_opt("CORS_ORIGINS")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// WebSocket URL sensors use for the command channel.
    pub fn ws_url(&self) -> String {
        ws_url_from(&self.public_url)
    }
}

pub fn ws_url_from(public_url: &str) -> String {
    let base = public_url.trim_end_matches('/');
    let swapped = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("wss://{base}")
    };
    format!("{swapped}/ws/raspi")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_swaps_scheme() {
        assert_eq!(ws_url_from("https://example.org"), "wss://example.org/ws/raspi");
        assert_eq!(ws_url_from("http://localhost:8080/"), "ws://localhost:8080/ws/raspi");
        assert_eq!(ws_url_from("example.org"), "wss://example.org/ws/raspi");
    }
}
