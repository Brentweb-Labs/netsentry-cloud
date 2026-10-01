//! Fixed-window rate limiter backed by Redis when available, memory otherwise.

use dashmap::DashMap;
use redis::aio::ConnectionManager;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    redis: Option<ConnectionManager>,
    local: DashMap<String, (Instant, u32)>,
}

impl RateLimiter {
    pub async fn new(redis_url: Option<&str>) -> Self {
        let redis = match redis_url {
            Some(url) => match redis::Client::open(url) {
                Ok(c) => match ConnectionManager::new(c).await {
                    Ok(cm) => Some(cm),
                    Err(e) => {
                        tracing::warn!("redis unavailable ({e}); using in-memory rate limits");
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!("invalid REDIS_URL ({e}); using in-memory rate limits");
                    None
                }
            },
            None => None,
        };
        Self {
            redis,
            local: DashMap::new(),
        }
    }

    pub fn in_memory() -> Self {
        Self {
            redis: None,
            local: DashMap::new(),
        }
    }

    /// Returns true if the call is allowed (and counts it).
    pub async fn allow(&self, key: &str, limit: u32, window: Duration) -> bool {
        if let Some(cm) = &self.redis {
            let mut conn = cm.clone();
            let rkey = format!("rl:{key}");
            let res: redis::RedisResult<u32> = redis::cmd("INCR").arg(&rkey).query_async(&mut conn).await;
            match res {
                Ok(n) => {
                    if n == 1 {
                        let _: redis::RedisResult<()> = redis::cmd("EXPIRE")
                            .arg(&rkey)
                            .arg(window.as_secs().max(1))
                            .query_async(&mut conn)
                            .await;
                    }
                    return n <= limit;
                }
                Err(e) => tracing::warn!("redis rate limit failed ({e}); falling back to memory"),
            }
        }
        self.allow_local(key, limit, window)
    }

    fn allow_local(&self, key: &str, limit: u32, window: Duration) -> bool {
        let now = Instant::now();
        let mut e = self.local.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(e.0) >= window {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocks_after_limit_and_is_per_key() {
        let rl = RateLimiter::in_memory();
        let w = Duration::from_secs(60);
        for _ in 0..3 {
            assert!(rl.allow("a", 3, w).await);
        }
        assert!(!rl.allow("a", 3, w).await);
        assert!(rl.allow("b", 3, w).await);
    }

    #[tokio::test]
    async fn window_resets() {
        let rl = RateLimiter::in_memory();
        let w = Duration::from_millis(20);
        assert!(rl.allow("a", 1, w).await);
        assert!(!rl.allow("a", 1, w).await);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(rl.allow("a", 1, w).await);
    }
}
