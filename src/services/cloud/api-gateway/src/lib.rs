//! NetSentry gateway: multi-tenant ingest, detection and prevention service.

pub mod auth;
pub mod config;
pub mod detection;
pub mod error;
pub mod models;
pub mod pipeline;
pub mod prevention;
pub mod ratelimit;
pub mod routes;
pub mod settings;
pub mod signing;
pub mod state;
pub mod store;
pub mod threat_intel;
pub mod ws;

use anyhow::Result;
use config::Config;
use state::AppState;
use store::Store;

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = Config::from_env()?;
    let mut opts = mongodb::options::ClientOptions::parse(&cfg.mongodb_uri).await?;
    opts.max_pool_size = Some(20);
    opts.app_name = Some("netsentry-gateway".into());
    let client = mongodb::Client::with_options(opts)?;
    let store = Store::new(client.database(&cfg.db_name));

    // Wait for MongoDB (compose start-up ordering is best effort).
    let mut attempt = 0;
    loop {
        match store.ensure_indexes(cfg.event_retention_days).await {
            Ok(()) => break,
            Err(e) if attempt < 30 => {
                attempt += 1;
                tracing::warn!("waiting for MongoDB ({attempt}/30): {e}");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e),
        }
    }

    let limiter = ratelimit::RateLimiter::new(cfg.redis_url.as_deref()).await;
    let port = cfg.port;
    let state = AppState::new(cfg, store, limiter);

    threat_intel::spawn_refresh_loop(state.clone());
    prevention::spawn_expiry_loop(state.clone());

    let app = routes::router(state);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("gateway listening on 0.0.0.0:{port}");
    axum::serve(listener, app).with_graceful_shutdown(shutdown()).await?;
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
