//! Stargate — Rust re-implementation of MeterGate's data plane.
//!
//! Same requirements as the Go version's core:
//!   - OpenAI-compatible `/v1/chat/completions` (stream + non-stream)
//!   - transparent upstream forwarding
//!   - streaming token metering (approximate, cross-checked with upstream usage)
//!   - request-level metering events (audit log)
//!   - static API-key auth
//!
//! Purpose: head-to-head performance comparison with the Go implementation
//! under identical conditions (same mock upstream, same load generator).
//! See README.md for the benchmark matrix.

mod billing;
#[cfg(test)]
mod billing_tests;
mod gateway;
mod metering;
mod openai;
mod upstream;

use std::env;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

fn env_or(key: &str, def: &str) -> String {
    env::var(key).unwrap_or_else(|_| def.to_string())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let port = env_or("STARGATE_PORT", "3000");
    let upstream_url = env_or("STARGATE_UPSTREAM", "");
    let upstream_key = env_or("STARGATE_UPSTREAM_KEY", "");
    let api_keys: Vec<String> = env_or("STARGATE_API_KEYS", "")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_string())
        .collect();

    if upstream_url.is_empty() {
        eprintln!("STARGATE_UPSTREAM is required");
        std::process::exit(1);
    }
    if api_keys.is_empty() {
        eprintln!("at least one STARGATE_API_KEYS entry is required");
        std::process::exit(1);
    }

    let cfg = Arc::new(gateway::Config {
        upstream_url: upstream_url.clone(),
        upstream_key,
        api_keys,
    });

    // --- optional billing stack (Redis pre-charge + PG settle) ---
    let redis_addr = env_or("STARGATE_REDIS_ADDR", "");
    let pg_dsn = env_or("STARGATE_PG_DSN", "");
    let billing = if !redis_addr.is_empty() && !pg_dsn.is_empty() {
        match init_billing(&redis_addr, &pg_dsn).await {
            Ok(bh) => {
                tracing::info!("dual-track billing enabled (redis + postgres)");
                Some(Arc::new(bh))
            }
            Err(e) => {
                tracing::error!("billing init failed, running without: {e}");
                None
            }
        }
    } else {
        None
    };

    let app = gateway::router_with_billing(cfg, billing);
    let addr = format!("0.0.0.0:{port}");
    tracing::info!("stargate listening on {addr} (upstream: {upstream_url})");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}

async fn init_billing(redis_addr: &str, pg_dsn: &str) -> Result<billing::BillingHandle, String> {
    let store = std::sync::Arc::new(billing::PostgresStore::connect(pg_dsn).await?);
    let pre = billing::Precharger::connect(redis_addr).await?;
    let settler = std::sync::Arc::new(billing::Settler::new(store.clone(), Some(pre), 500).await);
    Ok(billing::BillingHandle {
        pre: Some(std::sync::Arc::new(billing::Precharger::connect(redis_addr).await?)),
        settler,
        store,
    })
}
