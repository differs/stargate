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
        upstream_url,
        upstream_key,
        api_keys,
    });

    let app = gateway::router(cfg);
    let addr = format!("0.0.0.0:{port}");
    tracing::info!("stargate listening on {addr} (upstream: {})", env_or("STARGATE_UPSTREAM", ""));
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}
