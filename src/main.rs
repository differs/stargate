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

mod auth;
mod billing;
#[cfg(test)]
mod billing_tests;
mod jwt;
mod gateway;
mod metering;
mod openai;
mod payment;
mod portal;
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

    // --- P0 commercial: auth + payment + portal (requires PG) ---
    let mut key_store = None;
    if !pg_dsn.is_empty() {
        match auth::AuthService::connect(&pg_dsn).await {
            Ok(auth_svc) => {
                let auth_svc = std::sync::Arc::new(auth_svc);
                let ks = std::sync::Arc::new(auth::CachedKeyStore::new(
                    auth_svc.as_ref().clone(),
                    std::time::Duration::from_secs(60),
                ));

                let pay_svc = payment::PaymentService::new(
                    auth_svc.inner(),
                    Box::new(move |user_id: i64, amount: i64| {
                        let redis_addr = redis_addr.clone();
                        Box::pin(async move {
                            let client = redis::Client::open(format!("redis://{redis_addr}"))
                                .map_err(|e| e.to_string())?;
                            let mut conn = client
                                .get_multiplexed_tokio_connection()
                                .await
                                .map_err(|e| e.to_string())?;
                            redis::cmd("INCRBY")
                                .arg(format!("balance:user-{user_id}"))
                                .arg(amount)
                                .query_async::<i64>(&mut conn)
                                .await
                                .map_err(|e| e.to_string())?;
                            Ok(())
                        })
                    }),
                );
                let mut pay_svc = pay_svc;
                pay_svc.register_channel(Box::new(payment::MockChannel));

                let jwt_secret = env_or("STARGATE_JWT_SECRET", "");
                let jwt_mgr = if jwt_secret.is_empty() {
                    None
                } else {
                    Some(crate::jwt::JwtManager::new(&jwt_secret))
                };
                let oidc_client = if let Ok(url) = env::var("STARGATE_OIDC_PROVIDER_URL") {
                    match portal::OidcClient::new(
                        &url,
                        &env_or("STARGATE_OIDC_CLIENT_ID", ""),
                        &env_or("STARGATE_OIDC_CLIENT_SECRET", ""),
                        &env_or("STARGATE_OIDC_REDIRECT_URL", "http://localhost:3202/api/oidc/callback"),
                    )
                    .await
                    {
                        Ok(c) => Some(std::sync::Arc::new(c)),
                        Err(e) => {
                            tracing::error!("oidc init failed: {e}");
                            None
                        }
                    }
                } else {
                    None
                };
                if jwt_mgr.is_some() {
                    tracing::info!("session JWT enabled");
                }
                if oidc_client.is_some() {
                    tracing::info!("oidc enabled");
                }
                let portal_state = std::sync::Arc::new(portal::PortalState {
                    auth: auth_svc.as_ref().clone(),
                    keys: ks.clone(),
                    pay: pay_svc,
                    admin_key: env_or("STARGATE_PORTAL_KEY", ""),
                    jwt: jwt_mgr,
                    oidc: oidc_client,
                    web_dir: {
                        let d = env_or("STARGATE_WEB_DIR", "");
                        if d.is_empty() { None } else { Some(d) }
                    },
                });
                let app2 = portal::router(portal_state);
                let portal_port = env_or("STARGATE_PORTAL_PORT", "3202");
                let portal_listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{portal_port}"))
                    .await
                    .expect("portal bind");
                tokio::spawn(async move {
                    tracing::info!("stargate portal listening on :{portal_port}");
                    let _ = axum::serve(portal_listener, app2).await;
                });

                key_store = Some(ks);
                tracing::info!("commercial stack enabled (users/keys/recharge/pay)");
            }
            Err(e) => {
                tracing::error!("auth service failed, portal disabled: {e}");
            }
        }
    }

    let app = gateway::router_full(cfg, billing, key_store);
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
