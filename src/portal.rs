//! Portal — commercial user-facing API (Rust port): register, login,
//! API key management, recharge & pay. Serves the P0 "can take money"
//! loop on a separate port.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{AuthService, CachedKeyStore};
use crate::payment::PaymentService;

pub struct PortalState {
    pub auth: AuthService,
    pub keys: std::sync::Arc<CachedKeyStore>,
    pub pay: PaymentService,
    pub admin_key: String,
}

pub fn router(state: Arc<PortalState>) -> Router {
    Router::new()
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/keys", post(create_key).get(list_keys))
        .route("/api/recharge", post(recharge))
        .route("/api/recharge/pay", post(pay))
        .route("/api/recharge/status", axum::routing::get(recharge_status))
        .with_state(state)
}

fn admin_auth(state: &PortalState, headers: &axum::http::HeaderMap) -> bool {
    state.admin_key.is_empty()
        || headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.strip_prefix("Bearer ").unwrap_or("") == state.admin_key)
            .unwrap_or(false)
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response()
}

fn user_id_from(headers: &axum::http::HeaderMap, q: &axum::http::Uri) -> Result<i64, Response> {
    let raw = q.query().and_then(|s| {
        s.split('&')
            .find(|kv| kv.starts_with("user_id="))
            .map(|kv| kv[8..].to_string())
    });
    let raw = raw.or_else(|| {
        headers
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    });
    raw.and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, Json(json!({"error": "user_id required"}))).into_response())
}

#[derive(Deserialize)]
struct CredReq {
    username: String,
    password: String,
}

async fn register(State(st): State<Arc<PortalState>>, headers: axum::http::HeaderMap, Json(req): Json<CredReq>) -> Response {
    if !admin_auth(&st, &headers) {
        return unauthorized();
    }
    match st.auth.register(&req.username, &req.password).await {
        Ok(id) => (StatusCode::OK, Json(json!({"user_id": id, "username": req.username}))).into_response(),
        Err(e) => (StatusCode::CONFLICT, Json(json!({"error": e}))).into_response(),
    }
}

async fn login(State(st): State<Arc<PortalState>>, headers: axum::http::HeaderMap, Json(req): Json<CredReq>) -> Response {
    if !admin_auth(&st, &headers) {
        return unauthorized();
    }
    match st.auth.login(&req.username, &req.password).await {
        Ok(id) => (StatusCode::OK, Json(json!({"user_id": id, "token": format!("dev-{}", id)}))).into_response(),
        Err(e) => (StatusCode::UNAUTHORIZED, Json(json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
struct KeyReq {
    name: Option<String>,
}

async fn create_key(State(st): State<Arc<PortalState>>, headers: axum::http::HeaderMap, uri: axum::http::Uri, Json(req): Json<KeyReq>) -> Response {
    if !admin_auth(&st, &headers) {
        return unauthorized();
    }
    let uid = match user_id_from(&headers, &uri) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match st.auth.create_key(uid, req.name.as_deref().unwrap_or("")).await {
        Ok(key) => (StatusCode::OK, Json(json!({"key": key, "note": "shown once"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

async fn list_keys(State(st): State<Arc<PortalState>>, headers: axum::http::HeaderMap, uri: axum::http::Uri) -> Response {
    if !admin_auth(&st, &headers) {
        return unauthorized();
    }
    let uid = match user_id_from(&headers, &uri) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match st.auth.list_keys(uid).await {
        Ok(keys) => (StatusCode::OK, Json(json!({"keys": keys}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
struct RechargeReq {
    amount_micros: i64,
    #[serde(default)]
    idempotency_key: String,
}

async fn recharge(State(st): State<Arc<PortalState>>, headers: axum::http::HeaderMap, uri: axum::http::Uri, Json(req): Json<RechargeReq>) -> Response {
    if !admin_auth(&st, &headers) {
        return unauthorized();
    }
    let uid = match user_id_from(&headers, &uri) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match st.pay.recharge(uid, req.amount_micros, &req.idempotency_key).await {
        Ok(id) => (StatusCode::OK, Json(json!({"recharge_id": id, "status": "PENDING"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
struct PayReq {
    recharge_id: i64,
    #[serde(default)]
    channel: String,
}

async fn pay(State(st): State<Arc<PortalState>>, headers: axum::http::HeaderMap, Json(req): Json<PayReq>) -> Response {
    if !admin_auth(&st, &headers) {
        return unauthorized();
    }
    let channel = if req.channel.is_empty() { "mock" } else { &req.channel };
    match st.pay.pay(req.recharge_id, channel).await {
        Ok(txn) => (StatusCode::OK, Json(json!({"txn_id": txn, "status": "PAID"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

async fn recharge_status(State(st): State<Arc<PortalState>>, headers: axum::http::HeaderMap, uri: axum::http::Uri) -> Response {
    if !admin_auth(&st, &headers) {
        return unauthorized();
    }
    let rid = uri
        .query()
        .and_then(|s| s.split('&').find(|kv| kv.starts_with("recharge_id=")).map(|kv| kv[12..].to_string()))
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    if rid <= 0 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "recharge_id required"}))).into_response();
    }
    match st.pay.recharge_status(rid).await {
        Ok(status) => (StatusCode::OK, Json(json!({"recharge_id": rid, "status": status}))).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(),
    }
}
