//! Gateway: axum router, auth, chat completion handler (stream + non-stream),
//! streaming metering and metering events — mirroring MeterGate's Go data plane.

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use bytes::Bytes;
use futures_util::StreamExt;

use crate::billing::{self, BillingHandle};
use crate::metering::{self, Accumulator};
use crate::openai::{self, ChatRequest};
use crate::upstream::UpstreamClient;
use prometheus::{Encoder, IntCounter, IntCounterVec, Opts, TextEncoder};
use std::sync::LazyLock;
use uuid::Uuid;

// --- basic metrics (observability parity, minimal set) ---
// CounterVec::new does NOT register into the default registry — register
// a clone so prometheus::gather() (used by /metrics) sees the series.
fn registered_counter(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(Opts::new(name, help), labels).unwrap();
    let _ = prometheus::register(Box::new(c.clone())); // ignore duplicate-reg errors
    c
}

static HTTP_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    registered_counter("stargate_http_requests_total", "HTTP requests by status class", &["code"])
});
static PRECHARGE_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    registered_counter("stargate_precharge_total", "Pre-charge attempts by result", &["result"])
});
static ORDERS_SETTLED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    registered_counter("stargate_orders_settled_total", "Settled orders by status", &["status"])
});

pub struct Config {
    pub upstream_url: String,
    pub upstream_key: String,
    pub api_keys: Vec<String>,
}

pub struct AppState {
    cfg: Arc<Config>,
    upstream: UpstreamClient,
    keys: HashSet<String>,
    billing: Option<Arc<BillingHandle>>,
}

pub fn router_with_billing(cfg: Arc<Config>, billing: Option<Arc<BillingHandle>>) -> Router {
    let keys: HashSet<String> = cfg.api_keys.iter().cloned().collect();
    let state = Arc::new(AppState {
        upstream: UpstreamClient::new(cfg.upstream_url.clone(), cfg.upstream_key.clone()),
        keys,
        billing,
        cfg,
    });
    Router::new()
        .route("/v1/chat/completions", post(handle_chat))
        .route("/healthz", axum::routing::get(|| async { StatusCode::OK }))
        .route("/metrics", axum::routing::get(metrics_handler))
        .with_state(state)
}

pub fn router(cfg: Arc<Config>) -> Router {
    router_with_billing(cfg, None)
}

async fn metrics_handler() -> impl axum::response::IntoResponse {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    (StatusCode::OK, String::from_utf8_lossy(&buffer).to_string())
}

pub fn record_http(code: u16) {
    let class = format!("{}xx", code / 100);
    HTTP_REQUESTS.with_label_values(&[&class]).inc();
}

pub fn record_precharge(result: &str) {
    PRECHARGE_TOTAL.with_label_values(&[result]).inc();
}

pub fn record_orders(status: &str, n: usize) {
    ORDERS_SETTLED.with_label_values(&[status]).inc_by(n as u64);
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
        "error": {"message": "invalid or missing API key", "type": "stargate_error"}
    })))
    .into_response()
}

fn auth_check(headers: &HeaderMap, keys: &HashSet<String>) -> Result<String, Response> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let key = auth.strip_prefix("Bearer ").unwrap_or("").trim();
    if key.is_empty() || !keys.contains(key) {
        return Err(unauthorized());
    }
    Ok(key.to_string())
}

async fn handle_chat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match auth_check(&headers, &state.keys) {
        Ok(u) => u,
        Err(r) => {
            record_http(401);
            return r;
        }
    };
    record_http(200); // optimistic; failures recorded at their sites

    let req: ChatRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": {"message": format!("invalid JSON: {e}")}})),
            )
                .into_response();
        }
    };
    if req.model.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"message": "model is required"}})),
        )
            .into_response();
    }

    let request_id = Uuid::now_v7().to_string();
    let prompt_tokens = metering::estimate_prompt_tokens(&req.messages);

    // Freeze the price at request start: settlement must use this, never
    // the current table (in-flight requests are not repriced).
    let pricing = Some(billing::price_for(&req.model));

    // Billing fast path: atomic pre-charge before touching the upstream.
    if let Some(bh) = &state.billing {
        if let Some(pre) = &bh.pre {
            let p = billing::price_for(&req.model);
            let amount = billing::estimate_precharge(prompt_tokens as i64, req.max_tokens, p);
            record_precharge("ok");
            if let Err(_e) = pre.precharge(&user, &request_id, amount).await {
                record_precharge("insufficient");
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(serde_json::json!({"error": {"message": "insufficient balance"}})),
                )
                    .into_response();
            }
        }
    }

    if req.stream {
        handle_stream(state, body, request_id, prompt_tokens, req.model, user, pricing).await
    } else {
        handle_non_stream(state, body, request_id, prompt_tokens, req.model, user, pricing).await
    }
}

async fn handle_non_stream(
    state: Arc<AppState>,
    body: Bytes,
    request_id: String,
    prompt_tokens: u32,
    model: String,
    user: String,
    pricing: Option<billing::ModelPrice>,
) -> Response {
    let start = std::time::Instant::now();
    let _ = &user; // used by event attribution
    let (status, resp_body) = match state.upstream.forward(body).await {
        Ok(r) => r,
        Err(e) => {
            // failed events are emitted for audit + zero-completion insurance
            metering_event(&request_id, "failed", prompt_tokens, 0, start);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": {"message": format!("upstream error: {e}")}})),
            )
                .into_response();
        }
    };

    // extract upstream usage for cross-validation
    let mut completion = 0u32;
    let mut usage_raw = String::new();
    if (200..300).contains(&status) {
        if let Ok(parsed) = serde_json::from_slice::<openai::ChatResponse>(&resp_body) {
            if let Some(u) = parsed.usage {
                completion = u.completion_tokens;
                usage_raw = serde_json::to_string(&u).unwrap_or_default();
            }
        }
    }

    let event_status = if (200..300).contains(&status) { "completed" } else { "failed" };
    metering_event(&request_id, event_status, prompt_tokens, completion, start);
    emit_to_settler(&state, &request_id, &user, &model, event_status, prompt_tokens, completion, start, pricing);

    (StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY), resp_body).into_response()
}

async fn handle_stream(
    state: Arc<AppState>,
    body: Bytes,
    request_id: String,
    prompt_tokens: u32,
    model: String,
    user: String,
    pricing: Option<billing::ModelPrice>,
) -> Response {
    let start = std::time::Instant::now();
    let acc = Arc::new(Accumulator::new());

    let (status, stream) = match state.upstream.forward_stream(body).await {
        Ok(r) => r,
        Err(e) => {
            metering_event(&request_id, "failed", prompt_tokens, 0, start);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": {"message": format!("upstream error: {e}")}})),
            )
                .into_response();
        }
    };

    if status != 200 {
        // non-200 with stream: drain small body and fail
        metering_event(&request_id, "failed", prompt_tokens, 0, start);
        return (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            Body::empty(),
        )
            .into_response();
    }

    let acc_for_task = acc.clone();
    let request_id_for_task = request_id.clone();
    let sse_stream = stream.filter_map(move |chunk| {
        let acc = acc_for_task.clone();
        let rid = request_id_for_task.clone();
        async move {
            match chunk {
                Ok(bytes) => {
                    // fast-path metering: scan delta content without full parse
                    if let Some(content) = openai::fast_delta_content(&bytes) {
                        acc.add_delta(content);
                    }
                    // forward verbatim
                    let mut out = Vec::with_capacity(bytes.len() + 8);
                    out.extend_from_slice(b"data: ");
                    out.extend_from_slice(&bytes);
                    out.extend_from_slice(b"\n\n");
                    Some(Ok::<Bytes, std::convert::Infallible>(Bytes::from(out)))
                }
                Err(e) => {
                    tracing::warn!(request_id = %rid, "upstream stream error: {e}");
                    Some(Ok::<Bytes, std::convert::Infallible>(Bytes::from(
                        "data: [DONE]\n\n",
                    )))
                }
            }
        }
    });

    let resp = Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(sse_stream))
        .unwrap();

    // emit the metering event after the stream completes
    let completion = acc.completion();
    let state2 = state.clone();
    let user2 = user.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(0)).await;
        metering_event(&request_id, "completed", prompt_tokens, completion, start);
        emit_to_settler(&state2, &request_id, &user2, &model, "completed", prompt_tokens, completion, start, pricing);
    });

    resp
}

fn emit_to_settler(
    state: &AppState,
    request_id: &str,
    user_id: &str,
    model: &str,
    status: &str,
    prompt: u32,
    completion: u32,
    start: std::time::Instant,
    pricing: Option<billing::ModelPrice>,
) {
    if let Some(bh) = &state.billing {
        let ev = billing::MeteringEvent {
            request_id: request_id.to_string(),
            user_id: user_id.to_string(),
            model: model.to_string(),
            provider: state.upstream.url().to_string(),
            status: status.to_string(),
            prompt_tokens: prompt as i64,
            completion_tokens: completion as i64,
            duration_ms: start.elapsed().as_millis() as i64,
            ttft_ms: 0,
            pricing,
        };
        let settler = bh.settler.clone();
        tokio::spawn(async move {
            settler.handle(ev).await;
        });
    }
}

fn metering_event(request_id: &str, status: &str, prompt: u32, completion: u32, start: std::time::Instant) {
    // Audit event at DEBUG level (mirrors MeterGate: durable sinks handle
    // persistence; the log line must never tax the hot path).
    tracing::debug!(
        request_id = %request_id,
        status = %status,
        prompt_tokens = prompt,
        completion_tokens = completion,
        duration_ms = start.elapsed().as_millis() as u64,
        "metering"
    );
}
