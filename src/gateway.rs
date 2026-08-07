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

use crate::metering::{self, Accumulator};
use crate::openai::{self, ChatRequest};
use crate::upstream::UpstreamClient;
use uuid::Uuid;

pub struct Config {
    pub upstream_url: String,
    pub upstream_key: String,
    pub api_keys: Vec<String>,
}

pub struct AppState {
    cfg: Arc<Config>,
    upstream: UpstreamClient,
    keys: HashSet<String>,
}

pub fn router(cfg: Arc<Config>) -> Router {
    let keys: HashSet<String> = cfg.api_keys.iter().cloned().collect();
    let state = Arc::new(AppState {
        upstream: UpstreamClient::new(cfg.upstream_url.clone(), cfg.upstream_key.clone()),
        keys,
        cfg,
    });
    Router::new()
        .route("/v1/chat/completions", post(handle_chat))
        .route("/healthz", axum::routing::get(|| async { StatusCode::OK }))
        .with_state(state)
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
    let _user = match auth_check(&headers, &state.keys) {
        Ok(u) => u,
        Err(r) => return r,
    };

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

    if req.stream {
        handle_stream(state, body, request_id, prompt_tokens).await
    } else {
        handle_non_stream(state, body, request_id, prompt_tokens).await
    }
}

async fn handle_non_stream(
    state: Arc<AppState>,
    body: Bytes,
    request_id: String,
    prompt_tokens: u32,
) -> Response {
    let start = std::time::Instant::now();
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

    (StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY), resp_body).into_response()
}

async fn handle_stream(
    state: Arc<AppState>,
    body: Bytes,
    request_id: String,
    prompt_tokens: u32,
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
    tokio::spawn(async move {
        // brief yield so the response headers flush first; event is
        // best-effort at debug level anyway
        tokio::time::sleep(std::time::Duration::from_millis(0)).await;
        metering_event(&request_id, "completed", prompt_tokens, completion, start);
    });

    resp
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
