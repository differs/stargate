//! OpenAI-compatible wire protocol types (minimal subset needed by the
//! gateway hot path: request fields for routing/metering, response usage
//! for cross-validation, SSE chunk for streaming metering).

use serde::{Deserialize, Serialize};

/// Chat completion request — only the fields the gateway reads are
/// deserialized; the raw body is forwarded verbatim to the upstream.
#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct Message {
    pub role: String,
    #[serde(default)]
    pub content: serde_json::Value,
}

/// Upstream usage object (authoritative billing input when present).
#[derive(Debug, Deserialize, Serialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    #[serde(default)]
    pub total_tokens: u32,
}

/// Response envelope used to extract usage from non-stream responses.
#[derive(Debug, Deserialize)]
pub struct ChatResponse {
    #[serde(default)]
    pub usage: Option<Usage>,
}

/// SSE chunk payload of a streaming response.
#[derive(Debug, Deserialize)]
pub struct Chunk {
    #[serde(default)]
    pub choices: Vec<ChunkChoice>,
}

#[derive(Debug, Deserialize)]
pub struct ChunkChoice {
    #[serde(default)]
    pub delta: Delta,
}

#[derive(Debug, Deserialize, Default)]
pub struct Delta {
    #[serde(default)]
    pub content: String,
}

/// Extract the delta content from a raw SSE payload with a targeted byte
/// scan — avoids a full JSON parse per chunk on the streaming hot path
/// (mirrors MeterGate's fastDeltaContent).
pub fn fast_delta_content(data: &[u8]) -> Option<&str> {
    let marker = b"\"content\":\"";
    let idx = memchr(marker, data)?;
    let start = idx + marker.len();
    let end = data[start..].iter().position(|&b| b == b'"')? + start;
    // Only return when no escapes are present (the common case); escaped
    // content falls back to a slow path in the caller via full parse.
    if data[start..end].contains(&b'\\') {
        return None;
    }
    std::str::from_utf8(&data[start..end]).ok()
}

fn memchr(needle: &[u8], haystack: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
