//! Streaming token metering — same semantics as MeterGate's Go version:
//! approximate estimator (CJK-aware), incrementally accumulates completion
//! tokens from SSE deltas. Exact billing prefers upstream usage; the local
//! count is used for cross-validation and abort fallback.

use std::sync::atomic::{AtomicU32, Ordering};

/// Approximate token estimator:
///   - ASCII: ~4 chars per token (cl100k English behavior)
///   - wide (CJK etc.): ~1.5 chars per token
pub fn count_text(s: &str) -> u32 {
    let mut ascii = 0u32;
    let mut wide = 0u32;
    for c in s.chars() {
        if (c as u32) < 0x80 {
            ascii += 1;
        } else {
            wide += 1;
        }
    }
    if ascii == 0 && wide == 0 {
        return 0;
    }
    ascii / 4 + wide * 2 / 3 + 1
}

/// Estimate prompt tokens from request messages (role overhead per message).
pub fn estimate_prompt_tokens(messages: &[crate::openai::Message]) -> u32 {
    let mut total = 0u32;
    for m in messages {
        total += 4; // role overhead
        match &m.content {
            serde_json::Value::String(s) => total += count_text(s),
            serde_json::Value::Array(parts) => {
                for part in parts {
                    if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                        total += count_text(text);
                    }
                }
            }
            _ => {}
        }
    }
    total
}

/// Snapshot of metering state.
#[derive(Debug, Clone, Copy, Default)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

impl Usage {
    pub fn total(&self) -> u32 {
        self.prompt_tokens + self.completion_tokens
    }
}

/// Thread-safe accumulator for a streaming response.
#[derive(Debug, Default)]
pub struct Accumulator {
    completion: AtomicU32,
}

impl Accumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one streamed content fragment.
    pub fn add_delta(&self, content: &str) {
        if !content.is_empty() {
            self.completion
                .fetch_add(count_text(content), Ordering::Relaxed);
        }
    }

    /// Current completion token count.
    pub fn completion(&self) -> u32 {
        self.completion.load(Ordering::Relaxed)
    }
}
