//! Upstream forwarding via reqwest (connection-pooled, keep-alive).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;

/// Connection-pooled upstream client.
#[derive(Clone)]
pub struct UpstreamClient {
    inner: reqwest::Client,
    url: Arc<String>,
    key: Arc<String>,
}

impl UpstreamClient {
    pub fn new(url: String, key: String) -> Self {
        let inner = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(600)) // LLM streams can be long
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(512)
            .build()
            .expect("reqwest client");
        Self {
            inner,
            url: Arc::new(url),
            key: Arc::new(key),
        }
    }

    /// Non-streaming forward: returns the raw response body.
    pub async fn forward(&self, body: Bytes) -> Result<(u16, Bytes), String> {
        let resp = self
            .inner
            .post(self.url.as_str())
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.key.as_str()))
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        Ok((status, bytes))
    }

    /// Expose the upstream URL (used for metering provider attribution).
    pub fn url(&self) -> &str {
        self.url.as_str()
    }

    /// Streaming forward: returns the byte stream of the upstream body.
    pub async fn forward_stream(
        &self,
        body: Bytes,
    ) -> Result<
        (
            u16,
            impl tokio_stream::Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
        ),
        String,
    > {
        let resp = self
            .inner
            .post(self.url.as_str())
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.key.as_str()))
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        Ok((status, resp.bytes_stream()))
    }
}
