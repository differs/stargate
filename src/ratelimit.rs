//! Rate limiting — Redis sliding-window RPM/TPM quotas and in-flight
//! concurrency, enforced on the gateway hot path (Rust port of
//! MeterGate's internal/ratelimit). All counters are atomic Redis Lua
//! sliding windows so multi-instance gateways share the same quotas.
//!
//! This is the first layer of the six-layer budget model: org → team →
//! project → user → key → end-user.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use redis::Script;
use redis::aio::ConnectionManager;

use crate::auth::CachedKeyStore;

/// Per-scope quota (0 = unlimited).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub rpm: u64,
    pub tpm: u64,
    pub concurrency: u64,
    /// Layer 6: per end-user quotas of a key (scoped eu:{key}:{id}).
    pub end_user_rpm: u64,
    pub end_user_tpm: u64,
}

/// Sliding-window length.
const WINDOW_MS: u64 = 60_000;

/// Quota rejection: which layer refused the request and the retry-after.
#[derive(Debug, Clone, Copy)]
pub struct QuotaExceeded {
    pub retry_after: u64,
    pub layer: &'static str, // "key" | "user" (six-layer budget model)
}

/// Sliding-window counter with expiry (same semantics as the Go port):
///
///   KEYS[1] = rl:{scope}:{kind}
///   ARGV[1] = now_ms  ARGV[2] = window_ms  ARGV[3] = limit  ARGV[4] = weight
///
/// returns: -1 = over limit; otherwise the current window count.
const WINDOW_SCRIPT: &str = r#"
local now = tonumber(ARGV[1])
local win = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local weight = tonumber(ARGV[4])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - win)
local count = tonumber(redis.call('ZCARD', KEYS[1]) or '0')
if count + weight > limit then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  local oldest_ts = tonumber(oldest[2]) or now
  local retry = math.floor((oldest_ts + win - now) / 1000) + 1
  return -retry
end
for i = 1, weight do
  redis.call('ZADD', KEYS[1], now, now .. ':' .. redis.call('INCR', KEYS[1] .. ':seq'))
end
redis.call('EXPIRE', KEYS[1], win / 1000 + 1)
return count + weight
"#;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A held in-flight slot: DECRs the Redis counter when dropped, so the
/// release cannot be forgotten (RAII; the DECR itself is fire-and-forget).
pub struct ConcurrencyGuard {
    scope: String,
    redis: Option<ConnectionManager>,
}

impl ConcurrencyGuard {
    fn new(scope: &str, redis: ConnectionManager) -> Self {
        Self {
            scope: scope.to_string(),
            redis: Some(redis),
        }
    }

    /// A no-op guard for the unlimited path.
    fn noop() -> Self {
        Self {
            scope: String::new(),
            redis: None,
        }
    }
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        if let Some(mut redis) = self.redis.take() {
            let key = format!("rl:{}:inflight", self.scope);
            tokio::spawn(async move {
                let _: i64 = redis::cmd("DECRBY")
                    .arg(key)
                    .arg(1)
                    .query_async(&mut redis)
                    .await
                    .unwrap_or(0);
            });
        }
    }
}

/// Atomic counter checks against one Redis.
#[derive(Clone)]
pub struct Checker {
    redis: ConnectionManager,
}

impl Checker {
    /// Connect to `addr` (host:port, no scheme).
    pub async fn connect(addr: &str) -> Result<Self, String> {
        let client = redis::Client::open(format!("redis://{addr}")).map_err(|e| e.to_string())?;
        let mgr = ConnectionManager::new(client)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self { redis: mgr })
    }

    /// Record one request; Err(retry_after) when over the RPM limit.
    pub async fn check_rpm(&self, scope: &str, limit: u64) -> Result<(), u64> {
        if limit == 0 {
            return Ok(());
        }
        self.window(scope, "rpm", limit, 1).await
    }

    /// Record `tokens`; Err(retry_after) when over the TPM limit.
    pub async fn check_tpm(&self, scope: &str, limit: u64, tokens: u64) -> Result<(), u64> {
        if limit == 0 || tokens == 0 {
            return Ok(());
        }
        self.window(scope, "tpm", limit, tokens).await
    }

    /// Take one in-flight slot (concurrency). None when over the limit.
    pub async fn acquire(&self, scope: &str, limit: u64) -> Option<ConcurrencyGuard> {
        if limit == 0 {
            return Some(ConcurrencyGuard::noop());
        }
        let key = format!("rl:{scope}:inflight");
        let mut redis = self.redis.clone();
        // The key must always carry a TTL so a crashed gateway doesn't
        // leak the counter forever (renew on every acquire).
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut redis)
            .await
            .unwrap_or(-1);
        if ttl < 0 {
            let _ = redis::cmd("EXPIRE")
                .arg(&key)
                .arg((WINDOW_MS / 1000) * 2)
                .query_async::<i64>(&mut redis)
                .await;
        }
        let cur: i64 = redis::cmd("INCRBY")
            .arg(&key)
            .arg(1)
            .query_async(&mut redis)
            .await
            .unwrap_or(0);
        if cur > limit as i64 {
            let _: i64 = redis::cmd("DECRBY")
                .arg(&key)
                .arg(1)
                .query_async(&mut redis)
                .await
                .unwrap_or(0);
            return None;
        }
        Some(ConcurrencyGuard::new(scope, redis))
    }

    async fn window(&self, scope: &str, kind: &str, limit: u64, weight: u64) -> Result<(), u64> {
        let mut redis = self.redis.clone();
        let res: i64 = Script::new(WINDOW_SCRIPT)
            .key(format!("rl:{scope}:{kind}"))
            .arg(now_ms())
            .arg(WINDOW_MS)
            .arg(limit)
            .arg(weight)
            .invoke_async(&mut redis)
            .await
            .unwrap_or(-1);
        if res < 0 {
            // |res| = precise retry-after until the oldest entry slides out.
            Err((-res) as u64)
        } else {
            Ok(())
        }
    }
}

/// KeyLimiter enforces per-key limits from the stored key config; the
/// user-level aggregation layer (all keys of a user share a budget) is
/// the next layer of the six-layer model.
pub struct KeyLimiter {
    check: Checker,
    keys: Arc<CachedKeyStore>,
}

impl KeyLimiter {
    pub fn new(check: Checker, keys: Arc<CachedKeyStore>) -> Self {
        Self { check, keys }
    }

    /// Check the key layer (RPM → TPM → concurrency) then the user
    /// aggregate layer (RPM → TPM, scope `user-{id}`, shared by all keys
    /// of a user).
    /// Ok(Some(guard)) = hold the guard until the request finishes;
    /// Ok(None) = unlimited or no concurrency slot needed;
    /// Err(QuotaExceeded) = over a limit (layer + retry-after).
    /// Check the key layer (RPM → TPM → concurrency) then the aggregate
    /// chain: user → project → team → org, plus the per end-user layer.
    /// Ok(Some(guard)) = hold the guard until the request finishes;
    /// Ok(None) = unlimited or no concurrency slot needed;
    /// Err(QuotaExceeded) = over a limit (layer + retry-after).
    pub async fn check(
        &self,
        raw_key: &str,
        prompt_tokens: u32,
        end_user_id: &str,
    ) -> Result<Option<ConcurrencyGuard>, QuotaExceeded> {
        let layer = |r: u64| QuotaExceeded {
            retry_after: r,
            layer: "key",
        };

        // --- Layer 6: per end-user limits of this key (only when the
        // request carries X-End-User and the key has end-user quotas) ---
        let limits = self.keys.limits(raw_key).await.ok().unwrap_or_default();
        if !end_user_id.is_empty() && (limits.end_user_rpm > 0 || limits.end_user_tpm > 0) {
            let eu_layer = |r: u64| QuotaExceeded {
                retry_after: r,
                layer: "end_user",
            };
            let eu_scope = format!("eu:{raw_key}:{end_user_id}");
            if limits.end_user_rpm > 0 {
                self.check
                    .check_rpm(&eu_scope, limits.end_user_rpm)
                    .await
                    .map_err(eu_layer)?;
            }
            if limits.end_user_tpm > 0 {
                self.check
                    .check_tpm(&eu_scope, limits.end_user_tpm, prompt_tokens as u64 + 1000)
                    .await
                    .map_err(eu_layer)?;
            }
        }

        // --- Layer 1: per-key limits (cached) ---
        if limits.rpm > 0 {
            self.check
                .check_rpm(raw_key, limits.rpm)
                .await
                .map_err(layer)?;
        }
        if limits.tpm > 0 {
            // Estimate completion tokens (capped) — same policy as Go.
            self.check
                .check_tpm(raw_key, limits.tpm, prompt_tokens as u64 + 1000)
                .await
                .map_err(layer)?;
        }
        if limits.concurrency > 0 {
            match self.check.acquire(raw_key, limits.concurrency).await {
                Some(g) => return Ok(Some(g)),
                None => {
                    return Err(QuotaExceeded {
                        retry_after: 0,
                        layer: "key",
                    });
                }
            }
        }

        // --- Layers 2-5: user → project → team → org aggregate budgets ---
        if let Ok(uid) = self.keys.resolve(raw_key).await {
            let user_layer = |r: u64| QuotaExceeded {
                retry_after: r,
                layer: "user",
            };
            if let Ok(ul) = self.keys.user_limits(uid).await {
                if ul.rpm > 0 || ul.tpm > 0 {
                    let scope = format!("user-{uid}");
                    if ul.rpm > 0 {
                        self.check
                            .check_rpm(&scope, ul.rpm)
                            .await
                            .map_err(user_layer)?;
                    }
                    if ul.tpm > 0 {
                        self.check
                            .check_tpm(&scope, ul.tpm, prompt_tokens as u64 + 1000)
                            .await
                            .map_err(user_layer)?;
                    }
                }
            }

            if let Ok(pid) = self.keys.project_of_user(uid).await {
                if pid > 0 {
                    let project_layer = |r: u64| QuotaExceeded {
                        retry_after: r,
                        layer: "project",
                    };
                    if let Ok(pl) = self.keys.project_limits(pid).await {
                        if pl.rpm > 0 || pl.tpm > 0 {
                            let scope = format!("project-{pid}");
                            if pl.rpm > 0 {
                                self.check
                                    .check_rpm(&scope, pl.rpm)
                                    .await
                                    .map_err(project_layer)?;
                            }
                            if pl.tpm > 0 {
                                self.check
                                    .check_tpm(&scope, pl.tpm, prompt_tokens as u64 + 1000)
                                    .await
                                    .map_err(project_layer)?;
                            }
                        }
                    }

                    // --- Layer 4: team (project belongs to a team) ---
                    if let Ok(tid) = self.keys.team_of_project(pid).await {
                        if tid > 0 {
                            let team_layer = |r: u64| QuotaExceeded {
                                retry_after: r,
                                layer: "team",
                            };
                            if let Ok(tl) = self.keys.team_limits(tid).await {
                                if tl.rpm > 0 || tl.tpm > 0 {
                                    let scope = format!("team-{tid}");
                                    if tl.rpm > 0 {
                                        self.check
                                            .check_rpm(&scope, tl.rpm)
                                            .await
                                            .map_err(team_layer)?;
                                    }
                                    if tl.tpm > 0 {
                                        self.check
                                            .check_tpm(&scope, tl.tpm, prompt_tokens as u64 + 1000)
                                            .await
                                            .map_err(team_layer)?;
                                    }
                                }
                            }

                            // --- Layer 5: org (team belongs to an org) ---
                            if let Ok(oid) = self.keys.org_of_team(tid).await {
                                if oid > 0 {
                                    let org_layer = |r: u64| QuotaExceeded {
                                        retry_after: r,
                                        layer: "org",
                                    };
                                    if let Ok(ol) = self.keys.org_limits(oid).await {
                                        if ol.rpm > 0 || ol.tpm > 0 {
                                            let scope = format!("org-{oid}");
                                            if ol.rpm > 0 {
                                                self.check
                                                    .check_rpm(&scope, ol.rpm)
                                                    .await
                                                    .map_err(org_layer)?;
                                            }
                                            if ol.tpm > 0 {
                                                self.check
                                                    .check_tpm(
                                                        &scope,
                                                        ol.tpm,
                                                        prompt_tokens as u64 + 1000,
                                                    )
                                                    .await
                                                    .map_err(org_layer)?;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}
impl crate::gateway::RateLimiter for KeyLimiter {
    fn allow<'a>(
        &'a self,
        raw_key: &'a str,
        prompt_tokens: u32,
        end_user_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<ConcurrencyGuard>, QuotaExceeded>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move { self.check(raw_key, prompt_tokens, end_user_id).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration tests need a real Redis. Set STARGATE_TEST_REDIS
    /// (e.g. redis://127.0.0.1:6379); tests skip silently otherwise.
    async fn checker() -> Option<Checker> {
        match std::env::var("STARGATE_TEST_REDIS") {
            Ok(url) => {
                let addr = url.strip_prefix("redis://").unwrap_or(&url).to_string();
                Checker::connect(&addr).await.ok()
            }
            Err(_) => None,
        }
    }

    #[tokio::test]
    async fn rpm_enforced() {
        let Some(c) = checker().await else {
            eprintln!("skipping: STARGATE_TEST_REDIS not set");
            return;
        };
        let scope = format!("t-{}", std::process::id());
        for _ in 0..3 {
            assert!(c.check_rpm(&scope, 3).await.is_ok());
        }
        assert!(
            c.check_rpm(&scope, 3).await.is_err(),
            "4th request over RPM=3"
        );
        // other scope unaffected
        assert!(c.check_rpm("other", 3).await.is_ok());
    }

    #[tokio::test]
    async fn tpm_enforced() {
        let Some(c) = checker().await else {
            eprintln!("skipping: STARGATE_TEST_REDIS not set");
            return;
        };
        let scope = format!("t-{}", std::process::id());
        assert!(c.check_tpm(&scope, 100, 60).await.is_ok());
        assert!(c.check_tpm(&scope, 100, 60).await.is_err(), "60+60 > 100");
    }

    #[tokio::test]
    async fn concurrency_enforced() {
        let Some(c) = checker().await else {
            eprintln!("skipping: STARGATE_TEST_REDIS not set");
            return;
        };
        let scope = format!("t-{}", std::process::id());
        let g1 = c.acquire(&scope, 2).await;
        let g2 = c.acquire(&scope, 2).await;
        assert!(g1.is_some() && g2.is_some());
        assert!(
            c.acquire(&scope, 2).await.is_none(),
            "3rd in-flight rejected"
        );
        drop(g1);
        drop(g2);
        // give the fire-and-forget DECR a moment
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            c.acquire(&scope, 2).await.is_some(),
            "slot freed after drop"
        );
    }

    #[tokio::test]
    async fn unlimited_passes() {
        let Some(c) = checker().await else {
            eprintln!("skipping: STARGATE_TEST_REDIS not set");
            return;
        };
        let scope = format!("t-{}", std::process::id());
        for _ in 0..10 {
            assert!(c.check_rpm(&scope, 0).await.is_ok());
        }
        assert!(c.acquire(&scope, 0).await.is_some());
    }
}
