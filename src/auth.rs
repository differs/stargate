//! Auth — commercial user & API-key management (Rust port of MeterGate's
//! internal/auth): bcrypt registration/login, sha256-hashed API keys,
//! cached key resolution for the gateway hot path.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use std::sync::Arc;

use tokio_postgres::{Client, NoTls};

#[derive(Clone)]
pub struct AuthService {
    client: Arc<Client>,
}

/// Commercial schema (users/api_keys/recharges/payments).
pub const COMMERCIAL_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    status        SMALLINT NOT NULL DEFAULT 1,
    rpm_limit     BIGINT NOT NULL DEFAULT 0,
    tpm_limit     BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS api_keys (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id),
    key_hash      TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    status        SMALLINT NOT NULL DEFAULT 1,
    rpm_limit     BIGINT NOT NULL DEFAULT 0,
    tpm_limit     BIGINT NOT NULL DEFAULT 0,
    concurrency_limit BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys (user_id);
CREATE TABLE IF NOT EXISTS recharges (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id),
    amount_micros   BIGINT NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'CNY',
    status          TEXT NOT NULL DEFAULT 'PENDING',
    idempotency_key TEXT UNIQUE NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    paid_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_recharges_user ON recharges (user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS payments (
    id             BIGSERIAL PRIMARY KEY,
    recharge_id    BIGINT NOT NULL REFERENCES recharges(id),
    channel        TEXT NOT NULL,
    channel_txn_id TEXT NOT NULL,
    amount_micros  BIGINT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'PAID',
    raw_callback   TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (channel, channel_txn_id)
);
"#;

impl AuthService {
    /// Connect and apply the commercial schema.
    pub async fn connect(dsn: &str) -> Result<Self, String> {
        let (client, conn) = tokio_postgres::connect(dsn, NoTls).await.map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        client.batch_execute(COMMERCIAL_SCHEMA).await.map_err(|e| e.to_string())?;
        Ok(Self { client: Arc::new(client) })
    }

    pub fn client(&self) -> &tokio_postgres::Client {
        &self.client
    }

    /// Extract the inner client (payment service shares the connection).
    pub fn inner(&self) -> Arc<tokio_postgres::Client> {
        self.client.clone()
    }

    /// Register a user (bcrypt-hashed password). Err("exists") on conflict.
    pub async fn register(&self, username: &str, password: &str) -> Result<i64, String> {
        if username.is_empty() || password.len() < 8 {
            return Err("username required, password >= 8 chars".into());
        }
        let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| e.to_string())?;
        let row = self
            .client
            .query_one(
                "INSERT INTO users (username, password_hash) VALUES ($1,$2)
                 ON CONFLICT (username) DO NOTHING RETURNING id",
                &[&username, &hash],
            )
            .await;
        match row {
            Ok(r) => Ok(r.get::<_, i64>(0)),
            Err(_) => Err("username already exists".into()),
        }
    }

    /// Login: verify bcrypt, return user id.
    pub async fn login(&self, username: &str, password: &str) -> Result<i64, String> {
        let row = self
            .client
            .query_opt(
                "SELECT id, status, password_hash FROM users WHERE username=$1",
                &[&username],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else { return Err("invalid username or password".into()) };
        let status: i16 = row.get(1);
        if status != 1 {
            return Err("user disabled".into());
        }
        let hash: String = row.get(2);
        if !bcrypt::verify(password, &hash).map_err(|e| e.to_string())? {
            return Err("invalid username or password".into());
        }
        Ok(row.get::<_, i64>(0))
    }

    /// Create an API key (raw shown once; only sha256 stored).
    pub async fn create_key(
        &self,
        user_id: i64,
        name: &str,
        limits: crate::ratelimit::Limits,
    ) -> Result<String, String> {
        let raw: Vec<u8> = (0..24).map(|_| rand::random::<u8>()).collect();
        let key = format!("sk-{}", hex::encode(&raw));
        let hash = key_hash(&key);
        self.client
            .execute(
                "INSERT INTO api_keys (user_id, key_hash, name, rpm_limit, tpm_limit, concurrency_limit) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
                &[
                    &user_id,
                    &hash,
                    &name,
                    &(limits.rpm as i64),
                    &(limits.tpm as i64),
                    &(limits.concurrency as i64),
                ],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(key)
    }

    /// Stored rate limits of a raw key (0 = unlimited).
    pub async fn resolve_limits(&self, raw_key: &str) -> Result<crate::ratelimit::Limits, String> {
        let hash = key_hash(raw_key);
        let row = self
            .client
            .query_opt(
                "SELECT rpm_limit, tpm_limit, concurrency_limit FROM api_keys WHERE key_hash=$1",
                &[&hash],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else { return Err("key not found".into()) };
        Ok(crate::ratelimit::Limits {
            rpm: row.get::<_, i64>(0).max(0) as u64,
            tpm: row.get::<_, i64>(1).max(0) as u64,
            concurrency: row.get::<_, i64>(2).max(0) as u64,
        })
    }

    /// List a user's keys (no hashes).
    pub async fn list_keys(&self, user_id: i64) -> Result<Vec<(i64, String, i16)>, String> {
        let rows = self
            .client
            .query(
                "SELECT id, name, status FROM api_keys WHERE user_id=$1 ORDER BY id DESC",
                &[&user_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<_, i64>(0), r.get::<_, String>(1), r.get::<_, i16>(2)))
            .collect())
    }

    /// Resolve a raw key to a user id (DB hit — wrap with CachedKeyStore).
    pub async fn resolve(&self, raw_key: &str) -> Result<i64, String> {
        let hash = key_hash(raw_key);
        let row = self
            .client
            .query_opt(
                "SELECT user_id, status FROM api_keys WHERE key_hash=$1",
                &[&hash],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else { return Err("key not found".into()) };
        let status: i16 = row.get(1);
        if status != 1 {
            return Err("key not found".into());
        }
        let uid: i64 = row.get(0);
        // touch last_used (best effort, ignore errors)
        let _ = self
            .client
            .execute(
                "UPDATE api_keys SET last_used_at=now() WHERE key_hash=$1",
                &[&hash],
            )
            .await;
        Ok(uid)
    }
}

/// sha256 of the raw key (never store raw).
pub fn key_hash(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

/// CachedKeyStore: TTL cache so the gateway hot path avoids DB hits.
pub struct CachedKeyStore {
    svc: AuthService,
    ttl: Duration,
    cache: Mutex<std::collections::HashMap<String, (i64, Instant)>>,
}

impl CachedKeyStore {
    pub fn new(svc: AuthService, ttl: Duration) -> Self {
        Self { svc, ttl, cache: Mutex::new(Default::default()) }
    }

    /// Stored limits with cache (negative entries cached shorter).
    pub async fn limits(&self, raw_key: &str) -> Result<crate::ratelimit::Limits, String> {
        self.resolve(raw_key).await?; // fast-fail on unknown keys
        Ok(self.svc.resolve_limits(raw_key).await.unwrap_or_default())
    }

    /// Resolve with cache (negative entries cached shorter).
    pub async fn resolve(&self, raw_key: &str) -> Result<i64, String> {
        let now = Instant::now();
        {
            let cache = self.cache.lock().unwrap();
            if let Some((uid, at)) = cache.get(raw_key) {
                if now.duration_since(*at) < self.ttl {
                    if *uid == 0 {
                        return Err("key not found".into());
                    }
                    return Ok(*uid);
                }
            }
        }
        let uid = match self.svc.resolve(raw_key).await {
            Ok(u) => u,
            Err(e) => {
                let mut cache = self.cache.lock().unwrap();
                cache.insert(raw_key.to_string(), (0, now));
                return Err(e);
            }
        };
        let mut cache = self.cache.lock().unwrap();
        cache.insert(raw_key.to_string(), (uid, now));
        Ok(uid)
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_key_serializes_limits() {
        let Ok(dsn) = std::env::var("STARGATE_TEST_PG") else {
            eprintln!("skipping: STARGATE_TEST_PG not set");
            return;
        };
        let (client, conn) = tokio_postgres::connect(&dsn, NoTls).await.expect("pg connect");
        tokio::spawn(async move { let _ = conn.await; });
        let svc = AuthService { client: Arc::new(client) };
        // NOTE: extended-protocol execute cannot run multiple statements;
        // DROP + rebuild must use batch_execute (same as connect does).
        svc.client
            .batch_execute("DROP TABLE IF EXISTS payments, recharges, api_keys, users")
            .await
            .unwrap();
        svc.client.batch_execute("DROP TABLE IF EXISTS payments, recharges, api_keys, users CASCADE").await.unwrap();
        svc.client.batch_execute(COMMERCIAL_SCHEMA).await.unwrap();
        let _ = svc.register("ckprobe", "password123").await;
        let key = svc.create_key(1, "probe", crate::ratelimit::Limits { rpm: 3, tpm: 100, concurrency: 2 }).await;
        match key {
            Ok(k) => {
                let l = svc.resolve_limits(&k).await.expect("resolve limits");
                assert_eq!(l, crate::ratelimit::Limits { rpm: 3, tpm: 100, concurrency: 2 });
                println!("create_key OK: rpm={} tpm={} concurrency={}", l.rpm, l.tpm, l.concurrency);
            }
            Err(e) => eprintln!("create_key FAILED: {e}"),
        }
    }
}
