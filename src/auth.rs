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
CREATE TABLE IF NOT EXISTS orgs (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    rpm_limit  BIGINT NOT NULL DEFAULT 0,
    tpm_limit  BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS teams (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    org_id     BIGINT REFERENCES orgs(id),
    rpm_limit  BIGINT NOT NULL DEFAULT 0,
    tpm_limit  BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_teams_org ON teams (org_id);
CREATE TABLE IF NOT EXISTS projects (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    team_id    BIGINT REFERENCES teams(id),
    rpm_limit  BIGINT NOT NULL DEFAULT 0,
    tpm_limit  BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE projects ADD COLUMN IF NOT EXISTS team_id BIGINT REFERENCES teams(id);
CREATE INDEX IF NOT EXISTS idx_projects_team ON projects (team_id);
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    status        SMALLINT NOT NULL DEFAULT 1,
    rpm_limit     BIGINT NOT NULL DEFAULT 0,
    tpm_limit     BIGINT NOT NULL DEFAULT 0,
    project_id    BIGINT REFERENCES projects(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS project_id BIGINT REFERENCES projects(id);
CREATE TABLE IF NOT EXISTS api_keys (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id),
    key_hash      TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    status        SMALLINT NOT NULL DEFAULT 1,
    rpm_limit     BIGINT NOT NULL DEFAULT 0,
    tpm_limit     BIGINT NOT NULL DEFAULT 0,
    concurrency_limit BIGINT NOT NULL DEFAULT 0,
    end_user_rpm_limit BIGINT NOT NULL DEFAULT 0,
    end_user_tpm_limit BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS end_user_rpm_limit BIGINT NOT NULL DEFAULT 0;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS end_user_tpm_limit BIGINT NOT NULL DEFAULT 0;
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
        let (client, conn) = tokio_postgres::connect(dsn, NoTls)
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        client
            .batch_execute(COMMERCIAL_SCHEMA)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self {
            client: Arc::new(client),
        })
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
        let Some(row) = row else {
            return Err("invalid username or password".into());
        };
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
                "INSERT INTO api_keys (user_id, key_hash, name, rpm_limit, tpm_limit, concurrency_limit, end_user_rpm_limit, end_user_tpm_limit) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
                &[
                    &user_id,
                    &hash,
                    &name,
                    &(limits.rpm as i64),
                    &(limits.tpm as i64),
                    &(limits.concurrency as i64),
                    &(limits.end_user_rpm as i64),
                    &(limits.end_user_tpm as i64),
                ],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(key)
    }

    /// User-level aggregate quota (0 = unlimited) — layer 2 of the
    /// six-layer budget model: all keys of a user share this budget.
    pub async fn resolve_user_limits(
        &self,
        user_id: i64,
    ) -> Result<crate::ratelimit::Limits, String> {
        let row = self
            .client
            .query_opt(
                "SELECT rpm_limit, tpm_limit FROM users WHERE id=$1",
                &[&user_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Err("user not found".into());
        };
        Ok(crate::ratelimit::Limits {
            rpm: row.get::<_, i64>(0).max(0) as u64,
            tpm: row.get::<_, i64>(1).max(0) as u64,
            concurrency: 0,
            ..Default::default()
        })
    }

    /// Update a user's aggregate quota (admin operation).
    pub async fn set_user_limits(&self, user_id: i64, rpm: u64, tpm: u64) -> Result<(), String> {
        self.client
            .execute(
                "UPDATE users SET rpm_limit=$2, tpm_limit=$3 WHERE id=$1",
                &[&user_id, &(rpm as i64), &(tpm as i64)],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Layer 3: project aggregate quota (0 = unlimited).
    pub async fn resolve_project_limits(
        &self,
        project_id: i64,
    ) -> Result<crate::ratelimit::Limits, String> {
        let row = self
            .client
            .query_opt(
                "SELECT rpm_limit, tpm_limit FROM projects WHERE id=$1",
                &[&project_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Err("project not found".into());
        };
        Ok(crate::ratelimit::Limits {
            rpm: row.get::<_, i64>(0).max(0) as u64,
            tpm: row.get::<_, i64>(1).max(0) as u64,
            concurrency: 0,
            ..Default::default()
        })
    }

    /// Update a project's aggregate quota (admin operation).
    pub async fn set_project_limits(
        &self,
        project_id: i64,
        rpm: u64,
        tpm: u64,
    ) -> Result<(), String> {
        self.client
            .execute(
                "UPDATE projects SET rpm_limit=$2, tpm_limit=$3 WHERE id=$1",
                &[&project_id, &(rpm as i64), &(tpm as i64)],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Create a project with an aggregate quota; returns its id.
    pub async fn create_project(&self, name: &str, rpm: u64, tpm: u64) -> Result<i64, String> {
        let row = self
            .client
            .query_one(
                "INSERT INTO projects (name, rpm_limit, tpm_limit) VALUES ($1,$2,$3) RETURNING id",
                &[&name, &(rpm as i64), &(tpm as i64)],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.get(0))
    }

    /// Assign a user to a project (shares its budget).
    pub async fn set_user_project(&self, user_id: i64, project_id: i64) -> Result<(), String> {
        self.client
            .execute(
                "UPDATE users SET project_id=$2 WHERE id=$1",
                &[&user_id, &project_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// The project a user belongs to (0 = none).
    pub async fn project_of_user(&self, user_id: i64) -> Result<i64, String> {
        let row = self
            .client
            .query_opt(
                "SELECT COALESCE(project_id, 0) FROM users WHERE id=$1",
                &[&user_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Err("user not found".into());
        };
        Ok(row.get(0))
    }

    /// Layer 5: org aggregate quota (0 = unlimited).
    pub async fn resolve_org_limits(
        &self,
        org_id: i64,
    ) -> Result<crate::ratelimit::Limits, String> {
        let row = self
            .client
            .query_opt(
                "SELECT rpm_limit, tpm_limit FROM orgs WHERE id=$1",
                &[&org_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Err("org not found".into());
        };
        Ok(crate::ratelimit::Limits {
            rpm: row.get::<_, i64>(0).max(0) as u64,
            tpm: row.get::<_, i64>(1).max(0) as u64,
            concurrency: 0,
            ..Default::default()
        })
    }

    /// Update an org's aggregate quota (admin operation).
    pub async fn set_org_limits(&self, org_id: i64, rpm: u64, tpm: u64) -> Result<(), String> {
        self.client
            .execute(
                "UPDATE orgs SET rpm_limit=$2, tpm_limit=$3 WHERE id=$1",
                &[&org_id, &(rpm as i64), &(tpm as i64)],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Create an org with an aggregate quota; returns its id.
    pub async fn create_org(&self, name: &str, rpm: u64, tpm: u64) -> Result<i64, String> {
        let row = self
            .client
            .query_one(
                "INSERT INTO orgs (name, rpm_limit, tpm_limit) VALUES ($1,$2,$3) RETURNING id",
                &[&name, &(rpm as i64), &(tpm as i64)],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.get(0))
    }

    /// Layer 4: team aggregate quota (0 = unlimited).
    pub async fn resolve_team_limits(
        &self,
        team_id: i64,
    ) -> Result<crate::ratelimit::Limits, String> {
        let row = self
            .client
            .query_opt(
                "SELECT rpm_limit, tpm_limit FROM teams WHERE id=$1",
                &[&team_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Err("team not found".into());
        };
        Ok(crate::ratelimit::Limits {
            rpm: row.get::<_, i64>(0).max(0) as u64,
            tpm: row.get::<_, i64>(1).max(0) as u64,
            concurrency: 0,
            ..Default::default()
        })
    }

    /// Update a team's aggregate quota (admin operation).
    pub async fn set_team_limits(&self, team_id: i64, rpm: u64, tpm: u64) -> Result<(), String> {
        self.client
            .execute(
                "UPDATE teams SET rpm_limit=$2, tpm_limit=$3 WHERE id=$1",
                &[&team_id, &(rpm as i64), &(tpm as i64)],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Create a team inside an org; returns its id.
    pub async fn create_team(
        &self,
        name: &str,
        org_id: i64,
        rpm: u64,
        tpm: u64,
    ) -> Result<i64, String> {
        let row = self
            .client
            .query_one(
                "INSERT INTO teams (name, org_id, rpm_limit, tpm_limit) VALUES ($1,$2,$3,$4) RETURNING id",
                &[&name, &org_id, &(rpm as i64), &(tpm as i64)],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.get(0))
    }

    /// Attach a project to a team (shares the team budget).
    pub async fn set_project_team(&self, project_id: i64, team_id: i64) -> Result<(), String> {
        self.client
            .execute(
                "UPDATE projects SET team_id=$2 WHERE id=$1",
                &[&project_id, &team_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// The team a project belongs to (0 = none).
    pub async fn team_of_project(&self, project_id: i64) -> Result<i64, String> {
        let row = self
            .client
            .query_opt(
                "SELECT COALESCE(team_id, 0) FROM projects WHERE id=$1",
                &[&project_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Err("project not found".into());
        };
        Ok(row.get(0))
    }

    /// The org a team belongs to (0 = none).
    pub async fn org_of_team(&self, team_id: i64) -> Result<i64, String> {
        let row = self
            .client
            .query_opt(
                "SELECT COALESCE(org_id, 0) FROM teams WHERE id=$1",
                &[&team_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Err("team not found".into());
        };
        Ok(row.get(0))
    }

    /// Stored rate limits of a raw key (0 = unlimited).
    pub async fn resolve_limits(&self, raw_key: &str) -> Result<crate::ratelimit::Limits, String> {
        let hash = key_hash(raw_key);
        let row = self
            .client
            .query_opt(
                "SELECT rpm_limit, tpm_limit, concurrency_limit, end_user_rpm_limit, end_user_tpm_limit FROM api_keys WHERE key_hash=$1",
                &[&hash],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Err("key not found".into());
        };
        Ok(crate::ratelimit::Limits {
            rpm: row.get::<_, i64>(0).max(0) as u64,
            tpm: row.get::<_, i64>(1).max(0) as u64,
            concurrency: row.get::<_, i64>(2).max(0) as u64,
            end_user_rpm: row.get::<_, i64>(3).max(0) as u64,
            end_user_tpm: row.get::<_, i64>(4).max(0) as u64,
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
            .map(|r| {
                (
                    r.get::<_, i64>(0),
                    r.get::<_, String>(1),
                    r.get::<_, i16>(2),
                )
            })
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
        let Some(row) = row else {
            return Err("key not found".into());
        };
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
    limits_cache: Mutex<std::collections::HashMap<String, (crate::ratelimit::Limits, Instant)>>,
    user_limits_cache: Mutex<std::collections::HashMap<i64, (crate::ratelimit::Limits, Instant)>>,
    project_of_user_cache: Mutex<std::collections::HashMap<i64, (i64, Instant)>>,
    project_limits_cache:
        Mutex<std::collections::HashMap<i64, (crate::ratelimit::Limits, Instant)>>,
    team_of_project_cache: Mutex<std::collections::HashMap<i64, (i64, Instant)>>,
    team_limits_cache: Mutex<std::collections::HashMap<i64, (crate::ratelimit::Limits, Instant)>>,
    org_of_team_cache: Mutex<std::collections::HashMap<i64, (i64, Instant)>>,
    org_limits_cache: Mutex<std::collections::HashMap<i64, (crate::ratelimit::Limits, Instant)>>,
}

impl CachedKeyStore {
    pub fn new(svc: AuthService, ttl: Duration) -> Self {
        Self {
            svc,
            ttl,
            cache: Mutex::new(Default::default()),
            limits_cache: Mutex::new(Default::default()),
            user_limits_cache: Mutex::new(Default::default()),
            project_of_user_cache: Mutex::new(Default::default()),
            project_limits_cache: Mutex::new(Default::default()),
            team_of_project_cache: Mutex::new(Default::default()),
            team_limits_cache: Mutex::new(Default::default()),
            org_of_team_cache: Mutex::new(Default::default()),
            org_limits_cache: Mutex::new(Default::default()),
        }
    }

    /// Stored limits with cache (unknown keys fast-fail via resolve).
    pub async fn limits(&self, raw_key: &str) -> Result<crate::ratelimit::Limits, String> {
        self.resolve(raw_key).await?; // fast-fail on unknown keys
        let now = Instant::now();
        {
            let cache = self.limits_cache.lock().unwrap();
            if let Some((l, at)) = cache.get(raw_key) {
                if now.duration_since(*at) < self.ttl {
                    return Ok(*l);
                }
            }
        }
        let l = self.svc.resolve_limits(raw_key).await?;
        self.limits_cache
            .lock()
            .unwrap()
            .insert(raw_key.to_string(), (l, now));
        Ok(l)
    }

    /// User-level aggregate quota with cache.
    pub async fn user_limits(&self, user_id: i64) -> Result<crate::ratelimit::Limits, String> {
        let now = Instant::now();
        {
            let cache = self.user_limits_cache.lock().unwrap();
            if let Some((l, at)) = cache.get(&user_id) {
                if now.duration_since(*at) < self.ttl {
                    return Ok(*l);
                }
            }
        }
        let l = self.svc.resolve_user_limits(user_id).await?;
        self.user_limits_cache
            .lock()
            .unwrap()
            .insert(user_id, (l, now));
        Ok(l)
    }

    /// Project membership with cache (0 = none).
    pub async fn project_of_user(&self, user_id: i64) -> Result<i64, String> {
        let now = Instant::now();
        {
            let cache = self.project_of_user_cache.lock().unwrap();
            if let Some((pid, at)) = cache.get(&user_id) {
                if now.duration_since(*at) < self.ttl {
                    return Ok(*pid);
                }
            }
        }
        let pid = self.svc.project_of_user(user_id).await?;
        self.project_of_user_cache
            .lock()
            .unwrap()
            .insert(user_id, (pid, now));
        Ok(pid)
    }

    /// Project-level aggregate quota with cache.
    pub async fn project_limits(
        &self,
        project_id: i64,
    ) -> Result<crate::ratelimit::Limits, String> {
        let now = Instant::now();
        {
            let cache = self.project_limits_cache.lock().unwrap();
            if let Some((l, at)) = cache.get(&project_id) {
                if now.duration_since(*at) < self.ttl {
                    return Ok(*l);
                }
            }
        }
        let l = self.svc.resolve_project_limits(project_id).await?;
        self.project_limits_cache
            .lock()
            .unwrap()
            .insert(project_id, (l, now));
        Ok(l)
    }

    /// Team membership of a project with cache (0 = none).
    pub async fn team_of_project(&self, project_id: i64) -> Result<i64, String> {
        let now = Instant::now();
        {
            let cache = self.team_of_project_cache.lock().unwrap();
            if let Some((tid, at)) = cache.get(&project_id) {
                if now.duration_since(*at) < self.ttl {
                    return Ok(*tid);
                }
            }
        }
        let tid = self.svc.team_of_project(project_id).await?;
        self.team_of_project_cache
            .lock()
            .unwrap()
            .insert(project_id, (tid, now));
        Ok(tid)
    }

    /// Team-level aggregate quota with cache.
    pub async fn team_limits(&self, team_id: i64) -> Result<crate::ratelimit::Limits, String> {
        let now = Instant::now();
        {
            let cache = self.team_limits_cache.lock().unwrap();
            if let Some((l, at)) = cache.get(&team_id) {
                if now.duration_since(*at) < self.ttl {
                    return Ok(*l);
                }
            }
        }
        let l = self.svc.resolve_team_limits(team_id).await?;
        self.team_limits_cache
            .lock()
            .unwrap()
            .insert(team_id, (l, now));
        Ok(l)
    }

    /// Org membership of a team with cache (0 = none).
    pub async fn org_of_team(&self, team_id: i64) -> Result<i64, String> {
        let now = Instant::now();
        {
            let cache = self.org_of_team_cache.lock().unwrap();
            if let Some((oid, at)) = cache.get(&team_id) {
                if now.duration_since(*at) < self.ttl {
                    return Ok(*oid);
                }
            }
        }
        let oid = self.svc.org_of_team(team_id).await?;
        self.org_of_team_cache
            .lock()
            .unwrap()
            .insert(team_id, (oid, now));
        Ok(oid)
    }

    /// Org-level aggregate quota with cache.
    pub async fn org_limits(&self, org_id: i64) -> Result<crate::ratelimit::Limits, String> {
        let now = Instant::now();
        {
            let cache = self.org_limits_cache.lock().unwrap();
            if let Some((l, at)) = cache.get(&org_id) {
                if now.duration_since(*at) < self.ttl {
                    return Ok(*l);
                }
            }
        }
        let l = self.svc.resolve_org_limits(org_id).await?;
        self.org_limits_cache
            .lock()
            .unwrap()
            .insert(org_id, (l, now));
        Ok(l)
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
        let (client, conn) = tokio_postgres::connect(&dsn, NoTls)
            .await
            .expect("pg connect");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let svc = AuthService {
            client: Arc::new(client),
        };
        // Idempotent schema (never DROP: tests share the DB and run in
        // parallel — a DROP would race other tests' tables).
        svc.client.batch_execute(COMMERCIAL_SCHEMA).await.unwrap();
        let username = format!("ckprobe-{}", std::process::id());
        let uid = svc.register(&username, "password123").await.unwrap();
        let key = svc
            .create_key(
                uid,
                "probe",
                crate::ratelimit::Limits {
                    rpm: 3,
                    tpm: 100,
                    concurrency: 2,
                    ..Default::default()
                },
            )
            .await;
        match key {
            Ok(k) => {
                let l = svc.resolve_limits(&k).await.expect("resolve limits");
                assert_eq!(
                    l,
                    crate::ratelimit::Limits {
                        rpm: 3,
                        tpm: 100,
                        concurrency: 2,
                        ..Default::default()
                    }
                );
                println!(
                    "create_key OK: rpm={} tpm={} concurrency={}",
                    l.rpm, l.tpm, l.concurrency
                );
            }
            Err(e) => eprintln!("create_key FAILED: {e}"),
        }
    }

    /// User-level aggregate quota roundtrip (layer 2).
    #[tokio::test]
    async fn user_limits_roundtrip() {
        let Ok(dsn) = std::env::var("STARGATE_TEST_PG") else {
            eprintln!("skipping: STARGATE_TEST_PG not set");
            return;
        };
        let (client, conn) = tokio_postgres::connect(&dsn, NoTls)
            .await
            .expect("pg connect");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let svc = AuthService {
            client: Arc::new(client),
        };
        svc.client.batch_execute(COMMERCIAL_SCHEMA).await.unwrap();
        let username = format!("limits-probe-{}", std::process::id());
        let _ = svc.register(&username, "password123").await;
        let uid = svc.login(&username, "password123").await.expect("login");

        // default: unlimited
        let l = svc.resolve_user_limits(uid).await.expect("resolve default");
        assert_eq!(l.rpm, 0, "new user must be unlimited");
        assert_eq!(l.tpm, 0, "new user must be unlimited");

        // set aggregate budget and read back
        svc.set_user_limits(uid, 5, 1000).await.expect("set limits");
        let l = svc.resolve_user_limits(uid).await.expect("resolve set");
        assert_eq!(l.rpm, 5);
        assert_eq!(l.tpm, 1000);
        println!("user_limits OK: rpm={} tpm={} (uid={uid})", l.rpm, l.tpm);
    }

    /// Project roundtrip (layer 3): create → set → assign user → read back.
    #[tokio::test]
    async fn project_roundtrip() {
        let Ok(dsn) = std::env::var("STARGATE_TEST_PG") else {
            eprintln!("skipping: STARGATE_TEST_PG not set");
            return;
        };
        let (client, conn) = tokio_postgres::connect(&dsn, NoTls)
            .await
            .expect("pg connect");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let svc = AuthService {
            client: Arc::new(client),
        };
        svc.client.batch_execute(COMMERCIAL_SCHEMA).await.unwrap();

        let pid = svc
            .create_project("probe-project", 0, 0)
            .await
            .expect("create");
        let l = svc
            .resolve_project_limits(pid)
            .await
            .expect("resolve default");
        assert_eq!(l.rpm, 0, "new project unlimited");
        assert_eq!(l.tpm, 0);

        svc.set_project_limits(pid, 10, 5000).await.expect("set");
        let l = svc.resolve_project_limits(pid).await.expect("resolve set");
        assert_eq!(l.rpm, 10);
        assert_eq!(l.tpm, 5000);

        let username = format!("proj-user-{}", std::process::id());
        let uid = svc.register(&username, "password123").await.unwrap();
        svc.set_user_project(uid, pid).await.expect("assign");
        let got = svc.project_of_user(uid).await.expect("membership");
        assert_eq!(got, pid, "user must belong to the project");
        println!("project OK: pid={pid} rpm=10 tpm=5000 uid={uid}");
    }

    /// Org → team → project chain roundtrip (layers 3-5).
    #[tokio::test]
    async fn org_team_chain_roundtrip() {
        let Ok(dsn) = std::env::var("STARGATE_TEST_PG") else {
            eprintln!("skipping: STARGATE_TEST_PG not set");
            return;
        };
        let (client, conn) = tokio_postgres::connect(&dsn, NoTls)
            .await
            .expect("pg connect");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let svc = AuthService {
            client: Arc::new(client),
        };
        svc.client.batch_execute(COMMERCIAL_SCHEMA).await.unwrap();

        let oid = svc.create_org("chain-org", 0, 0).await.expect("create org");
        let tid = svc
            .create_team("chain-team", oid, 0, 0)
            .await
            .expect("create team");
        let pid = svc
            .create_project("chain-proj", 0, 0)
            .await
            .expect("create project");

        svc.set_org_limits(oid, 100, 50000)
            .await
            .expect("org limits");
        svc.set_team_limits(tid, 50, 20000)
            .await
            .expect("team limits");
        svc.set_project_team(pid, tid).await.expect("project team");

        let got_tid = svc.team_of_project(pid).await.expect("team of project");
        assert_eq!(got_tid, tid);
        let got_oid = svc.org_of_team(tid).await.expect("org of team");
        assert_eq!(got_oid, oid);

        let ol = svc.resolve_org_limits(oid).await.expect("org limits read");
        assert_eq!((ol.rpm, ol.tpm), (100, 50000));
        let tl = svc
            .resolve_team_limits(tid)
            .await
            .expect("team limits read");
        assert_eq!((tl.rpm, tl.tpm), (50, 20000));
        println!("chain OK: org={oid} team={tid} project={pid}");
    }

    /// End-user quotas roundtrip (layer 6).
    #[tokio::test]
    async fn end_user_limits_roundtrip() {
        let Ok(dsn) = std::env::var("STARGATE_TEST_PG") else {
            eprintln!("skipping: STARGATE_TEST_PG not set");
            return;
        };
        let (client, conn) = tokio_postgres::connect(&dsn, NoTls)
            .await
            .expect("pg connect");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let svc = AuthService {
            client: Arc::new(client),
        };
        svc.client.batch_execute(COMMERCIAL_SCHEMA).await.unwrap();
        let username = format!("eu-probe-{}", std::process::id());
        let uid = svc.register(&username, "password123").await.unwrap();
        let key = svc
            .create_key(
                uid,
                "eu-key",
                crate::ratelimit::Limits {
                    end_user_rpm: 3,
                    end_user_tpm: 1000,
                    ..Default::default()
                },
            )
            .await
            .expect("create key");
        let l = svc.resolve_limits(&key).await.expect("resolve");
        assert_eq!(l.end_user_rpm, 3);
        assert_eq!(l.end_user_tpm, 1000);
        println!("end_user OK: rpm=3 tpm=1000");
    }
}
