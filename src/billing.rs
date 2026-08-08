//! Dual-track billing engine — a faithful Rust port of MeterGate's Go
//! implementation:
//!
//!   fast path: Redis Lua pre-charge (atomic, no oversell, 402 on
//!              insufficient balance)
//!   slow path: sharded Settler buffers events → true multi-row INSERT
//!              into PostgreSQL (one commit per batch) → Redis batch
//!              settle (pipeline, clawback on overage)
//!
//! Money is int64 micro-units everywhere (1e-6 of the base currency).

use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};

use redis::AsyncCommands;
use tokio::sync::{Mutex, mpsc};
use tokio_postgres::NoTls;

// ---------------------------------------------------------------------------
// Pricing (micros per 1M tokens) — mirrors MeterGate's defaults.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct ModelPrice {
    pub input_per_1m: i64,
    pub output_per_1m: i64,
}

pub fn price_for(model: &str) -> ModelPrice {
    match model {
        "gpt-4o" => ModelPrice {
            input_per_1m: 2_500_000,
            output_per_1m: 10_000_000,
        },
        "gpt-4o-mini" => ModelPrice {
            input_per_1m: 150_000,
            output_per_1m: 600_000,
        },
        "deepseek-chat" => ModelPrice {
            input_per_1m: 270_000,
            output_per_1m: 1_100_000,
        },
        _ => ModelPrice {
            input_per_1m: 1_000_000,
            output_per_1m: 2_000_000,
        },
    }
}

/// amount = prompt*input/1e6 + completion*output/1e6 (integer math).
pub fn calculate_amount(prompt: i64, completion: i64, p: ModelPrice) -> i64 {
    prompt * p.input_per_1m / 1_000_000 + completion * p.output_per_1m / 1_000_000
}

/// Pre-charge estimate with completion cap (anti-abuse).
pub fn estimate_precharge(prompt: i64, max_tokens: Option<u32>, p: ModelPrice) -> i64 {
    let cap: i64 = 16_000;
    let completion_cap = match max_tokens {
        Some(m) if (m as i64) < cap => m as i64,
        _ => cap,
    };
    let est = calculate_amount(prompt, completion_cap, p);
    est + est / 10 + 1
}

// ---------------------------------------------------------------------------
// Redis keys + Lua scripts (byte-identical semantics to MeterGate)
// ---------------------------------------------------------------------------

fn bal_key(user: &str) -> String {
    format!("balance:{user}")
}
fn frozen_key(user: &str) -> String {
    format!("frozen:{user}")
}
fn pre_key(req: &str) -> String {
    format!("precharge:{req}")
}

const PRECHARGE_SCRIPT: &str = r#"
local bal = tonumber(redis.call('GET', KEYS[1]) or '0')
local amount = tonumber(ARGV[1])
if bal < amount then
  return -1
end
redis.call('DECRBY', KEYS[1], amount)
redis.call('INCRBY', KEYS[2], amount)
redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[2])
return 1
"#;

const SETTLE_SCRIPT: &str = r#"
local pre = tonumber(redis.call('GET', KEYS[3]) or '0')
if pre <= 0 then
  return 0
end
local charged = tonumber(ARGV[1])
local refund = pre - charged
if refund < 0 then
  redis.call('DECRBY', KEYS[1], -refund)
  refund = 0
elseif refund > 0 then
  redis.call('INCRBY', KEYS[1], refund)
end
redis.call('DECRBY', KEYS[2], pre)
redis.call('DEL', KEYS[3])
return refund
"#;

pub struct Precharger {
    conn: redis::aio::ConnectionManager,
}

impl Precharger {
    pub async fn connect(addr: &str) -> Result<Self, String> {
        let client = redis::Client::open(format!("redis://{addr}")).map_err(|e| e.to_string())?;
        let conn = redis::aio::ConnectionManager::new(client)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }

    pub async fn top_up(&mut self, user: &str, amount: i64) -> Result<(), String> {
        let _: () = self
            .conn
            .incr(bal_key(user), amount)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Atomic pre-charge; Err("insufficient") when balance cannot cover.
    pub async fn precharge(&self, user: &str, request_id: &str, amount: i64) -> Result<(), String> {
        if amount <= 0 {
            return Ok(());
        }
        let keys = vec![bal_key(user), frozen_key(user), pre_key(request_id)];
        let mut conn = self.conn.clone();
        let res: i64 = redis::cmd("EVAL")
            .arg(PRECHARGE_SCRIPT)
            .arg(3usize) // numkeys
            .arg(keys)
            .arg(amount)
            .arg(48 * 3600)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        if res < 0 {
            return Err("insufficient balance".into());
        }
        Ok(())
    }

    /// Batch-settle pre-charges in ONE pipeline round-trip (mirrors
    /// MeterGate's BatchSettle).
    pub async fn batch_settle(
        &self,
        orders: &[Order],
        events: &[MeteringEvent],
    ) -> Result<(), String> {
        let mut pipe = redis::pipe();
        for (o, ev) in orders.iter().zip(events.iter()) {
            let charged = if o.status == "NO_CHARGE" {
                0
            } else {
                o.amount_micros
            };
            pipe.cmd("EVAL")
                .arg(SETTLE_SCRIPT)
                .arg(3usize)
                .arg(bal_key(&ev.user_id))
                .arg(frozen_key(&ev.user_id))
                .arg(pre_key(&ev.request_id))
                .arg(charged.max(0));
        }
        let mut conn = self.conn.clone();
        pipe.query_async::<Vec<i64>>(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Settle one pre-charge (idempotent).
    pub async fn settle(&self, user: &str, request_id: &str, charged: i64) -> Result<(), String> {
        let charged = charged.max(0);
        let keys = vec![bal_key(user), frozen_key(user), pre_key(request_id)];
        let mut conn = self.conn.clone();
        let _: i64 = redis::cmd("EVAL")
            .arg(SETTLE_SCRIPT)
            .arg(3usize) // numkeys
            .arg(keys)
            .arg(charged)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Orders + PostgreSQL store (true multi-row INSERT)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Order {
    pub request_id: String,
    pub user_id: String,
    pub model: String,
    pub provider: String,
    pub status: String, // SETTLED | NO_CHARGE
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub amount_micros: i64,
    pub duration_ms: i64,
    pub ttft_ms: i64,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS orders (
    request_id         TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL,
    model              TEXT NOT NULL,
    provider           TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'SETTLED',
    prompt_tokens      BIGINT NOT NULL DEFAULT 0,
    completion_tokens  BIGINT NOT NULL DEFAULT 0,
    total_tokens       BIGINT NOT NULL DEFAULT 0,
    amount_micros      BIGINT NOT NULL DEFAULT 0,
    duration_ms        BIGINT NOT NULL DEFAULT 0,
    ttft_ms            BIGINT NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_orders_user_created ON orders (user_id, created_at DESC);
"#;

pub struct PostgresStore {
    pool: Pool,
}

impl PostgresStore {
    pub async fn connect(dsn: &str) -> Result<Self, String> {
        let cfg: tokio_postgres::Config = dsn
            .parse()
            .map_err(|e: tokio_postgres::error::Error| e.to_string())?;
        let mgr = Manager::from_config(
            cfg,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(mgr)
            .max_size(16)
            .build()
            .map_err(|e| e.to_string())?;
        let client = pool.get().await.map_err(|e| e.to_string())?;
        client
            .batch_execute(SCHEMA)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self { pool })
    }

    /// True multi-row INSERT, one commit, ON CONFLICT DO NOTHING
    /// (mirrors MeterGate's batched write).
    pub async fn insert_orders(&self, orders: &[Order]) -> Result<(), String> {
        if orders.is_empty() {
            return Ok(());
        }
        const COLS: usize = 11;
        // created_at uses the column DEFAULT now() — passing SystemTime as
        // a bind param trips PG's type inference; the default is exact.
        let mut sql = String::from(
            "INSERT INTO orders (request_id, user_id, model, provider, status, prompt_tokens, \
             completion_tokens, total_tokens, amount_micros, duration_ms, ttft_ms) VALUES ",
        );
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            Vec::with_capacity(orders.len() * COLS);
        for (i, o) in orders.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            let base = i * COLS;
            sql.push_str(&format!(
                "(${},${},${},${},${},${},${},${},${},${},${})",
                base + 1,
                base + 2,
                base + 3,
                base + 4,
                base + 5,
                base + 6,
                base + 7,
                base + 8,
                base + 9,
                base + 10,
                base + 11
            ));
            params.push(Box::new(o.request_id.clone()));
            params.push(Box::new(o.user_id.clone()));
            params.push(Box::new(o.model.clone()));
            params.push(Box::new(o.provider.clone()));
            params.push(Box::new(o.status.clone()));
            params.push(Box::new(o.prompt_tokens));
            params.push(Box::new(o.completion_tokens));
            params.push(Box::new(o.total_tokens));
            params.push(Box::new(o.amount_micros));
            params.push(Box::new(o.duration_ms));
            params.push(Box::new(o.ttft_ms));
        }
        sql.push_str(" ON CONFLICT (request_id) DO NOTHING");

        let client = self.pool.get().await.map_err(|e| e.to_string())?;
        // Upcast &dyn ToSql+Send+Sync → &dyn ToSql+Sync (sendable owner,
        // non-send borrow for the execute call — both live in this fn).
        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
            .iter()
            .map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();
        match client.execute(&sql, &params_refs).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("INSERT ERROR: {e:?}");
                return Err(format!("{e}"));
            }
        }
        Ok(())
    }

    pub async fn count(&self) -> Result<i64, String> {
        let client = self.pool.get().await.map_err(|e| e.to_string())?;
        let row = client
            .query_one("SELECT count(*) FROM orders", &[])
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.get::<_, i64>(0))
    }
}

// ---------------------------------------------------------------------------
// Settler: sharded buffer + async flush (mirrors MeterGate's design)
// ---------------------------------------------------------------------------

pub struct MeteringEvent {
    pub request_id: String,
    pub user_id: String,
    pub model: String,
    pub provider: String,
    pub status: String, // completed | failed | aborted
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub duration_ms: i64,
    pub ttft_ms: i64,
    /// Prices frozen at REQUEST START. Settlement MUST use this, never
    /// the current table — a mid-request price change must not reprice
    /// in-flight requests (accuracy gap #1, same fix as MeterGate).
    pub pricing: Option<ModelPrice>,
}

/// Price frozen at request start.
#[derive(Clone, Copy)]
pub struct PriceSnapshot {
    pub input_per_1m: i64,
    pub output_per_1m: i64,
}

struct Shard {
    buf: Mutex<(Vec<Order>, Vec<MeteringEvent>)>,
    notify: mpsc::Sender<()>,
}

pub struct Settler {
    store: Arc<PostgresStore>,
    pre: Option<Arc<Precharger>>,
    batch: usize,
    shards: Vec<Arc<Shard>>,
}

pub(crate) fn shard_index(key: &str, n: usize) -> usize {
    let mut h: u32 = 0x811c9dc5;
    for b in key.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    (h as usize) % n
}

impl Settler {
    pub async fn new(store: Arc<PostgresStore>, pre: Option<Precharger>, batch: usize) -> Self {
        let n = 8usize;
        let pre_shared = pre.map(Arc::new);
        let mut shards = Vec::with_capacity(n);
        for _ in 0..n {
            let (tx, mut rx) = mpsc::channel::<()>(1);
            let sh = Arc::new(Shard {
                buf: Mutex::new((Vec::new(), Vec::new())),
                notify: tx,
            });
            let sh2 = sh.clone();
            let store2 = store.clone();
            let pre2 = pre_shared.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(50));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = rx.recv() => {}
                        _ = interval.tick() => {}
                    }
                    flush_shard(&sh2, &store2, pre2.as_ref()).await;
                }
            });
            shards.push(sh);
        }
        Self {
            store,
            pre: pre_shared,
            batch,
            shards,
        }
    }

    /// Buffer one event (non-blocking). Drops when full (shard buffer
    /// bounded) — gateway must never block on billing.
    pub async fn handle(&self, ev: MeteringEvent) {
        let order = order_from_event(&ev);
        let idx = shard_index(&ev.request_id, self.shards.len());
        let sh = &self.shards[idx];
        {
            let mut guard = sh.buf.lock().await;
            if guard.0.len() >= 100_000 {
                return; // drop on overflow (audit-log recoverable)
            }
            guard.0.push(order);
            guard.1.push(ev);
            if guard.0.len() >= self.batch {
                let _ = sh.notify.try_send(());
            }
        }
    }
}

pub(crate) fn order_from_event(ev: &MeteringEvent) -> Order {
    let status = if ev.status == "failed" {
        "NO_CHARGE"
    } else {
        "SETTLED"
    };
    let completion = if ev.status == "failed" {
        0
    } else {
        ev.completion_tokens
    };
    // Price from the REQUEST-START snapshot; fall back to the current
    // table only for legacy events without a snapshot.
    let p = ev.pricing.unwrap_or_else(|| price_for(&ev.model));
    let amount = if ev.status == "failed" {
        0 // zero-completion insurance: failed requests are free
    } else {
        calculate_amount(ev.prompt_tokens, completion, p)
    };
    Order {
        request_id: ev.request_id.clone(),
        user_id: ev.user_id.clone(),
        model: ev.model.clone(),
        provider: ev.provider.clone(),
        status: status.to_string(),
        prompt_tokens: ev.prompt_tokens,
        completion_tokens: completion,
        total_tokens: ev.prompt_tokens + completion,
        amount_micros: amount,
        duration_ms: ev.duration_ms,
        ttft_ms: ev.ttft_ms,
    }
}

async fn flush_shard(sh: &Shard, store: &PostgresStore, pre: Option<&Arc<Precharger>>) {
    let (orders, events) = {
        let mut guard = sh.buf.lock().await;
        if guard.0.is_empty() {
            return;
        }
        (std::mem::take(&mut guard.0), std::mem::take(&mut guard.1))
    };

    if let Err(e) = store.insert_orders(&orders).await {
        tracing::error!(count = orders.len(), err = %e, "batch order insert failed");
        return;
    }
    crate::gateway::record_orders("settled", orders.len());
    if let Some(pre) = pre {
        // batch settle via one pipeline round-trip
        let _ = pre.batch_settle(&orders, &events).await;
    }
    tracing::debug!(count = orders.len(), "batch settled");
}

/// A small shared handle used by the gateway to top up + precharge.
pub struct BillingHandle {
    pub pre: Option<Arc<Precharger>>,
    pub settler: Arc<Settler>,
    pub store: Arc<PostgresStore>,
}
