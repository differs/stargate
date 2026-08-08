//! Payment — recharge & payment flow (Rust port of MeterGate's
//! internal/payment): idempotent recharge orders, channel adapters,
//! replay-safe callbacks, balance credit exactly once.

use std::sync::Arc;

use tokio_postgres::Client;

/// Channel is a payment provider adapter.
pub trait Channel: Send + Sync {
    fn name(&self) -> &str;
    fn pay(&self, recharge_id: i64, amount_micros: i64) -> String;
}

/// Mock channel: completes immediately (dev flow).
pub struct MockChannel;

impl Channel for MockChannel {
    fn name(&self) -> &str {
        "mock"
    }
    fn pay(&self, recharge_id: i64, _amount: i64) -> String {
        format!(
            "mock-txn-{}-{}",
            recharge_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }
}

pub struct PaymentService {
    client: Arc<Client>,
    channels: Vec<Box<dyn Channel>>,
    top_up: Box<
        dyn Fn(
                i64,
                i64,
            )
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>
            + Send
            + Sync,
    >,
}

impl PaymentService {
    pub fn new(
        client: Arc<Client>,
        top_up: Box<
            dyn Fn(
                    i64,
                    i64,
                ) -> std::pin::Pin<
                    Box<dyn std::future::Future<Output = Result<(), String>> + Send>,
                > + Send
                + Sync,
        >,
    ) -> Self {
        Self {
            client,
            channels: Vec::new(),
            top_up,
        }
    }

    pub fn register_channel(&mut self, ch: Box<dyn Channel>) {
        self.channels.push(ch);
    }

    /// Create a pending recharge (idempotent by idempotency_key).
    pub async fn recharge(
        &self,
        user_id: i64,
        amount_micros: i64,
        idempotency_key: &str,
    ) -> Result<i64, String> {
        if amount_micros <= 0 {
            return Err("amount must be positive".into());
        }
        let key = if idempotency_key.is_empty() {
            let raw: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
            format!("srv-{}", hex::encode(&raw))
        } else {
            idempotency_key.to_string()
        };
        let row = self
            .client
            .query_one(
                "INSERT INTO recharges (user_id, amount_micros, idempotency_key)
                 VALUES ($1,$2,$3)
                 ON CONFLICT (idempotency_key) DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key
                 RETURNING id",
                &[&user_id, &amount_micros, &key],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.get::<_, i64>(0))
    }

    /// Pay a pending recharge via a channel; mock settles synchronously.
    pub async fn pay(&self, recharge_id: i64, channel_name: &str) -> Result<String, String> {
        let ch = self
            .channels
            .iter()
            .find(|c| c.name() == channel_name)
            .ok_or_else(|| format!("unknown channel: {channel_name}"))?;
        let row = self
            .client
            .query_opt(
                "SELECT user_id, amount_micros, status FROM recharges WHERE id=$1",
                &[&recharge_id],
            )
            .await
            .map_err(|e| e.to_string())?
            .ok_or("recharge not found")?;
        let status: String = row.get(2);
        if status == "PAID" {
            return Err("recharge already paid".into());
        }
        let txn = ch.pay(recharge_id, row.get::<_, i64>(1));
        if ch.name() == "mock" {
            self.settle_callback(
                recharge_id,
                ch.name(),
                &txn,
                row.get::<_, i64>(1),
                "{\"mock\":true}",
            )
            .await?;
        }
        Ok(txn)
    }

    /// Callback handler — replay-safe by (channel, channel_txn_id).
    pub async fn settle_callback(
        &self,
        recharge_id: i64,
        channel: &str,
        txn_id: &str,
        amount_micros: i64,
        raw: &str,
    ) -> Result<(), String> {
        // insert payment (unique constraint → duplicate no-op)
        let inserted = self
            .client
            .query_opt(
                "INSERT INTO payments (recharge_id, channel, channel_txn_id, amount_micros, raw_callback)
                 VALUES ($1,$2,$3,$4,$5)
                 ON CONFLICT (channel, channel_txn_id) DO NOTHING
                 RETURNING id",
                &[&recharge_id, &channel, &txn_id, &amount_micros, &raw],
            )
            .await
            .map_err(|e| e.to_string())?;
        if inserted.is_none() {
            return Ok(()); // duplicate callback — no-op
        }

        // mark PAID (only from PENDING)
        let tag = self
            .client
            .execute(
                "UPDATE recharges SET status='PAID', paid_at=now() WHERE id=$1 AND status='PENDING'",
                &[&recharge_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        if tag == 0 {
            return Err("recharge not pending (duplicate or invalid)".into());
        }

        // get user id, then credit balance (operational view)
        let row = self
            .client
            .query_one("SELECT user_id FROM recharges WHERE id=$1", &[&recharge_id])
            .await
            .map_err(|e| e.to_string())?;
        let user_id: i64 = row.get(0);
        (self.top_up)(user_id, amount_micros).await
    }

    pub async fn recharge_status(&self, recharge_id: i64) -> Result<String, String> {
        let row = self
            .client
            .query_opt("SELECT status FROM recharges WHERE id=$1", &[&recharge_id])
            .await
            .map_err(|e| e.to_string())?;
        row.map(|r| r.get::<_, String>(0))
            .ok_or("recharge not found".into())
    }
}
