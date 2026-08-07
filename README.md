# Stargate

**Rust re-implementation of [MeterGate](https://github.com/differs/MeterGate)'s data plane** — an OpenAI-compatible LLM gateway with streaming token metering. Built as a head-to-head performance comparison against the Go version under identical conditions.

## What's implemented (same requirements as MeterGate's core)

- `POST /v1/chat/completions` — stream + non-stream, transparent upstream forwarding
- Streaming token metering (CJK-aware approximate estimator, fast byte-scan delta extraction — mirrors MeterGate's `fastDeltaContent`)
- Upstream usage extraction + cross-validation hooks
- Request-level metering events (audit log, debug level)
- Static API-key auth
- Zero external infrastructure (no Redis/PG/Kafka/CH — the comparison focuses on the data plane)

## Architecture

```
client ──▶ axum (tokio) ──▶ auth ──▶ stream? ──▶ reqwest (pooled) ──▶ upstream
                                      │
                                      └─▶ local token metering (atomic counters)
```

Stack: `axum 0.8` + `tokio` + `reqwest` + `serde` — all async, connection-pooled, keep-alive.

## Full billing stack (Rust port)

Stargate now implements MeterGate's complete dual-track billing engine:

- Redis Lua pre-charge (atomic, no oversell, 402 on insufficient balance)
- Sharded Settler (8 shards, hash-routed) → true multi-row INSERT into
  PostgreSQL (one commit per batch) → Redis batch-settle pipeline
  (clawback on overage, zero-completion insurance: failed = free)
- Pooled Redis (ConnectionManager) + pooled PG (deadpool-postgres)

```bash
STARGATE_REDIS_ADDR=127.0.0.1:6381 STARGATE_PG_DSN=postgres://postgres:mg@127.0.0.1:5436/metergate ./target/release/stargate
```

## Benchmark: Stargate (Rust) vs MeterGate (Go)

**Method**: same machine, same mock upstream (Go, ~76K req/s baseline), same
`hey` load generator, identical request payloads. Both gateways in minimal
config (pure forwarding + metering). Environment note: shared dev machine
(`load average ~31` on 16 cores from unrelated workloads) — numbers fluctuate,
so multiple rounds were taken; the Rust lead was consistent in every round.

| Scenario | Stargate (Rust) | MeterGate (Go) | Ratio |
|----------|----------------|----------------|-------|
| non-stream, 100 concurrent (round 1) | **58,611 req/s** | 40,488 req/s | **1.45x** |
| non-stream, 100 concurrent (round 2) | **78,571 req/s** | 44,177 req/s | **1.78x** |
| non-stream, 500 concurrent | **81,236 req/s** | 51,047 req/s | **1.59x** |
| streaming, 50 concurrent | 312 req/s | 313 req/s | ~1.0x (theoretical limit 322) |

### Full billing stack (Redis pre-charge + PG settle), 100 concurrent, 3 rounds

| Round | Stargate (Rust) | MeterGate (Go) | Ratio |
|-------|----------------|----------------|-------|
| 1 | **36,734 req/s** | 27,693 | **1.33x** |
| 2 | **41,069 req/s** | 27,191 | **1.51x** |
| 3 | **42,265 req/s** | 26,778 | **1.58x** |

- Billing integrity after 4M orders: balance exact to the micro, frozen 0
  (both implementations shared the same Redis+PG concurrently — cross-
  implementation consistency verified)
- ⚠️ The first Rust attempt serialized pre-charge behind one mutex
  (13K req/s, 2x slower than Go) — switching to a pooled
  ConnectionManager removed the lock and flipped the result. Same lesson
  as the Go version's Settler global mutex: **a single lock on the hot
  path caps throughput regardless of language**.
- Full billing pipeline (Kafka event bus, ClickHouse details, routing,
  reconciliation) remains in MeterGate; Stargate covers the dual-track
  core.

### Memory (controlled measurement, same lifecycle for both)

| Config | cold start | after 30s @100c | 30s after load |
|--------|-----------|-----------------|----------------|
| Rust pure forwarding | **5.1 MB** | 37.7 MB | 37.7 MB |
| Go pure forwarding | 14.9 MB | **33.1 MB** | 33.1 MB |
| Rust full billing | **5.7 MB** | **37.1 MB** | **36.8 MB** |
| Go full billing | 17.9 MB | 49.0 MB | 43.6 MB |

- **Cold start: Rust ~3x leaner** (5-6 MB vs 15-18 MB — Go's runtime
  initializes more eagerly).
- **After load: comparable** — pure forwarding Go is slightly leaner
  (33 vs 38 MB), full billing Rust is leaner (37 vs 49 MB). Go's GC
  releases some memory after load (49 → 44 MB); Rust's allocator holds
  its peak (steady ~37 MB).
- ⚠️ Earlier published numbers (69.9 MB / 140.4 MB) were sampled at
  different points in the load lifecycle and are NOT comparable — RSS
  fluctuates with connection pools and buffers. The table above uses
  identical measurement points.

### Takeaways

1. **Non-streaming forwarding: Rust ~1.5-1.8x faster.** The gap comes from
   lower per-request overhead (no GC, zero-cost async, smaller allocations).
2. **Streaming: identical** — both hit the theoretical limit (50 concurrent ÷
   160ms per mock stream = 322 req/s). The bottleneck is the upstream stream
   duration, not the gateway.
3. **Memory: Go wins** (39.8 MB vs 69.9 MB idle RSS) — tokio/reqwest runtime
   overhead vs Go's compact runtime. For many small instances, Go is cheaper.
4. The full billing pipeline (Redis pre-charge, batched PG settle, Kafka,
   ClickHouse) lives in MeterGate and was verified exact under 22K req/s;
   Stargate is the data-plane comparison baseline.

## Comprehensive performance matrix (Rust)

Full matrix, all on the same 16-core shared dev machine (load ~30 from
unrelated workloads — numbers fluctuate; every scenario ran twice and the
Rust lead was consistent).

| Scenario | Pure forwarding | Full billing (Redis pre-charge + PG settle) |
|----------|----------------|---------------------------------------------|
| non-stream, 100 concurrent | **51.8K-55.0K req/s** | **35.2K-35.9K req/s** |
| non-stream, 500 concurrent | **74.1K req/s** | **46.9K req/s** |
| streaming, 50 concurrent | 313 req/s (limit 322) | 314.5 req/s (limit 322) |
| avg latency (100c) | 3.0ms | 3.0ms |

Billing integrity after 3.55M orders in the full-billing run:
balance exact to the micro, frozen 0.

vs MeterGate (Go) under identical conditions:
- pure forwarding 100c: Rust ~1.3-1.5x
- full billing 100c: Rust ~1.3x (35-36K vs 26.8-27.7K)
- streaming: identical (both at the theoretical limit)

The billing stack costs Rust ~30% throughput (55K → 36K at 100c) —
pre-charge RTT + settle pipeline — same ratio as Go's ~30% (44K → 27K).

## Accuracy parity with MeterGate

Stargate syncs the accuracy-first fixes from the Go implementation:

- **Request-start price snapshots**: prices are frozen into the metering
  event when the request arrives; settlement uses the snapshot, never the
  current table — a mid-request price change cannot reprice in-flight
  requests.
- **Tests** (`cargo test`): snapshot pricing wins over table changes,
  legacy events fall back to current prices, zero-completion insurance
  (failed = free), pre-charge cap, shard-hash stability.
- The remaining accuracy modules (supplier reconciliation, traceability
  API, ClickHouse details) live in MeterGate where the full platform
  stack exists.

## Commercial stack (P0: can take money)

```bash
STARGATE_PORTAL_PORT=3202 STARGATE_PORTAL_KEY=admin-secret \
STARGATE_PG_DSN=postgres://... ./target/release/stargate

curl -X POST localhost:3202/api/register -d '{"username":"bob","password":"password123"}'
curl -X POST "localhost:3202/api/keys?user_id=1" -d '{"name":"prod"}'
curl -X POST "localhost:3202/api/recharge?user_id=1" -d '{"amount_micros":50000000,"idempotency_key":"r1"}'
curl -X POST localhost:3202/api/recharge/pay -d '{"recharge_id":1,"channel":"mock"}'
# consume with the issued sk- key (static allowlist OR stored keys, cached)
```

Verified end-to-end: register → login → key → recharge → mock pay →
consume with the new key → balance exact; duplicate callback no-ops
(money safe). Mirrors MeterGate's commercial stack.

## Sessions (JWT + OIDC)

```bash
STARGATE_JWT_SECRET=<32+ bytes> STARGATE_OIDC_PROVIDER_URL=https://accounts.google.com STARGATE_OIDC_CLIENT_ID=... STARGATE_OIDC_CLIENT_SECRET=... ./target/release/stargate
```

- Login returns a session JWT (HS256, 24h); portal endpoints accept the
  JWT OR the admin key.
- `GET /api/oidc/login` → redirect to the IdP; `/api/oidc/callback`
  exchanges the code, verifies the id_token (JWKS via discovery),
  auto-registers/resolves the local account and returns a session JWT.
- Verified end-to-end: login → JWT → create key with JWT (no admin
  key); forged JWT rejected 401.

## Observability

`GET /metrics` (Prometheus text format): HTTP requests by status class,
pre-charge attempts by result, settled orders by status. Scrape it with
the same Prometheus + alerting setup as MeterGate.

## Run

```bash
cargo build --release

STARGATE_PORT=3200 \
STARGATE_UPSTREAM=http://127.0.0.1:9901/v1/chat/completions \
STARGATE_UPSTREAM_KEY=sk-upstream \
STARGATE_API_KEYS=sk-your-key \
./target/release/stargate
```

```bash
curl http://localhost:3200/v1/chat/completions \
  -H "Authorization: Bearer sk-your-key" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
```

## Scope & roadmap

This repo implements the data plane AND the dual-track billing core
(pre-charge + batched settle). The remaining production features (Kafka
event bus, ClickHouse details, routing engine, reconciliation, auto-
refund) live in [MeterGate](https://github.com/differs/MeterGate) (Go).

## License

MIT
