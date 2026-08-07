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
| memory (idle RSS) | 69.9 MB | **39.8 MB** | Go uses 43% less |

### Full billing stack (Redis pre-charge + PG settle), 100 concurrent, 3 rounds

| Round | Stargate (Rust) | MeterGate (Go) | Ratio |
|-------|----------------|----------------|-------|
| 1 | **36,734 req/s** | 27,693 | **1.33x** |
| 2 | **41,069 req/s** | 27,191 | **1.51x** |
| 3 | **42,265 req/s** | 26,778 | **1.58x** |

- Billing integrity after 4M orders: balance exact to the micro, frozen 0
  (both implementations shared the same Redis+PG concurrently — cross-
  implementation consistency verified)
- Memory under full billing: **Rust 54.6 MB vs Go 140.4 MB** (Rust's
  pooled runtime wins once the billing stack is attached)
- ⚠️ The first Rust attempt serialized pre-charge behind one mutex
  (13K req/s, 2x slower than Go) — switching to a pooled
  ConnectionManager removed the lock and flipped the result. Same lesson
  as the Go version's Settler global mutex: **a single lock on the hot
  path caps throughput regardless of language**.
- Full billing pipeline (Kafka event bus, ClickHouse details, routing,
  reconciliation) remains in MeterGate; Stargate covers the dual-track
  core.

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
