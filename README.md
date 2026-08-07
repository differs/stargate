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

This repo intentionally implements only the data plane for the comparison.
Production features (dual-track billing, routing, reconciliation, event bus)
live in [MeterGate](https://github.com/differs/MeterGate) (Go). A Rust
full-stack port is a natural follow-up if the data-plane advantage matters
at scale.

## License

MIT
