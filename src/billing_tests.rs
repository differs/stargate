//! Pure-function accuracy tests (no external services needed):
//! request-start price snapshots, capped pre-charge, dedupe logic.

use crate::billing::{
    calculate_amount, estimate_precharge, order_from_event, price_for, MeteringEvent, ModelPrice,
};

fn ev(rid: &str) -> MeteringEvent {
    MeteringEvent {
        request_id: rid.to_string(),
        user_id: "u1".into(),
        model: "gpt-4o".into(),
        provider: "mock".into(),
        status: "completed".into(),
        prompt_tokens: 1000,
        completion_tokens: 1000,
        duration_ms: 5,
        ttft_ms: 0,
        pricing: None,
    }
}

#[test]
fn order_uses_request_start_snapshot() {
    let mut e = ev("req-snap");
    // Request started at $10/1M output...
    e.pricing = Some(ModelPrice { input_per_1m: 2_000_000, output_per_1m: 10_000_000 });
    // ...price table has since changed to $8 (simulated by constructing
    // the order with the snapshot present — table is irrelevant).
    let o = order_from_event(&e);
    // 1000*2 + 1000*10 = 12,000 µ
    assert_eq!(o.amount_micros, 12_000, "request-start price must win");
}

#[test]
fn order_falls_back_to_current_price_without_snapshot() {
    let e = ev("req-legacy"); // pricing: None
    let o = order_from_event(&e);
    let p = price_for("gpt-4o");
    let want = calculate_amount(1000, 1000, p);
    assert_eq!(o.amount_micros, want, "legacy events use current table");
}

#[test]
fn failed_requests_are_free() {
    let mut e = ev("req-fail");
    e.status = "failed".into();
    e.completion_tokens = 500; // would have billed if not failed
    let o = order_from_event(&e);
    assert_eq!(o.status, "NO_CHARGE");
    assert_eq!(o.amount_micros, 0, "zero-completion insurance: failed = free");
    assert_eq!(o.completion_tokens, 0);
}

#[test]
fn precharge_cap_applies() {
    let p = ModelPrice { input_per_1m: 2_000_000, output_per_1m: 10_000_000 };
    // max_tokens = 1_000_000 → capped at 16_000 completion
    let est = estimate_precharge(1000, Some(1_000_000), p);
    // (1000*2 + 16000*10)/1e6 * 1.1 ≈ 178,200; must not scale with 1M tokens
    assert!(est < 200_000, "cap must apply, got {est}");
    // without max_tokens: same cap
    let est2 = estimate_precharge(1000, None, p);
    assert_eq!(est, est2);
}

#[test]
fn shard_index_stable() {
    // same key → same shard (ordering/dedupe within a shard depends on it)
    assert_eq!(crate::billing::shard_index("req-x", 8), crate::billing::shard_index("req-x", 8));
    // different keys spread (fnv distribution sanity)
    let mut seen = std::collections::HashSet::new();
    for i in 0..1000 {
        seen.insert(crate::billing::shard_index(&format!("req-{i}"), 8));
    }
    assert!(seen.len() >= 6, "hash should spread across shards, got {}", seen.len());
}
