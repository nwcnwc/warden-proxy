//! Traffic monitor regression tests — ring buffer behavior,
//! entry fields, and filtering.

use std::collections::VecDeque;

/// Simulated traffic entry (mirrors RequestLog structure)
#[derive(Clone)]
struct Entry {
    id: String,
    timestamp: u64,
    method: String,
    service: String,
    path: String,
    status: u16,
    duration_ms: u64,
}

fn make_entry(id: u64, timestamp: u64) -> Entry {
    Entry {
        id: format!("wdn-{:08x}", id),
        timestamp,
        method: "GET".to_string(),
        service: "openai".to_string(),
        path: "/v1/chat/completions".to_string(),
        status: 200,
        duration_ms: 50,
    }
}

// ════════════════════════════════════════════════════════
// Ring Buffer Tests
// ════════════════════════════════════════════════════════

#[test]
fn ring_buffer_capped_at_1000() {
    let mut log: VecDeque<Entry> = VecDeque::with_capacity(1000);

    for i in 0..1500 {
        if log.len() >= 1000 { log.pop_front(); }
        log.push_back(make_entry(i, 1000 + i));
    }

    assert_eq!(log.len(), 1000, "ring buffer must not exceed 1000 entries");
}

#[test]
fn oldest_entries_evicted_when_full() {
    let mut log: VecDeque<Entry> = VecDeque::with_capacity(1000);

    for i in 0..1200 {
        if log.len() >= 1000 { log.pop_front(); }
        log.push_back(make_entry(i, 1000 + i));
    }

    // Oldest remaining should be entry 200 (entries 0-199 evicted)
    assert_eq!(log.front().unwrap().id, format!("wdn-{:08x}", 200u64));
    // Newest should be entry 1199
    assert_eq!(log.back().unwrap().id, format!("wdn-{:08x}", 1199u64));
}

#[test]
fn entries_have_correct_fields() {
    let entry = make_entry(42, 1709500000000);

    assert_eq!(entry.id, "wdn-0000002a");
    assert_eq!(entry.timestamp, 1709500000000);
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.service, "openai");
    assert_eq!(entry.path, "/v1/chat/completions");
    assert_eq!(entry.status, 200);
    assert_eq!(entry.duration_ms, 50);
}

#[test]
fn filter_by_since_timestamp() {
    let mut log: VecDeque<Entry> = VecDeque::new();

    // Add entries at different timestamps
    for i in 0..10 {
        log.push_back(make_entry(i, 1000 + i * 100));
    }

    // Filter since=1500 should return entries with timestamp > 1500
    let since = 1500u64;
    let filtered: Vec<&Entry> = log.iter()
        .filter(|e| e.timestamp > since)
        .collect();

    // Entries at 1600, 1700, 1800, 1900 = 4 entries
    assert_eq!(filtered.len(), 4);
    assert!(filtered.iter().all(|e| e.timestamp > since));
}

// ════════════════════════════════════════════════════════
// Verify ring buffer logic matches proxy source
// ════════════════════════════════════════════════════════

#[test]
fn proxy_source_uses_ring_buffer() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains("log.len() >= 1000"),
        "proxy must cap traffic log at 1000 entries");
    assert!(source.contains("log.pop_front()"),
        "proxy must evict oldest entries");
    assert!(source.contains("log.push_back"),
        "proxy must append new entries");
}

#[test]
fn traffic_log_entry_has_all_fields() {
    let source = include_str!("../src/lib.rs");
    // Verify RequestLog struct has required fields
    assert!(source.contains("pub id: String"));
    assert!(source.contains("pub timestamp: u64"));
    assert!(source.contains("pub method: String"));
    assert!(source.contains("pub service: String"));
    assert!(source.contains("pub path: String"));
    assert!(source.contains("pub status: u16"));
    assert!(source.contains("pub duration_ms: u64"));
}
