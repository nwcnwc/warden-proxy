//! Rate limiter regression tests — RPM enforcement, RPD enforcement,
//! per-service isolation.

use warden_proxy::config::{WardenConfig, LimitConfig};
use warden_proxy::limiter::RateLimiter;
use std::collections::HashMap;

fn make_limiter(limits: Vec<(&str, Option<u32>, Option<u32>)>) -> RateLimiter {
    let config = WardenConfig {
        limits: limits.into_iter().map(|(name, rpm, rpd)| {
            (name.to_string(), LimitConfig { rpm, rpd })
        }).collect(),
        ..Default::default()
    };
    RateLimiter::from_config(&config)
}

// ════════════════════════════════════════════════════════
// RPM Limit Enforced
// ════════════════════════════════════════════════════════

#[test]
fn rpm_limit_enforced() {
    let mut limiter = make_limiter(vec![("test", Some(5), None)]);

    // First 5 allowed
    for _ in 0..5 {
        assert!(limiter.check("test"), "requests under RPM limit should be allowed");
    }

    // 6th blocked
    assert!(!limiter.check("test"), "request over RPM limit must be blocked");
}

#[test]
fn rpm_exact_boundary() {
    let mut limiter = make_limiter(vec![("test", Some(1), None)]);

    assert!(limiter.check("test"), "first request should be allowed");
    assert!(!limiter.check("test"), "second request at RPM=1 must be blocked");
}

// ════════════════════════════════════════════════════════
// RPD Limit Enforced
// ════════════════════════════════════════════════════════

#[test]
fn rpd_limit_enforced() {
    let mut limiter = make_limiter(vec![("test", None, Some(3))]);

    assert!(limiter.check("test"));
    assert!(limiter.check("test"));
    assert!(limiter.check("test"));
    assert!(!limiter.check("test"), "request over RPD limit must be blocked");
}

// ════════════════════════════════════════════════════════
// Combined RPM + RPD
// ════════════════════════════════════════════════════════

#[test]
fn rpm_triggers_before_rpd_when_lower() {
    let mut limiter = make_limiter(vec![("test", Some(2), Some(100))]);

    assert!(limiter.check("test"));
    assert!(limiter.check("test"));
    assert!(!limiter.check("test"), "RPM should trigger before RPD");
}

// ════════════════════════════════════════════════════════
// Per-Service Isolation
// ════════════════════════════════════════════════════════

#[test]
fn limits_are_per_service_not_global() {
    let mut limiter = make_limiter(vec![
        ("openai", Some(2), None),
        ("anthropic", Some(2), None),
    ]);

    // Exhaust openai
    assert!(limiter.check("openai"));
    assert!(limiter.check("openai"));
    assert!(!limiter.check("openai"), "openai should be exhausted");

    // Anthropic should still work — limits are per-service
    assert!(limiter.check("anthropic"), "anthropic must have its own independent limit");
    assert!(limiter.check("anthropic"));
    assert!(!limiter.check("anthropic"));
}

#[test]
fn unconfigured_service_has_no_limit() {
    let mut limiter = make_limiter(vec![("openai", Some(1), None)]);

    // openai is limited
    assert!(limiter.check("openai"));
    assert!(!limiter.check("openai"));

    // unconfigured service is unlimited
    for _ in 0..100 {
        assert!(limiter.check("unconfigured"), "unconfigured service must have no limits");
    }
}

#[test]
fn no_limits_allows_everything() {
    let mut limiter = make_limiter(vec![]);
    for _ in 0..1000 {
        assert!(limiter.check("anything"));
    }
}
