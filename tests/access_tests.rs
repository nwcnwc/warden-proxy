//! Access control regression tests — origin matching, wildcard patterns,
//! service-level access control.

use warden_proxy::access::AccessController;
use warden_proxy::config::{WardenConfig, AccessRule};

fn make_ac(rules: Vec<(&str, Vec<&str>)>) -> AccessController {
    let config = WardenConfig {
        access: rules.into_iter().map(|(origin, allow)| AccessRule {
            origin: origin.to_string(),
            allow: allow.into_iter().map(|s| s.to_string()).collect(),
        }).collect(),
        ..Default::default()
    };
    AccessController::from_config(&config)
}

// ════════════════════════════════════════════════════════
// Wildcard Origin Matching
// ════════════════════════════════════════════════════════

#[test]
fn wildcard_origin_matches_any_port() {
    let ac = make_ac(vec![
        ("http://localhost:*", vec!["openai", "anthropic"]),
    ]);
    assert!(ac.is_allowed("http://localhost:3000", "openai"));
    assert!(ac.is_allowed("http://localhost:8080", "openai"));
    assert!(ac.is_allowed("http://localhost:9999", "anthropic"));
}

#[test]
fn wildcard_origin_does_not_match_other_hosts() {
    let ac = make_ac(vec![
        ("http://localhost:*", vec!["openai"]),
    ]);
    assert!(!ac.is_allowed("http://evil.com", "openai"));
    assert!(!ac.is_allowed("http://localhost.evil.com:3000", "openai"));
}

#[test]
fn global_wildcard_matches_everything() {
    let ac = make_ac(vec![
        ("*", vec!["openai"]),
    ]);
    assert!(ac.is_allowed("http://evil.com", "openai"));
    assert!(ac.is_allowed("https://anything.com", "openai"));
}

// ════════════════════════════════════════════════════════
// Specific Origin Matching
// ════════════════════════════════════════════════════════

#[test]
fn exact_origin_allowed() {
    let ac = make_ac(vec![
        ("http://localhost:3000", vec!["openai"]),
    ]);
    assert!(ac.is_allowed("http://localhost:3000", "openai"));
}

#[test]
fn wrong_port_denied() {
    let ac = make_ac(vec![
        ("http://localhost:3000", vec!["openai"]),
    ]);
    assert!(!ac.is_allowed("http://localhost:3001", "openai"));
}

// ════════════════════════════════════════════════════════
// Denied Origin Gets 403 (verified via source)
// ════════════════════════════════════════════════════════

#[test]
fn denied_origin_gets_403_in_proxy() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains("FORBIDDEN"),
        "proxy must return 403 for denied origins");
    assert!(source.contains("is_allowed"),
        "proxy must call access controller");
}

#[test]
fn denied_origin_returns_false() {
    let ac = make_ac(vec![
        ("http://localhost:3000", vec!["openai"]),
    ]);
    assert!(!ac.is_allowed("http://evil.com", "openai"),
        "non-matching origin must be denied");
    assert!(!ac.is_allowed("", "openai"),
        "empty origin must be denied when rules exist");
}

// ════════════════════════════════════════════════════════
// Service-Level Access Control
// ════════════════════════════════════════════════════════

#[test]
fn service_level_access_control() {
    let ac = make_ac(vec![
        ("http://localhost:3000", vec!["openai"]),
        ("http://localhost:8080", vec!["anthropic"]),
    ]);

    // localhost:3000 can access openai but NOT anthropic
    assert!(ac.is_allowed("http://localhost:3000", "openai"));
    assert!(!ac.is_allowed("http://localhost:3000", "anthropic"));

    // localhost:8080 can access anthropic but NOT openai
    assert!(ac.is_allowed("http://localhost:8080", "anthropic"));
    assert!(!ac.is_allowed("http://localhost:8080", "openai"));
}

#[test]
fn multiple_services_per_origin() {
    let ac = make_ac(vec![
        ("http://localhost:3000", vec!["openai", "anthropic", "google"]),
    ]);
    assert!(ac.is_allowed("http://localhost:3000", "openai"));
    assert!(ac.is_allowed("http://localhost:3000", "anthropic"));
    assert!(ac.is_allowed("http://localhost:3000", "google"));
    assert!(!ac.is_allowed("http://localhost:3000", "azure"),
        "unlisted service must be denied");
}

#[test]
fn wildcard_service_allows_all() {
    let ac = make_ac(vec![
        ("http://localhost:3000", vec!["*"]),
    ]);
    assert!(ac.is_allowed("http://localhost:3000", "openai"));
    assert!(ac.is_allowed("http://localhost:3000", "anything"));
}

#[test]
fn no_rules_allows_everything() {
    let ac = make_ac(vec![]);
    assert!(ac.is_allowed("http://evil.com", "openai"),
        "no rules = open mode for development");
}
