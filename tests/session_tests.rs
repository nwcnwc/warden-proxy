//! Session management regression tests — domain matching, cookie injection,
//! storage access, and session lifecycle.

use std::collections::HashMap;
use warden_proxy::sessions::*;

// ════════════════════════════════════════════════════════
// Domain Matching
// ════════════════════════════════════════════════════════

#[test]
fn domain_match_exact() {
    assert!(domain_matches("yahoo.com", "yahoo.com"));
    assert!(domain_matches("github.com", "github.com"));
}

#[test]
fn domain_match_subdomain_matches_parent() {
    assert!(domain_matches("mail.yahoo.com", "yahoo.com"));
    assert!(domain_matches("calendar.yahoo.com", "yahoo.com"));
    assert!(domain_matches("api.github.com", "github.com"));
}

#[test]
fn domain_match_deep_subdomain() {
    assert!(domain_matches("a.b.c.yahoo.com", "yahoo.com"));
}

#[test]
fn domain_match_does_not_match_similar_domain() {
    assert!(!domain_matches("notyahoo.com", "yahoo.com"),
        "notyahoo.com must NOT match yahoo.com");
    assert!(!domain_matches("fakeyahoo.com", "yahoo.com"));
    assert!(!domain_matches("yahoo.com.evil.com", "yahoo.com"));
}

#[test]
fn domain_match_parent_does_not_match_child() {
    assert!(!domain_matches("yahoo.com", "mail.yahoo.com"));
}

#[test]
fn domain_match_case_insensitive() {
    assert!(domain_matches("Mail.Yahoo.COM", "yahoo.com"));
    assert!(domain_matches("YAHOO.COM", "yahoo.com"));
}

// ════════════════════════════════════════════════════════
// Cookie Domain Matching
// ════════════════════════════════════════════════════════

#[test]
fn cookie_dotted_domain_matches_subdomain() {
    assert!(cookie_domain_matches("mail.yahoo.com", ".yahoo.com"));
    assert!(cookie_domain_matches("calendar.yahoo.com", ".yahoo.com"));
}

#[test]
fn cookie_dotted_domain_matches_bare_domain() {
    assert!(cookie_domain_matches("yahoo.com", ".yahoo.com"));
}

#[test]
fn cookie_subdomain_does_not_match_sibling() {
    // mail.yahoo.com cookie should NOT apply to finance.yahoo.com
    assert!(!cookie_domain_matches("finance.yahoo.com", "mail.yahoo.com"),
        "subdomain cookies must not apply to sibling subdomains");
}

#[test]
fn cookie_exact_domain_matches() {
    assert!(cookie_domain_matches("mail.yahoo.com", "mail.yahoo.com"));
}

#[test]
fn cookie_unrelated_domain_no_match() {
    assert!(!cookie_domain_matches("evil.com", ".yahoo.com"));
    assert!(!cookie_domain_matches("notyahoo.com", ".yahoo.com"));
}

// ════════════════════════════════════════════════════════
// Cookie Injection Tests
// ════════════════════════════════════════════════════════

fn make_session(domain: &str, cookies: Vec<Cookie>, status: SessionStatus) -> Session {
    Session {
        domain: domain.to_string(),
        captured_at: "2026-01-01T00:00:00Z".to_string(),
        last_used: "2026-01-01T00:00:00Z".to_string(),
        status,
        cookies,
        local_storage: HashMap::new(),
        session_storage: HashMap::new(),
        auth_cookie_names: vec![],
        token_fields: vec![],
        token_map: Default::default(),
    }
}

fn make_store(sessions: Vec<Session>) -> SessionStore {
    let map: HashMap<String, Session> = sessions.into_iter()
        .map(|s| (s.domain.clone(), s))
        .collect();
    SessionStore::with_sessions(map)
}

fn make_cookie(name: &str, domain: &str, path: &str, secure: bool, expires: Option<u64>) -> Cookie {
    Cookie {
        name: name.to_string(),
        value: format!("val_{}", name),
        domain: domain.to_string(),
        path: path.to_string(),
        expires,
        secure,
        http_only: false,
        same_site: None,
    }
}

#[test]
fn secure_cookies_only_injected_on_https() {
    let store = make_store(vec![make_session("example.com", vec![
        make_cookie("secure_sess", ".example.com", "/", true, None),
    ], SessionStatus::Active)]);

    let http_cookies = store.cookies_for_request("http://example.com/page");
    assert!(http_cookies.is_empty(), "secure cookie must NOT be injected on HTTP");

    let https_cookies = store.cookies_for_request("https://example.com/page");
    assert_eq!(https_cookies.len(), 1, "secure cookie must be injected on HTTPS");
}

#[test]
fn path_matching_for_cookies() {
    let store = make_store(vec![make_session("example.com", vec![
        make_cookie("root", ".example.com", "/", false, None),
        make_cookie("api", ".example.com", "/api", false, None),
        make_cookie("admin", ".example.com", "/admin", false, None),
    ], SessionStatus::Active)]);

    // Root path gets only root cookie
    let root = store.cookies_for_request("https://example.com/other");
    assert_eq!(root.len(), 1);
    assert_eq!(root[0].name, "root");

    // /api path gets root + api cookies
    let api = store.cookies_for_request("https://example.com/api/data");
    assert_eq!(api.len(), 2);

    // /admin gets root + admin cookies
    let admin = store.cookies_for_request("https://example.com/admin/users");
    assert_eq!(admin.len(), 2);
}

#[test]
fn expired_cookies_not_injected() {
    let store = make_store(vec![make_session("example.com", vec![
        make_cookie("old", ".example.com", "/", false, Some(1)), // expired in 1970
    ], SessionStatus::Active)]);

    let cookies = store.cookies_for_request("https://example.com/");
    assert!(cookies.is_empty(), "expired cookies must not be injected");
}

#[test]
fn app_cookies_stripped_before_session_injection() {
    // Verify via source code that proxy strips Cookie header before injecting sessions
    let source = include_str!("../src/proxy.rs");
    // Cookie is in the list of stripped auth headers
    assert!(source.contains(r#""cookie""#),
        "proxy must strip cookie header from app requests");
    // Session injection happens after stripping
    assert!(source.find(r#""cookie""#).unwrap() < source.find("cookies_for_request").unwrap(),
        "cookie stripping must happen before session injection");
}

#[test]
fn session_revocation_removes_all_auth_state() {
    let mut store = make_store(vec![make_session("example.com", vec![
        make_cookie("sess", ".example.com", "/", false, None),
    ], SessionStatus::Active)]);

    // Session exists
    assert!(!store.cookies_for_request("https://example.com/").is_empty());

    // Revoke
    store.remove("example.com");

    // All auth state gone
    assert!(store.cookies_for_request("https://example.com/").is_empty());
    assert!(store.get("example.com").is_none());
}

#[test]
fn expired_session_returns_no_cookies() {
    let store = make_store(vec![make_session("example.com", vec![
        make_cookie("sess", ".example.com", "/", false, None),
    ], SessionStatus::Expired)]);

    let cookies = store.cookies_for_request("https://example.com/");
    assert!(cookies.is_empty(), "expired sessions must not inject cookies");
}

// ════════════════════════════════════════════════════════
// Storage Tests
// ════════════════════════════════════════════════════════

#[test]
fn local_storage_returned_for_matching_origin() {
    let mut local = HashMap::new();
    let mut origin_data = HashMap::new();
    origin_data.insert("auth_token".to_string(), "jwt123".to_string());
    local.insert("https://mail.yahoo.com".to_string(), origin_data);

    let session = Session {
        domain: "yahoo.com".to_string(),
        captured_at: "2026-01-01T00:00:00Z".to_string(),
        last_used: "2026-01-01T00:00:00Z".to_string(),
        status: SessionStatus::Active,
        cookies: vec![],
        local_storage: local,
        session_storage: HashMap::new(),
        auth_cookie_names: vec![],
        token_fields: vec![],
        token_map: Default::default(),
    };
    let store = make_store(vec![session]);

    let data = store.storage_for_origin("https://mail.yahoo.com").unwrap();
    assert_eq!(data.local_storage.get("auth_token").unwrap(), "jwt123");
}

#[test]
fn revoked_session_returns_empty_storage() {
    let mut local = HashMap::new();
    let mut origin_data = HashMap::new();
    origin_data.insert("token".to_string(), "secret".to_string());
    local.insert("https://mail.yahoo.com".to_string(), origin_data);

    let session = Session {
        domain: "yahoo.com".to_string(),
        captured_at: "2026-01-01T00:00:00Z".to_string(),
        last_used: "2026-01-01T00:00:00Z".to_string(),
        status: SessionStatus::Expired,
        cookies: vec![],
        local_storage: local,
        session_storage: HashMap::new(),
        auth_cookie_names: vec![],
        token_fields: vec![],
        token_map: Default::default(),
    };
    let store = make_store(vec![session]);

    assert!(store.storage_for_origin("https://mail.yahoo.com").is_none(),
        "expired/revoked sessions must return no storage");
}

#[test]
fn no_storage_for_unmatched_domain() {
    let store = make_store(vec![]);
    assert!(store.storage_for_origin("https://unknown.com").is_none());
}
