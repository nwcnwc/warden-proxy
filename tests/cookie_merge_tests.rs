//! Cookie merge strategy regression tests.
//!
//! Tests verify that auth cookies are replaced while operational cookies
//! (CSRF, tracking, preferences) are kept and passed through.

use std::collections::HashMap;
use warden_proxy::sessions::*;
use warden_proxy::tokens::TokenMap;

fn make_cookie(name: &str, value: &str, domain: &str, path: &str) -> Cookie {
    Cookie {
        name: name.to_string(),
        value: value.to_string(),
        domain: domain.to_string(),
        path: path.to_string(),
        expires: None,
        secure: false,
        http_only: false,
        same_site: None,
    }
}

fn make_session_with_auth(
    domain: &str,
    cookies: Vec<Cookie>,
    auth_names: Vec<&str>,
) -> Session {
    Session {
        domain: domain.to_string(),
        captured_at: "2026-01-01T00:00:00Z".to_string(),
        last_used: "2026-01-01T00:00:00Z".to_string(),
        status: SessionStatus::Active,
        cookies,
        local_storage: HashMap::new(),
        session_storage: HashMap::new(),
        auth_cookie_names: auth_names.into_iter().map(String::from).collect(),
        token_fields: vec![],
        token_map: TokenMap::new(),
    }
}

fn make_store(sessions: Vec<Session>) -> SessionStore {
    let map: HashMap<String, Session> = sessions.into_iter()
        .map(|s| (s.domain.clone(), s))
        .collect();
    SessionStore::with_sessions(map)
}

// ════════════════════════════════════════════════════════
// Auth Cookie Identification
// ════════════════════════════════════════════════════════

#[test]
fn auth_cookie_names_stored_on_session() {
    let session = make_session_with_auth(
        "example.com",
        vec![
            make_cookie("session_id", "real-session", ".example.com", "/"),
            make_cookie("auth_token", "real-auth", ".example.com", "/"),
        ],
        vec!["session_id", "auth_token"],
    );

    assert_eq!(session.auth_cookie_names.len(), 2);
    assert!(session.auth_cookie_names.contains(&"session_id".to_string()));
    assert!(session.auth_cookie_names.contains(&"auth_token".to_string()));
}

// ════════════════════════════════════════════════════════
// Cookie Merge: Outgoing Requests
// ════════════════════════════════════════════════════════

#[test]
fn auth_cookies_replaced_operational_cookies_kept() {
    // Simulate the merge logic that proxy.rs performs
    let session = make_session_with_auth(
        "example.com",
        vec![
            make_cookie("session_id", "real-session-value", ".example.com", "/"),
        ],
        vec!["session_id"],
    );

    let auth_cookie_names = &session.auth_cookie_names;

    // App sends these cookies (session_id is fake, csrf is operational)
    let app_cookies = vec![
        ("session_id".to_string(), "fake-session-value".to_string()),
        ("csrf_token".to_string(), "abc123csrf".to_string()),
        ("tracking".to_string(), "ga_xyz".to_string()),
    ];

    // Merge: discard app auth cookies, keep operational, add real auth
    let mut merged: Vec<(String, String)> = Vec::new();

    for (name, val) in &app_cookies {
        if auth_cookie_names.iter().any(|a| a == name) {
            continue; // Discard fake auth cookie
        }
        merged.push((name.clone(), val.clone()));
    }

    // Add real auth cookies
    for c in &session.cookies {
        merged.push((c.name.clone(), c.value.clone()));
    }

    // Verify: real session_id + operational csrf + tracking
    assert_eq!(merged.len(), 3);

    // Auth cookie has real value (not the app's fake)
    let session_cookie = merged.iter().find(|(n, _)| n == "session_id").unwrap();
    assert_eq!(session_cookie.1, "real-session-value");

    // Operational cookies preserved as-is
    let csrf = merged.iter().find(|(n, _)| n == "csrf_token").unwrap();
    assert_eq!(csrf.1, "abc123csrf");

    let tracking = merged.iter().find(|(n, _)| n == "tracking").unwrap();
    assert_eq!(tracking.1, "ga_xyz");
}

#[test]
fn csrf_cookie_from_app_passes_through() {
    let auth_names = vec!["session_id".to_string()];

    let app_cookies = vec![
        ("csrf_token".to_string(), "csrf-real-value".to_string()),
    ];

    let mut merged: Vec<(String, String)> = Vec::new();
    for (name, val) in &app_cookies {
        if auth_names.iter().any(|a| a == name) {
            continue;
        }
        merged.push((name.clone(), val.clone()));
    }

    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].0, "csrf_token");
    assert_eq!(merged[0].1, "csrf-real-value");
}

#[test]
fn auth_cookie_from_app_discarded_real_one_used() {
    let session = make_session_with_auth(
        "example.com",
        vec![
            make_cookie("auth", "REAL_AUTH_VALUE", ".example.com", "/"),
        ],
        vec!["auth"],
    );

    // App sends a fake auth cookie
    let app_cookies = vec![
        ("auth".to_string(), "FAKE_AUTH_FROM_APP".to_string()),
    ];

    let mut merged: Vec<(String, String)> = Vec::new();
    for (name, val) in &app_cookies {
        if session.auth_cookie_names.iter().any(|a| a == name) {
            continue; // Discard
        }
        merged.push((name.clone(), val.clone()));
    }
    for c in &session.cookies {
        merged.push((c.name.clone(), c.value.clone()));
    }

    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].0, "auth");
    assert_eq!(merged[0].1, "REAL_AUTH_VALUE", "must use real cookie, not app's fake");
}

// ════════════════════════════════════════════════════════
// Cookie Merge: Incoming Responses (Set-Cookie)
// ════════════════════════════════════════════════════════

#[test]
fn set_cookie_for_auth_cookie_gets_fake_value() {
    let auth_names = vec!["session_id".to_string()];
    let domain = "example.com";

    // Server sends a Set-Cookie for an auth cookie
    let set_cookie = "session_id=new-real-session-value; Path=/; HttpOnly";

    // Parse cookie name
    let eq_pos = set_cookie.find('=').unwrap();
    let cookie_name = &set_cookie[..eq_pos];
    let is_auth = auth_names.iter().any(|a| a == cookie_name);

    assert!(is_auth, "session_id should be recognized as auth cookie");

    // Extract value
    let after_eq = &set_cookie[eq_pos+1..];
    let value_end = after_eq.find(';').unwrap_or(after_eq.len());
    let real_value = &after_eq[..value_end];

    // Generate fake
    let fake_value = TokenMap::generate_fake(real_value, domain);
    assert!(fake_value.starts_with("wdn_"));

    // Rewrite Set-Cookie
    let fake_set_cookie = format!(
        "{}={}{}",
        cookie_name,
        fake_value,
        if value_end < after_eq.len() { &after_eq[value_end..] } else { "" }
    );

    assert!(fake_set_cookie.starts_with("session_id=wdn_"));
    assert!(fake_set_cookie.contains("; Path=/; HttpOnly"));
}

#[test]
fn set_cookie_for_operational_cookie_passes_through() {
    let auth_names = vec!["session_id".to_string()];

    let set_cookie = "csrf_token=new-csrf-value; Path=/";

    let eq_pos = set_cookie.find('=').unwrap();
    let cookie_name = &set_cookie[..eq_pos];
    let is_auth = auth_names.iter().any(|a| a == cookie_name);

    assert!(!is_auth, "csrf_token should NOT be treated as auth cookie");
    // Operational Set-Cookie passes through untouched
}

// ════════════════════════════════════════════════════════
// Merged Cookie Header
// ════════════════════════════════════════════════════════

#[test]
fn merged_cookie_header_has_both_auth_and_operational() {
    let session = make_session_with_auth(
        "example.com",
        vec![
            make_cookie("session_id", "real-session", ".example.com", "/"),
            make_cookie("auth_tok", "real-auth", ".example.com", "/"),
        ],
        vec!["session_id", "auth_tok"],
    );

    // App sends: fake auth + real operational
    let app_cookies = vec![
        ("session_id".to_string(), "fake-session".to_string()),
        ("auth_tok".to_string(), "fake-auth".to_string()),
        ("_ga".to_string(), "GA1.2.12345".to_string()),
        ("csrf".to_string(), "csrf-val".to_string()),
    ];

    let mut merged: Vec<(String, String)> = Vec::new();

    // Keep operational
    for (name, val) in &app_cookies {
        if session.auth_cookie_names.iter().any(|a| a == name) {
            continue;
        }
        merged.push((name.clone(), val.clone()));
    }

    // Add real auth
    for c in &session.cookies {
        merged.push((c.name.clone(), c.value.clone()));
    }

    // Build header
    let header = merged.iter()
        .map(|(n, v)| format!("{}={}", n, v))
        .collect::<Vec<_>>()
        .join("; ");

    // Must contain real auth values
    assert!(header.contains("session_id=real-session"));
    assert!(header.contains("auth_tok=real-auth"));
    // Must contain operational values
    assert!(header.contains("_ga=GA1.2.12345"));
    assert!(header.contains("csrf=csrf-val"));
    // Must NOT contain fake values
    assert!(!header.contains("fake-session"));
    assert!(!header.contains("fake-auth"));
}

// ════════════════════════════════════════════════════════
// Session Store: cookies_for_request still works
// ════════════════════════════════════════════════════════

#[test]
fn cookies_for_request_returns_session_cookies() {
    let store = make_store(vec![make_session_with_auth(
        "example.com",
        vec![
            make_cookie("sess", "real-val", ".example.com", "/"),
        ],
        vec!["sess"],
    )]);

    let cookies = store.cookies_for_request("https://example.com/api");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "sess");
    assert_eq!(cookies[0].value, "real-val");
}
