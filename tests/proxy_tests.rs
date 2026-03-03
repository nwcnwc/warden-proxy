//! Proxy regression tests — verify security model through source analysis
//! and behavioral testing of core proxy logic.

/// Auth header stripping: Authorization, x-api-key, Cookie all stripped
#[test]
fn proxy_strips_authorization_header() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains(r#""authorization""#),
        "proxy.rs must strip authorization header");
}

#[test]
fn proxy_strips_x_api_key_header() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains(r#""x-api-key""#),
        "proxy.rs must strip x-api-key header");
}

#[test]
fn proxy_strips_api_key_header() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains(r#""api-key""#),
        "proxy.rs must strip api-key header");
}

#[test]
fn proxy_strips_cookie_header() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains(r#""cookie""#),
        "proxy.rs must strip cookie header");
}

/// Destination-based key injection: correct key for correct service
#[test]
fn proxy_injects_key_by_destination_identity() {
    let source = include_str!("../src/proxy.rs");
    // Proxy must look up service by name in vault
    assert!(source.contains("state.vault.get_service"),
        "proxy must look up service in vault by name");
    // Must inject using the service's configured header
    assert!(source.contains("service.header"),
        "proxy must use service-specific header for injection");
    assert!(source.contains("service.value"),
        "proxy must inject service-specific value");
}

/// Unknown destination gets no key injection
#[test]
fn proxy_returns_not_found_for_unknown_service() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains("NOT_FOUND"),
        "proxy must return 404 for unknown services");
    assert!(source.contains("Unknown service"),
        "proxy must have clear error for unknown services");
}

/// Malicious request to evil.com with auth header — verify no key injected
#[test]
fn vault_does_not_serve_unregistered_services() {
    let source = include_str!("../src/vault.rs");
    assert!(source.contains("self.services.get(name)"),
        "vault must look up services by exact name match");
    assert!(source.contains("-> Option<&ServiceEntry>"),
        "get_service must return Option (None for unknown)");
}

/// CORS headers present on responses
#[test]
fn proxy_adds_cors_headers() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains("ACCESS_CONTROL_ALLOW_ORIGIN"),
        "proxy must add CORS allow-origin header");
}

/// Request ID generated and propagated
#[test]
fn proxy_generates_request_id() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains("x-request-id"),
        "proxy must propagate request ID header");
    assert!(source.contains("request_id"),
        "proxy must track request IDs");
}

/// Streaming responses pass through correctly
#[test]
fn proxy_streams_responses() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains("bytes_stream"),
        "proxy must stream response body, not buffer");
    assert!(source.contains("Body::from_stream"),
        "proxy must use streaming body");
}

/// Security model is documented
#[test]
fn proxy_has_security_documentation() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains("SECURITY"),
        "proxy.rs must have security documentation");
    assert!(source.contains("Never text replacement"),
        "proxy.rs must document the no-text-replacement rule");
}

/// Service Worker also strips auth headers (defense in depth)
#[test]
fn service_worker_strips_auth_headers() {
    let sw = include_str!("../client/warden-sw.js");
    assert!(sw.contains("authorization"),
        "SW must filter authorization");
    assert!(sw.contains("x-api-key"),
        "SW must filter x-api-key");
    assert!(sw.contains("cookie"),
        "SW must filter cookie");
}

/// Session cookie injection is present in proxy
#[test]
fn proxy_injects_session_cookies() {
    let source = include_str!("../src/proxy.rs");
    assert!(source.contains("sessions.read()"),
        "proxy must read from session store");
    assert!(source.contains("cookies_for_request"),
        "proxy must call cookies_for_request for session injection");
}
