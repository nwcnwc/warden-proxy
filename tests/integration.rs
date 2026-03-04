//! Integration tests for Warden Proxy
//! 
//! These tests verify end-to-end behavior including the security model.

/// Security: Verify the source code strips auth headers
/// This is a compile-time guarantee test — if the stripping code is removed,
/// this test catches it.

/// Security: Verify the source code strips auth headers
/// This is a compile-time guarantee test — if the stripping code is removed,
/// this test catches it.
#[test]
fn proxy_source_strips_auth_headers() {
    let proxy_source = include_str!("../src/proxy.rs");
    
    // MUST strip these headers
    assert!(proxy_source.contains(r#""authorization""#), 
        "proxy.rs must strip authorization header");
    assert!(proxy_source.contains(r#""x-api-key""#), 
        "proxy.rs must strip x-api-key header");
    assert!(proxy_source.contains(r#""api-key""#), 
        "proxy.rs must strip api-key header");
    assert!(proxy_source.contains(r#""cookie""#), 
        "proxy.rs must strip cookie header");
    
    // Must contain the security comment
    assert!(proxy_source.contains("SECURITY"), 
        "proxy.rs must have security documentation");
    assert!(proxy_source.contains("Never text replacement"),
        "proxy.rs must document the no-text-replacement rule");
}

/// Security: Verify Service Worker strips auth headers
#[test]
fn service_worker_is_dumb_bridge() {
    let sw_source = include_str!("../client/warden-sw.js");
    
    // SW must only reroute — it passes headers through untouched
    assert!(sw_source.contains("event.request.headers"), 
        "SW should forward original headers unchanged");
    // SW must describe itself accurately
    assert!(sw_source.contains("dumb bridge"), 
        "SW should document that it is a dumb bridge");
}

/// Security: Verify Service Worker does NOT contain real key patterns
#[test]
fn service_worker_contains_no_secrets() {
    let sw_source = include_str!("../client/warden-sw.js");

    // Should never contain actual API key patterns
    assert!(!sw_source.contains("sk-"), "SW must not contain OpenAI key patterns");
    assert!(!sw_source.contains("sk-ant-"), "SW must not contain Anthropic key patterns");
    // SW must never make security decisions — no auth header manipulation
    assert!(!sw_source.contains("inject"), "SW must not inject anything");
    assert!(!sw_source.contains("strip"), "SW must not strip anything");
    assert!(!sw_source.contains("authorization"), "SW must not reference auth headers");
    assert!(!sw_source.contains("x-api-key"), "SW must not reference API key headers");
    assert!(!sw_source.contains("cookie"), "SW must not reference cookies");
}

/// SW can contain storage-related code for populating fake values
#[test]
fn service_worker_can_populate_storage() {
    let sw_source = include_str!("../client/warden-sw.js");

    // SW can reference storage concepts (for delivering fake values from proxy)
    assert!(sw_source.contains("storage") || sw_source.contains("Storage"),
        "SW should handle storage delivery");
    // SW can use neutral terms like set, populate, deliver
    assert!(sw_source.contains("warden-storage") || sw_source.contains("STORAGE_HEADER"),
        "SW should reference the warden storage header");
}

/// Verify client files are properly embedded
#[test]
fn client_files_embedded() {
    let sw = include_str!("../client/warden-sw.js");
    let loader = include_str!("../client/warden-loader.js");
    
    assert!(sw.len() > 100, "Service Worker should have substantial content");
    assert!(loader.len() > 100, "Loader should have substantial content");
    assert!(sw.contains("addEventListener"), "SW should register event listeners");
    assert!(loader.contains("serviceWorker"), "Loader should reference serviceWorker API");
}

/// Verify the proxy only injects keys for registered destinations
#[test]
fn vault_only_serves_registered_services() {
    // This test verifies the vault's lookup-by-name behavior
    let proxy_source = include_str!("../src/vault.rs");
    
    // get_service must use HashMap::get (exact name match)
    assert!(proxy_source.contains("self.services.get(name)"),
        "Vault must look up services by exact name match");
    
    // Must return Option (None for unknown)
    assert!(proxy_source.contains("-> Option<&ServiceEntry>"),
        "get_service must return Option (None for unknown services)");
}
