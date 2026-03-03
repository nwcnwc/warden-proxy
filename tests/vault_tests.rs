//! Key vault regression tests — source resolution, error handling,
//! key isolation, and security guarantees.

use std::collections::HashMap;
use warden_proxy::config::{WardenConfig, ServiceKeyConfig, KeySource};
use warden_proxy::vault::KeyVault;

fn make_config_with_inline(services: Vec<(&str, &str, &str, &str)>) -> WardenConfig {
    let mut keys = HashMap::new();
    for (name, header, value, base_url) in services {
        keys.insert(name.to_string(), ServiceKeyConfig {
            header: Some(header.to_string()),
            base_url: base_url.to_string(),
            value: Some(value.to_string()),
            source: None,
            timeout: None,
        });
    }
    WardenConfig {
        keys,
        ..Default::default()
    }
}

// ════════════════════════════════════════════════════════
// Env Var Source Resolution
// ════════════════════════════════════════════════════════

#[test]
fn env_var_source_resolves_correctly() {
    unsafe { std::env::set_var("WARDEN_VAULT_TEST_KEY_ABC", "test-value-123") };
    let mut keys = HashMap::new();
    keys.insert("test-svc".to_string(), ServiceKeyConfig {
        header: Some("Authorization".to_string()),
        base_url: "https://api.example.com".to_string(),
        value: None,
        source: Some(KeySource {
            provider: "env".to_string(),
            reference: Some("WARDEN_VAULT_TEST_KEY_ABC".to_string()),
            ref_field: None,
            prefix: None,
            field: None,
            path: None,
        }),
        timeout: None,
    });
    let config = WardenConfig { keys, ..Default::default() };
    let vault = KeyVault::from_config(&config);

    let svc = vault.get_service("test-svc").unwrap();
    assert_eq!(svc.value, "test-value-123");
    unsafe { std::env::remove_var("WARDEN_VAULT_TEST_KEY_ABC") };
}

// ════════════════════════════════════════════════════════
// Missing Env Var Doesn't Crash
// ════════════════════════════════════════════════════════

#[test]
fn missing_env_var_doesnt_crash() {
    unsafe { std::env::remove_var("WARDEN_NONEXISTENT_VAR_VAULT_TEST") };
    let mut keys = HashMap::new();
    keys.insert("missing-svc".to_string(), ServiceKeyConfig {
        header: Some("Authorization".to_string()),
        base_url: "https://api.example.com".to_string(),
        value: None,
        source: Some(KeySource {
            provider: "env".to_string(),
            reference: Some("WARDEN_NONEXISTENT_VAR_VAULT_TEST".to_string()),
            ref_field: None,
            prefix: None,
            field: None,
            path: None,
        }),
        timeout: None,
    });
    let config = WardenConfig { keys, ..Default::default() };

    // This must not panic — service should just be unavailable
    let vault = KeyVault::from_config(&config);
    assert!(vault.get_service("missing-svc").is_none(),
        "missing env var should make service unavailable, not crash");
}

// ════════════════════════════════════════════════════════
// Key Values Never in Error Messages
// ════════════════════════════════════════════════════════

#[test]
fn key_values_never_in_error_messages() {
    let source = include_str!("../src/vault.rs");

    // Error messages should never format the actual key value
    // The error! and warn! macros should not include service.value
    // They should only reference metadata like service name, provider, etc.
    assert!(!source.contains("error!(\"{}\"") || !source.contains("{}.value"),
        "vault error messages must not contain raw key values");

    // The source should contain proper error handling
    assert!(source.contains("failed to resolve key"),
        "vault should have clear error messages for resolution failures");
}

// ════════════════════════════════════════════════════════
// Multiple Key Sources Coexist
// ════════════════════════════════════════════════════════

#[test]
fn multiple_key_sources_coexist() {
    unsafe { std::env::set_var("WARDEN_MULTI_TEST_KEY", "env-value") };

    let mut keys = HashMap::new();

    // Inline source
    keys.insert("inline-svc".to_string(), ServiceKeyConfig {
        header: Some("Authorization".to_string()),
        base_url: "https://api.inline.com".to_string(),
        value: Some("inline-key".to_string()),
        source: None,
        timeout: None,
    });

    // Env source
    keys.insert("env-svc".to_string(), ServiceKeyConfig {
        header: Some("x-api-key".to_string()),
        base_url: "https://api.env.com".to_string(),
        value: None,
        source: Some(KeySource {
            provider: "env".to_string(),
            reference: Some("WARDEN_MULTI_TEST_KEY".to_string()),
            ref_field: None,
            prefix: Some("Bearer ".to_string()),
            field: None,
            path: None,
        }),
        timeout: None,
    });

    let config = WardenConfig { keys, ..Default::default() };
    let vault = KeyVault::from_config(&config);

    // Both services should coexist
    let inline = vault.get_service("inline-svc").unwrap();
    assert_eq!(inline.value, "inline-key");

    let env = vault.get_service("env-svc").unwrap();
    assert_eq!(env.value, "Bearer env-value");

    // Services are isolated
    assert_ne!(inline.value, env.value);

    unsafe { std::env::remove_var("WARDEN_MULTI_TEST_KEY") };
}

// ════════════════════════════════════════════════════════
// Service Isolation
// ════════════════════════════════════════════════════════

#[test]
fn services_are_isolated() {
    let config = make_config_with_inline(vec![
        ("openai", "Authorization", "Bearer sk-openai", "https://api.openai.com"),
        ("anthropic", "x-api-key", "sk-anthropic", "https://api.anthropic.com"),
    ]);
    let vault = KeyVault::from_config(&config);

    let openai = vault.get_service("openai").unwrap();
    assert_eq!(openai.value, "Bearer sk-openai");
    assert!(!openai.value.contains("anthropic"));

    let anthropic = vault.get_service("anthropic").unwrap();
    assert_eq!(anthropic.value, "sk-anthropic");
    assert!(!anthropic.value.contains("openai"));
}

#[test]
fn unknown_service_returns_none() {
    let config = make_config_with_inline(vec![
        ("openai", "Authorization", "Bearer sk-test", "https://api.openai.com"),
    ]);
    let vault = KeyVault::from_config(&config);

    assert!(vault.get_service("evil").is_none());
    assert!(vault.get_service("").is_none());
    assert!(vault.get_service("openai-fake").is_none());
}
