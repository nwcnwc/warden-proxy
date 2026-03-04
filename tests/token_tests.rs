//! Token substitution regression tests.

use warden_proxy::tokens::*;

// ════════════════════════════════════════════════════════
// Fake Token Generation
// ════════════════════════════════════════════════════════

#[test]
fn fake_token_starts_with_wdn_prefix() {
    let fake = TokenMap::generate_fake("real-token-abc123", "example.com");
    assert!(fake.starts_with("wdn_"), "fake tokens must start with wdn_");
}

#[test]
fn fake_token_generation_is_stable() {
    let a = TokenMap::generate_fake("my-secret-token", "api.example.com");
    let b = TokenMap::generate_fake("my-secret-token", "api.example.com");
    assert_eq!(a, b, "same input must always produce same fake token");
}

#[test]
fn different_tokens_produce_different_fakes() {
    let a = TokenMap::generate_fake("token-alpha", "example.com");
    let b = TokenMap::generate_fake("token-beta", "example.com");
    assert_ne!(a, b, "different real tokens must produce different fakes");
}

#[test]
fn different_domains_produce_different_fakes() {
    let a = TokenMap::generate_fake("same-token", "alpha.com");
    let b = TokenMap::generate_fake("same-token", "beta.com");
    assert_ne!(a, b, "same token on different domains must produce different fakes");
}

// ════════════════════════════════════════════════════════
// Token Map Roundtrip
// ════════════════════════════════════════════════════════

#[test]
fn real_to_fake_to_real_roundtrip() {
    let mut map = TokenMap::new();
    let real = "sk-real-secret-key-12345";
    let fake = map.insert(real, "example.com");

    assert!(fake.starts_with("wdn_"));
    assert_eq!(map.get_real(&fake).unwrap(), real);
    assert_eq!(map.get_fake(real).unwrap(), &fake);
}

#[test]
fn inserting_same_real_returns_same_fake() {
    let mut map = TokenMap::new();
    let fake1 = map.insert("real-token", "example.com");
    let fake2 = map.insert("real-token", "example.com");
    assert_eq!(fake1, fake2, "re-inserting same real token must return same fake");
}

#[test]
fn replace_fakes_with_reals_in_text() {
    let mut map = TokenMap::new();
    let fake = map.insert("real-secret", "example.com");

    let text = format!("Bearer {}", fake);
    let result = map.replace_fakes_with_reals(&text);
    assert_eq!(result, "Bearer real-secret");
}

#[test]
fn replace_reals_with_fakes_in_text() {
    let mut map = TokenMap::new();
    let fake = map.insert("real-secret", "example.com");

    let text = "Bearer real-secret".to_string();
    let result = map.replace_reals_with_fakes(&text);
    assert_eq!(result, format!("Bearer {}", fake));
}

// ════════════════════════════════════════════════════════
// JWT Detection
// ════════════════════════════════════════════════════════

#[test]
fn detects_valid_jwt() {
    assert!(is_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"));
}

#[test]
fn rejects_non_jwt_string() {
    assert!(!is_jwt("not-a-jwt"));
    assert!(!is_jwt("sk-abc123"));
    assert!(!is_jwt("Bearer something"));
}

#[test]
fn rejects_partial_jwt() {
    assert!(!is_jwt("eyJ")); // too short
    assert!(!is_jwt("eyJhbGciOiJIUzI1NiJ9")); // only one part, no dots
}

#[test]
fn rejects_short_eyj_with_dots() {
    assert!(!is_jwt("eyJ.a.b")); // too short total
}

// ════════════════════════════════════════════════════════
// Token Substitution in JSON Bodies
// ════════════════════════════════════════════════════════

#[test]
fn substitutes_access_token_in_json_response() {
    let mut map = TokenMap::new();
    let mut json: serde_json::Value = serde_json::json!({
        "access_token": "real-jwt-token-12345",
        "token_type": "Bearer",
        "expires_in": 3600,
    });

    let changed = substitute_tokens_in_json(
        &mut json,
        &mut map,
        &[],
        "example.com",
    );

    assert!(changed, "should have substituted the access_token");
    let fake = json["access_token"].as_str().unwrap();
    assert!(fake.starts_with("wdn_"), "substituted value must be a fake token");
    assert_eq!(map.get_real(fake).unwrap(), "real-jwt-token-12345");
    // Non-token fields untouched
    assert_eq!(json["token_type"].as_str().unwrap(), "Bearer");
    assert_eq!(json["expires_in"].as_i64().unwrap(), 3600);
}

#[test]
fn substitutes_jwt_in_any_field() {
    let mut map = TokenMap::new();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let mut json: serde_json::Value = serde_json::json!({
        "custom_field": jwt,
        "other": "not-a-token",
    });

    let changed = substitute_tokens_in_json(
        &mut json,
        &mut map,
        &[],
        "example.com",
    );

    assert!(changed, "should detect JWT pattern");
    let fake = json["custom_field"].as_str().unwrap();
    assert!(fake.starts_with("wdn_"));
    assert_eq!(json["other"].as_str().unwrap(), "not-a-token");
}

#[test]
fn substitutes_custom_token_fields() {
    let mut map = TokenMap::new();
    let mut json: serde_json::Value = serde_json::json!({
        "my_custom_token": "secret-value-xyz",
        "data": "normal-data",
    });

    let changed = substitute_tokens_in_json(
        &mut json,
        &mut map,
        &["my_custom_token".to_string()],
        "example.com",
    );

    assert!(changed);
    let fake = json["my_custom_token"].as_str().unwrap();
    assert!(fake.starts_with("wdn_"));
    assert_eq!(json["data"].as_str().unwrap(), "normal-data");
}

#[test]
fn substitution_in_nested_json() {
    let mut map = TokenMap::new();
    let mut json: serde_json::Value = serde_json::json!({
        "data": {
            "access_token": "nested-real-token",
        }
    });

    let changed = substitute_tokens_in_json(
        &mut json,
        &mut map,
        &[],
        "example.com",
    );

    assert!(changed);
    let fake = json["data"]["access_token"].as_str().unwrap();
    assert!(fake.starts_with("wdn_"));
}

#[test]
fn no_substitution_when_no_tokens() {
    let mut map = TokenMap::new();
    let mut json: serde_json::Value = serde_json::json!({
        "name": "John",
        "age": 30,
    });

    let changed = substitute_tokens_in_json(
        &mut json,
        &mut map,
        &[],
        "example.com",
    );

    assert!(!changed, "should not substitute when there are no token fields");
}

#[test]
fn does_not_double_substitute_fake_tokens() {
    let mut map = TokenMap::new();
    let fake = map.insert("real-token", "example.com");

    let mut json: serde_json::Value = serde_json::json!({
        "access_token": fake,
    });

    let changed = substitute_tokens_in_json(
        &mut json,
        &mut map,
        &[],
        "example.com",
    );

    assert!(!changed, "should not re-substitute already-fake tokens");
    assert_eq!(json["access_token"].as_str().unwrap(), fake);
}

// ════════════════════════════════════════════════════════
// Token Scan
// ════════════════════════════════════════════════════════

#[test]
fn scan_finds_known_token_fields() {
    let json: serde_json::Value = serde_json::json!({
        "access_token": "real-token",
        "refresh_token": "real-refresh",
        "other": "not-a-token",
    });

    let found = scan_json_for_tokens(&json, &[], "");
    assert!(found.iter().any(|(_, v)| v == "real-token"));
    assert!(found.iter().any(|(_, v)| v == "real-refresh"));
    assert!(!found.iter().any(|(_, v)| v == "not-a-token"));
}

#[test]
fn scan_detects_jwt_in_any_field() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let json: serde_json::Value = serde_json::json!({
        "my_field": jwt,
    });

    let found = scan_json_for_tokens(&json, &[], "");
    assert!(found.iter().any(|(_, v)| v == jwt));
}
