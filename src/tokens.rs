use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Known token field names to scan for in JSON response bodies.
pub const TOKEN_FIELD_NAMES: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "jwt",
    "api_key",
    "apiKey",
    "accessToken",
    "refreshToken",
    "idToken",
];

/// Bidirectional mapping between real and fake tokens.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenMap {
    /// fake → real
    pub fake_to_real: HashMap<String, String>,
    /// real → fake
    pub real_to_fake: HashMap<String, String>,
}

impl TokenMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a stable fake token for a real token + domain.
    /// Format: "wdn_" + hex(sha256(real_token + domain))[0..32]
    pub fn generate_fake(real_token: &str, domain: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(real_token.as_bytes());
        hasher.update(domain.as_bytes());
        let hash = hasher.finalize();
        format!("wdn_{}", hex::encode(&hash[..16]))
    }

    /// Insert a real↔fake mapping. Returns the fake token.
    pub fn insert(&mut self, real: &str, domain: &str) -> String {
        // Check if we already have a mapping for this real token
        if let Some(fake) = self.real_to_fake.get(real) {
            return fake.clone();
        }
        let fake = Self::generate_fake(real, domain);
        self.fake_to_real.insert(fake.clone(), real.to_string());
        self.real_to_fake.insert(real.to_string(), fake.clone());
        fake
    }

    /// Look up the real token for a fake.
    pub fn get_real(&self, fake: &str) -> Option<&String> {
        self.fake_to_real.get(fake)
    }

    /// Look up the fake token for a real.
    pub fn get_fake(&self, real: &str) -> Option<&String> {
        self.real_to_fake.get(real)
    }

    /// Replace all known fake tokens in text with their real equivalents.
    pub fn replace_fakes_with_reals(&self, text: &str) -> String {
        let mut result = text.to_string();
        for (fake, real) in &self.fake_to_real {
            result = result.replace(fake, real);
        }
        result
    }

    /// Replace all known real tokens in text with their fake equivalents.
    pub fn replace_reals_with_fakes(&self, text: &str) -> String {
        let mut result = text.to_string();
        for (real, fake) in &self.real_to_fake {
            result = result.replace(real, fake);
        }
        result
    }
}

/// Detect if a string looks like a JWT (eyJ... with 2 dots).
pub fn is_jwt(s: &str) -> bool {
    s.starts_with("eyJ") && s.matches('.').count() == 2 && s.len() > 20
}

/// Scan a JSON value for token fields and JWT patterns.
/// Returns a list of (field_path, token_value) pairs found.
pub fn scan_json_for_tokens(
    value: &serde_json::Value,
    token_fields: &[String],
    prefix: &str,
) -> Vec<(String, String)> {
    let mut found = Vec::new();

    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };

                // Check if this key is a known token field
                let is_token_field = token_fields.iter().any(|f| f == key)
                    || TOKEN_FIELD_NAMES.iter().any(|&f| f == key);

                if is_token_field {
                    if let Some(s) = val.as_str() {
                        if !s.is_empty() {
                            found.push((path.clone(), s.to_string()));
                        }
                    }
                }

                // Also check for JWT patterns in any string value
                if let Some(s) = val.as_str() {
                    if is_jwt(s) && !found.iter().any(|(_, v)| v == s) {
                        found.push((path.clone(), s.to_string()));
                    }
                }

                // Recurse into nested objects/arrays
                found.extend(scan_json_for_tokens(val, token_fields, &path));
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let path = format!("{}[{}]", prefix, i);
                found.extend(scan_json_for_tokens(val, token_fields, &path));
            }
        }
        _ => {}
    }

    found
}

/// Replace real token values in a JSON value with fakes using the token map.
/// Returns the modified JSON and whether any replacements were made.
pub fn substitute_tokens_in_json(
    value: &mut serde_json::Value,
    token_map: &mut TokenMap,
    token_fields: &[String],
    domain: &str,
) -> bool {
    let mut changed = false;

    match value {
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let is_token_field = token_fields.iter().any(|f| f == &key)
                    || TOKEN_FIELD_NAMES.iter().any(|&f| f == key);

                if is_token_field {
                    if let Some(serde_json::Value::String(s)) = map.get(&key) {
                        if !s.is_empty() && !s.starts_with("wdn_") {
                            let real = s.clone();
                            let fake = token_map.insert(&real, domain);
                            map.insert(key.clone(), serde_json::Value::String(fake));
                            changed = true;
                            continue;
                        }
                    }
                }

                // Check for JWT in any string field
                if let Some(serde_json::Value::String(s)) = map.get(&key) {
                    if is_jwt(s) && !s.starts_with("wdn_") {
                        let real = s.clone();
                        let fake = token_map.insert(&real, domain);
                        map.insert(key.clone(), serde_json::Value::String(fake));
                        changed = true;
                        continue;
                    }
                }

                // Recurse
                if let Some(val) = map.get_mut(&key) {
                    if substitute_tokens_in_json(val, token_map, token_fields, domain) {
                        changed = true;
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr.iter_mut() {
                if substitute_tokens_in_json(val, token_map, token_fields, domain) {
                    changed = true;
                }
            }
        }
        _ => {}
    }

    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_token_starts_with_prefix() {
        let fake = TokenMap::generate_fake("real-token-123", "example.com");
        assert!(fake.starts_with("wdn_"), "fake token must start with wdn_");
    }

    #[test]
    fn fake_token_is_stable() {
        let a = TokenMap::generate_fake("real-token-123", "example.com");
        let b = TokenMap::generate_fake("real-token-123", "example.com");
        assert_eq!(a, b, "same input must produce same fake token");
    }

    #[test]
    fn different_inputs_produce_different_fakes() {
        let a = TokenMap::generate_fake("token-a", "example.com");
        let b = TokenMap::generate_fake("token-b", "example.com");
        assert_ne!(a, b);
    }

    #[test]
    fn roundtrip_real_fake_real() {
        let mut map = TokenMap::new();
        let fake = map.insert("real-secret-token", "example.com");
        assert!(fake.starts_with("wdn_"));
        let real = map.get_real(&fake).unwrap();
        assert_eq!(real, "real-secret-token");
    }

    #[test]
    fn jwt_detection() {
        assert!(is_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"));
        assert!(!is_jwt("not-a-jwt"));
        assert!(!is_jwt("eyJ")); // too short
        assert!(!is_jwt("eyJhbGciOiJIUzI1NiJ9")); // only one part
    }
}
