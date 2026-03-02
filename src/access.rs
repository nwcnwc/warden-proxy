use serde::Serialize;
use crate::config::WardenConfig;

/// Origin-based access controller.
/// Determines which browser origins can access which backend services.
pub struct AccessController {
    rules: Vec<AccessRule>,
}

#[derive(Clone, Serialize)]
struct AccessRule {
    origin: String,
    allow: Vec<String>,
}

impl AccessController {
    pub fn from_config(config: &WardenConfig) -> Self {
        let rules = config.access.iter().map(|r| AccessRule {
            origin: r.origin.clone(),
            allow: r.allow.clone(),
        }).collect();

        Self { rules }
    }

    /// Check if an origin is allowed to access a service.
    /// No rules = open mode (allow all) for development.
    pub fn is_allowed(&self, origin: &str, service: &str) -> bool {
        if self.rules.is_empty() {
            return true;
        }

        let clean_origin = origin.trim_end_matches('/');

        for rule in &self.rules {
            if match_origin(clean_origin, &rule.origin) {
                if rule.allow.contains(&"*".to_string()) || rule.allow.contains(&service.to_string()) {
                    return true;
                }
            }
        }

        false
    }

    pub fn list_rules(&self) -> Vec<serde_json::Value> {
        self.rules.iter().map(|r| {
            serde_json::json!({
                "origin": r.origin,
                "allow": r.allow,
            })
        }).collect()
    }
}

fn match_origin(origin: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if origin.is_empty() {
        return false;
    }
    if pattern.contains('*') {
        // Convert wildcard pattern to simple matching
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            return origin.starts_with(parts[0]) && origin.ends_with(parts[1]);
        }
    }
    origin == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_when_no_rules() {
        let ac = AccessController { rules: vec![] };
        assert!(ac.is_allowed("http://evil.com", "openai"));
    }

    #[test]
    fn enforce_rules() {
        let ac = AccessController {
            rules: vec![AccessRule {
                origin: "http://localhost:3000".to_string(),
                allow: vec!["openai".to_string()],
            }],
        };
        assert!(ac.is_allowed("http://localhost:3000", "openai"));
        assert!(!ac.is_allowed("http://evil.com", "openai"));
    }

    #[test]
    fn wildcard_origins() {
        let ac = AccessController {
            rules: vec![AccessRule {
                origin: "http://localhost:*".to_string(),
                allow: vec!["openai".to_string()],
            }],
        };
        assert!(ac.is_allowed("http://localhost:3000", "openai"));
        assert!(ac.is_allowed("http://localhost:8080", "openai"));
        assert!(!ac.is_allowed("http://evil.com", "openai"));
    }
}
