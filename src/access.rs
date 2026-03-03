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

    fn make_ac(rules: Vec<(&str, Vec<&str>)>) -> AccessController {
        AccessController {
            rules: rules.into_iter().map(|(origin, allow)| AccessRule {
                origin: origin.to_string(),
                allow: allow.into_iter().map(|s| s.to_string()).collect(),
            }).collect(),
        }
    }

    // ── Open mode (no rules) ──

    #[test]
    fn allow_all_when_no_rules() {
        let ac = make_ac(vec![]);
        assert!(ac.is_allowed("http://evil.com", "openai"));
        assert!(ac.is_allowed("", "anything"));
        assert!(ac.is_allowed("http://localhost:3000", "anthropic"));
    }

    // ── Exact origin matching ──

    #[test]
    fn enforce_exact_origin() {
        let ac = make_ac(vec![
            ("http://localhost:3000", vec!["openai"]),
        ]);
        assert!(ac.is_allowed("http://localhost:3000", "openai"));
        assert!(!ac.is_allowed("http://localhost:3001", "openai"));
        assert!(!ac.is_allowed("http://evil.com", "openai"));
    }

    #[test]
    fn deny_wrong_service_for_allowed_origin() {
        let ac = make_ac(vec![
            ("http://localhost:3000", vec!["openai"]),
        ]);
        assert!(ac.is_allowed("http://localhost:3000", "openai"));
        assert!(!ac.is_allowed("http://localhost:3000", "anthropic"));
    }

    #[test]
    fn multiple_services_per_origin() {
        let ac = make_ac(vec![
            ("http://localhost:3000", vec!["openai", "anthropic", "google"]),
        ]);
        assert!(ac.is_allowed("http://localhost:3000", "openai"));
        assert!(ac.is_allowed("http://localhost:3000", "anthropic"));
        assert!(ac.is_allowed("http://localhost:3000", "google"));
        assert!(!ac.is_allowed("http://localhost:3000", "azure"));
    }

    #[test]
    fn multiple_rules_different_origins() {
        let ac = make_ac(vec![
            ("http://localhost:3000", vec!["openai"]),
            ("http://localhost:8080", vec!["anthropic"]),
        ]);
        assert!(ac.is_allowed("http://localhost:3000", "openai"));
        assert!(!ac.is_allowed("http://localhost:3000", "anthropic"));
        assert!(ac.is_allowed("http://localhost:8080", "anthropic"));
        assert!(!ac.is_allowed("http://localhost:8080", "openai"));
    }

    // ── Wildcard matching ──

    #[test]
    fn wildcard_origins() {
        let ac = make_ac(vec![
            ("http://localhost:*", vec!["openai"]),
        ]);
        assert!(ac.is_allowed("http://localhost:3000", "openai"));
        assert!(ac.is_allowed("http://localhost:8080", "openai"));
        assert!(ac.is_allowed("http://localhost:9999", "openai"));
        assert!(!ac.is_allowed("http://evil.com", "openai"));
    }

    #[test]
    fn wildcard_all_origins() {
        let ac = make_ac(vec![
            ("*", vec!["openai"]),
        ]);
        assert!(ac.is_allowed("http://evil.com", "openai"));
        assert!(ac.is_allowed("http://localhost:3000", "openai"));
        assert!(ac.is_allowed("https://anything.anywhere.com", "openai"));
    }

    #[test]
    fn wildcard_all_services() {
        let ac = make_ac(vec![
            ("http://localhost:3000", vec!["*"]),
        ]);
        assert!(ac.is_allowed("http://localhost:3000", "openai"));
        assert!(ac.is_allowed("http://localhost:3000", "anthropic"));
        assert!(ac.is_allowed("http://localhost:3000", "anything"));
        assert!(!ac.is_allowed("http://evil.com", "openai"));
    }

    // ── Edge cases ──

    #[test]
    fn trailing_slash_stripped() {
        let ac = make_ac(vec![
            ("http://localhost:3000", vec!["openai"]),
        ]);
        assert!(ac.is_allowed("http://localhost:3000/", "openai"));
    }

    #[test]
    fn empty_origin_denied_when_rules_exist() {
        let ac = make_ac(vec![
            ("http://localhost:3000", vec!["openai"]),
        ]);
        assert!(!ac.is_allowed("", "openai"));
    }

    #[test]
    fn unknown_service_always_denied() {
        let ac = make_ac(vec![
            ("http://localhost:3000", vec!["openai"]),
        ]);
        assert!(!ac.is_allowed("http://localhost:3000", "nonexistent"));
    }

    // ── list_rules ──

    #[test]
    fn list_rules_returns_all() {
        let ac = make_ac(vec![
            ("http://localhost:3000", vec!["openai"]),
            ("http://localhost:8080", vec!["anthropic"]),
        ]);
        assert_eq!(ac.list_rules().len(), 2);
    }
}
