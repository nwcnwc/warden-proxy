use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::config::WardenConfig;

/// Per-service rate limiter with sliding window counters.
pub struct RateLimiter {
    limits: HashMap<String, ServiceLimit>,
    counters: HashMap<String, Vec<u64>>,
}

struct ServiceLimit {
    rpm: Option<u32>,
    rpd: Option<u32>,
}

impl RateLimiter {
    pub fn from_config(config: &WardenConfig) -> Self {
        let limits = config.limits.iter().map(|(name, l)| {
            (name.clone(), ServiceLimit { rpm: l.rpm, rpd: l.rpd })
        }).collect();

        Self {
            limits,
            counters: HashMap::new(),
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Check if a request is allowed (under rate limit).
    /// Returns true if allowed, false if rate limited.
    pub fn check(&mut self, service: &str) -> bool {
        let limit = match self.limits.get(service) {
            Some(l) => l,
            None => return true, // No limits configured
        };

        let now = Self::now_ms();
        let requests = self.counters.entry(service.to_string()).or_default();

        // Clean old entries (older than 24h)
        requests.retain(|&t| t > now - 86_400_000);

        // Check per-minute limit
        if let Some(rpm) = limit.rpm {
            let minute_count = requests.iter().filter(|&&t| t > now - 60_000).count();
            if minute_count >= rpm as usize {
                return false;
            }
        }

        // Check per-day limit
        if let Some(rpd) = limit.rpd {
            if requests.len() >= rpd as usize {
                return false;
            }
        }

        // Record this request
        requests.push(now);
        true
    }

    pub fn get_status(&self) -> serde_json::Value {
        let now = Self::now_ms();
        let mut status = serde_json::Map::new();

        for (service, limit) in &self.limits {
            let requests = self.counters.get(service);
            let reqs = requests.map(|r| r.as_slice()).unwrap_or(&[]);

            let minute_count = reqs.iter().filter(|&&t| t > now - 60_000).count();
            let day_count = reqs.iter().filter(|&&t| t > now - 86_400_000).count();

            status.insert(service.clone(), serde_json::json!({
                "limits": { "rpm": limit.rpm, "rpd": limit.rpd },
                "usage": { "last_minute": minute_count, "last_day": day_count },
            }));
        }

        serde_json::Value::Object(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LimitConfig;

    fn make_limiter(limits: Vec<(&str, Option<u32>, Option<u32>)>) -> RateLimiter {
        let config = WardenConfig {
            limits: limits.into_iter().map(|(name, rpm, rpd)| {
                (name.to_string(), LimitConfig { rpm, rpd })
            }).collect(),
            ..Default::default()
        };
        RateLimiter::from_config(&config)
    }

    // ── RPM limits ──

    #[test]
    fn allows_under_rpm_limit() {
        let mut limiter = make_limiter(vec![("openai", Some(5), None)]);
        for _ in 0..5 {
            assert!(limiter.check("openai"));
        }
    }

    #[test]
    fn blocks_over_rpm_limit() {
        let mut limiter = make_limiter(vec![("test", Some(2), None)]);
        assert!(limiter.check("test"));
        assert!(limiter.check("test"));
        assert!(!limiter.check("test"));
    }

    #[test]
    fn rpm_limit_at_exact_boundary() {
        let mut limiter = make_limiter(vec![("test", Some(3), None)]);
        assert!(limiter.check("test")); // 1
        assert!(limiter.check("test")); // 2
        assert!(limiter.check("test")); // 3 — at limit
        assert!(!limiter.check("test")); // 4 — over
    }

    // ── RPD limits ──

    #[test]
    fn blocks_over_rpd_limit() {
        let mut limiter = make_limiter(vec![("test", None, Some(3))]);
        assert!(limiter.check("test"));
        assert!(limiter.check("test"));
        assert!(limiter.check("test"));
        assert!(!limiter.check("test")); // Over daily limit
    }

    // ── Combined limits ──

    #[test]
    fn rpm_and_rpd_both_enforced() {
        // 2 per minute, 10 per day — RPM should trigger first
        let mut limiter = make_limiter(vec![("test", Some(2), Some(10))]);
        assert!(limiter.check("test"));
        assert!(limiter.check("test"));
        assert!(!limiter.check("test")); // RPM hit before RPD
    }

    // ── No limits ──

    #[test]
    fn no_limits_allows_everything() {
        let mut limiter = make_limiter(vec![]);
        for _ in 0..100 {
            assert!(limiter.check("anything"));
        }
    }

    #[test]
    fn unlisted_service_always_allowed() {
        let mut limiter = make_limiter(vec![("openai", Some(1), None)]);
        // openai is limited, but "other" is not configured
        assert!(limiter.check("other"));
        assert!(limiter.check("other"));
        assert!(limiter.check("other"));
    }

    // ── Per-service isolation ──

    #[test]
    fn limits_are_per_service() {
        let mut limiter = make_limiter(vec![
            ("openai", Some(2), None),
            ("anthropic", Some(2), None),
        ]);
        assert!(limiter.check("openai"));
        assert!(limiter.check("openai"));
        assert!(!limiter.check("openai")); // openai exhausted

        // anthropic should still be fine
        assert!(limiter.check("anthropic"));
        assert!(limiter.check("anthropic"));
        assert!(!limiter.check("anthropic"));
    }

    // ── Status reporting ──

    #[test]
    fn get_status_reports_usage() {
        let mut limiter = make_limiter(vec![("openai", Some(10), Some(100))]);
        limiter.check("openai");
        limiter.check("openai");
        limiter.check("openai");

        let status = limiter.get_status();
        let openai = status.get("openai").unwrap();
        let usage = openai.get("usage").unwrap();
        assert_eq!(usage.get("last_minute").unwrap().as_u64().unwrap(), 3);
        assert_eq!(usage.get("last_day").unwrap().as_u64().unwrap(), 3);
    }

    #[test]
    fn get_status_empty_when_no_requests() {
        let limiter = make_limiter(vec![("openai", Some(10), None)]);
        let status = limiter.get_status();
        let openai = status.get("openai").unwrap();
        let usage = openai.get("usage").unwrap();
        assert_eq!(usage.get("last_minute").unwrap().as_u64().unwrap(), 0);
    }
}
