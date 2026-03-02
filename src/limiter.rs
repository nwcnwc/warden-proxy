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

    #[test]
    fn allows_under_limit() {
        let config = WardenConfig {
            port: 7400,
            log_level: "info".to_string(),
            keys: HashMap::new(),
            access: vec![],
            limits: HashMap::from([
                ("openai".to_string(), LimitConfig { rpm: Some(5), rpd: None }),
            ]),
        };
        let mut limiter = RateLimiter::from_config(&config);
        assert!(limiter.check("openai"));
        assert!(limiter.check("openai"));
    }

    #[test]
    fn blocks_over_limit() {
        let config = WardenConfig {
            port: 7400,
            log_level: "info".to_string(),
            keys: HashMap::new(),
            access: vec![],
            limits: HashMap::from([
                ("test".to_string(), LimitConfig { rpm: Some(2), rpd: None }),
            ]),
        };
        let mut limiter = RateLimiter::from_config(&config);
        assert!(limiter.check("test"));
        assert!(limiter.check("test"));
        assert!(!limiter.check("test")); // Over limit
    }
}
