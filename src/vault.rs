use std::collections::HashMap;
use crate::config::WardenConfig;

/// Key Vault — stores API keys for external services.
/// Keys are looked up by service name (destination-based, never by request content).
pub struct KeyVault {
    services: HashMap<String, ServiceEntry>,
}

#[derive(Clone)]
pub struct ServiceEntry {
    pub header: String,
    pub value: String,
    pub base_url: String,
}

impl KeyVault {
    pub fn from_config(config: &WardenConfig) -> Self {
        let mut services = HashMap::new();

        for (name, svc) in &config.keys {
            services.insert(name.clone(), ServiceEntry {
                header: svc.header.clone(),
                value: svc.value.clone(),
                base_url: svc.base_url.trim_end_matches('/').to_string(),
            });
        }

        Self { services }
    }

    /// Look up a service by name. Returns None for unregistered services
    /// (which means: no key injection, no access).
    pub fn get_service(&self, name: &str) -> Option<&ServiceEntry> {
        self.services.get(name)
    }

    /// List all registered service names
    pub fn list_services(&self) -> Vec<&str> {
        self.services.keys().map(|s| s.as_str()).collect()
    }

    /// Build a route map: base_url -> service_name
    /// Used by the Service Worker to know which URLs to intercept
    pub fn get_route_map(&self) -> HashMap<String, String> {
        self.services.iter()
            .map(|(name, entry)| (entry.base_url.clone(), name.clone()))
            .collect()
    }
}
