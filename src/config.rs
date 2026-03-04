use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WardenConfig {
    pub port: u16,
    pub log_level: String,
    #[serde(default)]
    pub keys: HashMap<String, ServiceKeyConfig>,
    #[serde(default)]
    pub access: Vec<AccessRule>,
    #[serde(default)]
    pub limits: HashMap<String, LimitConfig>,
    /// Map of URL path prefix -> local directory for static file serving
    #[serde(default)]
    pub sites: HashMap<String, String>,
    /// Default directory for static files (default: ~/.warden/sites/)
    pub public_dir: Option<String>,
    /// Max request body size in bytes (default: 10MB)
    pub max_body_size: usize,
    /// Default request timeout in seconds (default: 30)
    pub request_timeout: u64,
    /// Enable structured JSON logging
    pub json_logs: bool,
    /// Traffic monitoring configuration
    #[serde(default)]
    pub traffic: TrafficConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TrafficConfig {
    /// Inspection level: "metadata", "headers", or "full"
    pub inspection_level: String,
    /// How many days to retain traffic data
    pub retention_days: u64,
    /// Maximum database size in MB
    pub max_db_size_mb: u64,
    /// Paths to exclude from traffic logging
    pub excluded_paths: Vec<String>,
    /// Whether alert detection is enabled
    pub alerts_enabled: bool,
}

impl Default for TrafficConfig {
    fn default() -> Self {
        Self {
            inspection_level: "metadata".to_string(),
            retention_days: 7,
            max_db_size_mb: 50,
            excluded_paths: vec![
                "/health".to_string(),
                "/status".to_string(),
                "/favicon.svg".to_string(),
            ],
            alerts_enabled: true,
        }
    }
}

impl Default for WardenConfig {
    fn default() -> Self {
        Self {
            port: 7400,
            log_level: "info".to_string(),
            keys: HashMap::new(),
            access: vec![],
            limits: HashMap::new(),
            sites: HashMap::new(),
            public_dir: None,
            max_body_size: 10_485_760,
            request_timeout: 30,
            json_logs: false,
            traffic: TrafficConfig::default(),
        }
    }
}

/// Configuration for a single service's API key.
/// Supports multiple key sources — each service can use a different one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceKeyConfig {
    /// HTTP header to inject (default: "Authorization")
    pub header: Option<String>,
    /// Base URL of the API service
    pub base_url: String,
    /// Direct value (legacy mode — env var interpolation supported)
    pub value: Option<String>,
    /// Key source configuration (preferred over direct value)
    pub source: Option<KeySource>,
    /// Per-service request timeout in seconds (overrides global default)
    pub timeout: Option<u64>,
}

/// Where to fetch the actual API key from.
///
/// Supported providers:
///   - "1password" / "op"     — 1Password CLI
///   - "bitwarden" / "bw"     — Bitwarden CLI
///   - "bitwarden-secrets"    — Bitwarden Secrets Manager
///   - "keyring" / "keychain" — OS keyring (macOS Keychain, Linux Secret Service, Windows)
///   - "encrypted" / "vault"  — Local encrypted vault file (~/.warden/vault.enc)
///   - "env"                  — Environment variable
///   - "inline" / "plain"     — Direct value (development only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySource {
    /// Which provider to use
    pub provider: String,

    /// Reference string (meaning depends on provider):
    ///   - 1Password: "op://Vault/Item/field" or item name
    ///   - Bitwarden: item name or ID
    ///   - Keyring: service name (default: "warden-proxy/<service>")
    ///   - Encrypted: key name in vault
    ///   - Env: environment variable name
    ///   - Inline: the actual value
    #[serde(alias = "ref")]
    pub reference: Option<String>,

    /// Alias for reference (supports "ref" in JSON which is a Rust keyword)
    #[serde(rename = "ref", skip_serializing)]
    pub ref_field: Option<String>,

    /// Prefix to prepend to resolved value (e.g., "Bearer " for Authorization headers)
    pub prefix: Option<String>,

    /// Field name for password managers (e.g., "password", "credential", "api-key")
    pub field: Option<String>,

    /// Path to vault file (for encrypted provider)
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    pub origin: String,
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitConfig {
    #[serde(default)]
    pub rpm: Option<u32>,
    #[serde(default)]
    pub rpd: Option<u32>,
}

/// Get the config directory path (~/.warden/)
pub fn config_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Could not determine home directory")
        .join(".warden")
}

/// Get the config file path
pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

/// Get the default public directory for static files
pub fn default_public_dir() -> PathBuf {
    config_dir().join("sites")
}

/// Expand ~ to home directory in paths
pub fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(&path[2..])
    } else {
        PathBuf::from(path)
    }
}

/// Interpolate environment variables: ${VAR_NAME} -> env value
fn interpolate_env(s: &str) -> String {
    let mut result = s.to_string();
    let mut search_from = 0;
    while let Some(rel_start) = result[search_from..].find("${") {
        let start = search_from + rel_start;
        if let Some(rel_end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + rel_end];
            match std::env::var(var_name) {
                Ok(value) => {
                    result = format!("{}{}{}", &result[..start], value, &result[start + rel_end + 1..]);
                    search_from = start + value.len();
                }
                Err(_) => {
                    eprintln!("⚠️  Warning: Environment variable {} not set", var_name);
                    // Skip past this ${...} to avoid infinite loop
                    search_from = start + rel_end + 1;
                }
            }
        } else {
            break;
        }
    }
    result
}

/// Load config from file, interpolating env vars in plain values
pub fn load_config() -> Result<WardenConfig, Box<dyn std::error::Error>> {
    let path = config_path();

    if !path.exists() {
        eprintln!("⚠️  No config found at {}. Run 'warden init' first.", path.display());
        eprintln!("   Using default configuration.");
        return Ok(WardenConfig::default());
    }

    let raw = fs::read_to_string(&path)?;
    // Only interpolate env vars in plain values (not in source references)
    let interpolated = interpolate_env(&raw);
    let config: WardenConfig = serde_json::from_str(&interpolated)?;

    Ok(config)
}

/// Save config to file
pub fn save_config(config: &WardenConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path();
    let json = serde_json::to_string_pretty(config)?;
    fs::write(&path, json)?;
    Ok(())
}

/// Initialize config directory and default config
pub fn init_config() -> Result<(), Box<dyn std::error::Error>> {
    let dir = config_dir();
    let path = config_path();
    let sites_dir = default_public_dir();

    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        println!("✅ Created {}", dir.display());
    }

    if !sites_dir.exists() {
        fs::create_dir_all(&sites_dir)?;
        println!("✅ Created {}", sites_dir.display());
    }

    if !path.exists() {
        let default_config = serde_json::json!({
            "port": 7400,
            "log_level": "info",
            "keys": {
                "openai": {
                    "base_url": "https://api.openai.com",
                    "header": "Authorization",
                    "source": {
                        "provider": "env",
                        "ref": "OPENAI_API_KEY",
                        "prefix": "Bearer "
                    }
                },
                "anthropic": {
                    "base_url": "https://api.anthropic.com",
                    "header": "x-api-key",
                    "source": {
                        "provider": "env",
                        "ref": "ANTHROPIC_API_KEY"
                    }
                }
            },
            "access": [
                {
                    "origin": "http://localhost:*",
                    "allow": ["openai", "anthropic"]
                }
            ],
            "limits": {
                "openai": { "rpm": 60, "rpd": 1000 },
                "anthropic": { "rpm": 30, "rpd": 500 }
            }
        });

        fs::write(&path, serde_json::to_string_pretty(&default_config)?)?;
        println!("✅ Created {}", path.display());
    } else {
        println!("ℹ️  Config already exists at {}", path.display());
    }

    println!("\n🔒 Warden initialized!");
    println!("\nNext steps:");
    println!("  1. Edit {} with your API keys and sources", path.display());
    println!("  2. Run: warden start");
    println!("\nKey source options:");
    println!("  • env          — Environment variable (default)");
    println!("  • 1password    — 1Password CLI (op)");
    println!("  • bitwarden    — Bitwarden CLI (bw)");
    println!("  • keyring      — OS keyring (Keychain, Secret Service, Credential Manager)");
    println!("  • encrypted    — Local encrypted vault (~/.warden/vault.enc)");
    println!("  • inline       — Plain text (development only)");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Env var interpolation ──

    #[test]
    fn interpolate_single_var() {
        unsafe { std::env::set_var("WARDEN_INTERP_TEST_1", "hello") };
        let result = interpolate_env("prefix_${WARDEN_INTERP_TEST_1}_suffix");
        assert_eq!(result, "prefix_hello_suffix");
        unsafe { std::env::remove_var("WARDEN_INTERP_TEST_1") };
    }

    #[test]
    fn interpolate_multiple_vars() {
        unsafe { std::env::set_var("WARDEN_INTERP_A", "foo") };
        unsafe { std::env::set_var("WARDEN_INTERP_B", "bar") };
        let result = interpolate_env("${WARDEN_INTERP_A}:${WARDEN_INTERP_B}");
        assert_eq!(result, "foo:bar");
        unsafe { std::env::remove_var("WARDEN_INTERP_A") };
        unsafe { std::env::remove_var("WARDEN_INTERP_B") };
    }

    #[test]
    fn interpolate_missing_var_preserved() {
        unsafe { std::env::remove_var("WARDEN_MISSING_VAR_XYZ") };
        let result = interpolate_env("key=${WARDEN_MISSING_VAR_XYZ}");
        assert_eq!(result, "key=${WARDEN_MISSING_VAR_XYZ}");
    }

    #[test]
    fn interpolate_no_vars_unchanged() {
        let result = interpolate_env("no variables here");
        assert_eq!(result, "no variables here");
    }

    #[test]
    fn interpolate_empty_string() {
        let result = interpolate_env("");
        assert_eq!(result, "");
    }

    // ── Config parsing ──

    #[test]
    fn parse_minimal_config() {
        let json = r#"{ "port": 8080 }"#;
        let config: WardenConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.port, 8080);
        assert!(config.keys.is_empty());
        assert!(config.access.is_empty());
    }

    #[test]
    fn parse_full_config() {
        let json = r#"{
            "port": 7400,
            "log_level": "debug",
            "keys": {
                "openai": {
                    "base_url": "https://api.openai.com",
                    "header": "Authorization",
                    "source": {
                        "provider": "env",
                        "ref": "OPENAI_API_KEY",
                        "prefix": "Bearer "
                    }
                }
            },
            "access": [
                { "origin": "http://localhost:*", "allow": ["openai"] }
            ],
            "limits": {
                "openai": { "rpm": 60, "rpd": 1000 }
            }
        }"#;
        let config: WardenConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.port, 7400);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.keys.len(), 1);
        assert_eq!(config.access.len(), 1);
        assert_eq!(config.limits.len(), 1);

        let openai = config.keys.get("openai").unwrap();
        assert_eq!(openai.base_url, "https://api.openai.com");
        let source = openai.source.as_ref().unwrap();
        assert_eq!(source.provider, "env");
        assert_eq!(source.prefix.as_deref(), Some("Bearer "));
    }

    #[test]
    fn parse_legacy_value_config() {
        let json = r#"{
            "keys": {
                "openai": {
                    "base_url": "https://api.openai.com",
                    "header": "Authorization",
                    "value": "Bearer sk-test-key"
                }
            }
        }"#;
        let config: WardenConfig = serde_json::from_str(json).unwrap();
        let openai = config.keys.get("openai").unwrap();
        assert_eq!(openai.value.as_deref(), Some("Bearer sk-test-key"));
        assert!(openai.source.is_none());
    }

    #[test]
    fn parse_multiple_providers() {
        let json = r#"{
            "keys": {
                "openai": {
                    "base_url": "https://api.openai.com",
                    "source": { "provider": "1password", "ref": "op://Dev/OpenAI/key" }
                },
                "anthropic": {
                    "base_url": "https://api.anthropic.com",
                    "source": { "provider": "env", "ref": "ANTHROPIC_KEY" }
                },
                "google": {
                    "base_url": "https://generativelanguage.googleapis.com",
                    "source": { "provider": "keyring", "ref": "warden/google" }
                }
            }
        }"#;
        let config: WardenConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.keys.len(), 3);
        assert_eq!(config.keys["openai"].source.as_ref().unwrap().provider, "1password");
        assert_eq!(config.keys["anthropic"].source.as_ref().unwrap().provider, "env");
        assert_eq!(config.keys["google"].source.as_ref().unwrap().provider, "keyring");
    }

    // ── New config fields ──

    #[test]
    fn parse_config_with_sites() {
        let json = r#"{
            "sites": { "/app": "~/my-app/dist" },
            "public_dir": "~/.warden/sites",
            "max_body_size": 5242880,
            "request_timeout": 60,
            "json_logs": true
        }"#;
        let config: WardenConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.sites.get("/app").unwrap(), "~/my-app/dist");
        assert_eq!(config.public_dir.as_deref(), Some("~/.warden/sites"));
        assert_eq!(config.max_body_size, 5_242_880);
        assert_eq!(config.request_timeout, 60);
        assert!(config.json_logs);
    }

    #[test]
    fn parse_service_with_timeout() {
        let json = r#"{
            "keys": {
                "openai": {
                    "base_url": "https://api.openai.com",
                    "header": "Authorization",
                    "value": "Bearer test",
                    "timeout": 120
                }
            }
        }"#;
        let config: WardenConfig = serde_json::from_str(json).unwrap();
        let openai = config.keys.get("openai").unwrap();
        assert_eq!(openai.timeout, Some(120));
    }

    // ── Default values ──

    #[test]
    fn defaults_applied_for_missing_fields() {
        let json = r#"{}"#;
        let config: WardenConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.port, 7400);
        assert_eq!(config.log_level, "info");
        assert!(config.keys.is_empty());
        assert_eq!(config.max_body_size, 10_485_760);
        assert_eq!(config.request_timeout, 30);
        assert!(!config.json_logs);
    }

    // ── Config paths ──

    #[test]
    fn config_dir_is_in_home() {
        let dir = config_dir();
        assert!(dir.ends_with(".warden"));
    }

    #[test]
    fn config_path_is_json_in_dir() {
        let path = config_path();
        assert!(path.ends_with("config.json"));
    }

    // ── Path expansion ──

    #[test]
    fn expand_tilde_path() {
        let expanded = expand_path("~/foo/bar");
        assert!(!expanded.to_string_lossy().starts_with("~"));
        assert!(expanded.to_string_lossy().ends_with("foo/bar"));
    }

    #[test]
    fn expand_absolute_path_unchanged() {
        let expanded = expand_path("/tmp/test");
        assert_eq!(expanded, PathBuf::from("/tmp/test"));
    }
}
