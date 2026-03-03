use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WardenConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub keys: HashMap<String, ServiceKeyConfig>,
    #[serde(default)]
    pub access: Vec<AccessRule>,
    #[serde(default)]
    pub limits: HashMap<String, LimitConfig>,
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

fn default_port() -> u16 { 7400 }
fn default_log_level() -> String { "info".to_string() }

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

/// Interpolate environment variables: ${VAR_NAME} -> env value
fn interpolate_env(s: &str) -> String {
    let mut result = s.to_string();
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let value = std::env::var(var_name).unwrap_or_else(|_| {
                eprintln!("⚠️  Warning: Environment variable {} not set", var_name);
                format!("${{{}}}", var_name)
            });
            result = format!("{}{}{}", &result[..start], value, &result[start + end + 1..]);
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
        return Ok(WardenConfig {
            port: 7400,
            log_level: "info".to_string(),
            keys: HashMap::new(),
            access: vec![],
            limits: HashMap::new(),
        });
    }

    let raw = fs::read_to_string(&path)?;
    // Only interpolate env vars in plain values (not in source references)
    let interpolated = interpolate_env(&raw);
    let config: WardenConfig = serde_json::from_str(&interpolated)?;

    Ok(config)
}

/// Initialize config directory and default config
pub fn init_config() -> Result<(), Box<dyn std::error::Error>> {
    let dir = config_dir();
    let path = config_path();

    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        println!("✅ Created {}", dir.display());
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

    // ── Default values ──

    #[test]
    fn defaults_applied_for_missing_fields() {
        let json = r#"{}"#;
        let config: WardenConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.port, 7400);
        assert_eq!(config.log_level, "info");
        assert!(config.keys.is_empty());
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
}
