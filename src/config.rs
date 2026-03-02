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
    pub keys: HashMap<String, ServiceConfig>,
    #[serde(default)]
    pub access: Vec<AccessRule>,
    #[serde(default)]
    pub limits: HashMap<String, LimitConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub header: String,
    pub value: String,
    pub base_url: String,
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

/// Load config from file, interpolating env vars
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
                    "header": "Authorization",
                    "value": "Bearer ${OPENAI_API_KEY}",
                    "base_url": "https://api.openai.com"
                },
                "anthropic": {
                    "header": "x-api-key",
                    "value": "${ANTHROPIC_API_KEY}",
                    "base_url": "https://api.anthropic.com"
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
    println!("  1. Edit {} with your API keys", path.display());
    println!("  2. Set environment variables (OPENAI_API_KEY, etc.)");
    println!("  3. Run: warden start");

    Ok(())
}
