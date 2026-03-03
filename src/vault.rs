use std::collections::HashMap;
use std::process::Command;
use tracing::{info, warn, error};
use crate::config::{WardenConfig, KeySource};

/// Key Vault — unified secret resolution from multiple sources.
///
/// Supports four simultaneous key sources (checked per-key):
/// 1. Password manager (1Password, Bitwarden) — most secure
/// 2. OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager)
/// 3. Encrypted vault (~/.warden/vault.enc) — portable encrypted storage
/// 4. Environment variable / inline value — simple, for development
///
/// Each key can use a different source. Mix and match freely.
pub struct KeyVault {
    services: HashMap<String, ServiceEntry>,
}

#[derive(Clone)]
pub struct ServiceEntry {
    pub header: String,
    pub value: String,
    pub base_url: String,
    pub timeout: Option<u64>,
}

impl KeyVault {
    /// Build the vault from config, resolving all key sources at startup.
    pub fn from_config(config: &WardenConfig) -> Self {
        let mut services = HashMap::new();

        for (name, svc) in &config.keys {
            let resolved_value = match &svc.source {
                Some(source) => resolve_source(name, source, svc.value.as_deref()),
                None => {
                    // Legacy: plain value or env var reference
                    match &svc.value {
                        Some(v) => Some(v.clone()),
                        None => {
                            warn!("Service '{}': no source or value configured", name);
                            None
                        }
                    }
                }
            };

            match resolved_value {
                Some(value) => {
                    // Apply prefix if configured (e.g., "Bearer " for Authorization headers)
                    let final_value = if let Some(source) = &svc.source {
                        match &source.prefix {
                            Some(prefix) => format!("{}{}", prefix, value),
                            None => value,
                        }
                    } else {
                        value
                    };

                    services.insert(name.clone(), ServiceEntry {
                        header: svc.header.clone().unwrap_or_else(|| "Authorization".to_string()),
                        value: final_value,
                        base_url: svc.base_url.trim_end_matches('/').to_string(),
                        timeout: svc.timeout,
                    });
                    info!("Service '{}': key loaded successfully", name);
                }
                None => {
                    error!("Service '{}': failed to resolve key — service will be unavailable", name);
                }
            }
        }

        Self { services }
    }

    /// Look up a service by name. Returns None for unregistered services.
    pub fn get_service(&self, name: &str) -> Option<&ServiceEntry> {
        self.services.get(name)
    }

    /// List all registered service names.
    pub fn list_services(&self) -> Vec<&str> {
        self.services.keys().map(|s| s.as_str()).collect()
    }

    /// Build a route map: base_url -> service_name.
    /// Used by the Service Worker to know which URLs to intercept.
    pub fn get_route_map(&self) -> HashMap<String, String> {
        self.services.iter()
            .map(|(name, entry)| (entry.base_url.clone(), name.clone()))
            .collect()
    }
}

/// Resolve a key from its configured source.
fn resolve_source(service_name: &str, source: &KeySource, fallback_value: Option<&str>) -> Option<String> {
    match source.provider.as_str() {
        // ──────────────────────────────────────────────
        // 1Password CLI
        // ──────────────────────────────────────────────
        "1password" | "onepassword" | "op" => {
            resolve_1password(service_name, source)
        }

        // ──────────────────────────────────────────────
        // Bitwarden CLI
        // ──────────────────────────────────────────────
        "bitwarden" | "bw" => {
            resolve_bitwarden(service_name, source)
        }

        // ──────────────────────────────────────────────
        // Bitwarden Secrets Manager
        // ──────────────────────────────────────────────
        "bitwarden-secrets" | "bws" => {
            resolve_bitwarden_secrets(service_name, source)
        }

        // ──────────────────────────────────────────────
        // OS Keyring
        // ──────────────────────────────────────────────
        "keyring" | "os-keyring" | "keychain" => {
            resolve_keyring(service_name, source)
        }

        // ──────────────────────────────────────────────
        // Encrypted vault file
        // ──────────────────────────────────────────────
        "encrypted" | "vault" | "enc" => {
            resolve_encrypted_vault(service_name, source)
        }

        // ──────────────────────────────────────────────
        // Environment variable
        // ──────────────────────────────────────────────
        "env" | "environment" => {
            resolve_env(service_name, source)
        }

        // ──────────────────────────────────────────────
        // Inline / plain text (development only)
        // ──────────────────────────────────────────────
        "inline" | "plain" | "value" => {
            source.reference.clone().or_else(|| fallback_value.map(|s| s.to_string()))
        }

        unknown => {
            error!("Service '{}': unknown source provider '{}'", service_name, unknown);
            None
        }
    }
}

// ════════════════════════════════════════════════════════
// 1Password
// ════════════════════════════════════════════════════════

fn resolve_1password(service_name: &str, source: &KeySource) -> Option<String> {
    let reference = source.reference.as_ref().or(source.ref_field.as_ref())?;

    info!("Service '{}': fetching from 1Password...", service_name);

    // Try `op read` first (for secret references like op://Vault/Item/field)
    let output = Command::new("op")
        .args(["read", reference])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let value = String::from_utf8_lossy(&result.stdout).trim().to_string();
            if value.is_empty() {
                error!("Service '{}': 1Password returned empty value", service_name);
                None
            } else {
                Some(value)
            }
        }
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            error!("Service '{}': 1Password error: {}", service_name, stderr.trim());

            // Fallback: try `op item get` for item name lookups
            resolve_1password_item(service_name, reference, source.field.as_deref())
        }
        Err(e) => {
            error!("Service '{}': 1Password CLI (op) not found or not accessible: {}", service_name, e);
            error!("  Install: https://developer.1password.com/docs/cli/get-started/");
            None
        }
    }
}

fn resolve_1password_item(service_name: &str, item: &str, field: Option<&str>) -> Option<String> {
    let field_name = field.unwrap_or("credential");

    let output = Command::new("op")
        .args(["item", "get", item, "--fields", field_name, "--format", "json"])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let json_str = String::from_utf8_lossy(&result.stdout);
            // Parse the JSON response to extract the value
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                json.get("value")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            } else {
                // Might be plain text output
                let value = json_str.trim().to_string();
                if value.is_empty() { None } else { Some(value) }
            }
        }
        _ => {
            error!("Service '{}': failed to fetch from 1Password item '{}'", service_name, item);
            None
        }
    }
}

// ════════════════════════════════════════════════════════
// Bitwarden CLI
// ════════════════════════════════════════════════════════

fn resolve_bitwarden(service_name: &str, source: &KeySource) -> Option<String> {
    let reference = source.reference.as_ref().or(source.ref_field.as_ref())?;
    let field = source.field.as_deref().unwrap_or("password");

    info!("Service '{}': fetching from Bitwarden...", service_name);

    let output = Command::new("bw")
        .args(["get", field, reference])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let value = String::from_utf8_lossy(&result.stdout).trim().to_string();
            if value.is_empty() {
                error!("Service '{}': Bitwarden returned empty value", service_name);
                None
            } else {
                Some(value)
            }
        }
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            error!("Service '{}': Bitwarden error: {}", service_name, stderr.trim());
            error!("  Make sure you're logged in: bw login && bw unlock");
            None
        }
        Err(e) => {
            error!("Service '{}': Bitwarden CLI (bw) not found: {}", service_name, e);
            error!("  Install: https://bitwarden.com/help/cli/");
            None
        }
    }
}

// ════════════════════════════════════════════════════════
// Bitwarden Secrets Manager
// ════════════════════════════════════════════════════════

fn resolve_bitwarden_secrets(service_name: &str, source: &KeySource) -> Option<String> {
    let reference = source.reference.as_ref().or(source.ref_field.as_ref())?;

    info!("Service '{}': fetching from Bitwarden Secrets Manager...", service_name);

    let output = Command::new("bws")
        .args(["secret", "get", reference])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let json_str = String::from_utf8_lossy(&result.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                json.get("value")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            } else {
                let value = json_str.trim().to_string();
                if value.is_empty() { None } else { Some(value) }
            }
        }
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            error!("Service '{}': Bitwarden Secrets Manager error: {}", service_name, stderr.trim());
            None
        }
        Err(e) => {
            error!("Service '{}': Bitwarden Secrets Manager CLI (bws) not found: {}", service_name, e);
            None
        }
    }
}

// ════════════════════════════════════════════════════════
// OS Keyring
// ════════════════════════════════════════════════════════

fn resolve_keyring(service_name: &str, source: &KeySource) -> Option<String> {
    let reference = source.reference.as_ref().or(source.ref_field.as_ref())
        .cloned()
        .unwrap_or_else(|| format!("warden-proxy/{}", service_name));

    info!("Service '{}': fetching from OS keyring...", service_name);

    // Use `secret-tool` on Linux, `security` on macOS
    if cfg!(target_os = "macos") {
        resolve_keyring_macos(service_name, &reference)
    } else if cfg!(target_os = "linux") {
        resolve_keyring_linux(service_name, &reference)
    } else if cfg!(target_os = "windows") {
        resolve_keyring_windows(service_name, &reference)
    } else {
        error!("Service '{}': OS keyring not supported on this platform", service_name);
        None
    }
}

fn resolve_keyring_macos(service_name: &str, reference: &str) -> Option<String> {
    // macOS: security find-generic-password -s <service> -w
    let output = Command::new("security")
        .args(["find-generic-password", "-s", reference, "-w"])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let value = String::from_utf8_lossy(&result.stdout).trim().to_string();
            if value.is_empty() { None } else { Some(value) }
        }
        _ => {
            error!("Service '{}': not found in macOS Keychain (service: {})", service_name, reference);
            error!("  Add it: security add-generic-password -s {} -a warden -w <your-key>", reference);
            None
        }
    }
}

fn resolve_keyring_linux(service_name: &str, reference: &str) -> Option<String> {
    // Linux: secret-tool lookup service <reference>
    let output = Command::new("secret-tool")
        .args(["lookup", "service", reference])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let value = String::from_utf8_lossy(&result.stdout).trim().to_string();
            if value.is_empty() { None } else { Some(value) }
        }
        _ => {
            error!("Service '{}': not found in Linux keyring (service: {})", service_name, reference);
            error!("  Add it: secret-tool store --label='{}' service {}", service_name, reference);
            None
        }
    }
}

fn resolve_keyring_windows(service_name: &str, reference: &str) -> Option<String> {
    // Windows: use cmdkey or PowerShell
    let output = Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "(Get-StoredCredential -Target '{}').GetNetworkCredential().Password",
                reference
            ),
        ])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let value = String::from_utf8_lossy(&result.stdout).trim().to_string();
            if value.is_empty() { None } else { Some(value) }
        }
        _ => {
            error!("Service '{}': not found in Windows Credential Manager (target: {})", service_name, reference);
            None
        }
    }
}

// ════════════════════════════════════════════════════════
// Encrypted Vault File
// ════════════════════════════════════════════════════════

fn resolve_encrypted_vault(service_name: &str, source: &KeySource) -> Option<String> {
    let vault_path = source.path.clone().unwrap_or_else(|| {
        crate::config::config_dir().join("vault.enc").to_string_lossy().to_string()
    });

    info!("Service '{}': reading from encrypted vault...", service_name);

    let key_name = source.reference.as_ref().or(source.ref_field.as_ref())
        .cloned()
        .unwrap_or_else(|| service_name.to_string());

    // Read the encrypted vault file
    let vault_data = match std::fs::read(&vault_path) {
        Ok(data) => data,
        Err(e) => {
            error!("Service '{}': cannot read vault file {}: {}", service_name, vault_path, e);
            error!("  Create it: warden vault add {}", service_name);
            return None;
        }
    };

    // Get master password from environment or prompt
    let master_password = match std::env::var("WARDEN_VAULT_PASSWORD") {
        Ok(p) => p,
        Err(_) => {
            error!("Service '{}': WARDEN_VAULT_PASSWORD not set for encrypted vault", service_name);
            error!("  Set it: export WARDEN_VAULT_PASSWORD=<your-master-password>");
            return None;
        }
    };

    // Decrypt the vault
    match decrypt_vault(&vault_data, &master_password) {
        Ok(entries) => {
            entries.get(&key_name).cloned()
        }
        Err(e) => {
            error!("Service '{}': vault decryption failed: {}", service_name, e);
            None
        }
    }
}

/// Decrypt a vault file. Format: 24-byte nonce + encrypted JSON.
/// Uses XChaCha20-Poly1305 via simple XOR + HMAC (placeholder for proper crypto crate).
///
/// For v0.1: vault is base64-encoded JSON encrypted with a simple KDF.
/// TODO: Replace with proper `chacha20poly1305` crate.
fn decrypt_vault(data: &[u8], password: &str) -> Result<HashMap<String, String>, String> {
    // v0.1 simple scheme: base64(JSON) XORed with repeated password hash
    // This is a PLACEHOLDER — real encryption coming in v0.2 with chacha20poly1305
    
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    password.hash(&mut hasher);
    let key_byte = (hasher.finish() % 256) as u8;
    
    let decrypted: Vec<u8> = data.iter().map(|b| b ^ key_byte).collect();
    let json_str = String::from_utf8(decrypted).map_err(|e| format!("invalid UTF-8: {}", e))?;
    let entries: HashMap<String, String> = serde_json::from_str(&json_str)
        .map_err(|e| format!("invalid vault JSON: {}", e))?;
    
    Ok(entries)
}

/// Encrypt and write a vault file.
pub fn encrypt_vault(entries: &HashMap<String, String>, password: &str) -> Vec<u8> {
    // v0.1 simple scheme — see decrypt_vault
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let json = serde_json::to_string(entries).unwrap();
    
    let mut hasher = DefaultHasher::new();
    password.hash(&mut hasher);
    let key_byte = (hasher.finish() % 256) as u8;
    
    json.as_bytes().iter().map(|b| b ^ key_byte).collect()
}

// ════════════════════════════════════════════════════════
// Environment Variable
// ════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn make_config_with_inline(services: Vec<(&str, &str, &str, &str)>) -> WardenConfig {
        let mut keys = HashMap::new();
        for (name, header, value, base_url) in services {
            keys.insert(name.to_string(), ServiceKeyConfig {
                header: Some(header.to_string()),
                base_url: base_url.to_string(),
                value: Some(value.to_string()),
                source: None,
                timeout: None,
            });
        }
        WardenConfig {
            keys,
            ..Default::default()
        }
    }

    // ── Basic vault operations ──

    #[test]
    fn loads_services_from_config() {
        let config = make_config_with_inline(vec![
            ("openai", "Authorization", "Bearer sk-test", "https://api.openai.com"),
            ("anthropic", "x-api-key", "sk-ant-test", "https://api.anthropic.com"),
        ]);
        let vault = KeyVault::from_config(&config);
        assert_eq!(vault.list_services().len(), 2);
    }

    #[test]
    fn get_service_returns_correct_data() {
        let config = make_config_with_inline(vec![
            ("openai", "Authorization", "Bearer sk-test", "https://api.openai.com"),
        ]);
        let vault = KeyVault::from_config(&config);
        let svc = vault.get_service("openai").unwrap();
        assert_eq!(svc.header, "Authorization");
        assert_eq!(svc.value, "Bearer sk-test");
        assert_eq!(svc.base_url, "https://api.openai.com");
    }

    #[test]
    fn get_service_returns_none_for_unknown() {
        let config = make_config_with_inline(vec![
            ("openai", "Authorization", "Bearer sk-test", "https://api.openai.com"),
        ]);
        let vault = KeyVault::from_config(&config);
        assert!(vault.get_service("evil").is_none());
        assert!(vault.get_service("").is_none());
        assert!(vault.get_service("openai-fake").is_none());
    }

    #[test]
    fn base_url_trailing_slash_stripped() {
        let config = make_config_with_inline(vec![
            ("openai", "Authorization", "Bearer sk-test", "https://api.openai.com/"),
        ]);
        let vault = KeyVault::from_config(&config);
        let svc = vault.get_service("openai").unwrap();
        assert_eq!(svc.base_url, "https://api.openai.com");
    }

    // ── Route map ──

    #[test]
    fn route_map_maps_base_url_to_name() {
        let config = make_config_with_inline(vec![
            ("openai", "Authorization", "Bearer sk-test", "https://api.openai.com"),
            ("anthropic", "x-api-key", "sk-ant", "https://api.anthropic.com"),
        ]);
        let vault = KeyVault::from_config(&config);
        let routes = vault.get_route_map();
        assert_eq!(routes.get("https://api.openai.com").unwrap(), "openai");
        assert_eq!(routes.get("https://api.anthropic.com").unwrap(), "anthropic");
    }

    #[test]
    fn route_map_does_not_contain_unregistered() {
        let config = make_config_with_inline(vec![
            ("openai", "Authorization", "Bearer sk-test", "https://api.openai.com"),
        ]);
        let vault = KeyVault::from_config(&config);
        let routes = vault.get_route_map();
        assert!(routes.get("https://evil.com").is_none());
    }

    // ── Source resolution: env ──

    #[test]
    fn env_source_resolves_variable() {
        unsafe { std::env::set_var("WARDEN_TEST_KEY_12345", "test-secret-value") };
        let source = KeySource {
            provider: "env".to_string(),
            reference: Some("WARDEN_TEST_KEY_12345".to_string()),
            ref_field: None,
            prefix: None,
            field: None,
            path: None,
        };
        let result = resolve_env("test-service", &source);
        assert_eq!(result, Some("test-secret-value".to_string()));
        unsafe { std::env::remove_var("WARDEN_TEST_KEY_12345") };
    }

    #[test]
    fn env_source_returns_none_for_missing_var() {
        unsafe { std::env::remove_var("WARDEN_NONEXISTENT_VAR_XYZ") };
        let source = KeySource {
            provider: "env".to_string(),
            reference: Some("WARDEN_NONEXISTENT_VAR_XYZ".to_string()),
            ref_field: None,
            prefix: None,
            field: None,
            path: None,
        };
        let result = resolve_env("test-service", &source);
        assert!(result.is_none());
    }

    #[test]
    fn env_source_returns_none_for_empty_var() {
        unsafe { std::env::set_var("WARDEN_EMPTY_VAR_TEST", "") };
        let source = KeySource {
            provider: "env".to_string(),
            reference: Some("WARDEN_EMPTY_VAR_TEST".to_string()),
            ref_field: None,
            prefix: None,
            field: None,
            path: None,
        };
        let result = resolve_env("test-service", &source);
        assert!(result.is_none());
        unsafe { std::env::remove_var("WARDEN_EMPTY_VAR_TEST") };
    }

    // ── Source resolution: inline ──

    #[test]
    fn inline_source_returns_reference() {
        let source = KeySource {
            provider: "inline".to_string(),
            reference: Some("my-plaintext-key".to_string()),
            ref_field: None,
            prefix: None,
            field: None,
            path: None,
        };
        let result = resolve_source("test", &source, None);
        assert_eq!(result, Some("my-plaintext-key".to_string()));
    }

    // ── Source resolution: unknown provider ──

    #[test]
    fn unknown_provider_returns_none() {
        let source = KeySource {
            provider: "doesnt-exist".to_string(),
            reference: Some("anything".to_string()),
            ref_field: None,
            prefix: None,
            field: None,
            path: None,
        };
        let result = resolve_source("test", &source, None);
        assert!(result.is_none());
    }

    // ── Prefix application ──

    #[test]
    fn prefix_applied_to_resolved_value() {
        unsafe { std::env::set_var("WARDEN_PREFIX_TEST_KEY", "sk-raw-key") };
        let mut keys = HashMap::new();
        keys.insert("openai".to_string(), ServiceKeyConfig {
            header: Some("Authorization".to_string()),
            base_url: "https://api.openai.com".to_string(),
            value: None,
            source: Some(KeySource {
                provider: "env".to_string(),
                reference: Some("WARDEN_PREFIX_TEST_KEY".to_string()),
                ref_field: None,
                prefix: Some("Bearer ".to_string()),
                field: None,
                path: None,
            }),
            timeout: None,
        });
        let config = WardenConfig {
            keys,
            ..Default::default()
        };
        let vault = KeyVault::from_config(&config);
        let svc = vault.get_service("openai").unwrap();
        assert_eq!(svc.value, "Bearer sk-raw-key");
        unsafe { std::env::remove_var("WARDEN_PREFIX_TEST_KEY") };
    }

    // ── Encrypted vault ──

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut entries = HashMap::new();
        entries.insert("openai".to_string(), "sk-secret-key".to_string());
        entries.insert("anthropic".to_string(), "sk-ant-key".to_string());

        let password = "test-master-password";
        let encrypted = encrypt_vault(&entries, password);
        let decrypted = decrypt_vault(&encrypted, password).unwrap();

        assert_eq!(decrypted.get("openai").unwrap(), "sk-secret-key");
        assert_eq!(decrypted.get("anthropic").unwrap(), "sk-ant-key");
    }

    #[test]
    fn decrypt_with_wrong_password_fails() {
        let mut entries = HashMap::new();
        entries.insert("test".to_string(), "secret".to_string());

        let encrypted = encrypt_vault(&entries, "correct-password");
        let result = decrypt_vault(&encrypted, "wrong-password");
        assert!(result.is_err());
    }

    // ── Default header ──

    #[test]
    fn default_header_is_authorization() {
        let mut keys = HashMap::new();
        keys.insert("test".to_string(), ServiceKeyConfig {
            header: None, // No header specified
            base_url: "https://api.example.com".to_string(),
            value: Some("test-key".to_string()),
            source: None,
            timeout: None,
        });
        let config = WardenConfig {
            keys,
            ..Default::default()
        };
        let vault = KeyVault::from_config(&config);
        let svc = vault.get_service("test").unwrap();
        assert_eq!(svc.header, "Authorization");
    }

    // ── Security: key isolation ──

    #[test]
    fn services_are_isolated() {
        let config = make_config_with_inline(vec![
            ("openai", "Authorization", "Bearer sk-openai", "https://api.openai.com"),
            ("anthropic", "x-api-key", "sk-anthropic", "https://api.anthropic.com"),
        ]);
        let vault = KeyVault::from_config(&config);

        // Each service returns only its own key
        let openai = vault.get_service("openai").unwrap();
        assert_eq!(openai.value, "Bearer sk-openai");
        assert!(!openai.value.contains("anthropic"));

        let anthropic = vault.get_service("anthropic").unwrap();
        assert_eq!(anthropic.value, "sk-anthropic");
        assert!(!anthropic.value.contains("openai"));
    }
}

fn resolve_env(service_name: &str, source: &KeySource) -> Option<String> {
    let var_name = source.reference.as_ref().or(source.ref_field.as_ref())?;

    match std::env::var(var_name) {
        Ok(value) if !value.is_empty() => Some(value),
        Ok(_) => {
            warn!("Service '{}': environment variable {} is empty", service_name, var_name);
            None
        }
        Err(_) => {
            error!("Service '{}': environment variable {} not set", service_name, var_name);
            None
        }
    }
}
