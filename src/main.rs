mod config;
mod proxy;
mod vault;
mod access;
mod limiter;
mod client_files;
mod websocket;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use axum::{
    Router,
    routing::{any, get},
    extract::State,
    response::Json,
};
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use tracing::info;

use config::WardenConfig;
use vault::KeyVault;
use access::AccessController;
use limiter::RateLimiter;

/// Global request counter for generating unique request IDs
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique request ID for this process instance
pub fn next_request_id() -> String {
    let count = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("wdn-{:08x}", count)
}

/// Shared application state
pub struct AppState {
    pub config: WardenConfig,
    pub vault: KeyVault,
    pub access: AccessController,
    pub limiter: RwLock<RateLimiter>,
    pub client: reqwest::Client,
    pub start_time: std::time::Instant,
    pub request_count: AtomicU64,
}

#[derive(Parser)]
#[command(name = "warden")]
#[command(about = "🔒 Warden Proxy — Safe external access for browser applications")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize config directory (~/.warden/)
    Init,
    /// Start the proxy server
    Start {
        /// Port to listen on (overrides config)
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// Show proxy status
    Status,
    /// Add or update an API key service
    AddKey {
        /// Service name (e.g., "openai", "anthropic")
        service: String,
        /// Base URL of the API
        #[arg(long)]
        base_url: String,
        /// HTTP header for auth injection (default: "Authorization")
        #[arg(long, default_value = "Authorization")]
        header: String,
        /// Key source provider (env, 1password, bitwarden, keyring, encrypted, inline)
        #[arg(long, default_value = "env")]
        source: String,
        /// Reference for the key source (env var name, secret path, etc.)
        #[arg(long, alias = "ref")]
        reference: String,
        /// Prefix to prepend to resolved value (e.g., "Bearer ")
        #[arg(long)]
        prefix: Option<String>,
        /// Request timeout in seconds for this service
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Remove an API key service
    RemoveKey {
        /// Service name to remove
        service: String,
    },
    /// List configured API key services (never shows actual key values)
    ListKeys,
    /// Test resolving a key (reports success/fail without showing value)
    TestKey {
        /// Service name to test
        service: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            config::init_config().expect("Failed to initialize config");
        }
        Commands::Start { port } => {
            start_server(port).await;
        }
        Commands::Status => {
            check_status().await;
        }
        Commands::AddKey { service, base_url, header, source, reference, prefix, timeout } => {
            cmd_add_key(&service, &base_url, &header, &source, &reference, prefix.as_deref(), timeout);
        }
        Commands::RemoveKey { service } => {
            cmd_remove_key(&service);
        }
        Commands::ListKeys => {
            cmd_list_keys();
        }
        Commands::TestKey { service } => {
            cmd_test_key(&service);
        }
    }
}

async fn start_server(port_override: Option<u16>) {
    let config = config::load_config().expect("Failed to load config");

    // Initialize logging
    if config.json_logs {
        tracing_subscriber::fmt().json().init();
    } else {
        tracing_subscriber::fmt::init();
    }

    let port = port_override.unwrap_or(config.port);

    let vault = KeyVault::from_config(&config);
    let access = AccessController::from_config(&config);
    let limiter = RateLimiter::from_config(&config);

    let services: Vec<&str> = vault.list_services().into_iter().collect();
    info!("Services: {}", if services.is_empty() { "none configured".to_string() } else { services.join(", ") });

    // Build shared HTTP client for connection pooling
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(10)
        .build()
        .expect("Failed to build HTTP client");

    let state = Arc::new(AppState {
        config: config.clone(),
        vault,
        access,
        limiter: RwLock::new(limiter),
        client,
        start_time: std::time::Instant::now(),
        request_count: AtomicU64::new(0),
    });

    let mut app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/routes", get(routes))
        .route("/client/{filename}", get(client_files::serve_client_file))
        .route("/proxy/{service}", any(proxy::handle))
        .route("/proxy/{service}/{*path}", any(proxy::handle))
        .with_state(state.clone());

    // Mount site-specific directories
    for (prefix, dir_path) in &config.sites {
        let expanded = config::expand_path(dir_path);
        if expanded.exists() {
            let serve = ServeDir::new(&expanded).append_index_html_on_directories(true);
            info!("Serving site: {} -> {}", prefix, expanded.display());
            app = app.nest_service(prefix, serve);
        } else {
            tracing::warn!("Site directory not found: {} -> {}", prefix, expanded.display());
        }
    }

    // Default static file serving from public_dir
    let public_dir = config.public_dir
        .as_ref()
        .map(|p| config::expand_path(p))
        .unwrap_or_else(config::default_public_dir);

    if public_dir.exists() {
        let fallback = ServeDir::new(&public_dir).append_index_html_on_directories(true);
        info!("Static files: {}", public_dir.display());
        app = app.fallback_service(fallback);
    }

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    println!("🔒 Warden Proxy running on http://{}", addr);
    println!("   Config: {}", config::config_path().display());
    if public_dir.exists() {
        println!("   Static: {}", public_dir.display());
    }

    // Graceful shutdown on SIGTERM/SIGINT
    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate()
            ).expect("Failed to install SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
        info!("Shutting down gracefully...");
        println!("\n🔒 Warden Proxy shutting down...");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .unwrap();
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let limiter = state.limiter.read().await;
    let uptime = state.start_time.elapsed();
    let request_count = state.request_count.load(Ordering::Relaxed);

    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": uptime.as_secs(),
        "uptime": format_duration(uptime),
        "request_count": request_count,
        "services": state.vault.list_services(),
        "access": state.access.list_rules(),
        "limits": limiter.get_status(),
    }))
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

async fn routes(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let route_map = state.vault.get_route_map();
    Json(serde_json::json!(route_map))
}

async fn check_status() {
    let config = config::load_config().unwrap_or_default();
    let url = format!("http://127.0.0.1:{}/status", config.port);
    match reqwest::get(&url).await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                println!("🔒 Warden Proxy Status\n");
                if let Some(version) = body.get("version") {
                    println!("Version: {}", version.as_str().unwrap_or("unknown"));
                }
                if let Some(uptime) = body.get("uptime") {
                    println!("Uptime:  {}", uptime.as_str().unwrap_or("unknown"));
                }
                if let Some(count) = body.get("request_count") {
                    println!("Requests: {}", count);
                }
                if let Some(services) = body.get("services") {
                    println!("Services: {}", services);
                }
                if let Some(access) = body.get("access") {
                    println!("Access rules: {}", access);
                }
                if let Some(limits) = body.get("limits") {
                    println!("Rate limits: {}", limits);
                }
            }
        }
        Err(_) => {
            println!("⚠️  Warden Proxy is not running");
            println!("   Start it with: warden start");
        }
    }
}

// ════════════════════════════════════════════════════════
// CLI Key Management
// ════════════════════════════════════════════════════════

fn cmd_add_key(service: &str, base_url: &str, header: &str, source: &str, reference: &str, prefix: Option<&str>, timeout: Option<u64>) {
    let mut config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠️  Failed to load config: {}", e);
            eprintln!("   Run 'warden init' first.");
            return;
        }
    };

    let key_source = config::KeySource {
        provider: source.to_string(),
        reference: Some(reference.to_string()),
        ref_field: None,
        prefix: prefix.map(|s| s.to_string()),
        field: None,
        path: None,
    };

    let existed = config.keys.contains_key(service);
    config.keys.insert(service.to_string(), config::ServiceKeyConfig {
        header: Some(header.to_string()),
        base_url: base_url.to_string(),
        value: None,
        source: Some(key_source),
        timeout,
    });

    match config::save_config(&config) {
        Ok(()) => {
            if existed {
                println!("✅ Updated service '{}'", service);
            } else {
                println!("✅ Added service '{}'", service);
            }
            println!("   Base URL: {}", base_url);
            println!("   Header:   {}", header);
            println!("   Source:   {} (ref: {})", source, reference);
            if let Some(p) = prefix {
                println!("   Prefix:   {:?}", p);
            }
        }
        Err(e) => {
            eprintln!("⚠️  Failed to save config: {}", e);
        }
    }
}

fn cmd_remove_key(service: &str) {
    let mut config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠️  Failed to load config: {}", e);
            return;
        }
    };

    if config.keys.remove(service).is_some() {
        // Also clean up related access rules and limits
        config.limits.remove(service);

        match config::save_config(&config) {
            Ok(()) => println!("✅ Removed service '{}'", service),
            Err(e) => eprintln!("⚠️  Failed to save config: {}", e),
        }
    } else {
        eprintln!("⚠️  Service '{}' not found in config", service);
    }
}

fn cmd_list_keys() {
    let config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠️  Failed to load config: {}", e);
            return;
        }
    };

    if config.keys.is_empty() {
        println!("No services configured.");
        println!("Add one with: warden add-key <service> --base-url <url> --source <provider> --reference <ref>");
        return;
    }

    println!("🔒 Configured Services\n");
    for (name, svc) in &config.keys {
        let source_info = match &svc.source {
            Some(s) => format!("{} (ref: {})", s.provider, s.reference.as_deref().unwrap_or("-")),
            None => match &svc.value {
                Some(_) => "inline value".to_string(),
                None => "none".to_string(),
            },
        };
        println!("  {} ", name);
        println!("    URL:    {}", svc.base_url);
        println!("    Header: {}", svc.header.as_deref().unwrap_or("Authorization"));
        println!("    Source: {}", source_info);
        if let Some(t) = svc.timeout {
            println!("    Timeout: {}s", t);
        }
        println!();
    }
}

fn cmd_test_key(service: &str) {
    let config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠️  Failed to load config: {}", e);
            return;
        }
    };

    let svc = match config.keys.get(service) {
        Some(s) => s,
        None => {
            eprintln!("⚠️  Service '{}' not found in config", service);
            return;
        }
    };

    println!("🔑 Testing key resolution for '{}'...\n", service);
    println!("  Base URL: {}", svc.base_url);
    println!("  Header:   {}", svc.header.as_deref().unwrap_or("Authorization"));

    // Try to resolve the key through the vault
    let vault = KeyVault::from_config(&config);
    match vault.get_service(service) {
        Some(entry) => {
            // Show that a key was resolved without revealing its value
            let masked = if entry.value.len() > 8 {
                format!("{}...{} ({} chars)",
                    &entry.value[..4],
                    &entry.value[entry.value.len()-4..],
                    entry.value.len()
                )
            } else {
                format!("*** ({} chars)", entry.value.len())
            };
            println!("  Result:   ✅ Key resolved successfully");
            println!("  Preview:  {}", masked);
        }
        None => {
            println!("  Result:   ❌ Failed to resolve key");
            println!("\n  Check your source configuration and ensure the provider is accessible.");
        }
    }
}
