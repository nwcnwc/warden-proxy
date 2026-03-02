mod config;
mod proxy;
mod vault;
mod access;
mod limiter;
mod client_files;

use std::sync::Arc;
use axum::{
    Router,
    routing::{any, get},
    extract::State,
    response::Json,
};
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;
use tracing::info;

use config::WardenConfig;
use vault::KeyVault;
use access::AccessController;
use limiter::RateLimiter;

/// Shared application state
pub struct AppState {
    pub config: WardenConfig,
    pub vault: KeyVault,
    pub access: AccessController,
    pub limiter: RwLock<RateLimiter>,
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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

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
    }
}

async fn start_server(port_override: Option<u16>) {
    let config = config::load_config().expect("Failed to load config");
    let port = port_override.unwrap_or(config.port);

    let vault = KeyVault::from_config(&config);
    let access = AccessController::from_config(&config);
    let limiter = RateLimiter::from_config(&config);

    let services: Vec<&str> = vault.list_services().into_iter().collect();
    info!("Services: {}", if services.is_empty() { "none configured".to_string() } else { services.join(", ") });

    let state = Arc::new(AppState {
        config,
        vault,
        access,
        limiter: RwLock::new(limiter),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/routes", get(routes))
        .route("/client/{filename}", get(client_files::serve_client_file))
        .route("/proxy/{service}", any(proxy::handle))
        .route("/proxy/{service}/{*path}", any(proxy::handle))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    println!("🔒 Warden Proxy running on http://{}", addr);
    println!("   Config: {}", config::config_path().display());

    axum::serve(listener, app).await.unwrap();
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let limiter = state.limiter.read().await;
    Json(serde_json::json!({
        "services": state.vault.list_services(),
        "access": state.access.list_rules(),
        "limits": limiter.get_status(),
    }))
}

async fn routes(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let route_map = state.vault.get_route_map();
    Json(serde_json::json!(route_map))
}

async fn check_status() {
    match reqwest::get("http://127.0.0.1:7400/status").await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                println!("🔒 Warden Proxy Status\n");
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
