pub mod config;
pub mod proxy;
pub mod vault;
pub mod access;
pub mod limiter;
pub mod sessions;
pub mod tokens;
pub mod websocket;
pub mod client_files;
pub mod traffic;

#[cfg(feature = "session-capture")]
pub mod capture;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};

use sessions::SessionStore;

/// Global request counter for generating unique request IDs
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique request ID for this process instance
pub fn next_request_id() -> String {
    let count = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("wdn-{:08x}", count)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RequestLog {
    pub id: String,
    pub timestamp: u64,
    pub method: String,
    pub service: String,
    pub path: String,
    pub origin: String,
    pub status: u16,
    pub duration_ms: u64,
    pub request_size: u64,
    pub response_size: u64,
    // ── Enhanced fields: what Warden did ──
    #[serde(default)]
    pub headers_stripped: Vec<String>,
    #[serde(default)]
    pub key_injected: Option<String>,
    #[serde(default)]
    pub tokens_substituted: u32,
    #[serde(default)]
    pub cookies_merged: u32,
    #[serde(default)]
    pub inspection_level: String,
    #[serde(default)]
    pub request_headers: Option<serde_json::Value>,
    #[serde(default)]
    pub response_headers: Option<serde_json::Value>,
    #[serde(default)]
    pub request_body_preview: Option<String>,
    #[serde(default)]
    pub response_body_preview: Option<String>,
    #[serde(default)]
    pub alert_level: Option<String>,
}

impl RequestLog {
    /// Create a minimal RequestLog with default enhanced fields
    pub fn new(
        id: String,
        timestamp: u64,
        method: String,
        service: String,
        path: String,
        origin: String,
        status: u16,
        duration_ms: u64,
        request_size: u64,
        response_size: u64,
    ) -> Self {
        Self {
            id,
            timestamp,
            method,
            service,
            path,
            origin,
            status,
            duration_ms,
            request_size,
            response_size,
            headers_stripped: vec![],
            key_injected: None,
            tokens_substituted: 0,
            cookies_merged: 0,
            inspection_level: "metadata".to_string(),
            request_headers: None,
            response_headers: None,
            request_body_preview: None,
            response_body_preview: None,
            alert_level: None,
        }
    }
}

/// An active alert raised by the traffic monitoring system
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Alert {
    pub id: String,
    pub level: String,       // "critical", "warning", "info"
    pub message: String,
    pub service: String,
    pub timestamp: u64,
    pub dismissed: bool,
}

static ALERT_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Alert {
    pub fn new(level: &str, message: String, service: String) -> Self {
        let count = ALERT_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            id: format!("alert-{:08x}", count),
            level: level.to_string(),
            message,
            service,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            dismissed: false,
        }
    }
}

/// Shared application state
pub struct AppState {
    pub config: config::WardenConfig,
    pub vault: vault::KeyVault,
    pub access: access::AccessController,
    pub limiter: RwLock<limiter::RateLimiter>,
    pub sessions: RwLock<SessionStore>,
    pub client: reqwest::Client,
    pub start_time: std::time::Instant,
    pub request_count: AtomicU64,
    pub traffic_log: RwLock<VecDeque<RequestLog>>,
    pub traffic_tx: broadcast::Sender<RequestLog>,
    pub traffic_store: Arc<traffic::TrafficStore>,
    pub alerts: RwLock<Vec<Alert>>,
}
