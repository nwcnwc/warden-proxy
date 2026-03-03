pub mod config;
pub mod proxy;
pub mod vault;
pub mod access;
pub mod limiter;
pub mod sessions;
pub mod websocket;
pub mod client_files;

#[cfg(feature = "session-capture")]
pub mod capture;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{RwLock, broadcast};

use sessions::SessionStore;

/// Global request counter for generating unique request IDs
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique request ID for this process instance
pub fn next_request_id() -> String {
    let count = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("wdn-{:08x}", count)
}

#[derive(Clone, serde::Serialize)]
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
}
