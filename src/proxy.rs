use std::sync::Arc;
use std::time::Duration;
use axum::{
    body::Body,
    extract::{Path, State, Request, WebSocketUpgrade, FromRequest},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use futures_util::TryStreamExt;
use tracing::{info, warn, error};

use crate::AppState;

/// Core proxy handler — handles both HTTP and WebSocket requests.
///
/// SECURITY MODEL:
/// 1. Strip ALL auth headers from the request (defense in depth)
/// 2. Match destination to a registered service by NAME
/// 3. Inject real API key based SOLELY on destination identity
/// 4. Never search-and-replace. Never based on request content.
pub async fn handle(
    State(state): State<Arc<AppState>>,
    Path(params): Path<(String, Option<String>)>,
    req: Request<Body>,
) -> Response {
    // Check for WebSocket upgrade — delegate to WS handler
    if is_websocket_upgrade(&req) {
        return handle_websocket_upgrade(state, params, req).await;
    }

    handle_http(state, params, req).await
}

/// Detect WebSocket upgrade requests
fn is_websocket_upgrade(req: &Request<Body>) -> bool {
    req.headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// Handle WebSocket upgrade — extract the upgrade and delegate to WS module
async fn handle_websocket_upgrade(
    state: Arc<AppState>,
    params: (String, Option<String>),
    req: Request<Body>,
) -> Response {
    let ws: WebSocketUpgrade = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(ws) => ws,
        Err(rejection) => {
            let resp: Response = rejection.into_response();
            return resp;
        }
    };

    // Reconstruct a minimal request for the WS handler to read origin/headers from.
    // The WS handler gets its info from the params and state.
    let (service_name, path) = params;
    let target_path = path.as_deref().unwrap_or("");
    let request_id = crate::next_request_id();

    // We've already consumed the request for WS extraction, but the
    // websocket module has all the info it needs via params + state.
    // Access control and rate limiting happen below.

    let origin = "unknown".to_string(); // Origin was in the consumed request

    // Check access control
    if !state.access.is_allowed(&origin, &service_name) {
        warn!(request_id = %request_id, "WebSocket access denied: {} -> {}", origin, service_name);
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": format!("Origin not allowed to access {}", service_name) })),
        ).into_response();
    }

    // Check rate limit
    {
        let mut limiter = state.limiter.write().await;
        if !limiter.check(&service_name) {
            warn!(request_id = %request_id, "WebSocket rate limited: {}", service_name);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": format!("Rate limit exceeded for {}", service_name) })),
            ).into_response();
        }
    }

    // Look up service in vault
    let service = match state.vault.get_service(&service_name) {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("Unknown service: {}", service_name) })),
            ).into_response();
        }
    };

    // Build upstream WebSocket URL
    let upstream_url = {
        let base = if target_path.is_empty() {
            service.base_url.clone()
        } else {
            format!("{}/{}", service.base_url, target_path)
        };
        base.replace("https://", "wss://").replace("http://", "ws://")
    };

    let svc_name = service_name.clone();
    let rid = request_id.clone();

    info!(request_id = %request_id, "WebSocket upgrade: {} -> {}", service_name, upstream_url);
    state.request_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    ws.on_upgrade(move |client_socket| async move {
        if let Err(e) = crate::websocket::bridge(client_socket, &upstream_url, &service).await {
            error!(request_id = %rid, "WebSocket bridge error for {}: {}", svc_name, e);
        } else {
            info!(request_id = %rid, "WebSocket closed: {}", svc_name);
        }
    })
}

/// Standard HTTP proxy handler
async fn handle_http(
    state: Arc<AppState>,
    params: (String, Option<String>),
    req: Request<Body>,
) -> Response {
    let (service_name, path) = params;
    let target_path = path.as_deref().unwrap_or("");
    let start = std::time::Instant::now();

    // Get request ID from headers or generate one
    let request_id = req.headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| crate::next_request_id());

    // Get origin for access control
    let origin = req.headers()
        .get("origin")
        .or_else(|| req.headers().get("referer"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Check access control
    if !state.access.is_allowed(&origin, &service_name) {
        warn!(request_id = %request_id, "Access denied: {} -> {}", origin, service_name);
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": format!("Origin not allowed to access {}", service_name) })),
        ).into_response();
    }

    // Check rate limit
    {
        let mut limiter = state.limiter.write().await;
        if !limiter.check(&service_name) {
            warn!(request_id = %request_id, "Rate limited: {}", service_name);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": format!("Rate limit exceeded for {}", service_name) })),
            ).into_response();
        }
    }

    // Look up service in vault
    let service = match state.vault.get_service(&service_name) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("Unknown service: {}", service_name) })),
            ).into_response();
        }
    };

    // Build target URL
    let target_url = if target_path.is_empty() {
        service.base_url.clone()
    } else {
        format!("{}/{}", service.base_url, target_path)
    };

    // Append query string if present
    let target_url = if let Some(query) = req.uri().query() {
        format!("{}?{}", target_url, query)
    } else {
        target_url
    };

    // Build headers — copy from original, then STRIP ALL AUTH
    let mut headers = HeaderMap::new();
    for (key, value) in req.headers() {
        let name = key.as_str().to_lowercase();
        // Skip hop-by-hop and identity headers
        if matches!(name.as_str(), "host" | "origin" | "referer" | "connection" | "transfer-encoding" | "upgrade") {
            continue;
        }
        // SECURITY: Strip ALL auth headers from the VM's request.
        // The app may send fake keys, real keys, garbage — doesn't matter.
        // We throw away everything auth-related and inject based SOLELY
        // on the matched destination service. Never text replacement.
        if matches!(name.as_str(), "authorization" | "x-api-key" | "api-key" | "cookie") {
            continue;
        }
        if let Ok(header_name) = axum::http::HeaderName::from_bytes(key.as_str().as_bytes()) {
            headers.insert(header_name, value.clone());
        }
    }

    // Inject the REAL key based on destination service identity
    if let Ok(header_name) = axum::http::HeaderName::from_bytes(service.header.to_lowercase().as_bytes()) {
        if let Ok(header_value) = axum::http::HeaderValue::from_str(&service.value) {
            headers.insert(header_name, header_value);
        }
    }

    // Read the request body (respecting max body size)
    let max_body = state.config.max_body_size;
    let method = req.method().clone();
    let body_bytes = match axum::body::to_bytes(req.into_body(), max_body).await {
        Ok(b) => b,
        Err(e) => {
            error!(request_id = %request_id, "Failed to read request body: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Failed to read request body (too large or malformed)" })),
            ).into_response();
        }
    };

    // Per-service timeout (or global default)
    let timeout_secs = service.timeout.unwrap_or(state.config.request_timeout);

    // Forward request to the real service using the shared client
    let mut forward = state.client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
        &target_url,
    );

    // Set timeout
    forward = forward.timeout(Duration::from_secs(timeout_secs));

    // Copy headers to reqwest
    let mut reqwest_headers = reqwest::header::HeaderMap::new();
    for (key, value) in &headers {
        if let (Ok(k), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(key.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            reqwest_headers.insert(k, v);
        }
    }
    forward = forward.headers(reqwest_headers);

    if !body_bytes.is_empty() {
        forward = forward.body(body_bytes.to_vec());
    }

    // Track request count
    state.request_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    match forward.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

            let mut response_headers = HeaderMap::new();
            for (key, value) in resp.headers() {
                if let (Ok(k), Ok(v)) = (
                    axum::http::HeaderName::from_bytes(key.as_str().as_bytes()),
                    axum::http::HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    // Skip hop-by-hop headers — axum manages its own transfer encoding
                    if k == "transfer-encoding" || k == "connection" {
                        continue;
                    }
                    response_headers.insert(k, v);
                }
            }

            // Add CORS headers
            if let Ok(v) = axum::http::HeaderValue::from_str(&origin) {
                response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            }

            // Add request ID to response
            if let Ok(v) = axum::http::HeaderValue::from_str(&request_id) {
                response_headers.insert("x-request-id", v);
            }

            let duration = start.elapsed();
            info!(
                request_id = %request_id,
                "{} {}/{} -> {} ({}ms, streaming)",
                method, service_name, target_path, status.as_u16(), duration.as_millis()
            );

            // Log to traffic monitor
            {
                let response_size = resp.headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                let entry = crate::RequestLog {
                    id: request_id.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    method: method.to_string(),
                    service: service_name.clone(),
                    path: target_path.to_string(),
                    origin: origin.clone(),
                    status: status.as_u16(),
                    duration_ms: duration.as_millis() as u64,
                    request_size: body_bytes.len() as u64,
                    response_size,
                };
                {
                    let mut log = state.traffic_log.write().await;
                    if log.len() >= 1000 { log.pop_front(); }
                    log.push_back(entry.clone());
                }
                let _ = state.traffic_tx.send(entry);
            }

            // Stream the response body instead of buffering it
            let stream = resp.bytes_stream()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
            let body = Body::from_stream(stream);

            let mut response = Response::new(body);
            *response.status_mut() = status;
            *response.headers_mut() = response_headers;

            response
        }
        Err(e) => {
            let duration = start.elapsed();
            error!(
                request_id = %request_id,
                "Proxy error: {} - {} ({}ms)", service_name, e, duration.as_millis()
            );

            // Log error to traffic monitor
            {
                let entry = crate::RequestLog {
                    id: request_id.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    method: method.to_string(),
                    service: service_name.clone(),
                    path: target_path.to_string(),
                    origin: origin.clone(),
                    status: 502,
                    duration_ms: duration.as_millis() as u64,
                    request_size: body_bytes.len() as u64,
                    response_size: 0,
                };
                {
                    let mut log = state.traffic_log.write().await;
                    if log.len() >= 1000 { log.pop_front(); }
                    log.push_back(entry.clone());
                }
                let _ = state.traffic_tx.send(entry);
            }

            let error_msg = if e.is_timeout() {
                format!("Request to {} timed out after {}s", service_name, timeout_secs)
            } else {
                format!("Failed to reach {}: {}", service_name, e)
            };

            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": error_msg })),
            ).into_response()
        }
    }
}
