use std::sync::Arc;
use axum::{
    body::Body,
    extract::{Path, State, Request},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use tracing::{info, warn, error};

use crate::AppState;

/// Core proxy handler.
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
    let (service_name, path) = params;
    let target_path = path.as_deref().unwrap_or("");
    let start = std::time::Instant::now();

    // Get origin for access control
    let origin = req.headers()
        .get("origin")
        .or_else(|| req.headers().get("referer"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Check access control
    if !state.access.is_allowed(&origin, &service_name) {
        warn!("Access denied: {} -> {}", origin, service_name);
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": format!("Origin not allowed to access {}", service_name) })),
        ).into_response();
    }

    // Check rate limit
    {
        let mut limiter = state.limiter.write().await;
        if !limiter.check(&service_name) {
            warn!("Rate limited: {}", service_name);
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

    // Build headers — copy from original, then STRIP ALL AUTH
    let mut headers = HeaderMap::new();
    for (key, value) in req.headers() {
        let name = key.as_str().to_lowercase();
        // Skip hop-by-hop and identity headers
        if matches!(name.as_str(), "host" | "origin" | "referer" | "connection" | "transfer-encoding") {
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

    // Read the request body
    let method = req.method().clone();
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10_485_760).await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Failed to read request body" })),
            ).into_response();
        }
    };

    // Forward request to the real service
    let client = reqwest::Client::new();
    let mut forward = client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
        &target_url,
    );

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

    match forward.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

            let mut response_headers = HeaderMap::new();
            for (key, value) in resp.headers() {
                if let (Ok(k), Ok(v)) = (
                    axum::http::HeaderName::from_bytes(key.as_str().as_bytes()),
                    axum::http::HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    // Skip transfer-encoding — we handle the body ourselves
                    if k != "transfer-encoding" {
                        response_headers.insert(k, v);
                    }
                }
            }

            // Add CORS headers
            if let Ok(v) = axum::http::HeaderValue::from_str(&origin) {
                response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            }

            let body = resp.bytes().await.unwrap_or_default();
            let duration = start.elapsed();
            info!("{} {}/{} -> {} ({}ms)", method, service_name, target_path, status.as_u16(), duration.as_millis());

            (status, response_headers, body.to_vec()).into_response()
        }
        Err(e) => {
            error!("Proxy error: {} - {}", service_name, e);
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("Failed to reach {}: {}", service_name, e) })),
            ).into_response()
        }
    }
}
