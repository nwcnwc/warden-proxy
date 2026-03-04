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
use crate::sessions::SessionStatus;
use crate::tokens;
use crate::Alert;

/// Auth-related header names that get stripped from every request.
const AUTH_HEADERS: &[&str] = &["authorization", "x-api-key", "api-key", "cookie"];

/// Core proxy handler — handles both HTTP and WebSocket requests.
///
/// SECURITY MODEL:
/// 1. Strip ALL auth headers from the request (defense in depth)
/// 2. Match destination to a registered service by NAME
/// 3. Inject real API key based SOLELY on destination identity
/// 4. Never search-and-replace. Never based on request content.
/// 5. Cookie MERGE: keep app operational cookies, replace auth cookies with reals
/// 6. Token substitution: fake↔real swap in headers and JSON bodies
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

    let (service_name, path) = params;
    let target_path = path.as_deref().unwrap_or("");
    let request_id = crate::next_request_id();

    let origin = "unknown".to_string();

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

/// Parse an app's Cookie header into individual name=value pairs.
fn parse_cookie_header(header_value: &str) -> Vec<(String, String)> {
    header_value.split(';')
        .filter_map(|pair| {
            let pair = pair.trim();
            let eq = pair.find('=')?;
            Some((pair[..eq].to_string(), pair[eq+1..].to_string()))
        })
        .collect()
}

/// Redact auth header values for safe logging. Returns a JSON object
/// with header names as keys and values either passed through or redacted.
fn redact_headers(headers: &HeaderMap) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in headers {
        let name = key.as_str().to_lowercase();
        let val = if AUTH_HEADERS.contains(&name.as_str())
            || name.contains("secret")
            || name.contains("token")
            || name.contains("key")
        {
            "[REDACTED]".to_string()
        } else {
            value.to_str().unwrap_or("[binary]").to_string()
        };
        map.insert(name, serde_json::Value::String(val));
    }
    serde_json::Value::Object(map)
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

    let inspection_level = state.config.traffic.inspection_level.clone();

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

    // ── Capture request headers for inspection ──
    let captured_request_headers = if inspection_level == "headers" || inspection_level == "full" {
        Some(redact_headers(req.headers()))
    } else {
        None
    };

    // ── Save app's Cookie header before stripping ──
    let app_cookie_header = req.headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // ── Save app's Authorization header for fake→real substitution ──
    let app_auth_header = req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // ── ALERT: Check if incoming request contains a real API key (security breach) ──
    if state.config.traffic.alerts_enabled {
        if let Some(ref auth_val) = app_auth_header {
            check_real_key_leak(&state, auth_val, &service_name, &origin).await;
        }
        // Also check x-api-key
        if let Some(xkey) = req.headers().get("x-api-key").and_then(|v| v.to_str().ok()) {
            check_real_key_leak(&state, xkey, &service_name, &origin).await;
        }
    }

    // ── Track which auth headers were stripped ──
    let mut headers_stripped: Vec<String> = Vec::new();

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
            headers_stripped.push(name);
            continue;
        }
        if let Ok(header_name) = axum::http::HeaderName::from_bytes(key.as_str().as_bytes()) {
            headers.insert(header_name, value.clone());
        }
    }

    // Inject the REAL key based on destination service identity
    let key_injected: Option<String> = {
        if let Ok(header_name) = axum::http::HeaderName::from_bytes(service.header.to_lowercase().as_bytes()) {
            if let Ok(header_value) = axum::http::HeaderValue::from_str(&service.value) {
                headers.insert(header_name, header_value);
                Some(service_name.clone())
            } else {
                None
            }
        } else {
            None
        }
    };

    // ── Cookie MERGE strategy ──
    // Instead of replacing all cookies, merge: real auth + app operational cookies
    let mut cookies_merged: u32 = 0;
    {
        let sessions = state.sessions.read().await;
        let session_cookies = sessions.cookies_for_request(&target_url);

        // Get auth cookie names for this session (if any)
        let (_, request_domain, _) = crate::sessions::parse_url(&target_url)
            .unwrap_or((false, String::new(), String::new()));
        let session = sessions.find_for_domain(&request_domain);
        let auth_cookie_names: Vec<String> = session
            .filter(|s| s.status == SessionStatus::Active)
            .map(|s| s.auth_cookie_names.clone())
            .unwrap_or_default();

        if !session_cookies.is_empty() || !auth_cookie_names.is_empty() {
            // Start with app's operational cookies (non-auth)
            let mut merged_cookies: Vec<(String, String)> = Vec::new();

            if let Some(ref app_cookies) = app_cookie_header {
                let parsed = parse_cookie_header(app_cookies);
                for (name, val) in parsed {
                    // If this cookie name matches an auth cookie, discard it (app has a fake)
                    if auth_cookie_names.iter().any(|a| a == &name) {
                        continue;
                    }
                    // Keep operational cookies (CSRF, tracking, etc.)
                    merged_cookies.push((name, val));
                }
            }

            // Add real auth cookies from session store
            for c in &session_cookies {
                merged_cookies.push((c.name.clone(), c.value.clone()));
            }

            cookies_merged = merged_cookies.len() as u32;

            if !merged_cookies.is_empty() {
                let cookie_header = merged_cookies.iter()
                    .map(|(n, v)| format!("{}={}", n, v))
                    .collect::<Vec<_>>()
                    .join("; ");
                if let Ok(v) = axum::http::HeaderValue::from_str(&cookie_header) {
                    headers.insert(header::COOKIE, v);
                }
            }
        }
    }

    // ── Token substitution: outgoing fake→real in Authorization header ──
    let mut tokens_substituted: u32 = 0;
    {
        let sessions = state.sessions.read().await;
        let (_, request_domain, _) = crate::sessions::parse_url(&target_url)
            .unwrap_or((false, String::new(), String::new()));
        if let Some(session) = sessions.find_for_domain(&request_domain) {
            if session.status == SessionStatus::Active && !session.token_map.fake_to_real.is_empty() {
                // Check if the app sent a fake token in Authorization
                if let Some(ref auth_val) = app_auth_header {
                    let real_auth = session.token_map.replace_fakes_with_reals(auth_val);
                    if real_auth != *auth_val {
                        tokens_substituted += 1;
                        if let Ok(v) = axum::http::HeaderValue::from_str(&real_auth) {
                            headers.insert(header::AUTHORIZATION, v);
                        }
                    }
                }
            }
        }
    }

    // Read the request body (respecting max body size)
    let max_body = state.config.max_body_size;
    let method = req.method().clone();
    let mut body_bytes = match axum::body::to_bytes(req.into_body(), max_body).await {
        Ok(b) => b.to_vec(),
        Err(e) => {
            error!(request_id = %request_id, "Failed to read request body: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Failed to read request body (too large or malformed)" })),
            ).into_response();
        }
    };

    // ── Capture request body preview for "full" inspection ──
    let request_body_preview = if inspection_level == "full" && !body_bytes.is_empty() {
        std::str::from_utf8(&body_bytes).ok().map(|s| {
            if s.len() > 1000 { s[..1000].to_string() } else { s.to_string() }
        })
    } else {
        None
    };

    // ── Token substitution: outgoing fake→real in request body ──
    {
        let sessions = state.sessions.read().await;
        let (_, request_domain, _) = crate::sessions::parse_url(&target_url)
            .unwrap_or((false, String::new(), String::new()));
        if let Some(session) = sessions.find_for_domain(&request_domain) {
            if session.status == SessionStatus::Active && !session.token_map.fake_to_real.is_empty() && !body_bytes.is_empty() {
                if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
                    let replaced = session.token_map.replace_fakes_with_reals(body_str);
                    if replaced != body_str {
                        tokens_substituted += 1;
                        body_bytes = replaced.into_bytes();
                    }
                }
            }
        }
    }

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
        forward = forward.body(body_bytes.clone());
    }

    // Track request count
    state.request_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    match forward.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

            // Check if this is a JSON response that may need token substitution
            let is_json = resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| ct.contains("application/json"));

            // ── Capture response headers for inspection ──
            let captured_response_headers = if inspection_level == "headers" || inspection_level == "full" {
                Some(redact_headers(resp.headers()))
            } else {
                None
            };

            // ── Process Set-Cookie headers: swap auth cookie values ──
            let mut response_headers = HeaderMap::new();
            {
                let (_, request_domain, _) = crate::sessions::parse_url(&target_url)
                    .unwrap_or((false, String::new(), String::new()));

                // Collect auth cookie names and token map from session (read lock)
                let (auth_names, has_session) = {
                    let sessions = state.sessions.read().await;
                    let session = sessions.find_for_domain(&request_domain);
                    match session {
                        Some(s) if s.status == SessionStatus::Active => {
                            (s.auth_cookie_names.clone(), true)
                        }
                        _ => (vec![], false),
                    }
                };

                for (key, value) in resp.headers() {
                    if let (Ok(k), Ok(v)) = (
                        axum::http::HeaderName::from_bytes(key.as_str().as_bytes()),
                        axum::http::HeaderValue::from_bytes(value.as_bytes()),
                    ) {
                        // Skip hop-by-hop headers
                        if k == "transfer-encoding" || k == "connection" {
                            continue;
                        }

                        // Handle Set-Cookie: swap auth cookie values with fakes
                        if k == "set-cookie" && has_session && !auth_names.is_empty() {
                            if let Ok(sc_str) = v.to_str() {
                                // Parse cookie name from Set-Cookie header
                                if let Some(eq_pos) = sc_str.find('=') {
                                    let cookie_name = sc_str[..eq_pos].trim();
                                    if auth_names.iter().any(|a| a == cookie_name) {
                                        // This is an auth cookie — store new real value, send fake
                                        // Extract the value (up to first ; or end)
                                        let after_eq = &sc_str[eq_pos+1..];
                                        let value_end = after_eq.find(';').unwrap_or(after_eq.len());
                                        let real_value = &after_eq[..value_end];

                                        // Generate a stable fake cookie value
                                        let fake_value = tokens::TokenMap::generate_fake(real_value, &request_domain);

                                        // Update session with new real cookie value
                                        {
                                            let mut sessions = state.sessions.write().await;
                                            if let Some(session) = sessions.find_for_domain_mut(&request_domain) {
                                                // Update the cookie value in our store
                                                for c in &mut session.cookies {
                                                    if c.name == cookie_name {
                                                        c.value = real_value.to_string();
                                                    }
                                                }
                                                // Store in token map for completeness
                                                session.token_map.insert(real_value, &request_domain);
                                                sessions.save_domain(&request_domain).ok();
                                            }
                                        }

                                        // Rewrite Set-Cookie with fake value
                                        let fake_set_cookie = format!(
                                            "{}={}{}",
                                            cookie_name,
                                            fake_value,
                                            if value_end < after_eq.len() { &after_eq[value_end..] } else { "" }
                                        );
                                        if let Ok(fv) = axum::http::HeaderValue::from_str(&fake_set_cookie) {
                                            response_headers.append(k, fv);
                                        }
                                        continue;
                                    }
                                }
                            }
                        }

                        response_headers.append(k, v);
                    }
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

            // ── Add X-Warden-Storage header for the SW ──
            // Contains fake localStorage/sessionStorage values for this origin
            {
                let sessions = state.sessions.read().await;
                let (_, request_domain, _) = crate::sessions::parse_url(&target_url)
                    .unwrap_or((false, String::new(), String::new()));
                let origin_url = format!("https://{}", request_domain);
                if let Some(storage_data) = sessions.storage_for_origin(&origin_url) {
                    if !storage_data.local_storage.is_empty() || !storage_data.session_storage.is_empty() {
                        if let Ok(json) = serde_json::to_string(&storage_data) {
                            use base64::Engine;
                            let encoded = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
                            if let Ok(hv) = axum::http::HeaderValue::from_str(&encoded) {
                                response_headers.insert("x-warden-storage", hv);
                            }
                        }
                    }
                }
            }

            let duration = start.elapsed();
            info!(
                request_id = %request_id,
                "{} {}/{} -> {} ({}ms)",
                method, service_name, target_path, status.as_u16(), duration.as_millis()
            );

            // Log to traffic monitor
            let response_size = resp.headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            // ── Detect alert conditions ──
            let alert_level = if state.config.traffic.alerts_enabled {
                detect_alert_level(&state, &service_name, status.as_u16(), duration, response_size).await
            } else {
                None
            };

            let entry = {
                let mut e = crate::RequestLog::new(
                    request_id.clone(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    method.to_string(),
                    service_name.clone(),
                    target_path.to_string(),
                    origin.clone(),
                    status.as_u16(),
                    duration.as_millis() as u64,
                    body_bytes.len() as u64,
                    response_size,
                );
                e.headers_stripped = headers_stripped.clone();
                e.key_injected = key_injected.clone();
                e.tokens_substituted = tokens_substituted;
                e.cookies_merged = cookies_merged;
                e.inspection_level = inspection_level.clone();
                e.request_headers = captured_request_headers;
                e.response_headers = captured_response_headers;
                e.request_body_preview = request_body_preview;
                // response_body_preview filled below after reading body
                e.alert_level = alert_level;
                e
            };

            // Push to ring buffer + broadcast
            {
                let mut log = state.traffic_log.write().await;
                if log.len() >= 1000 { log.pop_front(); }
                log.push_back(entry.clone());
            }
            let _ = state.traffic_tx.send(entry.clone());

            // Write to SQLite in background (non-blocking)
            {
                let store = state.traffic_store.clone();
                let entry_clone = entry;
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = store.insert(&entry_clone) {
                        tracing::warn!("Failed to write traffic entry to SQLite: {}", e);
                    }
                });
            }

            // ── Token substitution in JSON response bodies ──
            if is_json {
                // Buffer the body for token substitution
                let body_result = resp.bytes().await;
                match body_result {
                    Ok(resp_bytes) => {
                        let (_, request_domain, _) = crate::sessions::parse_url(&target_url)
                            .unwrap_or((false, String::new(), String::new()));

                        let mut modified_body = resp_bytes.to_vec();

                        // Capture response body preview if full inspection
                        if inspection_level == "full" {
                            if let Ok(s) = std::str::from_utf8(&resp_bytes) {
                                let preview = if s.len() > 1000 { &s[..1000] } else { s };
                                // Update the SQLite entry with body preview (fire-and-forget)
                                let store = state.traffic_store.clone();
                                let rid = request_id.clone();
                                let prev = preview.to_string();
                                tokio::task::spawn_blocking(move || {
                                    let _ = store.update_response_preview(&rid, &prev);
                                });
                            }
                        }

                        // Try to parse and substitute tokens
                        if let Ok(body_str) = std::str::from_utf8(&resp_bytes) {
                            if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(body_str) {
                                let mut sessions = state.sessions.write().await;
                                if let Some(session) = sessions.find_for_domain_mut(&request_domain) {
                                    if session.status == SessionStatus::Active {
                                        let token_fields = session.token_fields.clone();
                                        if tokens::substitute_tokens_in_json(
                                            &mut json_val,
                                            &mut session.token_map,
                                            &token_fields,
                                            &request_domain,
                                        ) {
                                            if let Ok(new_body) = serde_json::to_vec(&json_val) {
                                                modified_body = new_body;
                                                sessions.save_domain(&request_domain).ok();
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Update content-length if body changed
                        if modified_body.len() != resp_bytes.len() {
                            if let Ok(cl) = axum::http::HeaderValue::from_str(&modified_body.len().to_string()) {
                                response_headers.insert(header::CONTENT_LENGTH, cl);
                            }
                        }

                        let body = Body::from(modified_body);
                        let mut response = Response::new(body);
                        *response.status_mut() = status;
                        *response.headers_mut() = response_headers;
                        response
                    }
                    Err(e) => {
                        error!(request_id = %request_id, "Failed to read JSON response body: {}", e);
                        let mut response = Response::new(Body::empty());
                        *response.status_mut() = status;
                        *response.headers_mut() = response_headers;
                        response
                    }
                }
            } else {
                // Non-JSON: stream the response body
                let stream = resp.bytes_stream()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
                let body = Body::from_stream(stream);

                let mut response = Response::new(body);
                *response.status_mut() = status;
                *response.headers_mut() = response_headers;

                response
            }
        }
        Err(e) => {
            let duration = start.elapsed();
            error!(
                request_id = %request_id,
                "Proxy error: {} - {} ({}ms)", service_name, e, duration.as_millis()
            );

            // Detect alert for errors
            let alert_level = if state.config.traffic.alerts_enabled {
                detect_alert_level(&state, &service_name, 502, duration, 0).await
            } else {
                None
            };

            // Log error to traffic monitor
            let entry = {
                let mut e = crate::RequestLog::new(
                    request_id.clone(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    method.to_string(),
                    service_name.clone(),
                    target_path.to_string(),
                    origin.clone(),
                    502,
                    duration.as_millis() as u64,
                    body_bytes.len() as u64,
                    0,
                );
                e.headers_stripped = headers_stripped;
                e.key_injected = key_injected;
                e.tokens_substituted = tokens_substituted;
                e.cookies_merged = cookies_merged;
                e.inspection_level = inspection_level;
                e.request_headers = captured_request_headers.clone();
                e.request_body_preview = request_body_preview.clone();
                e.alert_level = alert_level;
                e
            };
            {
                let mut log = state.traffic_log.write().await;
                if log.len() >= 1000 { log.pop_front(); }
                log.push_back(entry.clone());
            }
            let _ = state.traffic_tx.send(entry.clone());

            // Write to SQLite in background
            {
                let store = state.traffic_store.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = store.insert(&entry) {
                        tracing::warn!("Failed to write traffic entry to SQLite: {}", e);
                    }
                });
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

/// Check if an incoming auth header value matches a real key in the vault.
/// If so, raise a CRITICAL alert — the jailed app has the real key.
async fn check_real_key_leak(state: &Arc<AppState>, auth_value: &str, service_name: &str, origin: &str) {
    // Check all service keys to see if the raw value matches
    for svc_name in state.vault.list_services() {
        if let Some(entry) = state.vault.get_service(svc_name) {
            if !entry.value.is_empty() && auth_value.contains(&entry.value) {
                let alert = Alert::new(
                    "critical",
                    format!(
                        "Real API key for '{}' detected in request from origin '{}' targeting '{}'! The jailed app has the real key.",
                        svc_name, origin, service_name
                    ),
                    service_name.to_string(),
                );
                let mut alerts = state.alerts.write().await;
                alerts.push(alert);
                error!(
                    "SECURITY BREACH: Real API key for '{}' found in incoming request from '{}'",
                    svc_name, origin
                );
                return;
            }
        }
    }
}

/// Detect alert conditions based on response status, latency, and size.
async fn detect_alert_level(
    state: &Arc<AppState>,
    service_name: &str,
    status: u16,
    duration: Duration,
    response_size: u64,
) -> Option<String> {
    // CRITICAL: 429 from upstream (rate limit hit)
    if status == 429 {
        let alert = Alert::new(
            "warning",
            format!("Rate limit hit (429) from upstream service '{}'", service_name),
            service_name.to_string(),
        );
        state.alerts.write().await.push(alert);
        return Some("warning".to_string());
    }

    // CRITICAL: consecutive 5xx — check recent traffic
    if status >= 500 {
        let log = state.traffic_log.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let five_min_ago = now.saturating_sub(300_000);

        let recent_5xx: usize = log.iter()
            .rev()
            .take_while(|e| e.timestamp > five_min_ago)
            .filter(|e| e.service == service_name && e.status >= 500)
            .count();

        if recent_5xx >= 4 {
            // This will be the 5th
            let alert = Alert::new(
                "critical",
                format!("5+ consecutive 5xx errors from '{}' in last 5 minutes", service_name),
                service_name.to_string(),
            );
            state.alerts.write().await.push(alert);
            return Some("critical".to_string());
        }

        // Check error rate > 10%
        let total_recent: usize = log.iter()
            .rev()
            .take_while(|e| e.timestamp > five_min_ago)
            .filter(|e| e.service == service_name)
            .count();

        if total_recent > 10 {
            let error_rate = (recent_5xx as f64 + 1.0) / (total_recent as f64 + 1.0);
            if error_rate > 0.10 {
                let alert = Alert::new(
                    "info",
                    format!("Error rate > 10% for '{}' in last 5 minutes ({:.0}%)", service_name, error_rate * 100.0),
                    service_name.to_string(),
                );
                state.alerts.write().await.push(alert);
                return Some("info".to_string());
            }
        }
    }

    // INFO: High latency (> 5s)
    if duration.as_secs() > 5 {
        let alert = Alert::new(
            "info",
            format!("High latency ({:.1}s) for '{}'", duration.as_secs_f64(), service_name),
            service_name.to_string(),
        );
        state.alerts.write().await.push(alert);
        return Some("info".to_string());
    }

    // INFO: Large response (> 1MB)
    if response_size > 1_048_576 {
        let alert = Alert::new(
            "info",
            format!("Large response ({:.1} MB) from '{}'", response_size as f64 / 1_048_576.0, service_name),
            service_name.to_string(),
        );
        state.alerts.write().await.push(alert);
        return Some("info".to_string());
    }

    None
}
