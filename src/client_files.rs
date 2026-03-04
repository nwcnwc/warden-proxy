use axum::{
    extract::Path,
    http::{StatusCode, header, HeaderMap},
    response::{IntoResponse, Response},
};

/// Embedded client files — compiled into the binary.
/// No external file dependencies at runtime.
const WARDEN_SW: &str = include_str!("../client/warden-sw.js");
const WARDEN_LOADER: &str = include_str!("../client/warden-loader.js");
const WCURL_SCRIPT: &str = include_str!("../bin/wcurl");

pub async fn serve_client_file(Path(filename): Path<String>) -> Response {
    let (content, content_type) = match filename.as_str() {
        "warden-sw.js" => (WARDEN_SW, "application/javascript"),
        "warden-loader.js" => (WARDEN_LOADER, "application/javascript"),
        _ => {
            return (StatusCode::NOT_FOUND, "Not found").into_response();
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    // Service Worker requires this header to control scope beyond its path
    headers.insert("Service-Worker-Allowed", "/".parse().unwrap());
    // Allow any origin to load these files
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());

    (StatusCode::OK, headers, content.to_string()).into_response()
}

/// Serve the wcurl shell script for bootstrapping VMs and CLI clients.
pub async fn serve_wcurl() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    // Hint to clients that this is a downloadable script
    headers.insert("content-disposition", "attachment; filename=\"wcurl\"".parse().unwrap());

    (StatusCode::OK, headers, WCURL_SCRIPT.to_string()).into_response()
}
