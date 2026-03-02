use axum::{
    extract::Path,
    http::{StatusCode, header, HeaderMap},
    response::{IntoResponse, Response},
};

/// Embedded client files — compiled into the binary.
/// No external file dependencies at runtime.
const WARDEN_SW: &str = include_str!("../client/warden-sw.js");
const WARDEN_LOADER: &str = include_str!("../client/warden-loader.js");

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
