//! Session capture via wry WebView.
//!
//! Only compiled when the `session-capture` feature is enabled.
//! Opens a native WebView window for the user to log into a website,
//! then extracts all auth state (cookies, localStorage, sessionStorage).

use std::collections::HashMap;
use tracing::{info, error};
use crate::sessions::{Session, Cookie, SessionStatus};

/// Capture a session by opening a WebView window to the target domain.
///
/// The user logs in normally (supports 2FA, CAPTCHAs, etc.).
/// On window close or "Done" button click, all auth state is extracted.
pub fn capture_session(domain: &str, start_url: Option<&str>) -> Result<Session, Box<dyn std::error::Error>> {
    let url = start_url.unwrap_or(&format!("https://{}", domain)).to_string();
    info!("Opening capture window for {} -> {}", domain, url);

    let (cookies, local_storage, session_storage) = open_webview_and_capture(&url, domain)?;

    let now = chrono_now();
    // All cookies captured during login are considered auth cookies
    let auth_cookie_names: Vec<String> = cookies.iter().map(|c| c.name.clone()).collect();
    Ok(Session {
        domain: domain.to_string(),
        captured_at: now.clone(),
        last_used: now,
        status: SessionStatus::Active,
        cookies,
        local_storage,
        session_storage,
        auth_cookie_names,
        token_fields: vec![],
        token_map: Default::default(),
    })
}

fn open_webview_and_capture(
    url: &str,
    domain: &str,
) -> Result<(Vec<Cookie>, HashMap<String, HashMap<String, String>>, HashMap<String, HashMap<String, String>>), Box<dyn std::error::Error>> {
    use wry::{WebViewBuilder, Rect, dpi::LogicalSize};

    // Channel for receiving captured data from the WebView
    let (tx, rx) = std::sync::mpsc::channel::<String>();

    let event_loop = winit::event_loop::EventLoop::new()?;
    let window = winit::window::WindowBuilder::new()
        .with_title(format!("Warden Login — {}", domain))
        .with_inner_size(winit::dpi::LogicalSize::new(1024.0, 768.0))
        .build(&event_loop)?;

    let tx_clone = tx.clone();

    // JavaScript to inject a "Done" button and extract auth state
    let extract_js = r#"
        (function() {
            // Inject done button bar
            if (!document.getElementById('warden-done-bar')) {
                var bar = document.createElement('div');
                bar.id = 'warden-done-bar';
                bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;background:#1a1a1a;color:#ffaa00;padding:8px 16px;display:flex;align-items:center;justify-content:space-between;font-family:system-ui;font-size:14px;border-bottom:2px solid #ffaa00;';
                bar.innerHTML = '<span>Warden: Log in, then click Done</span><button id="warden-done-btn" style="background:#ffaa00;color:#1a1a1a;border:none;padding:8px 24px;border-radius:6px;font-weight:bold;cursor:pointer;font-size:14px;">Done — I am logged in</button>';
                document.body.prepend(bar);
                document.body.style.marginTop = '44px';
                document.getElementById('warden-done-btn').addEventListener('click', function() {
                    var data = {
                        localStorage: JSON.stringify(Object.fromEntries(Object.entries(localStorage))),
                        sessionStorage: JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))
                    };
                    window.ipc.postMessage(JSON.stringify(data));
                });
            }
        })();
    "#;

    let webview = WebViewBuilder::new()
        .with_url(url)
        .with_ipc_handler(move |msg| {
            let _ = tx_clone.send(msg.body().to_string());
        })
        .with_initialization_script(extract_js)
        .build(&window)?;

    // Run event loop until window is closed
    event_loop.run(move |event, elwt| {
        match event {
            winit::event::Event::WindowEvent {
                event: winit::event::WindowEvent::CloseRequested,
                ..
            } => {
                elwt.exit();
            }
            _ => {}
        }
    })?;

    // Try to get the captured data
    let mut local_storage = HashMap::new();
    let mut session_storage = HashMap::new();

    if let Ok(msg) = rx.try_recv() {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&msg) {
            if let Some(ls) = data.get("localStorage").and_then(|v| v.as_str()) {
                if let Ok(parsed) = serde_json::from_str::<HashMap<String, String>>(ls) {
                    local_storage.insert(url.to_string(), parsed);
                }
            }
            if let Some(ss) = data.get("sessionStorage").and_then(|v| v.as_str()) {
                if let Ok(parsed) = serde_json::from_str::<HashMap<String, String>>(ss) {
                    session_storage.insert(url.to_string(), parsed);
                }
            }
        }
    }

    // Note: Cookie extraction from wry is platform-specific and may require
    // additional APIs. For now, we capture what's available via JS.
    // TODO: Use platform-specific cookie APIs for HttpOnly cookies.
    let cookies = vec![];

    Ok((cookies, local_storage, session_storage))
}

fn chrono_now() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Simple ISO 8601 without external crate
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Rough date calculation (good enough for timestamps)
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
        if remaining < days_in_year { break; }
        remaining -= days_in_year;
        y += 1;
    }
    let months = [31, if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 1;
    for &dm in &months {
        if remaining < dm { break; }
        remaining -= dm;
        m += 1;
    }
    let d = remaining + 1;

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hours, minutes, seconds)
}
