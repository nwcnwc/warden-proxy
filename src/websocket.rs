use axum::extract::ws::{WebSocket, Message, CloseFrame};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite, MaybeTlsStream};
use tracing::error;

/// Bridge messages between a client WebSocket and an upstream WebSocket.
///
/// Auth injection happens via the upstream connection request headers.
/// The caller (proxy.rs) handles access control and rate limiting.
pub async fn bridge(
    client_socket: WebSocket,
    upstream_url: &str,
    service: &crate::vault::ServiceEntry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Build upstream connection request with auth header
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut request = upstream_url.into_client_request()?;
    // Inject the real auth header for the upstream service
    if let (Ok(name), Ok(value)) = (
        axum::http::HeaderName::from_bytes(service.header.as_bytes()),
        axum::http::HeaderValue::from_str(&service.value),
    ) {
        request.headers_mut().insert(name, value);
    }

    // Connect to upstream WebSocket
    let (upstream_socket, _response): (
        tokio_tungstenite::WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
        _,
    ) = connect_async(request).await?;

    let (mut client_write, mut client_read) = client_socket.split();
    let (mut upstream_write, mut upstream_read) = upstream_socket.split();

    // Bridge: client -> upstream
    let client_to_upstream = async {
        while let Some(msg) = client_read.next().await {
            match msg {
                Ok(msg) => {
                    let tung_msg = axum_to_tungstenite(msg);
                    if upstream_write.send(tung_msg).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("WebSocket client read error: {}", e);
                    break;
                }
            }
        }
    };

    // Bridge: upstream -> client
    let upstream_to_client = async {
        while let Some(msg) = upstream_read.next().await {
            match msg {
                Ok(msg) => {
                    let axum_msg = tungstenite_to_axum(msg);
                    if client_write.send(axum_msg).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("WebSocket upstream read error: {}", e);
                    break;
                }
            }
        }
    };

    // Run both directions concurrently — when one ends, the other stops
    tokio::select! {
        _ = client_to_upstream => {},
        _ = upstream_to_client => {},
    }

    Ok(())
}

/// Convert axum WebSocket message to tungstenite message
fn axum_to_tungstenite(msg: Message) -> tungstenite::Message {
    match msg {
        Message::Text(t) => tungstenite::Message::text(t.to_string()),
        Message::Binary(b) => tungstenite::Message::binary(b.to_vec()),
        Message::Ping(p) => tungstenite::Message::Ping(p.to_vec().into()),
        Message::Pong(p) => tungstenite::Message::Pong(p.to_vec().into()),
        Message::Close(frame) => {
            let tung_frame = frame.map(|f| tungstenite::protocol::CloseFrame {
                code: tungstenite::protocol::frame::coding::CloseCode::from(f.code),
                reason: f.reason.to_string().into(),
            });
            tungstenite::Message::Close(tung_frame)
        }
    }
}

/// Convert tungstenite message to axum WebSocket message
fn tungstenite_to_axum(msg: tungstenite::Message) -> Message {
    match msg {
        tungstenite::Message::Text(t) => Message::Text(t.to_string().into()),
        tungstenite::Message::Binary(b) => Message::Binary(b.to_vec().into()),
        tungstenite::Message::Ping(p) => Message::Ping(p.to_vec().into()),
        tungstenite::Message::Pong(p) => Message::Pong(p.to_vec().into()),
        tungstenite::Message::Close(frame) => {
            let axum_frame = frame.map(|f| CloseFrame {
                code: f.code.into(),
                reason: f.reason.to_string().into(),
            });
            Message::Close(axum_frame)
        }
        tungstenite::Message::Frame(_) => Message::Binary(vec![].into()),
    }
}
