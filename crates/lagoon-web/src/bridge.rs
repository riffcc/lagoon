use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{error, info, warn};

use crate::auth;
use crate::state::AppState;

/// Messages from the browser to the server.
#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMessage {
    /// Authenticate with session token.
    #[serde(rename = "auth")]
    Auth { token: String },
    /// Send raw IRC line.
    #[serde(rename = "irc")]
    Irc { line: String },
}

/// Messages from the server to the browser.
#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerMessage {
    /// Authentication result.
    #[serde(rename = "auth_ok")]
    AuthOk { username: String },
    #[serde(rename = "auth_fail")]
    AuthFail { reason: String },
    /// Raw IRC line from the server.
    #[serde(rename = "irc")]
    Irc { line: String },
    /// Connection status.
    #[serde(rename = "status")]
    Status { connected: bool, message: String },
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(ws: WebSocket, state: AppState) {
    let (mut ws_tx, mut ws_rx) = ws.split();

    // First message must be auth.
    let username = match wait_for_auth(&mut ws_rx, &state).await {
        Some(name) => name,
        None => {
            let msg = serde_json::to_string(&ServerMessage::AuthFail {
                reason: "Authentication required".into(),
            })
            .unwrap();
            let _ = ws_tx.send(Message::Text(msg.into())).await;
            return;
        }
    };

    let msg = serde_json::to_string(&ServerMessage::AuthOk {
        username: username.clone(),
    })
    .unwrap();
    if ws_tx.send(Message::Text(msg.into())).await.is_err() {
        return;
    }

    info!("web client authenticated: {username}");

    // Connect to the IRC server.
    let irc_stream = match TcpStream::connect(&state.irc_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to connect to IRC server at {}: {e}", state.irc_addr);
            let msg = serde_json::to_string(&ServerMessage::Status {
                connected: false,
                message: format!("IRC connection failed: {e}"),
            })
            .unwrap();
            let _ = ws_tx.send(Message::Text(msg.into())).await;
            return;
        }
    };

    let (irc_read, mut irc_write) = irc_stream.into_split();
    let mut irc_reader = BufReader::new(irc_read);

    // Auto-register on the IRC server with the authenticated username.
    // Gateway ident uses web~ prefix to distinguish web users from future direct IRC users.
    let nick_cmd = format!("NICK {username}\r\n");
    let user_cmd = format!("USER web~{username} 0 * :{username} via Lagoon Web Gateway\r\n");
    if let Err(e) = irc_write.write_all(nick_cmd.as_bytes()).await {
        error!("IRC write error: {e}");
        return;
    }
    if let Err(e) = irc_write.write_all(user_cmd.as_bytes()).await {
        error!("IRC write error: {e}");
        return;
    }

    let msg = serde_json::to_string(&ServerMessage::Status {
        connected: true,
        message: "Connected to IRC".into(),
    })
    .unwrap();
    let _ = ws_tx.send(Message::Text(msg.into())).await;

    // Bridge: IRC server → WebSocket (browser).
    let ws_tx = std::sync::Arc::new(tokio::sync::Mutex::new(ws_tx));
    let ws_tx_irc = ws_tx.clone();

    let irc_to_ws = tokio::spawn(async move {
        let mut line_buf = String::new();
        loop {
            line_buf.clear();
            match irc_reader.read_line(&mut line_buf).await {
                Ok(0) => {
                    // IRC disconnected.
                    let msg = serde_json::to_string(&ServerMessage::Status {
                        connected: false,
                        message: "IRC disconnected".into(),
                    })
                    .unwrap();
                    let _ = ws_tx_irc.lock().await.send(Message::Text(msg.into())).await;
                    break;
                }
                Ok(_) => {
                    let line = line_buf.trim_end().to_string();
                    if line.is_empty() {
                        continue;
                    }

                    // Handle PING from IRC server.
                    if line.starts_with("PING ") {
                        // We handle PING → PONG on the server side so the user doesn't have to.
                        // But the IRC server should handle this itself. Just relay it.
                    }

                    let msg = serde_json::to_string(&ServerMessage::Irc { line }).unwrap();
                    if ws_tx_irc.lock().await.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("IRC read error: {e}");
                    break;
                }
            }
        }
    });

    // Bridge: WebSocket (browser) → IRC server.
    let ws_to_irc = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Text(text) => {
                    let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text) else {
                        continue;
                    };
                    match client_msg {
                        ClientMessage::Irc { line } => {
                            // Send raw IRC line to server.
                            let irc_line = format!("{}\r\n", line.trim_end());
                            if let Err(e) = irc_write.write_all(irc_line.as_bytes()).await {
                                error!("IRC write error: {e}");
                                break;
                            }
                        }
                        ClientMessage::Auth { .. } => {
                            // Already authenticated, ignore.
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        // Clean up: send QUIT to IRC.
        let _ = irc_write.write_all(b"QUIT :Web client disconnected\r\n").await;
    });

    // Wait for either direction to finish.
    tokio::select! {
        _ = irc_to_ws => {},
        _ = ws_to_irc => {},
    }

    info!("web client disconnected: {username}");
}

/// Federation WebSocket endpoint — bridges WebSocket ↔ raw IRC for mesh federation.
///
/// No authentication required here: federation uses MESH HELLO with cryptographic
/// identity verification (Ed25519 lens IDs). This endpoint lets remote servers
/// tunnel IRC federation traffic over WebSocket, surviving CDN/proxy layers
/// (e.g. Cloudflare) that only pass HTTP/WebSocket, not raw TCP.
pub async fn federation_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| federation_ws_bridge(socket, state))
}

async fn federation_ws_bridge(ws: WebSocket, state: AppState) {
    let irc_stream = match TcpStream::connect(&state.irc_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("federation ws: failed to connect to IRC server at {}: {e}", state.irc_addr);
            return;
        }
    };

    info!("federation ws: new inbound tunnel");

    let (irc_read, mut irc_write) = irc_stream.into_split();
    let mut irc_reader = BufReader::new(irc_read);
    let (mut ws_tx, mut ws_rx) = ws.split();

    // WS → IRC: each text message is one IRC line.
    let ws_to_irc = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Text(text) => {
                    let line = format!("{}\r\n", text.trim_end());
                    if irc_write.write_all(line.as_bytes()).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    };

    // IRC → WS: each IRC line becomes a text message.
    let irc_to_ws = async {
        let mut line = String::new();
        loop {
            line.clear();
            match irc_reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    if ws_tx.send(Message::Text(trimmed.into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    tokio::select! {
        _ = ws_to_irc => {}
        _ = irc_to_ws => {}
    }

    info!("federation ws: tunnel closed");
}

async fn wait_for_auth(
    ws_rx: &mut (impl StreamExt<Item = Result<Message, axum::Error>> + Unpin),
    state: &AppState,
) -> Option<String> {
    // Give the client a reasonable window to authenticate.
    let timeout = tokio::time::Duration::from_secs(30);
    match tokio::time::timeout(timeout, ws_rx.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            let msg: ClientMessage = serde_json::from_str(&text).ok()?;
            match msg {
                ClientMessage::Auth { token } => auth::resolve_session(state, &token).await,
                _ => None,
            }
        }
        _ => None,
    }
}
