/// Web API for mesh topology — REST + WebSocket real-time updates.
use axum::{
    Json,
    extract::{State, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
};

use lagoon_server::irc::server::MeshSnapshot;

use crate::state::AppState;

/// GET /api/topology — current mesh topology snapshot.
pub async fn get_topology(
    State(state): State<AppState>,
) -> Result<Json<MeshSnapshot>, StatusCode> {
    let watch = state.mesh_watch.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let snapshot = watch.borrow().clone();
    Ok(Json(snapshot))
}

/// GET /api/topology/ws — WebSocket that pushes MeshSnapshot on every change.
pub async fn topology_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| topology_ws_handler(socket, state))
}

async fn topology_ws_handler(
    mut socket: axum::extract::ws::WebSocket,
    state: AppState,
) {
    use axum::extract::ws::Message;

    let Some(mut watch) = state.mesh_watch.clone() else {
        let _ = socket
            .send(Message::Close(None))
            .await;
        return;
    };

    // Send initial snapshot.
    let snapshot = watch.borrow().clone();
    if let Ok(json) = serde_json::to_string(&snapshot) {
        if socket.send(Message::Text(json.into())).await.is_err() {
            return;
        }
    }

    // Push updates as they arrive.
    loop {
        if watch.changed().await.is_err() {
            break;
        }
        let snapshot = watch.borrow_and_update().clone();
        if let Ok(json) = serde_json::to_string(&snapshot) {
            if socket.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    }
}
