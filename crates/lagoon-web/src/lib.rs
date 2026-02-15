mod auth;
mod bridge;
mod communities;
mod debug;
mod invites;
mod mesh;
pub mod state;
mod tls;
mod topology;

use axum::{
    Router,
    routing::{delete, get, patch, post},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tower::Service;
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{debug, info};

use crate::state::AppState;

fn build_router(state: AppState) -> Router {
    Router::new()
        // Auth endpoints
        .route("/api/auth/register/begin", post(auth::register_begin))
        .route("/api/auth/register/complete", post(auth::register_complete))
        .route("/api/auth/login/begin", post(auth::login_begin))
        .route("/api/auth/login/complete", post(auth::login_complete))
        .route("/api/auth/me", get(auth::me))
        // WebSocket IRC bridge
        .route("/api/ws", get(bridge::ws_handler))
        // Native mesh WebSocket — JSON over WS, no IRC
        .route("/api/mesh/ws", get(mesh::mesh_ws_handler))
        // Topology endpoints
        .route("/api/topology", get(topology::get_topology))
        .route("/api/topology/debug", get(topology::get_topology_debug))
        .route("/api/topology/ws", get(topology::topology_ws))
        // Debug endpoints
        .route("/api/debug/mesh", get(debug::get_debug_mesh))
        // Invite endpoints
        .route("/api/invite/create", post(invites::create_invite))
        .route("/api/invite/use", post(invites::use_invite))
        .route("/api/invite/list", get(invites::list_invites))
        .route("/api/invite/{code}", patch(invites::modify_invite))
        .route("/api/invite/{code}", delete(invites::revoke_invite))
        // Community (circle) endpoints
        .route("/api/communities", get(communities::list).post(communities::create))
        .route("/api/communities/{id}", get(communities::get_one).patch(communities::update).delete(communities::delete))
        .route("/api/communities/{id}/join", post(communities::join))
        .route("/api/communities/{id}/leave", post(communities::leave))
        .route("/api/communities/{id}/members", get(communities::members))
        .route("/api/communities/{id}/channels", post(communities::add_channel))
        .route("/api/communities/{id}/channels/{name}", delete(communities::remove_channel))
        // Serve Vue.js SPA (static files)
        .fallback_service(ServeDir::new("web/dist").append_index_html_on_directories(true))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = AppState::new()?;
    let app = build_router(state);

    let use_tls = std::env::var("LAGOON_WEB_TLS").is_ok();

    if use_tls {
        serve_tls(app).await
    } else {
        serve_plain(app).await
    }
}

/// Run the web gateway with an embedded IRC server.
///
/// Starts the IRC server internally via `server::start()`, shares state
/// directly — single process, no IPC. The gateway is the sole entry point —
/// IRC binds only on loopback (for the bridge) plus optionally on the Docker
/// network (for inter-container federation). No external IRC exposure.
pub async fn run_with_irc() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Start embedded IRC server.
    let bind_addr =
        std::env::var("LAGOON_IRC_BIND").unwrap_or_else(|_| "127.0.0.1:6667".to_string());
    let bind_static: &'static str = Box::leak(bind_addr.into_boxed_str());
    let mut addrs: Vec<&str> = vec![bind_static];

    // With embedded Yggdrasil: the overlay listener is handled by ygg_serve()
    // on port 8080 (same as the web gateway), serving ws:// federation.
    // No raw IRC port on the overlay — everything goes through the web gateway.
    //
    // For TUN-based Ygg (system install, not embedded): bind the IRC server
    // on the Ygg address too, so direct IRC clients can connect.
    let is_wildcard =
        bind_static.starts_with("[::]:") || bind_static.starts_with("0.0.0.0:");
    if !is_wildcard {
        if let Some(ygg_addr) = lagoon_server::irc::transport::detect_yggdrasil_addr() {
            info!("detected Yggdrasil TUN address: {ygg_addr}");
            let addr: &'static str =
                Box::leak(format!("[{ygg_addr}]:6667").into_boxed_str());
            addrs.push(addr);
        }
    }

    let (irc_state, topology_rx, _irc_handles, _vdf_shutdown) =
        lagoon_server::irc::server::start(&addrs).await?;

    // Extract our peer_id for transparent self-rejection, and Ygg node
    // for overlay web gateway listener.
    let (our_peer_id, ygg_node) = {
        let st = irc_state.read().await;
        (st.lens.peer_id.clone(), st.transport_config.ygg_node.clone())
    };

    let state = AppState::new()?.with_irc(irc_state, topology_rx);
    let app = build_router(state);

    // Spawn Ygg overlay web gateway — ws:// federation over the mesh.
    // Other nodes dial ws://[our_ygg_addr]:8080/api/mesh/ws through
    // the overlay. Ygg encrypts the transport, so no TLS needed.
    if let Some(ref node) = ygg_node {
        match node.listen(8080) {
            Ok(listener) => {
                info!("web gateway listening on Yggdrasil overlay port 8080");
                let app_clone = app.clone();
                tokio::spawn(ygg_serve(listener, app_clone));
            }
            Err(e) => tracing::warn!("failed to listen on Ygg overlay port 8080: {e}"),
        }
    }

    let use_tls = std::env::var("LAGOON_WEB_TLS").is_ok();

    if use_tls {
        serve_tls(app).await
    } else {
        serve_transparent(app, our_peer_id).await
    }
}

/// Serve over plain HTTP (for behind reverse proxy / CDN).
async fn serve_plain(app: Router) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::var("LAGOON_WEB_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    info!("listening on http://{addr} (plain — expects TLS termination upstream)");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Serve over plain HTTP with transparent self-rejection.
///
/// Every incoming TCP connection is peeked for the mesh WS handshake URL.
/// If the URL contains `?from={our_peer_id}`, the connection came from
/// ourselves through anycast — we drop it immediately without responding.
/// The proxy sees a backend connection failure and retries on ANOTHER machine.
///
/// To our own dials, we don't exist. We're transparent to ourselves.
/// The listener stays up 100% of the time for OTHER nodes.
async fn serve_transparent(
    app: Router,
    our_peer_id: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::var("LAGOON_WEB_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("listening on http://{addr} (transparent self-rejection enabled)");

    // Build the self-check needle: "from={peer_id}" as bytes.
    let self_needle = format!("from={our_peer_id}");

    loop {
        let (stream, remote_addr) = listener.accept().await?;

        // Peek at the first bytes of the HTTP request to check for self-dial.
        // The mesh WS URL looks like: GET /api/mesh/ws?from=b3b3/xxx HTTP/1.1
        // We check the raw bytes before any HTTP parsing.
        let mut buf = [0u8; 2048];
        let is_self = match stream.peek(&mut buf).await {
            Ok(n) if n > 0 => {
                // Check if the request line contains our peer_id.
                // Safe: peer_id is ASCII hex, URL path is ASCII.
                let request_bytes = &buf[..n];
                // Fast byte search — no UTF-8 allocation needed.
                contains_bytes(request_bytes, self_needle.as_bytes())
            }
            _ => false,
        };

        if is_self {
            // Self-connection through anycast. Drop immediately.
            // The proxy sees RST → retries on another machine.
            drop(stream);
            debug!("transparent self: dropped connection from {remote_addr} (self-dial detected)");
            continue;
        }

        // Not a self-connection — serve normally.
        let app = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let mut app = app.clone();
                    async move { app.call(req.map(axum::body::Body::new)).await }
                },
            );
            let builder =
                hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
                debug!("connection error from {remote_addr}: {e}");
            }
        });
    }
}

/// Fast byte-level substring search (no allocation).
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Serve over HTTPS with auto-generated self-signed certs.
async fn serve_tls(app: Router) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::var("LAGOON_WEB_ADDR").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
    let tls_dir = std::path::PathBuf::from(
        std::env::var("LAGOON_WEB_TLS_DIR").unwrap_or_else(|_| "tls".to_string()),
    );
    let hostname =
        std::env::var("LAGOON_WEB_TLS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    let tls_acceptor = tls::build_acceptor(&tls_dir, &hostname)?;

    info!("listening on https://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("TLS handshake failed from {remote_addr}: {e}");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);

            let service = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let mut app = app.clone();
                    async move { app.call(req.map(axum::body::Body::new)).await }
                },
            );

            let builder =
                hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
                debug!("connection error from {remote_addr}: {e}");
            }
        });
    }
}

/// Serve the web gateway over Yggdrasil overlay connections.
///
/// Accepts connections from the embedded Ygg node's listener (port 8080) and
/// serves the full Axum router — including `/api/mesh/ws` for native mesh
/// federation. This lets other nodes connect via `ws://[ygg_addr]:8080/...`
/// through the encrypted overlay, with no TLS needed (Ygg encrypts).
async fn ygg_serve(listener: yggbridge::YggListener, app: Router) {
    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("ygg overlay accept error: {e}");
                continue;
            }
        };

        let app = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let service = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let mut app = app.clone();
                    async move { app.call(req.map(axum::body::Body::new)).await }
                },
            );

            let builder =
                hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
                debug!("ygg overlay connection error from {remote_addr}: {e}");
            }
        });
    }
}
