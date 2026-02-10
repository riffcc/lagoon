mod auth;
mod bridge;
mod invites;
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
        // Federation WebSocket tunnel (IRC-over-WS for CDN/proxy traversal)
        .route("/api/federation/ws", get(bridge::federation_ws_handler))
        // Topology endpoints
        .route("/api/topology", get(topology::get_topology))
        .route("/api/topology/debug", get(topology::get_topology_debug))
        .route("/api/topology/ws", get(topology::topology_ws))
        // Invite endpoints
        .route("/api/invite/create", post(invites::create_invite))
        .route("/api/invite/use", post(invites::use_invite))
        .route("/api/invite/list", get(invites::list_invites))
        .route("/api/invite/{code}", patch(invites::modify_invite))
        .route("/api/invite/{code}", delete(invites::revoke_invite))
        // Serve Vue.js SPA (static files)
        .fallback_service(ServeDir::new("web/dist").append_index_html_on_directories(true))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = AppState::new()?;
    let app = build_router(state);

    let use_tls = std::env::var("LAGOON_WEB_NO_TLS").is_err();

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
    let addrs: Vec<&str> = vec![bind_static];

    // In gateway mode we do NOT bind Yggdrasil for IRC. The web gateway is the
    // sole user-facing entry point. Federation happens via outbound TLS
    // connections only (or inbound via HAProxy → loopback for London nodes).
    if lagoon_server::irc::transport::detect_yggdrasil_addr().is_some() {
        info!("Yggdrasil detected but suppressed in gateway mode — federation is outbound-only");
    }

    let (irc_state, topology_rx, _irc_handles) =
        lagoon_server::irc::server::start(&addrs).await?;

    let state = AppState::new()?.with_irc(irc_state, topology_rx);
    let app = build_router(state);

    let use_tls = std::env::var("LAGOON_WEB_NO_TLS").is_err();

    if use_tls {
        serve_tls(app).await
    } else {
        serve_plain(app).await
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
