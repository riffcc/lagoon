use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{OnceCell, RwLock, watch};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use lagoon_server::irc::server::{MeshSnapshot, SharedState};

/// A registered user — identified by their passkey.
#[derive(Clone, Debug)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub credentials: Vec<Passkey>,
    /// Ed25519 public key derived from passkey registration.
    /// This becomes the user's identity in the Lagoon mesh.
    pub ed25519_pubkey: Option<Vec<u8>>,
}

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Lazily initialized WebAuthn — auto-detects RP ID from first request's
    /// Origin header, or eagerly initialized from LAGOON_WEB_ORIGIN env var.
    webauthn: Arc<OnceCell<Webauthn>>,
    /// Users by username.
    pub users: Arc<RwLock<HashMap<String, User>>>,
    /// Active sessions: token → username.
    pub sessions: Arc<RwLock<HashMap<String, String>>>,
    /// IRC server address to bridge to.
    pub irc_addr: String,
    /// IRC server shared state (when embedded).
    pub irc_state: Option<SharedState>,
    /// Mesh topology watch channel receiver.
    pub mesh_watch: Option<watch::Receiver<MeshSnapshot>>,
    /// True when running in embedded mode (default).
    /// All clients are web gateway users — their IPs are meaningless.
    pub gateway_mode: bool,
}

/// Build a WebAuthn instance from an origin URL string.
/// RP ID is automatically extracted from the origin's hostname.
fn build_webauthn(origin: &str) -> Result<Webauthn, Box<dyn std::error::Error + Send + Sync>> {
    let rp_origin = url::Url::parse(origin)?;
    let rp_id = rp_origin
        .host_str()
        .ok_or("Origin URL must contain a hostname")?;

    tracing::info!("WebAuthn configured: rp_id={rp_id}, origin={origin}");

    let builder = WebauthnBuilder::new(rp_id, &rp_origin)?;
    Ok(builder.rp_name("Lagoon").build()?)
}

impl AppState {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cell = OnceCell::new();

        // If LAGOON_WEB_ORIGIN is set, eagerly initialize WebAuthn.
        // Otherwise, it auto-detects from the first request's Origin header.
        if let Ok(origin) = std::env::var("LAGOON_WEB_ORIGIN") {
            let webauthn = build_webauthn(&origin)?;
            cell.set(webauthn).expect("cell is fresh");
        } else {
            tracing::info!(
                "LAGOON_WEB_ORIGIN not set — WebAuthn will auto-detect from first request"
            );
        }

        let irc_addr =
            std::env::var("LAGOON_IRC_ADDR").unwrap_or_else(|_| "127.0.0.1:6667".to_string());

        Ok(Self {
            webauthn: Arc::new(cell),
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            irc_addr,
            irc_state: None,
            mesh_watch: None,
            gateway_mode: false,
        })
    }

    /// Create state with an embedded IRC server in gateway mode.
    /// All clients are web users — their IPs never reach the mesh.
    pub fn with_irc(
        mut self,
        irc_state: SharedState,
        mesh_watch: watch::Receiver<MeshSnapshot>,
    ) -> Self {
        self.irc_state = Some(irc_state);
        self.mesh_watch = Some(mesh_watch);
        self.gateway_mode = true;
        self
    }

    /// Get the WebAuthn instance, lazily initializing from the origin if needed.
    pub async fn webauthn(&self, origin: &str) -> Result<&Webauthn, String> {
        let origin = origin.to_string();
        self.webauthn
            .get_or_try_init(|| async { build_webauthn(&origin).map_err(|e| e.to_string()) })
            .await
    }
}
