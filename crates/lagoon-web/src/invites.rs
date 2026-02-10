/// Web API for invite code management.
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use lagoon_server::irc::invite::{InviteCode, InviteKind, Privilege};

use crate::auth;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateInviteRequest {
    pub kind: String,
    pub target: String,
    #[serde(default)]
    pub privileges: Vec<String>,
    pub max_uses: Option<u32>,
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
pub struct InviteResponse {
    pub code: String,
    pub kind: String,
    pub target: String,
    pub privileges: Vec<String>,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub active: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
}

impl From<&InviteCode> for InviteResponse {
    fn from(inv: &InviteCode) -> Self {
        Self {
            code: inv.code.clone(),
            kind: match inv.kind {
                InviteKind::CommunityLink => "community".into(),
                InviteKind::ServerPeering => "peering".into(),
            },
            target: inv.target.clone(),
            privileges: inv.privileges.iter().map(|p| p.to_string()).collect(),
            max_uses: inv.max_uses,
            uses: inv.uses,
            active: inv.active,
            created_at: inv.created_at.to_rfc3339(),
            expires_at: inv.expires_at.map(|e| e.to_rfc3339()),
        }
    }
}

impl From<InviteCode> for InviteResponse {
    fn from(inv: InviteCode) -> Self {
        InviteResponse::from(&inv)
    }
}

/// Extract the session username from the Authorization header.
async fn require_auth(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<String, StatusCode> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    auth::resolve_session(state, token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)
}

/// POST /api/invite/create
pub async fn create_invite(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateInviteRequest>,
) -> Result<Json<InviteResponse>, StatusCode> {
    let _username = require_auth(&state, &headers).await?;

    let irc_state = state.irc_state.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let kind = match req.kind.to_lowercase().as_str() {
        "community" | "communitylink" => InviteKind::CommunityLink,
        "peering" | "serverpeering" => InviteKind::ServerPeering,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let privileges: Vec<Privilege> = req
        .privileges
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let expires_at = req
        .expires_at
        .as_deref()
        .and_then(|s| s.parse::<chrono::DateTime<chrono::Utc>>().ok());

    let mut st = irc_state.write().await;
    let lens_id = st.lens.peer_id.clone();
    let invite = st
        .invites
        .create(kind, lens_id, req.target, privileges, req.max_uses, expires_at);
    let resp = InviteResponse::from(invite);
    Ok(Json(resp))
}

/// POST /api/invite/use
#[derive(Deserialize)]
pub struct UseInviteRequest {
    pub code: String,
}

pub async fn use_invite(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<UseInviteRequest>,
) -> Result<Json<InviteResponse>, StatusCode> {
    let _username = require_auth(&state, &headers).await?;

    let irc_state = state.irc_state.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let mut st = irc_state.write().await;
    let invite = st.invites.use_code(&req.code).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(InviteResponse::from(invite)))
}

/// GET /api/invite/list
pub async fn list_invites(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<InviteResponse>>, StatusCode> {
    let _username = require_auth(&state, &headers).await?;

    let irc_state = state.irc_state.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let st = irc_state.read().await;
    let invites: Vec<InviteResponse> = st
        .invites
        .list(None)
        .into_iter()
        .map(InviteResponse::from)
        .collect();
    Ok(Json(invites))
}

/// PATCH /api/invite/:code
#[derive(Deserialize)]
pub struct ModifyInviteRequest {
    pub privileges: Option<Vec<String>>,
    pub max_uses: Option<Option<u32>>,
    pub expires_at: Option<Option<String>>,
}

pub async fn modify_invite(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(code): Path<String>,
    Json(req): Json<ModifyInviteRequest>,
) -> Result<Json<InviteResponse>, StatusCode> {
    let _username = require_auth(&state, &headers).await?;

    let irc_state = state.irc_state.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let mut st = irc_state.write().await;

    let new_privs = req.privileges.map(|privs| {
        privs
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect::<Vec<Privilege>>()
    });

    let new_expires = req.expires_at.map(|opt| {
        opt.and_then(|s| s.parse::<chrono::DateTime<chrono::Utc>>().ok())
    });

    let invite = st
        .invites
        .modify(&code, new_privs, req.max_uses, new_expires)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(InviteResponse::from(invite)))
}

/// DELETE /api/invite/:code
pub async fn revoke_invite(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(code): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let _username = require_auth(&state, &headers).await?;

    let irc_state = state.irc_state.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let mut st = irc_state.write().await;
    st.invites
        .revoke(&code)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(StatusCode::NO_CONTENT)
}
