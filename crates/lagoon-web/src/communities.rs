/// Web API for community (circle) management.
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use lagoon_server::irc::community::{Community, CommunityRole};

use crate::auth;
use crate::state::AppState;

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

/// Get the IRC shared state or 503.
fn irc_state(state: &AppState) -> Result<&lagoon_server::irc::server::SharedState, StatusCode> {
    state
        .irc_state
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)
}

// -- Response types --

#[derive(Serialize)]
pub struct CommunityResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub owner: String,
    pub channels: Vec<String>,
    pub member_count: usize,
    pub created_at: String,
}

impl From<&Community> for CommunityResponse {
    fn from(c: &Community) -> Self {
        Self {
            id: c.id.to_string(),
            name: c.name.clone(),
            description: c.description.clone(),
            owner: c.owner.clone(),
            channels: c.channels.clone(),
            member_count: c.members.len(),
            created_at: c.created_at.to_rfc3339(),
        }
    }
}

#[derive(Serialize)]
pub struct MemberResponse {
    pub username: String,
    pub role: String,
}

// -- Request types --

#[derive(Deserialize)]
pub struct CreateCommunityRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Deserialize)]
pub struct UpdateCommunityRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct ChannelRequest {
    pub name: String,
}

// -- Handlers --

/// GET /api/communities — list communities the user belongs to.
pub async fn list(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<CommunityResponse>>, StatusCode> {
    let username = require_auth(&state, &headers).await?;
    let irc = irc_state(&state)?;
    let st = irc.read().await;
    let communities: Vec<CommunityResponse> = st
        .communities
        .list_for_user(&username)
        .into_iter()
        .map(CommunityResponse::from)
        .collect();
    Ok(Json(communities))
}

/// POST /api/communities — create a new community.
pub async fn create(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateCommunityRequest>,
) -> Result<(StatusCode, Json<CommunityResponse>), StatusCode> {
    let username = require_auth(&state, &headers).await?;
    let irc = irc_state(&state)?;

    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut st = irc.write().await;
    let community = st.communities.create(name, req.description, username);
    let resp = CommunityResponse::from(community);
    Ok((StatusCode::CREATED, Json(resp)))
}

/// GET /api/communities/:id — get a single community (must be a member).
pub async fn get_one(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<CommunityResponse>, StatusCode> {
    let username = require_auth(&state, &headers).await?;
    let id: Uuid = id.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let irc = irc_state(&state)?;
    let st = irc.read().await;

    if !st.communities.is_member(id, &username) {
        return Err(StatusCode::FORBIDDEN);
    }

    let community = st.communities.get(id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(CommunityResponse::from(community)))
}

/// PATCH /api/communities/:id — update community metadata (owner/mod only).
pub async fn update(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateCommunityRequest>,
) -> Result<Json<CommunityResponse>, StatusCode> {
    let username = require_auth(&state, &headers).await?;
    let id: Uuid = id.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let irc = irc_state(&state)?;
    let mut st = irc.write().await;

    if !st.communities.has_role(id, &username, CommunityRole::Moderator) {
        return Err(StatusCode::FORBIDDEN);
    }

    let community = st
        .communities
        .update(id, req.name, req.description)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(CommunityResponse::from(community)))
}

/// DELETE /api/communities/:id — delete a community (owner only).
pub async fn delete(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let username = require_auth(&state, &headers).await?;
    let id: Uuid = id.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let irc = irc_state(&state)?;
    let mut st = irc.write().await;

    st.communities
        .delete(id, &username)
        .map_err(|_| StatusCode::FORBIDDEN)?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/communities/:id/join — join a community.
pub async fn join(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<CommunityResponse>, StatusCode> {
    let username = require_auth(&state, &headers).await?;
    let id: Uuid = id.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let irc = irc_state(&state)?;
    let mut st = irc.write().await;

    let community = st
        .communities
        .join(id, &username)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(CommunityResponse::from(community)))
}

/// POST /api/communities/:id/leave — leave a community.
pub async fn leave(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let username = require_auth(&state, &headers).await?;
    let id: Uuid = id.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let irc = irc_state(&state)?;
    let mut st = irc.write().await;

    st.communities
        .leave(id, &username)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/communities/:id/members — list members of a community.
pub async fn members(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<MemberResponse>>, StatusCode> {
    let username = require_auth(&state, &headers).await?;
    let id: Uuid = id.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let irc = irc_state(&state)?;
    let st = irc.read().await;

    if !st.communities.is_member(id, &username) {
        return Err(StatusCode::FORBIDDEN);
    }

    let community = st.communities.get(id).ok_or(StatusCode::NOT_FOUND)?;
    let members: Vec<MemberResponse> = community
        .members
        .iter()
        .map(|(u, r)| MemberResponse {
            username: u.clone(),
            role: r.to_string(),
        })
        .collect();
    Ok(Json(members))
}

/// POST /api/communities/:id/channels — add a channel to a community (owner/mod).
pub async fn add_channel(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ChannelRequest>,
) -> Result<Json<CommunityResponse>, StatusCode> {
    let username = require_auth(&state, &headers).await?;
    let id: Uuid = id.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let irc = irc_state(&state)?;
    let mut st = irc.write().await;

    if !st.communities.has_role(id, &username, CommunityRole::Moderator) {
        return Err(StatusCode::FORBIDDEN);
    }

    let channel = req.name.trim().to_string();
    if channel.is_empty() || !channel.starts_with('#') {
        return Err(StatusCode::BAD_REQUEST);
    }

    let community = st
        .communities
        .add_channel(id, channel)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(CommunityResponse::from(community)))
}

/// DELETE /api/communities/:id/channels/:name — remove a channel from a community (owner/mod).
pub async fn remove_channel(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((id, name)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    let username = require_auth(&state, &headers).await?;
    let id: Uuid = id.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let irc = irc_state(&state)?;
    let mut st = irc.write().await;

    if !st.communities.has_role(id, &username, CommunityRole::Moderator) {
        return Err(StatusCode::FORBIDDEN);
    }

    let channel = format!("#{name}");
    st.communities
        .remove_channel(id, &channel)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(StatusCode::NO_CONTENT)
}
