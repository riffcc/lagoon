use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use axum_extra::TypedHeader;
use axum_extra::headers::{Authorization, authorization::Bearer};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::state::{AppState, User};

/// Extract the origin URL from request headers for WebAuthn auto-detection.
/// Prefers the `Origin` header (set by browsers on POST), falls back to `Host`.
fn extract_origin(headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    if let Some(origin) = headers.get("origin") {
        return origin
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Origin header".into()));
    }

    if let Some(host) = headers.get("host") {
        let host = host
            .to_str()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Host header".into()))?;
        return Ok(format!("https://{host}"));
    }

    Err((
        StatusCode::BAD_REQUEST,
        "No Origin or Host header — cannot determine WebAuthn RP ID".into(),
    ))
}

#[derive(Deserialize)]
pub struct RegisterBeginRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct RegisterBeginResponse {
    pub options: CreationChallengeResponse,
}

/// Begin passkey registration — returns a challenge for the browser.
pub async fn register_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterBeginRequest>,
) -> Result<Json<RegisterBeginResponse>, (StatusCode, String)> {
    let origin = extract_origin(&headers)?;
    let webauthn = state
        .webauthn(&origin)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("WebAuthn init: {e}")))?;

    let username = req.username.trim().to_string();
    if username.is_empty() || username.len() > 32 {
        return Err((StatusCode::BAD_REQUEST, "Username must be 1-32 characters".into()));
    }

    // Check if user already exists.
    let users = state.users.read().await;
    let existing_creds: Vec<Passkey> = users
        .get(&username)
        .map(|u| u.credentials.clone())
        .unwrap_or_default();
    drop(users);

    let user_id = Uuid::new_v4();

    let exclude = existing_creds
        .iter()
        .map(|c| c.cred_id().clone())
        .collect::<Vec<_>>();

    let (challenge, reg_state) = webauthn
        .start_passkey_registration(user_id, &username, &username, Some(exclude))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("WebAuthn error: {e}")))?;

    // Store the registration state for completion.
    state
        .reg_challenges
        .write()
        .await
        .insert(username, reg_state);

    Ok(Json(RegisterBeginResponse { options: challenge }))
}

#[derive(Deserialize)]
pub struct RegisterCompleteRequest {
    pub username: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub username: String,
}

/// Complete passkey registration — verify the credential and create the user.
pub async fn register_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterCompleteRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let origin = extract_origin(&headers)?;
    let webauthn = state
        .webauthn(&origin)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("WebAuthn init: {e}")))?;

    let username = req.username.trim().to_string();

    let reg_state = state
        .reg_challenges
        .write()
        .await
        .remove(&username)
        .ok_or((StatusCode::BAD_REQUEST, "No pending registration".into()))?;

    let passkey = webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Registration failed: {e}")))?;

    // Create or update user.
    let mut users = state.users.write().await;
    let user = users.entry(username.clone()).or_insert_with(|| User {
        id: Uuid::new_v4(),
        username: username.clone(),
        credentials: Vec::new(),
        ed25519_pubkey: None,
    });
    user.credentials.push(passkey);
    drop(users);

    // Create session token.
    let token = generate_session_token();
    state.sessions.write().await.insert(token.clone(), username.clone());

    Ok(Json(AuthResponse { token, username }))
}

#[derive(Deserialize)]
pub struct LoginBeginRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct LoginBeginResponse {
    pub options: RequestChallengeResponse,
}

/// Begin passkey authentication — returns a challenge.
pub async fn login_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginBeginRequest>,
) -> Result<Json<LoginBeginResponse>, (StatusCode, String)> {
    let origin = extract_origin(&headers)?;
    let webauthn = state
        .webauthn(&origin)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("WebAuthn init: {e}")))?;

    let username = req.username.trim().to_string();

    let users = state.users.read().await;
    let user = users
        .get(&username)
        .ok_or((StatusCode::NOT_FOUND, "User not found".into()))?;

    let (challenge, auth_state) = webauthn
        .start_passkey_authentication(&user.credentials)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("WebAuthn error: {e}")))?;

    drop(users);

    state
        .auth_challenges
        .write()
        .await
        .insert(username, auth_state);

    Ok(Json(LoginBeginResponse { options: challenge }))
}

#[derive(Deserialize)]
pub struct LoginCompleteRequest {
    pub username: String,
    pub credential: PublicKeyCredential,
}

/// Complete passkey authentication — verify and issue session.
pub async fn login_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginCompleteRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let origin = extract_origin(&headers)?;
    let webauthn = state
        .webauthn(&origin)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("WebAuthn init: {e}")))?;

    let username = req.username.trim().to_string();

    let auth_state = state
        .auth_challenges
        .write()
        .await
        .remove(&username)
        .ok_or((StatusCode::BAD_REQUEST, "No pending authentication".into()))?;

    let auth_result = webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Auth failed: {e}")))?;

    // Update credential counter to prevent replay.
    let mut users = state.users.write().await;
    if let Some(user) = users.get_mut(&username) {
        user.credentials.iter_mut().for_each(|cred| {
            cred.update_credential(&auth_result);
        });
    }
    drop(users);

    let token = generate_session_token();
    state.sessions.write().await.insert(token.clone(), username.clone());

    Ok(Json(AuthResponse { token, username }))
}

#[derive(Serialize)]
pub struct MeResponse {
    pub username: String,
}

/// Get current user from session token.
pub async fn me(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<MeResponse>, StatusCode> {
    let sessions = state.sessions.read().await;
    let username = sessions
        .get(auth.token())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .clone();

    Ok(Json(MeResponse { username }))
}

/// Resolve a session token to a username (used by the WS bridge).
pub async fn resolve_session(state: &AppState, token: &str) -> Option<String> {
    state.sessions.read().await.get(token).cloned()
}

fn generate_session_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}
