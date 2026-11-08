//! Auth HTTP surface: the `/auth/*` routes and the `Authorization: Bearer` extractor.
//!
//! Issuance (`magic-link`, `exchange`) requires a trusted service key in every environment.
//! `verify`, `refresh` and `logout` require their respective secret; `me` requires a
//! valid access token via the [`AuthContext`] extractor. The document/event REST + SSE
//! surface (stage 18) reuses this [`AuthContext`] and wires [`store::role_for`] into the
//! governance gate on the write path (see [`crate::ops::apply`]).

use axum::extract::{FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{random_token, sha256, store, token, AuthError, Login, MAGIC_LINK_TTL_SECONDS};
use crate::AppState;

/// The authenticated caller, extracted from a validated bearer token. A handler that
/// takes this as an argument is automatically gated: a missing/invalid token short-
/// circuits with `401` before the handler body runs.
/// Present only on a project device session ([`super::device::ProjectAuth`]). The
/// account extractor below never sets it and cannot decrypt a device token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceBinding {
    pub key_id: Uuid,
    pub project: Uuid,
    pub session: Uuid,
    /// The scope the route being served requires (`ProjectAuth<S>::SCOPE`). A key's
    /// per-project grant is rechecked against it under the account row lock.
    pub scope: &'static str,
}

pub struct AuthContext {
    pub identity_id: Uuid,
    pub session_generation: i64,
    pub session_id: Option<Uuid>,
    /// `None` for every account login and connector grant.
    pub device: Option<DeviceBinding>,
}

impl FromRequestParts<AppState> for AuthContext {
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AuthError> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::TokenInvalid)?;
        let raw = header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::TokenInvalid)?
            .trim();
        let (identity_id, session_generation, session_id) =
            token::verify_bound_session(&state.auth.paseto_key, raw)?;
        store::ensure_bound_session(&state.pool, identity_id, session_generation, session_id)
            .await?;
        Ok(AuthContext {
            identity_id,
            session_generation,
            session_id,
            device: None,
        })
    }
}

/// The `/auth/*` routes, parameterized over the shared [`AppState`].
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/magic-link", post(magic_link_request))
        .route("/auth/verify", post(verify))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/auth/exchange", post(exchange))
        .merge(super::handover::router())
        .merge(super::sessions::router())
}

// --- magic link request ---------------------------------------------------------

#[derive(Deserialize)]
struct MagicLinkRequest {
    email: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Serialize)]
struct MagicLinkResponse {
    /// Returned only to the authenticated web server, which delivers it by email.
    magic_link_token: String,
    /// Convenience URL a human can use to complete login.
    verify_url: String,
    expires_at: DateTime<Utc>,
}

/// Create the identity if new and issue a one-time magic link.
async fn magic_link_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MagicLinkRequest>,
) -> Result<Json<MagicLinkResponse>, AuthError> {
    require_service(&state, &headers)?;
    if req.email.len() > 254 || !req.email.contains('@') || is_service_email(&req.email) {
        return Err(AuthError::Forbidden);
    }
    let rate_key = sha256(req.email.trim().to_lowercase().as_bytes());
    let attempts: i32 = sqlx::query_scalar("insert into auth_request_window(key_hash) values($1) on conflict(key_hash) do update set attempts=case when auth_request_window.started_at < now()-interval '15 minutes' then 1 else auth_request_window.attempts+1 end, started_at=case when auth_request_window.started_at < now()-interval '15 minutes' then now() else auth_request_window.started_at end returning attempts")
        .bind(rate_key).fetch_one(&state.pool).await?;
    if attempts > 5 {
        return Err(AuthError::Forbidden);
    }
    let identity =
        store::upsert_identity(&state.pool, &req.email, req.display_name.as_deref()).await?;

    let (plaintext, hash) = random_token()?;
    let expires_at = Utc::now() + Duration::seconds(MAGIC_LINK_TTL_SECONDS);
    store::issue_magic_link(&state.pool, identity.id, &hash, expires_at).await?;

    tracing::info!("issued magic link to authenticated web service");
    let verify_url = format!(
        "{}/auth/verify?token={}",
        state.auth.public_base_url, plaintext
    );

    Ok(Json(MagicLinkResponse {
        magic_link_token: plaintext,
        verify_url,
        expires_at,
    }))
}

// --- token responses (verify + refresh) -----------------------------------------

#[derive(Serialize, utoipa::ToSchema)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    /// Access-token lifetime in seconds.
    expires_in: i64,
    /// Opaque refresh token (rotates on every use).
    refresh_token: String,
}

pub(super) async fn mint_session(
    state: &AppState,
    identity_id: Uuid,
    login: &Login<'_>,
) -> Result<TokenResponse, AuthError> {
    let generation = store::session_generation(&state.pool, identity_id).await?;
    mint_session_with(state, &state.pool, identity_id, generation, login)
        .await
        .map(|(tokens, _)| tokens)
}

/// The domain of service-account addresses (`svc-<name>@service.invalid`, a reserved name that
/// can never receive mail). No emailed link is ever issued for one.
pub const SERVICE_DOMAIN: &str = "service.invalid";

/// Whether `email` is a service-account address.
pub fn is_service_email(email: &str) -> bool {
    email
        .trim()
        .rsplit_once('@')
        .is_some_and(|(_, d)| d.trim_end_matches('.').eq_ignore_ascii_case(SERVICE_DOMAIN))
}

/// A new login for `identity_id` at `generation`, written through `executor` (a pool, or a
/// transaction that also does other work, as the app hand-over's redeem does). Returns the
/// tokens and the id of the login (the refresh-token lineage), which an audit row can name.
///
/// The `login_session` row is written by the same statement as the refresh row, with the
/// lifetimes of [`super::SessionPolicy`]. A service account (`identity.kind = 'service'`) gets a
/// login only from the administrators' enrolment route, never from any sign-in.
pub(crate) async fn mint_session_with(
    state: &AppState,
    executor: impl sqlx::PgExecutor<'_>,
    identity_id: Uuid,
    generation: i64,
    login: &Login<'_>,
) -> Result<(TokenResponse, Uuid), AuthError> {
    let session_id = Uuid::new_v4();
    let now = Utc::now();
    let policy = state.session_policy;
    let absolute = match login.lifetime_seconds {
        Some(seconds) => Some(now + Duration::seconds(seconds)),
        None => policy.absolute_end(now),
    };
    let refresh_expires = policy.refresh_expiry(now, absolute);
    let ttl = state
        .auth
        .token_ttl_seconds
        .min((refresh_expires - now).num_seconds().max(1));
    let access_token = token::mint_bound_session(
        &state.auth.paseto_key,
        identity_id,
        ttl,
        generation,
        Some(session_id),
    )?;
    let id_token_hint = match login
        .id_token
        .filter(|t| !t.is_empty() && t.len() <= 12_000)
    {
        Some(id_token) => {
            let installation = state.installation().await?;
            Some(
                crate::identity_secrets::seal(
                    &state.identity_sealing_key(),
                    installation,
                    "login_session",
                    "id_token_hint",
                    session_id.as_bytes(),
                    id_token.as_bytes(),
                )
                .map_err(|e| AuthError::TokenMint(e.to_string()))?,
            )
        }
        None => None,
    };
    let (refresh_plain, refresh_hash) = random_token()?;
    let written = sqlx::query("with r as (insert into refresh_token(identity_id,token_hash,expires_at,session_generation,session_id) select id,$2,$3,$4,$5 from identity where id=$1 and disabled_at is null and session_generation=$4 and (kind='person' or $6='service-enrolment') returning identity_id,session_id) insert into login_session(session_id,identity_id,provider,issuer,subject,idp_session,id_token_hint,auth_time,absolute_expires_at) select session_id,identity_id,$6,$7,$8,$9,$10,$11,$12 from r")
        .bind(identity_id)
        .bind(&refresh_hash)
        .bind(refresh_expires)
        .bind(generation)
        .bind(session_id)
        .bind(login.provider)
        .bind(login.issuer)
        .bind(login.subject)
        .bind(login.idp_session)
        .bind(id_token_hint)
        .bind(login.auth_time)
        .bind(absolute)
        .execute(executor)
        .await?;
    if written.rows_affected() != 1 {
        return Err(AuthError::TokenInvalid);
    }
    Ok((
        TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: ttl,
            refresh_token: refresh_plain,
        },
        session_id,
    ))
}

#[derive(Deserialize)]
struct VerifyRequest {
    token: String,
}

/// Exchange a sign-in link token for an access token + refresh token. An emailed (magic) link is
/// tried first; a token that is not one is looked up as an operator-issued link
/// ([`super::operator`], docs/decisions/018). Both make the same kind of login, and an unknown,
/// used, expired or revoked token of either kind is the same `401`.
async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<TokenResponse>, AuthError> {
    match store::consume_magic_link(&state.pool, &sha256(req.token.as_bytes())).await {
        Ok(identity_id) => {
            let tokens = mint_session(&state, identity_id, &Login::plain("email")).await?;
            join_by_domain(&state, identity_id).await;
            Ok(Json(tokens))
        }
        Err(AuthError::MagicLinkInvalid) => {
            Ok(Json(super::operator::redeem(&state, &req.token).await?))
        }
        Err(other) => Err(other),
    }
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RefreshRequest {
    refresh_token: String,
}

/// Rotate a refresh token and mint a fresh access token. The successor's expiry follows the
/// session policy and never passes the login's absolute cap.
async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, AuthError> {
    let presented = sha256(req.refresh_token.as_bytes());
    let (new_plain, new_hash) = random_token()?;
    let now = Utc::now();
    let refresh_expires = state.session_policy.refresh_expiry(now, None);
    let (identity_id, generation, session_id) =
        store::rotate_bound_refresh(&state.pool, &presented, &new_hash, refresh_expires).await?;
    let expires: DateTime<Utc> =
        sqlx::query_scalar("select expires_at from refresh_token where token_hash=$1")
            .bind(&new_hash)
            .fetch_one(&state.pool)
            .await?;
    let ttl = state
        .auth
        .token_ttl_seconds
        .min((expires - now).num_seconds().max(1));

    // The successor keeps the session generation of the presented credential.
    let access_token = token::mint_bound_session(
        &state.auth.paseto_key,
        identity_id,
        ttl,
        generation,
        session_id,
    )?;
    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ttl,
        refresh_token: new_plain,
    }))
}

// --- me -------------------------------------------------------------------------

/// Revoke the login identified by a refresh secret, including rotated ancestors.
/// Invalid/already revoked credentials have the same idempotent response.
#[utoipa::path(post,path="/auth/logout",request_body=RefreshRequest,responses((status=200,description="Login revoked; legacy sessions revoke the account generation",body=serde_json::Value)))]
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if req.refresh_token.len() != 64 || !req.refresh_token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Ok(Json(serde_json::json!({"ok":true})));
    }
    let ended = store::revoke_login(&state.pool, &sha256(req.refresh_token.as_bytes())).await?;
    // Only the web tier (service key) learns how the login was made, for RP-initiated logout at
    // the identity provider; the ID token is opened here and never kept in a cookie.
    let mut body = serde_json::json!({"ok":true});
    if let (Some(session), Ok(())) = (ended, require_service(&state, &headers)) {
        let row: Option<(String, Option<String>, Option<Vec<u8>>)> = sqlx::query_as(
            "select provider,issuer,id_token_hint from login_session where session_id=$1",
        )
        .bind(session)
        .fetch_optional(&state.pool)
        .await?;
        if let Some((provider, issuer, sealed)) = row {
            let installation = state.installation().await?;
            let hint = sealed.and_then(|sealed| {
                crate::identity_secrets::open(
                    &state.identity_opening_keys(),
                    installation,
                    "login_session",
                    "id_token_hint",
                    session.as_bytes(),
                    &sealed,
                )
                .and_then(|plain| String::from_utf8(plain).ok())
            });
            body["login"] =
                serde_json::json!({"provider": provider, "issuer": issuer, "id_token_hint": hint});
        }
    }
    Ok(Json(body))
}

#[derive(Serialize)]
struct MeResponse {
    identity_id: Uuid,
    email: String,
    display_name: Option<String>,
}

/// Return the authenticated identity (requires a valid bearer token).
async fn me(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<MeResponse>, AuthError> {
    let identity = store::get_identity(&state.pool, auth.identity_id).await?;
    Ok(Json(MeResponse {
        identity_id: identity.id.0,
        email: identity.email,
        display_name: identity.display_name,
    }))
}

// Only the web server may exchange a provider-verified identity. This route is
// unavailable without a configured service credential, including local development.
// With `external` (an identity provider's validated issuer and subject, and the provider's
// policy), the account is found by that link, never by email alone ([`crate::directory`]).
#[derive(Deserialize)]
struct ExchangeRequest {
    email: String,
    display_name: Option<String>,
    external: Option<crate::directory::ExternalSignIn>,
}
async fn exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ExchangeRequest>,
) -> Result<Json<serde_json::Value>, crate::error::ApiError> {
    require_service(&state, &headers)?;
    if let Some(external) = req.external {
        return Ok(Json(
            crate::directory::external_sign_in(
                &state,
                Some(&req.email),
                req.display_name.as_deref(),
                external,
            )
            .await?,
        ));
    }
    if req.email.len() > 254 || !req.email.contains('@') {
        return Err(AuthError::Forbidden.into());
    }
    let identity = store::upsert_identity(
        &state.pool,
        &req.email.trim().to_lowercase(),
        req.display_name.as_deref(),
    )
    .await?;
    let tokens = mint_session(&state, identity.id.0, &Login::plain("google")).await?;
    join_by_domain(&state, identity.id.0).await;
    Ok(Json(serde_json::to_value(tokens).map_err(|e| {
        crate::error::ApiError::Internal(e.to_string())
    })?))
}
/// Domain routing (migration 0077) after a sign-in; a failure is logged, never a refused sign-in.
async fn join_by_domain(state: &AppState, identity: Uuid) {
    if let Err(error) = crate::org_sign_in::join_by_domain(&state.pool, identity).await {
        tracing::warn!(%error, "domain routing after sign-in failed");
    }
}

pub(crate) fn require_service(state: &AppState, headers: &HeaderMap) -> Result<(), AuthError> {
    match &state.auth.service_key {
        Some(expected) if expected.len() >= 32 && !expected.trim().is_empty() => {
            let presented = headers
                .get("x-dynodoc-service-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            // HMAC verification uses ring's constant-time comparison.
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, expected.as_bytes());
            let tag = ring::hmac::sign(&key, b"dynodoc-service-auth");
            let candidate = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, presented.as_bytes());
            ring::hmac::verify(&candidate, b"dynodoc-service-auth", tag.as_ref())
                .map_err(|_| AuthError::Forbidden)
        }
        _ => Err(AuthError::Forbidden),
    }
}
