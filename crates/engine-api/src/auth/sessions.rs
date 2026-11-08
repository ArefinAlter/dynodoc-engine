//! Logins as records (docs/SELF-HOSTED-IDENTITY-AND-ACCESS.md 5.6 and 12.2, migration 0110): a
//! person lists and ends their own logins, an administrator (or an auditor, read-only) those of
//! anyone, and the web tier ends the logins an identity provider says are over (OpenID Connect
//! back-channel logout, after it validated the logout token).
//!
//! Ending a login revokes its refresh lineage, so every route refuses its access token at the next
//! request (`ensure_bound_session`), and burns the app hand-over codes it asked for. A live event
//! stream notices within a minute (the periodic check in [`crate::stream`]).

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::{routes::require_service, AuthContext};
use crate::{error::ApiError, AppState};

/// The routes of this module.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/sessions", get(own))
        .route("/auth/sessions/{id}/revoke", post(revoke_own))
        .route("/admin/sessions", get(admin_list))
        .route("/admin/sessions/{id}/revoke", post(admin_revoke))
        .route("/internal/auth/logout-propagation", post(propagate))
}

/// End `sessions` for `reason` in the caller's transaction; returns the identities affected. The
/// accounts are locked first, in id order, as rotation and logout lock them.
pub(crate) async fn end(
    tx: &mut Transaction<'_, Postgres>,
    sessions: &[Uuid],
    reason: &str,
) -> Result<Vec<Uuid>, ApiError> {
    if sessions.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query("select id from identity where id in (select identity_id from login_session where session_id=any($1)) order by id for update")
        .bind(sessions)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "update refresh_token set revoked_at=now() where session_id=any($1) and revoked_at is null",
    )
    .bind(sessions)
    .execute(&mut **tx)
    .await?;
    sqlx::query("update app_handover_code set consumed_at=now(), outcome='burned' where issued_session=any($1) and consumed_at is null")
        .bind(sessions)
        .execute(&mut **tx)
        .await?;
    let identities: Vec<Uuid> = sqlx::query_scalar("update login_session set revoked_at=now(),revoked_reason=$2 where session_id=any($1) and revoked_at is null returning identity_id")
        .bind(sessions)
        .bind(reason)
        .fetch_all(&mut **tx)
        .await?;
    Ok(identities)
}

/// The live logins of `identity` (a refresh row that is neither rotated, revoked nor expired).
const LIVE: &str = "select coalesce(jsonb_agg(jsonb_build_object('id',s.session_id,'provider',s.provider,'started_at',s.started_at,'last_refresh_at',s.last_refresh_at,'absolute_expires_at',s.absolute_expires_at,'expires_at',(select max(r.expires_at) from refresh_token r where r.session_id=s.session_id and r.rotated_at is null and r.revoked_at is null)) order by s.started_at desc),'[]'::jsonb) from login_session s where s.identity_id=$1 and s.revoked_at is null and exists(select 1 from refresh_token r where r.session_id=s.session_id and r.rotated_at is null and r.revoked_at is null and r.expires_at>now())";

/// `GET /auth/sessions`: the caller's own live logins; `current` marks this one.
async fn own(State(state): State<AppState>, auth: AuthContext) -> Result<Json<Value>, ApiError> {
    let mut items: Value = sqlx::query_scalar(LIVE)
        .bind(auth.identity_id)
        .fetch_one(&state.pool)
        .await?;
    if let Some(list) = items.as_array_mut() {
        for item in list {
            item["current"] = json!(auth.session_id.is_some_and(|s| item["id"] == json!(s)));
        }
    }
    Ok(Json(json!({ "items": items })))
}

/// `POST /auth/sessions/{id}/revoke`: end one of the caller's own logins (another person's id is
/// the same `404` as an unknown one).
async fn revoke_own(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = state.pool.begin().await?;
    let mine: bool = sqlx::query_scalar(
        "select exists(select 1 from login_session where session_id=$1 and identity_id=$2)",
    )
    .bind(id)
    .bind(auth.identity_id)
    .fetch_one(&mut *tx)
    .await?;
    if !mine {
        return Err(ApiError::NotFound);
    }
    let ended = end(&mut tx, &[id], "self").await?;
    tx.commit().await?;
    Ok(Json(json!({ "revoked": ended.len() })))
}

#[derive(Deserialize)]
struct ListQuery {
    identity: Uuid,
}

/// `GET /admin/sessions?identity=`: an administrator or auditor reads a person's live logins.
async fn admin_list(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    crate::admin::require_reader(&state, &auth).await?;
    let items: Value = sqlx::query_scalar(LIVE)
        .bind(q.identity)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(json!({ "items": items })))
}

/// `POST /admin/sessions/{id}/revoke`: an administrator ends one login (audited).
async fn admin_revoke(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    crate::admin::require_admin(&state, &auth).await?;
    let mut tx = state.pool.begin().await?;
    let ended = end(&mut tx, &[id], "admin").await?;
    for identity in &ended {
        crate::product::audit(
            &mut tx,
            auth.identity_id,
            "session.revoked",
            *identity,
            json!({"session_id": id, "reason": "admin"}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "revoked": ended.len() })))
}

#[derive(Deserialize)]
struct Propagation {
    issuer: String,
    subject: Option<String>,
    /// OIDC `sid` (or SAML `SessionIndex`).
    idp_session: Option<String>,
}

/// `POST /internal/auth/logout-propagation` (service key only): the identity provider `issuer`
/// says a session is over. With `idp_session`, the logins of that provider session end; with only
/// `subject`, every login of that subject at that issuer ends (OpenID Connect Back-Channel Logout
/// 1.0, section 2.4). The web tier validated the logout token before calling.
async fn propagate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Propagation>,
) -> Result<Json<Value>, ApiError> {
    require_service(&state, &headers).map_err(|_| ApiError::Forbidden)?;
    let bounded = |v: &Option<String>| v.as_ref().is_none_or(|v| !v.is_empty() && v.len() <= 512);
    if input.issuer.is_empty()
        || input.issuer.len() > 512
        || !bounded(&input.subject)
        || !bounded(&input.idp_session)
        || (input.subject.is_none() && input.idp_session.is_none())
    {
        return Err(ApiError::BadRequest {
            reason: "An issuer and a subject or session, each 1 to 512 characters.".into(),
        });
    }
    let mut tx = state.pool.begin().await?;
    let sessions: Vec<Uuid> = sqlx::query_scalar("select session_id from login_session where issuer=$1 and revoked_at is null and (case when $3::text is not null then idp_session=$3 and ($2::text is null or subject=$2) else subject=$2 end) limit 1000")
        .bind(&input.issuer)
        .bind(&input.subject)
        .bind(&input.idp_session)
        .fetch_all(&mut *tx)
        .await?;
    let ended = end(&mut tx, &sessions, "idp_logout").await?;
    let mut people = ended.clone();
    people.sort();
    people.dedup();
    for identity in &people {
        crate::product::audit(
            &mut tx,
            *identity,
            "session.idp_logout",
            *identity,
            json!({"logins": ended.iter().filter(|i| *i == identity).count()}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "revoked": ended.len() })))
}

/// Sensitive actions (erasing, sign-in settings, issuing SCIM or service-account credentials;
/// decision 043) need a fresh login: an account login of a person, not a device, agent or
/// connector credential, whose authentication is at most `state.reauth_seconds` old. The time is
/// the identity provider's `auth_time` when it sent one (an SSO session reused silently is not a
/// fresh sign-in), else the start of the Dynodoc login. A legacy token without a login record
/// never qualifies. `403` with code `reauth_required` tells the web tier to ask for a sign-in.
pub(crate) async fn require_recent_login(
    state: &AppState,
    auth: &AuthContext,
) -> Result<(), ApiError> {
    if state.reauth_seconds == 0 {
        return Ok(());
    }
    let fresh = match (auth.device.is_none(), auth.session_id) {
        (true, Some(session)) => sqlx::query_scalar("select exists(select 1 from login_session s join identity i on i.id=s.identity_id where s.session_id=$1 and s.identity_id=$2 and s.revoked_at is null and s.provider<>'service-enrolment' and i.kind='person' and coalesce(s.auth_time,s.started_at)>now()-make_interval(secs=>$3::float8))")
            .bind(session)
            .bind(auth.identity_id)
            .bind(state.reauth_seconds as f64)
            .fetch_one(&state.pool)
            .await?,
        _ => false,
    };
    if fresh {
        Ok(())
    } else {
        Err(ApiError::Coded {
            status: axum::http::StatusCode::FORBIDDEN,
            code: "reauth_required",
            reason: "Sign in again to confirm this change.".into(),
            details: serde_json::json!({ "max_age_seconds": state.reauth_seconds }),
        })
    }
}
