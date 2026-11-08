//! OAuth 2.1 for remote MCP clients (migration 0058): dynamic client registration
//! (RFC 7591), a consent a signed-in person gives on Dynodoc's page, and a token endpoint
//! with PKCE S256 and rotating refresh tokens. A grant is an agent key without a private
//! key, granted one project with `content:read`, and `content:propose` only when the person
//! ticked it on the consent page (decision 029: every write of such a key is held until that
//! person confirms it, [`crate::agent::held`]); tokens are ordinary project device
//! sessions ([`crate::device_sessions::issue_for_key`]), so the agent routes, revocation,
//! the kill switch and the issuance budget apply unchanged. Only hashes of codes and
//! refresh tokens are stored. The web tier serves the metadata documents and the consent
//! page; this module holds every decision.
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    auth::AuthContext, device_sessions::issue_for_key, devices::account_lock, error::ApiError,
    product::audit, projects, AppState,
};

/// The scope every remote client gets (read-only connectors, decision 026 follow-up).
pub const SCOPE: &str = "content:read";
/// The scope a person may add on the consent page: proposals, each held for them to confirm.
pub const PROPOSE: &str = "content:propose";
const CODE_TTL_SECONDS: i64 = 600;
const MAX_ACTIVE_KEYS: i64 = 20;
const CLIENTS_PER_HOUR: i64 = 500;
/// Registrations an hour from one visitor's address, below the global ceiling.
const CLIENTS_PER_ADDRESS_PER_HOUR: i32 = 20;
/// The refresh tokens a grant remembers having rotated away from (reuse detection).
const ROTATED_KEPT: i32 = 16;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/oauth/register", post(register))
        .route("/oauth/clients/{id}", get(client))
        .route("/oauth/authorize", post(authorize))
        .route("/oauth/token", post(token))
}

fn random(bytes: usize) -> Result<Vec<u8>, ApiError> {
    let mut out = vec![0u8; bytes];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| ApiError::Internal("random".into()))?;
    Ok(out)
}
fn sha256(text: &str) -> Vec<u8> {
    digest::digest(&digest::SHA256, text.as_bytes())
        .as_ref()
        .to_vec()
}
/// An OAuth error body (RFC 6749 section 5.2).
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"error":error,"error_description":description})),
    )
        .into_response()
}

/// The host of an absolute URI as a browser reads it (WHATWG URL), lowercased. A backslash is
/// refused: browsers read it as `/`, so `https://evil.example\.claude.ai/` is evil.example's.
fn host_of(uri: &str) -> Option<String> {
    if uri.contains('\\') {
        return None;
    }
    let url = url::Url::parse(uri).ok()?;
    url.host_str()
        .filter(|h| !h.is_empty())
        .map(str::to_ascii_lowercase)
}

/// A redirect URI a client may register: HTTPS, or HTTP on a loopback host; printable
/// ASCII without spaces or backslashes, no fragment, no credentials, at most 500 characters.
pub fn redirect_ok(uri: &str) -> bool {
    let (Some(host), Ok(url)) = (host_of(uri), url::Url::parse(uri)) else {
        return false;
    };
    let loopback = matches!(host.as_str(), "127.0.0.1" | "[::1]" | "localhost");
    uri.len() <= 500
        && uri.bytes().all(|b| b.is_ascii_graphic())
        && !uri.contains('#')
        && url.username().is_empty()
        && url.password().is_none()
        && (url.scheme() == "https" || (url.scheme() == "http" && loopback))
}
/// The client kind recorded on the key, from where it sends people back.
fn client_kind(redirect: &str) -> &'static str {
    match host_of(redirect).unwrap_or_default().as_str() {
        "chatgpt.com" | "chat.openai.com" => "chatgpt",
        "claude.ai" => "claude",
        h if h.ends_with("vertexaisearch.cloud.google.com") => "gemini",
        _ => "generic",
    }
}

#[derive(Deserialize)]
struct Registration {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(r): Json<Registration>,
) -> Result<Response, ApiError> {
    if r.redirect_uris.is_empty()
        || r.redirect_uris.len() > 5
        || !r.redirect_uris.iter().all(|u| redirect_ok(u))
    {
        return Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "Give one to five HTTPS redirect URIs.",
        ));
    }
    let name: String = r
        .client_name
        .unwrap_or_else(|| "AI assistant".into())
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    let name = if name.trim().is_empty() {
        "AI assistant".to_owned()
    } else {
        name.trim().to_owned()
    };
    let mut tx = state.pool.begin().await?;
    // Registration is anonymous: a global hourly cap keeps it from filling the table.
    sqlx::query("select pg_advisory_xact_lock(hashtextextended('oauth.register',58))")
        .execute(&mut *tx)
        .await?;
    let recent: i64 = sqlx::query_scalar(
        "select count(*) from oauth_client where created_at>now()-interval '1 hour'",
    )
    .fetch_one(&mut *tx)
    .await?;
    if recent >= CLIENTS_PER_HOUR {
        return Err(ApiError::RateLimited { retry_after: 600 });
    }
    // The visitor's address, named by the web tier (with the service key, so by nobody else).
    let address = crate::auth::routes::require_service(&state, &headers)
        .ok()
        .and_then(|_| headers.get("x-dynodoc-client-address"))
        .and_then(|v| v.to_str().ok())
        .filter(|a| !a.is_empty() && a.len() <= 64);
    if let Some(address) = address {
        let attempts: i32 = sqlx::query_scalar("insert into auth_request_window(key_hash) values($1) on conflict(key_hash) do update set attempts=case when auth_request_window.started_at < now()-interval '1 hour' then 1 else auth_request_window.attempts+1 end, started_at=case when auth_request_window.started_at < now()-interval '1 hour' then now() else auth_request_window.started_at end returning attempts")
            .bind(sha256(&format!("dynodoc/oauth-register/address/{address}")))
            .fetch_one(&mut *tx)
            .await?;
        if attempts > CLIENTS_PER_ADDRESS_PER_HOUR {
            return Err(ApiError::RateLimited { retry_after: 3600 });
        }
    }
    let id = hex::encode(random(16)?);
    sqlx::query("insert into oauth_client(id,name,redirect_uris) values($1,$2,$3)")
        .bind(&id)
        .bind(&name)
        .bind(&r.redirect_uris)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "client_id": id,
            "client_name": name,
            "redirect_uris": r.redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": format!("{SCOPE} {PROPOSE}")
        })),
    )
        .into_response())
}

/// What the consent page shows about a client.
async fn client(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let row: Option<(String, Vec<String>)> =
        sqlx::query_as("select name,redirect_uris from oauth_client where id=$1")
            .bind(&id)
            .fetch_optional(&state.pool)
            .await?;
    let (name, redirect_uris) = row.ok_or(ApiError::NotFound)?;
    Ok(Json(
        json!({"client_id":id,"client_name":name,"redirect_uris":redirect_uris}),
    ))
}

#[derive(Deserialize)]
struct Consent {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    project: Uuid,
    /// The person ticked "propose changes" (off unless sent).
    #[serde(default)]
    propose: bool,
}

/// A person approves a client for one project. Returns the single-use code.
async fn authorize(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(c): Json<Consent>,
) -> Result<impl IntoResponse, ApiError> {
    if c.code_challenge_method != "S256"
        || c.code_challenge.len() != 43
        || !c
            .code_challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ApiError::BadRequest {
            reason: "PKCE with S256 is required".into(),
        });
    }
    let mut tx = state.pool.begin().await?;
    account_lock(&mut tx, &auth).await?;
    let client: Option<(String, Vec<String>)> =
        sqlx::query_as("select name,redirect_uris from oauth_client where id=$1")
            .bind(&c.client_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((name, uris)) = client else {
        return Err(ApiError::NotFound);
    };
    if !uris.contains(&c.redirect_uri) {
        return Err(ApiError::BadRequest {
            reason: "The redirect URI is not registered for this client".into(),
        });
    }
    let role = projects::require(&mut tx, c.project, auth.identity_id).await?;
    // The person's organisation may deny this kind of client (migration 0116).
    if crate::auth::agent::client_kind_denied(
        &mut tx,
        auth.identity_id,
        client_kind(&c.redirect_uri),
    )
    .await?
    {
        return Err(ApiError::Denied {
            reason: "Your organisation does not allow this AI client.".into(),
        });
    }
    // A viewer cannot stage drafts, so a grant to propose would only ever be refused.
    if c.propose
        && !matches!(
            role.as_str(),
            "owner" | "manager" | "editor" | "reviewer" | "approver"
        )
    {
        return Err(ApiError::BadRequest {
            reason: "Your role in this project does not let you propose changes".into(),
        });
    }
    let scopes: Vec<String> = if c.propose {
        // Sorted, as device sessions carry them.
        vec![PROPOSE.to_owned(), SCOPE.to_owned()]
    } else {
        vec![SCOPE.to_owned()]
    };
    // One grant per client, person and project: a second consent reuses its key.
    let existing: Option<Uuid> = sqlx::query_scalar("select g.key_id from oauth_grant g where g.client_id=$1 and g.identity_id=$2 and g.project_id=$3 and not exists(select 1 from device_key_revocation r where r.key_id=g.key_id)")
        .bind(&c.client_id)
        .bind(auth.identity_id)
        .bind(c.project)
        .fetch_optional(&mut *tx)
        .await?;
    let key = match existing {
        Some(key) => {
            // A new consent sets the scopes again (a grant row's scopes never change in
            // place: revoke and insert).
            let current: Option<(Uuid, Vec<String>)> = sqlx::query_as("select id,scopes from device_key_project_grant where key_id=$1 and project_id=$2 and revoked_at is null for update")
                .bind(key)
                .bind(c.project)
                .fetch_optional(&mut *tx)
                .await?;
            if current.as_ref().is_none_or(|(_, s)| *s != scopes) {
                if let Some((grant, _)) = current {
                    sqlx::query("update device_key_project_grant set revoked_at=clock_timestamp() where id=$1")
                        .bind(grant)
                        .execute(&mut *tx)
                        .await?;
                }
                sqlx::query("insert into device_key_project_grant(key_id,project_id,scopes,created_at,created_by) values($1,$2,$3,clock_timestamp(),$4)")
                    .bind(key)
                    .bind(c.project)
                    .bind(&scopes)
                    .bind(auth.identity_id)
                    .execute(&mut *tx)
                    .await?;
            }
            key
        }
        None => {
            // A revoked earlier grant for the same triple is replaced.
            sqlx::query(
                "delete from oauth_grant where client_id=$1 and identity_id=$2 and project_id=$3",
            )
            .bind(&c.client_id)
            .bind(auth.identity_id)
            .bind(c.project)
            .execute(&mut *tx)
            .await?;
            let active: i64 = sqlx::query_scalar("select count(*) from device_signing_key k where identity_id=$1 and not exists(select 1 from device_key_revocation r where r.key_id=k.id)")
                .bind(auth.identity_id)
                .fetch_one(&mut *tx)
                .await?;
            if active >= MAX_ACTIVE_KEYS {
                return Err(ApiError::Conflict {
                    reason: "You have 20 active keys and connections. Revoke one in your profile (Signing keys), then try again.".into(),
                });
            }
            let key = Uuid::new_v4();
            // A random public key: nobody holds its private key, so it never signs a
            // device-session challenge; only this grant's refresh token obtains sessions.
            sqlx::query("insert into device_signing_key(id,identity_id,public_key,proof) values($1,$2,$3,$4)")
                .bind(key)
                .bind(auth.identity_id)
                .bind(hex::encode(random(32)?))
                .bind(json!({"kind":"oauth","client_id":c.client_id}))
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "insert into device_key_access(key_id,project_access) values($1,'granted')",
            )
            .bind(key)
            .execute(&mut *tx)
            .await?;
            sqlx::query("insert into device_key_class(key_id,class,label,client_kind) values($1,'agent',$2,$3)")
                .bind(key)
                .bind(&name)
                .bind(client_kind(&c.redirect_uri))
                .execute(&mut *tx)
                .await?;
            sqlx::query("insert into device_key_project_grant(key_id,project_id,scopes,created_at,created_by) values($1,$2,$3,clock_timestamp(),$4)")
                .bind(key)
                .bind(c.project)
                .bind(&scopes)
                .bind(auth.identity_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("insert into oauth_grant(key_id,client_id,identity_id,project_id) values($1,$2,$3,$4)")
                .bind(key)
                .bind(&c.client_id)
                .bind(auth.identity_id)
                .bind(c.project)
                .execute(&mut *tx)
                .await?;
            key
        }
    };
    // A grant that may propose has an agent identity to own its drafts, as a device grant does.
    if c.propose {
        crate::agent::identity::ensure(&mut tx, auth.identity_id, key).await?;
    }
    let code = URL_SAFE_NO_PAD.encode(random(32)?);
    sqlx::query("delete from oauth_code where expires_at<now()")
        .execute(&mut *tx)
        .await?;
    sqlx::query("insert into oauth_code(code_hash,key_id,redirect_uri,code_challenge,expires_at) values($1,$2,$3,$4,now()+make_interval(secs=>$5))")
        .bind(sha256(&code))
        .bind(key)
        .bind(&c.redirect_uri)
        .bind(&c.code_challenge)
        .bind(CODE_TTL_SECONDS as f64)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "oauth.authorized",
        c.project,
        json!({"client_id":c.client_id,"key_id":key,"scopes":scopes}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"code":code})),
    ))
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

async fn token(State(state): State<AppState>, Json(t): Json<TokenRequest>) -> Response {
    match token_inner(&state, t).await {
        Ok(r) => r,
        Err(TokenFail::OAuth(e, d)) => oauth_error(StatusCode::BAD_REQUEST, e, d),
        Err(TokenFail::Api(ApiError::RateLimited { .. })) => oauth_error(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "Too many tokens for this connection; try again later.",
        ),
        // A grant whose key, account or project access ended is a dead grant.
        Err(TokenFail::Api(ApiError::Forbidden | ApiError::NotFound | ApiError::Unauthorized)) => {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "This connection was revoked or lost access.",
            )
        }
        Err(TokenFail::Api(e)) => e.into_response(),
    }
}
enum TokenFail {
    OAuth(&'static str, &'static str),
    Api(ApiError),
}
impl From<ApiError> for TokenFail {
    fn from(e: ApiError) -> Self {
        TokenFail::Api(e)
    }
}
impl From<sqlx::Error> for TokenFail {
    fn from(e: sqlx::Error) -> Self {
        TokenFail::Api(e.into())
    }
}

/// A refresh token the grant already rotated away from came back: a copy exists somewhere
/// (RFC 9700 section 4.14.2), so the grant ends for every holder (its key is revoked).
async fn end_reused_grant(
    state: &AppState,
    presented: &[u8],
    client: &str,
) -> Result<(), ApiError> {
    let mut tx = state.pool.begin().await?;
    let grant: Option<(Uuid, Uuid)> = sqlx::query_as("update oauth_grant set refresh_hash=null where client_id=$1 and rotated_hashes @> array[$2::bytea] returning key_id,identity_id")
        .bind(client)
        .bind(presented)
        .fetch_optional(&mut *tx)
        .await?;
    if let Some((key, identity)) = grant {
        let revoked = sqlx::query(
            "insert into device_key_revocation(key_id) values($1) on conflict do nothing",
        )
        .bind(key)
        .execute(&mut *tx)
        .await?;
        if revoked.rows_affected() == 1 {
            audit(
                &mut tx,
                identity,
                "oauth.refresh_reused",
                key,
                json!({"client_id": client}),
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn token_inner(state: &AppState, t: TokenRequest) -> Result<Response, TokenFail> {
    let client = t
        .client_id
        .as_deref()
        .ok_or(TokenFail::OAuth("invalid_request", "client_id is required"))?;
    // A refresh rotates in its own transaction, committed only once the access token exists.
    let mut rotation = None;
    let (key, identity, project) = match t.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(verifier), Some(redirect)) = (
                t.code.as_deref(),
                t.code_verifier.as_deref(),
                t.redirect_uri.as_deref(),
            ) else {
                return Err(TokenFail::OAuth(
                    "invalid_request",
                    "code, code_verifier and redirect_uri are required",
                ));
            };
            if !(43..=128).contains(&verifier.len())
                || !verifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
            {
                return Err(TokenFail::OAuth("invalid_request", "Invalid code_verifier"));
            }
            // Single use: the row is gone whatever happens next.
            let row: Option<(Uuid, String, String, bool, String, Uuid, Uuid)> = sqlx::query_as("delete from oauth_code c using oauth_grant g where c.code_hash=$1 and g.key_id=c.key_id returning c.key_id,c.redirect_uri,c.code_challenge,c.expires_at>now(),g.client_id,g.identity_id,g.project_id")
                .bind(sha256(code))
                .fetch_optional(&state.pool)
                .await?;
            let Some((key, uri, challenge, fresh, owner, identity, project)) = row else {
                return Err(TokenFail::OAuth("invalid_grant", "Unknown or used code"));
            };
            let expected =
                URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
            if !fresh || owner != client || uri != redirect || expected != challenge {
                return Err(TokenFail::OAuth("invalid_grant", "The code does not match"));
            }
            (key, identity, project)
        }
        "refresh_token" => {
            let refresh = t.refresh_token.as_deref().ok_or(TokenFail::OAuth(
                "invalid_request",
                "refresh_token is required",
            ))?;
            let presented = sha256(refresh);
            let next = URL_SAFE_NO_PAD.encode(random(32)?);
            let mut tx = state.pool.begin().await?;
            // Find and rotate in one statement: of two requests with one token only one matches.
            let row: Option<(Uuid, Uuid, Uuid)> = sqlx::query_as("update oauth_grant set refresh_hash=$3,rotated_hashes=(array_prepend(refresh_hash,rotated_hashes))[1:$4],refreshed_at=now() where refresh_hash=$1 and client_id=$2 returning key_id,identity_id,project_id")
                .bind(&presented)
                .bind(client)
                .bind(sha256(&next))
                .bind(ROTATED_KEPT)
                .fetch_optional(&mut *tx)
                .await?;
            let Some(row) = row else {
                drop(tx);
                end_reused_grant(state, &presented, client).await?;
                return Err(TokenFail::OAuth("invalid_grant", "Unknown refresh token"));
            };
            rotation = Some((tx, next));
            row
        }
        _ => {
            return Err(TokenFail::OAuth(
                "unsupported_grant_type",
                "Use authorization_code or refresh_token",
            ))
        }
    };
    // The scopes the person consented to, as the grant holds them now.
    let scopes: Vec<String> = sqlx::query_scalar("select scopes from device_key_project_grant where key_id=$1 and project_id=$2 and revoked_at is null")
        .bind(key)
        .bind(project)
        .fetch_optional(&state.pool)
        .await?
        .unwrap_or_else(|| vec![SCOPE.to_owned()]);
    {
        let mut db = state.pool.acquire().await.map_err(ApiError::from)?;
        let kind = crate::auth::agent::key_client_kind(&mut db, key)
            .await
            .map_err(ApiError::from)?;
        if crate::auth::agent::client_kind_denied(&mut db, identity, &kind)
            .await
            .map_err(ApiError::from)?
        {
            return Err(TokenFail::OAuth(
                "invalid_grant",
                "The organisation does not allow this AI client",
            ));
        }
    }
    let (access, _) = issue_for_key(state, key, identity, project, &scopes, Uuid::new_v4()).await?;
    // Rotate: the previous refresh token stops working now.
    let refresh = match rotation {
        Some((tx, next)) => {
            tx.commit().await?;
            next
        }
        None => {
            let refresh = URL_SAFE_NO_PAD.encode(random(32)?);
            sqlx::query(
                "update oauth_grant set refresh_hash=$2,refreshed_at=now() where key_id=$1",
            )
            .bind(key)
            .bind(sha256(&refresh))
            .execute(&state.pool)
            .await?;
            refresh
        }
    };
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": crate::auth::token::DEVICE_SESSION_TTL_SECONDS,
            "refresh_token": refresh,
            "scope": scopes.join(" ")
        })),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_must_be_https_or_loopback() {
        assert!(redirect_ok(
            "https://chatgpt.com/connector_platform_oauth_redirect"
        ));
        assert!(redirect_ok("http://127.0.0.1:3000/cb"));
        assert!(!redirect_ok("http://evil.example/cb"));
        assert!(!redirect_ok("https://a.example/cb#x"));
        assert!(!redirect_ok("https://user:pw@a.example/cb"));
        assert!(!redirect_ok("javascript:alert(1)"));
        assert_eq!(client_kind("https://chatgpt.com/x"), "chatgpt");
        assert_eq!(client_kind("https://other.example/x"), "generic");
        // Security review of main 362d4b1, finding 4: a browser reads `\` as `/`.
        let tricked = r"https://evil.example\.vertexaisearch.cloud.google.com/cb";
        assert!(!redirect_ok(tricked));
        assert_eq!(client_kind(tricked), "generic");
        assert_eq!(
            host_of("https://EVIL.example:8443/x?y").as_deref(),
            Some("evil.example")
        );
        assert_eq!(host_of("http://[::1]:3000/cb").as_deref(), Some("[::1]"));
        assert!(!redirect_ok("https://a.example@evil.example/cb"));
        assert_eq!(
            client_kind("https://x.vertexaisearch.cloud.google.com/cb"),
            "gemini"
        );
    }
}
