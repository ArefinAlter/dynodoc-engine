//! Remote MCP over Streamable HTTP (`POST /mcp`, decision 026 follow-up) for clients that
//! cannot run a local server, such as ChatGPT custom connectors. The bearer is a project
//! device session from [`crate::oauth`]; this route runs the same `engine-mcp` server the
//! stdio verb runs, against this API's own agent routes, which decide every access. It is
//! read-only unless the person ticked `content:propose` at consent; then it offers the write
//! tools, and the API holds every write until that person confirms it in Dynodoc (decision
//! 029, [`crate::agent::held`]). One MCP session per `initialize`, bound to the token's
//! account, key and project, with an idle limit. JSON responses only (no server-sent events).
//!
//! Sessions work on every API replica (migration 0114): the `mcp_http_session` row (SHA-256 of the
//! session id only) is the authority on whether a session exists, whose it is and whether it is
//! idle, and every request reads it, so ending a session on one replica ends it on all. Each
//! process keeps the MCP server of a session it served as a cache, and builds one from the row
//! when another replica opened the session.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::Bytes,
    extract::{Extension, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use engine_mcp::{
    parse_base,
    server::{HumanConfirmation, WriteRequest},
    BackendConfig, HttpBackend, Profile, Server, Session, SessionError, Token,
};
use ring::rand::{SecureRandom, SystemRandom};
use uuid::Uuid;

use crate::{auth::token, AppState};

/// A session unused this long is over (retention prunes its row).
pub(crate) const IDLE: Duration = Duration::from_secs(3600);
/// Servers one process keeps in memory.
const MAX_SESSIONS: usize = 10_000;
/// Live sessions one account may hold; opening another ends its least recently used one.
const MAX_SESSIONS_PER_ACCOUNT: i64 = 50;
const SESSION_HEADER: &str = "mcp-session-id";

/// Each router (one per process) has its own cache of servers.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/mcp", post(handle).get(not_allowed).delete(end))
        .layer(Extension(Cache::default()))
}

/// The bearer of the latest request of this MCP session (a client renews it hourly), and
/// whether the grant has the write scope.
#[derive(Clone)]
struct Bearer(Arc<Mutex<String>>, bool);
impl Session for Bearer {
    async fn token(&self) -> Result<Token, SessionError> {
        let t = self
            .0
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .clone();
        let token = Token::new(t, 0);
        Ok(if self.1 {
            token
        } else {
            token.without_writes()
        })
    }
    async fn rejected(&self, _: &Token) -> Result<(), SessionError> {
        // The client holds the refresh token; it retries with a new bearer.
        Err(SessionError::Refused)
    }
}
struct Entry {
    server: Server<HttpBackend<Bearer>>,
    bearer: Bearer,
    owner: (Uuid, Uuid),
    seen: Instant,
}
/// The servers this process holds, by session id. The database decides whether each may be used.
#[derive(Clone, Default)]
struct Cache(Arc<Mutex<HashMap<String, Entry>>>);
impl Cache {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn id_hash(id: &str) -> Vec<u8> {
    crate::auth::sha256(id.as_bytes())
}

/// The session's row if it belongs to `owner`, is not idle, and (when `project` is given) is for
/// that project: its project and whether it may write. `seen_at` is moved at most once a minute.
async fn live(
    state: &AppState,
    id: &str,
    owner: (Uuid, Uuid),
) -> Result<Option<(Uuid, bool)>, sqlx::Error> {
    let row: Option<(Uuid, bool, bool)> = sqlx::query_as("select project_id,writes,seen_at<now()-interval '1 minute' from mcp_http_session where id_hash=$1 and identity_id=$2 and key_id=$3 and seen_at>now()-make_interval(secs=>$4::double precision)")
        .bind(id_hash(id))
        .bind(owner.0)
        .bind(owner.1)
        .bind(IDLE.as_secs_f64())
        .fetch_optional(&state.pool)
        .await?;
    if let Some((_, _, true)) = row {
        sqlx::query("update mcp_http_session set seen_at=now() where id_hash=$1")
            .bind(id_hash(id))
            .execute(&state.pool)
            .await?;
    }
    Ok(row.map(|(project, writes, _)| (project, writes)))
}

/// A new MCP server for a session of `project` with the bearer `raw`.
fn new_server(
    raw: &str,
    project: Uuid,
    writes: bool,
) -> Result<(Server<HttpBackend<Bearer>>, Bearer), StatusCode> {
    let base = std::env::var("MCP_INTERNAL_API_URL").unwrap_or_else(|_| {
        format!(
            "http://127.0.0.1:{}/",
            std::env::var("API_PORT").unwrap_or_else(|_| "8080".into())
        )
    });
    let Ok(base) = parse_base(&base, true) else {
        tracing::error!("MCP_INTERNAL_API_URL is not a usable base");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    let bearer = Bearer(Arc::new(Mutex::new(raw.to_owned())), writes);
    let backend = HttpBackend::new(BackendConfig::new(base, project), bearer.clone())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let server = if writes {
        Server::with_human_confirmation(backend, Profile::full(), Arc::new(HeldByTheApi))
    } else {
        Server::new(backend, Profile::read_only())
    };
    Ok((server, bearer))
}

/// The person's confirmation of a remote write happens later, in Dynodoc: the API holds every
/// write of an OAuth grant ([`crate::agent::held`]), so the call itself goes through and is
/// answered `state=held`. No preview is fetched here; the API keeps its own.
struct HeldByTheApi;
impl HumanConfirmation for HeldByTheApi {
    fn confirm<'a>(
        &'a self,
        _: WriteRequest<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async { true })
    }
    fn preview(&self) -> bool {
        false
    }
}

fn unauthorized() -> Response {
    // The web tier adds `resource_metadata` (it knows the public origin).
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "",
    )
        .into_response()
}
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

async fn not_allowed() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

async fn end(
    State(state): State<AppState>,
    Extension(cache): Extension<Cache>,
    headers: HeaderMap,
) -> StatusCode {
    let Some(claims) =
        bearer(&headers).and_then(|t| token::verify_project_device(&state.auth.paseto_key, t).ok())
    else {
        return StatusCode::UNAUTHORIZED;
    };
    let id = headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let owner = (claims.identity, claims.key);
    let ended = sqlx::query(
        "delete from mcp_http_session where id_hash=$1 and identity_id=$2 and key_id=$3",
    )
    .bind(id_hash(id))
    .bind(owner.0)
    .bind(owner.1)
    .execute(&state.pool)
    .await;
    if ended.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let mut all = cache.lock();
    if all.get(id).is_some_and(|e| e.owner == owner) {
        all.remove(id);
    }
    StatusCode::NO_CONTENT
}

async fn handle(
    State(state): State<AppState>,
    Extension(cache): Extension<Cache>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(raw) = bearer(&headers) else {
        return unauthorized();
    };
    let Ok(claims) = token::verify_project_device(&state.auth.paseto_key, raw) else {
        return unauthorized();
    };
    if body.len() > 1 << 20 {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Ok(line) = std::str::from_utf8(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let initialize = serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .is_some_and(|v| v["method"] == "initialize");
    let owner = (claims.identity, claims.key);
    let may_write = claims.scopes.iter().any(|s| s == crate::oauth::PROPOSE);
    let (id, server) = if initialize {
        // An organisation that denies this kind of client stops it here too (migration 0116);
        // its calls would be refused by the agent routes anyway.
        let denied = match state.pool.acquire().await {
            Ok(mut db) => match crate::auth::agent::key_client_kind(&mut db, claims.key).await {
                Ok(kind) => crate::auth::agent::client_kind_denied(&mut db, claims.identity, &kind)
                    .await
                    .unwrap_or(true),
                Err(_) => true,
            },
            Err(_) => true,
        };
        if denied {
            return StatusCode::FORBIDDEN.into_response();
        }
        let mut bytes = [0u8; 16];
        if SystemRandom::new().fill(&mut bytes).is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let id = hex::encode(bytes);
        let (server, bearer) = match new_server(raw, claims.project, may_write) {
            Ok(made) => made,
            Err(status) => return status.into_response(),
        };
        // The row first: the session exists for every replica, and an account keeps at most
        // MAX_SESSIONS_PER_ACCOUNT live ones (the least recently used go).
        let stored = sqlx::query("with gone as (delete from mcp_http_session where identity_id=$2 and id_hash in (select id_hash from mcp_http_session where identity_id=$2 order by seen_at desc offset $6)) insert into mcp_http_session(id_hash,identity_id,key_id,project_id,writes) values($1,$2,$3,$4,$5)")
            .bind(id_hash(&id))
            .bind(owner.0)
            .bind(owner.1)
            .bind(claims.project)
            .bind(may_write)
            .bind(MAX_SESSIONS_PER_ACCOUNT - 1)
            .execute(&state.pool)
            .await;
        if stored.is_err() {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let mut all = cache.lock();
        all.retain(|_, e| e.seen.elapsed() < IDLE);
        if all.len() >= MAX_SESSIONS {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        all.insert(
            id.clone(),
            Entry {
                server: server.clone(),
                bearer,
                owner,
                seen: Instant::now(),
            },
        );
        (id, server)
    } else {
        let id = headers
            .get(SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        // Unknown, ended, idle or another account's or key's: the client starts a new session
        // (spec: 404).
        let (project, writes) = match live(&state, &id, owner).await {
            Ok(Some(row)) => row,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
        let cached = {
            let mut all = cache.lock();
            all.get_mut(&id).filter(|e| e.owner == owner).map(|entry| {
                if let Ok(mut t) = entry.bearer.0.lock() {
                    *t = raw.to_owned();
                }
                entry.seen = Instant::now();
                entry.server.clone()
            })
        };
        let server = match cached {
            Some(server) => server,
            None => {
                // shortcut: opened on another replica (or before a restart): this process starts
                // the MCP connection state afresh (negotiated version, client name, the agent
                // session it records under), so one remote session can appear as several agent
                // sessions; move that state into the row if it must be one.
                let (server, bearer) = match new_server(raw, project, writes && may_write) {
                    Ok(made) => made,
                    Err(status) => return status.into_response(),
                };
                let mut all = cache.lock();
                all.retain(|_, e| e.seen.elapsed() < IDLE);
                if all.len() >= MAX_SESSIONS {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                all.insert(
                    id.clone(),
                    Entry {
                        server: server.clone(),
                        bearer,
                        owner,
                        seen: Instant::now(),
                    },
                );
                server
            }
        };
        (id, server)
    };
    let reply = server.handle_line(line).await;
    let mut response = match reply {
        Some(text) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            text,
        )
            .into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    };
    if let Ok(v) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(SESSION_HEADER, v);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
