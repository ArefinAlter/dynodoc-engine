//! Held writes of remote AI agents (decision 029 section 5, schema 66).
//!
//! A key behind an OAuth grant (a hosted MCP client such as ChatGPT) never writes directly.
//! Its `propose`, `submit`, `withdraw` and `remember` calls are checked as usual (a `propose`
//! is also compiled as a dry run, whose diff is kept for the person) and then held: the
//! request is stored here and the agent is told `state=held`. Nobody but the person the agent
//! acts for sees it; it is not a draft, not a change request, not in the reviewers' inbox and
//! not in the project memory.
//!
//! The person lists what waits (`GET /agent-held`) and confirms or declines each item on a
//! human-only surface: the web workspace (a form with the web tier's origin check) or the
//! desktop app, both signed in as that person. These routes take an account login only
//! ([`AuthContext`]), never a device session, an OAuth access token or a connector key, and
//! refuse an agent identity as a second lock. Confirming replays the stored request as the
//! agent through the same handler, with every check of a direct call (key, grant, scope,
//! policy, kill switch, roles, stale bases); a confirmed `propose` is then submitted for
//! review on the person's behalf, and a person still merges it. Declining discards the text.
//! An item not decided within [`HOLD_DAYS`] days expires and can no longer be confirmed.
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue},
    routing::{get, post},
    Json, Router,
};
use chrono::{SecondsFormat, Utc};
use engine_agent::dct::{HeaderBuilder, Tool};
use engine_shared::{DocumentId, IdentityId};
use serde_json::{json, Value};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{
    error::AgentFail,
    http::{self, Format},
    identity, memory, proposal,
    routes::{Call, Ctx, Served},
    write,
};
use crate::{auth::AuthContext, error::ApiError, ops::apply, product::audit, AppState};

/// Days a held write waits for the person before it expires.
pub const HOLD_DAYS: i64 = 7;
/// Held writes one person may have waiting at once; more are refused, not queued.
const MAX_WAITING: i64 = 200;

pub fn people_routes() -> Router<AppState> {
    Router::new()
        .route("/agent-held", get(list))
        .route("/agent-held/{held}/confirm", post(confirm))
        .route("/agent-held/{held}/decline", post(decline))
}

/// Must this call be held: a key of a remote grant (an OAuth client), not yet confirmed?
pub(super) async fn must_hold(ctx: &Ctx<'_>) -> Result<bool, ApiError> {
    if ctx.confirmed {
        return Ok(false);
    }
    Ok(
        sqlx::query_scalar("select exists(select 1 from oauth_grant where key_id=$1)")
            .bind(ctx.key)
            .fetch_one(&ctx.state.pool)
            .await?,
    )
}

/// What a held call keeps.
pub(super) struct Held {
    pub tool: &'static str,
    pub target: String,
    pub document: Option<Uuid>,
    pub body: Value,
    pub digest: [u8; 32],
    pub summary: String,
    pub preview: Option<String>,
}

/// Mark the person's held writes past their time as expired and remove their text. The
/// retention pass also expires everyone's ([`expire_due`]), so text never outlives its hold by
/// more than one retention interval.
async fn expire(db: &mut PgConnection, principal: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("update agent_held_write set state='expired',body='{}'::jsonb,summary='',preview=null where principal_id=$1 and state='held' and expires_at<=now()")
        .bind(principal)
        .execute(db)
        .await?;
    Ok(())
}

/// Expire up to `batch` held writes of anyone that are past their time, removing their text
/// (the retention timer, [`crate::retention`]). Returns how many it expired.
pub async fn expire_due(db: &mut PgConnection, batch: i64) -> Result<u64, sqlx::Error> {
    sqlx::query("with due as (select id from agent_held_write where state='held' and expires_at<=now() order by expires_at limit $1 for update skip locked) update agent_held_write h set state='expired',body='{}'::jsonb,summary='',preview=null from due where h.id=due.id")
        .bind(batch)
        .execute(db)
        .await
        .map(|done| done.rows_affected())
}

/// Hold a remote agent's write and answer `state=held`. The same request held again (a
/// resend) answers with the item already waiting.
pub(super) async fn hold(ctx: &Ctx<'_>, call: &mut Call, held: Held) -> Result<Served, AgentFail> {
    let mut db = ctx.state.pool.acquire().await.map_err(ApiError::from)?;
    expire(&mut db, ctx.identity)
        .await
        .map_err(ApiError::from)?;
    let waiting: Option<(Uuid, chrono::DateTime<Utc>)> = sqlx::query_as("select id,expires_at from agent_held_write where key_id=$1 and digest=$2 and tool=$3 and state='held' and expires_at>now()")
        .bind(ctx.key)
        .bind(&held.digest[..])
        .bind(held.tool)
        .fetch_optional(&mut *db)
        .await
        .map_err(ApiError::from)?;
    let (id, expires) = match waiting {
        Some(found) => found,
        None => {
            let count: i64 = sqlx::query_scalar("select count(*) from agent_held_write where principal_id=$1 and state='held' and expires_at>now()")
                .bind(ctx.identity)
                .fetch_one(&mut *db)
                .await
                .map_err(ApiError::from)?;
            if count >= MAX_WAITING {
                return Err(
                    engine_agent::error::AgentError::PolicyDenied { policy: "held" }.into(),
                );
            }
            let client = http::client_claim(ctx.headers).unwrap_or_default();
            sqlx::query_as("insert into agent_held_write(id,project_id,principal_id,key_id,session_id,session_generation,tool,target,document_id,body,digest,client,summary,preview,expires_at) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now()+make_interval(days=>$15)) returning id,expires_at")
                .bind(Uuid::new_v4())
                .bind(ctx.project)
                .bind(ctx.identity)
                .bind(ctx.key)
                .bind(ctx.session)
                .bind(ctx.generation)
                .bind(held.tool)
                .bind(&held.target)
                .bind(held.document)
                .bind(&held.body)
                .bind(&held.digest[..])
                .bind(client)
                .bind(cut(&held.summary, 8000))
                .bind(held.preview.as_deref().map(|p| cut(p, 64000)))
                .bind(HOLD_DAYS as i32)
                .fetch_one(&mut *db)
                .await
                .map_err(ApiError::from)?
        }
    };
    call.outcome = Some("held");
    let expires = expires.to_rfc3339_opts(SecondsFormat::Secs, true);
    let note = "Held: the person you act for must confirm it in Dynodoc (Waiting for your confirmation) before it is stored for review.";
    let text = match ctx.format {
        Format::Json => json!({"protocol":"dynodoc.agent/1","tool":held.tool,"state":"held","held":id,"expires_at":expires,"note":note,"trust":"data"}).to_string(),
        Format::Dct => HeaderBuilder::new(match held.tool {
            "remember" => Tool::Memory,
            "submit" | "withdraw" => Tool::Submit,
            _ => Tool::Propose,
        })
        .kv("state", "held")
        .kv("held", id)
        .kv("expires_at", &expires)
        .assemble(""),
    };
    Ok(Served {
        bytes: text.len(),
        response: http::reply(ctx.format, text, None),
    })
}

/// At most `max` characters.
fn cut(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// What a person reads about a held `propose`: its title, target, and each op in one line.
pub(super) fn propose_summary(body: &Value, file: Uuid) -> String {
    let ops = body["ops"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut lines = vec![format!(
        "{} operation(s) on file {} at revision {}{}",
        ops.len(),
        &file.to_string()[..8],
        body["rev"].as_u64().unwrap_or(0),
        body["name"]
            .as_str()
            .map(|n| format!(": \"{}\"", cut(n, 200)))
            .unwrap_or_default()
    )];
    for op in ops.iter().take(30) {
        let get = |key: &str| op.get(key).and_then(Value::as_str);
        let mut line = format!("- {}", get("op").unwrap_or("?"));
        for key in [
            "ref", "after", "before", "sheet", "range", "at", "slide", "shape",
        ] {
            if let Some(v) = get(key) {
                line.push_str(&format!(" {key}={}", cut(v, 40)));
            }
        }
        if let Some(new) = get("text").or_else(|| get("with")) {
            line.push_str(&format!(" \"{}\"", cut(new, 160)));
        }
        lines.push(line);
    }
    if ops.len() > 30 {
        lines.push(format!("... and {} more", ops.len() - 30));
    }
    lines.join("\n")
}

// --- the person's routes ----------------------------------------------------------------------

/// The person's own account, never an agent's.
async fn person(db: &mut PgConnection, auth: &AuthContext) -> Result<(), ApiError> {
    if auth.device.is_some() || identity::is_agent(db, auth.identity_id).await? {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

/// Every write held for you, newest first, in every project.
#[utoipa::path(operation_id="agent_held_list", get, path="/agent-held", tag="agent memory", security(("paseto"=[])), responses((status=200, description="Waiting for your confirmation: id, project, tool (propose, submit, withdraw or remember), client (the agent's self-description), client_name (the OAuth client's name), document, summary of the ops, preview (the dry-run diff of a propose), created_at, expires_at", body=Value),(status=401, description="Sign in required (device sessions, OAuth access tokens and connector keys are refused)"),(status=403, description="An agent identity")))]
pub(super) async fn list(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let mut db = state.pool.acquire().await?;
    person(&mut db, &auth).await?;
    expire(&mut db, auth.identity_id).await?;
    let items: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('id',h.id,'project',jsonb_build_object('id',h.project_id,'name',s.name),'tool',h.tool,'client',h.client,'client_name',c.label,'document',case when d.id is null then null else jsonb_build_object('id',d.id,'title',d.title) end,'summary',h.summary,'preview',h.preview,'created_at',h.created_at,'expires_at',h.expires_at) from agent_held_write h join access_space s on s.id=h.project_id left join device_key_class c on c.key_id=h.key_id left join document d on d.id=h.document_id where h.principal_id=$1 and h.state='held' and h.expires_at>now() order by h.created_at desc limit 100")
        .bind(auth.identity_id)
        .fetch_all(&mut *db)
        .await?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"items":items})),
    ))
}

/// `(project, key, session, generation, tool, target, document, body, digest, client)`
type HeldRow = (
    Uuid,
    Uuid,
    Uuid,
    i64,
    String,
    String,
    Option<Uuid>,
    Value,
    Vec<u8>,
    String,
);

/// Confirm a held write: it is carried out now as the agent, with every check of a direct
/// call, and a confirmed `propose` goes to review. A replay the checks refuse is `failed`.
#[utoipa::path(operation_id="agent_held_confirm", post, path="/agent-held/{held}/confirm", tag="agent memory", security(("paseto"=[])), params(("held"=Uuid,Path,description="Held write")), responses((status=200, description="state confirmed (result: what the call answered; a propose is also submitted for review) or failed (result.error: the agent code of the refusal)", body=Value),(status=401, description="Sign in required (device sessions, OAuth access tokens and connector keys are refused)"),(status=403, description="An agent identity"),(status=404, description="Not yours, already decided or expired")))]
pub(super) async fn confirm(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(held): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let mut db = state.pool.acquire().await?;
    person(&mut db, &auth).await?;
    // Claimed in one statement: two presses replay once.
    let row: Option<HeldRow> = sqlx::query_as("update agent_held_write set state='confirmed',decided_at=now(),decided_by=$2 where id=$1 and principal_id=$2 and state='held' and expires_at>now() returning project_id,key_id,session_id,session_generation,tool,target,document_id,body,digest,client")
        .bind(held)
        .bind(auth.identity_id)
        .fetch_optional(&mut *db)
        .await?;
    let (project, key, session, generation, tool, target, document, body, digest, client) =
        row.ok_or(ApiError::NotFound)?;
    drop(db);
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&client) {
        headers.insert("x-dynodoc-client", value);
    }
    let (scope, dct_tool) = match tool.as_str() {
        "submit" => ("content:submit", Tool::Submit),
        "withdraw" => ("content:submit", Tool::Submit),
        _ => ("content:propose", Tool::Propose),
    };
    let ctx = Ctx {
        state: &state,
        identity: auth.identity_id,
        key,
        session,
        generation,
        scope,
        project,
        headers: &headers,
        tool: dct_tool,
        digest: digest.as_slice().try_into().unwrap_or([0; 32]),
        format: Format::Json,
        confirmed: true,
    };
    let mut call = Call::default();
    let proposal_id = Uuid::parse_str(&target).ok();
    let result = match (tool.as_str(), proposal_id) {
        ("propose", _) => write::propose_call(&ctx, &mut call, &target, Ok(Json(body))).await,
        ("remember", _) => memory::agent_propose_call(&ctx, &mut call, Ok(Json(body))).await,
        ("submit", Some(id)) => {
            let bytes = serde_json::to_vec(&body).unwrap_or_default();
            proposal::submit_call(&ctx, &mut call, id, &bytes).await
        }
        ("withdraw", Some(id)) => {
            let bytes = serde_json::to_vec(&body).unwrap_or_default();
            proposal::withdraw_call(&ctx, &mut call, id, &bytes).await
        }
        _ => Err(ApiError::Internal("held write without a target".into()).into()),
    };
    let (ok, mut answer) = match ctx.finish(call, result).await {
        Ok(response) => {
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap_or_default();
            (true, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
        }
        Err(fail) => (false, json!({"error": fail.agent_code()})),
    };
    // The person's confirmation of a proposal is their submission of it for review.
    if ok && tool == "propose" && answer["state"] == "draft" {
        if let (Some(doc), Some(draft)) = (
            document,
            answer["proposal"].as_str().and_then(|p| p.parse().ok()),
        ) {
            let (mut tx, role, _) =
                apply::begin_write(&state, DocumentId(doc), IdentityId(auth.identity_id)).await?;
            if role != engine_core::governance::Role::Auditor
                && crate::reviews::mark_submitted(&mut tx, doc, draft, auth.identity_id, "", false)
                    .await?
            {
                tx.commit().await?;
                answer["state"] = json!("open");
            }
        }
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("update agent_held_write set result=$2,state=case when $3 then 'confirmed' else 'failed' end where id=$1")
        .bind(held)
        .bind(&answer)
        .bind(ok)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        if ok {
            "agent.held.confirmed"
        } else {
            "agent.held.failed"
        },
        project,
        json!({"held":held,"tool":tool,"key_id":key,"document":document,"result":answer}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":held,"state":if ok { "confirmed" } else { "failed" },"result":answer}),
    ))
}

/// Decline a held write: nothing is carried out and its text is removed.
#[utoipa::path(operation_id="agent_held_decline", post, path="/agent-held/{held}/decline", tag="agent memory", security(("paseto"=[])), params(("held"=Uuid,Path,description="Held write")), responses((status=200, description="state declined", body=Value),(status=401, description="Sign in required (device sessions, OAuth access tokens and connector keys are refused)"),(status=403, description="An agent identity"),(status=404, description="Not yours, already decided or expired")))]
pub(super) async fn decline(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(held): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = state.pool.begin().await?;
    person(&mut tx, &auth).await?;
    let row: Option<(Uuid, String, Uuid)> = sqlx::query_as("update agent_held_write set state='declined',decided_at=now(),decided_by=$2,body='{}'::jsonb,summary='',preview=null where id=$1 and principal_id=$2 and state='held' and expires_at>now() returning project_id,tool,key_id")
        .bind(held)
        .bind(auth.identity_id)
        .fetch_optional(&mut *tx)
        .await?;
    let (project, tool, key) = row.ok_or(ApiError::NotFound)?;
    audit(
        &mut tx,
        auth.identity_id,
        "agent.held.declined",
        project,
        json!({"held":held,"tool":tool,"key_id":key}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"id":held,"state":"declined"})))
}
