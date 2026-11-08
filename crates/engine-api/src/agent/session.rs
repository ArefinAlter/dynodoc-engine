//! Agent sessions and turns (decision 026, part 1): what an agent was asked and which of its
//! proposal calls a turn produced, so that a merged block can be traced to its prompt.
//!
//! An agent opens a session (`POST /projects/{id}/agent/sessions`), records each turn
//! (`POST .../sessions/{session}/turns`: the person's prompt as typed and the agent's visible
//! reasoning) and names `session` and `turn` in its `propose` calls. The project's capture
//! policy decides what is kept: nothing (`off`: sessions are refused), actions only
//! (`actions`: turns without text) or text too (`full`). Text is redacted for secrets before it
//! is stored and refused if it cannot be stored safely. Turns are hash-chained per session,
//! and each new head is signed with the server's receipt key when one is installed (a seal,
//! schema 65), so `GET /projects/{id}/agent-sessions/{session}/verify` detects a session or turn
//! changed after the fact (decision 026 acceptance 4).
//! Everything here is the agent's own record; nothing in it grants or decides anything.
use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::{HeaderMap, Uri},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, SecondsFormat, Utc};
use engine_agent::{
    dct::{HeaderBuilder, Tool},
    error::AgentError,
};
use serde_json::{json, Value};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use super::{
    error::AgentFail,
    http,
    http::Format,
    identity, ledger,
    routes::{Call, Ctx, Out, Served},
    write::json_body,
};
use crate::{
    auth::{
        agent::{verify_current, AgentAuth, Claimed, ContentPropose},
        AuthContext,
    },
    error::ApiError,
    projects, AppState,
};

const MAX_PROMPT: usize = 20_000;
const MAX_REASONING: usize = 40_000;
const MAX_TURNS: i32 = 10_000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/projects/{id}/agent/sessions", post(open))
        .route("/projects/{id}/agent/sessions/{session}/turns", post(turn))
}

/// The members' routes: verifying a session's chain and seal.
pub fn people_routes() -> Router<AppState> {
    Router::new().route(
        "/projects/{id}/agent-sessions/{session}/verify",
        get(verify_session),
    )
}

/// The capture policy of a project: `(capture, prompt_visibility)`; no row is the default.
pub(crate) async fn capture_policy(
    db: &mut PgConnection,
    project: Uuid,
) -> Result<(String, String), sqlx::Error> {
    let row: Option<(String, String)> = sqlx::query_as(
        "select capture,prompt_visibility from project_agent_capture where project_id=$1",
    )
    .bind(project)
    .fetch_optional(db)
    .await?;
    Ok(row.unwrap_or_else(|| ("full".into(), "author".into())))
}

// --- redaction ---------------------------------------------------------------------------

/// Replaces credentials in agent text with `[redacted]` and counts them. Covered: private
/// key blocks, common provider key and token prefixes, credentials in URLs, bearer values,
/// and `name=value` / `name: value` pairs whose name says secret. Conservative by design: a
/// false positive hides a word of a prompt, a false negative stores a secret.
pub fn redact(text: &str) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let mut count = 0usize;
    // Private key blocks first: they span lines.
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start..];
        let is_key = after
            .lines()
            .next()
            .is_some_and(|l| l.contains("PRIVATE KEY"));
        if !is_key {
            out.push_str(&rest[..start + 11]);
            rest = &rest[start + 11..];
            continue;
        }
        out.push_str(&rest[..start]);
        out.push_str("[redacted]");
        count += 1;
        match after.find("-----END ") {
            Some(end) => {
                let tail = &after[end..];
                let close = tail[9..].find("-----").map(|i| end + 9 + i + 5);
                rest = close.map_or("", |c| &after[c..]);
            }
            None => rest = "",
        }
    }
    out.push_str(rest);
    let mut text = out;
    // Token-like words.
    const PREFIXES: [&str; 14] = [
        "sk-ant-",
        "sk-proj-",
        "sk-",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "AIza",
        "glpat-",
        "ya29.",
    ];
    let mut words = String::with_capacity(text.len());
    for (i, piece) in split_keep(&text).into_iter().enumerate() {
        let _ = i;
        let token = piece.trim_matches(|c: char| "\"'`()[]{}<>,;".contains(c));
        let secret_prefix = PREFIXES
            .iter()
            .any(|p| token.starts_with(p) && token.len() >= p.len() + 12);
        let bearer_like = token.len() >= 32
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.=+/".contains(&b))
            && token.bytes().any(|b| b.is_ascii_digit())
            && token.bytes().any(|b| b.is_ascii_alphabetic())
            && !token.contains("://")
            && !is_uuid(token);
        let url_with_credentials = token.contains("://")
            && token
                .split("://")
                .nth(1)
                .and_then(|r| r.split('/').next())
                .is_some_and(|authority| authority.contains('@') && authority.contains(':'));
        if secret_prefix || bearer_like || url_with_credentials {
            words.push_str(&piece.replace(token, "[redacted]"));
            count += 1;
        } else {
            words.push_str(piece);
        }
    }
    text = words;
    // `password = value`, `api_key: value`, `Authorization: Bearer value`.
    let mut lines = Vec::new();
    for line in text.split('\n') {
        let lower = line.to_ascii_lowercase();
        let named = [
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "api-key",
            "token",
            "authorization",
            "private_key",
            "access_key",
        ]
        .iter()
        .find_map(|name| lower.find(name).map(|at| at + name.len()));
        match named {
            Some(at) => {
                let tail = &line[at..];
                let sep = tail.find(['=', ':']);
                match sep {
                    Some(s) if tail[..s].trim().is_empty() && !tail[s + 1..].trim().is_empty() => {
                        lines.push(format!("{}{} [redacted]", &line[..at], &tail[..=s]));
                        count += 1;
                    }
                    _ => lines.push(line.to_owned()),
                }
            }
            None => lines.push(line.to_owned()),
        }
    }
    (lines.join("\n"), count)
}

fn split_keep(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() {
            if start < i {
                out.push(&text[start..i]);
            }
            out.push(&text[i..i + c.len_utf8()]);
            start = i + c.len_utf8();
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

fn is_uuid(s: &str) -> bool {
    Uuid::parse_str(s).is_ok() && s.len() == 36
}

// --- hash chain --------------------------------------------------------------------------

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for p in parts {
        ctx.update(&(p.len() as u64).to_be_bytes());
        ctx.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// The first link of a session's chain: its header.
pub fn session_head(id: Uuid, product: &str, model: Option<&str>, started: &str) -> [u8; 32] {
    digest(&[
        b"dynodoc.agent-session.v1",
        id.as_bytes(),
        product.as_bytes(),
        model.unwrap_or("").as_bytes(),
        started.as_bytes(),
    ])
}

/// The hash of a turn: the previous link and every stored field, length-prefixed.
pub fn turn_hash(
    prev: &[u8; 32],
    seq: i32,
    at: &str,
    prompt: Option<&str>,
    source: Option<&str>,
    reasoning: Option<&str>,
    redactions: i32,
) -> [u8; 32] {
    digest(&[
        b"dynodoc.agent-turn.v1",
        prev,
        &seq.to_be_bytes(),
        at.as_bytes(),
        prompt.unwrap_or("\u{0}").as_bytes(),
        source.unwrap_or("").as_bytes(),
        reasoning.unwrap_or("\u{0}").as_bytes(),
        &redactions.to_be_bytes(),
    ])
}

/// What a seal signs: the session, its project, its turn count and its head.
pub fn seal_message(id: Uuid, project: Uuid, turns: i32, head: &[u8]) -> [u8; 32] {
    digest(&[
        b"dynodoc.agent-session-seal.v1",
        id.as_bytes(),
        project.as_bytes(),
        &turns.to_be_bytes(),
        head,
    ])
}

/// Sign the session's new head with the server's receipt key, in the transaction that moved it.
// shortcut: without an installed receipt key (development, tests) heads stay unsigned and
// verification says `unsigned`; require the key for agent sessions once every deployment has one.
async fn seal(
    tx: &mut Transaction<'_, Postgres>,
    state: &AppState,
    id: Uuid,
    project: Uuid,
    turns: i32,
    head: &[u8; 32],
) -> Result<(), ApiError> {
    let Some(signer) = state.ref_signer.as_deref() else {
        return Ok(());
    };
    use ring::signature::KeyPair;
    let signature = signer.sign(&seal_message(id, project, turns, head));
    sqlx::query("insert into agent_session_seal(session_id,turns,head,public_key,signature) values($1,$2,$3,$4,$5)")
        .bind(id)
        .bind(turns)
        .bind(&head[..])
        .bind(hex::encode(signer.public_key().as_ref()))
        .bind(signature.as_ref())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn text_field(body: &Value, name: &'static str, max: usize) -> Result<Option<String>, AgentFail> {
    match body.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.chars().count() <= max => Ok(Some(s.clone())),
        Some(Value::String(s)) => Err(AgentError::LimitExceeded {
            field: name,
            limit: max as u64,
            value: s.chars().count() as u64,
        }
        .into()),
        Some(_) => Err(AgentError::BadRequest { field: name }.into()),
    }
}

fn short(
    body: &Value,
    name: &'static str,
    max: usize,
    required: bool,
) -> Result<Option<String>, AgentFail> {
    let value = text_field(body, name, max)?;
    match value {
        Some(v) if v.trim().is_empty() || v.chars().any(char::is_control) => {
            Err(AgentError::BadRequest { field: name }.into())
        }
        None if required => Err(AgentError::BadRequest { field: name }.into()),
        other => Ok(other),
    }
}

async fn verify(tx: &mut Transaction<'_, Postgres>, ctx: &Ctx<'_>) -> Result<(), AgentFail> {
    verify_current(
        tx,
        &Claimed {
            identity: ctx.identity,
            key: ctx.key,
            project: ctx.project,
            session: ctx.session,
            generation: ctx.generation,
            scope: ctx.scope,
        },
        true,
    )
    .await?;
    Ok(())
}

// --- routes ------------------------------------------------------------------------------

/// Open a session for this agent key in this project.
#[utoipa::path(operation_id="agent_session_open", post, path="/projects/{id}/agent/sessions", tag="agent", params(("id"=Uuid,Path,description="Project")), request_body=Value, security(("device_session"=["content:propose"])), responses((status=200, description="The session id and the capture in force (actions or full). Body: source (mcp, acp, gateway or import), product, optional product_version and model", body=Value),(status=400, description="Invalid body"),(status=401, description="Not a project device session"),(status=403, description="Scope, grant or membership missing, or capture is off (details.policy: capture)"),(status=429, description="Admission budget")))]
async fn open(
    State(state): State<AppState>,
    auth: AgentAuth<ContentPropose>,
    Path(project): Path<Uuid>,
    headers: HeaderMap,
    uri: Uri,
    parsed: Result<Json<Value>, JsonRejection>,
) -> Out {
    let ctx = Ctx::new(
        &state,
        &auth,
        project,
        &headers,
        Tool::Propose,
        ledger::request_digest(&[b"POST", uri.path().as_bytes()]),
    )?;
    let mut call = Call::default();
    let result = open_call(&ctx, &mut call, parsed).await;
    ctx.finish(call, result).await
}

async fn open_call(
    ctx: &Ctx<'_>,
    call: &mut Call,
    parsed: Result<Json<Value>, JsonRejection>,
) -> Result<Served, AgentFail> {
    let admitted = ctx.admit(call).await?;
    drop(admitted);
    let body = json_body(parsed)?;
    let source = match body
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("gateway")
    {
        s @ ("mcp" | "acp" | "gateway" | "import") => s.to_owned(),
        _ => return Err(AgentError::BadRequest { field: "source" }.into()),
    };
    let product = short(&body, "product", 80, true)?.unwrap_or_default();
    let version = short(&body, "product_version", 40, false)?;
    let model = short(&body, "model", 120, false)?;
    let mut tx = ctx.state.pool.begin().await.map_err(ApiError::from)?;
    verify(&mut tx, ctx).await?;
    let (capture, _) = capture_policy(&mut tx, ctx.project)
        .await
        .map_err(ApiError::from)?;
    if capture == "off" {
        return Err(AgentError::PolicyDenied { policy: "capture" }.into());
    }
    let agent = identity::ensure(&mut tx, ctx.identity, ctx.key).await?;
    let id = Uuid::new_v4();
    let started = Utc::now();
    let started_text = started.to_rfc3339_opts(SecondsFormat::Micros, true);
    let head = session_head(id, &product, model.as_deref(), &started_text);
    sqlx::query("insert into agent_session(id,project_id,agent_identity_id,principal_id,key_id,source,product,product_version,model,capture,started_at,head) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(id)
        .bind(ctx.project)
        .bind(agent.id)
        .bind(ctx.identity)
        .bind(ctx.key)
        .bind(&source)
        .bind(&product)
        .bind(&version)
        .bind(&model)
        .bind(&capture)
        .bind(started)
        .bind(&head[..])
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from)?;
    seal(&mut tx, ctx.state, id, ctx.project, 0, &head).await?;
    tx.commit().await.map_err(ApiError::from)?;
    let text = match ctx.format {
        Format::Json => json!({"protocol":"dynodoc.agent/1","tool":"session","session":id,"capture":capture,"started_at":started_text,"trust":"data"}).to_string(),
        Format::Dct => HeaderBuilder::new(Tool::Session)
            .kv("session", id)
            .kv("capture", &capture)
            .kv("started_at", &started_text)
            .assemble(""),
    };
    let bytes = text.len();
    Ok(Served {
        response: http::reply(ctx.format, text, None),
        bytes,
    })
}

/// Record one turn of a session: the prompt as the person typed it (`prompt_source`
/// `launcher`) or as the agent reports it (`agent`), and the agent's visible reasoning.
#[utoipa::path(operation_id="agent_session_turn", post, path="/projects/{id}/agent/sessions/{session}/turns", tag="agent", params(("id"=Uuid,Path,description="Project"),("session"=Uuid,Path,description="A session of this agent key")), request_body=Value, security(("device_session"=["content:propose"])), responses((status=200, description="The turn number and how many secrets were redacted. Prompt and reasoning are stored only under full capture. Name session and turn in a later propose call to link its blocks to this turn", body=Value),(status=400, description="Invalid body or not this key's session"),(status=401, description="Not a project device session"),(status=403, description="Scope, grant or membership missing, or capture is off"),(status=429, description="Admission budget")))]
async fn turn(
    State(state): State<AppState>,
    auth: AgentAuth<ContentPropose>,
    Path((project, session)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    uri: Uri,
    parsed: Result<Json<Value>, JsonRejection>,
) -> Out {
    let ctx = Ctx::new(
        &state,
        &auth,
        project,
        &headers,
        Tool::Propose,
        ledger::request_digest(&[b"POST", uri.path().as_bytes()]),
    )?;
    let mut call = Call::default();
    let result = turn_call(&ctx, &mut call, session, parsed).await;
    ctx.finish(call, result).await
}

async fn turn_call(
    ctx: &Ctx<'_>,
    call: &mut Call,
    session: Uuid,
    parsed: Result<Json<Value>, JsonRejection>,
) -> Result<Served, AgentFail> {
    let admitted = ctx.admit(call).await?;
    drop(admitted);
    let body = json_body(parsed)?;
    let prompt = text_field(&body, "prompt", MAX_PROMPT)?;
    let reasoning = text_field(&body, "reasoning", MAX_REASONING)?;
    let source = match body.get("prompt_source").and_then(Value::as_str) {
        None if prompt.is_none() => None,
        None | Some("agent") => Some("agent"),
        Some("launcher") => Some("launcher"),
        Some(_) => {
            return Err(AgentError::BadRequest {
                field: "prompt_source",
            }
            .into())
        }
    };
    let mut tx = ctx.state.pool.begin().await.map_err(ApiError::from)?;
    verify(&mut tx, ctx).await?;
    let agent = identity::resolve(&mut tx, ctx.identity, ctx.key)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::NotFound)?;
    let row: Option<(i32, Vec<u8>, String)> = sqlx::query_as("select turns,head,capture from agent_session where id=$1 and project_id=$2 and agent_identity_id=$3 and principal_id=$4 for update")
        .bind(session)
        .bind(ctx.project)
        .bind(agent.id)
        .bind(ctx.identity)
        .fetch_optional(&mut *tx)
        .await
        .map_err(ApiError::from)?;
    let (turns, head, session_capture) = row.ok_or(ApiError::NotFound)?;
    if turns >= MAX_TURNS {
        return Err(AgentError::LimitExceeded {
            field: "turns",
            limit: MAX_TURNS as u64,
            value: turns as u64,
        }
        .into());
    }
    // The stricter of the session's capture and the project's current one applies.
    let (capture, _) = capture_policy(&mut tx, ctx.project)
        .await
        .map_err(ApiError::from)?;
    if capture == "off" {
        return Err(AgentError::PolicyDenied { policy: "capture" }.into());
    }
    let keep_text = capture == "full" && session_capture == "full";
    let mut redactions = 0usize;
    let mut clean = |t: Option<String>| {
        t.filter(|_| keep_text).map(|t| {
            let (r, n) = redact(&t);
            redactions += n;
            r
        })
    };
    let prompt = clean(prompt);
    let reasoning = clean(reasoning);
    let seq = turns + 1;
    let at: DateTime<Utc> = Utc::now();
    let at_text = at.to_rfc3339_opts(SecondsFormat::Micros, true);
    let prev: [u8; 32] = head
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Internal("session head".into()))?;
    let source = if prompt.is_some() { source } else { None };
    let hash = turn_hash(
        &prev,
        seq,
        &at_text,
        prompt.as_deref(),
        source,
        reasoning.as_deref(),
        redactions as i32,
    );
    sqlx::query("insert into agent_turn(session_id,seq,at,prompt,prompt_source,reasoning,redactions,prev,hash) values($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(session)
        .bind(seq)
        .bind(at)
        .bind(&prompt)
        .bind(source)
        .bind(&reasoning)
        .bind(redactions as i32)
        .bind(&prev[..])
        .bind(&hash[..])
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from)?;
    sqlx::query("update agent_session set turns=$2,head=$3 where id=$1")
        .bind(session)
        .bind(seq)
        .bind(&hash[..])
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from)?;
    seal(&mut tx, ctx.state, session, ctx.project, seq, &hash).await?;
    tx.commit().await.map_err(ApiError::from)?;
    let text = match ctx.format {
        Format::Json => json!({"protocol":"dynodoc.agent/1","tool":"turn","session":session,"turn":seq,"stored_text":keep_text,"redactions":redactions,"trust":"data"}).to_string(),
        Format::Dct => HeaderBuilder::new(Tool::Session)
            .kv("session", session)
            .kv("turn", seq)
            .kv("stored_text", keep_text)
            .kv("redactions", redactions)
            .assemble(""),
    };
    let bytes = text.len();
    Ok(Served {
        response: http::reply(ctx.format, text, None),
        bytes,
    })
}

/// The session and turn a `propose` call names, checked to belong to the calling agent and
/// project. Returns `None` when the call names none.
pub(super) async fn check_link(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    agent: Uuid,
    session: Option<Uuid>,
    turn: Option<i32>,
) -> Result<Option<(Uuid, Option<i32>)>, AgentFail> {
    let Some(session) = session else {
        if turn.is_some() {
            return Err(AgentError::BadRequest { field: "turn" }.into());
        }
        return Ok(None);
    };
    let turns: Option<i32> = sqlx::query_scalar(
        "select turns from agent_session where id=$1 and project_id=$2 and agent_identity_id=$3",
    )
    .bind(session)
    .bind(project)
    .bind(agent)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::from)?;
    let turns = turns.ok_or(AgentError::BadRequest { field: "session" })?;
    if let Some(t) = turn {
        if t < 1 || t > turns {
            return Err(AgentError::BadRequest { field: "turn" }.into());
        }
    }
    Ok(Some((session, turn)))
}

/// product, model, started_at, turns, head
type SessionRow = (String, Option<String>, DateTime<Utc>, i32, Vec<u8>);

/// seq, at, prompt, prompt_source, reasoning, redactions, prev, hash, erased
type TurnRow = (
    i32,
    DateTime<Utc>,
    Option<String>,
    Option<String>,
    Option<String>,
    i32,
    Vec<u8>,
    Vec<u8>,
    bool,
);

/// Recompute a session's chain from its header and turns, and check its latest seal.
/// `chain` is `valid` or `broken`; `seal` is `valid`, `invalid` (a signature, key or head that
/// does not match), `behind` (valid, but turns were added after it) or `unsigned`. An erased
/// turn's text is gone, so its own hash is taken as stored and only its links are checked.
#[utoipa::path(operation_id="agent_session_verify", get, path="/projects/{id}/agent-sessions/{session}/verify", tag="agent memory", security(("paseto"=[])), params(("id"=Uuid,Path,description="Project"),("session"=Uuid,Path,description="Agent session")), responses((status=200, description="verified, chain (valid or broken), seal (valid, invalid, behind or unsigned), turns, sealed_turns, erased_turns and the signing epoch", body=Value),(status=403, description="Not a project member, or an agent identity"),(status=404, description="No such session in this project")))]
pub(super) async fn verify_session(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((project, session)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, ApiError> {
    let mut db = state.pool.acquire().await?;
    projects::require(&mut db, project, auth.identity_id).await?;
    if identity::is_agent(&mut db, auth.identity_id).await? {
        return Err(ApiError::Forbidden);
    }
    let row: Option<SessionRow> = sqlx::query_as(
        "select product,model,started_at,turns,head from agent_session where id=$1 and project_id=$2",
    )
    .bind(session)
    .bind(project)
    .fetch_optional(&mut *db)
    .await?;
    let (product, model, started, count, head) = row.ok_or(ApiError::NotFound)?;
    let turns: Vec<TurnRow> = sqlx::query_as("select seq,at,prompt,prompt_source,reasoning,redactions,prev,hash,erased from agent_turn where session_id=$1 order by seq")
        .bind(session)
        .fetch_all(&mut *db)
        .await?;
    let started = started.to_rfc3339_opts(SecondsFormat::Micros, true);
    let mut link = session_head(session, &product, model.as_deref(), &started).to_vec();
    let mut heads = vec![link.clone()];
    let mut chain = turns.len() == count as usize;
    let mut erased_turns = 0;
    for (i, (seq, at, prompt, source, reasoning, redactions, prev, hash, erased)) in
        turns.into_iter().enumerate()
    {
        let computed = if erased {
            erased_turns += 1;
            hash.clone()
        } else {
            let prev: [u8; 32] = link.as_slice().try_into().unwrap_or([0; 32]);
            let at = at.to_rfc3339_opts(SecondsFormat::Micros, true);
            turn_hash(
                &prev,
                seq,
                &at,
                prompt.as_deref(),
                source.as_deref(),
                reasoning.as_deref(),
                redactions,
            )
            .to_vec()
        };
        chain &= seq == i as i32 + 1 && prev == link && computed == hash;
        link = hash;
        heads.push(link.clone());
    }
    chain &= link == head;
    let seal: Option<(i32, Vec<u8>, String, Vec<u8>)> = sqlx::query_as("select turns,head,public_key,signature from agent_session_seal where session_id=$1 order by turns desc limit 1")
        .bind(session)
        .fetch_optional(&mut *db)
        .await?;
    let keys = engine_core::repository::server_authority::keys(&mut db).await?;
    let (seal_state, sealed_turns, epoch) = match seal {
        None => ("unsigned", None, None),
        Some((turns, sealed, key, signature)) => {
            let epoch = keys.get(&key).copied();
            let signed = epoch.is_some()
                && hex::decode(&key).is_ok_and(|k| {
                    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, k)
                        .verify(&seal_message(session, project, turns, &sealed), &signature)
                        .is_ok()
                });
            let matches = heads.get(turns as usize) == Some(&sealed);
            let state = match (signed && matches, turns == count) {
                (false, _) => "invalid",
                (true, true) => "valid",
                (true, false) => "behind",
            };
            (state, Some(turns), epoch)
        }
    };
    Ok(Json(json!({
        "session": session,
        "verified": chain && seal_state == "valid",
        "chain": if chain { "valid" } else { "broken" },
        "seal": seal_state,
        "turns": count,
        "sealed_turns": sealed_turns,
        "erased_turns": erased_turns,
        "epoch": epoch,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_redacted_and_ordinary_text_kept() {
        let (out, n) = redact("Use key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUV and push.");
        assert_eq!(out, "Use key [redacted] and push.");
        assert_eq!(n, 1);
        let (out, _) = redact("password = hunter2-very-secret");
        assert_eq!(out, "password = [redacted]");
        let (out, _) = redact("Authorization: Bearer abcdef0123456789abcdef0123456789");
        assert!(!out.contains("abcdef0123456789"), "{out}");
        let (out, _) = redact("clone https://user:pa55@example.org/repo now");
        assert!(!out.contains("pa55"), "{out}");
        let (out, _) = redact(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\nafter",
        );
        assert_eq!(out, "[redacted]\nafter");
        let ordinary =
            "Rewrite the summary in plain English; keep the 0042 site code and the table.";
        assert_eq!(redact(ordinary), (ordinary.to_owned(), 0));
        let id = "0b6a1d6e-6c0a-4a64-9a43-1f2b7d0a0001";
        assert_eq!(redact(id).1, 0);
    }

    #[test]
    fn the_chain_binds_every_field() {
        let head = session_head(
            Uuid::nil(),
            "Claude Code",
            Some("model"),
            "2026-11-05T00:00:00Z",
        );
        let a = turn_hash(&head, 1, "t", Some("p"), Some("launcher"), None, 0);
        assert_ne!(
            a,
            turn_hash(&head, 1, "t", Some("p2"), Some("launcher"), None, 0)
        );
        assert_ne!(
            a,
            turn_hash(&head, 2, "t", Some("p"), Some("launcher"), None, 0)
        );
        assert_ne!(a, turn_hash(&head, 1, "t", None, None, Some("p"), 0));
        assert_eq!(
            a,
            turn_hash(&head, 1, "t", Some("p"), Some("launcher"), None, 0)
        );
    }
}
