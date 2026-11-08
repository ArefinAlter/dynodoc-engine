//! The outbound mail outbox (migration 0111, docs/SELF-HOSTED-EDITION.md 6.5): the web tier queues
//! a message whose send failed in a way that may pass, and its workers drain the queue. The API only
//! stores, leases and records; it never talks to a mail server.
//!
//! - Every route but the administrators' view needs the service key: people and agents cannot
//!   queue mail, read it or mark it sent.
//! - Only invitations, approval and notice messages are accepted. A sign-in link is a credential
//!   and is never stored (the web tier never queues one; the kind list refuses it anyway).
//! - A claimed message is leased; nothing else claims it until the lease ends, so two web
//!   processes never send it twice at once. A message sent or failed for good loses its subject
//!   and bodies at once; retention prunes the row later.
//! - The administrators' view (`GET /admin/mail-outbox`, also auditors) shows counts and states,
//!   the recipient's domain only, never a subject or a body.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{auth::routes::require_service, error::ApiError, AppState};

/// Attempts after which a message is given up.
pub const MAX_ATTEMPTS: i32 = 8;
const KINDS: [&str; 3] = ["invitation", "approval", "notice"];
const MAX_BODIES: usize = 256 * 1024;

/// The routes of this module.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/internal/mail/outbox", post(enqueue))
        .route("/internal/mail/outbox/claim", post(claim))
        .route("/internal/mail/outbox/{id}/result", post(result))
        .route("/admin/mail-outbox", get(view))
}

fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}

fn service(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    require_service(state, headers).map_err(|_| ApiError::Forbidden)
}

/// A deliverable address: plain, not reserved for agents or service accounts.
fn address(raw: &str) -> Result<String, ApiError> {
    crate::directory::normal_email(raw)
        .filter(|e| {
            !crate::agent::identity::is_reserved_email(e)
                && !crate::auth::routes::is_service_email(e)
        })
        .ok_or_else(|| bad("The address cannot receive mail."))
}

#[derive(Deserialize)]
struct Message {
    kind: String,
    to: String,
    subject: String,
    text: String,
    html: String,
    reply_to: Option<String>,
}

/// `POST /internal/mail/outbox`: queue one message; answers its id.
async fn enqueue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(m): Json<Message>,
) -> Result<Json<Value>, ApiError> {
    service(&state, &headers)?;
    if !KINDS.contains(&m.kind.as_str()) {
        return Err(bad(
            "Only invitation, approval and notice messages are queued.",
        ));
    }
    let to = address(&m.to)?;
    let reply_to = m.reply_to.as_deref().map(address).transpose()?;
    let subject = m.subject.trim();
    if subject.is_empty() || subject.chars().count() > 300 || subject.chars().any(char::is_control)
    {
        return Err(bad("A subject of 1 to 300 characters on one line."));
    }
    if m.text.len() + m.html.len() > MAX_BODIES {
        return Err(bad("The message is larger than 256 KiB."));
    }
    let id: Uuid = sqlx::query_scalar("insert into mail_outbox(kind,recipient,reply_to,subject,text_body,html_body) values($1,$2,$3,$4,$5,$6) returning id")
        .bind(&m.kind)
        .bind(&to)
        .bind(&reply_to)
        .bind(subject)
        .bind(&m.text)
        .bind(&m.html)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(json!({ "id": id })))
}

#[derive(Deserialize)]
struct Claim {
    limit: i64,
    lease_seconds: i64,
}

/// `POST /internal/mail/outbox/claim`: lease up to `limit` due messages for `lease_seconds`.
async fn claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(c): Json<Claim>,
) -> Result<Json<Value>, ApiError> {
    service(&state, &headers)?;
    if !(1..=20).contains(&c.limit) || !(30..=300).contains(&c.lease_seconds) {
        return Err(bad("limit is 1 to 20 and lease_seconds 30 to 300."));
    }
    let items: Value = sqlx::query_scalar("with due as (select id from mail_outbox where sent_at is null and failed_at is null and next_attempt_at<=now() and (lease_until is null or lease_until<now()) order by next_attempt_at,created_at limit $1 for update skip locked), leased as (update mail_outbox m set lease_until=now()+make_interval(secs=>$2::double precision),attempts=m.attempts+1 from due where m.id=due.id returning m.*) select coalesce(jsonb_agg(jsonb_build_object('id',id,'kind',kind,'to',recipient,'subject',subject,'text',text_body,'html',html_body,'reply_to',reply_to,'attempts',attempts) order by next_attempt_at,created_at),'[]'::jsonb) from leased")
        .bind(c.limit)
        .bind(c.lease_seconds)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize)]
struct Outcome {
    ok: bool,
    #[serde(default)]
    permanent: bool,
    error_class: Option<String>,
}

/// `POST /internal/mail/outbox/{id}/result`: the worker's report on a message it leased. Sent or
/// failed for good: the content is cleared. Otherwise it is due again after `2^attempts` minutes,
/// at most six hours.
async fn result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(o): Json<Outcome>,
) -> Result<Json<Value>, ApiError> {
    service(&state, &headers)?;
    let class = o
        .error_class
        .as_deref()
        .unwrap_or(if o.ok { "" } else { "unknown" });
    if !o.ok
        && (class.is_empty()
            || class.len() > 40
            || !class.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
    {
        return Err(bad(
            "error_class is 1 to 40 lower-case letters and underscores.",
        ));
    }
    let state_sql = if o.ok {
        "update mail_outbox set sent_at=now(),lease_until=null,subject='',text_body='',html_body='' where id=$1 and lease_until is not null and sent_at is null and failed_at is null returning 'sent'"
    } else {
        "update mail_outbox set lease_until=null,last_error_class=$2,
            failed_at=case when $3 or attempts>=$4 then now() end,
            subject=case when $3 or attempts>=$4 then '' else subject end,
            text_body=case when $3 or attempts>=$4 then '' else text_body end,
            html_body=case when $3 or attempts>=$4 then '' else html_body end,
            next_attempt_at=now()+least(make_interval(mins=>power(2,least(attempts,16))::int),interval '6 hours')
          where id=$1 and lease_until is not null and sent_at is null and failed_at is null
          returning case when failed_at is null then 'queued' else 'failed' end"
    };
    let query = sqlx::query_scalar(state_sql).bind(id);
    let query = if o.ok {
        query
    } else {
        query.bind(class).bind(o.permanent).bind(MAX_ATTEMPTS)
    };
    let outcome: Option<String> = query.fetch_optional(&state.pool).await?;
    let outcome = outcome.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "id": id, "state": outcome })))
}

/// `GET /admin/mail-outbox`: counts per state and the 50 newest messages, without content.
async fn view(
    State(state): State<AppState>,
    auth: crate::auth::AuthContext,
) -> Result<Json<Value>, ApiError> {
    crate::admin::require_reader(&state, &auth).await?;
    const STATE: &str = "case when sent_at is not null then 'sent' when failed_at is not null then 'failed' when lease_until>now() then 'sending' else 'queued' end";
    let body: Value = sqlx::query_scalar(&format!("select jsonb_build_object(
        'counts',(select coalesce(jsonb_object_agg(s,n),'{{}}'::jsonb) from (select {STATE} as s,count(*) as n from mail_outbox group by 1) c),
        'items',(select coalesce(jsonb_agg(r order by r->>'created_at' desc),'[]'::jsonb) from (select jsonb_build_object('id',id,'kind',kind,'recipient_domain',split_part(recipient,'@',2),'attempts',attempts,'state',{STATE},'last_error_class',last_error_class,'created_at',created_at,'next_attempt_at',next_attempt_at,'sent_at',sent_at,'failed_at',failed_at) as r from mail_outbox order by created_at desc limit 50) l))"))
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(body))
}
