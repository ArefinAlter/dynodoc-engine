//! Portable observed change bundles. Host/timestamps are claims; uploader and
//! reception time are server facts. Submission creates a review draft, never a merge.
use crate::{
    access::{self, MemberRole},
    auth::{random_token, sha256, AuthContext},
    error::ApiError,
    reviews, AppState,
};
use axum::{
    extract::{FromRequestParts, Path, Query, State},
    http::{header, request::Parts},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use engine_shared::EventPayload;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/documents/{id}/provenance",
            get(checkpoint)
                .post(push)
                .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route("/documents/{id}/provenance/bundles/{bundle}", get(bundle))
        .route("/documents/{id}/connectors", get(grants).post(grant))
        .route("/documents/{id}/connectors/{grant}/revoke", post(revoke))
        .route("/connector/connection", get(connection))
        .route(
            "/connector/documents/{id}/checkpoint",
            get(connector_checkpoint),
        )
        .route(
            "/connector/documents/{id}/bundles",
            post(connector_push).layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route("/connector/documents/{id}/changes", get(connector_changes))
        .route(
            "/connector/documents/{id}/media",
            post(connector_media_put)
                .layer(axum::extract::DefaultBodyLimit::max(MEDIA_MAX_BYTES + 1024)),
        )
        .route(
            "/connector/documents/{id}/media/missing",
            post(connector_media_missing),
        )
        .route(
            "/connector/documents/{id}/media/{sha}",
            get(connector_media_get),
        )
        .route(
            "/connector/documents/{id}/nodes/{node}/history",
            get(connector_node_history),
        )
        .route(
            "/connector/documents/{id}/requests/{draft}/merge",
            post(connector_merge),
        )
        .route(
            "/connector/documents/{id}/requests/{draft}/withdraw",
            post(connector_withdraw),
        )
}
fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub host: String,
    pub mode: String,
    pub document_name: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub operation: EventPayload,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub format: String,
    pub version: u32,
    pub bundle_id: Uuid,
    pub client_id: Uuid,
    pub document_id: Uuid,
    pub base_seq: i64,
    pub base_chain_hash: String,
    pub capture: Capture,
    pub changes: Vec<Change>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Push {
    pub name: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub submit: bool,
    pub bundle: Bundle,
}

pub(crate) async fn anchor(db: &mut PgConnection, id: Uuid, seq: i64) -> Result<String, ApiError> {
    if seq == 0 {
        return Ok("0".repeat(64));
    }
    sqlx::query_scalar("select encode(chain_hash,'hex') from event where document_id=$1 and seq=$2")
        .bind(id)
        .bind(seq)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| bad("The starting revision does not exist"))
}
// JSON object keys are sorted by serde_json's default map representation. Persist
// the typed request: input whitespace/key order cannot cause duplicate proposals.
pub(crate) async fn prepare(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    actor: Uuid,
    input: &Push,
) -> Result<(Vec<u8>, Option<Value>), ApiError> {
    let b = &input.bundle;
    if b.format != "dynodoc.change-bundle"
        || b.version != 1
        || b.document_id != id
        || b.base_seq < 0
        || ![
            "word",
            "google-docs",
            "excel",
            "google-sheets",
            "powerpoint",
            "google-slides",
            "portable",
        ]
        .contains(&b.capture.host.as_str())
        || !["observed_snapshot", "imported"].contains(&b.capture.mode.as_str())
        || b.capture.document_name.chars().count() > 500
        || b.changes.is_empty()
        || b.changes.len() > 20_000
    {
        return Err(bad(
            "Invalid version, document, capture description or changes",
        ));
    }
    let mut ids = std::collections::HashSet::new();
    if b.changes.iter().any(|c| !ids.insert(c.id)) {
        return Err(bad("Change IDs must be unique inside a bundle"));
    }
    let body = serde_json::to_vec(&json!(input)).map_err(|e| ApiError::Internal(e.to_string()))?;
    let digest = sha256(&body);
    if let Some((previous_actor,previous_digest,receipt))=sqlx::query_as::<_,(Uuid,Vec<u8>,Value)>("select actor_id,digest,receipt from provenance_bundle where document_id=$1 and bundle_id=$2").bind(id).bind(b.bundle_id).fetch_optional(&mut **tx).await?{
        if previous_actor!=actor || previous_digest!=digest{return Err(ApiError::Conflict{reason:"This bundle ID was already used for a different upload".into()});}
        return Ok((digest,Some(receipt)));
    }
    if b.base_chain_hash != anchor(tx, id, b.base_seq).await? {
        return Err(ApiError::Conflict{reason:"The starting revision hash differs. Reconnect to the correct file; do not guess its history.".into()});
    }
    Ok((digest, None))
}
pub(crate) async fn record(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    actor: Uuid,
    draft: Uuid,
    input: &Push,
    digest: &[u8],
    receipt: &Value,
) -> Result<(), ApiError> {
    sqlx::query("insert into provenance_bundle(document_id,bundle_id,draft_id,actor_id,body,digest,receipt) values($1,$2,$3,$4,$5,$6,$7)")
        .bind(id).bind(input.bundle.bundle_id).bind(draft).bind(actor).bind(json!(input)).bind(digest).bind(receipt).execute(&mut **tx).await?;
    Ok(())
}
async fn propose(
    state: AppState,
    id: Uuid,
    auth: AuthContext,
    input: Push,
    credential: Option<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let req = reviews::CreateRequest {
        name: input.name.clone(),
        note: input.note.clone(),
        base_seq: input.bundle.base_seq,
        ops: input
            .bundle
            .changes
            .iter()
            .map(|c| c.operation.clone())
            .collect(),
        source: json!({"kind":"provenance","bundle_id":input.bundle.bundle_id,"host":input.bundle.capture.host,"capture_mode":input.bundle.capture.mode,"filename":input.bundle.capture.document_name}),
        submit: input.submit,
        provenance: Some(input),
        connector_grant: credential,
    };
    reviews::create(State(state), Path(id), auth, Json(req)).await
}
#[derive(Deserialize)]
struct CheckpointQuery {
    through_seq: Option<i64>,
}
async fn read_checkpoint(
    s: &AppState,
    id: Uuid,
    actor: Uuid,
    credential: Option<Uuid>,
    through_seq: Option<i64>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = s.pool.begin().await?;
    sqlx::query("select id from document where id=$1 for share")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    crate::projects::lock_document_project(&mut tx, id).await?;
    access::require_member(&mut tx, id, actor).await?;
    if let Some(grant) = credential {
        check_grant(&mut tx, grant, id, actor).await?;
    }
    let _budget = s.workloads.document(&mut tx, actor, id).await?;
    let (title, kind): (String, String) = sqlx::query_as(
        "select title,coalesce(settings->>'kind','questionnaire') from document where id=$1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let head: i64 =
        sqlx::query_scalar("select coalesce(max(seq),0) from event where document_id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let seq = through_seq.unwrap_or(head);
    if seq < 0 || seq > head {
        return Err(bad(
            "The requested checkpoint is outside this document's history",
        ));
    }
    let hash = anchor(&mut tx, id, seq).await?;
    let state = reviews::state_through(&mut tx, id, seq).await?;
    let proposals: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('id',d.id,'status',case when d.merged_at is not null then 'merged' when d.review_outcome is not null then d.review_outcome when d.submitted_at is null then 'draft' else 'open' end) from workspace_draft d where d.document_id=$1 and d.created_by=$2 and d.source->>'kind'='provenance' order by d.created_at desc limit 100")
        .bind(id).bind(actor).fetch_all(&mut *tx).await?;
    Ok(Json(
        json!({"format":"dynodoc.checkpoint","version":1,"document_id":id,"title":title,"kind":kind,"through_seq":seq,"chain_hash":hash,"state":state,"proposals":proposals}),
    ))
}
#[utoipa::path(get,path="/documents/{id}/provenance",params(("id"=Uuid,Path),("through_seq"=Option<i64>,Query,description="Historical canonical revision; omitted means current head")),security(("paseto"=[])),responses((status=200,description="Consistent full checkpoint with stable block IDs",body=Value),(status=400,description="Revision outside history")))]
async fn checkpoint(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    a: AuthContext,
    Query(query): Query<CheckpointQuery>,
) -> Result<Json<Value>, ApiError> {
    read_checkpoint(&s, id, a.identity_id, None, query.through_seq).await
}
#[utoipa::path(post,path="/documents/{id}/provenance",params(("id"=Uuid,Path)),request_body=Value,security(("paseto"=[])),responses((status=200,description="Durable idempotent review receipt",body=Value),(status=409,description="Wrong base or reused bundle ID")))]
async fn push(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    a: AuthContext,
    Json(p): Json<Push>,
) -> Result<Json<Value>, ApiError> {
    propose(s, id, a, p, None).await
}
#[utoipa::path(get,path="/documents/{id}/provenance/bundles/{bundle}",params(("id"=Uuid,Path),("bundle"=Uuid,Path)),security(("paseto"=[])),responses((status=200,description="Preserved upload and server attribution; private until submitted",body=Value)))]
async fn bundle(
    State(s): State<AppState>,
    Path((id, bundle)): Path<(Uuid, Uuid)>,
    a: AuthContext,
) -> Result<Json<Value>, ApiError> {
    let mut db = s.pool.acquire().await?;
    access::require_member(&mut db, id, a.identity_id).await?;
    let item:Value=sqlx::query_scalar("select jsonb_build_object('upload',b.body,'digest',encode(b.digest,'hex'),'uploaded_by',b.actor_id,'received_at',b.received_at,'receipt',b.receipt) from provenance_bundle b join workspace_draft d on d.id=b.draft_id where b.document_id=$1 and b.bundle_id=$2 and (d.submitted_at is not null or b.actor_id=$3)")
        .bind(id).bind(bundle).bind(a.identity_id).fetch_optional(&mut *db).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(item))
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct GrantInput {
    host: String,
    /// SHA-256 of a 256-bit secret held by the requesting editor. Never the secret.
    key_challenge: Option<String>,
    /// Approval link expiry as Unix seconds; ten minutes plus one minute clock allowance.
    expires_at: Option<i64>,
}
#[utoipa::path(post,path="/documents/{id}/connectors",params(("id"=Uuid,Path)),request_body=GrantInput,security(("paseto"=[])),responses((status=200,description="Seven-day file-scoped credential; pairing approval returns no secret",body=Value)))]
async fn grant(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    a: AuthContext,
    Json(p): Json<GrantInput>,
) -> Result<Json<Value>, ApiError> {
    let pairing_hash =
        match (&p.key_challenge, p.expires_at) {
            (None, None) => None,
            (Some(challenge), Some(expires))
                if challenge.len() == 64
                    && challenge
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                    && expires > Utc::now().timestamp()
                    && expires <= Utc::now().timestamp() + 660 =>
            {
                Some(hex::decode(challenge).map_err(|_| bad("Invalid connection challenge"))?)
            }
            _ => return Err(bad(
                "This connection link is invalid or expired. Start sign-in again in the editor.",
            )),
        };
    if ![
        "word",
        "google-docs",
        "excel",
        "google-sheets",
        "powerpoint",
        "google-slides",
    ]
    .contains(&p.host.as_str())
    {
        return Err(bad("Choose a supported Microsoft or Google editor"));
    }
    let mut tx = s.pool.begin().await?;
    let kind: String = sqlx::query_scalar(
        "select coalesce(settings->>'kind','questionnaire') from document where id=$1 for update",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    crate::projects::lock_document_project(&mut tx, id).await?;
    if access::require_member(&mut tx, id, a.identity_id).await? < MemberRole::Contributor {
        return Err(ApiError::Forbidden);
    }
    let expected = match p.host.as_str() {
        "word" | "google-docs" => "document",
        "excel" | "google-sheets" => "spreadsheet",
        _ => "presentation",
    };
    if kind != expected {
        return Err(bad("Choose a connection for this file format"));
    }
    if let Some(hash) = &pairing_hash {
        let existing: Option<Value> = sqlx::query_scalar("select jsonb_build_object('id',id,'expires_at',expires_at,'host',host) from connector_grant where token_hash=$1 and document_id=$2 and identity_id=$3 and host=$4 and session_generation=$5 and revoked_at is null and expires_at>now()")
            .bind(hash).bind(id).bind(a.identity_id).bind(&p.host).bind(a.session_generation).fetch_optional(&mut *tx).await?;
        if let Some(grant) = existing {
            return Ok(Json(json!({"grant":grant,"document_id":id})));
        }
    }
    let active:i64=sqlx::query_scalar("select count(*) from connector_grant where document_id=$1 and identity_id=$2 and revoked_at is null and expires_at>now()").bind(id).bind(a.identity_id).fetch_one(&mut *tx).await?;
    if active >= 10 {
        return Err(bad("Revoke an existing connection before creating another"));
    }
    let (token, hash) = if let Some(hash) = pairing_hash {
        (None, hash)
    } else {
        let (token, hash) = random_token()?;
        (Some(token), hash)
    };
    let item:Value=sqlx::query_scalar("insert into connector_grant(document_id,identity_id,token_hash,session_generation,host) values($1,$2,$3,$4,$5) on conflict(token_hash) do nothing returning jsonb_build_object('id',id,'expires_at',expires_at,'host',host)")
        .bind(id).bind(a.identity_id).bind(hash).bind(a.session_generation).bind(&p.host).fetch_optional(&mut *tx).await?
        .ok_or_else(|| ApiError::Conflict { reason: "This connection was already used. Start sign-in again in the editor.".into() })?;
    crate::product::audit(
        &mut tx,
        a.identity_id,
        "document.connector_created",
        id,
        json!({"grant_id":item["id"],"host":p.host}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"grant":item,"token":token,"document_id":id})))
}

/// Completion needs the editor's secret, not the public approval challenge.
#[utoipa::path(get,path="/connector/connection",security(("connector_key"=[])),responses((status=200,description="Approved file and host for this scoped credential",body=Value),(status=401,description="Not approved, expired or revoked")))]
async fn connection(State(s): State<AppState>, c: Connector) -> Result<Json<Value>, ApiError> {
    let mut tx = s.pool.begin().await?;
    sqlx::query("select id from document where id=$1 for share")
        .bind(c.document)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    crate::projects::lock_document_project(&mut tx, c.document).await?;
    if access::require_member(&mut tx, c.document, c.auth.identity_id).await?
        < MemberRole::Contributor
    {
        return Err(ApiError::Forbidden);
    }
    check_grant(&mut tx, c.grant, c.document, c.auth.identity_id).await?;
    Ok(Json(
        json!({"document_id":c.document,"host":c.host,"grant_id":c.grant}),
    ))
}
#[utoipa::path(get,path="/documents/{id}/connectors",params(("id"=Uuid,Path)),security(("paseto"=[])),responses((status=200,description="Caller connections; no credentials",body=Value)))]
async fn grants(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    a: AuthContext,
) -> Result<Json<Value>, ApiError> {
    let mut db = s.pool.acquire().await?;
    access::require_member(&mut db, id, a.identity_id).await?;
    let items:Vec<Value>=sqlx::query_scalar("select jsonb_build_object('id',id,'host',host,'created_at',created_at,'expires_at',expires_at,'revoked_at',revoked_at) from connector_grant where document_id=$1 and identity_id=$2 order by created_at desc limit 100").bind(id).bind(a.identity_id).fetch_all(&mut *db).await?;
    Ok(Json(json!({"items":items})))
}
#[utoipa::path(post,path="/documents/{id}/connectors/{grant}/revoke",params(("id"=Uuid,Path),("grant"=Uuid,Path)),security(("paseto"=[])),responses((status=200,description="Own connection revoked",body=Value)))]
async fn revoke(
    State(s): State<AppState>,
    Path((id, grant)): Path<(Uuid, Uuid)>,
    a: AuthContext,
) -> Result<Json<Value>, ApiError> {
    let mut tx = s.pool.begin().await?;
    sqlx::query("select id from document where id=$1 for update")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let changed=sqlx::query("update connector_grant set revoked_at=coalesce(revoked_at,now()) where id=$1 and document_id=$2 and identity_id=$3").bind(grant).bind(id).bind(a.identity_id).execute(&mut *tx).await?;
    if changed.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    crate::product::audit(
        &mut tx,
        a.identity_id,
        "document.connector_revoked",
        id,
        json!({"grant_id":grant}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"revoked":true})))
}
pub(crate) async fn check_grant(
    db: &mut PgConnection,
    grant: Uuid,
    doc: Uuid,
    actor: Uuid,
) -> Result<(), ApiError> {
    let valid:Option<Uuid>=sqlx::query_scalar("select g.id from connector_grant g join identity i on i.id=g.identity_id where g.id=$1 and g.document_id=$2 and g.identity_id=$3 and g.revoked_at is null and g.expires_at>now() and i.disabled_at is null and i.erased_at is null and i.session_generation=g.session_generation for share of g")
        .bind(grant).bind(doc).bind(actor).fetch_optional(db).await?;
    valid.ok_or(ApiError::Unauthorized)?;
    Ok(())
}
struct Connector {
    auth: AuthContext,
    document: Uuid,
    grant: Uuid,
    host: String,
}
impl FromRequestParts<AppState> for Connector {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|v| v.len() == 64)
            .ok_or(ApiError::Unauthorized)?;
        let (grant,document,identity,generation,host):(Uuid,Uuid,Uuid,i64,String)=sqlx::query_as("select g.id,g.document_id,g.identity_id,g.session_generation,g.host from connector_grant g join identity i on i.id=g.identity_id where g.token_hash=$1 and g.revoked_at is null and g.expires_at>now() and i.disabled_at is null and i.erased_at is null and i.session_generation=g.session_generation")
            .bind(sha256(token.as_bytes())).fetch_optional(&s.pool).await?.ok_or(ApiError::Unauthorized)?;
        Ok(Self {
            auth: AuthContext {
                identity_id: identity,
                session_generation: generation,
                session_id: None,
                device: None,
            },
            document,
            grant,
            host,
        })
    }
}
#[utoipa::path(get,path="/connector/documents/{id}/checkpoint",params(("id"=Uuid,Path),("through_seq"=Option<i64>,Query,description="Historical canonical revision; omitted means current head")),security(("connector_key"=[])),responses((status=200,description="File-scoped credential checkpoint",body=Value),(status=400,description="Revision outside history")))]
async fn connector_checkpoint(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: Connector,
    Query(query): Query<CheckpointQuery>,
) -> Result<Json<Value>, ApiError> {
    if c.document != id {
        return Err(ApiError::Forbidden);
    }
    read_checkpoint(&s, id, c.auth.identity_id, Some(c.grant), query.through_seq).await
}
#[utoipa::path(post,path="/connector/documents/{id}/bundles",params(("id"=Uuid,Path)),request_body=Value,security(("connector_key"=[])),responses((status=200,description="Scoped proposal; canonical history unchanged",body=Value)))]
async fn connector_push(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: Connector,
    Json(p): Json<Push>,
) -> Result<Json<Value>, ApiError> {
    if c.document != id || p.bundle.capture.host != c.host {
        return Err(ApiError::Forbidden);
    }
    propose(s, id, c.auth, p, Some(c.grant)).await
}
/// Largest single image a block may reference (decision 024). Below the 16 MiB request
/// limit of the API and of the web tier (BODY_SIZE_LIMIT), so the limit users see is this one.
const MEDIA_MAX_BYTES: usize = 15 * 1024 * 1024;
/// Images stored for one document across all its blocks.
const MEDIA_QUOTA_BYTES: i64 = 512 * 1024 * 1024;
/// The type is accepted only when the bytes start the way that format starts.
fn media_matches(content_type: &str, b: &[u8]) -> bool {
    match content_type {
        "image/png" => b.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => b.starts_with(&[0xFF, 0xD8, 0xFF]),
        "image/gif" => b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a"),
        "image/bmp" => b.starts_with(b"BM"),
        "image/tiff" => b.starts_with(b"II*\0") || b.starts_with(b"MM\0*"),
        "image/x-emf" => b.len() > 44 && b.starts_with(&[1, 0, 0, 0]) && &b[40..44] == b" EMF",
        "image/x-wmf" => {
            b.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A])
                || b.starts_with(&[1, 0, 9, 0])
                || b.starts_with(&[2, 0, 9, 0])
        }
        "image/svg+xml" => {
            let head = String::from_utf8_lossy(&b[..b.len().min(2048)]).to_ascii_lowercase();
            head.trim_start_matches('\u{feff}')
                .trim_start()
                .starts_with('<')
                && head.contains("<svg")
                && !head.contains("<!doctype")
                && !head.contains("<!entity")
        }
        _ => false,
    }
}
fn sha_hex(v: &str) -> Result<Vec<u8>, ApiError> {
    if v.len() != 64
        || !v
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(bad("Use a lowercase SHA-256 hex digest"));
    }
    hex::decode(v).map_err(|_| bad("Use a lowercase SHA-256 hex digest"))
}
/// Opens a scoped connector transaction: the credential's document, membership and
/// live grant, checked as the checkpoint read checks them.
async fn connector_tx(
    s: &AppState,
    c: &Connector,
    id: Uuid,
) -> Result<Transaction<'static, Postgres>, ApiError> {
    if c.document != id {
        return Err(ApiError::Forbidden);
    }
    let mut tx = s.pool.begin().await?;
    sqlx::query("select id from document where id=$1 for share")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    crate::projects::lock_document_project(&mut tx, id).await?;
    access::require_member(&mut tx, id, c.auth.identity_id).await?;
    check_grant(&mut tx, c.grant, id, c.auth.identity_id).await?;
    Ok(tx)
}
#[derive(Deserialize)]
struct ChangesQuery {
    since_seq: i64,
    /// Chain hash of `since_seq` as the client holds it; a different value means the
    /// client's base is not this document's history.
    since_chain_hash: String,
}
#[utoipa::path(get,path="/connector/documents/{id}/changes",params(("id"=Uuid,Path),("since_seq"=i64,Query,description="Revision the client holds"),("since_chain_hash"=String,Query,description="Chain hash of that revision as the client holds it")),security(("connector_key"=[])),responses((status=200,description="Only the blocks changed after since_seq, at the current head",body=Value),(status=409,description="The client's base is not this history")))]
async fn connector_changes(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: Connector,
    Query(q): Query<ChangesQuery>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = connector_tx(&s, &c, id).await?;
    let _budget = s
        .workloads
        .document(&mut tx, c.auth.identity_id, id)
        .await?;
    let head: i64 =
        sqlx::query_scalar("select coalesce(max(seq),0) from event where document_id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if q.since_seq < 0 || q.since_seq > head {
        return Err(bad(
            "The starting revision is outside this document's history",
        ));
    }
    if anchor(&mut tx, id, q.since_seq).await? != q.since_chain_hash {
        return Err(ApiError::Conflict {
            reason: "This file's starting revision is not part of this document's history. Reconnect it; do not guess.".into(),
        });
    }
    let changed: Vec<String> = sqlx::query_scalar("select distinct target_node_id from event where document_id=$1 and seq>$2 and target_node_id is not null")
        .bind(id)
        .bind(q.since_seq)
        .fetch_all(&mut *tx)
        .await?;
    let state = serde_json::to_value(reviews::state_through(&mut tx, id, head).await?)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let all = state
        .get("nodes")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let nodes: serde_json::Map<String, Value> = changed
        .into_iter()
        .filter_map(|n| all.get(&n).map(|v| (n, v.clone())))
        .collect();
    let hash = anchor(&mut tx, id, head).await?;
    let proposals: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('id',d.id,'status',case when d.merged_at is not null then 'merged' when d.review_outcome is not null then d.review_outcome when d.submitted_at is null then 'draft' else 'open' end) from workspace_draft d where d.document_id=$1 and d.created_by=$2 and d.source->>'kind'='provenance' order by d.created_at desc limit 100")
        .bind(id).bind(c.auth.identity_id).fetch_all(&mut *tx).await?;
    Ok(Json(
        json!({"format":"dynodoc.changes","version":1,"document_id":id,"since_seq":q.since_seq,"through_seq":head,"chain_hash":hash,"nodes":nodes,"proposals":proposals}),
    ))
}
#[utoipa::path(post,path="/connector/documents/{id}/media",params(("id"=Uuid,Path)),request_body(content=Vec<u8>,content_type="application/octet-stream"),security(("connector_key"=[])),responses((status=200,description="Stored once per document by SHA-256",body=Value),(status=400,description="Unsupported type, mismatched bytes, too large, or the document's image quota is used up")))]
async fn connector_media_put(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: Connector,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let content_type = headers
        .get("x-dynodoc-media-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if body.is_empty() || body.len() > MEDIA_MAX_BYTES || !media_matches(&content_type, &body) {
        return Err(bad("Use a PNG, JPEG, GIF, BMP, TIFF, EMF, WMF or SVG image up to 15 MB whose bytes match its type"));
    }
    let mut tx = connector_tx(&s, &c, id).await?;
    if access::require_member(&mut tx, id, c.auth.identity_id).await? < MemberRole::Contributor {
        return Err(ApiError::Forbidden);
    }
    let digest = sha256(&body);
    // One upload at a time per document, so concurrent uploads cannot both pass the quota.
    sqlx::query(
        "select pg_advisory_xact_lock(hashtextextended('connector_media:' || $1::text, 0))",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let exists: bool = sqlx::query_scalar(
        "select exists(select 1 from connector_media where document_id=$1 and sha256=$2)",
    )
    .bind(id)
    .bind(&digest)
    .fetch_one(&mut *tx)
    .await?;
    if !exists {
        let used: i64 = sqlx::query_scalar(
            "select coalesce(sum(size),0)::bigint from connector_media where document_id=$1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if used + body.len() as i64 > MEDIA_QUOTA_BYTES {
            return Err(bad("This document's images already use the 512 MB limit"));
        }
        sqlx::query("insert into connector_media(document_id,sha256,content_type,bytes,size,created_by) values($1,$2,$3,$4,$5,$6) on conflict do nothing")
            .bind(id).bind(&digest).bind(&content_type).bind(body.as_ref()).bind(body.len() as i32).bind(c.auth.identity_id)
            .execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(
        json!({"sha256":hex::encode(&digest),"size":body.len(),"stored":!exists}),
    ))
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct MissingInput {
    hashes: Vec<String>,
}
#[utoipa::path(post,path="/connector/documents/{id}/media/missing",params(("id"=Uuid,Path)),request_body=MissingInput,security(("connector_key"=[])),responses((status=200,description="The hashes this document does not store yet",body=Value)))]
async fn connector_media_missing(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: Connector,
    Json(p): Json<MissingInput>,
) -> Result<Json<Value>, ApiError> {
    if p.hashes.len() > 1000 {
        return Err(bad("Ask about at most 1,000 images at once"));
    }
    let wanted = p
        .hashes
        .iter()
        .map(|h| sha_hex(h))
        .collect::<Result<Vec<_>, _>>()?;
    let mut tx = connector_tx(&s, &c, id).await?;
    let have: Vec<Vec<u8>> = sqlx::query_scalar(
        "select sha256 from connector_media where document_id=$1 and sha256=any($2)",
    )
    .bind(id)
    .bind(&wanted)
    .fetch_all(&mut *tx)
    .await?;
    let missing: Vec<&String> = p
        .hashes
        .iter()
        .zip(&wanted)
        .filter(|(_, w)| !have.contains(w))
        .map(|(h, _)| h)
        .collect();
    Ok(Json(json!({"missing":missing})))
}
#[utoipa::path(get,path="/connector/documents/{id}/media/{sha}",params(("id"=Uuid,Path),("sha"=String,Path)),security(("connector_key"=[])),responses((status=200,description="Image bytes as an attachment; the type is in x-dynodoc-media-type")))]
async fn connector_media_get(
    State(s): State<AppState>,
    Path((id, sha)): Path<(Uuid, String)>,
    c: Connector,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    let digest = sha_hex(&sha)?;
    let mut tx = connector_tx(&s, &c, id).await?;
    let (content_type, bytes): (String, Vec<u8>) = sqlx::query_as(
        "select content_type,bytes from connector_media where document_id=$1 and sha256=$2",
    )
    .bind(id)
    .bind(&digest)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    // Never rendered by the browser: SVG and other images stay inert on this origin.
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, "attachment".to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (
                header::CONTENT_SECURITY_POLICY,
                "sandbox; default-src 'none'".to_string(),
            ),
            (
                header::CACHE_CONTROL,
                "private, max-age=31536000, immutable".to_string(),
            ),
            (
                header::HeaderName::from_static("x-dynodoc-media-type"),
                content_type,
            ),
        ],
        bytes,
    )
        .into_response())
}
#[utoipa::path(get,path="/connector/documents/{id}/nodes/{node}/history",params(("id"=Uuid,Path),("node"=String,Path)),security(("connector_key"=[])),responses((status=200,description="Newest first: each event of the block with who appended it and, for merged change requests, the contributor and message",body=Value)))]
async fn connector_node_history(
    State(s): State<AppState>,
    Path((id, node)): Path<(Uuid, String)>,
    c: Connector,
) -> Result<Json<Value>, ApiError> {
    if node.len() != 26 || !node.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(bad("Use a block identifier"));
    }
    let mut tx = connector_tx(&s, &c, id).await?;
    let items: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('seq',e.seq,'type',e.type,'at',e.created_at,'field',e.payload->>'field','actor',jsonb_build_object('id',i.id,'name',case when i.erased_at is null then i.display_name end),'request',(select jsonb_build_object('id',d.id,'name',d.name,'note',d.submission_note,'host',d.source->>'host','author',jsonb_build_object('id',au.id,'name',case when au.erased_at is null then au.display_name end),'agent',exists(select 1 from agent_identity ai where ai.identity_id=au.id)) from operation_audit a join workspace_draft d on d.id::text=a.detail->>'draft_id' and d.document_id=e.document_id join identity au on au.id=d.created_by where a.resource_id=e.document_id and a.action='document.change_request_merged' and a.detail->>'from_seq' ~ '^[0-9]{1,18}$' and a.detail->>'through_seq' ~ '^[0-9]{1,18}$' and (a.detail->>'from_seq')::bigint<=e.seq and (a.detail->>'through_seq')::bigint>=e.seq order by a.created_at limit 1)) from event e join identity i on i.id=e.actor_id where e.document_id=$1 and e.target_node_id=$2 order by e.seq desc limit 200")
        .bind(id)
        .bind(&node)
        .fetch_all(&mut *tx)
        .await?;
    Ok(Json(json!({"node_id":node,"events":items})))
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct ConnectorMergeInput {
    #[serde(default)]
    note: String,
}
#[utoipa::path(post,path="/connector/documents/{id}/requests/{draft}/merge",params(("id"=Uuid,Path),("draft"=Uuid,Path)),request_body=ConnectorMergeInput,security(("connector_key"=[])),responses((status=200,description="Merged through the same human-only rules as the web review"),(status=403,description="Not your request or not permitted"),(status=409,description="Overlapping team changes: resolve them in the review screens")))]
async fn connector_merge(
    State(s): State<AppState>,
    Path((id, draft)): Path<(Uuid, Uuid)>,
    c: Connector,
    Json(p): Json<ConnectorMergeInput>,
) -> Result<Json<Value>, ApiError> {
    let (team_seq, revision) = {
        let mut tx = connector_tx(&s, &c, id).await?;
        // The editor pane merges only the person's own, just-sent connector request;
        // reviewing other people's requests stays in the web review screens.
        let revision: Option<i64> = sqlx::query_scalar("select revision from workspace_draft where id=$1 and document_id=$2 and created_by=$3 and source->>'kind'='provenance'")
            .bind(draft)
            .bind(id)
            .bind(c.auth.identity_id)
            .fetch_optional(&mut *tx)
            .await?;
        let revision = revision.ok_or(ApiError::Forbidden)?;
        let head: i64 =
            sqlx::query_scalar("select coalesce(max(seq),0) from event where document_id=$1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        (head, revision)
    };
    // The same merge as the web review: approvals, merge roles, agent refusal and the
    // three-way plan (overlaps are refused, never auto-resolved) all apply.
    let request: reviews::MergeRequest =
        serde_json::from_value(json!({"team_seq":team_seq,"revision":revision,"note":p.note}))
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    reviews::merge(State(s), Path((id, draft)), c.auth, Json(request)).await
}
#[utoipa::path(post,path="/connector/documents/{id}/requests/{draft}/withdraw",params(("id"=Uuid,Path),("draft"=Uuid,Path)),request_body=ConnectorMergeInput,security(("connector_key"=[])),responses((status=200,description="The person's own connector request is closed as withdrawn and kept as history"),(status=403,description="Not your connector request"),(status=409,description="Already closed")))]
async fn connector_withdraw(
    State(s): State<AppState>,
    Path((id, draft)): Path<(Uuid, Uuid)>,
    c: Connector,
    Json(p): Json<ConnectorMergeInput>,
) -> Result<Json<Value>, ApiError> {
    {
        let mut tx = connector_tx(&s, &c, id).await?;
        let own: bool = sqlx::query_scalar("select exists(select 1 from workspace_draft where id=$1 and document_id=$2 and created_by=$3 and source->>'kind'='provenance')")
            .bind(draft)
            .bind(id)
            .bind(c.auth.identity_id)
            .fetch_one(&mut *tx)
            .await?;
        if !own {
            return Err(ApiError::Forbidden);
        }
    }
    reviews::close_request(&s, id, draft, &c.auth, "withdrawn", &p.note).await
}
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        checkpoint,
        push,
        bundle,
        grant,
        grants,
        revoke,
        connection,
        connector_checkpoint,
        connector_push,
        connector_changes,
        connector_media_put,
        connector_media_missing,
        connector_media_get,
        connector_node_history,
        connector_merge,
        connector_withdraw
    ),
    components(schemas(GrantInput, MissingInput, ConnectorMergeInput))
)]
pub struct ProvenanceApi;
