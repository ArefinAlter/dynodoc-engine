//! Resumable, hash-verified uploads (decision 034; tus 1.0.0 semantics with Dynodoc
//! authentication). A client creates a session with the size and SHA-256 of the whole
//! payload, appends chunks at the server's offset with each chunk's own SHA-256, reads
//! the offset back after a dropped connection, and completes: the server re-hashes
//! every staged byte before it uses any. Open sessions reserve quota when they are
//! created, under a lock, so concurrent uploads cannot overrun it. Editor panes upload
//! large images and long commits (connector key); people upload large imports (session).
use crate::{
    access::{self, MemberRole},
    auth::{sha256, AuthContext},
    error::ApiError,
    ops::apply,
    provenance::{self, Connector},
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use engine_core::governance::Role;
use engine_shared::{DocumentId, IdentityId};
use futures::TryStreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Chunk size clients should send.
pub const CHUNK_BYTES: usize = 4 << 20;
/// Largest chunk accepted (design section 7: resumable chunks of 4-16 MiB).
pub const MAX_CHUNK_BYTES: usize = 8 << 20;
/// Largest commit sent as an upload; it is parsed in memory once complete.
pub const BUNDLE_MAX_BYTES: i64 = 32 << 20;
/// Hard ceiling of the import limit (rung L5 of the limit ladder).
pub const IMPORT_CEILING_BYTES: i64 = 500 << 20;
/// Open sessions per person and per document (design section 7).
const OPEN_PER_IDENTITY: i64 = 4;
const OPEN_PER_DOCUMENT: i64 = 20;

/// The import limit: `DYNODOC_MAX_ORIGINAL_BYTES`, default the pilot cap. Raising it is
/// a rung of the limit ladder and needs a passing acceptance report (decision 034).
pub fn max_import_bytes() -> i64 {
    std::env::var("DYNODOC_MAX_ORIGINAL_BYTES")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .map_or(crate::workspace::MAX_UPLOAD_BYTES as i64, |v| {
            v.clamp(1, IMPORT_CEILING_BYTES)
        })
}

pub fn router() -> Router<AppState> {
    let chunk = axum::extract::DefaultBodyLimit::max(MAX_CHUNK_BYTES + 1024);
    Router::new()
        .route("/connector/documents/{id}/uploads", post(connector_create))
        .route(
            "/connector/documents/{id}/uploads/{upload}",
            get(connector_status),
        )
        .route(
            "/connector/documents/{id}/uploads/{upload}/chunks",
            post(connector_chunk).layer(chunk),
        )
        .route(
            "/connector/documents/{id}/uploads/{upload}/complete",
            post(connector_complete),
        )
        .route(
            "/connector/documents/{id}/uploads/{upload}/cancel",
            post(connector_cancel),
        )
        .route("/documents/{id}/imports", post(import_create))
        .route("/documents/{id}/imports/{upload}", get(import_status))
        .route(
            "/documents/{id}/imports/{upload}/chunks",
            post(import_chunk).layer(chunk),
        )
        .route(
            "/documents/{id}/imports/{upload}/complete",
            post(import_complete),
        )
        .route(
            "/documents/{id}/imports/{upload}/cancel",
            post(import_cancel),
        )
}

fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}

fn closed() -> ApiError {
    ApiError::Coded {
        status: StatusCode::GONE,
        code: "upload_closed",
        reason: "This upload expired or was cancelled. Start it again.".into(),
        details: Value::Null,
    }
}

const MEDIA_TYPES: [&str; 8] = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/bmp",
    "image/tiff",
    "image/x-emf",
    "image/x-wmf",
    "image/svg+xml",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInput {
    kind: String,
    size: i64,
    sha256: String,
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    filename: Option<String>,
}

#[derive(Deserialize)]
pub struct ChunkQuery {
    offset: i64,
}

async fn status_json(tx: &mut Transaction<'_, Postgres>, upload: Uuid) -> Result<Value, ApiError> {
    sqlx::query_scalar("select jsonb_build_object('id',id,'kind',kind,'size',size,'offset',received,'state',case when state='open' and expires_at<=now() then 'expired' else state end,'expires_at',expires_at,'chunk_bytes',$2::bigint,'max_chunk_bytes',$3::bigint,'result',result) from upload_session where id=$1")
        .bind(upload)
        .bind(CHUNK_BYTES as i64)
        .bind(MAX_CHUNK_BYTES as i64)
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
}

/// Create a session after the caller's access to `id` was checked.
async fn create(
    mut tx: Transaction<'static, Postgres>,
    actor: Uuid,
    id: Uuid,
    input: CreateInput,
    allowed: &[&str],
) -> Result<Json<Value>, ApiError> {
    if !allowed.contains(&input.kind.as_str()) {
        return Err(bad("This upload kind is not accepted here"));
    }
    let digest = provenance::sha_hex(&input.sha256)?;
    let limit = match input.kind.as_str() {
        "media" => provenance::MEDIA_MAX_BYTES as i64,
        "bundle" => BUNDLE_MAX_BYTES,
        _ => max_import_bytes(),
    };
    if input.size < 1 || input.size > limit {
        return Err(bad(&format!("This upload must be 1 to {limit} bytes")));
    }
    let media_type = match (input.kind.as_str(), input.media_type.as_deref()) {
        ("media", Some(t)) if MEDIA_TYPES.contains(&t) => Some(t.to_string()),
        ("media", _) => return Err(bad("Name the image type of a media upload")),
        (_, None) => None,
        _ => return Err(bad("Only media uploads have a media type")),
    };
    let filename = input.filename.unwrap_or_default();
    if input.kind == "import" && (filename.is_empty() || filename.len() > 255) {
        return Err(bad("Name the file being imported (at most 255 bytes)"));
    }
    // Serialize one person's creates: the open-session count cannot be raced.
    sqlx::query("select pg_advisory_xact_lock(hashtextextended('upload_session:' || $1::text, 0))")
        .bind(actor)
        .execute(&mut *tx)
        .await?;
    // Expired sessions, and created ones that never received a byte (a lost create),
    // stop holding quota.
    sqlx::query("delete from upload_session where created_by=$1 and state='open' and (expires_at<=now() or (received=0 and created_at<now()-interval '15 minutes')) and not exists (select 1 from import_job j where j.upload_id=upload_session.id)")
        .bind(actor)
        .execute(&mut *tx)
        .await?;
    let (mine, here): (i64, i64) = sqlx::query_as("select count(*) filter (where created_by=$1), count(*) filter (where document_id=$2) from upload_session where state='open' and expires_at>now() and (created_by=$1 or document_id=$2)")
        .bind(actor)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if mine >= OPEN_PER_IDENTITY || here >= OPEN_PER_DOCUMENT {
        return Err(ApiError::RateLimited { retry_after: 60 });
    }
    if input.kind == "media" {
        sqlx::query(
            "select pg_advisory_xact_lock(hashtextextended('connector_media:' || $1::text, 0))",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        if provenance::media_used(&mut tx, id, None).await? + input.size
            > provenance::MEDIA_QUOTA_BYTES
        {
            return Err(bad("This document's images already use the 512 MB limit"));
        }
    }
    let upload: Uuid = sqlx::query_scalar("insert into upload_session(document_id,created_by,kind,media_type,size,sha256,result) values($1,$2,$3,$4,$5,$6,null) returning id")
        .bind(id).bind(actor).bind(&input.kind).bind(&media_type).bind(input.size).bind(&digest)
        .fetch_one(&mut *tx).await?;
    if input.kind == "import" {
        sqlx::query("insert into import_job(upload_id,document_id,created_by,filename,state) values($1,$2,$3,$4,'queued')")
            .bind(upload).bind(id).bind(actor).bind(&filename)
            .execute(&mut *tx).await?;
        // Not runnable until complete: the worker only takes jobs of complete uploads.
    }
    let body = status_json(&mut tx, upload).await?;
    tx.commit().await?;
    Ok(Json(body))
}

/// kind, size, SHA-256, received, state, expired, media type
type SessionRow = (String, i64, Vec<u8>, i64, String, bool, Option<String>);

/// The session row, locked; only its creator may touch it.
async fn session(
    tx: &mut Transaction<'_, Postgres>,
    actor: Uuid,
    id: Uuid,
    upload: Uuid,
) -> Result<SessionRow, ApiError> {
    sqlx::query_as("select kind,size,sha256,received,state,expires_at<=now(),media_type from upload_session where id=$1 and document_id=$2 and created_by=$3 for update")
        .bind(upload)
        .bind(id)
        .bind(actor)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn chunk(
    mut tx: Transaction<'static, Postgres>,
    actor: Uuid,
    id: Uuid,
    upload: Uuid,
    offset: i64,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Json<Value>, ApiError> {
    let claimed = headers
        .get("x-dynodoc-chunk-sha256")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| bad("Send the chunk's SHA-256 in x-dynodoc-chunk-sha256"))?;
    let claimed = provenance::sha_hex(claimed)?;
    if body.is_empty() || body.len() > MAX_CHUNK_BYTES {
        return Err(bad("A chunk is 1 byte to 8 MiB"));
    }
    let (_, size, _, received, state, expired, _) = session(&mut tx, actor, id, upload).await?;
    if state != "open" || expired {
        return Err(closed());
    }
    if offset != received {
        return Err(ApiError::Coded {
            status: StatusCode::CONFLICT,
            code: "offset_mismatch",
            reason: "The upload is at a different offset; continue from it.".into(),
            details: json!({ "offset": received }),
        });
    }
    if received + body.len() as i64 > size {
        return Err(bad("This chunk goes past the declared size"));
    }
    // Trust boundary: the bytes must be the ones the client hashed.
    if sha256(body) != claimed {
        return Err(bad("The chunk does not match its SHA-256; send it again"));
    }
    sqlx::query("insert into upload_chunk(session_id,at,sha256,bytes) values($1,$2,$3,$4)")
        .bind(upload)
        .bind(offset)
        .bind(&claimed)
        .bind(body)
        .execute(&mut *tx)
        .await?;
    sqlx::query("update upload_session set received=received+$2 where id=$1")
        .bind(upload)
        .bind(body.len() as i64)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"offset": received + body.len() as i64, "size": size}),
    ))
}

/// Stream the staged chunks in order, re-hash them and return the payload when it is
/// at most `keep` bytes (media and commits); larger payloads are only verified.
async fn verify(
    tx: &mut Transaction<'_, Postgres>,
    upload: Uuid,
    size: i64,
    sha: &[u8],
    keep: i64,
) -> Result<Option<Vec<u8>>, ApiError> {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut kept = (size <= keep).then(|| Vec::with_capacity(size as usize));
    let mut expected = 0i64;
    let mut rows = sqlx::query_as::<_, (i64, Vec<u8>, Vec<u8>)>(
        "select at,sha256,bytes from upload_chunk where session_id=$1 order by at",
    )
    .bind(upload)
    .fetch(&mut **tx);
    while let Some((at, chunk_sha, bytes)) = rows.try_next().await? {
        if at != expected || sha256(&bytes) != chunk_sha {
            return Err(ApiError::Internal("staged upload is inconsistent".into()));
        }
        hash.update(&bytes);
        if let Some(kept) = kept.as_mut() {
            kept.extend_from_slice(&bytes);
        }
        expected += bytes.len() as i64;
    }
    if expected != size || hash.finish().as_ref() != sha {
        return Err(bad(
            "The uploaded file does not match its SHA-256. Start the upload again.",
        ));
    }
    Ok(kept)
}

/// What a connector upload produces once its bytes are verified.
enum Use<'a> {
    Connector(&'a AppState, Connector),
    Import(&'a AppState),
}

async fn complete(
    mut tx: Transaction<'static, Postgres>,
    actor: Uuid,
    id: Uuid,
    upload: Uuid,
    usage: Use<'_>,
) -> Result<Json<Value>, ApiError> {
    let (kind, size, sha, received, state, expired, media_type) =
        session(&mut tx, actor, id, upload).await?;
    if state == "complete" {
        // Idempotent: a client whose response was lost reads the same result.
        return Ok(Json(status_json(&mut tx, upload).await?));
    }
    if state != "open" || expired {
        return Err(closed());
    }
    if received != size {
        return Err(ApiError::Coded {
            status: StatusCode::CONFLICT,
            code: "upload_incomplete",
            reason: "Send the rest of the file first.".into(),
            details: json!({ "offset": received }),
        });
    }
    let result = match (kind.as_str(), usage) {
        ("media", Use::Connector(state, _)) => {
            let bytes = verify(&mut tx, upload, size, &sha, size)
                .await?
                .unwrap_or_default();
            let media_type = media_type.unwrap_or_default();
            if !provenance::media_matches(&media_type, &bytes) {
                return Err(bad("The image bytes do not match its type"));
            }
            provenance::store_media(
                &mut tx,
                &state.objects,
                id,
                actor,
                &media_type,
                &bytes,
                Some(upload),
            )
            .await?
        }
        ("bundle", Use::Connector(state, connector)) => {
            let bytes = verify(&mut tx, upload, size, &sha, size)
                .await?
                .unwrap_or_default();
            let push: provenance::Push = serde_json::from_slice(&bytes)
                .map_err(|_| bad("The uploaded commit is not a valid change bundle"))?;
            drop(bytes);
            // Release the row before proposing. A bundle ID proposes once: a retried
            // completion (lost response) returns the same receipt (provenance::prepare).
            tx.commit().await?;
            let receipt = provenance::connector_propose(state, id, connector, push).await?;
            let mut tx = state.pool.begin().await?;
            sqlx::query(
                "update upload_session set state='complete',result=$2 where id=$1 and state='open'",
            )
            .bind(upload)
            .bind(&receipt.0)
            .execute(&mut *tx)
            .await?;
            sqlx::query("delete from upload_chunk where session_id=$1")
                .bind(upload)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(receipt);
        }
        ("import", Use::Import(state)) => {
            verify(&mut tx, upload, size, &sha, 0).await?;
            let job: Uuid = sqlx::query_scalar("select id from import_job where upload_id=$1")
                .bind(upload)
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query("update upload_session set state='complete',result=$2,expires_at=now()+interval '7 days' where id=$1")
                .bind(upload)
                .bind(json!({"import_job": job}))
                .execute(&mut *tx)
                .await?;
            let body = status_json(&mut tx, upload).await?;
            tx.commit().await?;
            crate::ingest::spawn(state.clone(), job);
            return Ok(Json(body));
        }
        _ => return Err(ApiError::NotFound),
    };
    sqlx::query("update upload_session set state='complete',result=$2 where id=$1")
        .bind(upload)
        .bind(&result)
        .execute(&mut *tx)
        .await?;
    sqlx::query("delete from upload_chunk where session_id=$1")
        .bind(upload)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(result))
}

async fn cancel(
    mut tx: Transaction<'static, Postgres>,
    actor: Uuid,
    id: Uuid,
    upload: Uuid,
) -> Result<Json<Value>, ApiError> {
    let (.., state, _, _) = session(&mut tx, actor, id, upload).await?;
    if state == "complete" {
        return Err(ApiError::Conflict {
            reason: "This upload is already complete".into(),
        });
    }
    sqlx::query("update upload_session set state='cancelled' where id=$1")
        .bind(upload)
        .execute(&mut *tx)
        .await?;
    sqlx::query("delete from upload_chunk where session_id=$1")
        .bind(upload)
        .execute(&mut *tx)
        .await?;
    sqlx::query("update import_job set state='failed',error='Cancelled',updated_at=now() where upload_id=$1 and state='queued'")
        .bind(upload)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"id": upload, "state": "cancelled"})))
}

async fn connector_write_tx(
    s: &AppState,
    c: &Connector,
    id: Uuid,
) -> Result<Transaction<'static, Postgres>, ApiError> {
    let mut tx = provenance::connector_tx(s, c, id).await?;
    if access::require_member(&mut tx, id, c.auth.identity_id).await? < MemberRole::Contributor {
        return Err(ApiError::Forbidden);
    }
    Ok(tx)
}

async fn connector_create(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: Connector,
    Json(input): Json<CreateInput>,
) -> Result<Json<Value>, ApiError> {
    let tx = connector_write_tx(&s, &c, id).await?;
    create(tx, c.auth.identity_id, id, input, &["media", "bundle"]).await
}

async fn connector_status(
    State(s): State<AppState>,
    Path((id, upload)): Path<(Uuid, Uuid)>,
    c: Connector,
) -> Result<Json<Value>, ApiError> {
    let mut tx = provenance::connector_tx(&s, &c, id).await?;
    session(&mut tx, c.auth.identity_id, id, upload).await?;
    Ok(Json(status_json(&mut tx, upload).await?))
}

async fn connector_chunk(
    State(s): State<AppState>,
    Path((id, upload)): Path<(Uuid, Uuid)>,
    Query(q): Query<ChunkQuery>,
    c: Connector,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let tx = connector_write_tx(&s, &c, id).await?;
    chunk(
        tx,
        c.auth.identity_id,
        id,
        upload,
        q.offset,
        &headers,
        &body,
    )
    .await
}

async fn connector_complete(
    State(s): State<AppState>,
    Path((id, upload)): Path<(Uuid, Uuid)>,
    c: Connector,
) -> Result<Json<Value>, ApiError> {
    let tx = connector_write_tx(&s, &c, id).await?;
    let actor = c.auth.identity_id;
    complete(tx, actor, id, upload, Use::Connector(&s, c)).await
}

async fn connector_cancel(
    State(s): State<AppState>,
    Path((id, upload)): Path<(Uuid, Uuid)>,
    c: Connector,
) -> Result<Json<Value>, ApiError> {
    let tx = provenance::connector_tx(&s, &c, id).await?;
    cancel(tx, c.auth.identity_id, id, upload).await
}

/// Imports need the editing role, like the legacy upload.
async fn import_tx(
    s: &AppState,
    auth: &AuthContext,
    id: Uuid,
) -> Result<Transaction<'static, Postgres>, ApiError> {
    let role = apply::require_role(&s.pool, DocumentId(id), IdentityId(auth.identity_id)).await?;
    if role != Role::Author {
        return Err(ApiError::Forbidden);
    }
    Ok(s.pool.begin().await?)
}

async fn import_create(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AuthContext,
    Json(input): Json<CreateInput>,
) -> Result<Json<Value>, ApiError> {
    let tx = import_tx(&s, &auth, id).await?;
    create(tx, auth.identity_id, id, input, &["import"]).await
}

async fn import_status(
    State(s): State<AppState>,
    Path((id, upload)): Path<(Uuid, Uuid)>,
    auth: AuthContext,
) -> Result<Json<Value>, ApiError> {
    let mut tx = import_tx(&s, &auth, id).await?;
    session(&mut tx, auth.identity_id, id, upload).await?;
    let mut body = status_json(&mut tx, upload).await?;
    let job: Option<Value> = sqlx::query_scalar("select jsonb_build_object('id',id,'state',state,'paragraphs',cursor,'root_node_id',root_node_id,'through_seq',through_seq,'original_root',original_root,'error',error) from import_job where upload_id=$1")
        .bind(upload)
        .fetch_optional(&mut *tx)
        .await?;
    body["import"] = job.unwrap_or(Value::Null);
    Ok(Json(body))
}

async fn import_chunk(
    State(s): State<AppState>,
    Path((id, upload)): Path<(Uuid, Uuid)>,
    Query(q): Query<ChunkQuery>,
    auth: AuthContext,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let tx = import_tx(&s, &auth, id).await?;
    chunk(tx, auth.identity_id, id, upload, q.offset, &headers, &body).await
}

async fn import_complete(
    State(s): State<AppState>,
    Path((id, upload)): Path<(Uuid, Uuid)>,
    auth: AuthContext,
) -> Result<Json<Value>, ApiError> {
    let mut tx = import_tx(&s, &auth, id).await?;
    // Per-person ingest queue (design section 7): at most four waiting or running.
    let queued: i64 = sqlx::query_scalar("select count(*) from import_job j join upload_session u on u.id=j.upload_id where j.created_by=$1 and j.state in ('queued','running') and u.state='complete'")
        .bind(auth.identity_id)
        .fetch_one(&mut *tx)
        .await?;
    if queued >= 4 {
        return Err(ApiError::RateLimited { retry_after: 60 });
    }
    complete(tx, auth.identity_id, id, upload, Use::Import(&s)).await
}

async fn import_cancel(
    State(s): State<AppState>,
    Path((id, upload)): Path<(Uuid, Uuid)>,
    auth: AuthContext,
) -> Result<Json<Value>, ApiError> {
    let tx = import_tx(&s, &auth, id).await?;
    cancel(tx, auth.identity_id, id, upload).await
}
