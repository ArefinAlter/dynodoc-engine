//! Streaming egress (decision 034, design 8.3): a published v3 checkpoint as NDJSON
//! and the current document as .docx, written while they are read. Neither builds the
//! document in memory: the checkpoint walks its node map, the export streams node rows
//! in tree order from PostgreSQL into a data-descriptor zip. A dropped client stops
//! the work; one export at a time counts against the person's expensive-read budget.
use crate::{error::ApiError, ops::apply, AppState};
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::header,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use engine_core::{
    ooxml::{docx, zip::ZipWriter},
    shared_checkpoint::{postgres::PgStore, typed::NodeWalker, Address, Limits},
};
use engine_shared::{DocumentId, IdentityId};
use futures::TryStreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::auth::AuthContext;

/// Budget of one streamed walk: far above any accepted document, still finite.
const WALK_LIMITS: Limits = Limits {
    max_objects: 50_000_000,
    max_bytes: 64 << 30,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/documents/{id}/checkpoints/{seq}/nodes",
            get(checkpoint_nodes),
        )
        .route("/documents/{id}/export.docx", get(export_docx))
}

/// Bytes written to `writer` become the response body; the task stops when the
/// client goes away (the duplex reader is dropped and writes fail).
fn streamed(
    content_type: &'static str,
    disposition: Option<String>,
    run: impl FnOnce(tokio::io::DuplexStream) -> futures::future::BoxFuture<'static, ()>,
) -> Response {
    let (writer, reader) = tokio::io::duplex(256 * 1024);
    tokio::spawn(run(writer));
    let stream = futures::stream::unfold(reader, |mut reader| async move {
        let mut buf = vec![0u8; 64 * 1024];
        match reader.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<_, std::io::Error>(Bytes::from(buf)), reader))
            }
            Err(e) => Some((Err(e), reader)),
        }
    });
    let mut headers = vec![
        (header::CONTENT_TYPE, content_type.to_string()),
        (header::CACHE_CONTROL, "private, no-store".to_string()),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
    ];
    if let Some(d) = disposition {
        headers.push((header::CONTENT_DISPOSITION, d));
    }
    let mut response = Body::from_stream(stream).into_response();
    for (name, value) in headers {
        if let Ok(value) = value.parse() {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

async fn admit(
    state: &AppState,
    auth: &AuthContext,
    id: Uuid,
) -> Result<crate::workloads::ReadPermit, ApiError> {
    apply::require_role(&state.pool, DocumentId(id), IdentityId(auth.identity_id)).await?;
    let mut connection = state.pool.acquire().await?;
    state
        .workloads
        .document(&mut connection, auth.identity_id, id)
        .await
}

/// The nodes of the v3 checkpoint published at `seq`, one JSON object per line,
/// verified object by object. An error mid-stream ends the body early: clients
/// must check that the last line is the `{"end":...}` trailer.
async fn checkpoint_nodes(
    State(state): State<AppState>,
    Path((id, seq)): Path<(Uuid, i64)>,
    auth: AuthContext,
) -> Result<Response, ApiError> {
    let permit = admit(&state, &auth, id).await?;
    let mut tx = state.pool.begin().await?;
    let row: Option<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as("select c.state_root,c.event_chain_hash,e.chain_hash from shared_checkpoint c join event e on e.document_id=c.document_id and e.seq=c.through_seq where c.document_id=$1 and c.through_seq=$2 and c.codec_version=3")
        .bind(id)
        .bind(seq)
        .fetch_optional(&mut *tx)
        .await?;
    let (root, recorded, chain) = row.ok_or(ApiError::NotFound)?;
    if recorded != chain {
        return Err(ApiError::Internal("checkpoint chain position".into()));
    }
    let root = Address::try_from(root).map_err(|e| ApiError::Internal(e.to_string()))?;
    let document = DocumentId(id);
    Ok(streamed("application/x-ndjson", None, move |mut out| {
        Box::pin(async move {
            let _permit = permit;
            let result: Result<u64, String> = async {
                let mut store = PgStore::new(&mut tx);
                let mut walker = NodeWalker::new(&mut store, document, &root, WALK_LIMITS)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut count = 0u64;
                while let Some(node) = walker
                    .next(&mut store, document)
                    .await
                    .map_err(|e| e.to_string())?
                {
                    let mut line = serde_json::to_vec(&node).map_err(|e| e.to_string())?;
                    line.push(b'\n');
                    out.write_all(&line).await.map_err(|e| e.to_string())?;
                    count += 1;
                }
                Ok(count)
            }
            .await;
            match result {
                Ok(count) => {
                    let end = serde_json::json!({"end": {"through_seq": seq, "nodes": count}});
                    let _ = out.write_all(format!("{end}\n").as_bytes()).await;
                }
                Err(reason) => tracing::warn!(document=%id, %reason, "checkpoint stream stopped"),
            }
            let _ = out.shutdown().await;
        })
    }))
}

/// The current document as a Word package, paragraphs and headings only, streamed
/// in tree order. Spreadsheets and presentations are not streamed yet.
async fn export_docx(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AuthContext,
) -> Result<Response, ApiError> {
    let permit = admit(&state, &auth, id).await?;
    let (title, kind): (String, Option<String>) =
        sqlx::query_as("select title,settings->>'kind' from document where id=$1")
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
    if kind.as_deref().is_some_and(|k| k != "document") {
        return Err(ApiError::BadRequest {
            reason: "Streaming export writes Word documents so far".into(),
        });
    }
    let safe: String = title
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || " -_".contains(*c))
        .take(80)
        .collect();
    let filename = if safe.trim().is_empty() {
        "document".into()
    } else {
        safe
    };
    let pool = state.pool.clone();
    Ok(streamed(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some(format!("attachment; filename=\"{filename}.docx\"")),
        move |out| {
            Box::pin(async move {
                let _permit = permit;
                if let Err(reason) = write_docx(&pool, id, out).await {
                    tracing::warn!(document=%id, %reason, "export stream stopped");
                }
            })
        },
    ))
}

async fn write_docx(
    pool: &sqlx::PgPool,
    id: Uuid,
    out: tokio::io::DuplexStream,
) -> Result<(), String> {
    let err = |e: &dyn std::fmt::Display| e.to_string();
    let mut tx = pool.begin().await.map_err(|e| err(&e))?;
    // The rows stream as the client reads; a large file takes longer than the API's
    // default statement deadline. The transaction pins one snapshot of the document.
    sqlx::query("set local statement_timeout='30min'")
        .execute(&mut *tx)
        .await
        .map_err(|e| err(&e))?;
    let mut zip = ZipWriter::new(out);
    for (name, body) in [
        ("[Content_Types].xml", docx::CONTENT_TYPES),
        ("_rels/.rels", docx::PACKAGE_RELS),
    ] {
        zip.start(name, 6).await.map_err(|e| err(&e))?;
        zip.write(body.as_bytes()).await.map_err(|e| err(&e))?;
    }
    zip.start("word/document.xml", 6)
        .await
        .map_err(|e| err(&e))?;
    zip.write(docx::DOCUMENT_HEAD.as_bytes())
        .await
        .map_err(|e| err(&e))?;
    let mut rows = sqlx::query_as::<_, (Option<String>, Option<String>, Option<String>)>(
        "with recursive t(id,path,depth) as (
           select id,array[pos],0 from node where document_id=$1 and parent_id is null and not deleted
           union all
           select n.id,t.path||n.pos,t.depth+1 from node n join t on n.parent_id=t.id
           where n.document_id=$1 and not n.deleted and t.depth<64)
         select n.current_fields->>'label',n.current_fields->'content'->>'type',
                n.current_fields->'content'->'attrs'->>'level'
         from t join node n on n.id=t.id where t.depth>0 order by t.path",
    )
    .bind(id)
    .fetch(&mut *tx);
    let mut xml = String::new();
    while let Some((label, kind, level)) = rows.try_next().await.map_err(|e| err(&e))? {
        let level = match kind.as_deref() {
            Some("heading") => level.and_then(|l| l.parse().ok()).unwrap_or(1),
            _ => 0,
        };
        docx::paragraph_xml(label.as_deref().unwrap_or_default(), level, false, &mut xml);
        if xml.len() >= 64 * 1024 {
            zip.write(xml.as_bytes()).await.map_err(|e| err(&e))?;
            xml.clear();
        }
    }
    drop(rows);
    xml.push_str(docx::DOCUMENT_TAIL);
    zip.write(xml.as_bytes()).await.map_err(|e| err(&e))?;
    let (mut out, _) = zip.finish().await.map_err(|e| err(&e))?;
    out.shutdown().await.map_err(|e| err(&e))?;
    tx.commit().await.map_err(|e| err(&e))
}
