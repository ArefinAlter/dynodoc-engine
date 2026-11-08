//! Streaming server ingest of a large Word import (decision 034, design 8.2). The
//! worker reads the verified staged upload by range, inflates `word/document.xml`
//! through the bounded OOXML reader, and commits paragraphs in batches. Each batch
//! commits with the job cursor in one transaction: a crash resumes at the next
//! batch and never applies one twice. Memory is one staged chunk, one inflate window
//! and one batch, whatever the file size. The original is then kept as a
//! document-scoped content tree (part-aligned, decision 034) and the staging is freed.
//
// shortcut: runs inside the API process, one import at a time per process; move to
// a separate worker process with its own memory limit (design 12) before rung L3.
use crate::{error::ApiError, ops::apply, AppState};
use engine_core::governance::Role;
use engine_core::{
    log,
    ooxml::{
        docx::{Body, Paragraph},
        zip::{self, Source},
        OoxmlError,
    },
    shared_checkpoint::{
        content::{self, Chunker},
        postgres::PgStore,
        typed, Limits,
    },
    snapshot::{self, PeriodicStorage, SnapshotEngine},
};
use engine_shared::{DocumentId, EventPayload, IdentityId, NodeId, NodeType};
use serde_json::json;
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

/// Paragraphs per committed batch, and the text bytes that also end one.
const BATCH_PARAGRAPHS: usize = 2_000;
const BATCH_TEXT_BYTES: usize = 4 << 20;
/// Compressed bytes read per step.
const WINDOW: usize = 1 << 20;
const DOCX: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

static WORKER: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Run one job in the background; failures are recorded on the job.
pub(crate) fn spawn(state: AppState, job: Uuid) {
    tokio::spawn(async move {
        let Ok(_permit) = WORKER.acquire().await else {
            return;
        };
        if let Err(error) = run(&state, job).await {
            let reason = match &error {
                Failure::Package(OoxmlError::Source(_)) => {
                    "The staged file could not be read; the import can be retried".into()
                }
                Failure::Package(e) => e.to_string(),
                Failure::Api(ApiError::Forbidden) => "You can no longer edit this file".into(),
                Failure::Api(ApiError::BadRequest { reason } | ApiError::Conflict { reason }) => {
                    reason.clone()
                }
                Failure::Api(_) => "The import stopped on a server error; it can be retried".into(),
            };
            tracing::warn!(%job, %reason, "import failed");
            let _ = sqlx::query("update import_job set state='failed',error=left($2,500),updated_at=now() where id=$1 and state<>'done'")
                .bind(job)
                .bind(reason)
                .execute(&state.pool)
                .await;
        }
    });
}

/// Resume queued and interrupted jobs after a restart.
pub fn resume(state: AppState) {
    tokio::spawn(async move {
        let jobs: Vec<Uuid> = sqlx::query_scalar("select j.id from import_job j join upload_session u on u.id=j.upload_id where j.state in ('queued','running') and u.state='complete' order by j.created_at")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
        for job in jobs {
            spawn(state.clone(), job);
        }
    });
}

#[derive(Debug)]
enum Failure {
    Package(OoxmlError),
    Api(ApiError),
}
impl From<OoxmlError> for Failure {
    fn from(e: OoxmlError) -> Self {
        Self::Package(e)
    }
}
impl From<ApiError> for Failure {
    fn from(e: ApiError) -> Self {
        Self::Api(e)
    }
}
impl From<sqlx::Error> for Failure {
    fn from(e: sqlx::Error) -> Self {
        Self::Api(e.into())
    }
}

/// Random access to verified staged chunks; one chunk is resident.
struct Staged {
    pool: PgPool,
    upload: Uuid,
    size: u64,
    chunk: (u64, Vec<u8>),
}

impl Source for Staged {
    fn size(&self) -> u64 {
        self.size
    }
    async fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, OoxmlError> {
        if offset + len as u64 > self.size {
            return Err(OoxmlError::Zip("truncated package"));
        }
        let mut out = Vec::with_capacity(len);
        let mut at = offset;
        while out.len() < len {
            let (start, held) = (self.chunk.0, self.chunk.1.len() as u64);
            if at < start || at >= start + held {
                self.chunk = sqlx::query_as::<_, (i64, Vec<u8>)>("select at,bytes from upload_chunk where session_id=$1 and at<=$2 order by at desc limit 1")
                    .bind(self.upload)
                    .bind(at as i64)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| OoxmlError::Source(e.to_string()))?
                    .map(|(s, b)| (s as u64, b))
                    .ok_or(OoxmlError::Zip("staged chunk missing"))?;
                continue;
            }
            let from = (at - start) as usize;
            let take = (len - out.len()).min(held as usize - from);
            out.extend_from_slice(&self.chunk.1[from..from + take]);
            at += take as u64;
        }
        Ok(out)
    }
}

struct Job {
    document: Uuid,
    actor: Uuid,
    upload: Uuid,
    filename: String,
    cursor: i64,
    root: Option<String>,
    checkpoints: bool,
}

/// document, creator, upload, filename, cursor, root node, upload size
type JobRow = (Uuid, Uuid, Uuid, String, i64, Option<String>, i64);

async fn run(state: &AppState, id: Uuid) -> Result<(), Failure> {
    let row: Option<JobRow> = sqlx::query_as("update import_job j set state='running',updated_at=now() from upload_session u where j.id=$1 and u.id=j.upload_id and u.state='complete' and j.state in ('queued','running') returning j.document_id,j.created_by,j.upload_id,j.filename,j.cursor,j.root_node_id,u.size")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    let Some((document, actor, upload, filename, cursor, root, size)) = row else {
        return Ok(());
    };
    let mut job = Job {
        document,
        actor,
        upload,
        filename,
        cursor,
        root,
        checkpoints: true,
    };
    let mut source = Staged {
        pool: state.pool.clone(),
        upload,
        size: size as u64,
        chunk: (0, Vec::new()),
    };
    let entries = zip::central_directory(&mut source, zip::ZipLimits::default()).await?;
    let entry = entries
        .iter()
        .find(|e| e.name == "word/document.xml")
        .ok_or(ApiError::BadRequest {
            reason: "Server import reads Word documents (.docx) so far; import workbooks and presentations in the browser".into(),
        })?
        .clone();
    let start = zip::data_offset(&mut source, &entry).await?;
    let mut inflater = zip::Inflater::new(&entry);
    let mut body = Body::default();
    let (mut seen, mut batch, mut batch_bytes) = (0i64, Vec::new(), 0usize);
    let mut at = start;
    while inflater.remaining() > 0 {
        let piece = source
            .read_at(at, (inflater.remaining() as usize).min(WINDOW))
            .await?;
        at += piece.len() as u64;
        inflater.feed(&piece, &mut |data| body.feed(data, false))?;
        for p in body.take() {
            seen += 1;
            if seen <= job.cursor {
                continue; // committed before a restart
            }
            batch_bytes += p.text.len();
            batch.push(p);
            if batch.len() >= BATCH_PARAGRAPHS || batch_bytes >= BATCH_TEXT_BYTES {
                commit(state, id, &mut job, std::mem::take(&mut batch)).await?;
                batch_bytes = 0;
            }
        }
    }
    body.feed(&[], true)?;
    batch.extend(
        body.take()
            .into_iter()
            .skip((job.cursor - seen).max(0) as usize),
    );
    if !batch.is_empty() || job.root.is_none() {
        commit(state, id, &mut job, batch).await?;
    }
    checkpoint(state, DocumentId(job.document)).await;
    keep_original(state, id, &job, &entries).await
}

fn paragraph_op(parent: &NodeId, pos: i64, p: Paragraph) -> EventPayload {
    let id = NodeId(ulid::Ulid::generate().to_string());
    let content = if p.text.is_empty() {
        json!([])
    } else {
        json!([{"type":"text","text":p.text}])
    };
    let block = if p.level > 0 {
        json!({"type":"heading","attrs":{"blockId":id.0,"level":p.level},"content":content})
    } else {
        json!({"type":"paragraph","attrs":{"blockId":id.0},"content":content})
    };
    EventPayload::NodeCreated {
        node_id: id,
        node_type: NodeType::Item,
        parent_id: Some(parent.clone()),
        pos: format!("{pos:010}"),
        fields: json!({"label": p.text, "content": block}),
        var_name: None,
    }
}

/// Commit one batch and advance the cursor in the same transaction.
async fn commit(
    state: &AppState,
    id: Uuid,
    job: &mut Job,
    batch: Vec<Paragraph>,
) -> Result<(), Failure> {
    let doc = DocumentId(job.document);
    let actor = IdentityId(job.actor);
    let (mut tx, role) = apply::begin_write_locked(state, doc, actor).await?;
    if role != Role::Author {
        return Err(ApiError::Forbidden.into());
    }
    let cursor: i64 = sqlx::query_scalar(
        "select cursor from import_job where id=$1 and state='running' for update",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Conflict {
        reason: "The import was cancelled".into(),
    })?;
    if cursor != job.cursor {
        return Err(ApiError::Conflict {
            reason: "Another worker is running this import".into(),
        }
        .into());
    }
    let mut ops = Vec::with_capacity(batch.len() + 1);
    let root = match &job.root {
        Some(root) => NodeId(root.clone()),
        None => {
            let head: i64 =
                sqlx::query_scalar("select coalesce(max(seq),0) from event where document_id=$1")
                    .bind(job.document)
                    .fetch_one(&mut *tx)
                    .await?;
            if head != 0 {
                return Err(ApiError::BadRequest {
                    reason: "Import into an empty file".into(),
                }
                .into());
            }
            let root = NodeId(ulid::Ulid::generate().to_string());
            ops.push(EventPayload::NodeCreated {
                node_id: root.clone(),
                node_type: NodeType::Form,
                parent_id: None,
                pos: "000000".into(),
                fields: json!({"label": job.filename}),
                var_name: None,
            });
            root
        }
    };
    let count = batch.len() as i64;
    for (i, p) in batch.into_iter().enumerate() {
        ops.push(paragraph_op(&root, cursor + i as i64, p));
    }
    let (mut first, mut last) = (None, None);
    for op in &ops {
        apply::materialize_node_change(&mut tx, doc, op).await?;
        let event = log::append_in_tx(&mut tx, doc, op, actor)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        first.get_or_insert(event.seq);
        last = Some(event.seq);
    }
    sqlx::query("update import_job set cursor=cursor+$2,root_node_id=$3,first_seq=coalesce(first_seq,$4),through_seq=coalesce($5,through_seq),updated_at=now() where id=$1")
        .bind(id)
        .bind(count)
        .bind(&root.0)
        .bind(first)
        .bind(last)
        .execute(&mut *tx)
        .await?;
    sqlx::query("update document set updated_at=now() where id=$1")
        .bind(job.document)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    job.cursor += count;
    job.root = Some(root.0);
    // Changed-node checkpoints keep pace batch by batch (awaited, so the tail never
    // outgrows that path). A full-state writer would make the import quadratic, so it
    // checkpoints once at the end instead.
    if job.checkpoints && snapshot::periodic_storage() == PeriodicStorage::SharedV3 {
        job.checkpoints = checkpoint(state, doc).await;
    }
    Ok(())
}

/// Best effort, as after any append: the import's events are already committed.
/// `false` stops further per-batch attempts after a failure.
async fn checkpoint(state: &AppState, doc: DocumentId) -> bool {
    let result = SnapshotEngine::new(state.pool.clone())
        .with_periodic_storage(snapshot::periodic_storage())
        .ensure_recent(doc, snapshot::DEFAULT_MAX_EVENTS_IN_TAIL)
        .await;
    if let Err(error) = &result {
        tracing::warn!(document = %doc.0, %error, "import checkpoint failed");
    }
    result.is_ok()
}

/// Store the original as a part-aligned content tree with an asset manifest, then
/// free the staging. The tree is charged to the document's shared storage budget.
async fn keep_original(
    state: &AppState,
    id: Uuid,
    job: &Job,
    entries: &[zip::Entry],
) -> Result<(), Failure> {
    // Approximate part boundaries (a local header may carry extra bytes): they only
    // decide which chunks deduplicate, never what is stored.
    let mut boundaries: Vec<u64> = entries
        .iter()
        .flat_map(|e| {
            let data = e.header_offset + 30 + e.name.len() as u64;
            [e.header_offset, data, data + e.compressed]
        })
        .collect();
    boundaries.sort_unstable();
    let doc = DocumentId(job.document);
    let mut tx = state.pool.begin().await?;
    sqlx::query("set local statement_timeout='120s'")
        .execute(&mut *tx)
        .await?;
    let (mut writer, mut reader) = tokio::io::duplex(1 << 20);
    let pool = state.pool.clone();
    let upload = job.upload;
    let feed = async move {
        let mut at = 0i64;
        loop {
            let chunk: Option<Vec<u8>> =
                sqlx::query_scalar("select bytes from upload_chunk where session_id=$1 and at=$2")
                    .bind(upload)
                    .bind(at)
                    .fetch_optional(&pool)
                    .await
                    .map_err(std::io::Error::other)?;
            let Some(chunk) = chunk else { break };
            writer.write_all(&chunk).await?;
            at += chunk.len() as i64;
        }
        writer.shutdown().await
    };
    let limits = Limits {
        max_objects: 100_000,
        max_bytes: crate::uploads::IMPORT_CEILING_BYTES as usize * 2,
    };
    let store = async {
        let mut store = PgStore::new(&mut tx);
        let (root, _) = content::write_v2(
            &mut store,
            doc,
            &mut reader,
            &boundaries,
            Chunker::Fixed,
            limits,
        )
        .await?;
        typed::write_asset(&mut store, doc, &root, DOCX, limits).await
    };
    let (fed, stored) = tokio::join!(feed, store);
    fed.map_err(|e| ApiError::Internal(e.to_string()))?;
    let asset = stored.map_err(|e| match e {
        engine_core::shared_checkpoint::Error::Db(db) => ApiError::from(db),
        other => ApiError::Internal(other.to_string()),
    })?;
    sqlx::query("update import_job set state='done',original_root=$2,error=null,updated_at=now() where id=$1")
        .bind(id)
        .bind(asset.as_str())
        .execute(&mut *tx)
        .await?;
    sqlx::query("delete from upload_chunk where session_id=$1")
        .bind(job.upload)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.copy_index.wake();
    Ok(())
}
