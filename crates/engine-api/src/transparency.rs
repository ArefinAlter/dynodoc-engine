//! Transparency log service side (docs/DESIGN-WITNESSES-AND-TRANSPARENCY.md sections
//! 4.7 to 4.9, phases W1 and W5, decision 032).
//!
//! Off unless `DYNODOC_TRANSPARENCY_ORIGIN` names this installation's log. Then every
//! ref receipt and every shared horizon adds a blinded leaf to the outbox in its own
//! transaction, the log worker (`engine-cli transparency log-worker`, operator
//! credential) integrates them with [`integrate`], and these routes serve the log:
//! the cosigned checkpoint (public), tiles and entry bundles (any signed-in account:
//! a private log, decision 032), and for project readers the project's tag key, an
//! inclusion bundle for a receipt or horizon, and consistency proofs.
use crate::{
    auth::{
        device::{HistoryRead, ProjectAuth},
        AuthContext,
    },
    error::ApiError,
    project_staging::{authorize, bad, start},
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use engine_core::{
    shared_checkpoint::Address,
    transparency::{
        anchor, leaf::Leaf, merkle::Hash, note::NoteSignature, tiles, Checkpoint, Log,
        MemoryTileStore, Note, Origin, ProbeStore, Signer, TagKey, TileStore, VerifierKey,
    },
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// Leaves integrated per checkpoint (design 4.2 cadence: 1,000 pending or 10 s).
pub const BATCH: i64 = 1000;
const LEADER_LOCK: i64 = 0x7472_616e_7370; // "transp"

/// The configured log. Readers and the worker load only the tiles an operation reads
/// (decision 042), so memory does not grow with the log.
#[derive(Clone)]
pub struct Transparency {
    pub origin: Origin,
}

impl Transparency {
    /// From `DYNODOC_TRANSPARENCY_ORIGIN`; `Err` when it is set but not a valid origin.
    pub fn from_env() -> Result<Option<Self>, String> {
        match std::env::var("DYNODOC_TRANSPARENCY_ORIGIN") {
            Err(_) => Ok(None),
            Ok(value) => Origin::new(&value)
                .map(|origin| Some(Self::new(origin)))
                .map_err(|e| format!("DYNODOC_TRANSPARENCY_ORIGIN: {e}")),
        }
    }

    pub fn new(origin: Origin) -> Self {
        Self { origin }
    }

    pub fn origin_hash(&self) -> String {
        hex::encode(ring::digest::digest(
            &ring::digest::SHA256,
            self.origin.as_str().as_bytes(),
        ))
    }
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(error.to_string())
}

fn raw(address: &Address) -> Result<[u8; 32], ApiError> {
    hex::decode(address.as_str())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| internal("address"))
}

/// The project's blinding key, created on first use (32 random bytes).
async fn project_key(db: &mut PgConnection, project: Uuid) -> Result<TagKey, ApiError> {
    let mut fresh = [0u8; 32];
    SystemRandom::new()
        .fill(&mut fresh)
        .map_err(|_| internal("random"))?;
    sqlx::query("insert into transparency_project_key(project_id,tag_key) values($1,$2) on conflict do nothing")
        .bind(project)
        .bind(fresh.to_vec())
        .execute(&mut *db)
        .await?;
    let key: Vec<u8> =
        sqlx::query_scalar("select tag_key from transparency_project_key where project_id=$1")
            .bind(project)
            .fetch_one(&mut *db)
            .await?;
    Ok(TagKey::new(
        key.try_into().map_err(|_| internal("tag key"))?,
    ))
}

async fn enqueue(
    db: &mut PgConnection,
    kind: &str,
    leaf: &Leaf,
    project: Option<Uuid>,
    subject: Option<&Address>,
) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar("insert into transparency_outbox(leaf_type,leaf,project_id,subject) values($1,$2,$3,$4) returning seq")
        .bind(kind)
        .bind(leaf.data().map_err(internal)?)
        .bind(project)
        .bind(subject.map(Address::as_str))
        .fetch_one(db)
        .await?)
}

/// The `ref-receipt` leaf of a receipt issued in this transaction.
pub(crate) async fn enqueue_receipt(
    db: &mut PgConnection,
    state: &AppState,
    project: Uuid,
    branch: &str,
    generation: i64,
    receipt: &Address,
) -> Result<(), ApiError> {
    if state.transparency.is_none() {
        return Ok(());
    }
    let key = project_key(db, project).await?;
    let leaf = Leaf::RefReceipt {
        tag: key.ref_tag(branch, generation as u64),
        receipt: raw(receipt)?,
    };
    enqueue(db, "ref", &leaf, Some(project), Some(receipt)).await?;
    Ok(())
}

/// The `named-version` leaf of a project release created in this transaction (decision
/// 042): a project release names a project commit, so the tag's UUID is the project's.
pub(crate) async fn enqueue_release(
    db: &mut PgConnection,
    state: &AppState,
    project: Uuid,
    commit: &Address,
) -> Result<(), ApiError> {
    if state.transparency.is_none() {
        return Ok(());
    }
    let key = project_key(db, project).await?;
    let leaf = Leaf::NamedVersion {
        tag: key.version_tag(&project),
        version: raw(commit)?,
    };
    enqueue(db, "ver", &leaf, Some(project), Some(commit)).await?;
    Ok(())
}

/// The `history-horizon` leaf of a horizon created in this transaction.
pub(crate) async fn enqueue_horizon(
    db: &mut PgConnection,
    state: &AppState,
    project: Uuid,
    sequence: u64,
    horizon: &Address,
) -> Result<(), ApiError> {
    if state.transparency.is_none() {
        return Ok(());
    }
    let key = project_key(db, project).await?;
    let leaf = Leaf::HistoryHorizon {
        tag: key.horizon_tag(sequence),
        horizon: raw(horizon)?,
        seq: sequence,
    };
    enqueue(db, "hzn", &leaf, Some(project), Some(horizon)).await?;
    Ok(())
}

// ---- the log worker (operator credential) -------------------------------------

/// The log at `size` holding only the tiles `read` touches: `read` runs first against
/// placeholders ([`ProbeStore`]), then exactly those tile rows are fetched.
async fn log_for(
    db: &mut PgConnection,
    origin: &Origin,
    size: u64,
    read: impl FnOnce(&mut Log<ProbeStore>) -> Result<(), engine_core::transparency::Error>,
) -> anyhow::Result<Log<MemoryTileStore>> {
    let mut probe = Log::open(origin.clone(), ProbeStore::new(size))?;
    read(&mut probe)?;
    let wanted: Vec<String> = probe.store().wanted().into_iter().collect();
    let mut store = MemoryTileStore::new();
    let rows: Vec<(String, Vec<u8>)> =
        sqlx::query_as("select path,bytes from transparency_tile where path=any($1)")
            .bind(&wanted)
            .fetch_all(&mut *db)
            .await?;
    for (path, bytes) in rows {
        store.put(&path, &bytes)?;
    }
    store.set_size(size)?;
    Ok(Log::open(origin.clone(), store)?)
}

/// The latest checkpoint: `(size, root, note)`.
async fn latest(db: &mut PgConnection) -> anyhow::Result<Option<(u64, Vec<u8>, String)>> {
    let row: Option<(i64, Vec<u8>, String)> = sqlx::query_as(
        "select size,root,note from transparency_checkpoint order by size desc limit 1",
    )
    .fetch_optional(&mut *db)
    .await?;
    Ok(row.map(|(size, root, note)| (size as u64, root, note)))
}

/// RFC 6962 consistency proof between two checkpointed sizes, from the stored tiles.
pub async fn consistency_proof(
    pool: &PgPool,
    origin: &Origin,
    first: u64,
    second: u64,
) -> anyhow::Result<Vec<Hash>> {
    let mut db = pool.acquire().await?;
    let log = log_for(&mut db, origin, second, |l| {
        l.consistency_proof(first, second).map(drop)
    })
    .await?;
    Ok(log.consistency_proof(first, second)?)
}

/// One integration step: what changed, for witness submission.
pub struct Integrated {
    pub size: u64,
    pub root: Hash,
    pub old_size: u64,
    pub note: Note,
    pub leaves: u64,
}

/// Integrate up to [`BATCH`] pending outbox rows and sign a checkpoint, in one
/// transaction under the leader lock: leaf rows, new tiles and the checkpoint commit
/// together, so a crash leaves the previous checkpoint and every pending row as they
/// were. Returns `None` when nothing is pending (an empty interval signs nothing).
pub async fn integrate(
    pool: &PgPool,
    signer: &Signer,
    origin: &Origin,
) -> anyhow::Result<Option<Integrated>> {
    anyhow::ensure!(
        signer.verifier_key().name() == origin.as_str(),
        "the log key's name must be the origin"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(LEADER_LOCK)
        .execute(&mut *tx)
        .await?;
    let step = integrate_locked(&mut tx, signer, origin).await?;
    tx.commit().await?;
    Ok(step)
}

/// [`integrate`] inside a transaction that already holds the leader lock.
async fn integrate_locked(
    tx: &mut PgConnection,
    signer: &Signer,
    origin: &Origin,
) -> anyhow::Result<Option<Integrated>> {
    let pending: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "select o.seq,o.leaf from transparency_outbox o where not exists(select 1 from transparency_leaf l where l.outbox_seq=o.seq) order by o.seq limit $1",
    )
    .bind(BATCH)
    .fetch_all(&mut *tx)
    .await?;
    if pending.is_empty() {
        return Ok(None);
    }
    let leaves = pending
        .iter()
        .map(|(_, data)| Leaf::parse(data))
        .collect::<Result<Vec<_>, _>>()?;
    let previous = latest(&mut *tx).await?;
    let old_size = previous.as_ref().map_or(0, |p| p.0);
    let mut log = log_for(&mut *tx, origin, old_size, |l| {
        l.append_batch(&leaves).map(drop)
    })
    .await?;
    if let Some((_, root, _)) = &previous {
        anyhow::ensure!(
            log.root().as_slice() == root.as_slice(),
            "stored tiles do not reproduce the latest checkpoint root; refusing to sign"
        );
    }
    let before: std::collections::BTreeSet<String> = log.store().files().keys().cloned().collect();
    let first = log.append_batch(&leaves)?;
    for (i, (seq, _)) in pending.iter().enumerate() {
        sqlx::query("insert into transparency_leaf(leaf_index,outbox_seq) values($1,$2)")
            .bind((first + i as u64) as i64)
            .bind(seq)
            .execute(&mut *tx)
            .await?;
    }
    for (path, bytes) in log.store().files() {
        if !before.contains(path) {
            sqlx::query("insert into transparency_tile(path,bytes) values($1,$2)")
                .bind(path)
                .bind(bytes)
                .execute(&mut *tx)
                .await?;
        }
    }
    let note = log.signed_checkpoint(signer)?;
    sqlx::query("insert into transparency_checkpoint(size,root,note) values($1,$2,$3)")
        .bind(log.size() as i64)
        .bind(log.root().to_vec())
        .bind(note.encode())
        .execute(&mut *tx)
        .await?;
    Ok(Some(Integrated {
        size: log.size(),
        root: log.root(),
        old_size,
        note,
        leaves: pending.len() as u64,
    }))
}

/// Log key rotation (design 8): the first leaf the new key signs is a `log-successor`
/// naming the previous origin's last checkpoint, and the tree continues under the new
/// origin, so a verifier pinned to the old log checks consistency across the change.
/// Refused while leaves are pending (integrate them with the old key first) and when the
/// origin does not change. Witnesses bind origin and key; adding the new log to each
/// witness is a separate operator act.
pub async fn rotate_log(
    pool: &PgPool,
    signer: &Signer,
    origin: &Origin,
) -> anyhow::Result<Integrated> {
    anyhow::ensure!(
        signer.verifier_key().name() == origin.as_str(),
        "the new log key's name must be the new origin"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(LEADER_LOCK)
        .execute(&mut *tx)
        .await?;
    let pending: i64 = sqlx::query_scalar(
        "select count(*) from transparency_outbox o where not exists(select 1 from transparency_leaf l where l.outbox_seq=o.seq)",
    )
    .fetch_one(&mut *tx)
    .await?;
    anyhow::ensure!(
        pending == 0,
        "{pending} leaves are pending; run the log worker with the old key first"
    );
    let (size, root, note) = latest(&mut tx)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the log has no checkpoint to succeed"))?;
    let previous = Checkpoint::parse(Note::parse(note.as_bytes())?.text())?;
    anyhow::ensure!(
        previous.origin != origin.as_str(),
        "a successor needs a new origin (C2SP witnesses bind origin and key)"
    );
    let leaf = Leaf::LogSuccessor {
        prev_origin: Origin::new(&previous.origin)?,
        size,
        root: root
            .try_into()
            .map_err(|_| anyhow::anyhow!("checkpoint root"))?,
    };
    sqlx::query("insert into transparency_outbox(leaf_type,leaf) values('suc',$1)")
        .bind(leaf.data()?)
        .execute(&mut *tx)
        .await?;
    let step = integrate_locked(&mut tx, signer, origin)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the successor leaf was not integrated"))?;
    tx.commit().await?;
    Ok(step)
}

/// Store a witness's cosignature line for checkpoint `size` after verifying it under
/// the witness's key. A line that does not verify is refused, never stored.
pub async fn add_cosignature(
    pool: &PgPool,
    size: u64,
    witness: &VerifierKey,
    line: &str,
) -> anyhow::Result<()> {
    let note: String = sqlx::query_scalar("select note from transparency_checkpoint where size=$1")
        .bind(size as i64)
        .fetch_one(pool)
        .await?;
    let signature = NoteSignature::parse(line.trim_end_matches('\n'))?;
    let cosigned = Note::parse(note.as_bytes())?.with_signature(signature)?;
    anyhow::ensure!(
        cosigned.verify(witness)?.is_some(),
        "the witness answered a line that is not its own"
    );
    sqlx::query("insert into transparency_cosignature(size,witness,line) values($1,$2,$3) on conflict do nothing")
        .bind(size as i64)
        .bind(witness.name())
        .bind(line.trim_end_matches('\n'))
        .execute(pool)
        .await?;
    Ok(())
}

/// Anchor the event-chain heads of one completed hour (`interval_id` = Unix seconds
/// / 3600): the latest event of every document that changed in it. Idempotent: an
/// interval is anchored once. Returns the number of documents.
pub async fn anchor_interval(pool: &PgPool, interval_id: i64) -> anyhow::Result<u64> {
    let mut tx = pool.begin().await?;
    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(LEADER_LOCK)
        .execute(&mut *tx)
        .await?;
    let done: bool = sqlx::query_scalar(
        "select exists(select 1 from transparency_event_anchor where interval_id=$1)",
    )
    .bind(interval_id)
    .fetch_one(&mut *tx)
    .await?;
    if done {
        return Ok(0);
    }
    let installation: Uuid = sqlx::query_scalar("select id from device_authority where singleton")
        .fetch_one(&mut *tx)
        .await?;
    let rows: Vec<(Uuid, i64, Vec<u8>)> = sqlx::query_as(
        "select distinct on (document_id) document_id,seq,chain_hash from event
         where created_at>=to_timestamp($1*3600) and created_at<to_timestamp(($1+1)*3600)
         order by document_id,seq desc",
    )
    .bind(interval_id)
    .fetch_all(&mut *tx)
    .await?;
    let heads = rows
        .into_iter()
        .map(|(document, seq, chain_hash)| {
            Ok(anchor::Head {
                doc_tag: anchor::doc_tag(&installation, &document),
                seq: seq as u64,
                chain_hash: chain_hash
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("chain hash"))?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let root = anchor::root(&heads)?;
    let seq = if heads.is_empty() {
        None
    } else {
        let leaf = Leaf::EventHeads {
            root,
            count: heads.len() as u64,
            interval: interval_id as u64,
        };
        Some(
            sqlx::query_scalar::<_, i64>(
                "insert into transparency_outbox(leaf_type,leaf) values('evh',$1) returning seq",
            )
            .bind(leaf.data()?)
            .fetch_one(&mut *tx)
            .await?,
        )
    };
    sqlx::query("insert into transparency_event_anchor(interval_id,root,count,outbox_seq) values($1,$2,$3,$4)")
        .bind(interval_id)
        .bind(root.to_vec())
        .bind(heads.len() as i64)
        .bind(seq)
        .execute(&mut *tx)
        .await?;
    for head in &heads {
        sqlx::query("insert into transparency_event_heads(interval_id,doc_tag,seq,chain_hash) values($1,$2,$3,$4)")
            .bind(interval_id)
            .bind(head.doc_tag.to_vec())
            .bind(head.seq as i64)
            .bind(head.chain_hash.to_vec())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(heads.len() as u64)
}

/// What an auditor needs for one document of one anchored interval: the head, its
/// path to the anchor root, and the log leaf index of the `event-heads` leaf.
pub async fn anchor_proof(
    pool: &PgPool,
    interval_id: i64,
    document: Uuid,
) -> anyhow::Result<Value> {
    let installation: Uuid = sqlx::query_scalar("select id from device_authority where singleton")
        .fetch_one(pool)
        .await?;
    let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = sqlx::query_as(
        "select doc_tag,seq,chain_hash from transparency_event_heads where interval_id=$1",
    )
    .bind(interval_id)
    .fetch_all(pool)
    .await?;
    let heads = rows
        .into_iter()
        .map(|(tag, seq, chain)| {
            Ok(anchor::Head {
                doc_tag: tag.try_into().map_err(|_| anyhow::anyhow!("tag"))?,
                seq: seq as u64,
                chain_hash: chain
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("chain hash"))?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let proof = anchor::prove(&heads, &anchor::doc_tag(&installation, &document))?;
    let (root, leaf_index): (Vec<u8>, Option<i64>) = sqlx::query_as(
        "select a.root,l.leaf_index from transparency_event_anchor a left join transparency_leaf l on l.outbox_seq=a.outbox_seq where a.interval_id=$1",
    )
    .bind(interval_id)
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "format": "dynodoc.event-head-proof.v1",
        "document": document,
        "interval": interval_id,
        "root": hex::encode(root),
        "proof": proof,
        "leaf_index": leaf_index,
    }))
}

// ---- readers ----------------------------------------------------------------------

/// The latest checkpoint with every stored cosignature, and its tree size.
async fn current(db: &mut PgConnection) -> Result<(u64, Note), ApiError> {
    let latest: Option<(i64, String)> =
        sqlx::query_as("select size,note from transparency_checkpoint order by size desc limit 1")
            .fetch_optional(&mut *db)
            .await?;
    let (size, note) = latest.ok_or(ApiError::NotFound)?;
    let lines: Vec<String> = sqlx::query_scalar(
        "select line from transparency_cosignature where size=$1 order by witness",
    )
    .bind(size)
    .fetch_all(&mut *db)
    .await?;
    let mut note = Note::parse(note.as_bytes()).map_err(internal)?;
    for line in lines {
        note = note
            .with_signature(NoteSignature::parse(&line).map_err(internal)?)
            .map_err(internal)?;
    }
    Ok((size as u64, note))
}

fn configured(state: &AppState, origin_hash: &str) -> Result<Transparency, ApiError> {
    let transparency = state.transparency.clone().ok_or(ApiError::NotFound)?;
    if transparency.origin_hash() != origin_hash {
        return Err(ApiError::NotFound);
    }
    Ok(transparency)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/transparency/v1/{origin}/checkpoint", get(checkpoint))
        .route("/transparency/v1/{origin}/tile/{*path}", get(tile))
        .route("/projects/{id}/history/transparency-key", get(key))
        .route(
            "/projects/{id}/history/transparency/inclusion",
            get(inclusion),
        )
        .route(
            "/projects/{id}/history/transparency/consistency",
            get(consistency),
        )
}

/// C2SP checkpoint text with every cosignature: public by default (WT-Q1).
async fn checkpoint(
    State(state): State<AppState>,
    Path(origin): Path<String>,
) -> Result<Response, ApiError> {
    configured(&state, &origin)?;
    let mut db = state.pool.acquire().await?;
    let (_, note) = current(&mut db).await?;
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        note.encode(),
    )
        .into_response())
}

/// Tiles and entry bundles: a private log serves them to signed-in accounts only.
async fn tile(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path((origin, path)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    configured(&state, &origin)?;
    let bytes: Vec<u8> = sqlx::query_scalar("select bytes from transparency_tile where path=$1")
        .bind(format!("tile/{path}"))
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

#[utoipa::path(operation_id="project_history_transparency_key",get,path="/projects/{id}/history/transparency-key",tag="project history",params(("id"=Uuid,Path)),security(("paseto"=[]),("device_session"=["history:read"])),responses((status=200,description="The project's blinding key for its log leaves, the log origin and the current cosigned checkpoint",body=Value)))]
async fn key(
    State(state): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let transparency = state.transparency.clone().ok_or(ApiError::NotFound)?;
    let mut tx = start(&state, &auth).await?;
    authorize(&mut tx, &auth, id, &[], false).await?;
    let key: Option<Vec<u8>> =
        sqlx::query_scalar("select tag_key from transparency_project_key where project_id=$1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let checkpoint = match current(&mut tx).await {
        Ok((_, note)) => Some(note.encode()),
        Err(ApiError::NotFound) => None,
        Err(error) => return Err(error),
    };
    tx.commit().await?;
    Ok(Json(json!({
        "origin": transparency.origin.as_str(),
        "origin_hash": transparency.origin_hash(),
        "key": key.map(hex::encode),
        "checkpoint": checkpoint,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectQuery {
    subject: Address,
}

#[utoipa::path(operation_id="project_history_transparency_inclusion",get,path="/projects/{id}/history/transparency/inclusion",tag="project history",params(("id"=Uuid,Path),("subject"=String,Query)),security(("paseto"=[]),("device_session"=["history:read"])),responses((status=200,description="Inclusion bundle of a receipt or horizon leaf under the current cosigned checkpoint",body=Value),(status=404,description="Not logged, or `inclusion_pending` while the worker has not integrated it")))]
async fn inclusion(
    State(state): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path(id): Path<Uuid>,
    Query(query): Query<SubjectQuery>,
) -> Result<Json<Value>, ApiError> {
    let transparency = state.transparency.clone().ok_or(ApiError::NotFound)?;
    let mut tx = start(&state, &auth).await?;
    authorize(&mut tx, &auth, id, &[], false).await?;
    let row: Option<(i64, Option<i64>)> = sqlx::query_as(
        "select o.seq,l.leaf_index from transparency_outbox o left join transparency_leaf l on l.outbox_seq=o.seq where o.project_id=$1 and o.subject=$2 order by o.seq limit 1",
    )
    .bind(id)
    .bind(query.subject.as_str())
    .fetch_optional(&mut *tx)
    .await?;
    let index = match row {
        None => return Err(ApiError::NotFound),
        Some((_, None)) => {
            return Err(ApiError::Coded {
                status: StatusCode::NOT_FOUND,
                code: "inclusion_pending",
                reason: "The log worker has not integrated this leaf yet; retry later".into(),
                details: json!({}),
            })
        }
        Some((_, Some(index))) => index as u64,
    };
    let (size, note) = current(&mut tx).await?;
    if index >= size {
        return Err(ApiError::NotFound);
    }
    let width = tiles::TILE_WIDTH;
    let bundle_path =
        tiles::entry_bundle_path(index / width, (size - index / width * width).min(width));
    let log = log_for(&mut tx, &transparency.origin, size, |l| {
        l.store().get(&bundle_path)?;
        l.inclusion_proof(index, size).map(drop)
    })
    .await
    .map_err(internal)?;
    let bundle = log.bundle(index, &note).map_err(internal)?;
    tx.commit().await?;
    let value: Value = serde_json::from_slice(&bundle.to_json()).map_err(internal)?;
    Ok(Json(value))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsistencyQuery {
    first: u64,
    second: u64,
}

#[utoipa::path(operation_id="project_history_transparency_consistency",get,path="/projects/{id}/history/transparency/consistency",tag="project history",params(("id"=Uuid,Path),("first"=u64,Query),("second"=u64,Query)),security(("paseto"=[]),("device_session"=["history:read"])),responses((status=200,description="RFC 6962 consistency proof between two checkpointed sizes, hex hashes",body=Value)))]
async fn consistency(
    State(state): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path(id): Path<Uuid>,
    Query(query): Query<ConsistencyQuery>,
) -> Result<Json<Value>, ApiError> {
    let transparency = state.transparency.clone().ok_or(ApiError::NotFound)?;
    let mut tx = start(&state, &auth).await?;
    authorize(&mut tx, &auth, id, &[], false).await?;
    let (size, _) = current(&mut tx).await?;
    if query.first > query.second || query.second > size {
        return Err(bad(
            "Sizes must satisfy first <= second <= the current tree size",
        ));
    }
    let (first, second) = (query.first, query.second);
    let log = log_for(&mut tx, &transparency.origin, second, |l| {
        l.consistency_proof(first, second).map(drop)
    })
    .await
    .map_err(internal)?;
    let proof = log.consistency_proof(first, second).map_err(internal)?;
    tx.commit().await?;
    Ok(Json(json!({
        "first": query.first,
        "second": query.second,
        "proof": proof.iter().map(hex::encode).collect::<Vec<_>>(),
    })))
}
