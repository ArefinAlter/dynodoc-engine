//! The at-rest envelope store (Phase 0, decision 041): `checkpoint_object.bytes` of a project
//! with an active data key are written as `DYNOENC` envelopes and opened on read. Projects
//! without a data key, rows written before (legacy plaintext) and objects of encrypted
//! projects (`DYNOSEAL`, typed v4: already ciphertext under keys the service never holds) are
//! stored and read unchanged.
//!
//! Not end-to-end: the running service unwraps the data key and reads content (see the module
//! documentation of [`super`]).
//!
//! The process installs one [`AtRest`] at start-up ([`install`]); [`PgStore`] and every direct
//! reader of `checkpoint_object.bytes` go through [`seal_object`] and [`open_object`].
//! Envelopes are content-addressed ([`super::seal_content_addressed`]): the same object under
//! the same data key is the same bytes, so the store's byte comparison keeps deduplicating.
//!
//! shortcut: one process-wide configuration, not one per store; pass it through `AppState`
//! if a process ever needs two installations.
//!
//! [`PgStore`]: crate::shared_checkpoint::postgres::PgStore
use super::{
    has_magic, open, seal_content_addressed, Context, DataKey, DekCache, Header, KeyProvider,
    Purpose, WrapContext, Wrapped, DEFAULT_MAX_ENTRIES, DEFAULT_TTL,
};
use crate::shared_checkpoint::Error;
use sqlx::PgConnection;
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

pub const TABLE: &str = "checkpoint_object";
pub const COLUMN: &str = "bytes";

/// The provider, the installation every wrap context names, and the unwrapped-key cache.
pub struct AtRest {
    installation: Uuid,
    provider: Arc<dyn KeyProvider>,
    cache: DekCache,
}

impl std::fmt::Debug for AtRest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtRest")
            .field("installation", &self.installation)
            .field("provider", &self.provider.describe().provider)
            .finish_non_exhaustive()
    }
}

impl AtRest {
    pub fn new(installation: Uuid, provider: Arc<dyn KeyProvider>) -> Self {
        Self {
            installation,
            provider,
            cache: DekCache::new(DEFAULT_TTL, DEFAULT_MAX_ENTRIES),
        }
    }
    /// Drop expired keys; call from a timer so an idle process holds none.
    pub fn purge_expired(&self) -> usize {
        self.cache.purge_expired()
    }
}

static ACTIVE: OnceLock<AtRest> = OnceLock::new();

/// Install the process's at-rest configuration once; a second call is refused (`false`).
pub fn install(at_rest: AtRest) -> bool {
    ACTIVE.set(at_rest).is_ok()
}
pub fn active() -> Option<&'static AtRest> {
    ACTIVE.get()
}

/// Objects of encrypted projects are ciphertext already and keep their exact bytes (the
/// storage-boundary trigger of schema 95 accepts only them in sealed documents).
fn end_to_end_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(crate::e2ee::seal::MAGIC) || bytes.starts_with(crate::e2ee::state::MAGIC)
}

fn row_key(document: Uuid, address: &str) -> Vec<u8> {
    [document.as_bytes().as_slice(), address.as_bytes()].concat()
}

fn refused(what: &'static str) -> Error {
    // Never the provider's text: it may name a key or an endpoint.
    Error::Invalid(what)
}

/// The data key row `id`, unwrapped for the document's project. A row of another project does
/// not unwrap: the wrap context names the project.
async fn key(
    a: &'static AtRest,
    db: &mut PgConnection,
    document: Uuid,
    id: Option<i32>,
) -> Result<Option<Arc<DataKey>>, Error> {
    let row: Option<(i32, Option<Uuid>, i32, Vec<u8>)> = sqlx::query_as(
        "select k.id,k.project_id,k.kek_version,k.wrapped from data_key k
         where k.project_id=document_project($1) and (($2::int is null and k.state='active') or k.id=$2)",
    )
    .bind(document)
    .bind(id)
    .fetch_optional(db)
    .await?;
    let Some((id, project, version, wrapped)) = row else {
        return match id {
            None => Ok(None),
            Some(_) => Err(refused("at-rest data key missing")),
        };
    };
    let dek_id = u32::try_from(id).map_err(|_| refused("at-rest data key id"))?;
    if let Some(k) = a.cache.get(dek_id) {
        return Ok(Some(k));
    }
    let version = u32::try_from(version).map_err(|_| refused("at-rest key version"))?;
    let wrapped =
        Wrapped::new(version, wrapped).map_err(|_| refused("at-rest wrapped data key"))?;
    let ctx = WrapContext::new(a.installation, project, Purpose::Data);
    // Network providers block: unwrap off the async workers.
    let provider = a.provider.clone();
    let dek = tokio::task::spawn_blocking(move || provider.unwrap(&wrapped, &ctx))
        .await
        .map_err(|_| refused("at-rest key provider"))?
        .map_err(|_| refused("at-rest key provider refused the data key"))?;
    Ok(Some(a.cache.insert(DataKey::new(dek_id, version, dek))))
}

/// The bytes to store for `plain`: an envelope when the document's project has an active
/// data key, else `plain` unchanged.
pub async fn seal_object(
    db: &mut PgConnection,
    document: Uuid,
    address: &str,
    plain: &[u8],
) -> Result<Vec<u8>, Error> {
    let Some(a) = active() else {
        return Ok(plain.to_vec());
    };
    if end_to_end_sealed(plain) {
        return Ok(plain.to_vec());
    }
    let Some(k) = key(a, db, document, None).await? else {
        return Ok(plain.to_vec());
    };
    let row = row_key(document, address);
    let ctx = Context::new(a.installation, TABLE, COLUMN, &row)
        .map_err(|_| refused("at-rest context"))?;
    seal_content_addressed(&k, &ctx, document.as_bytes(), address.as_bytes(), plain)
        .map_err(|_| refused("at-rest seal"))
}

/// The object bytes of a stored value: opened when it is an envelope, else as stored.
pub async fn open_object(
    db: &mut PgConnection,
    document: Uuid,
    address: &str,
    stored: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    if !has_magic(&stored) {
        return Ok(stored);
    }
    let a = active().ok_or(refused(
        "an at-rest envelope needs the key provider configured",
    ))?;
    let header = Header::parse(&stored).map_err(|_| refused("at-rest envelope header"))?;
    let id = i32::try_from(header.dek_id).map_err(|_| refused("at-rest data key id"))?;
    let k = key(a, db, document, Some(id))
        .await?
        .ok_or(refused("at-rest data key missing"))?;
    let row = row_key(document, address);
    let ctx = Context::new(a.installation, TABLE, COLUMN, &row)
        .map_err(|_| refused("at-rest context"))?;
    open(&k, &ctx, &stored).map_err(|_| refused("at-rest envelope does not open"))
}

/// One step of the resumable backfill (migration M-c of existing rows): seal up to `limit`
/// plaintext objects of `project` after `(document, address)` in key order, each with a
/// compare-and-set on its old bytes. Returns the rows sealed and the position to resume from;
/// `None` when nothing is left. Rows already sealed, rows of encrypted projects and rows
/// another writer changed meanwhile are skipped, so a rerun from the start is also safe.
pub async fn backfill_step(
    db: &mut PgConnection,
    project: Uuid,
    after: Option<(Uuid, String)>,
    limit: i64,
) -> Result<(u64, Option<(Uuid, String)>), Error> {
    if active().is_none() {
        return Err(refused("configure the key provider first"));
    }
    let (doc, addr) = after.unwrap_or((Uuid::nil(), String::new()));
    let rows: Vec<(Uuid, String, Vec<u8>)> = sqlx::query_as(
        "select o.document_id,o.address,o.bytes from checkpoint_object o
         where document_project(o.document_id)=$1 and (o.document_id,o.address)>($2,$3)
         order by o.document_id,o.address limit $4",
    )
    .bind(project)
    .bind(doc)
    .bind(&addr)
    .bind(limit)
    .fetch_all(&mut *db)
    .await?;
    let next = rows.last().map(|(d, a, _)| (*d, a.clone()));
    let mut sealed = 0;
    for (document, address, bytes) in rows {
        if has_magic(&bytes) || end_to_end_sealed(&bytes) {
            continue;
        }
        let envelope = seal_object(db, document, &address, &bytes).await?;
        if envelope == bytes {
            // The project has no active data key.
            return Err(refused("the project has no active data key"));
        }
        sealed += sqlx::query(
            "update checkpoint_object set bytes=$3 where document_id=$1 and address=$2 and bytes=$4",
        )
        .bind(document)
        .bind(&address)
        .bind(&envelope)
        .bind(&bytes)
        .execute(&mut *db)
        .await?
        .rows_affected();
    }
    Ok((sealed, next))
}
