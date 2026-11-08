//! Draft, apply, verify, show and rehydrate history horizons on one local project
//! repository (docs/DESIGN-COMMIT-PRUNING.md phases P2 and P3, decision 032).
//!
//! An apply holds SQLite's writer lock for one transaction. Inside it the applier
//! upgrades schema 3 to 4 when this is the first horizon, recomputes the plan from the
//! rows it is about to change, and refuses unless the reviewed plan hash and the
//! signed record both describe exactly that plan (a record that releases anything the
//! policy does not select is refused: truncation outside policy). It then checks the
//! signatures (H2) and the archive, writes the horizon, skeleton, frontier and
//! released-state rows, deletes the released commit bodies and objects with the
//! immutability guards dropped and restored inside the same transaction (the
//! staged-object collector's technique), lowers the capacity counters, compares them
//! with a fresh recount (H9) and checks H1 to H8 before it commits. Any error rolls
//! all of it back, including the schema upgrade.
//!
//! Resumable batches (design 6.2 "for very large releases", decision 042): with
//! `horizon_apply_batched` the first transaction makes every check above, writes the
//! horizon rows and the list of released commits and objects still to delete
//! (`history_apply_pending`), and commits. Each later transaction deletes at most one
//! batch, lowers the counters by exactly that batch and records the running totals
//! (`history_apply_progress`); the last one compares the totals with the signed counts
//! and checks H1 to H9. A crash loses at most the batch in flight: calling the apply
//! again with the same envelope resumes. `horizon-verify` refuses while a release is
//! still in progress.
use super::{
    decode_commit,
    horizon_plan::{load_view, ObjectKey},
    pack, storage, LocalRepository, Store,
};
use crate::{
    repository::{
        horizon::{
            self,
            archive::{ArchiveReader, ArchiveWriter, Entry},
            plan::{self, HistoryView, HorizonPlan, PlanOptions},
            policy::{LoadOptions, Policy},
            Envelope, Error, FrontierEdge, HeadRef, HorizonRecord, HorizonRows, Retained, Scope,
            Signature, SkeletonEntry, StateKey, Usage,
        },
        Error as RepoError,
    },
    shared_checkpoint::{Address, ObjectStore},
};
use engine_shared::DocumentId;
use serde::Serialize;
use sqlx::{Connection, SqliteConnection};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};

pub const APPLY_FORMAT: &str = "dynodoc.horizon-apply.v1";
pub const VERIFY_FORMAT: &str = "dynodoc.horizon-verify.v1";
const HAS_HORIZONS: &str =
    "select exists(select 1 from sqlite_master where type='table' and name='history_horizon')";
const NOW_MS: &str = "cast(strftime('%s','now') as integer)*1000";

fn db(error: sqlx::Error) -> Error {
    RepoError::from(error).into()
}

async fn has_horizons(connection: &mut SqliteConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(HAS_HORIZONS).fetch_one(connection).await
}

fn parents_text(parents: &[Address]) -> String {
    parents.iter().map(Address::as_str).collect()
}

fn parse_parents(text: &str) -> Result<Vec<Address>, RepoError> {
    if !text.len().is_multiple_of(64) || text.len() > 128 {
        return Err(RepoError::Invalid("stored skeleton parents"));
    }
    (0..text.len() / 64)
        .map(|i| Ok(Address::try_from(text[i * 64..(i + 1) * 64].to_owned())?))
        .collect()
}

fn height_of(value: i64) -> Result<u64, RepoError> {
    u64::try_from(value).map_err(|_| RepoError::Invalid("stored skeleton height"))
}

// ---- readers (called from local.rs) -----------------------------------------

/// [`RepoError::HistoryPruned`] for an address a local horizon or a verified remote
/// horizon released; `None` when the address is unknown.
pub(super) async fn pruned(
    connection: &mut SqliteConnection,
    address: &Address,
) -> Result<Option<RepoError>, RepoError> {
    if !has_horizons(connection).await? {
        return Ok(None);
    }
    let row: Option<(String, i64, i64)> = sqlx::query_as(
        "select parents,height,horizon_sequence from history_skeleton where address=?1
         union all select parents,height,sequence from history_remote_skeleton where address=?1
         limit 1",
    )
    .bind(address.as_str())
    .fetch_optional(connection)
    .await?;
    row.map(|(parents, height, horizon)| {
        Ok(RepoError::HistoryPruned {
            address: address.clone(),
            horizon: height_of(horizon)?,
            parents: parse_parents(&parents)?,
            height: height_of(height)?,
        })
    })
    .transpose()
}

/// The horizon that released `(document, root)`, if one did.
pub(super) async fn released_state(
    connection: &mut SqliteConnection,
    document: DocumentId,
    root: &Address,
) -> Result<Option<u64>, RepoError> {
    if !has_horizons(connection).await? {
        return Ok(None);
    }
    let sequence: Option<i64> = sqlx::query_scalar(
        "select horizon_sequence from history_released_state where document=? and state_root=?",
    )
    .bind(document.0.to_string())
    .bind(root.as_str())
    .fetch_optional(connection)
    .await?;
    sequence.map(height_of).transpose()
}

/// Before a body is stored: a body a local horizon released comes back only through
/// `horizon-rehydrate` (H7); a body a remote horizon released replaces its cached
/// skeleton row, whose topology must match.
pub(super) async fn admit_released(
    connection: &mut SqliteConnection,
    address: &Address,
    height: i64,
) -> Result<(), RepoError> {
    if !has_horizons(connection).await? {
        return Ok(());
    }
    let local: bool =
        sqlx::query_scalar("select exists(select 1 from history_skeleton where address=?)")
            .bind(address.as_str())
            .fetch_one(&mut *connection)
            .await?;
    if local {
        return Err(RepoError::Invalid(
            "this commit was released by a local horizon; restore it with horizon-rehydrate",
        ));
    }
    let remote: Option<i64> =
        sqlx::query_scalar("select height from history_remote_skeleton where address=?")
            .bind(address.as_str())
            .fetch_optional(&mut *connection)
            .await?;
    if let Some(remote) = remote {
        if remote != height {
            return Err(RepoError::Invalid(
                "a remote skeleton height differs from the commit's own ancestry",
            ));
        }
        sqlx::query("delete from history_remote_skeleton where address=?")
            .bind(address.as_str())
            .execute(connection)
            .await?;
    }
    Ok(())
}

/// Skeleton entries (local and remote) and released states of earlier horizons.
pub(super) struct Prior {
    pub skeleton: Vec<SkeletonEntry>,
    pub remote: Vec<SkeletonEntry>,
    pub released: BTreeSet<StateKey>,
}

pub(super) async fn prior(connection: &mut SqliteConnection) -> Result<Prior, Error> {
    let mut prior = Prior {
        skeleton: Vec::new(),
        remote: Vec::new(),
        released: BTreeSet::new(),
    };
    if !has_horizons(connection).await.map_err(db)? {
        return Ok(prior);
    }
    let local: Vec<(String, String, i64)> =
        sqlx::query_as("select address,parents,height from history_skeleton order by address")
            .fetch_all(&mut *connection)
            .await
            .map_err(db)?;
    let remote: Vec<(String, String, i64)> = sqlx::query_as(
        "select address,parents,height from history_remote_skeleton order by address",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(db)?;
    for (rows, out) in [(local, &mut prior.skeleton), (remote, &mut prior.remote)] {
        for (address, parents, height) in rows {
            out.push(SkeletonEntry {
                address: Address::try_from(address)?,
                parents: parse_parents(&parents)?,
                height: height_of(height)?,
            });
        }
    }
    let states: Vec<(String, String)> =
        sqlx::query_as("select document,state_root from history_released_state")
            .fetch_all(&mut *connection)
            .await
            .map_err(db)?;
    for (document, root) in states {
        prior.released.insert(StateKey {
            document: uuid::Uuid::parse_str(&document)
                .map_err(|_| RepoError::Invalid("stored document id"))?,
            state_root: Address::try_from(root)?,
        });
    }
    Ok(prior)
}

// ---- reports ----------------------------------------------------------------

/// Rows and bytes one apply removed (logical bytes are what the limits charge).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Released {
    pub commits: u64,
    pub commit_bytes: u64,
    pub states: u64,
    pub objects: u64,
    pub object_bytes: u64,
    pub stored_object_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApplyReport {
    pub format: &'static str,
    pub project: uuid::Uuid,
    pub sequence: u64,
    pub address: Address,
    pub plan_hash: String,
    /// True only when this call released rows and committed.
    pub applied: bool,
    /// True when this exact envelope was applied before: nothing changed now.
    pub already_applied: bool,
    pub released: Released,
    pub capacity_before: super::StorageUsage,
    pub capacity_after: super::StorageUsage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    pub format: &'static str,
    pub project: uuid::Uuid,
    pub schema: i64,
    pub horizons: u64,
    pub rehydrated: u64,
    pub retained_commits: u64,
    pub skeleton_entries: u64,
    pub remote_skeleton_entries: u64,
    pub released_states: u64,
    /// Every check H1 to H9 passed; a failure is an error, never `false` here.
    pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StoredHorizon {
    pub sequence: u64,
    pub address: Address,
    pub record: HorizonRecord,
    pub signatures: Vec<Signature>,
    pub policy: serde_json::Value,
    pub rehydrated: bool,
    pub skeleton_rows: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RehydrateReport {
    pub project: uuid::Uuid,
    pub sequence: u64,
    pub commits: u64,
    pub objects: u64,
    pub archive_sha256: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemoteSkeletonReport {
    pub horizon: Address,
    pub sequence: u64,
    /// Entries stored now (commits this repository has no body for).
    pub stored: u64,
    /// Entries skipped because the body is already here.
    pub bodies_present: u64,
}

/// Points inside an apply where a test injects a crash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    Locked,
    Upgraded,
    Rows,
    Commits,
    Objects,
    Accounted,
    Verified,
}

pub(super) type Hook<'a> = dyn FnMut(Stage) -> Result<(), Error> + Send + 'a;

// ---- planning helpers --------------------------------------------------------

/// Objects reachable from a released state and from no other state a stored commit
/// keeps, in `(document, address)` order: exactly what the planner counted.
fn released_objects(
    view: &HistoryView,
    keys: &[ObjectKey],
    plan: &HorizonPlan,
    prior: &BTreeSet<StateKey>,
) -> Result<Vec<ObjectKey>, Error> {
    let index: HashMap<ObjectKey, u32> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (*k, i as u32))
        .collect();
    let key_of = |document: uuid::Uuid, root: &Address| (document.as_u128(), horizon::raw(root));
    let released: BTreeSet<&StateKey> = plan.sets.released_states.iter().collect();
    let objects = &view.objects;
    let mut reached = vec![false; objects.sizes.len()];
    let walk = |roots: Vec<u32>, reached: &mut Vec<bool>, out: Option<&mut Vec<u32>>| {
        let mut out = out;
        let mut stack = roots;
        while let Some(object) = stack.pop() {
            if std::mem::replace(&mut reached[object as usize], true) {
                continue;
            }
            if let Some(out) = out.as_deref_mut() {
                out.push(object);
            }
            stack.extend(objects.children[object as usize].iter().copied());
        }
    };
    let kept: Vec<u32> = view
        .state_keys()
        .into_iter()
        .filter(|(document, root)| {
            let state = StateKey {
                document: *document,
                state_root: root.clone(),
            };
            !released.contains(&state) && !prior.contains(&state)
        })
        .filter_map(|(document, root)| index.get(&key_of(document, &root)).copied())
        .collect();
    walk(kept, &mut reached, None);
    let roots: Vec<u32> = plan
        .sets
        .released_states
        .iter()
        .filter_map(|s| index.get(&key_of(s.document, &s.state_root)).copied())
        .collect();
    let mut found = Vec::new();
    walk(roots, &mut reached, Some(&mut found));
    let bytes: u64 = found.iter().map(|o| objects.sizes[*o as usize]).sum();
    if found.len() as u64 != plan.counts.objects_released
        || bytes != plan.counts.object_bytes_released
    {
        return Err(Error::Plan(
            "released objects differ from the plan's own count",
        ));
    }
    let mut out: Vec<ObjectKey> = found.into_iter().map(|o| keys[o as usize]).collect();
    out.sort_unstable();
    Ok(out)
}

fn object_address(key: &ObjectKey) -> (uuid::Uuid, Address) {
    (uuid::Uuid::from_u128(key.0), horizon::address_of(&key.1))
}

/// The next sequence and the address of the latest record.
async fn next_sequence(connection: &mut SqliteConnection) -> Result<(u64, Option<Address>), Error> {
    if !has_horizons(connection).await.map_err(db)? {
        return Ok((1, None));
    }
    let row: Option<(i64, String)> = sqlx::query_as(
        "select sequence,address from history_horizon order by sequence desc limit 1",
    )
    .fetch_optional(connection)
    .await
    .map_err(db)?;
    match row {
        None => Ok((1, None)),
        Some((sequence, address)) => {
            Ok((height_of(sequence)? + 1, Some(Address::try_from(address)?)))
        }
    }
}

async fn logical_object(
    connection: &mut SqliteConnection,
    key: &ObjectKey,
) -> Result<(Vec<u8>, u64), Error> {
    let (document, address) = object_address(key);
    let (stored, codec, size): (Vec<u8>, i64, Option<i64>) = sqlx::query_as(
        "select bytes,codec,size from objects where document=? and address=? and length(bytes)<=1048576",
    )
    .bind(document.to_string())
    .bind(address.as_str())
    .fetch_optional(&mut *connection)
    .await
    .map_err(db)?
    .ok_or(Error::Plan("a released object vanished"))?;
    let length = stored.len() as u64;
    Ok((pack::unpack(codec, stored, size)?, length))
}

async fn commit_body(
    connection: &mut SqliteConnection,
    address: &Address,
) -> Result<Vec<u8>, Error> {
    sqlx::query_scalar("select body from commits where address=?")
        .bind(address.as_str())
        .fetch_optional(connection)
        .await
        .map_err(db)?
        .ok_or(Error::Plan("a released commit vanished"))
}

/// Write the archive of exactly the released commits and objects.
async fn write_archive(
    connection: &mut SqliteConnection,
    path: &Path,
    project: uuid::Uuid,
    sequence: u64,
    plan: &HorizonPlan,
    objects: &[ObjectKey],
) -> Result<horizon::Archive, Error> {
    let mut writer = ArchiveWriter::create(path, project, sequence)?;
    for address in &plan.sets.released {
        let body = commit_body(&mut *connection, address).await?;
        writer.add_commit(address, &body)?;
    }
    for key in objects {
        let (bytes, _) = logical_object(&mut *connection, key).await?;
        let (document, address) = object_address(key);
        writer.add_object(document, &address, &bytes)?;
    }
    writer.finish()
}

/// The archive holds exactly the plan's released commits and objects, its trailer
/// matches, and its hash, length and counts are the ones the record signs.
fn check_archive(
    path: &Path,
    envelope: &Envelope,
    plan: &HorizonPlan,
    objects: &[ObjectKey],
) -> Result<(), Error> {
    let mut reader = ArchiveReader::open(path)?;
    if reader.project != envelope.horizon.project || reader.sequence != envelope.horizon.sequence {
        return Err(Error::Format("history archive belongs to another horizon"));
    }
    let mut commits = plan.sets.released.iter();
    let mut keys = objects.iter();
    while let Some(entry) = reader.next_entry()? {
        let expected = match &entry {
            Entry::Commit { address, .. } => commits.next() == Some(address),
            Entry::Object {
                document, address, ..
            } => keys
                .next()
                .is_some_and(|k| object_address(k) == (*document, address.clone())),
        };
        if !expected {
            return Err(Error::Format(
                "history archive content differs from the released history",
            ));
        }
    }
    if commits.next().is_some() || keys.next().is_some() {
        return Err(Error::Format("history archive lacks released history"));
    }
    if Some(reader.finish()?) != envelope.horizon.archive {
        return Err(Error::Format(
            "history archive differs from the horizon record",
        ));
    }
    Ok(())
}

// ---- verification -------------------------------------------------------------

struct Loaded {
    chain: Vec<Envelope>,
    policies: BTreeMap<Address, Policy>,
    rehydrated: BTreeSet<u64>,
}

async fn load_chain(connection: &mut SqliteConnection) -> Result<Loaded, Error> {
    let rows: Vec<(i64, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "select sequence,address,envelope,policy from history_horizon order by sequence",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(db)?;
    let mut loaded = Loaded {
        chain: Vec::new(),
        policies: BTreeMap::new(),
        rehydrated: BTreeSet::new(),
    };
    for (sequence, address, envelope, policy) in rows {
        let envelope = Envelope::from_bytes(&envelope)?;
        if envelope.horizon.address()?.as_str() != address
            || envelope.horizon.sequence != height_of(sequence)?
        {
            return Err(Error::Format(
                "stored horizon row differs from its envelope",
            ));
        }
        let policy = Policy::load(&policy, LoadOptions::default())
            .map_err(|_| Error::Format("stored horizon policy"))?;
        loaded.policies.insert(policy.hash(), policy);
        loaded.chain.push(envelope);
    }
    let rehydrated: Vec<i64> = sqlx::query_scalar("select sequence from history_rehydration")
        .fetch_all(&mut *connection)
        .await
        .map_err(db)?;
    for sequence in rehydrated {
        loaded.rehydrated.insert(height_of(sequence)?);
    }
    Ok(loaded)
}

/// H1 to H9 over the repository as it is, inside the caller's transaction.
/// The batch bookkeeping tables (decision 042), created on first use in a schema-4
/// repository. Older schema-4 binaries ignore them.
async fn ensure_batch_tables(connection: &mut SqliteConnection) -> Result<(), Error> {
    sqlx::raw_sql(
        "create table if not exists history_apply_progress(horizon_sequence integer primary key, commits integer not null default 0, commit_bytes integer not null default 0, objects integer not null default 0, object_bytes integer not null default 0, stored_object_bytes integer not null default 0, batches integer not null default 0);
         create table if not exists history_apply_pending(horizon_sequence integer not null, kind text not null check(kind in ('commit','object')), document text, address text not null, primary key(horizon_sequence,kind,document,address));",
    )
    .execute(&mut *connection)
    .await
    .map_err(db)?;
    Ok(())
}

async fn verify_in(
    connection: &mut SqliteConnection,
    project: uuid::Uuid,
) -> Result<VerifyReport, Error> {
    let batching: bool = sqlx::query_scalar(
        "select exists(select 1 from sqlite_master where type='table' and name='history_apply_progress')",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(db)?;
    if batching {
        let open: bool = sqlx::query_scalar("select exists(select 1 from history_apply_progress)")
            .fetch_one(&mut *connection)
            .await
            .map_err(db)?;
        if open {
            return Err(Error::Plan(
                "a batched horizon release is in progress; run horizon-apply --batch again to finish it",
            ));
        }
    }
    let schema: i64 = sqlx::query_scalar("select version from local_meta where singleton=1")
        .fetch_one(&mut *connection)
        .await
        .map_err(db)?;
    let horizons = has_horizons(connection).await.map_err(db)?;
    let loaded = if horizons {
        load_chain(connection).await?
    } else {
        Loaded {
            chain: Vec::new(),
            policies: BTreeMap::new(),
            rehydrated: BTreeSet::new(),
        }
    };
    if loaded
        .chain
        .first()
        .is_some_and(|e| e.horizon.project != project)
    {
        return Err(Error::Format("horizon of another project"));
    }
    horizon::validate_chain(&loaded.chain, Scope::Local, |policy| {
        loaded
            .policies
            .get(&policy.hash)
            .filter(|p| p.id == policy.id)
            .map(|p| p.signatures_required)
    })?;
    // Rows per horizon that was not rehydrated.
    let mut skeleton: BTreeMap<u64, Vec<SkeletonEntry>> = BTreeMap::new();
    let mut frontier: BTreeMap<u64, Vec<FrontierEdge>> = BTreeMap::new();
    let mut released: BTreeMap<u64, Vec<StateKey>> = BTreeMap::new();
    let mut remote = Vec::new();
    if horizons {
        let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
            "select address,parents,height,horizon_sequence from history_skeleton order by address",
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(db)?;
        for (address, parents, height, sequence) in rows {
            skeleton
                .entry(height_of(sequence)?)
                .or_default()
                .push(SkeletonEntry {
                    address: Address::try_from(address)?,
                    parents: parse_parents(&parents)?,
                    height: height_of(height)?,
                });
        }
        let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
            "select child,parent,parent_height,horizon_sequence from history_frontier",
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(db)?;
        for (child, parent, parent_height, sequence) in rows {
            frontier
                .entry(height_of(sequence)?)
                .or_default()
                .push(FrontierEdge {
                    child: Address::try_from(child)?,
                    parent: Address::try_from(parent)?,
                    parent_height: height_of(parent_height)?,
                });
        }
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            "select document,state_root,horizon_sequence from history_released_state",
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(db)?;
        for (document, root, sequence) in rows {
            released
                .entry(height_of(sequence)?)
                .or_default()
                .push(StateKey {
                    document: uuid::Uuid::parse_str(&document)
                        .map_err(|_| RepoError::Invalid("stored document id"))?,
                    state_root: Address::try_from(root)?,
                });
        }
        remote = prior(connection).await?.remote;
    }
    let live: Vec<&Envelope> = loaded
        .chain
        .iter()
        .filter(|e| !loaded.rehydrated.contains(&e.horizon.sequence))
        .collect();
    for sequence in skeleton
        .keys()
        .chain(frontier.keys())
        .chain(released.keys())
    {
        if !live.iter().any(|e| e.horizon.sequence == *sequence) {
            return Err(horizon::Error::Violated(
                horizon::Invariant::H5,
                format!("rows of horizon {sequence}, which is not a live horizon"),
            ));
        }
    }
    let empty: (Vec<SkeletonEntry>, Vec<FrontierEdge>, Vec<StateKey>) =
        (Vec::new(), Vec::new(), Vec::new());
    let rows: Vec<HorizonRows<'_>> = live
        .iter()
        .map(|e| {
            let sequence = e.horizon.sequence;
            HorizonRows {
                record: &e.horizon,
                skeleton: skeleton.get(&sequence).unwrap_or(&empty.0),
                frontier: frontier.get(&sequence).unwrap_or(&empty.1),
                released_states: released.get(&sequence).unwrap_or(&empty.2),
            }
        })
        .collect();
    // Retained bodies, their states and whether each state's root object is stored.
    let mut retained = Vec::new();
    let mut present = BTreeSet::new();
    let mut after = String::new();
    loop {
        let page: Vec<(String, Vec<u8>, i64)> = sqlx::query_as(
            "select address,body,height from commits where address>? order by address limit 64",
        )
        .bind(&after)
        .fetch_all(&mut *connection)
        .await
        .map_err(db)?;
        let Some(last) = page.last() else { break };
        after = last.0.clone();
        for (address, body, height) in page {
            let address = Address::try_from(address)?;
            let signed = decode_commit(&body, &address, project)?;
            let mut states = Vec::new();
            for file in signed.commit.files.values() {
                let state = StateKey {
                    document: file.document.0,
                    state_root: file.state.clone(),
                };
                // shortcut: presence is the root object's row, not the whole graph;
                // `repository verify` re-reads graphs when a full check is wanted.
                let stored: bool = sqlx::query_scalar(
                    "select exists(select 1 from objects where document=? and address=?)",
                )
                .bind(file.document.0.to_string())
                .bind(file.state.as_str())
                .fetch_one(&mut *connection)
                .await
                .map_err(db)?;
                if stored {
                    present.insert(state.clone());
                }
                states.push(state);
            }
            retained.push(Retained {
                address,
                parents: signed.commit.parents,
                height: height_of(height)?,
                states,
            });
        }
    }
    let heads: Vec<(String, String, i64)> =
        sqlx::query_as("select name,head,generation from refs order by name")
            .fetch_all(&mut *connection)
            .await
            .map_err(db)?;
    let heads = heads
        .into_iter()
        .map(|(branch, commit, generation)| {
            Ok(HeadRef {
                branch,
                commit: Address::try_from(commit)?,
                generation,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    horizon::check_state_with(&retained, &rows, &remote, &heads, &present)?;
    // H9: the persistent counters equal a recount of the rows.
    let usage = storage::usage(&mut *connection, schema).await?;
    let (objects, object_bytes): (i64, i64) = sqlx::query_as(if schema >= 3 {
        "select count(*),coalesce(sum(coalesce(size,length(bytes))),0) from objects"
    } else {
        "select count(*),coalesce(sum(length(bytes)),0) from objects"
    })
    .fetch_one(&mut *connection)
    .await
    .map_err(db)?;
    let (commits, commit_bytes): (i64, i64) =
        sqlx::query_as("select count(*),coalesce(sum(length(body)),0) from commits")
            .fetch_one(&mut *connection)
            .await
            .map_err(db)?;
    let recorded = Usage {
        commits: height_of(usage.commits_used)?,
        objects: height_of(usage.objects_used)?,
        bytes: height_of(usage.bytes_used)?,
    };
    horizon::check_counters(
        recorded,
        Usage {
            commits: height_of(commits)?,
            objects: height_of(objects)?,
            bytes: height_of(object_bytes + commit_bytes)?,
        },
    )?;
    Ok(VerifyReport {
        format: VERIFY_FORMAT,
        project,
        schema,
        horizons: loaded.chain.len() as u64,
        rehydrated: loaded.rehydrated.len() as u64,
        retained_commits: retained.len() as u64,
        skeleton_entries: skeleton.values().map(|v| v.len() as u64).sum(),
        remote_skeleton_entries: remote.len() as u64,
        released_states: released.values().map(|v| v.len() as u64).sum(),
        verified: true,
    })
}

/// Drop one immutability guard, run `body`, restore the guard exactly.
async fn without_guard(connection: &mut SqliteConnection, trigger: &str) -> Result<String, Error> {
    let guard: String =
        sqlx::query_scalar("select sql from sqlite_master where type='trigger' and name=?")
            .bind(trigger)
            .fetch_optional(&mut *connection)
            .await
            .map_err(db)?
            .ok_or(Error::Repository(format!(
                "immutability guard {trigger} is missing"
            )))?;
    sqlx::query(&format!("drop trigger {trigger}"))
        .execute(&mut *connection)
        .await
        .map_err(db)?;
    Ok(guard)
}

async fn restore_guard(
    connection: &mut SqliteConnection,
    trigger: &str,
    guard: &str,
) -> Result<(), Error> {
    sqlx::query(guard)
        .execute(&mut *connection)
        .await
        .map_err(db)?;
    let restored: Option<String> =
        sqlx::query_scalar("select sql from sqlite_master where type='trigger' and name=?")
            .bind(trigger)
            .fetch_optional(&mut *connection)
            .await
            .map_err(db)?;
    if restored.as_deref() != Some(guard) {
        return Err(Error::Repository(format!(
            "immutability guard {trigger} was not restored"
        )));
    }
    Ok(())
}

impl LocalRepository {
    async fn read_only_connection(&self) -> Result<SqliteConnection, Error> {
        SqliteConnection::connect_with(
            &self
                .options
                .clone()
                .create_if_missing(false)
                .pragma("query_only", "ON"),
        )
        .await
        .map_err(db)
    }

    /// The record a horizon for this exact plan would carry, without changing the
    /// repository. With `archive`, also writes the archive of the released history to
    /// that new file and records its hash. Each signer signs the returned record.
    pub async fn horizon_draft(
        &self,
        policy: &Policy,
        options: &PlanOptions,
        plan_hash: &str,
        created_at_ms: u64,
        archive: Option<&Path>,
    ) -> Result<HorizonRecord, Error> {
        if policy.archive.required && archive.is_none() {
            return Err(Error::Plan("the policy requires an archive"));
        }
        let mut connection = self.read_only_connection().await?;
        let result = async {
            let mut tx = connection.begin().await.map_err(db)?;
            let (view, keys) = load_view(&mut tx, self.project).await?;
            let plan = plan::plan(&view, policy, options)?;
            if plan.plan_hash != plan_hash.to_ascii_lowercase() {
                return Err(Error::Plan(
                    "plan hash differs from the repository now; run horizon-plan again",
                ));
            }
            let (sequence, previous) = next_sequence(&mut tx).await?;
            let mut record = plan.draft_record(sequence, previous, created_at_ms)?;
            if let Some(path) = archive {
                let prior = prior(&mut tx).await?;
                let objects = released_objects(&view, &keys, &plan, &prior.released)?;
                record.archive = Some(
                    write_archive(&mut tx, path, self.project, sequence, &plan, &objects).await?,
                );
                record.validate()?;
            }
            tx.rollback().await.map_err(db)?;
            Ok(record)
        }
        .await;
        let _ = connection.close().await;
        result
    }

    /// Apply a signed horizon: see the module documentation. `plan_hash` is the hash
    /// the operator reviewed; `archive` the file the record's `archive` names.
    pub async fn horizon_apply(
        &self,
        envelope: &Envelope,
        policy: &Policy,
        options: &PlanOptions,
        plan_hash: &str,
        archive: Option<&Path>,
    ) -> Result<ApplyReport, Error> {
        self.horizon_apply_with(
            envelope,
            policy,
            options,
            plan_hash,
            archive,
            None,
            &mut |_| Ok(()),
        )
        .await
    }

    /// [`Self::horizon_apply`] in resumable batches of at most `batch` deletions per
    /// transaction (module documentation). Calling it again after a crash resumes.
    pub async fn horizon_apply_batched(
        &self,
        envelope: &Envelope,
        policy: &Policy,
        options: &PlanOptions,
        plan_hash: &str,
        archive: Option<&Path>,
        batch: u64,
    ) -> Result<ApplyReport, Error> {
        self.horizon_apply_with(
            envelope,
            policy,
            options,
            plan_hash,
            archive,
            Some(batch.clamp(1, 1_000_000)),
            &mut |_| Ok(()),
        )
        .await
    }

    /// Delete the pending rows of horizon `sequence` one batch per transaction, then
    /// check the totals against the signed counts and every invariant.
    async fn release_batches(
        &self,
        sequence: u64,
        record: &HorizonRecord,
        batch: u64,
    ) -> Result<Released, Error> {
        loop {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
            let pending: Vec<(String, Option<String>, String)> = sqlx::query_as(
                "select kind,document,address from history_apply_pending where horizon_sequence=? order by kind,document,address limit ?",
            )
            .bind(sequence as i64)
            .bind(batch as i64)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
            let mut step = Released::default();
            let commits: Vec<&(String, Option<String>, String)> =
                pending.iter().filter(|p| p.0 == "commit").collect();
            if !commits.is_empty() {
                let guard = without_guard(&mut tx, "commits_no_delete").await?;
                for (_, _, address) in &commits {
                    let address = Address::try_from(address.clone())?;
                    let bytes = commit_body(&mut tx, &address).await?.len() as u64;
                    sqlx::query("delete from commits where address=?")
                        .bind(address.as_str())
                        .execute(&mut *tx)
                        .await
                        .map_err(db)?;
                    step.commits += 1;
                    step.commit_bytes += bytes;
                }
                restore_guard(&mut tx, "commits_no_delete", &guard).await?;
            }
            let objects: Vec<&(String, Option<String>, String)> =
                pending.iter().filter(|p| p.0 == "object").collect();
            if !objects.is_empty() {
                let guard = without_guard(&mut tx, "objects_no_delete").await?;
                for (_, document, address) in &objects {
                    let document =
                        uuid::Uuid::parse_str(document.as_deref().unwrap_or_default())
                            .map_err(|_| Error::Plan("a pending object names no document"))?;
                    let address = Address::try_from(address.clone())?;
                    let key = (document.as_u128(), horizon::raw(&address));
                    let (bytes, stored) = logical_object(&mut tx, &key).await?;
                    sqlx::query("delete from objects where document=? and address=?")
                        .bind(document.to_string())
                        .bind(address.as_str())
                        .execute(&mut *tx)
                        .await
                        .map_err(db)?;
                    step.objects += 1;
                    step.object_bytes += bytes.len() as u64;
                    step.stored_object_bytes += stored;
                }
                restore_guard(&mut tx, "objects_no_delete", &guard).await?;
            }
            for (kind, document, address) in &pending {
                sqlx::query("delete from history_apply_pending where horizon_sequence=? and kind=? and document is ? and address=?")
                    .bind(sequence as i64)
                    .bind(kind)
                    .bind(document)
                    .bind(address)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
            }
            let changed = sqlx::query(
                "update local_storage set bytes_used=bytes_used-?,stored_bytes=stored_bytes-?,objects_used=objects_used-?,commits_used=commits_used-? where singleton=1",
            )
            .bind((step.commit_bytes + step.object_bytes) as i64)
            .bind((step.commit_bytes + step.stored_object_bytes) as i64)
            .bind(step.objects as i64)
            .bind(step.commits as i64)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected();
            if changed != 1 {
                return Err(Error::Repository("capacity accounting row missing".into()));
            }
            sqlx::query("update history_apply_progress set commits=commits+?,commit_bytes=commit_bytes+?,objects=objects+?,object_bytes=object_bytes+?,stored_object_bytes=stored_object_bytes+?,batches=batches+1 where horizon_sequence=?")
                .bind(step.commits as i64)
                .bind(step.commit_bytes as i64)
                .bind(step.objects as i64)
                .bind(step.object_bytes as i64)
                .bind(step.stored_object_bytes as i64)
                .bind(sequence as i64)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            let left: i64 = sqlx::query_scalar(
                "select count(*) from history_apply_pending where horizon_sequence=?",
            )
            .bind(sequence as i64)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            if left > 0 {
                tx.commit().await.map_err(db)?;
                continue;
            }
            let (commits, commit_bytes, objects, object_bytes, stored_object_bytes, states): (
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
            ) = sqlx::query_as(
                "select commits,commit_bytes,objects,object_bytes,stored_object_bytes,(select count(*) from history_released_state where horizon_sequence=?) from history_apply_progress where horizon_sequence=?",
            )
            .bind(sequence as i64)
            .bind(sequence as i64)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            let total = Released {
                commits: commits as u64,
                commit_bytes: commit_bytes as u64,
                states: states as u64,
                objects: objects as u64,
                object_bytes: object_bytes as u64,
                stored_object_bytes: stored_object_bytes as u64,
            };
            if total.commits != record.counts.commits_released
                || total.commit_bytes != record.counts.commit_bytes_released
                || total.objects != record.counts.objects_released
                || total.object_bytes != record.counts.object_bytes_released
            {
                return Err(Error::Plan("released rows differ from the signed counts"));
            }
            sqlx::query("delete from history_apply_progress where horizon_sequence=?")
                .bind(sequence as i64)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            verify_in(&mut tx, self.project).await?;
            tx.commit().await.map_err(db)?;
            return Ok(total);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn horizon_apply_with(
        &self,
        envelope: &Envelope,
        policy: &Policy,
        options: &PlanOptions,
        plan_hash: &str,
        archive: Option<&Path>,
        batch: Option<u64>,
        hook: &mut Hook<'_>,
    ) -> Result<ApplyReport, Error> {
        let expected = plan_hash.to_ascii_lowercase();
        let record = &envelope.horizon;
        let address = record.address()?;
        let envelope_bytes = envelope.bytes()?;
        if record.project != self.project {
            return Err(Error::Format("horizon of another project"));
        }
        if record.policy != policy.policy_ref() {
            return Err(Error::Plan("the record names another policy"));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        hook(Stage::Locked)?;
        let query_only: i64 = sqlx::query_scalar("pragma query_only")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        if query_only != 0 {
            return Err(Error::Plan("horizon apply needs a writable repository"));
        }
        let schema: i64 = sqlx::query_scalar("select version from local_meta where singleton=1")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        if schema < storage::SCHEMA_VERSION {
            return Err(Error::Plan(
                "open the repository writable once to upgrade it first",
            ));
        }
        let before = storage::usage(&mut tx, schema).await?;
        if schema >= storage::HORIZON_SCHEMA_VERSION {
            let applied: bool =
                sqlx::query_scalar("select exists(select 1 from history_horizon where address=?)")
                    .bind(address.as_str())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db)?;
            if applied {
                ensure_batch_tables(&mut tx).await?;
                let in_progress: bool = sqlx::query_scalar(
                    "select exists(select 1 from history_apply_progress where horizon_sequence=?)",
                )
                .bind(record.sequence as i64)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
                if in_progress {
                    // Resume a batched release: the checks were made when it started.
                    tx.commit().await.map_err(db)?;
                    let released = self
                        .release_batches(record.sequence, record, batch.unwrap_or(4096))
                        .await?;
                    let after = self.storage_usage().await?;
                    return Ok(ApplyReport {
                        format: APPLY_FORMAT,
                        project: self.project,
                        sequence: record.sequence,
                        address,
                        plan_hash: expected,
                        applied: true,
                        already_applied: false,
                        released,
                        capacity_before: before,
                        capacity_after: after,
                    });
                }
                return Ok(ApplyReport {
                    format: APPLY_FORMAT,
                    project: self.project,
                    sequence: record.sequence,
                    address,
                    plan_hash: expected,
                    applied: false,
                    already_applied: true,
                    released: Released::default(),
                    capacity_before: before.clone(),
                    capacity_after: before,
                });
            }
        } else {
            storage::upgrade_horizons(&mut tx).await?;
        }
        hook(Stage::Upgraded)?;

        // The plan, recomputed from the rows this transaction will change.
        let (view, keys) = load_view(&mut tx, self.project).await?;
        let plan = plan::plan(&view, policy, options)?;
        if plan.plan_hash != expected {
            return Err(Error::Plan(
                "plan hash differs from the repository now (a branch moved or history changed); run horizon-plan again",
            ));
        }
        let (sequence, previous) = next_sequence(&mut tx).await?;
        let mut draft = plan.draft_record(sequence, previous, record.created_at_ms)?;
        draft.archive = record.archive.clone();
        if &draft != record {
            return Err(Error::Plan(
                "the signed record does not describe this plan; refusing to release history outside the policy",
            ));
        }
        envelope.verify(Scope::Local, policy.signatures_required)?;
        let prior = prior(&mut tx).await?;
        let objects = released_objects(&view, &keys, &plan, &prior.released)?;
        match (&record.archive, archive) {
            (Some(_), Some(path)) => check_archive(path, envelope, &plan, &objects)?,
            (Some(_), None) => return Err(Error::Plan("the record names an archive; supply it")),
            (None, Some(_)) => return Err(Error::Plan("the record names no archive")),
            (None, None) if policy.archive.required => {
                return Err(Error::Plan("the policy requires an archive"))
            }
            (None, None) => {}
        }

        // Rows: horizon, skeleton, frontier, released states.
        sqlx::query(&format!(
            "insert into history_horizon(sequence,address,envelope,policy,applied_wall_ms) values(?,?,?,?,{NOW_MS})"
        ))
        .bind(sequence as i64)
        .bind(address.as_str())
        .bind(&envelope_bytes)
        .bind(policy.canonical_bytes())
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        for entry in &plan.sets.skeleton {
            sqlx::query("insert into history_skeleton(address,parents,height,horizon_sequence) values(?,?,?,?)")
                .bind(entry.address.as_str())
                .bind(parents_text(&entry.parents))
                .bind(entry.height as i64)
                .bind(sequence as i64)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        for edge in &plan.sets.frontier {
            sqlx::query("insert into history_frontier(child,parent,parent_height,horizon_sequence) values(?,?,?,?)")
                .bind(edge.child.as_str())
                .bind(edge.parent.as_str())
                .bind(edge.parent_height as i64)
                .bind(sequence as i64)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        for state in &plan.sets.released_states {
            sqlx::query("insert into history_released_state(document,state_root,horizon_sequence) values(?,?,?)")
                .bind(state.document.to_string())
                .bind(state.state_root.as_str())
                .bind(sequence as i64)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        hook(Stage::Rows)?;
        if let Some(batch) = batch {
            // Record what is left to delete, commit, and release it batch by batch.
            ensure_batch_tables(&mut tx).await?;
            sqlx::query("insert into history_apply_progress(horizon_sequence) values(?)")
                .bind(sequence as i64)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            for address in &plan.sets.released {
                sqlx::query("insert into history_apply_pending(horizon_sequence,kind,document,address) values(?,'commit',null,?)")
                    .bind(sequence as i64)
                    .bind(address.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
            }
            for key in &objects {
                let (document, address) = object_address(key);
                sqlx::query("insert into history_apply_pending(horizon_sequence,kind,document,address) values(?,'object',?,?)")
                    .bind(sequence as i64)
                    .bind(document.to_string())
                    .bind(address.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
            }
            tx.commit().await.map_err(db)?;
            let released = self.release_batches(sequence, record, batch).await?;
            let after = self.storage_usage().await?;
            return Ok(ApplyReport {
                format: APPLY_FORMAT,
                project: self.project,
                sequence,
                address,
                plan_hash: expected,
                applied: true,
                already_applied: false,
                released,
                capacity_before: before,
                capacity_after: after,
            });
        }

        // Commit bodies. `refs.head` references `commits`, so a head cannot go (H6).
        let mut released = Released {
            states: plan.sets.released_states.len() as u64,
            ..Released::default()
        };
        if !plan.sets.released.is_empty() {
            let guard = without_guard(&mut tx, "commits_no_delete").await?;
            for address in &plan.sets.released {
                let bytes = commit_body(&mut tx, address).await?.len() as u64;
                let affected = sqlx::query("delete from commits where address=?")
                    .bind(address.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?
                    .rows_affected();
                if affected != 1 {
                    return Err(Error::Plan("a released commit vanished"));
                }
                released.commits += 1;
                released.commit_bytes += bytes;
            }
            restore_guard(&mut tx, "commits_no_delete", &guard).await?;
        }
        hook(Stage::Commits)?;
        if !objects.is_empty() {
            let guard = without_guard(&mut tx, "objects_no_delete").await?;
            for key in &objects {
                let (bytes, stored) = logical_object(&mut tx, key).await?;
                let (document, address) = object_address(key);
                let affected = sqlx::query("delete from objects where document=? and address=?")
                    .bind(document.to_string())
                    .bind(address.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?
                    .rows_affected();
                if affected != 1 {
                    return Err(Error::Plan("a released object vanished"));
                }
                released.objects += 1;
                released.object_bytes += bytes.len() as u64;
                released.stored_object_bytes += stored;
            }
            restore_guard(&mut tx, "objects_no_delete", &guard).await?;
        }
        hook(Stage::Objects)?;
        if released.commits != record.counts.commits_released
            || released.commit_bytes != record.counts.commit_bytes_released
            || released.objects != record.counts.objects_released
            || released.object_bytes != record.counts.object_bytes_released
        {
            return Err(Error::Plan("released rows differ from the signed counts"));
        }
        let changed = sqlx::query(
            "update local_storage set bytes_used=bytes_used-?,stored_bytes=stored_bytes-?,objects_used=objects_used-?,commits_used=commits_used-? where singleton=1",
        )
        .bind((released.commit_bytes + released.object_bytes) as i64)
        .bind((released.commit_bytes + released.stored_object_bytes) as i64)
        .bind(released.objects as i64)
        .bind(released.commits as i64)
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected();
        if changed != 1 {
            return Err(Error::Repository("capacity accounting row missing".into()));
        }
        hook(Stage::Accounted)?;
        verify_in(&mut tx, self.project).await?;
        let after = storage::usage(&mut tx, storage::HORIZON_SCHEMA_VERSION).await?;
        hook(Stage::Verified)?;
        tx.commit().await.map_err(db)?;
        Ok(ApplyReport {
            format: APPLY_FORMAT,
            project: self.project,
            sequence,
            address,
            plan_hash: expected,
            applied: true,
            already_applied: false,
            released,
            capacity_before: before,
            capacity_after: after,
        })
    }

    /// Check H1 to H9 in one read snapshot. Never needs a released body.
    pub async fn horizon_verify(&self) -> Result<VerifyReport, Error> {
        let mut connection = self.read_only_connection().await?;
        let result = async {
            let mut tx = connection.begin().await.map_err(db)?;
            let report = verify_in(&mut tx, self.project).await?;
            tx.rollback().await.map_err(db)?;
            Ok(report)
        }
        .await;
        let _ = connection.close().await;
        result
    }

    /// Every stored horizon, oldest first, with its signatures and policy.
    pub async fn horizons(&self) -> Result<Vec<StoredHorizon>, Error> {
        let mut connection = self.pool.acquire().await.map_err(db)?;
        if !has_horizons(&mut connection).await.map_err(db)? {
            return Ok(Vec::new());
        }
        let loaded = load_chain(&mut connection).await?;
        let mut out = Vec::new();
        for envelope in loaded.chain {
            let sequence = envelope.horizon.sequence;
            let rows: i64 = sqlx::query_scalar(
                "select count(*) from history_skeleton where horizon_sequence=?",
            )
            .bind(sequence as i64)
            .fetch_one(&mut *connection)
            .await
            .map_err(db)?;
            let policy = loaded
                .policies
                .get(&envelope.horizon.policy.hash)
                .map(Policy::to_value)
                .unwrap_or_default();
            out.push(StoredHorizon {
                sequence,
                address: envelope.horizon.address()?,
                record: envelope.horizon,
                signatures: envelope.signatures,
                policy,
                rehydrated: loaded.rehydrated.contains(&sequence),
                skeleton_rows: height_of(rows)?,
            });
        }
        Ok(out)
    }

    /// Restore what horizon `sequence` released from its archive. The horizon row
    /// stays (the chain is append-only); its skeleton, frontier and released-state
    /// rows go, and a rehydration row records the archive used.
    pub async fn horizon_rehydrate(
        &self,
        sequence: u64,
        archive: &Path,
    ) -> Result<RehydrateReport, Error> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if !has_horizons(&mut tx).await.map_err(db)? {
            return Err(Error::Plan("this repository has no horizon"));
        }
        let loaded = load_chain(&mut tx).await?;
        let envelope = loaded
            .chain
            .iter()
            .find(|e| e.horizon.sequence == sequence)
            .ok_or(Error::Plan("no horizon with that sequence"))?;
        if loaded.rehydrated.contains(&sequence) {
            return Err(Error::Plan("that horizon was already rehydrated"));
        }
        let expected = envelope
            .horizon
            .archive
            .clone()
            .ok_or(Error::Plan("that horizon wrote no archive"))?;
        let mut reader = ArchiveReader::open(archive)?;
        if reader.project != self.project || reader.sequence != sequence {
            return Err(Error::Format("history archive belongs to another horizon"));
        }
        let dropped = envelope
            .horizon
            .evidence
            .iter()
            .any(|e| e == "topology:drop");
        let mut commits = 0u64;
        let mut objects = 0u64;
        while let Some(entry) = reader.next_entry()? {
            match entry {
                Entry::Commit {
                    address,
                    envelope: body,
                } => {
                    let row: Option<(i64, i64)> = sqlx::query_as(
                        "select height,horizon_sequence from history_skeleton where address=?",
                    )
                    .bind(address.as_str())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db)?;
                    let height = match row {
                        Some((height, owner)) if owner == sequence as i64 => height,
                        Some(_) => {
                            return Err(Error::Format("archived commit belongs to another horizon"))
                        }
                        None if dropped => {
                            // No skeleton to check against: recompute from parents.
                            let signed = decode_commit(&body, &address, self.project)?;
                            let mut height = 0i64;
                            for parent in &signed.commit.parents {
                                let parent_height: Option<i64> = sqlx::query_scalar(
                                    "select height from commits where address=?1 union all select height from history_skeleton where address=?1 limit 1",
                                )
                                .bind(parent.as_str())
                                .fetch_optional(&mut *tx)
                                .await
                                .map_err(db)?;
                                height = height.max(parent_height.unwrap_or(-1) + 1);
                            }
                            height
                        }
                        None => {
                            return Err(Error::Format("archived commit is not in the skeleton"))
                        }
                    };
                    sqlx::query("insert into commits(address,body,height) values(?,?,?)")
                        .bind(address.as_str())
                        .bind(&body)
                        .bind(height)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| Error::from(storage::error(e)))?;
                    commits += 1;
                }
                Entry::Object {
                    document,
                    address,
                    bytes,
                } => {
                    let mut store = Store {
                        connection: &mut tx,
                        read_budget: None,
                        packed: true,
                    };
                    store.put(DocumentId(document), &address, &bytes).await?;
                    objects += 1;
                }
            }
        }
        if reader.finish()? != expected {
            return Err(Error::Format(
                "history archive differs from the horizon record",
            ));
        }
        sqlx::query(&format!(
            "insert into history_rehydration(sequence,archive_sha256,rehydrated_wall_ms) values(?,?,{NOW_MS})"
        ))
        .bind(sequence as i64)
        .bind(expected.sha256.as_str())
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        for table in [
            "history_skeleton",
            "history_frontier",
            "history_released_state",
        ] {
            sqlx::query(&format!("delete from {table} where horizon_sequence=?"))
                .bind(sequence as i64)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        verify_in(&mut tx, self.project).await?;
        tx.commit().await.map_err(db)?;
        Ok(RehydrateReport {
            project: self.project,
            sequence,
            commits,
            objects,
            archive_sha256: expected.sha256,
        })
    }

    /// Store the skeleton of one remote horizon whose envelope the caller verified
    /// against its trust journal, after checking the entries reproduce the record's
    /// skeleton root. Entries for commits stored here as bodies are skipped.
    pub async fn import_remote_skeleton(
        &self,
        envelope: &Envelope,
        entries: &[SkeletonEntry],
    ) -> Result<RemoteSkeletonReport, Error> {
        let record = &envelope.horizon;
        if record.project != self.project {
            return Err(Error::Format("horizon of another project"));
        }
        if horizon::skeleton_root(entries)? != record.roots.skeleton
            || entries.len() as u64 != record.counts.commits_released
        {
            return Err(Error::Violated(
                horizon::Invariant::H5,
                "remote skeleton does not reproduce the signed root".into(),
            ));
        }
        let address = record.address()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let schema: i64 = sqlx::query_scalar("select version from local_meta where singleton=1")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        if schema < storage::HORIZON_SCHEMA_VERSION {
            storage::upgrade_horizons(&mut tx).await?;
        }
        let mut report = RemoteSkeletonReport {
            horizon: address.clone(),
            sequence: record.sequence,
            stored: 0,
            bodies_present: 0,
        };
        for entry in entries {
            let body: bool =
                sqlx::query_scalar("select exists(select 1 from commits where address=?)")
                    .bind(entry.address.as_str())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db)?;
            if body {
                report.bodies_present += 1;
                continue;
            }
            report.stored += sqlx::query(
                "insert into history_remote_skeleton(address,parents,height,horizon,sequence) values(?,?,?,?,?) on conflict(address) do nothing",
            )
            .bind(entry.address.as_str())
            .bind(parents_text(&entry.parents))
            .bind(entry.height as i64)
            .bind(address.as_str())
            .bind(record.sequence as i64)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected();
        }
        tx.commit().await.map_err(db)?;
        Ok(report)
    }
}
