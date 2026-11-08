//! Shared object collector (docs/DESIGN-COMMIT-PRUNING.md section 6.4, phase P5b,
//! decision 032). Operator only: it runs with the owner credential through
//! `engine-cli shared-object-gc`, never on an API route.
//!
//! For one document, under an advisory lock: mark every object reachable from a live
//! root (shared checkpoints, draft bases and merge bases, named snapshots, every
//! remaining publication row, staged objects and the file states of staged commits),
//! collect the objects reachable from states a horizon released whose publication
//! rows a release batch already removed, and sweep the collected objects no root
//! reaches. The plan is hash-bound like `gc-plan`; the apply recomputes it inside its
//! transaction. Foreign keys from every direct reference still refuse a wrong delete.
//!
//! The graph walk is streamed (decision 042): the marked and candidate sets live in
//! transaction-local temporary tables, and the walk reads at most `CHUNK` objects at
//! a time, so memory does not grow with the document's history.
use engine_core::shared_checkpoint::{self, Address};
use ring::digest;
use serde::Serialize;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

const DOMAIN: &[u8] = b"dynodoc.shared-object-collection\0v1\0";
const CHUNK: i64 = 4096;
/// Addresses listed in a plan for review; the hash and the apply cover all of them.
const LISTED: usize = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CollectionPlan {
    pub document: Uuid,
    pub plan_hash: String,
    /// Objects reachable from a live root.
    pub marked: u64,
    /// Objects reachable only from released states.
    pub candidates: u64,
    /// The first sorted addresses an apply deletes (at most 10,000 are listed).
    pub sweep: Vec<String>,
    /// Every object an apply deletes.
    pub sweep_objects: u64,
    pub sweep_bytes: u64,
    pub applied: bool,
}

/// Walk from the unvisited rows of `table` (`gc_mark` or `gc_candidate`) to every
/// object they reach, adding children to `table`; a candidate walk stops at marked
/// objects. Returns the number of rows in `table` afterwards.
async fn walk(db: &mut PgConnection, document: Uuid, table: &str) -> anyhow::Result<i64> {
    let skip_marked = if table == "gc_candidate" {
        "and not exists(select 1 from gc_mark m where m.address=a)"
    } else {
        ""
    };
    loop {
        let rows: Vec<(String, Option<Vec<u8>>)> = sqlx::query_as(&format!(
            "select t.address,o.bytes from {table} t left join checkpoint_object o on o.document_id=$1 and o.address=t.address where not t.done order by t.address limit $2"
        ))
        .bind(document)
        .bind(CHUNK)
        .fetch_all(&mut *db)
        .await?;
        if rows.is_empty() {
            break;
        }
        let mut children: Vec<String> = Vec::new();
        let mut visited: Vec<String> = Vec::with_capacity(rows.len());
        for (address, bytes) in rows {
            visited.push(address.clone());
            // A root whose bytes are already gone has nothing left to protect.
            let Some(bytes) = bytes else { continue };
            let bytes =
                engine_core::at_rest::store::open_object(&mut *db, document, &address, bytes)
                    .await?;
            let parsed = Address::try_from(address)?;
            children.extend(
                shared_checkpoint::references(&parsed, &bytes)?
                    .into_iter()
                    .map(|c| c.as_str().to_owned()),
            );
        }
        sqlx::query(&format!(
            "update {table} set done=true where address=any($1)"
        ))
        .bind(&visited)
        .execute(&mut *db)
        .await?;
        for chunk in children.chunks(CHUNK as usize) {
            sqlx::query(&format!(
                "insert into {table}(address) select a from unnest($1::text[]) a where true {skip_marked} on conflict do nothing"
            ))
            .bind(chunk)
            .execute(&mut *db)
            .await?;
        }
    }
    Ok(sqlx::query_scalar(&format!("select count(*) from {table}"))
        .fetch_one(&mut *db)
        .await?)
}

/// One page of the sweep after `after`: `(address, size)` in address order.
async fn sweep_page(
    db: &mut PgConnection,
    document: Uuid,
    after: &str,
) -> anyhow::Result<Vec<(String, i64)>> {
    Ok(sqlx::query_as(
        "select c.address,octet_length(o.bytes)::bigint from gc_candidate c join checkpoint_object o on o.document_id=$1 and o.address=c.address
         where c.address>$2 order by c.address limit $3",
    )
    .bind(document)
    .bind(after)
    .bind(CHUNK)
    .fetch_all(db)
    .await?)
}

async fn compute(db: &mut PgConnection, document: Uuid) -> anyhow::Result<CollectionPlan> {
    for table in ["gc_mark", "gc_candidate"] {
        sqlx::query(&format!("create temporary table {table}(address text primary key, done boolean not null default false) on commit drop"))
            .execute(&mut *db)
            .await?;
        sqlx::query(&format!("create index on {table}(address) where not done"))
            .execute(&mut *db)
            .await?;
    }
    for sql in [
        "select state_root from shared_checkpoint where document_id=$1",
        "select base_state_root from workspace_draft where document_id=$1 and base_state_root is not null",
        "select merge_base_root from workspace_draft where document_id=$1 and merge_base_root is not null",
        "select state_root from snapshot where document_id=$1 and state_root is not null",
        "select address from project_published_object where document_id=$1",
        "select address from project_staged_object where document_id=$1",
    ] {
        sqlx::query(&format!(
            "insert into gc_mark(address) {sql} on conflict do nothing"
        ))
        .bind(document)
        .execute(&mut *db)
        .await?;
    }
    // Staged commits are bounded (a person's private staging); their file states are roots.
    let staged: Vec<Vec<u8>> = sqlx::query_scalar(
        "select body from project_staged_commit where scope @> array[$1]::uuid[]",
    )
    .bind(document)
    .fetch_all(&mut *db)
    .await?;
    let mut roots: Vec<String> = Vec::new();
    for body in staged {
        let signed: engine_core::repository::SignedCommit = serde_json::from_slice(&body)?;
        roots.extend(
            signed
                .commit
                .files
                .values()
                .filter(|f| f.document.0 == document)
                .map(|f| f.state.as_str().to_owned()),
        );
    }
    sqlx::query("insert into gc_mark(address) select unnest($1::text[]) on conflict do nothing")
        .bind(&roots)
        .execute(&mut *db)
        .await?;
    let marked = walk(db, document, "gc_mark").await?;
    // Released states whose publication rows are gone (the release batch ran).
    sqlx::query(
        "insert into gc_candidate(address) select s.state_root from project_history_released_state s where s.document_id=$1
         and not exists(select 1 from project_published_object o where o.project_id=s.project_id and o.document_id=s.document_id and o.state_root=s.state_root)
         and not exists(select 1 from gc_mark m where m.address=s.state_root)
         on conflict do nothing",
    )
    .bind(document)
    .execute(&mut *db)
    .await?;
    let candidates = walk(db, document, "gc_candidate").await?;
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(DOMAIN);
    hash.update(document.as_bytes());
    let (mut sweep, mut sweep_objects, mut sweep_bytes) = (Vec::new(), 0u64, 0u64);
    let mut after = String::new();
    loop {
        let page = sweep_page(db, document, &after).await?;
        let Some((last, _)) = page.last() else { break };
        after = last.clone();
        for (address, size) in page {
            hash.update(address.as_bytes());
            hash.update(b"\n");
            sweep_objects += 1;
            sweep_bytes += size as u64;
            if sweep.len() < LISTED {
                sweep.push(address);
            }
        }
    }
    Ok(CollectionPlan {
        document,
        plan_hash: hex::encode(hash.finish()),
        marked: marked as u64,
        candidates: candidates as u64,
        sweep,
        sweep_objects,
        sweep_bytes,
        applied: false,
    })
}

async fn lock(db: &mut PgConnection, document: Uuid) -> anyhow::Result<()> {
    // The same document lock order as the API (document row first): publication,
    // staging and erasure of this document wait until the collection commits.
    sqlx::query("select 1 from document where id=$1 for update")
        .bind(document)
        .fetch_optional(&mut *db)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no such document"))?;
    Ok(())
}

/// What a collection of `document` would delete, changing nothing (the transaction
/// writes only its own temporary tables and is rolled back).
pub async fn plan(pool: &PgPool, document: Uuid) -> anyhow::Result<CollectionPlan> {
    let mut tx = pool.begin().await?;
    sqlx::query("set transaction isolation level repeatable read")
        .execute(&mut *tx)
        .await?;
    let plan = compute(&mut tx, document).await?;
    tx.rollback().await?;
    Ok(plan)
}

/// Delete exactly the reviewed plan's objects; refuses if anything changed.
pub async fn apply(
    pool: &PgPool,
    document: Uuid,
    plan_hash: &str,
) -> anyhow::Result<CollectionPlan> {
    let mut tx = pool.begin().await?;
    lock(&mut tx, document).await?;
    let mut plan = compute(&mut tx, document).await?;
    anyhow::ensure!(
        plan.plan_hash == plan_hash.to_ascii_lowercase(),
        "the collection plan changed since review; plan again"
    );
    let mut after = String::new();
    loop {
        let page = sweep_page(&mut tx, document, &after).await?;
        let Some((last, _)) = page.last() else { break };
        after = last.clone();
        let addresses: Vec<&str> = page.iter().map(|(a, _)| a.as_str()).collect();
        sqlx::query("insert into shared_object_collection(document_id,addresses,plan_hash) values($1,$2,$3)")
            .bind(document)
            .bind(&addresses)
            .bind(&plan.plan_hash)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    plan.applied = plan.sweep_objects > 0;
    Ok(plan)
}
