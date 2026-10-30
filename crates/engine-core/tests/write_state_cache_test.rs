use engine_core::{
    log,
    materializer::{DocumentState, Materializer},
    snapshot::{
        cache::CurrentStateCache, read_current_state, NamedStorage, SnapshotEngine, SnapshotReason,
    },
};
use engine_shared::{DocumentId, EventPayload, IdentityId, NodeId, NodeType};
use serde_json::json;
use sqlx::PgPool;

async fn seed(pool: &PgPool) -> anyhow::Result<(IdentityId, DocumentId, NodeId)> {
    let actor = IdentityId(sqlx::query_scalar("insert into identity(email,display_name) values('cache@example.test','Synthetic cache author') returning id").fetch_one(pool).await?);
    let doc = DocumentId(sqlx::query_scalar("insert into document(title,created_by) values('Synthetic cache document',$1) returning id").bind(actor.0).fetch_one(pool).await?);
    let node = NodeId(ulid::Ulid::generate().to_string());
    let mut tx = pool.begin().await?;
    sqlx::query(
        "insert into node(id,document_id,type,pos,current_fields) values($1,$2,'form','a0',$3)",
    )
    .bind(&node.0)
    .bind(doc.0)
    .bind(json!({"title":"0"}))
    .execute(&mut *tx)
    .await?;
    log::append_in_tx(
        &mut tx,
        doc,
        &EventPayload::NodeCreated {
            node_id: node.clone(),
            node_type: NodeType::Form,
            parent_id: None,
            pos: "a0".into(),
            fields: json!({"title":"0"}),
            var_name: None,
        },
        actor,
    )
    .await?;
    tx.commit().await?;
    Ok((actor, doc, node))
}

fn edit(node: &NodeId, title: &str) -> EventPayload {
    EventPayload::FieldEdited {
        node_id: node.clone(),
        field: "title".into(),
        value: json!(title),
    }
}

async fn lock(
    pool: &PgPool,
    doc: DocumentId,
) -> anyhow::Result<sqlx::Transaction<'_, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("select id from document where id=$1 for no key update")
        .bind(doc.0)
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn checked(
    cache: &CurrentStateCache,
    pool: &PgPool,
    doc: DocumentId,
) -> anyhow::Result<DocumentState> {
    let mut tx = lock(pool, doc).await?;
    let (actual, seq) = cache.read(&mut tx, doc).await?;
    let (reference, reference_seq) = read_current_state(&mut tx, doc).await?;
    assert_eq!(seq, reference_seq);
    assert_eq!(actual, reference);
    tx.commit().await?;
    log::verify_chain(pool, doc).await?;
    let folded = Materializer::fold(&log::read_range(pool, doc, 1, i64::MAX).await?)?;
    assert_eq!(actual, folded);
    Ok(actual)
}

#[sqlx::test(migrations = "../../migrations")]
async fn cached_state_equals_fold_after_rollback_and_concurrency(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (actor, doc, node) = seed(&pool).await?;
    let cache = CurrentStateCache::default();
    checked(&cache, &pool, doc).await?;
    checked(&cache, &pool, doc).await?;
    assert_eq!(cache.stats().hits, 1);
    // Populate from a transaction that later rolls back its event/projection.
    let mut tx = lock(&pool, doc).await?;
    log::append_in_tx(&mut tx, doc, &edit(&node, "uncommitted"), actor).await?;
    let (uncommitted, seq) = cache.read(&mut tx, doc).await?;
    assert_eq!(seq, 2);
    assert_eq!(
        uncommitted.nodes[&node].current_fields["title"],
        "uncommitted"
    );
    tx.rollback().await?;
    assert_eq!(
        checked(&cache, &pool, doc).await?.nodes[&node].current_fields["title"],
        "0"
    );

    let mut writers = Vec::new();
    for _ in 0..16 {
        let (pool, cache, node) = (pool.clone(), cache.clone(), node.clone());
        writers.push(tokio::spawn(async move {
            let mut tx = lock(&pool, doc).await?;
            let (mut state, seq) = cache.read(&mut tx, doc).await?;
            assert_eq!(
                state.nodes[&node].current_fields["title"],
                (seq - 1).to_string()
            );
            // Returned states are owned: a caller's mutation must not alter the cache.
            state.nodes.get_mut(&node).unwrap().current_fields["title"] = json!("local only");
            log::append_in_tx(&mut tx, doc, &edit(&node, &seq.to_string()), actor).await?;
            tx.commit().await?;
            Ok::<_, anyhow::Error>(())
        }));
    }
    for writer in writers {
        writer.await??;
    }
    assert_eq!(
        checked(&cache, &pool, doc).await?.nodes[&node].current_fields["title"],
        "16"
    );
    assert!(cache.stats().hits >= 16, "{:?}", cache.stats());
    // A fresh process/cache has no dependency on another process's notifications.
    assert_eq!(
        checked(&CurrentStateCache::default(), &pool, doc).await?,
        checked(&cache, &pool, doc).await?
    );
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn another_writer_and_new_snapshot_invalidate_without_notifications(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (actor, doc, node) = seed(&pool).await?;
    let cache = CurrentStateCache::default();
    checked(&cache, &pool, doc).await?;
    let mut tx = lock(&pool, doc).await?;
    log::append_in_tx(&mut tx, doc, &edit(&node, "other process"), actor).await?;
    tx.commit().await?;
    assert_eq!(
        checked(&cache, &pool, doc).await?.nodes[&node].current_fields["title"],
        "other process"
    );
    assert_eq!(cache.stats().hits, 1);
    SnapshotEngine::new(pool.clone())
        .take(doc, SnapshotReason::Periodic)
        .await?;
    let misses = cache.stats().misses;
    checked(&cache, &pool, doc).await?;
    assert_eq!(cache.stats().misses, misses + 1);
    checked(&cache, &pool, doc).await?;
    assert_eq!(cache.stats().hits, 2);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_receipt_is_not_hidden_by_a_warm_write_cache(pool: PgPool) -> anyhow::Result<()> {
    let (_, doc, _) = seed(&pool).await?;
    SnapshotEngine::new(pool.clone())
        .take(doc, SnapshotReason::Periodic)
        .await?;
    let cache = CurrentStateCache::default();
    checked(&cache, &pool, doc).await?;
    checked(&cache, &pool, doc).await?;
    sqlx::raw_sql("alter table snapshot_verification disable trigger snapshot_verification_no_delete; delete from snapshot_verification; alter table snapshot_verification enable trigger snapshot_verification_no_delete").execute(&pool).await?;
    let mut tx = lock(&pool, doc).await?;
    let error = cache.read(&mut tx, doc).await.unwrap_err();
    assert!(error.to_string().contains("receipt"), "{error}");
    assert_eq!(cache.stats().entries, 0);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn corrupt_snapshot_cannot_escape_through_warm_write_cache(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (_, doc, node) = seed(&pool).await?;
    let snapshot = SnapshotEngine::new(pool.clone())
        .take(doc, SnapshotReason::Periodic)
        .await?;
    let cache = CurrentStateCache::default();
    checked(&cache, &pool, doc).await?;
    checked(&cache, &pool, doc).await?;
    let mut tx = lock(&pool, doc).await?;
    sqlx::query("alter table snapshot disable trigger snapshot_no_update")
        .execute(&mut *tx)
        .await?;
    sqlx::query("update snapshot set state=jsonb_set(state,$2,'\"forged\"') where id=$1")
        .bind(snapshot.id.0)
        .bind(vec!["nodes", &node.0, "current_fields", "title"])
        .execute(&mut *tx)
        .await?;
    sqlx::query("alter table snapshot enable trigger snapshot_no_update")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut tx = lock(&pool, doc).await?;
    let error = cache.read(&mut tx, doc).await.unwrap_err();
    assert!(error.to_string().contains("receipt"), "{error}");
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn earlier_tail_rewrite_is_detected_even_when_head_hash_is_unchanged(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (actor, doc, node) = seed(&pool).await?;
    let mut tx = lock(&pool, doc).await?;
    log::append_in_tx(&mut tx, doc, &edit(&node, "second"), actor).await?;
    tx.commit().await?;
    let cache = CurrentStateCache::default();
    checked(&cache, &pool, doc).await?;
    checked(&cache, &pool, doc).await?;
    let head: Vec<u8> =
        sqlx::query_scalar("select chain_hash from event where document_id=$1 and seq=2")
            .bind(doc.0)
            .fetch_one(&pool)
            .await?;
    let mut tx = lock(&pool, doc).await?;
    sqlx::query("alter table event disable trigger event_no_update")
        .execute(&mut *tx)
        .await?;
    sqlx::query("update event set payload=jsonb_set(payload,'{fields,title}','\"forged\"') where document_id=$1 and seq=1").bind(doc.0).execute(&mut *tx).await?;
    sqlx::query("alter table event enable trigger event_no_update")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let same: Vec<u8> =
        sqlx::query_scalar("select chain_hash from event where document_id=$1 and seq=2")
            .bind(doc.0)
            .fetch_one(&pool)
            .await?;
    assert_eq!(head, same);
    let mut tx = lock(&pool, doc).await?;
    let error = cache.read(&mut tx, doc).await.unwrap_err();
    assert!(error.to_string().contains("chain broken"), "{error}");
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn shared_storage_snapshots_bypass_write_cache(pool: PgPool) -> anyhow::Result<()> {
    let (_, doc, _) = seed(&pool).await?;
    let cache = CurrentStateCache::default();
    checked(&cache, &pool, doc).await?;
    assert_eq!(cache.stats().entries, 1);
    SnapshotEngine::new(pool.clone())
        .with_named_storage(NamedStorage::SharedV2)
        .take(doc, SnapshotReason::Deployed)
        .await?;
    checked(&cache, &pool, doc).await?;
    checked(&cache, &pool, doc).await?;
    assert_eq!(cache.stats().entries, 0);
    assert_eq!(cache.stats().hits, 0);
    Ok(())
}

async fn shared_checkpoint_bypass(
    pool: PgPool,
    codec: engine_core::shared_checkpoint::postgres::Codec,
) -> anyhow::Result<()> {
    let (_, doc, _) = seed(&pool).await?;
    let cache = CurrentStateCache::default();
    checked(&cache, &pool, doc).await?;
    engine_core::shared_checkpoint::postgres::take_with_codec(
        &pool,
        doc,
        1,
        Default::default(),
        codec,
    )
    .await?;
    checked(&cache, &pool, doc).await?;
    checked(&cache, &pool, doc).await?;
    assert_eq!(cache.stats().entries, 0);
    assert_eq!(cache.stats().hits, 0);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn shared_v1_checkpoints_bypass_write_cache(pool: PgPool) -> anyhow::Result<()> {
    shared_checkpoint_bypass(pool, engine_core::shared_checkpoint::postgres::Codec::V1).await
}
#[sqlx::test(migrations = "../../migrations")]
async fn shared_v2_checkpoints_bypass_write_cache(pool: PgPool) -> anyhow::Result<()> {
    shared_checkpoint_bypass(pool, engine_core::shared_checkpoint::postgres::Codec::V2).await
}
