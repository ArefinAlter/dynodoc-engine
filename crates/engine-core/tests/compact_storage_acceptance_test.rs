//! Acceptance across compact storage: mixed-codec checkpoints, incremental v3
//! publication, named v3 snapshots, retention planning and the re-encode check.

use engine_core::{
    log::append,
    materializer::Materializer,
    shared_checkpoint::{postgres, Limits},
    snapshot::{read_state_at, CheckpointFormat, NamedStorage, SnapshotEngine, SnapshotReason},
};
use engine_shared::{DocumentId, Event, EventPayload, IdentityId, NodeId, NodeType};
use futures::future::try_join_all;
use serde_json::json;
use sqlx::PgPool;

const NODES: usize = 40;
const EDITS: usize = 8;
const HEAD: i64 = (NODES + EDITS + 1) as i64;

/// A document with `NODES` blocks (revisions 1..=NODES), `EDITS` later edits and one comment.
async fn workload(pool: &PgPool, tag: usize) -> anyhow::Result<(IdentityId, DocumentId)> {
    let actor: uuid::Uuid = sqlx::query_scalar(
        "insert into identity(email,display_name) values($1,'Acceptance') returning id",
    )
    .bind(format!("{}@acceptance.test", uuid::Uuid::new_v4()))
    .fetch_one(pool)
    .await?;
    let doc: uuid::Uuid =
        sqlx::query_scalar("insert into document(title,created_by) values($1,$2) returning id")
            .bind(format!("Acceptance {tag}"))
            .bind(actor)
            .fetch_one(pool)
            .await?;
    let (actor, doc) = (IdentityId(actor), DocumentId(doc));
    let mut nodes = Vec::new();
    for i in 0..NODES {
        let id = NodeId(ulid::Ulid::generate().to_string());
        let pos = format!("a{i:03}");
        sqlx::query(
            "insert into node(id,document_id,type,pos,current_fields) values($1,$2,'form',$3,'{}')",
        )
        .bind(&id.0)
        .bind(doc.0)
        .bind(&pos)
        .execute(pool)
        .await?;
        let created = EventPayload::NodeCreated {
            node_id: id.clone(),
            node_type: NodeType::Form,
            parent_id: None,
            pos,
            fields: json!({"label": format!("block {i}")}),
            var_name: None,
        };
        append(pool, doc, &created, actor).await?;
        nodes.push(id);
    }
    let first_node = nodes[0].clone();
    for (i, node_id) in nodes.into_iter().take(EDITS).enumerate() {
        let edit = EventPayload::FieldEdited {
            node_id,
            field: "label".into(),
            value: json!(format!("edited {i}")),
        };
        append(pool, doc, &edit, actor).await?;
    }
    let comment = EventPayload::CommentAdded {
        node_id: Some(first_node),
        body: "Retained review".into(),
    };
    append(pool, doc, &comment, actor).await?;
    Ok((actor, doc))
}

#[sqlx::test(migrations = "../../migrations")]
async fn compact_storage_stays_faithful_orphan_free_and_small_across_documents(
    pool: PgPool,
) -> anyhow::Result<()> {
    let limits = Limits::default();
    let docs = try_join_all((0..3).map(|tag| workload(&pool, tag))).await?;
    let v3_seqs = [NODES as i64, NODES as i64 + 4, HEAD];
    let all_seqs = [10, v3_seqs[0], v3_seqs[1], v3_seqs[2]];

    for (_, doc) in docs {
        // A legacy v2 checkpoint early in the history, then a v3 chain.
        postgres::take_incremental(&pool, doc, 10, limits).await?;
        let started = std::time::Instant::now();
        let full = postgres::take_incremental_v3(&pool, doc, v3_seqs[0], limits).await?;
        assert!(full.fallback_ran, "v2 is not an eligible v3 base");
        let mut base = v3_seqs[0];
        for seq in &v3_seqs[1..] {
            let next = postgres::take_incremental_v3(&pool, doc, *seq, limits).await?;
            assert_eq!(next.base_seq, Some(base));
            assert!(
                next.stats.new_bytes * 2 < full.stats.new_bytes,
                "an increment of a few edits writes far less than the full graph"
            );
            eprintln!(
                "acceptance revision {seq}: {} objects visited, {} new, {} new bytes, {}/{} read/write queries",
                next.stats.visited_objects, next.stats.new_objects, next.stats.new_bytes,
                next.object_read_queries, next.object_write_queries
            );
            base = *seq;
        }
        eprintln!(
            "acceptance full v3: {} objects, {} new bytes; chain took {:?} (not asserted)",
            full.stats.visited_objects,
            full.stats.new_bytes,
            started.elapsed()
        );

        // An aborted publication and a retry add nothing.
        let tiny = Limits {
            max_objects: 1,
            ..limits
        };
        assert!(postgres::take_incremental_v3(&pool, doc, 45, tiny)
            .await
            .is_err());
        let retry = postgres::take_incremental_v3(&pool, doc, HEAD, limits).await?;
        assert_eq!(retry.stats.new_objects, 0);

        SnapshotEngine::new(pool.clone())
            .with_named_storage(NamedStorage::SharedV3)
            .take(doc, SnapshotReason::Deployed)
            .await?;

        // Every revision matches replay through whichever checkpoint serves it.
        let events: Vec<Event> =
            sqlx::query_as("select * from event where document_id=$1 order by seq")
                .bind(doc.0)
                .fetch_all(&pool)
                .await?;
        let mut connection = pool.acquire().await?;
        for seq in 0..=HEAD {
            let at = read_state_at(&mut connection, doc, seq).await?;
            assert_eq!(
                at.state,
                Materializer::fold(&events[..seq as usize])?,
                "revision {seq}"
            );
        }
        let at = read_state_at(&mut connection, doc, v3_seqs[1]).await?;
        assert_eq!(
            (at.checkpoint_format, at.replayed_events),
            (CheckpointFormat::SharedV3, 0)
        );
        drop(connection);

        // Failed transactions leave no orphan: every stored object is reached by a stored
        // root. Objects of checkpoints outside a keep set are not orphans, only freeable.
        let report = postgres::retention_report(&pool, doc, &all_seqs, limits).await?;
        assert!(report.outside_keep.is_empty() && report.unreferenced.is_empty());
        let report = postgres::retention_report(&pool, doc, &[HEAD], limits).await?;
        assert!(!report.outside_keep.is_empty() && report.unreferenced.is_empty());

        // The legacy checkpoint re-encodes as v3 with the same state, byte for byte every time.
        let check = postgres::reencode_check(&pool, doc, 10, limits).await?;
        assert_eq!(check.codec_version, 2);
        let again = postgres::reencode_check(&pool, doc, 10, limits).await?;
        assert_eq!(
            (check.v3_root, check.v3.encoded_bytes),
            (again.v3_root, again.v3.encoded_bytes)
        );
    }
    Ok(())
}
