//! H5 measurement (decision 034): cost of publishing a checkpoint after a small edit,
//! by changed-node publication and by the full incremental path, at several document
//! sizes on PostgreSQL. Disposable database only: it creates a database per run.
//! DYNODOC_CHECKPOINT_BENCH=disposable DATABASE_URL=postgres://owner@host/postgres \
//!   cargo run --release -p engine-core --example changed_publication_bench -- 20000 200000
//! `--memory N...` measures the same paths on the in-memory store (CPU and objects
//! written, no database): no environment variables needed.
use engine_core::{
    database::MIGRATOR,
    log::append_in_tx,
    materializer::{DocumentState, MaterializedNode},
    shared_checkpoint::{
        postgres,
        typed::{self, NodeChanges},
        Limits, MemoryStore,
    },
};
use engine_shared::{DocumentId, EventPayload, IdentityId, NodeId, NodeType};
use serde_json::json;
use sqlx::PgPool;
use std::time::Instant;

/// The same three paths on the in-memory store, so CPU and objects written can be
/// compared at sizes the shared test database cannot seed in reasonable time.
async fn memory() -> anyhow::Result<()> {
    let limits = Limits {
        max_objects: usize::MAX,
        max_bytes: usize::MAX,
    };
    let semantic = typed::SemanticLimits::default();
    let mut rows = Vec::new();
    for arg in std::env::args().skip(2) {
        let nodes: usize = arg.parse()?;
        anyhow::ensure!((100..=2_000_000).contains(&nodes), "nodes 100-2000000");
        let doc = DocumentId(uuid::Uuid::from_u128(nodes as u128));
        let mut state = DocumentState::default();
        for i in 0..nodes {
            let id = NodeId(format!("{i:026}"));
            state.nodes.insert(
                id.clone(),
                MaterializedNode {
                    id,
                    parent_id: None,
                    node_type: "item".into(),
                    pos: format!("{i:010}"),
                    current_fields: paragraph(i),
                    var_name: None,
                    deleted: false,
                },
            );
        }
        let mut store = MemoryStore::default();
        let start = Instant::now();
        let (base, _) = typed::write_state_v3(&mut store, doc, &state, limits, semantic).await?;
        let full_s = start.elapsed().as_secs_f64();
        let mut changes = NodeChanges::default();
        let mut target = state.clone();
        for e in 0..100 {
            let id = NodeId(format!("{:026}", (e * 7919) % nodes));
            let node = target
                .nodes
                .get_mut(&id)
                .ok_or_else(|| anyhow::anyhow!("node"))?;
            node.current_fields["label"] = json!(format!("Edited {e}"));
            changes.nodes.insert(id, node.clone());
        }
        let start = Instant::now();
        let (changed, changed_stats) =
            typed::apply_changes_v3(&mut store, doc, &base, &changes, limits, semantic).await?;
        let changed_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        let (incremental, incremental_stats) =
            typed::update_state_v3(&mut store, doc, &base, &state, &target, limits, semantic)
                .await?;
        let incremental_ms = start.elapsed().as_secs_f64() * 1000.0;
        anyhow::ensure!(changed == incremental, "both paths give one root");
        let row = json!({
            "nodes": nodes, "objects": store.object_count(), "full_v3_write_s": full_s,
            "changed": {"ms": changed_ms, "visited_objects": changed_stats.visited_objects, "new_objects": changed_stats.new_objects, "new_bytes": changed_stats.new_bytes},
            "incremental_with_resident_states": {"ms": incremental_ms, "visited_objects": incremental_stats.visited_objects, "new_objects": incremental_stats.new_objects, "new_bytes": incremental_stats.new_bytes},
        });
        eprintln!("{row}");
        rows.push(row);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "benchmark": "H5 changed-node publication on the in-memory store (decision 034)",
            "measurement": "one 100-node commit; wall time of one call; single run per size; the incremental path is given both resident states, which the database path must first read",
            "results": rows,
        }))?
    );
    Ok(())
}

fn paragraph(i: usize) -> serde_json::Value {
    let text = format!("Paragraph {i} of a synthetic long report with ordinary sentence length.");
    json!({"label": text, "content": {"type":"paragraph","attrs":{"blockId":format!("{i:026}")},"content":[{"type":"text","text":text}]}})
}

async fn size(pool: &PgPool, doc: DocumentId) -> anyhow::Result<(i64, i64)> {
    Ok(sqlx::query_as("select count(*),coalesce(sum(octet_length(bytes)),0)::bigint from checkpoint_object where document_id=$1")
        .bind(doc.0)
        .fetch_one(pool)
        .await?)
}

async fn run(pool: &PgPool, nodes: usize, edits: usize) -> anyhow::Result<serde_json::Value> {
    let actor = IdentityId(sqlx::query_scalar("insert into identity(email,display_name) values($1,'Synthetic benchmark') returning id").bind(format!("bench-{nodes}@example.test")).fetch_one(pool).await?);
    let doc = DocumentId(sqlx::query_scalar("insert into document(title,created_by) values('Disposable publication benchmark',$1) returning id").bind(actor.0).fetch_one(pool).await?);
    // Node ids are unique across documents: each size gets its own prefix.
    let id = |i: usize| NodeId(format!("{:07}{i:019}", nodes));
    let root = id(0);
    let started = Instant::now();
    let mut ids = Vec::with_capacity(nodes);
    for batch in 0..=nodes / 5000 {
        let mut tx = pool.begin().await?;
        for i in (batch * 5000).max(1)..((batch + 1) * 5000).min(nodes + 1) {
            ids.push(id(i));
        }
        let mut ops = Vec::new();
        if batch == 0 {
            ops.push(EventPayload::NodeCreated {
                node_id: root.clone(),
                node_type: NodeType::Form,
                parent_id: None,
                pos: "000000".into(),
                fields: json!({"label":"Report"}),
                var_name: None,
            });
        }
        for i in (batch * 5000).max(1)..((batch + 1) * 5000).min(nodes + 1) {
            ops.push(EventPayload::NodeCreated {
                node_id: id(i),
                node_type: NodeType::Item,
                parent_id: Some(root.clone()),
                pos: format!("{i:010}"),
                fields: paragraph(i),
                var_name: None,
            });
        }
        for op in &ops {
            if let EventPayload::NodeCreated { node_id, pos, .. } = op {
                sqlx::query("insert into node(id,document_id,type,pos) values($1,$2,'item',$3)")
                    .bind(&node_id.0)
                    .bind(doc.0)
                    .bind(pos)
                    .execute(&mut *tx)
                    .await?;
            }
            append_in_tx(&mut tx, doc, op, actor).await?;
        }
        tx.commit().await?;
    }
    let seed_s = started.elapsed().as_secs_f64();
    // Disposable database: lift this document's shared-object budget for the run.
    sqlx::query("insert into checkpoint_storage_account(identity_id,byte_limit,object_limit) values($1,1099511627776,1000000000) on conflict(identity_id) do update set byte_limit=excluded.byte_limit,object_limit=excluded.object_limit").bind(actor.0).execute(pool).await?;
    sqlx::query("insert into checkpoint_storage_document(document_id,identity_id,byte_limit,object_limit) values($1,$2,1099511627776,1000000000) on conflict(document_id) do update set byte_limit=excluded.byte_limit,object_limit=excluded.object_limit").bind(doc.0).bind(actor.0).execute(pool).await?;
    let limits = Limits {
        max_objects: 100_000_000,
        max_bytes: 64 << 30,
    };
    let head = nodes as i64 + 1;
    let start = Instant::now();
    postgres::take_with_codec(pool, doc, head, limits, postgres::Codec::V3).await?;
    let full_s = start.elapsed().as_secs_f64();
    let (base_objects, base_bytes) = size(pool, doc).await?;
    let mut measure = Vec::new();
    for (round, path) in ["changed", "incremental", "changed"].iter().enumerate() {
        let mut tx = pool.begin().await?;
        for e in 0..edits {
            let node = ids[(e * 7919 + round * 104_729) % ids.len()].clone();
            append_in_tx(
                &mut tx,
                doc,
                &EventPayload::FieldEdited {
                    node_id: node,
                    field: "label".into(),
                    value: json!(format!("Edited {round}-{e}")),
                },
                actor,
            )
            .await?;
        }
        tx.commit().await?;
        let seq = head + ((round + 1) * edits) as i64;
        let (objects_before, bytes_before) = size(pool, doc).await?;
        let start = Instant::now();
        let published = if *path == "changed" {
            postgres::take_changed_v3(pool, doc, seq, limits).await?
        } else {
            postgres::take_incremental_v3(pool, doc, seq, limits).await?
        };
        let wall_ms = start.elapsed().as_secs_f64() * 1000.0;
        let (objects_after, bytes_after) = size(pool, doc).await?;
        measure.push(json!({
            "path": path, "wall_ms": wall_ms, "fallback": published.fallback_ran,
            "visited_objects": published.stats.visited_objects,
            "new_objects": objects_after - objects_before, "new_bytes": bytes_after - bytes_before,
            "object_read_queries": published.object_read_queries,
        }));
    }
    Ok(json!({
        "nodes": nodes, "edited_nodes_per_commit": edits, "seed_events_s": seed_s,
        "full_v3_publication_s": full_s, "objects": base_objects, "object_bytes": base_bytes,
        "publications": measure,
    }))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--memory") {
        return memory().await;
    }
    anyhow::ensure!(
        std::env::var("DYNODOC_CHECKPOINT_BENCH").as_deref() == Ok("disposable"),
        "explicit disposable database acknowledgement required"
    );
    let admin = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    let name = format!("large_files_bench_{}", std::process::id());
    sqlx::query(&format!("create database {name}"))
        .execute(&admin)
        .await?;
    let mut options: sqlx::postgres::PgConnectOptions = std::env::var("DATABASE_URL")?.parse()?;
    options = options.database(&name);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await?;
    MIGRATOR.run(&pool).await?;
    let mut results = Vec::new();
    for arg in std::env::args().skip(1) {
        let nodes: usize = arg.parse()?;
        anyhow::ensure!((100..=2_000_000).contains(&nodes), "nodes 100-2000000");
        let row = run(&pool, nodes, 100).await?;
        eprintln!("{row}");
        results.push(row);
    }
    pool.close().await;
    sqlx::query(&format!("drop database {name}"))
        .execute(&admin)
        .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "benchmark": "H5 changed-node publication (decision 034)",
            "measurement": "wall time of one publication after a 100-node commit; single run per size; PostgreSQL on the same host",
            "results": results,
        }))?
    );
    Ok(())
}
