//! Integration tests for `engine-cli shared-snapshot --typed --incremental` (NEXT-09).

use std::process::Command;
use std::time::Instant;

use engine_core::materializer::{CommentState, DocumentState, MaterializedNode, SuggestionState};
use engine_core::shared_checkpoint::{postgres::Codec, Limits, MemoryStore};
use engine_shared::{DocumentId, EventPayload, IdentityId, NodeId, NodeType};
use serde_json::json;
use sqlx::PgPool;

fn owner_url(pool: &PgPool) -> String {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let server = base.rsplit_once('/').unwrap().0;
    format!(
        "{server}/{}",
        pool.connect_options().get_database().unwrap()
    )
}

fn run_cli(url: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_engine-cli"))
        .args(args)
        .env("DATABASE_URL", url)
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

async fn seed_document(pool: &PgPool) -> (IdentityId, DocumentId, NodeId) {
    let actor: uuid::Uuid = sqlx::query_scalar(
        "insert into identity(email,display_name) values($1,'CLI Author') returning id",
    )
    .bind(format!("{}@cli.test", uuid::Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .unwrap();
    let doc: uuid::Uuid = sqlx::query_scalar(
        "insert into document(title,created_by) values('CLI Shared Checkpoint',$1) returning id",
    )
    .bind(actor)
    .fetch_one(pool)
    .await
    .unwrap();
    let node = NodeId(format!("01{}", uuid::Uuid::new_v4().simple()));
    sqlx::query(
        "insert into node(id,document_id,type,pos,current_fields) values($1,$2,'form','a0','{}')",
    )
    .bind(&node.0)
    .bind(doc)
    .execute(pool)
    .await
    .unwrap();
    engine_core::log::append(
        pool,
        DocumentId(doc),
        &EventPayload::NodeCreated {
            node_id: node.clone(),
            node_type: NodeType::Form,
            parent_id: None,
            pos: "a0".into(),
            fields: json!({"label": "Initial title"}),
            var_name: None,
        },
        IdentityId(actor),
    )
    .await
    .unwrap();
    (IdentityId(actor), DocumentId(doc), node)
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_first_snapshot_publishes_fallback_ran_true(pool: PgPool) {
    let (_, doc, _) = seed_document(&pool).await;
    let url = owner_url(&pool);

    let (ok, out) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--typed",
            "--incremental",
        ],
    );
    assert!(ok, "cli output: {out}");
    assert!(
        out.contains("shared checkpoint V2 (incremental) at revision 1:"),
        "{out}"
    );
    assert!(out.contains("selected base: none"), "{out}");
    assert!(out.contains("fallback ran: true"), "{out}");
    assert!(out.contains("new objects:"), "{out}");
    assert!(out.contains("read queries:"), "{out}");
    assert!(out.contains("write queries:"), "{out}");

    // Compare root with ordinary typed writer
    let oracle = engine_core::shared_checkpoint::postgres::take_with_codec(
        &pool,
        doc,
        1,
        Limits::default(),
        Codec::V2,
    )
    .await
    .unwrap();
    assert!(out.contains(oracle.root.as_str()), "{out}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_incremental_edit_selects_earlier_base(pool: PgPool) {
    let (actor, doc, node) = seed_document(&pool).await;
    let url = owner_url(&pool);

    // Initial snapshot at revision 1
    let (ok1, out1) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--typed",
            "--incremental",
        ],
    );
    assert!(ok1, "{out1}");

    // Append edit event at revision 2
    engine_core::log::append(
        &pool,
        doc,
        &EventPayload::FieldEdited {
            node_id: node,
            field: "label".into(),
            value: json!("Updated title"),
        },
        actor,
    )
    .await
    .unwrap();

    // Incremental snapshot at revision 2
    let (ok2, out2) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "2",
            "--typed",
            "--incremental",
        ],
    );
    assert!(ok2, "cli output: {out2}");
    assert!(
        out2.contains("shared checkpoint V2 (incremental) at revision 2:"),
        "{out2}"
    );
    assert!(out2.contains("selected base: revision 1"), "{out2}");
    assert!(out2.contains("fallback ran: false"), "{out2}");

    // Compare with ordinary typed writer root
    let oracle = engine_core::shared_checkpoint::postgres::take_with_codec(
        &pool,
        doc,
        2,
        Limits::default(),
        Codec::V2,
    )
    .await
    .unwrap();
    assert!(out2.contains(oracle.root.as_str()), "{out2}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_no_eligible_base_falls_back_cleanly(pool: PgPool) {
    let (actor, doc, node) = seed_document(&pool).await;
    let url = owner_url(&pool);

    // Append revision 2 without ever taking revision 1
    engine_core::log::append(
        &pool,
        doc,
        &EventPayload::FieldEdited {
            node_id: node,
            field: "label".into(),
            value: json!("Second version"),
        },
        actor,
    )
    .await
    .unwrap();

    let (ok, out) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "2",
            "--typed",
            "--incremental",
        ],
    );
    assert!(ok, "{out}");
    assert!(
        out.contains("shared checkpoint V2 (incremental) at revision 2:"),
        "{out}"
    );
    assert!(out.contains("selected base: none"), "{out}");
    assert!(out.contains("fallback ran: true"), "{out}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_corrupt_base_fails_closed(pool: PgPool) {
    let (actor, doc, node) = seed_document(&pool).await;
    let url = owner_url(&pool);

    // Append revision 2
    engine_core::log::append(
        &pool,
        doc,
        &EventPayload::FieldEdited {
            node_id: node,
            field: "label".into(),
            value: json!("Second version"),
        },
        actor,
    )
    .await
    .unwrap();

    // Simulate pre-existing corrupt base checkpoint at rev 1
    let dummy_root = "c".repeat(64);
    sqlx::query("insert into checkpoint_object(document_id,address,bytes) values($1,$2,$3)")
        .bind(doc.0)
        .bind(&dummy_root)
        .bind(b"corrupted_bytes".as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    let chain = engine_core::shared_checkpoint::postgres::chain_at(&mut conn, doc, 1)
        .await
        .unwrap();
    sqlx::query(
        "insert into shared_checkpoint(document_id,through_seq,codec_version,state_root,event_chain_hash)
         values($1,1,2,$2,$3)",
    )
    .bind(doc.0)
    .bind(&dummy_root)
    .bind(&chain)
    .execute(&pool)
    .await
    .unwrap();

    // CLI invocation for rev 2 must fail closed
    let (ok2, out2) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "2",
            "--typed",
            "--incremental",
        ],
    );
    assert!(!ok2, "expected failure on corrupt base, got: {out2}");

    // Checkpoint at revision 2 must not have been created
    let count: i64 = sqlx::query_scalar(
        "select count(*) from shared_checkpoint where document_id=$1 and through_seq=2",
    )
    .bind(doc.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_invalid_flags_rejected(pool: PgPool) {
    let (_, doc, _) = seed_document(&pool).await;
    let url = owner_url(&pool);

    // --incremental without --typed must be rejected
    let (ok, out) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--incremental",
        ],
    );
    assert!(!ok, "expected failure without --typed, got: {out}");
    assert!(out.contains("--incremental requires --typed"), "{out}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_quota_failure_rolls_back_atomically(pool: PgPool) {
    let (actor, doc, node) = seed_document(&pool).await;
    let url = owner_url(&pool);

    let (ok1, out1) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--typed",
            "--incremental",
        ],
    );
    assert!(ok1, "{out1}");

    let count_before: i64 =
        sqlx::query_scalar("select count(*) from checkpoint_object where document_id=$1")
            .bind(doc.0)
            .fetch_one(&pool)
            .await
            .unwrap();

    // Cap budget to exactly current usage so any new object addition fails quota
    sqlx::query(
        "update checkpoint_storage_document set byte_limit = bytes_used, object_limit = objects_used
         where document_id = $1",
    )
    .bind(doc.0)
    .execute(&pool)
    .await
    .unwrap();

    engine_core::log::append(
        &pool,
        doc,
        &EventPayload::FieldEdited {
            node_id: node,
            field: "label".into(),
            value: json!("Second version"),
        },
        actor,
    )
    .await
    .unwrap();

    let (ok2, out2) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "2",
            "--typed",
            "--incremental",
        ],
    );
    assert!(!ok2, "expected failure due to storage quota, got: {out2}");
    assert!(
        out2.contains("budget reached") || out2.contains("publishing shared checkpoint failed"),
        "{out2}"
    );

    // Transaction must roll back: no revision 2 checkpoint, no new objects
    let count_chk: i64 = sqlx::query_scalar(
        "select count(*) from shared_checkpoint where document_id=$1 and through_seq=2",
    )
    .bind(doc.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count_chk, 0);

    let count_after: i64 =
        sqlx::query_scalar("select count(*) from checkpoint_object where document_id=$1")
            .bind(doc.0)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count_after, count_before);
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_existing_invocations_preserve_behavior(pool: PgPool) {
    let (_, doc, _) = seed_document(&pool).await;
    let url = owner_url(&pool);

    // Legacy V1 snapshot
    let (ok1, out1) = run_cli(
        &url,
        &["shared-snapshot", &doc.0.to_string(), "--through-seq", "1"],
    );
    assert!(ok1, "{out1}");
    assert!(
        out1.contains("shared checkpoint V1 at revision 1:"),
        "{out1}"
    );
    assert!(!out1.contains("selected base:"), "{out1}");
    assert!(!out1.contains("fallback ran:"), "{out1}");

    // Standard V2 snapshot without --incremental
    let (_, doc2, _) = seed_document(&pool).await;
    let (ok2, out2) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc2.0.to_string(),
            "--through-seq",
            "1",
            "--typed",
        ],
    );
    assert!(ok2, "{out2}");
    assert!(
        out2.contains("shared checkpoint V2 at revision 1:"),
        "{out2}"
    );
    assert!(!out2.contains("selected base:"), "{out2}");
    assert!(!out2.contains("fallback ran:"), "{out2}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_compact_v3_successful_publication_and_flag_selection(pool: PgPool) {
    let (_, doc, _) = seed_document(&pool).await;
    let url = owner_url(&pool);

    let (ok, out) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--codec",
            "compact-v3",
        ],
    );
    assert!(ok, "cli output: {out}");
    assert!(out.contains("shared checkpoint V3 at revision 1:"), "{out}");
    assert!(out.contains("encoded objects:"), "{out}");
    assert!(out.contains("encoded bytes:"), "{out}");
    assert!(out.contains("new objects:"), "{out}");
    assert!(out.contains("new canonical bytes:"), "{out}");

    // Verify row in database has codec_version = 3
    let (codec_ver, root): (i16, String) = sqlx::query_as(
        "select codec_version, state_root from shared_checkpoint where document_id = $1 and through_seq = 1",
    )
    .bind(doc.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(codec_ver, 3);
    assert!(out.contains(&root));

    // Loaded state matches
    let loaded = engine_core::shared_checkpoint::postgres::load(&pool, doc, 1, Limits::default())
        .await
        .unwrap();
    assert_eq!(loaded.nodes.len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_compact_v3_flag_conflicts_rejected(pool: PgPool) {
    let (_, doc, _) = seed_document(&pool).await;
    let url = owner_url(&pool);

    // Conflict with --typed
    let (ok_typed, out_typed) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--codec",
            "compact-v3",
            "--typed",
        ],
    );
    assert!(!ok_typed, "{out_typed}");
    assert!(
        out_typed.contains("--codec compact-v3 cannot be combined with --typed"),
        "{out_typed}"
    );

    // Conflict with --incremental
    let (ok_inc, out_inc) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--codec",
            "compact-v3",
            "--incremental",
        ],
    );
    assert!(!ok_inc, "{out_inc}");
    assert!(
        out_inc.contains(
            "--codec compact-v3 cannot be combined with --incremental (compact v3 uses the full writer only)"
        ),
        "{out_inc}"
    );

    // Unsupported codec
    let (ok_bad, out_bad) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--codec",
            "invalid-codec",
        ],
    );
    assert!(!ok_bad, "{out_bad}");
    assert!(
        out_bad.contains("unsupported codec 'invalid-codec', expected 'compact-v3'"),
        "{out_bad}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_compact_v3_existing_revision_with_another_codec_rejected(pool: PgPool) {
    let (_, doc, _) = seed_document(&pool).await;
    let url = owner_url(&pool);

    // Take v2 checkpoint first at revision 1
    let (ok1, out1) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--typed",
        ],
    );
    assert!(ok1, "{out1}");

    // Attempting to publish compact-v3 at the same revision must be rejected
    let (ok2, out2) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--codec",
            "compact-v3",
        ],
    );
    assert!(!ok2, "expected failure, got: {out2}");
    assert!(
        out2.contains("different checkpoint already published at revision")
            || out2.contains("publishing shared checkpoint failed"),
        "{out2}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_compact_v3_quota_failure_rolls_back(pool: PgPool) {
    let (actor, doc, node) = seed_document(&pool).await;
    let url = owner_url(&pool);

    let (ok1, out1) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "1",
            "--codec",
            "compact-v3",
        ],
    );
    assert!(ok1, "{out1}");

    let count_before: i64 =
        sqlx::query_scalar("select count(*) from checkpoint_object where document_id=$1")
            .bind(doc.0)
            .fetch_one(&pool)
            .await
            .unwrap();

    // Cap budget to current usage
    sqlx::query(
        "update checkpoint_storage_document set byte_limit = bytes_used, object_limit = objects_used
         where document_id = $1",
    )
    .bind(doc.0)
    .execute(&pool)
    .await
    .unwrap();

    engine_core::log::append(
        &pool,
        doc,
        &EventPayload::FieldEdited {
            node_id: node,
            field: "label".into(),
            value: json!("Second version"),
        },
        actor,
    )
    .await
    .unwrap();

    let (ok2, out2) = run_cli(
        &url,
        &[
            "shared-snapshot",
            &doc.0.to_string(),
            "--through-seq",
            "2",
            "--codec",
            "compact-v3",
        ],
    );
    assert!(!ok2, "expected quota failure, got: {out2}");
    assert!(
        out2.contains("budget reached") || out2.contains("publishing shared checkpoint failed"),
        "{out2}"
    );

    // Rollback check: no revision 2 checkpoint
    let count_chk: i64 = sqlx::query_scalar(
        "select count(*) from shared_checkpoint where document_id=$1 and through_seq=2",
    )
    .bind(doc.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count_chk, 0);

    let count_after: i64 =
        sqlx::query_scalar("select count(*) from checkpoint_object where document_id=$1")
            .bind(doc.0)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count_after, count_before);
}

fn build_benchmark_state(nodes: usize) -> DocumentState {
    let mut state = DocumentState::default();
    for i in 0..nodes {
        let node_id = NodeId(format!("01{:024x}", i));
        let is_derived = i % 2 == 0;
        let is_matching_block_id = i % 3 != 0;
        let is_media_heavy = i % 50 == 0;
        let is_tiny = i % 5 == 1;

        let block_id = if is_matching_block_id {
            node_id.0.clone()
        } else {
            format!("custom_block_{i}")
        };

        let content_text = if is_media_heavy {
            format!(
                "Media payload {} with large text blob: {}",
                i,
                "ABCD1234efgh".repeat(80)
            )
        } else if is_tiny {
            "x".into()
        } else {
            format!("Paragraph content for node {}", i)
        };

        let label = if is_derived {
            content_text.clone()
        } else {
            format!("Custom Label {}", i)
        };

        let current_fields = json!({
            "blockId": block_id,
            "label": label,
            "content": content_text,
            "active": true,
            "order": i,
        });

        state.nodes.insert(
            node_id.clone(),
            MaterializedNode {
                id: node_id.clone(),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: format!("a{:08x}", i),
                current_fields,
                var_name: None,
                deleted: false,
            },
        );

        if i % 25 == 0 {
            state.comments.push(CommentState {
                node_id: Some(node_id.clone()),
                body: format!("Comment on node {i}"),
            });
            state.suggestions.insert(
                format!("sug_{i}"),
                SuggestionState {
                    target_node_id: Some(node_id),
                    detail: json!({"change": format!("suggestion for {i}")}),
                    accepted: false,
                    rejected_reason: None,
                },
            );
        }
    }
    state
}

#[tokio::test]
async fn acceptance_synthetic_fixture_1000_and_8000_nodes_v2_vs_v3_comparison() {
    let doc = DocumentId(uuid::Uuid::new_v4());

    for &node_count in &[1_000, 8_000] {
        let state = build_benchmark_state(node_count);

        // V2 Write & Read
        let mut store_v2 = MemoryStore::default();
        let t_w2 = Instant::now();
        let (root_v2, stats_v2) = Codec::V2
            .write(&mut store_v2, doc, &state, Limits::default())
            .await
            .unwrap();
        let write_dur_v2 = t_w2.elapsed();

        let t_r2 = Instant::now();
        let recon_v2 = Codec::V2
            .read(&mut store_v2, doc, &root_v2, Limits::default())
            .await
            .unwrap();
        let read_dur_v2 = t_r2.elapsed();
        assert_eq!(recon_v2, state);

        // V3 Write & Read
        let mut store_v3 = MemoryStore::default();
        let t_w3 = Instant::now();
        let (root_v3, stats_v3) = Codec::V3
            .write(&mut store_v3, doc, &state, Limits::default())
            .await
            .unwrap();
        let write_dur_v3 = t_w3.elapsed();

        let t_r3 = Instant::now();
        let recon_v3 = Codec::V3
            .read(&mut store_v3, doc, &root_v3, Limits::default())
            .await
            .unwrap();
        let read_dur_v3 = t_r3.elapsed();
        assert_eq!(recon_v3, state);

        // Identical reconstructed states
        assert_eq!(
            recon_v2, recon_v3,
            "Reconstructed states must be identical for {node_count} nodes"
        );

        // V3 compacts node bodies and fields, so storage root diverges
        assert_ne!(root_v2, root_v3);

        // Verify physical storage savings
        assert!(
            stats_v3.new_bytes < stats_v2.new_bytes,
            "V3 bytes ({}) must be less than V2 bytes ({}) for {node_count} nodes",
            stats_v3.new_bytes,
            stats_v2.new_bytes
        );
        let bytes_saved = stats_v2.new_bytes - stats_v3.new_bytes;
        let pct_saved = (bytes_saved as f64 / stats_v2.new_bytes as f64) * 100.0;

        println!(
            "Benchmark [{node_count} nodes]:\n  V2: {} bytes, {} objects (write: {:?}, read: {:?})\n  V3: {} bytes, {} objects (write: {:?}, read: {:?})\n  Savings: {} bytes ({:.2}%)",
            stats_v2.new_bytes,
            stats_v2.new_objects,
            write_dur_v2,
            read_dur_v2,
            stats_v3.new_bytes,
            stats_v3.new_objects,
            write_dur_v3,
            read_dur_v3,
            bytes_saved,
            pct_saved
        );
    }
}
