//! Integration tests for `engine-cli shared-snapshot --typed --incremental` (NEXT-09).

use std::process::Command;

use engine_core::shared_checkpoint::{postgres::Codec, Limits};
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
