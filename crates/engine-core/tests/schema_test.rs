//! Stage-13 schema integration tests.
//!
//! Each `#[sqlx::test(migrations = "../../migrations")]` provisions a fresh database,
//! applies every migration, and hands over a connected pool — so requirement (a),
//! "run all migrations on a fresh database", is exercised by every test here. The
//! tests then verify inserts, indexes, the 32-byte hash columns, and the
//! append-only / stable-identity guarantees enforced by triggers.
//!
//! Requires a reachable Postgres (DATABASE_URL): the dev container or the CI service.

use engine_shared::{Document, Event, Identity, Node, Snapshot};
use sqlx::{PgPool, Row};

/// Ids of a minimal seeded instrument: an identity, a document, one node, one event.
struct Seed {
    identity_id: uuid::Uuid,
    document_id: uuid::Uuid,
    node_id: String,
    event_id: String,
}

/// A 32-byte SHA-256-shaped digest with a single distinguishing byte.
fn digest(marker: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = marker;
    h
}

/// Insert identity -> document -> node -> genesis event, honoring the FKs.
async fn seed(pool: &PgPool) -> sqlx::Result<Seed> {
    let identity_id: uuid::Uuid = sqlx::query_scalar(
        "insert into identity (email, display_name) values ($1, $2) returning id",
    )
    .bind("author@dynodoc.local")
    .bind("Test Author")
    .fetch_one(pool)
    .await?;

    let document_id: uuid::Uuid =
        sqlx::query_scalar("insert into document (title, created_by) values ($1, $2) returning id")
            .bind("Sample Instrument")
            .bind(identity_id)
            .fetch_one(pool)
            .await?;

    let node_id = ulid::Ulid::generate().to_string();
    sqlx::query(
        "insert into node (id, document_id, parent_id, type, pos, current_fields, var_name)
         values ($1, $2, null, 'item', 'a0', $3, $4)",
    )
    .bind(&node_id)
    .bind(document_id)
    .bind(serde_json::json!({ "label": { "en": "How many hours outdoors?" } }))
    .bind("hours_outdoors")
    .execute(pool)
    .await?;

    let event_id = ulid::Ulid::generate().to_string();
    // Genesis event: prev_chain_hash is 32 zero bytes; chain_hash folds it in.
    sqlx::query(
        "insert into event
           (id, document_id, seq, type, actor_id, target_node_id, payload,
            content_hash, prev_chain_hash, chain_hash)
         values ($1, $2, 1, 'NodeCreated', $3, $4, $5, $6, $7, $8)",
    )
    .bind(&event_id)
    .bind(document_id)
    .bind(identity_id)
    .bind(&node_id)
    .bind(serde_json::json!({ "node_type": "item" }))
    .bind(&digest(0x11)[..]) // content_hash
    .bind(&digest(0x00)[..]) // prev_chain_hash (genesis = zeros)
    .bind(&digest(0x22)[..]) // chain_hash
    .execute(pool)
    .await?;

    Ok(Seed {
        identity_id,
        document_id,
        node_id,
        event_id,
    })
}

/// (b) A sample document + node + event insert, read back through the FromRow types.
#[sqlx::test(migrations = "../../migrations")]
async fn inserts_and_reads_back_core_rows(pool: PgPool) -> sqlx::Result<()> {
    let s = seed(&pool).await?;

    let doc: Document = sqlx::query_as("select * from document where id = $1")
        .bind(s.document_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(doc.title, "Sample Instrument");
    assert_eq!(doc.status, "draft");
    assert_eq!(doc.languages, vec!["en".to_string()]);
    assert_eq!(doc.created_by.map(|i| i.0), Some(s.identity_id));

    let node: Node = sqlx::query_as("select * from node where id = $1")
        .bind(&s.node_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(node.node_type, "item");
    assert_eq!(node.var_name.as_deref(), Some("hours_outdoors"));
    assert!(!node.deleted);

    let ev: Event = sqlx::query_as("select * from event where id = $1")
        .bind(&s.event_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(ev.event_type, "NodeCreated");
    assert_eq!(ev.seq, 1);
    assert_eq!(
        ev.target_node_id.as_ref().map(|n| n.0.as_str()),
        Some(s.node_id.as_str())
    );

    let ident: Identity = sqlx::query_as("select * from identity where id = $1")
        .bind(s.identity_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(ident.email, "author@dynodoc.local");

    Ok(())
}

/// (d) The hash-chain columns accept and store exactly 32-byte values.
#[sqlx::test(migrations = "../../migrations")]
async fn stores_32_byte_chain_hashes(pool: PgPool) -> sqlx::Result<()> {
    let s = seed(&pool).await?;

    let ev: Event = sqlx::query_as("select * from event where id = $1")
        .bind(&s.event_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(ev.content_hash.len(), 32);
    assert_eq!(ev.prev_chain_hash.len(), 32);
    assert_eq!(ev.chain_hash.len(), 32);
    assert_eq!(ev.content_hash[0], 0x11);
    assert_eq!(ev.chain_hash[0], 0x22);

    // A snapshot's roots are likewise 32 bytes and round-trip intact.
    let snap_id: uuid::Uuid = sqlx::query_scalar(
        "insert into snapshot (document_id, through_seq, state, merkle_root, event_chain_hash)
         values ($1, 1, $2, $3, $4) returning id",
    )
    .bind(s.document_id)
    .bind(serde_json::json!({ "nodes": 1 }))
    .bind(&digest(0x33)[..])
    .bind(&digest(0x22)[..])
    .fetch_one(&pool)
    .await?;

    let snap: Snapshot = sqlx::query_as("select * from snapshot where id = $1")
        .bind(snap_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(snap.merkle_root.len(), 32);
    assert_eq!(snap.event_chain_hash, ev.chain_hash);

    Ok(())
}

/// A non-32-byte hash is rejected by the octet_length CHECK constraint.
#[sqlx::test(migrations = "../../migrations")]
async fn rejects_wrong_length_hash(pool: PgPool) -> sqlx::Result<()> {
    let s = seed(&pool).await?;

    let bad = [0u8; 31]; // one byte short
    let res = sqlx::query(
        "insert into event
           (id, document_id, seq, type, actor_id, payload, content_hash, prev_chain_hash, chain_hash)
         values ($1, $2, 2, 'FieldEdited', $3, '{}'::jsonb, $4, $5, $6)",
    )
    .bind(ulid::Ulid::generate().to_string())
    .bind(s.document_id)
    .bind(s.identity_id)
    .bind(&bad[..])
    .bind(&digest(0x22)[..])
    .bind(&digest(0x44)[..])
    .execute(&pool)
    .await;

    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("octet_length") || err.to_lowercase().contains("check"),
        "got: {err}"
    );
    Ok(())
}

/// (c) Every expected index exists (queried via pg_indexes).
#[sqlx::test(migrations = "../../migrations")]
async fn expected_indexes_exist(pool: PgPool) -> sqlx::Result<()> {
    let rows = sqlx::query("select indexname from pg_indexes where schemaname = 'public'")
        .fetch_all(&pool)
        .await?;
    let names: Vec<String> = rows
        .iter()
        .map(|r| r.get::<String, _>("indexname"))
        .collect();

    for expected in [
        // primary keys / unique constraints
        "document_pkey",
        "node_pkey",
        "event_pkey",
        "snapshot_pkey",
        "identity_pkey",
        "magic_link_pkey",
        "event_document_seq_unique",
        "event_document_chain_unique",
        "snapshot_document_seq_unique",
        "identity_email_lower_idx",
        // secondary indexes declared in the migrations
        "document_status_idx",
        "node_document_idx",
        "node_parent_idx",
        "node_varname_idx",
        "node_fields_gin",
        "event_document_seq_idx",
        "event_target_node_idx",
        "event_type_idx",
        "snapshot_latest_idx",
        "magic_link_token_idx",
        "magic_link_identity_idx",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "missing index {expected}; have {names:?}"
        );
    }
    Ok(())
}

/// The event table is append-only: UPDATE and DELETE both raise.
#[sqlx::test(migrations = "../../migrations")]
async fn event_table_is_append_only(pool: PgPool) -> sqlx::Result<()> {
    let s = seed(&pool).await?;

    let upd = sqlx::query("update event set seq = 99 where id = $1")
        .bind(&s.event_id)
        .execute(&pool)
        .await;
    assert!(upd.unwrap_err().to_string().contains("append-only"));

    let del = sqlx::query("delete from event where id = $1")
        .bind(&s.event_id)
        .execute(&pool)
        .await;
    assert!(del
        .unwrap_err()
        .to_string()
        .contains("history is immutable"));

    Ok(())
}

/// node.id is immutable: reassigning it raises; other-column updates are fine.
#[sqlx::test(migrations = "../../migrations")]
async fn node_id_is_immutable(pool: PgPool) -> sqlx::Result<()> {
    let s = seed(&pool).await?;

    // A normal update (not touching id) succeeds.
    sqlx::query("update node set deleted = true where id = $1")
        .bind(&s.node_id)
        .execute(&pool)
        .await?;

    // Reassigning id raises.
    let res = sqlx::query("update node set id = $1 where id = $2")
        .bind(ulid::Ulid::generate().to_string())
        .bind(&s.node_id)
        .execute(&pool)
        .await;
    assert!(res.unwrap_err().to_string().contains("immutable"));
    Ok(())
}

/// content_hash is NOT NULL — omitting it fails before the row lands.
#[sqlx::test(migrations = "../../migrations")]
async fn content_hash_is_not_null(pool: PgPool) -> sqlx::Result<()> {
    let s = seed(&pool).await?;

    let res = sqlx::query(
        "insert into event
           (id, document_id, seq, type, actor_id, payload, prev_chain_hash, chain_hash)
         values ($1, $2, 2, 'FieldEdited', $3, '{}'::jsonb, $4, $5)",
    )
    .bind(ulid::Ulid::generate().to_string())
    .bind(s.document_id)
    .bind(s.identity_id)
    .bind(&digest(0x00)[..])
    .bind(&digest(0x55)[..])
    .execute(&pool)
    .await;

    let err = res.unwrap_err().to_string().to_lowercase();
    assert!(
        err.contains("content_hash") || err.contains("not-null") || err.contains("null value"),
        "got: {err}"
    );
    Ok(())
}

/// Ordering diagnostic audits catalog collations and synthetic ordering without modifying data.
#[sqlx::test(migrations = "../../migrations")]
async fn ordering_audit_diagnoses_catalog_collations(pool: PgPool) -> anyhow::Result<()> {
    let report = engine_core::database::ordering::audit_ordering(&pool).await?;

    // Verifies that the inventory includes the required ID, pos, and reference columns.
    assert!(report
        .columns
        .iter()
        .any(|c| c.table_name == "node" && c.column_name == "id"));
    assert!(report
        .columns
        .iter()
        .any(|c| c.table_name == "node" && c.column_name == "pos"));
    assert!(report
        .columns
        .iter()
        .any(|c| c.table_name == "node" && c.column_name == "parent_id"));
    assert!(report
        .columns
        .iter()
        .any(|c| c.table_name == "event" && c.column_name == "target_node_id"));

    // Foreign keys to node(id) are inventoried
    assert!(report
        .foreign_keys
        .iter()
        .any(|fk| fk.target_table == "node" && fk.target_column == "id"));

    // Synthetic comparisons were evaluated without printing/reading node contents
    assert_eq!(report.comparisons.len(), 5);

    // After migration 0053, all target columns have explicit "C" byte-order collation.
    assert!(
        report.incompatible_columns.is_empty(),
        "incompatible columns: {:?}",
        report.incompatible_columns
    );
    assert!(report.compatible, "expected schema 53 to be compatible");
    for col in &report.columns {
        assert!(
            col.is_byte_order,
            "column {}.{} must have byte-order collation",
            col.table_name, col.column_name
        );
        assert_eq!(col.explicit_collation.as_deref(), Some("C"));
    }
    Ok(())
}

/// Tests schema-47 upgrade path to 0053 byte-order collation with synthetic existing
/// data, foreign key integrity, append-only triggers, and SQL/Rust order parity (NEXT-02).
#[sqlx::test(migrations = "../../migrations")]
async fn byte_order_collation_migration_and_schema47_upgrade(pool: PgPool) -> anyhow::Result<()> {
    // 1. First verify the fully-migrated state (schema 53)
    let report = engine_core::database::ordering::audit_ordering(&pool).await?;
    assert!(report.incompatible_columns.is_empty());
    assert!(report.compatible);

    // 2. Simulate schema 47 (strip explicit collation to "default" on all target columns)
    // to verify the upgrade path and timing from an existing schema-47 deployment.
    sqlx::query("ALTER TABLE event DROP CONSTRAINT IF EXISTS event_target_node_id_fkey")
        .execute(&pool)
        .await?;
    sqlx::query("ALTER TABLE node DROP CONSTRAINT IF EXISTS node_parent_id_fkey")
        .execute(&pool)
        .await?;
    sqlx::query("ALTER TABLE node ALTER COLUMN id TYPE text COLLATE \"default\"")
        .execute(&pool)
        .await?;
    sqlx::query("ALTER TABLE node ALTER COLUMN parent_id TYPE text COLLATE \"default\"")
        .execute(&pool)
        .await?;
    sqlx::query("ALTER TABLE node ALTER COLUMN pos TYPE text COLLATE \"default\"")
        .execute(&pool)
        .await?;
    sqlx::query("ALTER TABLE event ALTER COLUMN target_node_id TYPE text COLLATE \"default\"")
        .execute(&pool)
        .await?;
    sqlx::query(
        "ALTER TABLE change_request_review ALTER COLUMN node_id TYPE text COLLATE \"default\"",
    )
    .execute(&pool)
    .await?;
    sqlx::query("ALTER TABLE node ADD CONSTRAINT node_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES node(id) ON DELETE CASCADE")
        .execute(&pool)
        .await?;
    sqlx::query("ALTER TABLE event ADD CONSTRAINT event_target_node_id_fkey FOREIGN KEY (target_node_id) REFERENCES node(id)")
        .execute(&pool)
        .await?;

    // In simulated schema 47 on non-C database, diagnostic reports incompatible columns
    let pre_report = engine_core::database::ordering::audit_ordering(&pool).await?;
    if !pre_report.database.is_byte_order_default {
        assert!(!pre_report.compatible);
        assert!(!pre_report.incompatible_columns.is_empty());
    }

    // 3. Insert synthetic pre-existing data across documents, parent-child relationships,
    // fractional pos keys ({, |, a0, aO, b, B, etc.), and immutable events.
    let user_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO identity (email, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind("upgrade-test@dynodoc.local")
    .bind("Upgrade Tester")
    .fetch_one(&pool)
    .await?;

    let doc_id: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO document (title, created_by) VALUES ($1, $2) RETURNING id")
            .bind("Upgrade Test Doc")
            .bind(user_id)
            .fetch_one(&pool)
            .await?;

    // Synthetic nodes with various pos keys and IDs
    let synthetic_nodes = vec![
        ("root", None, "000000"),
        ("node_z9", Some("root"), "z9"),
        ("node_pipe", Some("root"), "|"),
        ("node_brace", Some("root"), "{"),
        ("node_x", Some("root"), "x"),
        ("node_r", Some("root"), "r"),
        ("node_f", Some("root"), "f"),
        ("node_aO", Some("root"), "aO"),
        ("node_ab", Some("root"), "ab"),
        ("node_a1", Some("root"), "a1"),
        ("node_a0V", Some("root"), "a0V"),
        ("node_a0", Some("root"), "a0"),
        ("node_O", Some("root"), "O"),
    ];

    for (nid, pid, pos) in &synthetic_nodes {
        sqlx::query(
            "INSERT INTO node (id, document_id, parent_id, type, pos, current_fields) VALUES ($1, $2, $3, 'item', $4, '{}'::jsonb)",
        )
        .bind(nid)
        .bind(doc_id)
        .bind(pid)
        .bind(pos)
        .execute(&pool)
        .await?;
    }

    // Insert referencing event row
    let event_id = ulid::Ulid::generate().to_string();
    sqlx::query(
        "INSERT INTO event (id, document_id, seq, type, actor_id, target_node_id, payload, content_hash, prev_chain_hash, chain_hash) VALUES ($1, $2, 1, 'NodeCreated', $3, 'node_a0', '{}'::jsonb, $4, $5, $6)",
    )
    .bind(&event_id)
    .bind(doc_id)
    .bind(user_id)
    .bind(&[0x11u8; 32][..])
    .bind(&[0u8; 32][..])
    .bind(&[0x22u8; 32][..])
    .execute(&pool)
    .await?;

    // 4. Measure synthetic lock and migration execution timing
    let start_migration = std::time::Instant::now();
    let migration_sql = include_str!("../../../migrations/0053_byte_order_collation.sql");
    sqlx::raw_sql(migration_sql).execute(&pool).await?;
    let migration_elapsed = start_migration.elapsed();
    eprintln!(
        "Synthetic schema-47 to 0053 upgrade completed in {:?}",
        migration_elapsed
    );

    // 5. Verify post-upgrade diagnostic report
    let post_report = engine_core::database::ordering::audit_ordering(&pool).await?;
    assert!(
        post_report.compatible,
        "post-migration report must be compatible"
    );
    assert!(
        post_report.incompatible_columns.is_empty(),
        "incompatible columns must be empty"
    );
    assert_eq!(post_report.ordering_mismatches, 0);

    // 6. Verify exact string values and count preserved
    let row_count: i64 = sqlx::query_scalar("SELECT count(*) FROM node WHERE document_id = $1")
        .bind(doc_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(row_count, synthetic_nodes.len() as i64);

    // 7. Verify SQL/Rust order parity on (pos, id)
    let sql_ordered: Vec<(String, String)> = sqlx::query_as(
        "SELECT pos, id FROM node WHERE document_id = $1 AND parent_id = 'root' ORDER BY pos, id",
    )
    .bind(doc_id)
    .fetch_all(&pool)
    .await?;

    let mut rust_expected: Vec<(String, String)> = synthetic_nodes
        .iter()
        .filter(|(_, p, _)| p.as_deref() == Some("root"))
        .map(|(id, _, pos)| (pos.to_string(), id.to_string()))
        .collect();
    rust_expected.sort();

    assert_eq!(
        sql_ordered, rust_expected,
        "SQL ORDER BY (pos, id) must match Rust tuple sort byte-for-byte"
    );

    // 8. Verify foreign key integrity
    let target_node: String = sqlx::query_scalar("SELECT target_node_id FROM event WHERE id = $1")
        .bind(&event_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(target_node, "node_a0");

    let bad_fk = sqlx::query(
        "INSERT INTO node (id, document_id, parent_id, type, pos) VALUES ('child_bad', $1, 'missing_parent', 'item', 'b0')",
    )
    .bind(doc_id)
    .execute(&pool)
    .await;
    assert!(bad_fk.is_err(), "missing parent must fail FK check");

    // Attempting to delete node_a0 (referenced by event) fails FK constraint
    let del_err = sqlx::query("DELETE FROM node WHERE id = 'node_a0'")
        .execute(&pool)
        .await;
    assert!(
        del_err.is_err(),
        "deleting node referenced by event must fail FK check"
    );

    // Cascade delete on parent removes child for subtrees without referencing events
    sqlx::query(
        "INSERT INTO node (id, document_id, parent_id, type, pos) VALUES ('branch_parent', $1, 'root', 'section', 'c0')",
    )
    .bind(doc_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO node (id, document_id, parent_id, type, pos) VALUES ('branch_child', $1, 'branch_parent', 'item', 'c1')",
    )
    .bind(doc_id)
    .execute(&pool)
    .await?;
    sqlx::query("DELETE FROM node WHERE id = 'branch_parent'")
        .execute(&pool)
        .await?;
    let child_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM node WHERE id = 'branch_child')")
            .fetch_one(&pool)
            .await?;
    assert!(
        !child_exists,
        "deleting branch_parent must cascade to branch_child"
    );

    // 9. Verify append-only / immutability guards
    let imm_err = sqlx::query("UPDATE event SET seq = 999 WHERE id = $1")
        .bind(&event_id)
        .execute(&pool)
        .await;
    assert!(
        imm_err.is_err(),
        "event immutability trigger must remain intact"
    );

    Ok(())
}
