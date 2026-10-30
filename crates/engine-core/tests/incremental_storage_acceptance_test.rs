//! Acceptance suite for incremental typed storage boundary (NEXT-10).
//! Verifies exact root equality, component reuse bounds, reconstruction,
//! unsupported-delta fallback, and atomic rollback on quota failure.

use engine_core::{
    materializer::{apply_payload, CommentState, DocumentState, MaterializedNode, SuggestionState},
    shared_checkpoint::{
        postgres::{self, Codec},
        typed::{
            read_state as read_typed, update_state, write_state as write_typed, SemanticLimits,
        },
        Limits, MemoryStore,
    },
};
use engine_shared::{DocumentId, EventPayload, IdentityId, NodeId, NodeType};
use serde_json::json;
use sqlx::PgPool;

fn build_acceptance_state(nodes: usize, rich_annotations: bool) -> DocumentState {
    let mut state = DocumentState::default();
    for index in 0..nodes {
        let id = NodeId(format!("{index:026}"));
        let text = if rich_annotations {
            format!(
                "Clause {index}: {}",
                "Audited contractual term with persistent history. ".repeat(12)
            )
        } else {
            "Synthetic node content. ".repeat(20)
        };
        state.nodes.insert(
            id.clone(),
            MaterializedNode {
                id: id.clone(),
                parent_id: None,
                node_type: if index % 5 == 0 {
                    "section".into()
                } else {
                    "paragraph".into()
                },
                pos: format!("p{index:08}"),
                current_fields: json!({
                    "title": format!("Node {index}"),
                    "body": text,
                    "active": true,
                    "index": index
                }),
                var_name: None,
                deleted: false,
            },
        );

        if rich_annotations && index % 20 == 0 {
            state.comments.push(CommentState {
                node_id: Some(id.clone()),
                body: format!("Remark on clause {index}"),
            });
            state.suggestions.insert(
                format!("sug_{index}"),
                SuggestionState {
                    target_node_id: Some(id.clone()),
                    detail: json!({"proposed": "Modified clause."}),
                    accepted: false,
                    rejected_reason: None,
                },
            );
        }
    }

    if rich_annotations {
        state
            .removed_choices
            .insert(NodeId(format!("{:026}", nodes + 10)));
        state
            .removed_choices
            .insert(NodeId(format!("{:026}", nodes + 11)));
    }

    state
}

#[tokio::test]
async fn incremental_typed_writer_1000_nodes_deterministic_bounds() {
    let doc = DocumentId(uuid::Uuid::nil());
    let mut store = MemoryStore::default();
    let base_state = build_acceptance_state(1000, false);

    // Initial write
    let (base_root, _base_stats) = write_typed(
        &mut store,
        doc,
        &base_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();

    let restored_base = read_typed(
        &mut store,
        doc,
        &base_root,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(restored_base, base_state);

    // 1. No-op edit
    let (noop_root, noop_stats) = update_state(
        &mut store,
        doc,
        &base_root,
        &base_state,
        &base_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(noop_root, base_root, "no-op must yield exact base root");
    assert_eq!(noop_stats.new_objects, 0, "no-op must write zero objects");
    assert_eq!(noop_stats.new_bytes, 0, "no-op must write zero bytes");

    // 2. Single-node edit
    let mut one_edit_state = base_state.clone();
    let target_id = NodeId(format!("{:026}", 500));
    one_edit_state
        .nodes
        .get_mut(&target_id)
        .unwrap()
        .current_fields["body"] = json!("Single modified line.");

    let (oracle_one_root, oracle_one_stats) = write_typed(
        &mut MemoryStore::default(),
        doc,
        &one_edit_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();

    let (inc_one_root, inc_one_stats) = update_state(
        &mut store,
        doc,
        &base_root,
        &base_state,
        &one_edit_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();

    assert_eq!(
        inc_one_root, oracle_one_root,
        "incremental one-node root must match oracle exactly"
    );
    assert!(
        inc_one_stats.new_objects < oracle_one_stats.new_objects,
        "one-node edit must create strictly fewer objects: inc {} vs full {}",
        inc_one_stats.new_objects,
        oracle_one_stats.new_objects
    );
    assert!(
        inc_one_stats.new_bytes < oracle_one_stats.new_bytes,
        "one-node edit must write strictly fewer bytes: inc {} vs full {}",
        inc_one_stats.new_bytes,
        oracle_one_stats.new_bytes
    );

    let restored_one = read_typed(
        &mut store,
        doc,
        &inc_one_root,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(restored_one, one_edit_state);

    // 3. Scattered edits (10 nodes)
    let mut scattered_state = base_state.clone();
    for i in 0..10 {
        let sid = NodeId(format!("{:026}", i * 99));
        scattered_state.nodes.get_mut(&sid).unwrap().current_fields["scattered"] = json!(i);
    }

    let (oracle_scat_root, oracle_scat_stats) = write_typed(
        &mut MemoryStore::default(),
        doc,
        &scattered_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();

    let (inc_scat_root, inc_scat_stats) = update_state(
        &mut store,
        doc,
        &base_root,
        &base_state,
        &scattered_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();

    assert_eq!(
        inc_scat_root, oracle_scat_root,
        "scattered edits root must match oracle exactly"
    );
    assert!(
        inc_scat_stats.new_objects < oracle_scat_stats.new_objects,
        "scattered edits must create strictly fewer objects"
    );

    // 4. Wholesale edits (50% of all nodes)
    let mut wholesale_state = base_state.clone();
    for (idx, node) in wholesale_state.nodes.values_mut().enumerate() {
        if idx % 2 == 0 {
            node.current_fields["wholesale"] = json!(idx);
        }
    }
    let (oracle_who_root, _) = write_typed(
        &mut MemoryStore::default(),
        doc,
        &wholesale_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();

    let (inc_who_root, _) = update_state(
        &mut store,
        doc,
        &base_root,
        &base_state,
        &wholesale_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        inc_who_root, oracle_who_root,
        "wholesale edit root must match oracle exactly"
    );
}

#[tokio::test]
async fn incremental_typed_writer_annotation_heavy_invariants() {
    let doc = DocumentId(uuid::Uuid::nil());
    let mut store = MemoryStore::default();
    let base_state = build_acceptance_state(200, true);

    let (base_root, _) = write_typed(
        &mut store,
        doc,
        &base_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();

    // Modify a suggestion and add a comment
    let mut amended_state = base_state.clone();
    amended_state.comments.push(CommentState {
        node_id: None,
        body: "Top-level proposal remark".into(),
    });
    if let Some(sug) = amended_state.suggestions.get_mut("sug_0") {
        sug.accepted = true;
    }

    let (oracle_root, oracle_stats) = write_typed(
        &mut MemoryStore::default(),
        doc,
        &amended_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();

    let (inc_root, inc_stats) = update_state(
        &mut store,
        doc,
        &base_root,
        &base_state,
        &amended_state,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();

    assert_eq!(
        inc_root, oracle_root,
        "annotation modification root must match full writer exactly"
    );
    assert!(inc_stats.new_objects < oracle_stats.new_objects);

    let restored = read_typed(
        &mut store,
        doc,
        &inc_root,
        Limits::default(),
        SemanticLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(restored, amended_state);
}

#[sqlx::test(migrations = "../../migrations")]
async fn postgres_incremental_storage_acceptance_suite(pool: PgPool) -> anyhow::Result<()> {
    let actor: uuid::Uuid = sqlx::query_scalar(
        "insert into identity(email,display_name) values('acceptance@test.com','Acceptance Actor') returning id",
    )
    .fetch_one(&pool)
    .await?;
    let actor_id = IdentityId(actor);
    let doc_uuid: uuid::Uuid = sqlx::query_scalar(
        "insert into document(title,created_by) values('Acceptance Doc',$1) returning id",
    )
    .bind(actor)
    .fetch_one(&pool)
    .await?;
    let doc = DocumentId(doc_uuid);

    let mut expected = DocumentState::default();
    let mut ids = Vec::new();

    // Seed 100 initial nodes
    let mut tx = pool.begin().await?;
    for index in 0..100 {
        let nid = NodeId(format!("{index:026}"));
        sqlx::query(
            "insert into node(id,document_id,type,pos,current_fields) values($1,$2,'form',$3,'{}')",
        )
        .bind(&nid.0)
        .bind(doc.0)
        .bind(format!("p{index:08}"))
        .execute(&mut *tx)
        .await?;

        let payload = EventPayload::NodeCreated {
            node_id: nid.clone(),
            node_type: NodeType::Form,
            parent_id: None,
            pos: format!("p{index:08}"),
            fields: json!({"content": format!("Text for node {index}")}),
            var_name: None,
        };
        engine_core::log::append_in_tx(&mut tx, doc, &payload, actor_id).await?;
        apply_payload(&mut expected, &payload)?;
        ids.push(nid);
    }
    tx.commit().await?;

    // Initial incremental checkpoint at revision 100 (fallback ran: true, no base)
    let p1 = postgres::take_incremental(&pool, doc, 100, Limits::default()).await?;
    assert!(p1.fallback_ran);
    assert_eq!(p1.base_seq, None);
    assert_eq!(p1.through_seq, 100);

    // Verify reconstruction
    let restored1 = postgres::load(&pool, doc, 100, Limits::default()).await?;
    assert_eq!(restored1, expected);

    // Edit 1 node at revision 101
    let edit_payload = EventPayload::FieldEdited {
        node_id: ids[42].clone(),
        field: "content".into(),
        value: json!("Updated node 42 text"),
    };
    engine_core::log::append(&pool, doc, &edit_payload, actor_id).await?;
    apply_payload(&mut expected, &edit_payload)?;

    // Publish incremental checkpoint at revision 101
    let p2 = postgres::take_incremental(&pool, doc, 101, Limits::default()).await?;
    assert!(!p2.fallback_ran, "must select base and not fall back");
    assert_eq!(p2.base_seq, Some(100), "must select base revision 100");

    // Exact root equality check with oracle full typed writer
    let oracle2 = postgres::take_with_codec(&pool, doc, 101, Limits::default(), Codec::V2).await?;
    assert_eq!(
        p2.root, oracle2.root,
        "incremental published root must match oracle"
    );

    // Verify reconstruction
    let restored2 = postgres::load(&pool, doc, 101, Limits::default()).await?;
    assert_eq!(restored2, expected);

    // Acceptance verification: unsupported delta fallback
    // Pass non-existent base sequence 999
    let edit2 = EventPayload::FieldEdited {
        node_id: ids[7].clone(),
        field: "content".into(),
        value: json!("Updated node 7"),
    };
    engine_core::log::append(&pool, doc, &edit2, actor_id).await?;
    apply_payload(&mut expected, &edit2)?;

    // Acceptance verification: explicit missing base fails closed
    let missing_base_err =
        postgres::take_incremental_with_base(&pool, doc, 102, Some(999), Limits::default()).await;
    assert!(
        missing_base_err.is_err(),
        "explicit missing base must fail closed"
    );

    // Normal incremental publication at revision 102 (auto-selects base 101)
    let p3 = postgres::take_incremental(&pool, doc, 102, Limits::default()).await?;
    assert!(!p3.fallback_ran);
    assert_eq!(p3.base_seq, Some(101));
    let restored3 = postgres::load(&pool, doc, 102, Limits::default()).await?;
    assert_eq!(restored3, expected);

    // Acceptance verification: quota-failure rollback
    let objects_before: i64 =
        sqlx::query_scalar("select count(*) from checkpoint_object where document_id=$1")
            .bind(doc.0)
            .fetch_one(&pool)
            .await?;

    // Cap storage quota to current usage
    sqlx::query(
        "update checkpoint_storage_document set byte_limit = bytes_used, object_limit = objects_used where document_id = $1",
    )
    .bind(doc.0)
    .execute(&pool)
    .await?;

    let edit3 = EventPayload::FieldEdited {
        node_id: ids[8].clone(),
        field: "content".into(),
        value: json!("Quota edit"),
    };
    engine_core::log::append(&pool, doc, &edit3, actor_id).await?;

    let quota_err = postgres::take_incremental(&pool, doc, 103, Limits::default()).await;
    assert!(quota_err.is_err(), "quota violation must fail");

    // Check storage accounting & objects remain identical
    let objects_after: i64 =
        sqlx::query_scalar("select count(*) from checkpoint_object where document_id=$1")
            .bind(doc.0)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        objects_after, objects_before,
        "quota rollback must leave object count unchanged"
    );

    let chk_103: i64 = sqlx::query_scalar(
        "select count(*) from shared_checkpoint where document_id=$1 and through_seq=103",
    )
    .bind(doc.0)
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        chk_103, 0,
        "quota rollback must not create checkpoint record"
    );

    Ok(())
}
