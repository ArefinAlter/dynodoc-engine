//! Synthetic storage growth and incremental storage boundary measurements.
//! Compares full and incremental typed writers across no-op, one-node, scattered,
//! and wholesale edits, plus fallback and rollback cases.
//!
//! cargo run --release -p engine-core --example shared_checkpoint_bench

use std::time::Instant;

use engine_core::{
    materializer::{CommentState, DocumentState, MaterializedNode, SuggestionState},
    shared_checkpoint::{
        read_state,
        typed::{read_state as read_typed_state, update_state, write_state as write_typed_state},
        write_state, Address, Error, Limits, MemoryStore, ObjectStore,
    },
};
use engine_shared::{DocumentId, NodeId};
use serde_json::json;

#[derive(Default)]
struct CountingStore {
    inner: MemoryStore,
    read_calls: usize,
    write_calls: usize,
    stored_addresses: Vec<Address>,
}

impl ObjectStore for CountingStore {
    async fn put(
        &mut self,
        doc: DocumentId,
        address: &Address,
        bytes: &[u8],
    ) -> Result<bool, Error> {
        self.write_calls += 1;
        self.stored_addresses.push(address.clone());
        self.inner.put(doc, address, bytes).await
    }

    async fn get(&mut self, doc: DocumentId, address: &Address) -> Result<Vec<u8>, Error> {
        self.read_calls += 1;
        self.inner.get(doc, address).await
    }
}

fn build_document(node_count: usize, annotation_heavy: bool) -> DocumentState {
    let mut state = DocumentState::default();
    for index in 0..node_count {
        let id = NodeId(format!("{index:026}"));
        let text = if annotation_heavy {
            format!(
                "Section {index} detailed analysis. {}",
                "Deterministic rich legal prose block with long text. ".repeat(16)
            )
        } else {
            "Synthetic document text. ".repeat(24)
        };
        state.nodes.insert(
            id.clone(),
            MaterializedNode {
                id: id.clone(),
                parent_id: None,
                node_type: if index % 10 == 0 {
                    "section".into()
                } else {
                    "paragraph".into()
                },
                pos: format!("p{index:08}"),
                current_fields: json!({
                    "content": { "text": text, "bold": index % 5 == 0 },
                    "meta": { "index": index, "status": "active" }
                }),
                var_name: None,
                deleted: false,
            },
        );

        if annotation_heavy && index % 50 == 0 {
            state.comments.push(CommentState {
                node_id: Some(id.clone()),
                body: format!("Audited verification remark for node {index}"),
            });
            state.suggestions.insert(
                format!("sug_{index}"),
                SuggestionState {
                    target_node_id: Some(id.clone()),
                    detail: json!({"proposed_text": "Amended clause wording."}),
                    accepted: false,
                    rejected_reason: None,
                },
            );
        }
    }

    if annotation_heavy {
        state
            .removed_choices
            .insert(NodeId(format!("{:026}", node_count + 1)));
        state
            .removed_choices
            .insert(NodeId(format!("{:026}", node_count + 2)));
    }

    state
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let doc_id = DocumentId(uuid::Uuid::nil());
    let sizes = if let Ok(val) = std::env::var("DYNODOC_BENCH_NODES") {
        vec![val.parse::<usize>()?]
    } else {
        vec![1000, 8000]
    };

    let mut report = Vec::new();

    for size in sizes {
        for annotation_heavy in [false, true] {
            let workload_name = if annotation_heavy {
                "annotation_heavy"
            } else {
                "standard_paragraphs"
            };
            let base_state = build_document(size, annotation_heavy);
            let baseline_json_bytes = serde_json::to_vec(&base_state)?.len();

            let mut store = CountingStore::default();

            // 1. Initial write with full typed writer
            let start = Instant::now();
            let (initial_root, initial_stats) = write_typed_state(
                &mut store,
                doc_id,
                &base_state,
                Limits::default(),
                Default::default(),
            )
            .await?;
            let initial_write_ms = start.elapsed().as_secs_f64() * 1000.0;

            // Verify initial reconstruction
            let restored = read_typed_state(
                &mut store,
                doc_id,
                &initial_root,
                Limits::default(),
                Default::default(),
            )
            .await?;
            assert_eq!(restored, base_state);

            // 2. Scenario: No-op edit
            let start = Instant::now();
            let (noop_root, noop_stats) = update_state(
                &mut store,
                doc_id,
                &initial_root,
                &base_state,
                &base_state,
                Limits::default(),
                Default::default(),
            )
            .await?;
            let noop_write_ms = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(noop_root, initial_root);
            assert_eq!(noop_stats.new_objects, 0);
            assert_eq!(noop_stats.new_bytes, 0);

            // 3. Scenario: One-node edit
            let mut one_node_state = base_state.clone();
            let target_node_id = NodeId(format!("{:026}", size / 2));
            if let Some(node) = one_node_state.nodes.get_mut(&target_node_id) {
                node.current_fields["meta"]["status"] = json!("updated");
            }
            // Oracle root from full writer
            let (oracle_one_root, oracle_one_stats) = write_typed_state(
                &mut MemoryStore::default(),
                doc_id,
                &one_node_state,
                Limits::default(),
                Default::default(),
            )
            .await?;

            let start = Instant::now();
            let (inc_one_root, inc_one_stats) = update_state(
                &mut store,
                doc_id,
                &initial_root,
                &base_state,
                &one_node_state,
                Limits::default(),
                Default::default(),
            )
            .await?;
            let inc_one_ms = start.elapsed().as_secs_f64() * 1000.0;

            assert_eq!(inc_one_root, oracle_one_root);
            assert!(inc_one_stats.new_objects < oracle_one_stats.new_objects);
            assert!(inc_one_stats.new_bytes < oracle_one_stats.new_bytes);

            let restored_one = read_typed_state(
                &mut store,
                doc_id,
                &inc_one_root,
                Limits::default(),
                Default::default(),
            )
            .await?;
            assert_eq!(restored_one, one_node_state);

            // 4. Scenario: Scattered edits (10 nodes)
            let mut scattered_state = base_state.clone();
            for step in 0..10 {
                let id = NodeId(format!("{:026}", (step * 97) % size));
                if let Some(node) = scattered_state.nodes.get_mut(&id) {
                    node.current_fields["revision"] = json!(step + 1);
                }
            }
            let (oracle_scat_root, oracle_scat_stats) = write_typed_state(
                &mut MemoryStore::default(),
                doc_id,
                &scattered_state,
                Limits::default(),
                Default::default(),
            )
            .await?;

            let start = Instant::now();
            let (inc_scat_root, inc_scat_stats) = update_state(
                &mut store,
                doc_id,
                &initial_root,
                &base_state,
                &scattered_state,
                Limits::default(),
                Default::default(),
            )
            .await?;
            let inc_scat_ms = start.elapsed().as_secs_f64() * 1000.0;

            assert_eq!(inc_scat_root, oracle_scat_root);
            assert!(inc_scat_stats.new_objects < oracle_scat_stats.new_objects);

            // 5. Scenario: Wholesale edits (50% of nodes)
            let mut wholesale_state = base_state.clone();
            for (i, node) in wholesale_state.nodes.values_mut().enumerate() {
                if i % 2 == 0 {
                    node.current_fields["wholesale"] = json!(i);
                }
            }
            let (oracle_who_root, oracle_who_stats) = write_typed_state(
                &mut MemoryStore::default(),
                doc_id,
                &wholesale_state,
                Limits::default(),
                Default::default(),
            )
            .await?;

            let start = Instant::now();
            let (inc_who_root, inc_who_stats) = update_state(
                &mut store,
                doc_id,
                &initial_root,
                &base_state,
                &wholesale_state,
                Limits::default(),
                Default::default(),
            )
            .await?;
            let inc_who_ms = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(inc_who_root, oracle_who_root);

            // 6. Scenario: Unsupported-delta fallback
            // Pass a valid non-State typed object address from the store as base_root
            let non_state_root = store
                .stored_addresses
                .iter()
                .find(|addr| *addr != &initial_root)
                .cloned()
                .unwrap();
            let (fallback_root, _fallback_stats) = update_state(
                &mut store,
                doc_id,
                &non_state_root,
                &base_state,
                &one_node_state,
                Limits::default(),
                Default::default(),
            )
            .await?;
            assert_eq!(fallback_root, oracle_one_root);

            // 7. Scenario: Quota-failure rollback
            let store_count_before = store.inner.object_count();
            let store_bytes_before = store.inner.stored_bytes();
            let impossible_limits = Limits {
                max_objects: 1,
                max_bytes: 10,
            };
            let quota_err = update_state(
                &mut store,
                doc_id,
                &initial_root,
                &base_state,
                &one_node_state,
                impossible_limits,
                Default::default(),
            )
            .await;
            assert!(matches!(quota_err, Err(Error::Limit(_))));
            // Storage accounting is completely unchanged
            assert_eq!(store.inner.object_count(), store_count_before);
            assert_eq!(store.inner.stored_bytes(), store_bytes_before);

            // 8. Legacy V1 comparison for context
            let mut v1_store = MemoryStore::default();
            let (v1_root, v1_initial) =
                write_state(&mut v1_store, doc_id, &base_state, Limits::default()).await?;
            assert_eq!(
                read_state(&mut v1_store, doc_id, &v1_root, Limits::default()).await?,
                base_state
            );

            report.push(json!({
                "nodes": size,
                "workload": workload_name,
                "baseline_json_bytes": baseline_json_bytes,
                "v1_baseline_objects": v1_store.object_count(),
                "v1_baseline_bytes": v1_initial.new_bytes,
                "v2_initial": {
                    "new_objects": initial_stats.new_objects,
                    "new_bytes": initial_stats.new_bytes,
                    "visited_objects": initial_stats.visited_objects,
                    "write_ms": initial_write_ms,
                },
                "noop_update": {
                    "new_objects": noop_stats.new_objects,
                    "new_bytes": noop_stats.new_bytes,
                    "write_ms": noop_write_ms,
                },
                "one_node_edit": {
                    "incremental_new_objects": inc_one_stats.new_objects,
                    "incremental_new_bytes": inc_one_stats.new_bytes,
                    "incremental_visited_objects": inc_one_stats.visited_objects,
                    "incremental_ms": inc_one_ms,
                    "oracle_full_new_objects": oracle_one_stats.new_objects,
                    "oracle_full_new_bytes": oracle_one_stats.new_bytes,
                    "object_savings_pct": (1.0 - (inc_one_stats.new_objects as f64 / oracle_one_stats.new_objects as f64)) * 100.0,
                    "byte_savings_pct": (1.0 - (inc_one_stats.new_bytes as f64 / oracle_one_stats.new_bytes as f64)) * 100.0,
                },
                "scattered_edits_10_nodes": {
                    "incremental_new_objects": inc_scat_stats.new_objects,
                    "incremental_new_bytes": inc_scat_stats.new_bytes,
                    "incremental_ms": inc_scat_ms,
                    "oracle_full_new_objects": oracle_scat_stats.new_objects,
                    "oracle_full_new_bytes": oracle_scat_stats.new_bytes,
                    "object_savings_pct": (1.0 - (inc_scat_stats.new_objects as f64 / oracle_scat_stats.new_objects as f64)) * 100.0,
                },
                "wholesale_edits_50pct": {
                    "incremental_new_objects": inc_who_stats.new_objects,
                    "incremental_new_bytes": inc_who_stats.new_bytes,
                    "incremental_ms": inc_who_ms,
                    "oracle_full_new_objects": oracle_who_stats.new_objects,
                },
                "fallback_verified": true,
                "quota_rollback_verified": true,
                "store_total_unique_objects": store.inner.object_count(),
                "store_total_unique_bytes": store.inner.stored_bytes(),
            }));
        }
    }

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
