//! Historical file diff across commits and offline archives without extracting files to disk.
use super::{Address, Error, FileEntry};
use crate::materializer::DocumentState;
use crate::workspace_merge;
use engine_shared::DocumentId;
use serde::{Deserialize, Serialize};
use similar::TextDiff;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeChangeKind {
    Added,
    Deleted,
    Modified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeChange {
    pub kind: NodeChangeKind,
    pub node_id: String,
    pub node_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalDiffReport {
    pub commit_a: Address,
    pub path_a: String,
    pub document_a: DocumentId,
    pub state_a: Address,
    pub commit_b: Address,
    pub path_b: String,
    pub document_b: DocumentId,
    pub state_b: Address,
    pub is_identical: bool,
    pub node_changes: Vec<NodeChange>,
    pub events: Vec<serde_json::Value>,
    pub unified_diff: String,
}

/// Produce deterministic canonical string lines for nodes in a document state.
pub fn canonical_node_lines(state: &DocumentState) -> Vec<String> {
    let mut nodes: Vec<_> = state.nodes.values().filter(|n| !n.deleted).collect();
    nodes.sort_by(|a, b| a.pos.cmp(&b.pos).then_with(|| a.id.0.cmp(&b.id.0)));
    nodes
        .into_iter()
        .map(|n| {
            let fields = serde_json::to_string(&n.current_fields).unwrap_or_default();
            match &n.var_name {
                Some(v) => {
                    format!(
                        "{}: {} pos={} var={}: {}",
                        n.id.0, n.node_type, n.pos, v, fields
                    )
                }
                None => format!("{}: {} pos={}: {}", n.id.0, n.node_type, n.pos, fields),
            }
        })
        .collect()
}

/// Compute a structured and unified structural diff between two historical file states.
#[allow(clippy::too_many_arguments)]
pub fn diff_states(
    commit_a_addr: &Address,
    path_a: &str,
    file_a: &FileEntry,
    state_a: &DocumentState,
    commit_b_addr: &Address,
    path_b: &str,
    file_b: &FileEntry,
    state_b: &DocumentState,
) -> Result<HistoricalDiffReport, Error> {
    if file_a.state == file_b.state && path_a == path_b {
        return Ok(HistoricalDiffReport {
            commit_a: commit_a_addr.clone(),
            path_a: path_a.to_string(),
            document_a: file_a.document,
            state_a: file_a.state.clone(),
            commit_b: commit_b_addr.clone(),
            path_b: path_b.to_string(),
            document_b: file_b.document,
            state_b: file_b.state.clone(),
            is_identical: true,
            node_changes: Vec::new(),
            events: Vec::new(),
            unified_diff: String::new(),
        });
    }

    let a_lines = canonical_node_lines(state_a);
    let b_lines = canonical_node_lines(state_b);
    let a_text = if a_lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", a_lines.join("\n"))
    };
    let b_text = if b_lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", b_lines.join("\n"))
    };

    let text_diff = TextDiff::from_lines(&a_text, &b_text);
    let has_text_diff = text_diff
        .ops()
        .iter()
        .any(|op| op.tag() != similar::DiffTag::Equal);

    let unified_diff = if has_text_diff {
        text_diff
            .unified_diff()
            .header(
                &format!("a/{} ({})", path_a, commit_a_addr.as_str()),
                &format!("b/{} ({})", path_b, commit_b_addr.as_str()),
            )
            .context_radius(3)
            .to_string()
    } else {
        String::new()
    };

    let events = workspace_merge::diff(state_a, state_b)
        .map_err(|_e| Error::Invalid("failed to compute semantic diff"))?
        .into_iter()
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();

    let mut node_changes = Vec::new();
    let mut all_node_ids: BTreeSet<_> = state_a.nodes.keys().collect();
    for id in state_b.nodes.keys() {
        all_node_ids.insert(id);
    }

    for id in all_node_ids {
        let in_a = state_a.nodes.get(id).filter(|n| !n.deleted);
        let in_b = state_b.nodes.get(id).filter(|n| !n.deleted);
        match (in_a, in_b) {
            (None, Some(b)) => {
                node_changes.push(NodeChange {
                    kind: NodeChangeKind::Added,
                    node_id: b.id.0.clone(),
                    node_type: b.node_type.clone(),
                    before: None,
                    after: Some(b.current_fields.clone()),
                });
            }
            (Some(a), None) => {
                node_changes.push(NodeChange {
                    kind: NodeChangeKind::Deleted,
                    node_id: a.id.0.clone(),
                    node_type: a.node_type.clone(),
                    before: Some(a.current_fields.clone()),
                    after: None,
                });
            }
            (Some(a), Some(b)) => {
                if a.current_fields != b.current_fields
                    || a.node_type != b.node_type
                    || a.pos != b.pos
                    || a.var_name != b.var_name
                {
                    node_changes.push(NodeChange {
                        kind: NodeChangeKind::Modified,
                        node_id: b.id.0.clone(),
                        node_type: b.node_type.clone(),
                        before: Some(a.current_fields.clone()),
                        after: Some(b.current_fields.clone()),
                    });
                }
            }
            (None, None) => {}
        }
    }

    let is_identical = !has_text_diff && node_changes.is_empty();

    Ok(HistoricalDiffReport {
        commit_a: commit_a_addr.clone(),
        path_a: path_a.to_string(),
        document_a: file_a.document,
        state_a: file_a.state.clone(),
        commit_b: commit_b_addr.clone(),
        path_b: path_b.to_string(),
        document_b: file_b.document,
        state_b: file_b.state.clone(),
        is_identical,
        node_changes,
        events,
        unified_diff,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materializer::MaterializedNode;
    use engine_shared::NodeId;

    fn make_entry(doc_u128: u128, state_byte: &str) -> FileEntry {
        FileEntry {
            document: DocumentId(uuid::Uuid::from_u128(doc_u128)),
            state: Address::try_from(state_byte.repeat(64)).unwrap(),
        }
    }

    fn make_node(id_str: &str, pos_str: &str, label: &str) -> MaterializedNode {
        MaterializedNode {
            id: NodeId(id_str.to_string()),
            parent_id: None,
            node_type: "paragraph".into(),
            pos: pos_str.to_string(),
            var_name: None,
            deleted: false,
            current_fields: serde_json::json!({ "label": label }),
        }
    }

    #[test]
    fn test_identical_diff_is_noop() {
        let commit_a = Address::try_from("aa".repeat(32)).unwrap();
        let commit_b = Address::try_from("bb".repeat(32)).unwrap();
        let file_a = make_entry(1, "1");
        let file_b = make_entry(1, "1");

        let mut state = DocumentState::default();
        state
            .nodes
            .insert(NodeId("001".into()), make_node("001", "p01", "Hello"));

        let report = diff_states(
            &commit_a, "doc.docx", &file_a, &state, &commit_b, "doc.docx", &file_b, &state,
        )
        .unwrap();

        assert!(report.is_identical);
        assert!(report.unified_diff.is_empty());
        assert!(report.node_changes.is_empty());
        assert!(report.events.is_empty());
    }

    #[test]
    fn test_text_modification_diff() {
        let commit_a = Address::try_from("aa".repeat(32)).unwrap();
        let commit_b = Address::try_from("bb".repeat(32)).unwrap();
        let file_a = make_entry(1, "1");
        let file_b = make_entry(1, "2");

        let mut state_a = DocumentState::default();
        state_a
            .nodes
            .insert(NodeId("001".into()), make_node("001", "p01", "Genesis"));

        let mut state_b = DocumentState::default();
        state_b
            .nodes
            .insert(NodeId("001".into()), make_node("001", "p01", "Modified"));

        let report = diff_states(
            &commit_a, "doc.docx", &file_a, &state_a, &commit_b, "doc.docx", &file_b, &state_b,
        )
        .unwrap();

        assert!(!report.is_identical);
        assert_eq!(report.node_changes.len(), 1);
        assert_eq!(report.node_changes[0].kind, NodeChangeKind::Modified);
        assert!(report
            .unified_diff
            .contains("-001: paragraph pos=p01: {\"label\":\"Genesis\"}"));
        assert!(report
            .unified_diff
            .contains("+001: paragraph pos=p01: {\"label\":\"Modified\"}"));
    }

    #[test]
    fn test_node_insertion_and_deletion_diff() {
        let commit_a = Address::try_from("aa".repeat(32)).unwrap();
        let commit_b = Address::try_from("bb".repeat(32)).unwrap();
        let file_a = make_entry(1, "1");
        let file_b = make_entry(1, "2");

        let mut state_a = DocumentState::default();
        state_a
            .nodes
            .insert(NodeId("001".into()), make_node("001", "p01", "Keep"));
        state_a
            .nodes
            .insert(NodeId("002".into()), make_node("002", "p02", "To Delete"));

        let mut state_b = DocumentState::default();
        state_b
            .nodes
            .insert(NodeId("001".into()), make_node("001", "p01", "Keep"));
        state_b.nodes.insert(
            NodeId("003".into()),
            make_node("003", "p03", "Newly Inserted"),
        );

        let report = diff_states(
            &commit_a, "doc.docx", &file_a, &state_a, &commit_b, "doc.docx", &file_b, &state_b,
        )
        .unwrap();

        assert!(!report.is_identical);
        assert_eq!(report.node_changes.len(), 2);
        let deleted = report
            .node_changes
            .iter()
            .find(|c| c.kind == NodeChangeKind::Deleted)
            .unwrap();
        assert_eq!(deleted.node_id, "002");
        let added = report
            .node_changes
            .iter()
            .find(|c| c.kind == NodeChangeKind::Added)
            .unwrap();
        assert_eq!(added.node_id, "003");
        assert!(report.unified_diff.contains("-002: paragraph pos=p02:"));
        assert!(report.unified_diff.contains("+003: paragraph pos=p03:"));
    }
}
