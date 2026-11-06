//! Historical file diff across commits and offline archives without extracting files to disk.
use super::{hex, Address, Error, FileEntry};
use crate::materializer::{DocumentState, MaterializedNode};
use crate::workspace_merge;
use engine_shared::DocumentId;
use serde::{Deserialize, Serialize};
use similar::TextDiff;
use std::collections::BTreeSet;

/// Most node changes one report lists, and the most diff bytes it carries; whatever is
/// left out is counted in `omitted`. The event list is all or nothing, because a partial
/// list is not a patch: it is listed whole within these limits or not at all.
const MAX_NODE_CHANGES: usize = 1_000;
const MAX_EVENTS: usize = 1_000;
const MAX_EVENT_BYTES: usize = 256 * 1024;
const MAX_DIFF_BYTES: usize = 256 * 1024;
/// Largest value or diff line shown whole; longer text is replaced by its length and SHA-256.
const MAX_VALUE_BYTES: usize = 4 * 1024;

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
    /// For a modified node: which of fields, type, position, parent and var_name differ.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed: Vec<String>,
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
    /// Complete-state equality for the same document: nodes with their parents,
    /// tombstones and variable names, comments, suggestions and removed choices.
    pub is_identical: bool,
    /// Differences that are not live-node changes: document, comments, suggestions,
    /// removed_choices, tombstones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_differs: Vec<String>,
    pub node_changes: Vec<NodeChange>,
    pub events: Vec<serde_json::Value>,
    /// Why `events` is empty when a change exists: a comparison is not an executable
    /// patch for every pair of states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_unavailable: Option<String>,
    pub unified_diff: String,
    /// Output left out to stay within the report limits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omitted: Vec<String>,
}

fn digest(text: &str) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref())
}

fn json_text(value: &serde_json::Value) -> Result<String, Error> {
    serde_json::to_string(value).map_err(|_| Error::Invalid("node fields are not serializable"))
}

/// A field value as reported: whole when small, otherwise its length and SHA-256.
fn bounded_value(value: &serde_json::Value) -> Result<serde_json::Value, Error> {
    let text = json_text(value)?;
    if text.len() <= MAX_VALUE_BYTES {
        return Ok(value.clone());
    }
    Ok(serde_json::json!({"omitted_bytes": text.len(), "sha256": digest(&text)}))
}

/// Produce deterministic canonical string lines for the live nodes of a document state.
/// A value over the limit is shown as its length and SHA-256, so changing it still shows.
pub fn canonical_node_lines(state: &DocumentState) -> Result<Vec<String>, Error> {
    let mut nodes: Vec<_> = state.nodes.values().filter(|n| !n.deleted).collect();
    nodes.sort_by(|a, b| a.pos.cmp(&b.pos).then_with(|| a.id.0.cmp(&b.id.0)));
    nodes
        .into_iter()
        .map(|n| {
            let mut fields = json_text(&n.current_fields)?;
            if fields.len() > MAX_VALUE_BYTES {
                fields = format!(
                    "<omitted {} bytes sha256={}>",
                    fields.len(),
                    digest(&fields)
                );
            }
            let parent = n
                .parent_id
                .as_ref()
                .map_or(String::new(), |p| format!(" parent={}", p.0));
            let var = n
                .var_name
                .as_ref()
                .map_or(String::new(), |v| format!(" var={v}"));
            Ok(format!(
                "{}: {} pos={}{parent}{var}: {}",
                n.id.0, n.node_type, n.pos, fields
            ))
        })
        .collect()
}

fn changed_aspects(a: &MaterializedNode, b: &MaterializedNode) -> Vec<String> {
    [
        ("fields", a.current_fields != b.current_fields),
        ("type", a.node_type != b.node_type),
        ("position", a.pos != b.pos),
        ("parent", a.parent_id != b.parent_id),
        ("var_name", a.var_name != b.var_name),
    ]
    .into_iter()
    .filter(|(_, differs)| *differs)
    .map(|(name, _)| name.to_string())
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
    let same_document = file_a.document == file_b.document;
    let mut also_differs = Vec::new();
    if !same_document {
        also_differs.push("document".to_string());
    }
    if state_a.comments != state_b.comments {
        also_differs.push("comments".into());
    }
    if state_a.suggestions != state_b.suggestions {
        also_differs.push("suggestions".into());
    }
    if state_a.removed_choices != state_b.removed_choices {
        also_differs.push("removed_choices".into());
    }
    let tombstones = |s: &DocumentState| {
        s.nodes
            .values()
            .filter(|n| n.deleted)
            .cloned()
            .collect::<Vec<_>>()
    };
    if tombstones(state_a) != tombstones(state_b) {
        also_differs.push("tombstones".into());
    }

    let mut report = HistoricalDiffReport {
        commit_a: commit_a_addr.clone(),
        path_a: path_a.to_string(),
        document_a: file_a.document,
        state_a: file_a.state.clone(),
        commit_b: commit_b_addr.clone(),
        path_b: path_b.to_string(),
        document_b: file_b.document,
        state_b: file_b.state.clone(),
        is_identical: same_document && state_a == state_b,
        also_differs,
        node_changes: Vec::new(),
        events: Vec::new(),
        events_unavailable: None,
        unified_diff: String::new(),
        omitted: Vec::new(),
    };
    if report.is_identical {
        return Ok(report);
    }

    let lines = |s: &DocumentState| -> Result<String, Error> {
        let lines = canonical_node_lines(s)?;
        Ok(if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        })
    };
    let (a_text, b_text) = (lines(state_a)?, lines(state_b)?);
    let text_diff = TextDiff::from_lines(&a_text, &b_text);
    if text_diff
        .ops()
        .iter()
        .any(|op| op.tag() != similar::DiffTag::Equal)
    {
        let mut unified = text_diff
            .unified_diff()
            .header(
                &format!("a/{} ({})", path_a, commit_a_addr.as_str()),
                &format!("b/{} ({})", path_b, commit_b_addr.as_str()),
            )
            .context_radius(3)
            .to_string();
        if unified.len() > MAX_DIFF_BYTES {
            let mut cut = MAX_DIFF_BYTES;
            while !unified.is_char_boundary(cut) {
                cut -= 1;
            }
            report.omitted.push(format!(
                "unified_diff: {} of {} bytes",
                unified.len() - cut,
                unified.len()
            ));
            unified.truncate(cut);
        }
        report.unified_diff = unified;
    }

    match workspace_merge::diff(state_a, state_b) {
        Ok(list) => {
            let (mut events, mut bytes, mut reason) = (Vec::new(), 0usize, None);
            for event in list {
                if events.len() == MAX_EVENTS {
                    reason = Some(format!("more than {MAX_EVENTS} events"));
                    break;
                }
                match serde_json::to_value(&event) {
                    Ok(value) => {
                        bytes += value.to_string().len();
                        if bytes > MAX_EVENT_BYTES {
                            reason = Some(format!("events exceed {MAX_EVENT_BYTES} bytes"));
                            break;
                        }
                        events.push(value);
                    }
                    Err(e) => {
                        reason = Some(format!("events cannot be serialized: {e}"));
                        break;
                    }
                }
            }
            match reason {
                Some(reason) => report.events_unavailable = Some(reason),
                None => report.events = events,
            }
        }
        Err(e) => {
            report.events_unavailable =
                Some(format!("no event sequence turns state a into state b: {e}"));
        }
    }

    let ids: BTreeSet<_> = state_a.nodes.keys().chain(state_b.nodes.keys()).collect();
    let mut total_changes = 0usize;
    for id in ids {
        let in_a = state_a.nodes.get(id).filter(|n| !n.deleted);
        let in_b = state_b.nodes.get(id).filter(|n| !n.deleted);
        let change = match (in_a, in_b) {
            (None, Some(b)) => Some((NodeChangeKind::Added, b, Vec::new(), None, Some(b))),
            (Some(a), None) => Some((NodeChangeKind::Deleted, a, Vec::new(), Some(a), None)),
            (Some(a), Some(b)) => {
                let changed = changed_aspects(a, b);
                (!changed.is_empty()).then_some((
                    NodeChangeKind::Modified,
                    b,
                    changed,
                    Some(a),
                    Some(b),
                ))
            }
            (None, None) => None,
        };
        let Some((kind, node, changed, before, after)) = change else {
            continue;
        };
        total_changes += 1;
        if report.node_changes.len() < MAX_NODE_CHANGES {
            report.node_changes.push(NodeChange {
                kind,
                node_id: node.id.0.clone(),
                node_type: node.node_type.clone(),
                changed,
                before: before
                    .map(|n| bounded_value(&n.current_fields))
                    .transpose()?,
                after: after
                    .map(|n| bounded_value(&n.current_fields))
                    .transpose()?,
            });
        }
    }
    if total_changes > MAX_NODE_CHANGES {
        report.omitted.push(format!(
            "node_changes: {} of {total_changes}",
            total_changes - MAX_NODE_CHANGES
        ));
    }
    Ok(report)
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

    fn diff(
        file_a: &FileEntry,
        a: &DocumentState,
        file_b: &FileEntry,
        b: &DocumentState,
    ) -> HistoricalDiffReport {
        let (commit_a, commit_b) = (
            Address::try_from("aa".repeat(32)).unwrap(),
            Address::try_from("bb".repeat(32)).unwrap(),
        );
        diff_states(
            &commit_a, "doc.docx", file_a, a, &commit_b, "doc.docx", file_b, b,
        )
        .unwrap()
    }

    fn one_node(node: MaterializedNode) -> DocumentState {
        let mut state = DocumentState::default();
        state.nodes.insert(node.id.clone(), node);
        state
    }

    #[test]
    fn a_parent_only_move_is_a_change() {
        let mut moved = make_node("001", "p01", "Same");
        moved.parent_id = Some(NodeId("000".into()));
        let report = diff(
            &make_entry(1, "1"),
            &one_node(make_node("001", "p01", "Same")),
            &make_entry(1, "2"),
            &one_node(moved),
        );
        assert!(!report.is_identical);
        assert_eq!(report.node_changes.len(), 1);
        assert_eq!(report.node_changes[0].changed, vec!["parent".to_string()]);
        assert!(report
            .unified_diff
            .contains("+001: paragraph pos=p01 parent=000:"));
    }

    #[test]
    fn annotations_and_tombstones_alone_are_not_identical() {
        let base = one_node(make_node("001", "p01", "Same"));

        let mut commented = base.clone();
        commented.comments.push(crate::materializer::CommentState {
            node_id: Some(NodeId("001".into())),
            body: "Retained review".into(),
        });
        let report = diff(&make_entry(1, "1"), &base, &make_entry(1, "2"), &commented);
        assert!(!report.is_identical && report.node_changes.is_empty());
        assert_eq!(report.also_differs, vec!["comments".to_string()]);

        let mut removed = base.clone();
        removed.removed_choices.insert(NodeId("c1".into()));
        let report = diff(&make_entry(1, "1"), &base, &make_entry(1, "2"), &removed);
        assert_eq!(report.also_differs, vec!["removed_choices".to_string()]);

        let mut dead_a = base.clone();
        let mut gone = make_node("009", "p09", "old");
        gone.deleted = true;
        dead_a.nodes.insert(gone.id.clone(), gone.clone());
        let mut dead_b = base.clone();
        gone.current_fields = serde_json::json!({ "label": "newer" });
        dead_b.nodes.insert(gone.id.clone(), gone);
        let report = diff(&make_entry(1, "1"), &dead_a, &make_entry(1, "2"), &dead_b);
        assert!(!report.is_identical && report.node_changes.is_empty());
        assert_eq!(report.also_differs, vec!["tombstones".to_string()]);
    }

    #[test]
    fn a_replaced_document_with_an_equal_root_is_not_identical() {
        let state = one_node(make_node("001", "p01", "Same"));
        let report = diff(&make_entry(1, "1"), &state, &make_entry(2, "1"), &state);
        assert!(!report.is_identical);
        assert_eq!(report.also_differs, vec!["document".to_string()]);
        assert!(report.node_changes.is_empty());
    }

    #[test]
    fn large_unicode_values_are_summarised_but_a_change_still_shows() {
        let big = |c: &str| "a\u{3bb}".repeat(400_000) + c;
        let report = diff(
            &make_entry(1, "1"),
            &one_node(make_node("001", "p01", &big("x"))),
            &make_entry(1, "2"),
            &one_node(make_node("001", "p01", &big("y"))),
        );
        let change = &report.node_changes[0];
        let (before, after) = (
            change.before.as_ref().unwrap(),
            change.after.as_ref().unwrap(),
        );
        assert!(before["omitted_bytes"].as_u64().unwrap() > 1_000_000);
        assert_ne!(before["sha256"], after["sha256"]);
        assert!(report.unified_diff.contains("<omitted") && report.unified_diff.len() < 1_000);
        assert!(report.events.is_empty() && report.events_unavailable.is_some());
        assert!(serde_json::to_string(&report).unwrap().len() < 20_000);
    }

    #[test]
    fn the_report_lists_a_bounded_page_and_counts_the_rest() {
        let mut after = DocumentState::default();
        for i in 0..1_200 {
            let node = make_node(&format!("{i:05}"), &format!("p{i:05}"), "new");
            after.nodes.insert(node.id.clone(), node);
        }
        let report = diff(
            &make_entry(1, "1"),
            &DocumentState::default(),
            &make_entry(1, "2"),
            &after,
        );
        assert_eq!(report.node_changes.len(), MAX_NODE_CHANGES);
        assert!(report
            .omitted
            .contains(&"node_changes: 200 of 1200".to_string()));
        // A partial event list would not be a patch, so none is listed.
        assert!(report.events.is_empty());
        assert_eq!(
            report.events_unavailable.as_deref(),
            Some("more than 1000 events")
        );
    }
}
