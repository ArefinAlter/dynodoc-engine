//! Project-level three-way planning and two-commit manifest comparison.
//!
//! Equal/unchanged roots merge without reading document bodies; competing
//! changes are explicit conflicts. No guessed identity matching, silent file
//! deletion, or automatic merge of shared constraints.

use super::{Address, Commit, Error, FileEntry, SignedCommit};
use engine_shared::{DocumentId, NodeId};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_DIFF_LIMIT: usize = 50;
pub const MAX_DIFF_LIMIT: usize = 100;
pub const MAX_DIFF_RESPONSE_BYTES: usize = 256 * 1024;
pub const CURSOR_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    Added,
    Removed,
    Modified,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathDiff {
    pub path: String,
    pub kind: DiffKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<FileEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<FileEntry>,
    /// Set to true when `kind == Modified` and the document ID was replaced at the same path.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub document_replaced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffTotals {
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub unchanged: usize,
    pub total_changes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDiffReport {
    pub project: uuid::Uuid,
    pub from: Address,
    pub to: Address,
    pub totals: DiffTotals,
    pub changes: Vec<PathDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub more: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DiffOptions<'a> {
    pub limit: Option<usize>,
    pub cursor: Option<&'a str>,
    pub include_unchanged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompareCursor {
    pub v: u8,
    pub p: uuid::Uuid,
    pub from: Address,
    pub to: Address,
    pub last: String,
}

impl CompareCursor {
    pub fn encode(&self) -> String {
        super::hex(&serde_json::to_vec(self).expect("valid cursor serialization"))
    }

    pub fn decode(
        raw: &str,
        expected_project: uuid::Uuid,
        expected_from: &Address,
        expected_to: &Address,
    ) -> Result<Self, Error> {
        if !raw.len().is_multiple_of(2) || raw.len() > 2048 {
            return Err(Error::Invalid("invalid cursor encoding"));
        }
        let bytes =
            super::unhex(raw, raw.len() / 2).map_err(|_| Error::Invalid("invalid cursor hex"))?;
        let cursor: Self =
            serde_json::from_slice(&bytes).map_err(|_| Error::Invalid("invalid cursor payload"))?;
        if cursor.v != CURSOR_VERSION {
            return Err(Error::Invalid("unsupported cursor version"));
        }
        if cursor.p != expected_project
            || &cursor.from != expected_from
            || &cursor.to != expected_to
        {
            return Err(Error::Invalid("cursor project or commit mismatch"));
        }
        Ok(cursor)
    }
}

/// Compares two signed project commits and produces a bounded two-commit diff report.
///
/// Compares exact paths and document identity/state address without guessing renames.
/// Paths are sorted in Rust byte order. Output is bounded by limit (default 50, max 100)
/// and by the 256 KiB response byte budget.
pub fn compare_manifests(
    from: &SignedCommit,
    to: &SignedCommit,
    options: DiffOptions<'_>,
) -> Result<ProjectDiffReport, Error> {
    let from_addr = from.verify()?;
    let to_addr = to.verify()?;
    from.commit.validate()?;
    to.commit.validate()?;

    if from.commit.project != to.commit.project {
        return Err(Error::Invalid("compare project scope"));
    }
    let project = from.commit.project;

    let cursor = match options.cursor {
        Some(raw) => Some(CompareCursor::decode(raw, project, &from_addr, &to_addr)?),
        None => None,
    };

    let limit = options
        .limit
        .unwrap_or(DEFAULT_DIFF_LIMIT)
        .clamp(1, MAX_DIFF_LIMIT);

    let all_paths: BTreeSet<&String> = from
        .commit
        .files
        .keys()
        .chain(to.commit.files.keys())
        .collect();

    let mut totals = DiffTotals {
        added: 0,
        removed: 0,
        modified: 0,
        unchanged: 0,
        total_changes: 0,
    };

    let mut all_diffs = Vec::with_capacity(all_paths.len());
    for &path in &all_paths {
        let f = from.commit.files.get(path);
        let t = to.commit.files.get(path);
        let diff = match (f, t) {
            (None, Some(to_file)) => {
                totals.added += 1;
                Some(PathDiff {
                    path: path.clone(),
                    kind: DiffKind::Added,
                    from: None,
                    to: Some(to_file.clone()),
                    document_replaced: false,
                })
            }
            (Some(from_file), None) => {
                totals.removed += 1;
                Some(PathDiff {
                    path: path.clone(),
                    kind: DiffKind::Removed,
                    from: Some(from_file.clone()),
                    to: None,
                    document_replaced: false,
                })
            }
            (Some(from_file), Some(to_file)) => {
                if from_file == to_file {
                    totals.unchanged += 1;
                    if options.include_unchanged {
                        Some(PathDiff {
                            path: path.clone(),
                            kind: DiffKind::Unchanged,
                            from: Some(from_file.clone()),
                            to: Some(to_file.clone()),
                            document_replaced: false,
                        })
                    } else {
                        None
                    }
                } else {
                    totals.modified += 1;
                    let document_replaced = from_file.document != to_file.document;
                    Some(PathDiff {
                        path: path.clone(),
                        kind: DiffKind::Modified,
                        from: Some(from_file.clone()),
                        to: Some(to_file.clone()),
                        document_replaced,
                    })
                }
            }
            (None, None) => unreachable!(),
        };
        if let Some(d) = diff {
            all_diffs.push(d);
        }
    }
    totals.total_changes = totals.added + totals.removed + totals.modified;

    // Filter by cursor (strictly greater than cursor.last in Rust byte order)
    let candidate_diffs: Vec<PathDiff> = match &cursor {
        Some(c) => all_diffs.into_iter().filter(|d| d.path > c.last).collect(),
        None => all_diffs,
    };

    let mut page_changes = Vec::new();
    let mut last_path = None;
    let mut more = false;

    // Response budget: 256 KiB
    let base_estimate = 256;
    let mut current_bytes = base_estimate;

    for diff in &candidate_diffs {
        if page_changes.len() >= limit {
            more = true;
            break;
        }

        let item_bytes = serde_json::to_vec(diff).map_err(Error::Json)?.len() + 2;
        if current_bytes + item_bytes > MAX_DIFF_RESPONSE_BYTES {
            more = true;
            break;
        }

        current_bytes += item_bytes;
        last_path = Some(diff.path.clone());
        page_changes.push(diff.clone());
    }

    if !more && candidate_diffs.len() > page_changes.len() {
        more = true;
    }

    let next_cursor = if more {
        last_path.map(|last| {
            CompareCursor {
                v: CURSOR_VERSION,
                p: project,
                from: from_addr.clone(),
                to: to_addr.clone(),
                last,
            }
            .encode()
        })
    } else {
        None
    };

    Ok(ProjectDiffReport {
        project,
        from: from_addr,
        to: to_addr,
        totals,
        changes: page_changes,
        next_cursor,
        more,
    })
}

pub const DEFAULT_NODE_DIFF_LIMIT: usize = 50;
pub const MAX_NODE_DIFF_LIMIT: usize = 100;
pub const MAX_NODE_DIFF_RESPONSE_BYTES: usize = 256 * 1024;
pub const NODE_DIFF_CURSOR_VERSION: u8 = 1;
pub const MAX_INLINE_FIELD_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeDiffKind {
    Added,
    Removed,
    Modified,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmittedValue {
    pub omitted: bool,
    pub sha256: String,
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BoundedValue {
    Omitted(OmittedValue),
    Value(serde_json::Value),
}

impl BoundedValue {
    pub fn bound(val: &serde_json::Value) -> Self {
        let canonical_bytes = serde_json::to_vec(val).unwrap_or_default();
        if canonical_bytes.len() > MAX_INLINE_FIELD_BYTES {
            let hash = ring::digest::digest(&ring::digest::SHA256, &canonical_bytes);
            BoundedValue::Omitted(OmittedValue {
                omitted: true,
                sha256: super::hex(hash.as_ref()),
                bytes: canonical_bytes.len(),
            })
        } else {
            BoundedValue::Value(val.clone())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDiff {
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<BoundedValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<BoundedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAttributes {
    pub node_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<NodeId>,
    pub pos: String,
    pub deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub var_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDiff {
    pub node_id: NodeId,
    pub kind: NodeDiffKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<NodeAttributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<NodeAttributes>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_changes: Vec<FieldDiff>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub structural_change: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentChanges {
    pub comments_changed: bool,
    pub comments_from_count: usize,
    pub comments_to_count: usize,
    pub suggestions_changed: bool,
    pub suggestions_from_count: usize,
    pub suggestions_to_count: usize,
    pub removed_choices_changed: bool,
    pub removed_choices_from_count: usize,
    pub removed_choices_to_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDiffTotals {
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub unchanged: usize,
    pub total_changes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCompareCursor {
    pub v: u8,
    pub doc: DocumentId,
    pub from: Address,
    pub to: Address,
    pub last: String,
}

impl NodeCompareCursor {
    pub fn encode(&self) -> String {
        super::hex(&serde_json::to_vec(self).expect("valid cursor serialization"))
    }

    pub fn decode(
        raw: &str,
        expected_doc: DocumentId,
        expected_from: &Address,
        expected_to: &Address,
    ) -> Result<Self, Error> {
        if !raw.len().is_multiple_of(2) || raw.len() > 4096 {
            return Err(Error::Invalid("invalid cursor encoding"));
        }
        let bytes =
            super::unhex(raw, raw.len() / 2).map_err(|_| Error::Invalid("invalid cursor hex"))?;
        let cursor: Self =
            serde_json::from_slice(&bytes).map_err(|_| Error::Invalid("invalid cursor payload"))?;
        if cursor.v != NODE_DIFF_CURSOR_VERSION {
            return Err(Error::Invalid("unsupported cursor version"));
        }
        if cursor.doc != expected_doc || &cursor.from != expected_from || &cursor.to != expected_to
        {
            return Err(Error::Invalid("cursor document or root mismatch"));
        }
        Ok(cursor)
    }
}

#[derive(Debug, Clone, Default)]
pub struct NodeDiffOptions<'a> {
    pub limit: Option<usize>,
    pub cursor: Option<&'a str>,
    pub include_unchanged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentNodeDiffReport {
    pub document_id: DocumentId,
    pub from_root: Address,
    pub to_root: Address,
    pub whole_state_identical: bool,
    pub totals: NodeDiffTotals,
    pub components: ComponentChanges,
    pub changes: Vec<NodeDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub more: bool,
    pub limits: Cow<'static, str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCompareReport {
    pub project: uuid::Uuid,
    pub from: Address,
    pub to: Address,
    pub path: String,
    pub kind: DiffKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_file: Option<FileEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_file: Option<FileEntry>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub document_replaced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_diff: Option<DocumentNodeDiffReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub more: bool,
}

/// Bounded comparison of two materialized document states.
///
/// Compares node identity, type, parent, position, deletion, var_name, and exact stored fields
/// in stable node-ID order. Distinguishes missing fields from JSON null. Oversized values
/// are represented by an explicit omitted marker with hash and byte count.
pub fn compare_nodes(
    document_id: DocumentId,
    from_root: &Address,
    to_root: &Address,
    from: &crate::materializer::DocumentState,
    to: &crate::materializer::DocumentState,
    options: NodeDiffOptions<'_>,
) -> Result<DocumentNodeDiffReport, Error> {
    let cursor = match options.cursor {
        Some(raw) => Some(NodeCompareCursor::decode(
            raw,
            document_id,
            from_root,
            to_root,
        )?),
        None => None,
    };

    let limit = options
        .limit
        .unwrap_or(DEFAULT_NODE_DIFF_LIMIT)
        .clamp(1, MAX_NODE_DIFF_LIMIT);

    let whole_state_identical = from == to;

    let components = ComponentChanges {
        comments_changed: from.comments != to.comments,
        comments_from_count: from.comments.len(),
        comments_to_count: to.comments.len(),
        suggestions_changed: from.suggestions != to.suggestions,
        suggestions_from_count: from.suggestions.len(),
        suggestions_to_count: to.suggestions.len(),
        removed_choices_changed: from.removed_choices != to.removed_choices,
        removed_choices_from_count: from.removed_choices.len(),
        removed_choices_to_count: to.removed_choices.len(),
    };

    let all_node_ids: BTreeSet<&NodeId> = from.nodes.keys().chain(to.nodes.keys()).collect();

    let mut totals = NodeDiffTotals {
        added: 0,
        removed: 0,
        modified: 0,
        unchanged: 0,
        total_changes: 0,
    };

    let mut all_diffs = Vec::with_capacity(all_node_ids.len());

    for &node_id in &all_node_ids {
        let f = from.nodes.get(node_id);
        let t = to.nodes.get(node_id);

        let diff = match (f, t) {
            (None, Some(node)) => {
                totals.added += 1;
                let attrs = NodeAttributes {
                    node_type: node.node_type.clone(),
                    parent_id: node.parent_id.clone(),
                    pos: node.pos.clone(),
                    deleted: node.deleted,
                    var_name: node.var_name.clone(),
                };
                let mut field_changes = Vec::new();
                if let serde_json::Value::Object(map) = &node.current_fields {
                    let mut keys: Vec<_> = map.keys().collect();
                    keys.sort_unstable();
                    for k in keys {
                        field_changes.push(FieldDiff {
                            field: k.clone(),
                            from: None,
                            to: Some(BoundedValue::bound(&map[k])),
                        });
                    }
                }
                Some(NodeDiff {
                    node_id: node_id.clone(),
                    kind: NodeDiffKind::Added,
                    from: None,
                    to: Some(attrs),
                    field_changes,
                    structural_change: true,
                })
            }
            (Some(node), None) => {
                totals.removed += 1;
                let attrs = NodeAttributes {
                    node_type: node.node_type.clone(),
                    parent_id: node.parent_id.clone(),
                    pos: node.pos.clone(),
                    deleted: node.deleted,
                    var_name: node.var_name.clone(),
                };
                let mut field_changes = Vec::new();
                if let serde_json::Value::Object(map) = &node.current_fields {
                    let mut keys: Vec<_> = map.keys().collect();
                    keys.sort_unstable();
                    for k in keys {
                        field_changes.push(FieldDiff {
                            field: k.clone(),
                            from: Some(BoundedValue::bound(&map[k])),
                            to: None,
                        });
                    }
                }
                Some(NodeDiff {
                    node_id: node_id.clone(),
                    kind: NodeDiffKind::Removed,
                    from: Some(attrs),
                    to: None,
                    field_changes,
                    structural_change: true,
                })
            }
            (Some(fn_node), Some(to_node)) => {
                let structural = fn_node.node_type != to_node.node_type
                    || fn_node.parent_id != to_node.parent_id
                    || fn_node.pos != to_node.pos
                    || fn_node.deleted != to_node.deleted
                    || fn_node.var_name != to_node.var_name;

                let mut field_changes = Vec::new();
                let f_map = fn_node.current_fields.as_object();
                let t_map = to_node.current_fields.as_object();

                let empty = serde_json::Map::new();
                let f_keys = f_map.unwrap_or(&empty);
                let t_keys = t_map.unwrap_or(&empty);

                let all_keys: BTreeSet<&String> = f_keys.keys().chain(t_keys.keys()).collect();
                for &key in &all_keys {
                    let f_val = f_keys.get(key);
                    let t_val = t_keys.get(key);
                    if f_val != t_val {
                        field_changes.push(FieldDiff {
                            field: key.clone(),
                            from: f_val.map(BoundedValue::bound),
                            to: t_val.map(BoundedValue::bound),
                        });
                    }
                }

                if !structural && field_changes.is_empty() {
                    totals.unchanged += 1;
                    if options.include_unchanged {
                        let from_attrs = NodeAttributes {
                            node_type: fn_node.node_type.clone(),
                            parent_id: fn_node.parent_id.clone(),
                            pos: fn_node.pos.clone(),
                            deleted: fn_node.deleted,
                            var_name: fn_node.var_name.clone(),
                        };
                        let to_attrs = NodeAttributes {
                            node_type: to_node.node_type.clone(),
                            parent_id: to_node.parent_id.clone(),
                            pos: to_node.pos.clone(),
                            deleted: to_node.deleted,
                            var_name: to_node.var_name.clone(),
                        };
                        Some(NodeDiff {
                            node_id: node_id.clone(),
                            kind: NodeDiffKind::Unchanged,
                            from: Some(from_attrs),
                            to: Some(to_attrs),
                            field_changes: Vec::new(),
                            structural_change: false,
                        })
                    } else {
                        None
                    }
                } else {
                    totals.modified += 1;
                    let from_attrs = NodeAttributes {
                        node_type: fn_node.node_type.clone(),
                        parent_id: fn_node.parent_id.clone(),
                        pos: fn_node.pos.clone(),
                        deleted: fn_node.deleted,
                        var_name: fn_node.var_name.clone(),
                    };
                    let to_attrs = NodeAttributes {
                        node_type: to_node.node_type.clone(),
                        parent_id: to_node.parent_id.clone(),
                        pos: to_node.pos.clone(),
                        deleted: to_node.deleted,
                        var_name: to_node.var_name.clone(),
                    };
                    Some(NodeDiff {
                        node_id: node_id.clone(),
                        kind: NodeDiffKind::Modified,
                        from: Some(from_attrs),
                        to: Some(to_attrs),
                        field_changes,
                        structural_change: structural,
                    })
                }
            }
            (None, None) => None,
        };

        if let Some(d) = diff {
            all_diffs.push(d);
        }
    }

    totals.total_changes = totals.added + totals.removed + totals.modified;

    let candidate_diffs: Vec<NodeDiff> = match &cursor {
        Some(c) => all_diffs
            .into_iter()
            .filter(|d| d.node_id.0 > c.last)
            .collect(),
        None => all_diffs,
    };

    let mut page_changes = Vec::new();
    let mut last_node_id = None;
    let mut more = false;

    let base_estimate = 512;
    let mut current_bytes = base_estimate;

    for diff in &candidate_diffs {
        if page_changes.len() >= limit {
            more = true;
            break;
        }

        let item_bytes = serde_json::to_vec(diff).map_err(Error::Json)?.len() + 2;
        if current_bytes + item_bytes > MAX_NODE_DIFF_RESPONSE_BYTES && !page_changes.is_empty() {
            more = true;
            break;
        }

        current_bytes += item_bytes;
        last_node_id = Some(diff.node_id.0.clone());
        page_changes.push(diff.clone());
    }

    if !more && candidate_diffs.len() > page_changes.len() {
        more = true;
    }

    let next_cursor = if more {
        last_node_id.map(|last| {
            NodeCompareCursor {
                v: NODE_DIFF_CURSOR_VERSION,
                doc: document_id,
                from: from_root.clone(),
                to: to_root.clone(),
                last,
            }
            .encode()
        })
    } else {
        None
    };

    Ok(DocumentNodeDiffReport {
        document_id,
        from_root: from_root.clone(),
        to_root: to_root.clone(),
        whole_state_identical,
        totals,
        components,
        changes: page_changes,
        next_cursor,
        more,
        limits: "Annotation bodies and word-level attribution are outside this report; see docs/PRODUCT-SPEC.md.".into(),
    })
}

#[derive(Debug, Serialize)]
pub struct FileConflict {
    pub path: String,
    pub base: Option<FileEntry>,
    pub left: Option<FileEntry>,
    pub right: Option<FileEntry>,
}

#[derive(Debug, Serialize)]
pub struct ProjectPlan {
    /// Resolved paths only. A caller must resolve conflicts before signing a
    /// commit, and validate the resulting complete file map again.
    pub files: BTreeMap<String, FileEntry>,
    pub conflicts: Vec<FileConflict>,
}

pub fn plan(base: &Commit, left: &Commit, right: &Commit) -> Result<ProjectPlan, super::Error> {
    for commit in [base, left, right] {
        commit.validate()?;
    }
    if base.project != left.project || base.project != right.project {
        return Err(Error::Invalid("merge project scope"));
    }
    let paths: BTreeSet<_> = base
        .files
        .keys()
        .chain(left.files.keys())
        .chain(right.files.keys())
        .collect();
    let mut result = ProjectPlan {
        files: BTreeMap::new(),
        conflicts: Vec::new(),
    };
    for path in paths {
        let b = base.files.get(path);
        let l = left.files.get(path);
        let r = right.files.get(path);
        let chosen = if l == r || r == b {
            Some(l)
        } else if l == b {
            Some(r)
        } else {
            None
        };
        match chosen {
            Some(Some(file)) => {
                result.files.insert(path.clone(), file.clone());
            }
            Some(None) => {}
            None => result.conflicts.push(FileConflict {
                path: path.clone(),
                base: b.cloned(),
                left: l.cloned(),
                right: r.cloned(),
            }),
        }
    }
    // Independent paths may violate shared identity/namespace constraints, such
    // as two concurrent renames. Surface every participant, not an arbitrary winner.
    let mut invalid = BTreeSet::new();
    let mut ids = BTreeMap::new();
    for (path, file) in &result.files {
        if let Some(other) = ids.insert(file.document.0, path) {
            invalid.insert(other.clone());
            invalid.insert(path.clone());
        }
        for (index, _) in path.match_indices('/') {
            if result.files.contains_key(&path[..index]) {
                invalid.insert(path[..index].into());
                invalid.insert(path.clone());
            }
        }
    }
    for path in invalid {
        result.files.remove(&path);
        result.conflicts.push(FileConflict {
            base: base.files.get(&path).cloned(),
            left: left.files.get(&path).cloned(),
            right: right.files.get(&path).cloned(),
            path,
        });
    }
    result.conflicts.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_checkpoint::Address;
    use engine_shared::DocumentId;

    fn entry(id: u128, byte: &str) -> FileEntry {
        FileEntry {
            document: DocumentId(uuid::Uuid::from_u128(id)),
            state: Address::try_from(byte.repeat(64)).unwrap(),
        }
    }
    fn commit(files: BTreeMap<String, FileEntry>) -> Commit {
        super::super::tests::signed(uuid::Uuid::from_u128(1), vec![], files, "test").commit
    }
    #[test]
    fn independent_files_converge_in_either_order_and_conflicting_edits_remain_explicit() {
        let base = commit(BTreeMap::from([
            ("a".into(), entry(1, "a")),
            ("b".into(), entry(2, "b")),
        ]));
        let mut left = base.clone();
        left.files.get_mut("a").unwrap().state = entry(1, "c").state;
        let mut right = base.clone();
        right.files.get_mut("b").unwrap().state = entry(2, "d").state;
        let forward = plan(&base, &left, &right).unwrap();
        let reverse = plan(&base, &right, &left).unwrap();
        assert!(forward.conflicts.is_empty());
        assert_eq!(forward.files, reverse.files);
        right.files.remove("a");
        let conflict = plan(&base, &left, &right).unwrap();
        assert_eq!(conflict.conflicts.len(), 1);
        assert_eq!(conflict.conflicts[0].path, "a");
    }
    #[test]
    fn different_paths_are_not_independent_when_they_share_identity_or_namespace() {
        let base = commit(BTreeMap::from([("old".into(), entry(1, "a"))]));
        let left = commit(BTreeMap::from([("left".into(), entry(1, "a"))]));
        let right = commit(BTreeMap::from([("right".into(), entry(1, "a"))]));
        let result = plan(&base, &left, &right).unwrap();
        assert_eq!(result.conflicts.len(), 2);
        assert!(result.files.is_empty());
        let base = commit(BTreeMap::new());
        let left = commit(BTreeMap::from([("dir".into(), entry(1, "a"))]));
        let right = commit(BTreeMap::from([("dir/file".into(), entry(2, "b"))]));
        let result = plan(&base, &left, &right).unwrap();
        assert_eq!(result.conflicts.len(), 2);
        assert!(result.files.is_empty());
    }

    fn signed_commit(files: BTreeMap<String, FileEntry>) -> SignedCommit {
        super::super::tests::signed(uuid::Uuid::from_u128(1), vec![], files, "test")
    }

    fn signed_commit_project(project: u128, files: BTreeMap<String, FileEntry>) -> SignedCommit {
        super::super::tests::signed(uuid::Uuid::from_u128(project), vec![], files, "test")
    }

    #[test]
    fn compare_manifests_add_delete_modify_and_unchanged() {
        let from = signed_commit(BTreeMap::from([
            ("deleted.txt".into(), entry(1, "1")),
            ("modified.txt".into(), entry(2, "2")),
            ("unchanged.txt".into(), entry(3, "3")),
        ]));
        let to = signed_commit(BTreeMap::from([
            ("added.txt".into(), entry(4, "4")),
            ("modified.txt".into(), entry(2, "5")),
            ("unchanged.txt".into(), entry(3, "3")),
        ]));

        let report = compare_manifests(&from, &to, DiffOptions::default()).unwrap();
        assert_eq!(report.totals.added, 1);
        assert_eq!(report.totals.removed, 1);
        assert_eq!(report.totals.modified, 1);
        assert_eq!(report.totals.unchanged, 1);
        assert_eq!(report.totals.total_changes, 3);
        assert_eq!(report.changes.len(), 3);
        assert!(!report.more);
        assert!(report.next_cursor.is_none());

        assert_eq!(report.changes[0].path, "added.txt");
        assert_eq!(report.changes[0].kind, DiffKind::Added);
        assert!(report.changes[0].from.is_none());
        assert_eq!(report.changes[0].to, Some(entry(4, "4")));

        assert_eq!(report.changes[1].path, "deleted.txt");
        assert_eq!(report.changes[1].kind, DiffKind::Removed);
        assert_eq!(report.changes[1].from, Some(entry(1, "1")));
        assert!(report.changes[1].to.is_none());

        assert_eq!(report.changes[2].path, "modified.txt");
        assert_eq!(report.changes[2].kind, DiffKind::Modified);
        assert_eq!(report.changes[2].from, Some(entry(2, "2")));
        assert_eq!(report.changes[2].to, Some(entry(2, "5")));
        assert!(!report.changes[2].document_replaced);
    }

    #[test]
    fn compare_manifests_same_path_replaced_document_identity() {
        let from = signed_commit(BTreeMap::from([("file.txt".into(), entry(1, "a"))]));
        let to = signed_commit(BTreeMap::from([("file.txt".into(), entry(2, "a"))]));

        let report = compare_manifests(&from, &to, DiffOptions::default()).unwrap();
        assert_eq!(report.totals.modified, 1);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].path, "file.txt");
        assert_eq!(report.changes[0].kind, DiffKind::Modified);
        assert!(report.changes[0].document_replaced);
    }

    #[test]
    fn compare_manifests_equal_commits_report_zero_changes() {
        let commit = signed_commit(BTreeMap::from([
            ("a.txt".into(), entry(1, "a")),
            ("b.txt".into(), entry(2, "b")),
        ]));
        let report = compare_manifests(&commit, &commit, DiffOptions::default()).unwrap();
        assert_eq!(report.totals.added, 0);
        assert_eq!(report.totals.removed, 0);
        assert_eq!(report.totals.modified, 0);
        assert_eq!(report.totals.unchanged, 2);
        assert_eq!(report.totals.total_changes, 0);
        assert!(report.changes.is_empty());
        assert!(!report.more);
        assert!(report.next_cursor.is_none());
    }

    #[test]
    fn compare_manifests_reversed_inputs_are_symmetric() {
        let a = signed_commit(BTreeMap::from([
            ("file_a.txt".into(), entry(1, "a")),
            ("shared.txt".into(), entry(2, "a")),
        ]));
        let b = signed_commit(BTreeMap::from([
            ("file_b.txt".into(), entry(3, "b")),
            ("shared.txt".into(), entry(2, "b")),
        ]));

        let fwd = compare_manifests(&a, &b, DiffOptions::default()).unwrap();
        let rev = compare_manifests(&b, &a, DiffOptions::default()).unwrap();

        assert_eq!(fwd.totals.added, rev.totals.removed);
        assert_eq!(fwd.totals.removed, rev.totals.added);
        assert_eq!(fwd.totals.modified, rev.totals.modified);
        assert_eq!(fwd.totals.total_changes, rev.totals.total_changes);
    }

    #[test]
    fn compare_manifests_complete_pagination_without_duplicates() {
        let from = signed_commit(BTreeMap::new());
        let mut files = BTreeMap::new();
        for i in 0..120 {
            let path = format!("dir/file_{:03}.txt", i);
            files.insert(path, entry(1000 + i as u128, "a"));
        }
        let to = signed_commit(files);

        let p1 = compare_manifests(
            &from,
            &to,
            DiffOptions {
                limit: Some(50),
                cursor: None,
                include_unchanged: false,
            },
        )
        .unwrap();
        assert_eq!(p1.totals.total_changes, 120);
        assert_eq!(p1.changes.len(), 50);
        assert!(p1.more);
        let c1 = p1.next_cursor.expect("cursor on page 1");

        let p2 = compare_manifests(
            &from,
            &to,
            DiffOptions {
                limit: Some(50),
                cursor: Some(&c1),
                include_unchanged: false,
            },
        )
        .unwrap();
        assert_eq!(p2.changes.len(), 50);
        assert!(p2.more);
        let c2 = p2.next_cursor.expect("cursor on page 2");

        let p3 = compare_manifests(
            &from,
            &to,
            DiffOptions {
                limit: Some(50),
                cursor: Some(&c2),
                include_unchanged: false,
            },
        )
        .unwrap();
        assert_eq!(p3.changes.len(), 20);
        assert!(!p3.more);
        assert!(p3.next_cursor.is_none());

        let mut all_paths = Vec::new();
        for change in p1.changes.into_iter().chain(p2.changes).chain(p3.changes) {
            all_paths.push(change.path);
        }
        assert_eq!(all_paths.len(), 120);
        for i in 0..119 {
            assert!(
                all_paths[i] < all_paths[i + 1],
                "paths must be strictly increasing in byte order"
            );
        }
    }

    #[test]
    fn compare_manifests_cursor_rejection_on_mismatch_and_tampering() {
        let from = signed_commit(BTreeMap::from([("a.txt".into(), entry(1, "a"))]));
        let to = signed_commit(BTreeMap::from([("b.txt".into(), entry(2, "b"))]));
        let other = signed_commit_project(2, BTreeMap::from([("c.txt".into(), entry(3, "c"))]));

        let p1 = compare_manifests(
            &from,
            &to,
            DiffOptions {
                limit: Some(1),
                cursor: None,
                include_unchanged: false,
            },
        )
        .unwrap();
        let valid_cursor = p1.next_cursor.unwrap();

        assert!(compare_manifests(
            &other,
            &other,
            DiffOptions {
                limit: Some(1),
                cursor: Some(&valid_cursor),
                include_unchanged: false,
            },
        )
        .is_err());

        assert!(compare_manifests(
            &from,
            &to,
            DiffOptions {
                limit: Some(1),
                cursor: Some("deadbeef_corrupted"),
                include_unchanged: false,
            },
        )
        .is_err());
    }

    #[test]
    fn compare_manifests_rejects_foreign_project_scope() {
        let p1 = signed_commit_project(1, BTreeMap::new());
        let p2 = signed_commit_project(2, BTreeMap::new());
        let err = compare_manifests(&p1, &p2, DiffOptions::default()).unwrap_err();
        assert!(matches!(err, Error::Invalid("compare project scope")));
    }

    use crate::materializer::{CommentState, DocumentState, MaterializedNode, SuggestionState};

    fn dummy_roots() -> (DocumentId, Address, Address) {
        (
            DocumentId(uuid::Uuid::new_v4()),
            Address::try_from("1".repeat(64)).unwrap(),
            Address::try_from("2".repeat(64)).unwrap(),
        )
    }

    #[test]
    fn compare_nodes_identical_states_report_zero_changes() {
        let (doc, from_root, to_root) = dummy_roots();
        let mut state = DocumentState::default();
        let node_id = NodeId("01NODEAAA".into());
        state.nodes.insert(
            node_id.clone(),
            MaterializedNode {
                id: node_id,
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a0".into(),
                current_fields: serde_json::json!({"text": "Hello world"}),
                var_name: None,
                deleted: false,
            },
        );

        let report = compare_nodes(
            doc,
            &from_root,
            &to_root,
            &state,
            &state,
            NodeDiffOptions::default(),
        )
        .unwrap();
        assert!(report.whole_state_identical);
        assert_eq!(report.totals.total_changes, 0);
        assert_eq!(report.totals.unchanged, 1);
        assert!(report.changes.is_empty());
    }

    #[test]
    fn compare_nodes_add_remove_modify_moves_and_tombstones() {
        let (doc, from_root, to_root) = dummy_roots();
        let mut from = DocumentState::default();
        let mut to = DocumentState::default();

        let removed_id = NodeId("01REMOVED".into());
        from.nodes.insert(
            removed_id.clone(),
            MaterializedNode {
                id: removed_id.clone(),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a0".into(),
                current_fields: serde_json::json!({"field": "old"}),
                var_name: None,
                deleted: false,
            },
        );

        let added_id = NodeId("02ADDED".into());
        to.nodes.insert(
            added_id.clone(),
            MaterializedNode {
                id: added_id.clone(),
                parent_id: None,
                node_type: "section".into(),
                pos: "b0".into(),
                current_fields: serde_json::json!({"field": "new"}),
                var_name: Some("sec_var".into()),
                deleted: false,
            },
        );

        // Moved & tombstoned node
        let moved_id = NodeId("03MOVED".into());
        from.nodes.insert(
            moved_id.clone(),
            MaterializedNode {
                id: moved_id.clone(),
                parent_id: None,
                node_type: "item".into(),
                pos: "a1".into(),
                current_fields: serde_json::json!({"content": "Stay"}),
                var_name: None,
                deleted: false,
            },
        );
        to.nodes.insert(
            moved_id.clone(),
            MaterializedNode {
                id: moved_id.clone(),
                parent_id: Some(added_id.clone()),
                node_type: "item".into(),
                pos: "z9".into(),
                current_fields: serde_json::json!({"content": "Stay"}),
                var_name: None,
                deleted: true, // tombstoned
            },
        );

        let report = compare_nodes(
            doc,
            &from_root,
            &to_root,
            &from,
            &to,
            NodeDiffOptions::default(),
        )
        .unwrap();

        assert!(!report.whole_state_identical);
        assert_eq!(report.totals.added, 1);
        assert_eq!(report.totals.removed, 1);
        assert_eq!(report.totals.modified, 1);
        assert_eq!(report.totals.total_changes, 3);

        let moved_diff = report
            .changes
            .iter()
            .find(|d| d.node_id == moved_id)
            .unwrap();
        assert!(moved_diff.structural_change);
        assert_eq!(moved_diff.kind, NodeDiffKind::Modified);
        assert_eq!(moved_diff.from.as_ref().unwrap().pos, "a1");
        assert_eq!(moved_diff.to.as_ref().unwrap().pos, "z9");
        assert!(!moved_diff.from.as_ref().unwrap().deleted);
        assert!(moved_diff.to.as_ref().unwrap().deleted);
        assert_eq!(moved_diff.to.as_ref().unwrap().parent_id, Some(added_id));
    }

    #[test]
    fn compare_nodes_formatting_and_unicode_edits() {
        let (doc, from_root, to_root) = dummy_roots();
        let mut from = DocumentState::default();
        let mut to = DocumentState::default();

        let unicode_id = NodeId("01বাংলা_নথি".into());
        from.nodes.insert(
            unicode_id.clone(),
            MaterializedNode {
                id: unicode_id.clone(),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a0".into(),
                current_fields: serde_json::json!({
                    "text": "শুরু",
                    "formatting": {"bold": false, "italic": true}
                }),
                var_name: None,
                deleted: false,
            },
        );
        to.nodes.insert(
            unicode_id.clone(),
            MaterializedNode {
                id: unicode_id.clone(),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a0".into(),
                current_fields: serde_json::json!({
                    "text": "শুরু এবং শেষ",
                    "formatting": {"bold": true, "italic": true}
                }),
                var_name: None,
                deleted: false,
            },
        );

        let report = compare_nodes(
            doc,
            &from_root,
            &to_root,
            &from,
            &to,
            NodeDiffOptions::default(),
        )
        .unwrap();

        assert_eq!(report.totals.modified, 1);
        let diff = &report.changes[0];
        assert_eq!(diff.node_id, unicode_id);
        assert!(!diff.structural_change);
        assert_eq!(diff.field_changes.len(), 2);
    }

    #[test]
    fn compare_nodes_distinguishes_null_from_missing() {
        let (doc, from_root, to_root) = dummy_roots();
        let mut from = DocumentState::default();
        let mut to = DocumentState::default();

        let id = NodeId("01NULLCHECK".into());
        // In from: field_a is missing, field_b is null, field_c is "val"
        from.nodes.insert(
            id.clone(),
            MaterializedNode {
                id: id.clone(),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a0".into(),
                current_fields: serde_json::json!({
                    "field_b": null,
                    "field_c": "val",
                }),
                var_name: None,
                deleted: false,
            },
        );
        // In to: field_a is null, field_b is missing, field_c is null
        to.nodes.insert(
            id.clone(),
            MaterializedNode {
                id: id.clone(),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a0".into(),
                current_fields: serde_json::json!({
                    "field_a": null,
                    "field_c": null,
                }),
                var_name: None,
                deleted: false,
            },
        );

        let report = compare_nodes(
            doc,
            &from_root,
            &to_root,
            &from,
            &to,
            NodeDiffOptions::default(),
        )
        .unwrap();

        let diff = &report.changes[0];
        assert_eq!(diff.field_changes.len(), 3);

        let fa = diff
            .field_changes
            .iter()
            .find(|f| f.field == "field_a")
            .unwrap();
        assert_eq!(fa.from, None); // was missing
        assert_eq!(fa.to, Some(BoundedValue::Value(serde_json::Value::Null))); // now null

        let fb = diff
            .field_changes
            .iter()
            .find(|f| f.field == "field_b")
            .unwrap();
        assert_eq!(fb.from, Some(BoundedValue::Value(serde_json::Value::Null))); // was null
        assert_eq!(fb.to, None); // now missing

        let fc = diff
            .field_changes
            .iter()
            .find(|f| f.field == "field_c")
            .unwrap();
        assert_eq!(fc.from, Some(BoundedValue::Value(serde_json::json!("val"))));
        assert_eq!(fc.to, Some(BoundedValue::Value(serde_json::Value::Null)));
    }

    #[test]
    fn compare_nodes_oversized_values_are_bounded() {
        let (doc, from_root, to_root) = dummy_roots();
        let mut from = DocumentState::default();
        let mut to = DocumentState::default();

        let id = NodeId("01BIGTEXT".into());
        let huge_string = "a".repeat(10_000);
        from.nodes.insert(
            id.clone(),
            MaterializedNode {
                id: id.clone(),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a0".into(),
                current_fields: serde_json::json!({"content": huge_string}),
                var_name: None,
                deleted: false,
            },
        );
        to.nodes.insert(
            id.clone(),
            MaterializedNode {
                id: id.clone(),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a0".into(),
                current_fields: serde_json::json!({"content": "small"}),
                var_name: None,
                deleted: false,
            },
        );

        let report = compare_nodes(
            doc,
            &from_root,
            &to_root,
            &from,
            &to,
            NodeDiffOptions::default(),
        )
        .unwrap();

        let diff = &report.changes[0];
        let fc = &diff.field_changes[0];
        match &fc.from {
            Some(BoundedValue::Omitted(omitted)) => {
                assert!(omitted.omitted);
                assert!(omitted.bytes > 10_000);
                assert_eq!(omitted.sha256.len(), 64);
            }
            other => panic!("expected omitted marker, got {other:?}"),
        }
        assert_eq!(fc.to, Some(BoundedValue::Value(serde_json::json!("small"))));
    }

    #[test]
    fn compare_nodes_annotation_only_changes() {
        let (doc, from_root, to_root) = dummy_roots();
        let mut from = DocumentState::default();
        let mut to = DocumentState::default();

        let id = NodeId("01STATIC".into());
        let node = MaterializedNode {
            id: id.clone(),
            parent_id: None,
            node_type: "paragraph".into(),
            pos: "a0".into(),
            current_fields: serde_json::json!({"text": "Static"}),
            var_name: None,
            deleted: false,
        };
        from.nodes.insert(id.clone(), node.clone());
        to.nodes.insert(id, node);

        from.comments.push(CommentState {
            node_id: None,
            body: "First comment".into(),
        });
        to.comments.push(CommentState {
            node_id: None,
            body: "First comment".into(),
        });
        to.comments.push(CommentState {
            node_id: None,
            body: "Second comment".into(),
        });

        to.suggestions.insert(
            "sug1".into(),
            SuggestionState {
                target_node_id: None,
                detail: serde_json::json!({"fix": true}),
                accepted: false,
                rejected_reason: None,
            },
        );

        let report = compare_nodes(
            doc,
            &from_root,
            &to_root,
            &from,
            &to,
            NodeDiffOptions::default(),
        )
        .unwrap();

        assert!(!report.whole_state_identical);
        assert_eq!(report.totals.total_changes, 0); // zero node changes!
        assert!(report.changes.is_empty());
        assert!(report.components.comments_changed);
        assert_eq!(report.components.comments_from_count, 1);
        assert_eq!(report.components.comments_to_count, 2);
        assert!(report.components.suggestions_changed);
        assert_eq!(report.components.suggestions_from_count, 0);
        assert_eq!(report.components.suggestions_to_count, 1);
    }

    #[test]
    fn compare_nodes_pagination_and_cursor_validation() {
        let (doc, from_root, to_root) = dummy_roots();
        let mut from = DocumentState::default();
        let mut to = DocumentState::default();

        for i in 0..15 {
            let id = NodeId(format!("01NODE_{i:02}"));
            from.nodes.insert(
                id.clone(),
                MaterializedNode {
                    id: id.clone(),
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: format!("p{i:02}"),
                    current_fields: serde_json::json!({"val": i}),
                    var_name: None,
                    deleted: false,
                },
            );
            to.nodes.insert(
                id.clone(),
                MaterializedNode {
                    id: id.clone(),
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: format!("p{i:02}"),
                    current_fields: serde_json::json!({"val": i + 100}),
                    var_name: None,
                    deleted: false,
                },
            );
        }

        // Page 1: limit 5
        let p1 = compare_nodes(
            doc,
            &from_root,
            &to_root,
            &from,
            &to,
            NodeDiffOptions {
                limit: Some(5),
                cursor: None,
                include_unchanged: false,
            },
        )
        .unwrap();
        assert_eq!(p1.changes.len(), 5);
        assert!(p1.more);
        assert!(p1.next_cursor.is_some());
        let c1 = p1.next_cursor.unwrap();

        // Page 2: limit 5
        let p2 = compare_nodes(
            doc,
            &from_root,
            &to_root,
            &from,
            &to,
            NodeDiffOptions {
                limit: Some(5),
                cursor: Some(&c1),
                include_unchanged: false,
            },
        )
        .unwrap();
        assert_eq!(p2.changes.len(), 5);
        assert!(p2.more);
        let c2 = p2.next_cursor.unwrap();

        // Page 3: limit 5 (last page)
        let p3 = compare_nodes(
            doc,
            &from_root,
            &to_root,
            &from,
            &to,
            NodeDiffOptions {
                limit: Some(5),
                cursor: Some(&c2),
                include_unchanged: false,
            },
        )
        .unwrap();
        assert_eq!(p3.changes.len(), 5);
        assert!(!p3.more);
        assert_eq!(p3.next_cursor, None);

        // Verify distinct items across pages
        let mut seen = std::collections::BTreeSet::new();
        for diff in p1.changes.iter().chain(&p2.changes).chain(&p3.changes) {
            assert!(seen.insert(diff.node_id.clone()));
        }
        assert_eq!(seen.len(), 15);

        // Cursor tampering / mismatch rejection
        let other_doc = DocumentId(uuid::Uuid::new_v4());
        assert!(compare_nodes(
            other_doc,
            &from_root,
            &to_root,
            &from,
            &to,
            NodeDiffOptions {
                limit: Some(5),
                cursor: Some(&c1),
                include_unchanged: false,
            },
        )
        .is_err());

        assert!(compare_nodes(
            doc,
            &from_root,
            &to_root,
            &from,
            &to,
            NodeDiffOptions {
                limit: Some(5),
                cursor: Some("corrupted_hex"),
                include_unchanged: false,
            },
        )
        .is_err());
    }
}
