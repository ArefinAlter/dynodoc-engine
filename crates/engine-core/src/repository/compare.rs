//! Project-level three-way planning and two-commit manifest comparison.
//!
//! Equal/unchanged roots merge without reading document bodies; competing
//! changes are explicit conflicts. No guessed identity matching, silent file
//! deletion, or automatic merge of shared constraints.

use super::{Address, Commit, Error, FileEntry, SignedCommit};
use serde::{Deserialize, Serialize};
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
}
