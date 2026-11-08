//! `plan_v2` (cross-document design 6.1): the project three-way plan keyed by
//! document UUID, not path. Path, presence and state are decided separately, so a
//! rename on one side and an edit on the other merge (rename-follow, XD-F8), where
//! the path planner (`compare::plan`) reports a delete/edit conflict.
//!
//! For histories without renames it decides exactly what `plan` decides: the paths
//! `plan` reports as conflicts are this plan's conflicts and documents that need a
//! node merge, and the resolved files are equal (property test T1).

use super::{
    constraints,
    project::{Class, PathDecision, XdConflict},
    Commit, Error, FileEntry,
};
use crate::shared_checkpoint::Address;
use engine_shared::DocumentId;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// A document whose state changed on both sides: it needs the node merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocMerge {
    pub document: DocumentId,
    /// The merged path.
    pub path: String,
    /// `None` when the document was added on both sides (XD-F7).
    pub base: Option<Address>,
    pub left: Address,
    pub right: Address,
}

/// A path decision that took the path of one side and the state of the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenameFollow {
    pub document: DocumentId,
    pub path: PathDecision,
    pub base: Address,
    pub left: Address,
    pub right: Address,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PlanV2 {
    /// Resolved entries, without the documents of `merges` and `conflicts`.
    pub files: BTreeMap<String, FileEntry>,
    pub merges: Vec<DocMerge>,
    pub renames: Vec<RenameFollow>,
    pub conflicts: Vec<XdConflict>,
    pub warnings: Vec<constraints::Warning>,
}

type Side<'a> = Option<(&'a String, &'a FileEntry)>;

fn index(commit: &Commit) -> BTreeMap<uuid::Uuid, (&String, &FileEntry)> {
    commit
        .files
        .iter()
        .map(|(p, f)| (f.document.0, (p, f)))
        .collect()
}

fn three<T: PartialEq + Clone>(b: &T, l: &T, r: &T) -> Option<T> {
    if r == b || l == r {
        Some(l.clone())
    } else if l == b {
        Some(r.clone())
    } else {
        None
    }
}

pub fn plan_v2(base: &Commit, left: &Commit, right: &Commit) -> Result<PlanV2, Error> {
    for commit in [base, left, right] {
        commit.validate()?;
    }
    if base.project != left.project || base.project != right.project {
        return Err(Error::Invalid("merge project scope"));
    }
    let (ib, il, ir) = (index(base), index(left), index(right));
    let ids: BTreeSet<uuid::Uuid> = ib
        .keys()
        .chain(il.keys())
        .chain(ir.keys())
        .copied()
        .collect();
    let mut plan = PlanV2::default();
    // Candidate entries by path before the namespace checks, with their documents.
    let mut candidate: Vec<(String, FileEntry, Option<usize>)> = Vec::new();
    for id in ids {
        let doc = DocumentId(id);
        let (b, l, r): (Side, Side, Side) = (
            ib.get(&id).copied(),
            il.get(&id).copied(),
            ir.get(&id).copied(),
        );
        let paths = |sides: &[Side]| {
            sides
                .iter()
                .flatten()
                .map(|(p, _)| (*p).clone())
                .collect::<Vec<_>>()
        };
        match (b, l, r) {
            (Some(_), None, None) => {}
            (Some(b), None, Some(o)) | (Some(b), Some(o), None) => {
                if o.1 == b.1 && o.0 == b.0 {
                    continue; // unchanged on one side, deleted on the other
                }
                let class = if o.1 == b.1 {
                    Class::RenameDelete
                } else {
                    Class::DeleteEdit
                };
                plan.conflicts.push(XdConflict::new(
                    class,
                    paths(&[Some(b), Some(o)]),
                    vec![doc],
                    match class {
                        Class::RenameDelete => "renamed on one side and deleted on the other",
                        _ => "deleted on one side and edited on the other",
                    },
                ));
            }
            (None, Some(x), None) | (None, None, Some(x)) => {
                candidate.push((x.0.clone(), x.1.clone(), None))
            }
            (None, Some(l), Some(r)) => {
                if l == r {
                    candidate.push((l.0.clone(), l.1.clone(), None));
                } else if l.0 != r.0 {
                    plan.conflicts.push(XdConflict::new(
                        Class::RenameRename,
                        paths(&[Some(l), Some(r)]),
                        vec![doc],
                        "one document added on both sides at different paths",
                    ));
                } else {
                    plan.merges.push(DocMerge {
                        document: doc,
                        path: l.0.clone(),
                        base: None,
                        left: l.1.state.clone(),
                        right: r.1.state.clone(),
                    });
                    candidate.push((l.0.clone(), l.1.clone(), Some(plan.merges.len() - 1)));
                }
            }
            (Some(b), Some(l), Some(r)) => {
                let Some(path) = three(b.0, l.0, r.0) else {
                    plan.conflicts.push(XdConflict::new(
                        Class::RenameRename,
                        paths(&[Some(b), Some(l), Some(r)]),
                        vec![doc],
                        "renamed to different paths on the two sides",
                    ));
                    continue;
                };
                let renamed = path != *b.0;
                match three(&b.1.state, &l.1.state, &r.1.state) {
                    Some(state) => {
                        let entry = FileEntry {
                            document: doc,
                            state: state.clone(),
                        };
                        // Path from one side, state from the other: rename-follow.
                        if renamed && (l.0 == b.0) != (l.1.state == b.1.state) {
                            plan.renames.push(RenameFollow {
                                document: doc,
                                path: PathDecision {
                                    base: b.0.clone(),
                                    left: l.0.clone(),
                                    right: r.0.clone(),
                                    merged: path.clone(),
                                },
                                base: b.1.state.clone(),
                                left: l.1.state.clone(),
                                right: r.1.state.clone(),
                            });
                        }
                        candidate.push((path.clone(), entry, None));
                    }
                    None => {
                        if renamed {
                            plan.renames.push(RenameFollow {
                                document: doc,
                                path: PathDecision {
                                    base: b.0.clone(),
                                    left: l.0.clone(),
                                    right: r.0.clone(),
                                    merged: path.clone(),
                                },
                                base: b.1.state.clone(),
                                left: l.1.state.clone(),
                                right: r.1.state.clone(),
                            });
                        }
                        plan.merges.push(DocMerge {
                            document: doc,
                            path: path.clone(),
                            base: Some(b.1.state.clone()),
                            left: l.1.state.clone(),
                            right: r.1.state.clone(),
                        });
                        candidate.push((path.clone(), l.1.clone(), Some(plan.merges.len() - 1)));
                    }
                }
            }
            (None, None, None) => {}
        }
    }
    // Namespace: two documents on one path (XD-F4), a file used as a directory
    // (XD-F5); every participant is a conflict, never an arbitrary winner.
    let mut by_path: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (k, (path, _, _)) in candidate.iter().enumerate() {
        by_path.entry(path.as_str()).or_default().push(k);
    }
    let mut out: BTreeSet<usize> = BTreeSet::new();
    for (path, at) in &by_path {
        if at.len() > 1 {
            plan.conflicts.push(XdConflict::new(
                Class::PathClaimedTwice,
                vec![(*path).to_string()],
                at.iter().map(|k| candidate[*k].1.document).collect(),
                "two documents claim one path",
            ));
            out.extend(at);
        }
        for (i, _) in path.match_indices('/') {
            if let Some(dir) = by_path.get(&path[..i]) {
                plan.conflicts.push(XdConflict::new(
                    Class::FileDirectory,
                    vec![(*path).to_string(), path[..i].to_string()],
                    at.iter()
                        .chain(dir)
                        .map(|k| candidate[*k].1.document)
                        .collect(),
                    "a file is also a directory",
                ));
                out.extend(at.iter().chain(dir));
            }
        }
    }
    let mut dropped_merges = BTreeSet::new();
    for (k, (path, entry, merge)) in candidate.into_iter().enumerate() {
        if out.contains(&k) {
            if let Some(m) = merge {
                dropped_merges.insert(m);
            }
            continue;
        }
        if merge.is_none() {
            plan.files.insert(path, entry);
        }
    }
    let merges = std::mem::take(&mut plan.merges);
    plan.merges = merges
        .into_iter()
        .enumerate()
        .filter(|(k, _)| !dropped_merges.contains(k))
        .map(|(_, m)| m)
        .collect();
    let in_conflict: BTreeSet<uuid::Uuid> = plan
        .conflicts
        .iter()
        .flat_map(|c| c.documents.iter().map(|d| d.0))
        .collect();
    plan.renames
        .retain(|r| !in_conflict.contains(&r.document.0));
    // C7: portability over every path the result would hold.
    let mut all = plan.files.clone();
    for m in &plan.merges {
        all.insert(
            m.path.clone(),
            FileEntry {
                document: m.document,
                state: m.left.clone(),
            },
        );
    }
    let (collisions, warnings) = constraints::portability(&all);
    for c in &collisions {
        for d in &c.documents {
            plan.files.retain(|_, f| f.document != *d);
        }
    }
    plan.merges
        .retain(|m| !collisions.iter().any(|c| c.documents.contains(&m.document)));
    plan.conflicts.extend(collisions);
    plan.warnings = warnings;
    plan.conflicts.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(doc: u128, state: u8) -> FileEntry {
        FileEntry {
            document: DocumentId(uuid::Uuid::from_u128(doc)),
            state: Address::try_from(format!("{state:02x}").repeat(32)).unwrap(),
        }
    }

    fn commit(files: &[(&str, FileEntry)]) -> Commit {
        Commit {
            version: 1,
            project: uuid::Uuid::from_u128(9),
            parents: Vec::new(),
            files: files
                .iter()
                .map(|(p, f)| (p.to_string(), f.clone()))
                .collect(),
            author_key: "00".repeat(32),
            authored_at_ms: 0,
            message: String::new(),
            recovery: None,
            same_file_resolutions: Vec::new(),
            sealed: None,
            project_resolutions: Vec::new(),
            relocations: Vec::new(),
            merge_policy: None,
        }
    }

    #[test]
    fn rename_on_one_side_and_edit_on_the_other_follow_where_plan_conflicts() {
        let base = commit(&[("Budget.xlsx", entry(1, 1))]);
        let left = commit(&[("Finance/Budget.xlsx", entry(1, 1))]);
        let right = commit(&[("Budget.xlsx", entry(1, 2))]);
        // P0: the path planner's behaviour, pinned. The old path is a delete/edit
        // conflict and the new path carries the old state.
        let old = super::super::compare::plan(&base, &left, &right).unwrap();
        assert_eq!(
            old.conflicts
                .iter()
                .map(|c| c.path.as_str())
                .collect::<Vec<_>>(),
            ["Budget.xlsx"]
        );
        assert_eq!(old.files["Finance/Budget.xlsx"], entry(1, 1));
        let plan = plan_v2(&base, &left, &right).unwrap();
        assert!(plan.conflicts.is_empty() && plan.merges.is_empty());
        assert_eq!(plan.files["Finance/Budget.xlsx"], entry(1, 2));
        assert_eq!(plan.renames.len(), 1);
        assert_eq!(plan.renames[0].path.merged, "Finance/Budget.xlsx");
        // Either orientation.
        let swapped = plan_v2(&base, &right, &left).unwrap();
        assert_eq!(swapped.files, plan.files);
    }

    #[test]
    fn competing_renames_and_rename_against_delete_are_never_automatic() {
        let base = commit(&[("a", entry(1, 1))]);
        let p = plan_v2(
            &base,
            &commit(&[("b", entry(1, 1))]),
            &commit(&[("c", entry(1, 1))]),
        )
        .unwrap();
        assert_eq!(p.conflicts[0].class, Class::RenameRename);
        let p = plan_v2(&base, &commit(&[("b", entry(1, 1))]), &commit(&[])).unwrap();
        assert_eq!(p.conflicts[0].class, Class::RenameDelete);
        let p = plan_v2(&base, &commit(&[("a", entry(1, 2))]), &commit(&[])).unwrap();
        assert_eq!(p.conflicts[0].class, Class::DeleteEdit);
        // Two documents on one path, and a collision only case folding sees.
        let p = plan_v2(
            &base,
            &commit(&[("a", entry(1, 1)), ("x", entry(2, 1))]),
            &commit(&[("a", entry(1, 1)), ("X", entry(3, 1))]),
        )
        .unwrap();
        assert_eq!(p.conflicts.len(), 1);
        assert_eq!(p.conflicts[0].class, Class::PortabilityCollision);
        assert!(p.files.contains_key("a") && !p.files.contains_key("x"));
    }
}
