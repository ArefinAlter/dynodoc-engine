//! The project merge orchestrator (cross-document design 3.3 and 6): identity-keyed
//! planning, relocation lineage, edit-follows-move, split and join, project
//! constraints, explicit choices, and a v4 commit that records every automatic
//! decision so `verify-merge` can re-run it.
//!
//! Edit-follows-move (6.2, 6.3): when one side (X) relocated subtree `T` out of
//! document `P` into `A` and the other side (Y) edited `T` in `P`, the
//! destination is merged three ways over virtual states, each made by applying
//! X's own relocation record:
//!
//! ```text
//! base  = apply(rho, P at base,  A at base)      team  = A on X
//! draft = apply(rho, P on Y,     A on Y)         (Y's new children under T get
//!                                                 derived ids; its deletions follow)
//! ```
//!
//! and `P` is merged with Y's edits of `T` taken back to the base (X tombstoned
//! them). Both merges run through the node resolvers under the policy, in both
//! orientations, and must be clean; otherwise the pair is XD-R1. Y deleting a root
//! (XD-R2), Y deleting the destination parent (XD-R5), both sides relocating one
//! root differently (XD-R3, XD-R7), two splits of one file (XD-S2) and a join whose
//! source root fields Y changed (XD-S3) are never automatic.
//!
//! Chains (decision 042): when each side moved or split a different subtree out of
//! one source document `P` and the other side edited it there, both destinations
//! merge as above and `P` merges once, with each side's edits inside the subtree the
//! other side relocated taken back (they followed it). Both records name the same
//! merged source; each record's resolution set covers its destination's decisions and
//! the shared source merge. Other chains (a join, more than one relocation per side
//! out of `P`, a destination that is another relocation's source) stay XD-R3.
//!
//! Not built: typed cross-document references (E3 holds vacuously), re-anchoring
//! pending suggestions (refused at relocation, XD-Q5).

use super::{
    constraints::{self, Warning},
    convergence::converge_with_policy,
    local::LocalRepository,
    plan_v2::plan_v2,
    project::{
        self, Class, EmbeddedPolicy, Parent, PathDecision, ProjectResolution, ResolutionFile,
        SourceStates, XdConflict,
    },
    relocation::{self, Kind, Relocation},
    Commit, Error, FileEntry,
};
use crate::{
    materializer::DocumentState,
    merge_policy::{review, MergePolicy},
    shared_checkpoint::Address,
};
use engine_shared::DocumentId;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// What the merge decided for one document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileReport {
    pub document: DocumentId,
    pub path: String,
    /// `rename-follow`, `node-merge`, `edit-follows-move`, `explicit-left`,
    /// `explicit-right` or `explicit-delete`.
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_from: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelocationReport {
    pub id: String,
    pub kind: Kind,
    pub count: u32,
    pub side: Parent,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Evidence {
    pub documents_read: usize,
    pub orientations: u8,
    pub needs_review: bool,
    /// The hash a review of the commit binds (`project::resolution_set_hash`).
    pub resolution_set_hash: Option<String>,
}

/// The report of design 8.3.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub files: Vec<FileReport>,
    pub relocations: Vec<RelocationReport>,
    pub conflicts: Vec<XdConflict>,
    pub warnings: Vec<Warning>,
    pub evidence: Evidence,
}

#[derive(Debug)]
pub struct ProjectMerge {
    pub base: Address,
    /// The unsigned commit; `None` while a conflict has no choice (nothing stored).
    pub commit: Option<Commit>,
    pub report: Report,
}

/// `convergence::state_address`, boxed: the merge futures embed it many times and
/// an unboxed state machine that size overflows rustc's stack on Windows.
async fn address(document: DocumentId, state: &DocumentState) -> Result<Address, Error> {
    Box::pin(super::convergence::state_address(document, state)).await
}

fn entry_of(commit: &Commit, doc: DocumentId) -> Option<(&String, &FileEntry)> {
    commit.files.iter().find(|(_, f)| f.document == doc)
}

/// The outcome of one edit-follows-move.
pub(crate) struct Followed {
    pub dest: DocumentState,
    pub source: Option<DocumentState>,
    pub entries: Vec<review::Entry>,
    /// The destination merge's decisions alone (the first part of `entries`).
    pub dest_entries: Vec<review::Entry>,
}

/// `state` with every edit inside the subtree `t` taken back to `base` and every new
/// node under it removed: those edits followed the subtree to its destination.
fn take_back(
    state: &DocumentState,
    base: &DocumentState,
    t: &BTreeSet<engine_shared::NodeId>,
) -> DocumentState {
    let mut rest = state.clone();
    rest.nodes.retain(|id, n| {
        t.contains(id) || base.nodes.contains_key(id) || {
            let mut at = n.parent_id.as_ref();
            let mut steps = 0;
            while let Some(p) = at.filter(|_| steps < 4096) {
                if t.contains(p) {
                    return false;
                }
                steps += 1;
                at = state.nodes.get(p).and_then(|n| n.parent_id.as_ref());
            }
            true
        }
    });
    for id in t {
        if let Some(node) = base.nodes.get(id) {
            rest.nodes.insert(id.clone(), node.clone());
        }
    }
    rest
}

/// Relocation kinds that can form a chain out of one source document.
fn chainable(kind: Kind) -> bool {
    matches!(kind, Kind::Move | Kind::Split)
}

/// The source of a chain merged once (module notes): `left_rho` was made on the left,
/// `right_rho` on the right, both out of `document`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn chain_source(
    document: DocumentId,
    left_rho: &Relocation,
    right_rho: &Relocation,
    base_p: &DocumentState,
    left_p: &DocumentState,
    right_p: &DocumentState,
    policy: &MergePolicy,
) -> Result<(DocumentState, Vec<review::Entry>), (Class, String)> {
    let subtree = |rho: &Relocation| {
        relocation::subtree(base_p, &rho.spec().from.roots).map_err(|_| {
            (
                Class::MoveMove,
                "a relocated subtree is not in the base".to_string(),
            )
        })
    };
    let (tl, tr) = (subtree(left_rho)?, subtree(right_rho)?);
    if !tl.is_disjoint(&tr) {
        return Err((Class::MoveMove, "the two relocated subtrees overlap".into()));
    }
    let left = take_back(left_p, base_p, &tr);
    let right = take_back(right_p, base_p, &tl);
    Box::pin(converge(document, base_p, &left, &right, policy))
        .await
        .map_err(|n| {
            (
                Class::MoveMove,
                format!("{n} node conflicts left in the source both sides relocated out of"),
            )
        })
}

/// The node merge of one document in commit order, through `converge_with_policy`;
/// `Err(n)` with the number of node conflicts.
async fn converge(
    document: DocumentId,
    base: &DocumentState,
    left: &DocumentState,
    right: &DocumentState,
    policy: &MergePolicy,
) -> Result<(DocumentState, Vec<review::Entry>), usize> {
    let (la, ra) = match (
        address(document, left).await,
        address(document, right).await,
    ) {
        (Ok(l), Ok(r)) => (l, r),
        _ => return Err(1),
    };
    let (result, evidence) = converge_with_policy(base, left, right, &la, &ra, policy);
    match result.merged {
        Some(state) => Ok((
            state,
            review::entries(&evidence.evidence, evidence.team, Some(document)),
        )),
        None => Err(result.conflicts.len().max(1)),
    }
}

/// The destination and source merges of an edit-follows-move (module notes),
/// shared by preparing and verifying a merge. `x_is_left` says which parent made
/// the relocation; states are `None` where the document does not exist.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn follow(
    rho: &Relocation,
    x_is_left: bool,
    base_p: &DocumentState,
    x_p: Option<&DocumentState>,
    y_p: &DocumentState,
    base_a: Option<&DocumentState>,
    x_a: &DocumentState,
    y_a: Option<&DocumentState>,
    policy: &MergePolicy,
) -> Result<Followed, (Class, String)> {
    let spec = rho.spec();
    let t = relocation::subtree(base_p, &spec.from.roots).map_err(|_| {
        (
            Class::MoveEdit,
            "the relocated subtree is not in the base".to_string(),
        )
    })?;
    // XD-R2: Y removed a root, or a container above one.
    for root in &spec.from.roots {
        let mut at = Some(root);
        while let Some(id) = at {
            if y_p.nodes.get(id).is_none_or(|n| n.deleted) {
                return Err((
                    Class::MoveDelete,
                    format!(
                        "node {} was moved on one side and deleted on the other",
                        id.0
                    ),
                ));
            }
            at = base_p.nodes.get(id).and_then(|n| n.parent_id.as_ref());
        }
    }
    if rho.kind == Kind::Join {
        let root = base_p.nodes.values().find(|n| n.parent_id.is_none());
        if root.is_some_and(|r| y_p.nodes.get(&r.id) != Some(r)) {
            return Err((
                Class::JoinDropsProperties,
                "the joined document's root fields changed on the other side".into(),
            ));
        }
    }
    if rho.kind != Kind::Split
        && y_a.is_none_or(|a| a.nodes.get(&spec.to.parent).is_none_or(|n| n.deleted))
    {
        return Err((
            Class::DestinationDeleted,
            "the destination parent was deleted on the other side".into(),
        ));
    }
    let r1 = |e: Error| {
        (
            Class::MoveEdit,
            format!("the moved nodes' edits do not apply at the destination: {e}"),
        )
    };
    let vbase = relocation::apply(
        &spec,
        base_p,
        if rho.kind == Kind::Split {
            None
        } else {
            base_a
        },
    )
    .map_err(r1)?
    .dest;
    let y_dest = if rho.kind == Kind::Split { None } else { y_a };
    let mut vdraft = relocation::apply(&spec, y_p, y_dest).map_err(r1)?.dest;
    if rho.kind == Kind::Split {
        // The new document's root is a copy made at the split; root fields edited
        // on the other side stay with the source (design 6.4).
        let root = relocation::dest_id(&rho.id, &spec.to.parent);
        if let Some(at_base) = vbase.nodes.get(&root) {
            vdraft.nodes.insert(root, at_base.clone());
        }
    }
    let (l, r) = if x_is_left {
        (x_a, &vdraft)
    } else {
        (&vdraft, x_a)
    };
    let (dest, dest_entries) = Box::pin(converge(spec.to.document, &vbase, l, r, policy))
        .await
        .map_err(|n| {
            (
                Class::MoveEdit,
                format!("{n} node conflicts where the moved nodes were edited"),
            )
        })?;
    let mut entries = dest_entries.clone();
    let source = match (rho.kind, x_p) {
        (Kind::Join, _) => None,
        (_, None) => return Err((Class::MoveEdit, "the source document is missing".into())),
        (_, Some(x_p)) => {
            // Y's edits of T are at the destination now; take them back in P.
            let y_rest = take_back(y_p, base_p, &t);
            let (l, r) = if x_is_left {
                (x_p, &y_rest)
            } else {
                (&y_rest, x_p)
            };
            let (merged, more) = Box::pin(converge(spec.from.document, base_p, l, r, policy))
                .await
                .map_err(|n| {
                    (
                        Class::MoveEdit,
                        format!("{n} node conflicts left in the source document"),
                    )
                })?;
            entries.extend(more);
            Some(merged)
        }
    };
    Ok(Followed {
        dest,
        source,
        entries,
        dest_entries,
    })
}

impl LocalRepository {
    /// Relocation records of the commits reachable from `side` and not from `base`.
    pub async fn relocations_since(
        &self,
        base: &Address,
        side: &Address,
    ) -> Result<Vec<(Address, Relocation)>, Error> {
        let known = self.ancestors(base).await?;
        let mut out = Vec::new();
        for address in self.ancestors(side).await?.into_keys() {
            if known.contains_key(&address) {
                continue;
            }
            let commit = self.commit(&address).await?.commit;
            out.extend(commit.relocations.into_iter().map(|r| (address.clone(), r)));
        }
        out.sort_by(|a, b| a.1.id.cmp(&b.1.id));
        Ok(out)
    }

    async fn state_of(
        &self,
        commit: &Commit,
        doc: DocumentId,
    ) -> Result<Option<DocumentState>, Error> {
        match entry_of(commit, doc) {
            Some((_, f)) => Ok(Some(self.read_state(doc, &f.state).await?)),
            None => Ok(None),
        }
    }

    /// Prepare a two-parent project merge of `left` (first parent) and `right`
    /// under `policy`. Pure until every conflict has a choice; then the merged
    /// states are stored and the unsigned commit (v4 when anything was decided
    /// automatically, v1 otherwise) is returned.
    #[allow(clippy::too_many_lines)]
    pub async fn prepare_project_merge(
        &self,
        left: &Address,
        right: &Address,
        policy: &MergePolicy,
        choices: &ResolutionFile,
        authored_at_ms: i64,
        message: String,
    ) -> Result<ProjectMerge, Error> {
        if !choices.choices.is_empty() {
            choices.validate()?;
        }
        if left == right {
            return Err(Error::Invalid("merge parents must differ"));
        }
        let lc = self.commit(left).await?.commit;
        let rc = self.commit(right).await?.commit;
        let bases = self.merge_bases(left, right).await?;
        let [base] = bases.as_slice() else {
            return Err(Error::Invalid(
                "merge requires the unique best common ancestor; resolve disconnected or criss-cross history explicitly",
            ));
        };
        let bc = self.commit(base).await?.commit;
        let plan = plan_v2(&bc, &lc, &rc)?;
        let mut report = Report {
            warnings: plan.warnings.clone(),
            evidence: Evidence {
                orientations: 2,
                ..Evidence::default()
            },
            ..Report::default()
        };
        let mut conflicts = plan.conflicts.clone();
        let mut files = plan.files.clone();
        // Merged states by document, with the path they end at.
        let mut merged: BTreeMap<uuid::Uuid, (String, DocumentState)> = BTreeMap::new();
        let mut records: Vec<ProjectResolution> = Vec::new();
        let mut handled: BTreeSet<uuid::Uuid> = BTreeSet::new();
        // Destination decisions of each edit-follows-move record, by record index.
        let mut chain_dest: BTreeMap<usize, Vec<review::Entry>> = BTreeMap::new();
        let lrel = self.relocations_since(base, left).await?;
        let rrel = self.relocations_since(base, right).await?;
        let path_of = |doc: DocumentId| {
            [&lc, &rc, &bc]
                .into_iter()
                .find_map(|c| entry_of(c, doc).map(|(p, _)| p.clone()))
                .unwrap_or_else(|| doc.0.to_string())
        };
        for (side, list) in [(Parent::Left, &lrel), (Parent::Right, &rrel)] {
            for (_, r) in list {
                report.relocations.push(RelocationReport {
                    id: r.id.clone(),
                    kind: r.kind,
                    count: r.count,
                    side,
                    from: format!(
                        "{}#{}",
                        path_of(r.from.document),
                        r.from
                            .roots
                            .iter()
                            .map(|n| n.0.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                    to: format!("{}#{}", path_of(r.to.document), r.to.parent.0),
                });
            }
        }
        let shared: BTreeSet<&str> = lrel
            .iter()
            .filter(|(_, a)| rrel.iter().any(|(_, b)| b.id == a.id))
            .map(|(_, a)| a.id.as_str())
            .collect();
        let block = |class: Class,
                     docs: Vec<DocumentId>,
                     detail: String,
                     conflicts: &mut Vec<XdConflict>,
                     handled: &mut BTreeSet<uuid::Uuid>| {
            let participants = docs.iter().map(|d| path_of(*d)).collect();
            conflicts.push(XdConflict::new(class, participants, docs.clone(), detail));
            handled.extend(docs.iter().map(|d| d.0));
        };
        // Both sides relocated overlapping roots differently, or split one file twice.
        for (_, a) in &lrel {
            for (_, b) in &rrel {
                if a.id == b.id || a.from.document != b.from.document {
                    continue;
                }
                let overlap = a.from.roots.iter().any(|n| b.from.roots.contains(n));
                let class = if a.kind == Kind::Split && b.kind == Kind::Split {
                    Class::SplitSplit
                } else if overlap && (a.kind == Kind::Copy || b.kind == Kind::Copy) {
                    Class::DuplicateRelocation
                } else if overlap {
                    Class::MoveMove
                } else {
                    continue;
                };
                block(
                    class,
                    vec![a.from.document, a.to.document, b.to.document],
                    "one subtree relocated differently on the two sides".into(),
                    &mut conflicts,
                    &mut handled,
                );
            }
        }
        // Edit follows move.
        for (x, xc, yc, list) in [
            (Parent::Left, &lc, &rc, &lrel),
            (Parent::Right, &rc, &lc, &rrel),
        ] {
            for (_, rho) in list {
                if shared.contains(rho.id.as_str()) || rho.kind == Kind::Copy {
                    continue;
                }
                let (p, a) = (rho.from.document, rho.to.document);
                let Some((_, base_pe)) = entry_of(&bc, p) else {
                    continue; // the source was created after the base: nothing to follow
                };
                let y_pe = entry_of(yc, p);
                if y_pe.is_some_and(|(_, f)| f == base_pe) {
                    continue; // the other side left the source alone
                }
                // A chain: the other side already followed a relocation out of `p`.
                let partner = records.iter().position(|r| {
                    r.strategy == project::EDIT_FOLLOWS_MOVE
                        && r.follows != Some(x)
                        && r.source.as_ref().is_some_and(|s| s.document == p)
                        && r.document != a
                        && r.document != p
                        && [&lrel, &rrel].iter().any(|list| {
                            list.iter().any(|(_, q)| {
                                Some(&q.id) == r.relocation.as_ref() && chainable(q.kind)
                            })
                        })
                });
                let chain = partner.filter(|_| {
                    chainable(rho.kind)
                        && !handled.contains(&a.0)
                        && records
                            .iter()
                            .filter(|r| {
                                r.strategy == project::EDIT_FOLLOWS_MOVE
                                    && r.source.as_ref().is_some_and(|s| s.document == p)
                            })
                            .count()
                            == 1
                });
                if (handled.contains(&p.0) || handled.contains(&a.0)) && chain.is_none() {
                    block(
                        Class::MoveMove,
                        vec![p, a],
                        "relocations interact with other relocations".into(),
                        &mut conflicts,
                        &mut handled,
                    );
                    continue;
                }
                let base_p = self.read_state(p, &base_pe.state).await?;
                let Some((_, y_pe)) = y_pe else {
                    block(
                        Class::MoveDelete,
                        vec![p, a],
                        "the source document was deleted on the other side".into(),
                        &mut conflicts,
                        &mut handled,
                    );
                    continue;
                };
                let y_p = self.read_state(p, &y_pe.state).await?;
                let Ok(t) = relocation::subtree(&base_p, &rho.from.roots) else {
                    continue; // roots made after the base on the relocating side
                };
                let touched = t.iter().any(|n| y_p.nodes.get(n) != base_p.nodes.get(n))
                    || y_p.nodes.values().any(|n| {
                        !base_p.nodes.contains_key(&n.id)
                            && n.parent_id.as_ref().is_some_and(|q| t.contains(q))
                    });
                if !touched {
                    continue;
                }
                let x_p = self.state_of(xc, p).await?;
                let base_a = self.state_of(&bc, a).await?;
                let x_a = self
                    .state_of(xc, a)
                    .await?
                    .ok_or(Error::Invalid("relocation destination missing on its side"))?;
                let y_a = match (self.state_of(yc, a).await?, &base_a) {
                    (Some(s), _) => Some(s),
                    // The destination does not exist on Y: it was new on X (split).
                    (None, None) => None,
                    (None, Some(_)) => {
                        block(
                            Class::DestinationDeleted,
                            vec![p, a],
                            "the destination document was deleted on the other side".into(),
                            &mut conflicts,
                            &mut handled,
                        );
                        continue;
                    }
                };
                report.evidence.documents_read += 6;
                match Box::pin(follow(
                    rho,
                    x == Parent::Left,
                    &base_p,
                    x_p.as_ref(),
                    &y_p,
                    base_a.as_ref(),
                    &x_a,
                    y_a.as_ref(),
                    policy,
                ))
                .await
                {
                    Err((class, detail)) => {
                        block(class, vec![p, a], detail, &mut conflicts, &mut handled)
                    }
                    Ok(mut done) => {
                        handled.extend([p.0, a.0]);
                        let dest_addr = address(a, &done.dest).await?;
                        if let Some(k) = chain {
                            let other_id = records[k].relocation.clone().unwrap_or_default();
                            let other = lrel
                                .iter()
                                .chain(rrel.iter())
                                .map(|(_, q)| q)
                                .find(|q| q.id == other_id)
                                .ok_or(Error::Invalid("chained relocation vanished"))?;
                            let (left_rho, right_rho) = if x == Parent::Left {
                                (rho, other)
                            } else {
                                (other, rho)
                            };
                            let (Some(left_p), Some(right_p)) =
                                (self.state_of(&lc, p).await?, self.state_of(&rc, p).await?)
                            else {
                                return Err(Error::Invalid("chain source missing on a side"));
                            };
                            match chain_source(
                                p, left_rho, right_rho, &base_p, &left_p, &right_p, policy,
                            )
                            .await
                            {
                                Err((class, detail)) => {
                                    block(class, vec![p, a], detail, &mut conflicts, &mut handled);
                                    continue;
                                }
                                Ok((source, shared)) => {
                                    let source_addr = address(p, &source).await?;
                                    let other_dest = chain_dest.remove(&k).unwrap_or_default();
                                    let mut other_entries = other_dest;
                                    other_entries.extend(shared.iter().cloned());
                                    let r = &mut records[k];
                                    if let Some(s) = r.source.as_mut() {
                                        s.merged = Some(source_addr.clone());
                                    }
                                    r.needs_review = review::needs_review(&other_entries);
                                    r.resolution_set = Some(review::hash_hex(&other_entries));
                                    done.entries = done.dest_entries.clone();
                                    done.entries.extend(shared);
                                    done.source = Some(source);
                                }
                            }
                        }
                        let source_addr = match &done.source {
                            Some(s) => Some(address(p, s).await?),
                            None => None,
                        };
                        let a_path = entry_of(xc, a)
                            .map(|(p, _)| p.clone())
                            .unwrap_or_else(|| path_of(a));
                        merged.insert(a.0, (a_path.clone(), done.dest));
                        if let Some(s) = done.source {
                            let p_path = entry_of(xc, p)
                                .map(|(p, _)| p.clone())
                                .unwrap_or_else(|| path_of(p));
                            merged.insert(p.0, (p_path, s));
                        }
                        let st = |c: &Commit, d| entry_of(c, d).map(|(_, f)| f.state.clone());
                        chain_dest.insert(records.len(), done.dest_entries.clone());
                        records.push(ProjectResolution {
                            id: String::new(),
                            strategy: project::EDIT_FOLLOWS_MOVE.into(),
                            document: a,
                            base: st(&bc, a),
                            left: st(&lc, a),
                            right: st(&rc, a),
                            merged: dest_addr,
                            path: None,
                            relocation: Some(rho.id.clone()),
                            follows: Some(x),
                            source: Some(SourceStates {
                                document: p,
                                base: base_pe.state.clone(),
                                left: st(&lc, p),
                                right: st(&rc, p),
                                merged: source_addr,
                            }),
                            needs_review: review::needs_review(&done.entries),
                            resolution_set: Some(review::hash_hex(&done.entries)),
                        });
                        report.files.push(FileReport {
                            document: a,
                            path: a_path,
                            decision: "edit-follows-move".into(),
                            path_from: None,
                        });
                    }
                }
            }
        }
        // Handled documents leave the plan's own decisions and conflicts.
        let relocation_class =
            |c: &XdConflict| c.id.starts_with("XD-R") || c.id.starts_with("XD-S");
        conflicts
            .retain(|c| relocation_class(c) || !c.documents.iter().all(|d| handled.contains(&d.0)));
        files.retain(|_, f| !handled.contains(&f.document.0));
        // Ordinary node merges.
        for m in plan
            .merges
            .iter()
            .filter(|m| !handled.contains(&m.document.0))
        {
            let base_s = match &m.base {
                Some(b) => self.read_state(m.document, b).await?,
                None => DocumentState::default(),
            };
            let left_s = self.read_state(m.document, &m.left).await?;
            let right_s = self.read_state(m.document, &m.right).await?;
            report.evidence.documents_read += 3;
            match Box::pin(converge(m.document, &base_s, &left_s, &right_s, policy)).await {
                Ok((state, entries)) => {
                    records.push(ProjectResolution {
                        id: String::new(),
                        strategy: project::SAME_FILE.into(),
                        document: m.document,
                        base: m.base.clone(),
                        left: Some(m.left.clone()),
                        right: Some(m.right.clone()),
                        merged: address(m.document, &state).await?,
                        path: None,
                        relocation: None,
                        follows: None,
                        source: None,
                        needs_review: review::needs_review(&entries),
                        resolution_set: Some(review::hash_hex(&entries)),
                    });
                    report.files.push(FileReport {
                        document: m.document,
                        path: m.path.clone(),
                        decision: "node-merge".into(),
                        path_from: None,
                    });
                    merged.insert(m.document.0, (m.path.clone(), state));
                }
                Err(n) => conflicts.push(XdConflict::new(
                    if m.base.is_some() {
                        Class::SameDocumentEdited
                    } else {
                        Class::AddAdd
                    },
                    vec![m.path.clone()],
                    vec![m.document],
                    format!("{n} node or field conflicts"),
                )),
            }
        }
        // C3 over the documents the merge produced.
        let produced: Vec<(String, DocumentId, &DocumentState)> = merged
            .iter()
            .map(|(d, (p, s))| (p.clone(), DocumentId(*d), s))
            .collect();
        conflicts.extend(constraints::node_identity(&produced));
        // Explicit choices.
        let known: BTreeSet<&str> = conflicts.iter().map(|c| c.id.as_str()).collect();
        if choices
            .choices
            .iter()
            .any(|c| !known.contains(c.conflict.as_str()))
        {
            return Err(Error::Invalid("resolution names an unknown conflict"));
        }
        let mut unresolved = Vec::new();
        let mut explicit: BTreeSet<uuid::Uuid> = BTreeSet::new();
        for conflict in &conflicts {
            let Some(choice) = choices.choices.iter().find(|c| c.conflict == conflict.id) else {
                unresolved.push(conflict.clone());
                continue;
            };
            for doc in &conflict.documents {
                explicit.insert(doc.0);
                files.retain(|_, f| f.document != *doc);
                merged.remove(&doc.0);
                let side = match choice.take.as_str() {
                    "left" => Some(&lc),
                    "right" => Some(&rc),
                    _ => None,
                };
                if let Some((path, f)) = side.and_then(|c| entry_of(c, *doc)) {
                    files.insert(path.clone(), f.clone());
                }
                report.files.push(FileReport {
                    document: *doc,
                    path: path_of(*doc),
                    decision: format!("explicit-{}", choice.take),
                    path_from: None,
                });
            }
        }
        records.retain(|r| {
            !explicit.contains(&r.document.0)
                && r.source
                    .as_ref()
                    .is_none_or(|s| !explicit.contains(&s.document.0))
        });
        // Rename-follow records for renamed documents the merge kept automatically.
        for rf in &plan.renames {
            if explicit.contains(&rf.document.0)
                || (handled.contains(&rf.document.0) && !merged.contains_key(&rf.document.0))
            {
                continue;
            }
            let state = match merged.get(&rf.document.0) {
                Some((_, s)) => address(rf.document, s).await?,
                None => match files.get(&rf.path.merged) {
                    Some(f) if f.document == rf.document => f.state.clone(),
                    _ => continue,
                },
            };
            records.push(ProjectResolution {
                id: String::new(),
                strategy: project::RENAME_FOLLOW.into(),
                document: rf.document,
                base: Some(rf.base.clone()),
                left: Some(rf.left.clone()),
                right: Some(rf.right.clone()),
                merged: state,
                path: Some(PathDecision { ..rf.path.clone() }),
                relocation: None,
                follows: None,
                source: None,
                needs_review: false,
                resolution_set: None,
            });
            report.files.push(FileReport {
                document: rf.document,
                path: rf.path.merged.clone(),
                decision: "rename-follow".into(),
                path_from: Some(rf.path.base.clone()),
            });
        }
        report.files.sort_by(|a, b| {
            (a.path.as_str(), a.decision.as_str()).cmp(&(b.path.as_str(), b.decision.as_str()))
        });
        unresolved.sort_by(|a, b| a.id.cmp(&b.id));
        report.conflicts = unresolved;
        if !report.conflicts.is_empty() {
            return Ok(ProjectMerge {
                base: base.clone(),
                commit: None,
                report,
            });
        }
        // Store the merged states; the addresses must be the predicted ones.
        for (doc, (path, state)) in &merged {
            let document = DocumentId(*doc);
            let predicted = address(document, state).await?;
            let (stored, _) = self.write_state(document, state).await?;
            if stored != predicted {
                return Err(Error::Invalid("merged state address changed while storing"));
            }
            files.retain(|_, f| f.document != document);
            files.insert(
                path.clone(),
                FileEntry {
                    document,
                    state: stored,
                },
            );
        }
        for (k, r) in records.iter_mut().enumerate() {
            r.id = format!("r{}", k + 1);
        }
        let v4 = !records.is_empty();
        let commit = Commit {
            version: if v4 { 4 } else { 1 },
            project: self.project(),
            parents: vec![left.clone(), right.clone()],
            files,
            author_key: "00".repeat(32),
            authored_at_ms,
            message,
            recovery: None,
            same_file_resolutions: Vec::new(),
            sealed: None,
            project_resolutions: records,
            relocations: Vec::new(),
            merge_policy: v4.then(|| EmbeddedPolicy::of(policy)),
        };
        commit.bytes()?;
        if v4 {
            report.evidence.needs_review = project::needs_review(&commit);
            report.evidence.resolution_set_hash = Some(project::resolution_set_hash(&commit));
        }
        Ok(ProjectMerge {
            base: base.clone(),
            commit: Some(commit),
            report,
        })
    }

    /// Re-run every project resolution of a stored v4 merge from its recorded
    /// inputs under its embedded policy, and require the recorded merged states,
    /// review flags and resolution sets. Returns the number of records verified.
    pub async fn verify_project_resolutions(&self, commit: &Address) -> Result<usize, Error> {
        let c = self.commit(commit).await?.commit;
        verify_records(&c, &mut LocalInputs(self)).await
    }
}

/// What re-running a merge's recorded resolutions reads: a local repository, or the
/// shared service's published history at publication (decision 042).
pub trait ResolutionInputs: Send {
    /// A document state by address.
    fn state(
        &mut self,
        document: DocumentId,
        at: &Address,
    ) -> impl std::future::Future<Output = Result<DocumentState, Error>> + Send;
    /// The best common ancestors of two commits.
    fn merge_bases(
        &mut self,
        left: &Address,
        right: &Address,
    ) -> impl std::future::Future<Output = Result<Vec<Address>, Error>> + Send;
    /// The relocation records of the commits reachable from `side` and not `base`.
    fn relocations_since(
        &mut self,
        base: &Address,
        side: &Address,
    ) -> impl std::future::Future<Output = Result<Vec<Relocation>, Error>> + Send;
}

struct LocalInputs<'a>(&'a LocalRepository);

impl ResolutionInputs for LocalInputs<'_> {
    async fn state(&mut self, document: DocumentId, at: &Address) -> Result<DocumentState, Error> {
        self.0.read_state(document, at).await
    }
    async fn merge_bases(
        &mut self,
        left: &Address,
        right: &Address,
    ) -> Result<Vec<Address>, Error> {
        self.0.merge_bases(left, right).await
    }
    async fn relocations_since(
        &mut self,
        base: &Address,
        side: &Address,
    ) -> Result<Vec<Relocation>, Error> {
        Ok(self
            .0
            .relocations_since(base, side)
            .await?
            .into_iter()
            .map(|(_, rho)| rho)
            .collect())
    }
}

/// Re-run every project resolution of the v4 merge `c` from its recorded inputs
/// under its embedded policy, and require the recorded merged states, review flags
/// and resolution sets: a forged or altered automatic resolution is refused. Returns
/// the number of records verified.
pub async fn verify_records<I: ResolutionInputs>(
    c: &Commit,
    inputs: &mut I,
) -> Result<usize, Error> {
    if c.project_resolutions.is_empty() {
        return Ok(0);
    }
    let policy = c
        .merge_policy
        .as_ref()
        .ok_or(Error::Invalid("v4 merge without a policy"))?
        .load()?;
    let fail = || Error::Invalid("project resolution does not reproduce its recorded state");
    for r in &c.project_resolutions {
        match r.strategy.as_str() {
            project::SAME_FILE => {
                let base = match &r.base {
                    Some(a) => inputs.state(r.document, a).await?,
                    None => DocumentState::default(),
                };
                let (Some(left), Some(right)) = (&r.left, &r.right) else {
                    return Err(fail());
                };
                let left = inputs.state(r.document, left).await?;
                let right = inputs.state(r.document, right).await?;
                let (state, entries) =
                    Box::pin(converge(r.document, &base, &left, &right, &policy))
                        .await
                        .map_err(|_| fail())?;
                if address(r.document, &state).await? != r.merged
                    || r.resolution_set.as_deref() != Some(review::hash_hex(&entries).as_str())
                    || r.needs_review != review::needs_review(&entries)
                {
                    return Err(fail());
                }
            }
            project::RENAME_FOLLOW => {
                let p = r.path.as_ref().ok_or_else(fail)?;
                let three = if p.right == p.base {
                    &p.left
                } else if p.left == p.base {
                    &p.right
                } else {
                    return Err(fail());
                };
                if *three != p.merged {
                    return Err(fail());
                }
            }
            _ => {
                let (Some(id), Some(x), Some(s)) = (&r.relocation, r.follows, &r.source) else {
                    return Err(fail());
                };
                let side = &c.parents[usize::from(x == Parent::Right)];
                let bases = inputs.merge_bases(&c.parents[0], &c.parents[1]).await?;
                let [base] = bases.as_slice() else {
                    return Err(fail());
                };
                let rho = inputs
                    .relocations_since(base, side)
                    .await?
                    .into_iter()
                    .find(|rho| rho.id == *id)
                    .ok_or_else(fail)?;
                let (x_dest, y_dest) = if x == Parent::Left {
                    (&r.left, &r.right)
                } else {
                    (&r.right, &r.left)
                };
                let (x_src, y_src) = if x == Parent::Left {
                    (&s.left, &s.right)
                } else {
                    (&s.right, &s.left)
                };
                let mut read = async |doc: DocumentId, a: &Option<Address>| match a {
                    Some(a) => inputs.state(doc, a).await.map(Some),
                    None => Ok(None),
                };
                let base_p = read(s.document, &Some(s.base.clone()))
                    .await?
                    .ok_or_else(fail)?;
                let x_p = read(s.document, x_src).await?;
                let y_p = read(s.document, y_src).await?.ok_or_else(fail)?;
                let base_a = read(r.document, &r.base).await?;
                let x_a = read(r.document, x_dest).await?.ok_or_else(fail)?;
                let y_a = read(r.document, y_dest).await?;
                let done = Box::pin(follow(
                    &rho,
                    x == Parent::Left,
                    &base_p,
                    x_p.as_ref(),
                    &y_p,
                    base_a.as_ref(),
                    &x_a,
                    y_a.as_ref(),
                    &policy,
                ))
                .await
                .map_err(|_| fail())?;
                let partner = c.project_resolutions.iter().find(|q| {
                    q.id != r.id
                        && q.strategy == project::EDIT_FOLLOWS_MOVE
                        && q.follows != r.follows
                        && q.source
                            .as_ref()
                            .is_some_and(|qs| qs.document == s.document)
                });
                let (source, entries) = match partner {
                    None => (done.source, done.entries),
                    Some(q) => {
                        // A chain: the source merged once with both relocations.
                        let (Some(q_id), Some(q_x)) = (&q.relocation, q.follows) else {
                            return Err(fail());
                        };
                        let q_side = &c.parents[usize::from(q_x == Parent::Right)];
                        let other = inputs
                            .relocations_since(base, q_side)
                            .await?
                            .into_iter()
                            .find(|o| o.id == *q_id && chainable(o.kind))
                            .ok_or_else(fail)?;
                        if !chainable(rho.kind) {
                            return Err(fail());
                        }
                        let (left_rho, right_rho) = if x == Parent::Left {
                            (&rho, &other)
                        } else {
                            (&other, &rho)
                        };
                        let x_p = x_p.as_ref().ok_or_else(fail)?;
                        let (left_p, right_p) = if x == Parent::Left {
                            (x_p, &y_p)
                        } else {
                            (&y_p, x_p)
                        };
                        let (state, shared) = chain_source(
                            s.document, left_rho, right_rho, &base_p, left_p, right_p, &policy,
                        )
                        .await
                        .map_err(|_| fail())?;
                        let mut entries = done.dest_entries;
                        entries.extend(shared);
                        (Some(state), entries)
                    }
                };
                let source = match &source {
                    Some(st) => Some(address(s.document, st).await?),
                    None => None,
                };
                if address(r.document, &done.dest).await? != r.merged
                    || source != s.merged
                    || r.resolution_set.as_deref() != Some(review::hash_hex(&entries).as_str())
                    || r.needs_review != review::needs_review(&entries)
                {
                    return Err(fail());
                }
            }
        }
    }
    Ok(c.project_resolutions.len())
}

/// Re-run the same-file resolutions of `c` (commit format v3, the frozen hunk merge)
/// and require each recorded merged state. Returns the number verified.
pub async fn verify_same_file_records<I: ResolutionInputs>(
    c: &Commit,
    inputs: &mut I,
) -> Result<usize, Error> {
    for record in &c.same_file_resolutions {
        let base = inputs.state(record.document, &record.base).await?;
        let left = inputs.state(record.document, &record.left).await?;
        let right = inputs.state(record.document, &record.right).await?;
        let result =
            super::convergence::converge(&base, &left, &right, &record.left, &record.right);
        let reproduced = match &result.merged {
            Some(state) => Some(address(record.document, state).await?),
            None => None,
        };
        if reproduced.as_ref() != Some(&record.merged) {
            return Err(Error::Invalid(
                "same-file resolution does not reproduce its recorded state",
            ));
        }
    }
    Ok(c.same_file_resolutions.len())
}
