//! Relocation records (cross-document design 4.3, 5.1, 5.2): signed lineage for a
//! subtree moved, copied, split off into a new document or joined into another.
//!
//! Identifiers are re-minted, because a node id is the primary key of the
//! centralized `node` table and cannot live in two documents of one installation.
//! They are derived, so two replicas making the same relocation get the same ids:
//!
//! ```text
//! relocation_id = hex SHA-256("dynodoc.relocation\0v1\0" || kind || 0 || from_document
//!                  || 0 || roots joined by "," || 0 || to_document || 0 || to_parent
//!                  || 0 || to_position)
//! dest_id(n)    = ULID of SHA-256("dynodoc.node-derive\0v1\0" || relocation_id (32
//!                  bytes) || n)[0..16]
//! ```
//!
//! (Any 128 bits are a valid ULID; the first of its 26 Crockford characters is
//! `0`-`7`.) `kind` is part of the relocation id, so a copy and a move to one slot
//! differ. For a split, `to.parent` names the source root: its derived copy is the
//! new document's root, holding the source root's type and fields.
//!
//! A record is accepted only when re-applying it to the parent's states gives
//! exactly the commit's states (R1 to R7); R8 (the signer may write the
//! destination) is the service's check. Nothing here reads text: records hold
//! ids, paths and state roots only.

use super::{convergence::state_address, Commit, Error, FileEntry};
use crate::{
    materializer::{CommentState, DocumentState, MaterializedNode},
    shared_checkpoint::Address,
};
use engine_shared::{DocumentId, NodeId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_RELOCATIONS: usize = 256;
pub const MAX_NODES: usize = 10_000;
const MAX_ROOTS: usize = 256;
const RELOCATION_DOMAIN: &[u8] = b"dynodoc.relocation\0v1\0";
const DERIVE_DOMAIN: &[u8] = b"dynodoc.node-derive\0v1\0";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// The subtree leaves the source (tombstoned) and lives in the destination.
    Move,
    /// The source keeps the subtree; the destination gets a derived copy.
    Copy,
    /// A move into a document the parent commit does not have.
    Split,
    /// The source's root children move into the destination and the source is
    /// removed from the project.
    Join,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Move => "move",
            Self::Copy => "copy",
            Self::Split => "split",
            Self::Join => "join",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub document: DocumentId,
    /// The subtree roots, in the order they are placed.
    pub roots: Vec<NodeId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub document: DocumentId,
    pub parent: NodeId,
    pub position: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relocation {
    pub id: String,
    pub kind: Kind,
    pub from: Source,
    pub to: Destination,
    /// Live nodes in the relocated subtrees (R3).
    pub count: u32,
    /// The source state after the relocation; `None` for a join (source removed).
    pub source_state_after: Option<Address>,
    pub dest_state_after: Address,
}

/// What to relocate, before ids and states are derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub kind: Kind,
    pub from: Source,
    pub to: Destination,
}

impl Spec {
    pub fn id(&self) -> String {
        let mut ctx = Sha256::new();
        ctx.update(RELOCATION_DOMAIN);
        let roots: Vec<&str> = self.from.roots.iter().map(|r| r.0.as_str()).collect();
        let parts = [
            self.kind.name().to_string(),
            self.from.document.0.to_string(),
            roots.join(","),
            self.to.document.0.to_string(),
            self.to.parent.0.clone(),
            self.to.position.clone(),
        ];
        for (k, part) in parts.iter().enumerate() {
            if k > 0 {
                ctx.update(b"\0");
            }
            ctx.update(part.as_bytes());
        }
        super::hex(ctx.finalize().as_ref())
    }
}

impl Relocation {
    pub fn spec(&self) -> Spec {
        Spec {
            kind: self.kind,
            from: self.from.clone(),
            to: self.to.clone(),
        }
    }
}

/// The id a relocated node gets (design 4.3).
pub fn dest_id(relocation_id: &str, node: &NodeId) -> NodeId {
    let raw = super::unhex(relocation_id, 32).unwrap_or_default();
    let mut ctx = Sha256::new();
    ctx.update(DERIVE_DOMAIN);
    ctx.update(&raw);
    ctx.update(node.0.as_bytes());
    let digest = ctx.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    let n = u128::from_be_bytes(bytes);
    let text: String = (0..26)
        .map(|i| CROCKFORD[((n >> (5 * (25 - i))) & 31) as usize] as char)
        .collect();
    NodeId(text)
}

/// The shape rules of relocation records that need no states.
pub(crate) fn validate_records(commit: &Commit) -> Result<(), Error> {
    if commit.relocations.len() > MAX_RELOCATIONS {
        return Err(Error::Limit("relocations"));
    }
    let mut ids = BTreeSet::new();
    for r in &commit.relocations {
        let doc_state = |d: &DocumentId| {
            commit
                .files
                .values()
                .find(|f| f.document == *d)
                .map(|f| &f.state)
        };
        let ok = r.id == r.spec().id()
            && ids.insert(r.id.as_str())
            && r.from.document != r.to.document
            && !r.from.roots.is_empty()
            && r.from.roots.len() <= MAX_ROOTS
            && (r.count as usize) <= MAX_NODES
            && r.count as usize >= r.from.roots.len()
            && !r.to.position.is_empty()
            && r.to.position.len() <= 64
            && doc_state(&r.to.document).is_some()
            && match (r.kind, &r.source_state_after) {
                (Kind::Join, None) => doc_state(&r.from.document).is_none(),
                (Kind::Join, Some(_)) | (_, None) => false,
                (_, Some(_)) => true,
            };
        if !ok {
            return Err(Error::Invalid("relocation record"));
        }
    }
    Ok(())
}

/// The live nodes of the subtrees under `roots`, refusing roots that are missing,
/// deleted, repeated or inside another root's subtree.
pub fn subtree(state: &DocumentState, roots: &[NodeId]) -> Result<BTreeSet<NodeId>, Error> {
    let unique: BTreeSet<&NodeId> = roots.iter().collect();
    if unique.len() != roots.len()
        || roots
            .iter()
            .any(|r| state.nodes.get(r).is_none_or(|n| n.deleted))
    {
        return Err(Error::Invalid("relocation roots"));
    }
    let parent = |id: &NodeId| state.nodes.get(id).and_then(|n| n.parent_id.as_ref());
    // A root below another root would be relocated twice.
    for root in roots {
        let mut at = parent(root);
        let mut steps = 0;
        while let Some(id) = at.filter(|_| steps < 4096) {
            if unique.contains(id) {
                return Err(Error::Invalid("nested relocation roots"));
            }
            steps += 1;
            at = parent(id);
        }
    }
    let mut out = BTreeSet::new();
    for node in state.nodes.values().filter(|n| !n.deleted) {
        let mut at = Some(&node.id);
        let mut steps = 0;
        while let Some(id) = at {
            if unique.contains(id) {
                out.insert(node.id.clone());
                break;
            }
            steps += 1;
            if steps > 4096 {
                return Err(Error::Invalid("relocation parent chain"));
            }
            at = state.nodes.get(id).and_then(|n| n.parent_id.as_ref());
        }
    }
    if out.len() > MAX_NODES {
        return Err(Error::Limit("relocated nodes"));
    }
    Ok(out)
}

/// The result of applying a relocation to the states before it.
#[derive(Debug, Clone, PartialEq)]
pub struct Applied {
    /// `None` for a join: the source leaves the project.
    pub source: Option<DocumentState>,
    pub dest: DocumentState,
    pub count: usize,
}

/// Apply `spec` to the source state and the destination state (`None` for the new
/// document of a split). Pure and deterministic; refuses what R2 to R5 forbid.
pub fn apply(
    spec: &Spec,
    source: &DocumentState,
    dest: Option<&DocumentState>,
) -> Result<Applied, Error> {
    let id = spec.id();
    let nodes = subtree(source, &spec.from.roots)?;
    // R5: a pending suggestion on the subtree must be settled first (XD-R8).
    if source.suggestions.values().any(|s| {
        !s.accepted
            && s.rejected_reason.is_none()
            && s.target_node_id.as_ref().is_some_and(|t| nodes.contains(t))
    }) {
        return Err(Error::Invalid(
            "a pending suggestion targets the relocated subtree",
        ));
    }
    let mut dest = match (spec.kind, dest) {
        (Kind::Split, None) => {
            let root = source
                .nodes
                .get(&spec.to.parent)
                .filter(|n| n.parent_id.is_none() && !n.deleted)
                .ok_or(Error::Invalid(
                    "a split names the source root as its parent",
                ))?;
            let mut state = DocumentState::default();
            let copy = MaterializedNode {
                id: dest_id(&id, &root.id),
                parent_id: None,
                ..root.clone()
            };
            state.nodes.insert(copy.id.clone(), copy);
            state
        }
        (Kind::Split, Some(_)) | (_, None) => {
            return Err(Error::Invalid("relocation destination document"));
        }
        (_, Some(d)) => d.clone(),
    };
    let parent = match spec.kind {
        Kind::Split => dest_id(&id, &spec.to.parent),
        _ => spec.to.parent.clone(),
    };
    // R4: a live destination parent that may contain every root.
    let parent_type = dest
        .nodes
        .get(&parent)
        .filter(|n| !n.deleted)
        .and_then(|n| crate::ops::parse_node_type(&n.node_type))
        .ok_or(Error::Invalid("relocation destination parent"))?;
    for root in &spec.from.roots {
        let child = crate::ops::parse_node_type(&source.nodes[root].node_type)
            .ok_or(Error::Invalid("relocated node type"))?;
        if !crate::ops::can_contain(parent_type, child) {
            return Err(Error::Invalid("relocation breaks containment"));
        }
    }
    let names: BTreeSet<&str> = dest
        .nodes
        .values()
        .filter(|n| !n.deleted)
        .filter_map(|n| n.var_name.as_deref())
        .collect();
    let mut added = Vec::new();
    for old in &nodes {
        let n = &source.nodes[old];
        if n.var_name.as_deref().is_some_and(|v| names.contains(v)) {
            return Err(Error::Invalid("relocation repeats a variable name"));
        }
        let root_index = spec.from.roots.iter().position(|r| r == old);
        let copy = MaterializedNode {
            id: dest_id(&id, old),
            parent_id: Some(match root_index {
                Some(_) => parent.clone(),
                None => dest_id(
                    &id,
                    n.parent_id
                        .as_ref()
                        .ok_or(Error::Invalid("relocated parent"))?,
                ),
            }),
            pos: match root_index {
                Some(_) if spec.from.roots.len() == 1 => spec.to.position.clone(),
                Some(k) => format!("{}{k:04}", spec.to.position),
                None => n.pos.clone(),
            },
            ..n.clone()
        };
        added.push(copy);
    }
    for copy in added {
        if dest.nodes.contains_key(&copy.id) {
            return Err(Error::Invalid(
                "relocation already applied to the destination",
            ));
        }
        dest.nodes.insert(copy.id.clone(), copy);
    }
    // Comments anchored in the subtree follow it (R5).
    let anchored = |c: &CommentState| c.node_id.as_ref().is_some_and(|n| nodes.contains(n));
    for c in source.comments.iter().filter(|c| anchored(c)) {
        dest.comments.push(CommentState {
            node_id: c.node_id.as_ref().map(|n| dest_id(&id, n)),
            body: c.body.clone(),
        });
    }
    let source = match spec.kind {
        Kind::Join => None,
        Kind::Copy => Some(source.clone()),
        Kind::Move | Kind::Split => {
            let mut s = source.clone();
            for n in &nodes {
                if let Some(node) = s.nodes.get_mut(n) {
                    node.deleted = true;
                }
            }
            s.comments.retain(|c| !anchored(c));
            Some(s)
        }
    };
    Ok(Applied {
        source,
        dest,
        count: nodes.len(),
    })
}

/// The documents (and their state roots in `files`) that applying `specs` reads:
/// every source and every destination that already exists.
pub fn involved(files: &BTreeMap<String, FileEntry>, specs: &[Spec]) -> Vec<FileEntry> {
    let mut out: Vec<FileEntry> = Vec::new();
    for spec in specs {
        for d in [spec.from.document, spec.to.document] {
            if let Some(f) = files.values().find(|f| f.document == d) {
                if !out.contains(f) {
                    out.push(f.clone());
                }
            }
        }
    }
    out
}

/// Apply relocations in order to `files` (a commit's file map), starting from the
/// `states` of [`involved`] documents; returns the new file map, the records and
/// the states to store. `paths` gives the path of each split's new document.
#[allow(clippy::type_complexity)]
pub async fn plan_commit(
    files: &BTreeMap<String, FileEntry>,
    specs: &[Spec],
    paths: &BTreeMap<uuid::Uuid, String>,
    mut states: BTreeMap<uuid::Uuid, DocumentState>,
) -> Result<
    (
        BTreeMap<String, FileEntry>,
        Vec<Relocation>,
        Vec<(DocumentId, DocumentState)>,
    ),
    Error,
> {
    if specs.is_empty() || specs.len() > MAX_RELOCATIONS {
        return Err(Error::Invalid("relocation count"));
    }
    let mut files = files.clone();
    let mut records = Vec::new();
    for spec in specs {
        let path_of = |files: &BTreeMap<String, FileEntry>, d: &DocumentId| {
            files
                .iter()
                .find(|(_, f)| f.document == *d)
                .map(|(p, _)| p.clone())
        };
        let source_path = path_of(&files, &spec.from.document)
            .ok_or(Error::Invalid("relocation source document"))?;
        let dest_path = path_of(&files, &spec.to.document);
        let load = |d: DocumentId| {
            states
                .get(&d.0)
                .cloned()
                .ok_or(Error::Invalid("relocation document state"))
        };
        let source = load(spec.from.document)?;
        let dest = match (&dest_path, spec.kind) {
            (Some(_), Kind::Split) => return Err(Error::Invalid("a split creates a new document")),
            (None, Kind::Split) => None,
            (Some(_), _) => Some(load(spec.to.document)?),
            (None, _) => return Err(Error::Invalid("relocation destination document")),
        };
        let applied = apply(spec, &source, dest.as_ref())?;
        let dest_after = state_address(spec.to.document, &applied.dest).await?;
        let source_after = match &applied.source {
            Some(s) => Some(state_address(spec.from.document, s).await?),
            None => None,
        };
        match (&applied.source, &source_after) {
            (Some(s), Some(a)) => {
                files.insert(
                    source_path.clone(),
                    FileEntry {
                        document: spec.from.document,
                        state: a.clone(),
                    },
                );
                states.insert(spec.from.document.0, s.clone());
            }
            _ => {
                files.remove(&source_path);
                states.remove(&spec.from.document.0);
            }
        }
        let dest_path = match dest_path {
            Some(p) => p,
            None => paths
                .get(&spec.to.document.0)
                .cloned()
                .ok_or(Error::Invalid("a split needs a new path"))?,
        };
        files.insert(
            dest_path,
            FileEntry {
                document: spec.to.document,
                state: dest_after.clone(),
            },
        );
        states.insert(spec.to.document.0, applied.dest.clone());
        records.push(Relocation {
            id: spec.id(),
            kind: spec.kind,
            from: spec.from.clone(),
            to: spec.to.clone(),
            count: u32::try_from(applied.count).map_err(|_| Error::Limit("relocated nodes"))?,
            source_state_after: source_after,
            dest_state_after: dest_after,
        });
    }
    // Only the states the relocations produced are new.
    let written = states
        .into_iter()
        .filter(|(d, _)| files.values().any(|f| f.document.0 == *d))
        .map(|(d, s)| (DocumentId(d), s))
        .collect();
    Ok((files, records, written))
}

/// Re-apply a one-parent v4 commit's relocations to its parent's states and
/// require exactly the commit's files and recorded states (R1 to R7; XD-C5 on any
/// difference). The service runs the same check before accepting the commit.
pub async fn verify_commit(
    parent: &Commit,
    commit: &Commit,
    states: BTreeMap<uuid::Uuid, DocumentState>,
) -> Result<(), Error> {
    if commit.relocations.is_empty() {
        return Ok(());
    }
    let specs: Vec<Spec> = commit.relocations.iter().map(Relocation::spec).collect();
    let mut paths = BTreeMap::new();
    for r in &commit.relocations {
        if r.kind == Kind::Split {
            let (path, _) = commit
                .files
                .iter()
                .find(|(_, f)| f.document == r.to.document)
                .ok_or(Error::Invalid("relocation record inconsistent with states"))?;
            paths.insert(r.to.document.0, path.clone());
        }
    }
    let (files, records, _) = plan_commit(&parent.files, &specs, &paths, states).await?;
    if files != commit.files || records != commit.relocations {
        return Err(Error::Invalid("relocation record inconsistent with states"));
    }
    Ok(())
}

/// One step of a node's relocation history: it was `from` and became `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    pub commit: Address,
    pub relocation: String,
    pub kind: Kind,
    pub from_document: DocumentId,
    pub from_node: NodeId,
    pub to_document: DocumentId,
    pub to_node: NodeId,
}

impl super::local::LocalRepository {
    /// Build (and store the states of) a one-parent v4 commit on `onto` that
    /// applies `specs` in order. Unsigned: `author_key` is filled by signing.
    pub async fn relocate(
        &self,
        onto: &Address,
        specs: &[Spec],
        paths: &BTreeMap<uuid::Uuid, String>,
        authored_at_ms: i64,
        message: String,
    ) -> Result<Commit, Error> {
        let parent = self.commit(onto).await?.commit;
        let mut read = BTreeMap::new();
        for f in involved(&parent.files, specs) {
            read.insert(f.document.0, self.read_state(f.document, &f.state).await?);
        }
        let (files, relocations, states) = plan_commit(&parent.files, specs, paths, read).await?;
        let commit = Commit {
            version: 4,
            project: self.project(),
            parents: vec![onto.clone()],
            files,
            author_key: "00".repeat(32),
            authored_at_ms,
            message,
            recovery: None,
            same_file_resolutions: Vec::new(),
            sealed: None,
            project_resolutions: Vec::new(),
            relocations,
            merge_policy: None,
        };
        commit.bytes()?;
        for (document, state) in states {
            self.write_state(document, &state).await?;
        }
        Ok(commit)
    }

    /// The relocation history of `node` (in `document`) reachable from `head` by
    /// first parents, newest first: each step names where the node came from.
    pub async fn lineage(
        &self,
        head: &Address,
        document: DocumentId,
        node: &NodeId,
    ) -> Result<Vec<Step>, Error> {
        let mut steps = Vec::new();
        let (mut doc, mut current) = (document, node.clone());
        let mut at = Some(head.clone());
        let mut walked = 0;
        while let Some(address) = at.take() {
            walked += 1;
            if walked > super::MAX_ANCESTORS {
                return Err(Error::Limit("ancestor count"));
            }
            let commit = self.commit(&address).await?.commit;
            at = commit.parents.first().cloned();
            for r in commit.relocations.iter().rev() {
                if r.to.document != doc {
                    continue;
                }
                let Some(parent) = commit.parents.first() else {
                    continue;
                };
                let parent = self.commit(parent).await?.commit;
                let Some(entry) = parent
                    .files
                    .values()
                    .find(|f| f.document == r.from.document)
                else {
                    continue;
                };
                let source = self.read_state(r.from.document, &entry.state).await?;
                let mut candidates: Vec<NodeId> =
                    subtree(&source, &r.from.roots)?.into_iter().collect();
                if r.kind == Kind::Split {
                    candidates.push(r.to.parent.clone());
                }
                if let Some(origin) = candidates
                    .into_iter()
                    .find(|s| dest_id(&r.id, s) == current)
                {
                    steps.push(Step {
                        commit: address.clone(),
                        relocation: r.id.clone(),
                        kind: r.kind,
                        from_document: r.from.document,
                        from_node: origin.clone(),
                        to_document: doc,
                        to_node: current.clone(),
                    });
                    doc = r.from.document;
                    current = origin;
                }
            }
        }
        Ok(steps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(id: &str, parent: Option<&str>, kind: &str) -> MaterializedNode {
        MaterializedNode {
            id: NodeId(id.into()),
            parent_id: parent.map(|p| NodeId(p.into())),
            node_type: kind.into(),
            pos: format!("p{id}"),
            current_fields: json!({"label": id}),
            var_name: None,
            deleted: false,
        }
    }

    fn doc(nodes: &[(&str, Option<&str>, &str)]) -> DocumentState {
        let mut s = DocumentState::default();
        for (id, parent, kind) in nodes {
            s.nodes
                .insert(NodeId((*id).into()), node(id, *parent, kind));
        }
        s
    }

    fn spec(kind: Kind, roots: &[&str], parent: &str) -> Spec {
        Spec {
            kind,
            from: Source {
                document: DocumentId(uuid::Uuid::from_u128(1)),
                roots: roots.iter().map(|r| NodeId((*r).into())).collect(),
            },
            to: Destination {
                document: DocumentId(uuid::Uuid::from_u128(2)),
                parent: NodeId(parent.into()),
                position: "a3".into(),
            },
        }
    }

    #[test]
    fn derived_ids_are_deterministic_valid_ulids_and_depend_on_every_input() {
        let s = spec(Kind::Move, &["S2"], "B");
        let id = s.id();
        assert_eq!(id, spec(Kind::Move, &["S2"], "B").id());
        assert_ne!(id, spec(Kind::Copy, &["S2"], "B").id());
        assert_ne!(id, spec(Kind::Move, &["S2"], "C").id());
        let n = dest_id(&id, &NodeId("n5".into()));
        assert_eq!(n.0.len(), 26);
        assert!(matches!(n.0.as_bytes()[0], b'0'..=b'7'));
        assert!(n.0.bytes().all(|b| CROCKFORD.contains(&b)));
        assert_eq!(n, dest_id(&id, &NodeId("n5".into())));
        assert_ne!(n, dest_id(&id, &NodeId("n6".into())));
    }

    #[test]
    fn a_move_tombstones_the_source_and_copies_with_derived_ids() {
        let source = doc(&[
            ("R", None, "form"),
            ("S2", Some("R"), "section"),
            ("n5", Some("S2"), "item"),
        ]);
        let dest = doc(&[("A", None, "form"), ("B", Some("A"), "section")]);
        let s = spec(Kind::Move, &["S2"], "B");
        let out = apply(&s, &source, Some(&dest)).unwrap();
        assert_eq!(out.count, 2);
        let src = out.source.unwrap();
        assert!(src.nodes[&NodeId("S2".into())].deleted && src.nodes[&NodeId("n5".into())].deleted);
        let id = s.id();
        let moved = &out.dest.nodes[&dest_id(&id, &NodeId("n5".into()))];
        assert_eq!(moved.parent_id, Some(dest_id(&id, &NodeId("S2".into()))));
        assert_eq!(
            out.dest.nodes[&dest_id(&id, &NodeId("S2".into()))].pos,
            "a3"
        );
        // Applying it again to its own result is refused, never duplicated.
        assert!(apply(&s, &source, Some(&out.dest)).is_err());
        // A copy keeps the source.
        let copy = apply(&spec(Kind::Copy, &["S2"], "B"), &source, Some(&dest)).unwrap();
        assert_eq!(copy.source.unwrap(), source);
    }

    #[test]
    fn illegal_relocations_are_refused() {
        let source = doc(&[
            ("R", None, "form"),
            ("S2", Some("R"), "section"),
            ("n5", Some("S2"), "item"),
        ]);
        let dest = doc(&[("A", None, "form"), ("C", Some("A"), "item")]);
        // A section cannot live under an item.
        assert!(apply(&spec(Kind::Move, &["S2"], "C"), &source, Some(&dest)).is_err());
        // Missing parent, nested roots, repeated roots, missing roots.
        assert!(apply(&spec(Kind::Move, &["S2"], "Z"), &source, Some(&dest)).is_err());
        assert!(subtree(&source, &[NodeId("S2".into()), NodeId("n5".into())]).is_err());
        assert!(subtree(&source, &[NodeId("S2".into()), NodeId("S2".into())]).is_err());
        assert!(subtree(&source, &[NodeId("nope".into())]).is_err());
        // A pending suggestion on the subtree must be settled first (XD-R8).
        let mut pending = source.clone();
        pending.suggestions.insert(
            "s1".into(),
            crate::materializer::SuggestionState {
                target_node_id: Some(NodeId("n5".into())),
                detail: json!({}),
                accepted: false,
                rejected_reason: None,
            },
        );
        let ok_dest = doc(&[("A", None, "form"), ("B", Some("A"), "section")]);
        assert!(apply(&spec(Kind::Move, &["S2"], "B"), &pending, Some(&ok_dest)).is_err());
    }

    #[test]
    fn a_split_makes_a_new_document_rooted_in_a_copy_of_the_source_root() {
        let source = doc(&[("R", None, "form"), ("S2", Some("R"), "section")]);
        let s = spec(Kind::Split, &["S2"], "R");
        let out = apply(&s, &source, None).unwrap();
        let root = dest_id(&s.id(), &NodeId("R".into()));
        assert!(out.dest.nodes[&root].parent_id.is_none());
        assert_eq!(
            out.dest.nodes[&dest_id(&s.id(), &NodeId("S2".into()))].parent_id,
            Some(root)
        );
        assert!(apply(&spec(Kind::Split, &["S2"], "S2"), &source, None).is_err());
    }
}
