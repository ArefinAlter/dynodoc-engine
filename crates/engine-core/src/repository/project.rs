//! Commit format v4 records (cross-document design 5.1) and the conflict taxonomy
//! of section 7.
//!
//! A v4 commit is either a two-parent merge, with `project_resolutions` and the
//! embedded `merge_policy`, or a one-parent commit with `relocations` (written by
//! `relocate`, `split` and `join`). Versions 1 to 3 never serialize these fields
//! and keep their addresses, signatures and vectors. The signature domain is
//! `dynodoc.project-commit-signature\0v4\0`, the address domain
//! `dynodoc.project-commit\0v4\0`; readers older than v4 reject the version.
//!
//! An importer accepts only the strategy ids of [`STRATEGIES`]; the records are
//! checked against the commit's parents on import, and `verify-merge` re-runs them.
//! Commit pruning (design `DESIGN-COMMIT-PRUNING.md`) adds pin rules for these
//! records and no fields: each record's base, left, right and source states are
//! merge inputs, and a relocation's parent is evidence (decision 033).

use super::{convergence, relocation, Commit, Error};
use crate::{
    merge_policy::{MergePolicy, Registry},
    shared_checkpoint::Address,
};
use engine_shared::DocumentId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Node/field convergence of one document under the embedded policy (the v3
/// strategy, now with a recorded policy).
pub const SAME_FILE: &str = convergence::STRATEGY;
/// The path from one side and the state from the other (XD-F8).
pub const RENAME_FOLLOW: &str = "dynodoc.project.rename-follow.v1";
/// One side's edits of relocated nodes applied at their destination (XD-R1, XD-S1).
pub const EDIT_FOLLOWS_MOVE: &str = "dynodoc.project.edit-follows-move.v1";
/// Every strategy a v4 record may name.
pub const STRATEGIES: [&str; 3] = [SAME_FILE, RENAME_FOLLOW, EDIT_FOLLOWS_MOVE];
pub const MAX_RESOLUTIONS: usize = 256;
pub const RESOLUTION_SET_DOMAIN: &[u8] = b"dynodoc.resolution-set\0v1\0";

/// The merge policy a v4 merge was decided under, embedded canonically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedPolicy {
    /// `MergePolicy::hash_hex` of `policy`.
    pub hash: String,
    /// The policy's canonical value (`MergePolicy::canonical_value`).
    pub policy: Value,
}

impl EmbeddedPolicy {
    pub fn of(policy: &MergePolicy) -> Self {
        Self {
            hash: policy.hash_hex(),
            policy: policy.canonical_value(),
        }
    }

    /// The policy, checked: it loads, its canonical form is the embedded value and
    /// its hash is the recorded one.
    pub fn load(&self) -> Result<MergePolicy, Error> {
        let bytes = serde_json::to_vec(&self.policy)?;
        let policy = MergePolicy::from_json(&bytes, &Registry::builtin())
            .map_err(|_| Error::Invalid("embedded merge policy"))?;
        if policy.canonical_value() != self.policy || policy.hash_hex() != self.hash {
            return Err(Error::Invalid("embedded merge policy hash"));
        }
        Ok(policy)
    }
}

/// A path three ways and the path the merge kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathDecision {
    pub base: String,
    pub left: String,
    pub right: String,
    pub merged: String,
}

/// The source document of an edit-follows-move record: its states in the three
/// commits and after the merge (`None` when a join removed it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStates {
    pub document: DocumentId,
    pub base: Address,
    pub left: Option<Address>,
    pub right: Option<Address>,
    pub merged: Option<Address>,
}

/// Which parent made the relocation an edit follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Parent {
    Left,
    Right,
}

/// One automatic project-level decision of a v4 merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectResolution {
    /// `r1`, `r2`, ... in record order.
    pub id: String,
    pub strategy: String,
    /// The document whose merged state the record produces (the destination for
    /// edit-follows-move).
    pub document: DocumentId,
    /// Its state at the merge base, and in the first and second parents; `None`
    /// where the document does not exist (a destination created by a split).
    pub base: Option<Address>,
    pub left: Option<Address>,
    pub right: Option<Address>,
    pub merged: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relocation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follows: Option<Parent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceStates>,
    /// The policy's gates ask for review of an automatic choice in this record.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub needs_review: bool,
    /// `resolution_set_hash` of this record's automatic node decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_set: Option<String>,
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The shape rules of a v4 commit that need no states (called by
/// `Commit::validate`); the import check compares records with the parents.
pub fn validate(commit: &Commit) -> Result<(), Error> {
    let bad = |what: &'static str| Err(Error::Invalid(what));
    if commit.project_resolutions.len() > MAX_RESOLUTIONS {
        return Err(Error::Limit("project resolutions"));
    }
    if let Some(policy) = &commit.merge_policy {
        policy.load()?;
    }
    let mut ids = BTreeSet::new();
    let mut produced = BTreeSet::new();
    for (k, r) in commit.project_resolutions.iter().enumerate() {
        if r.id != format!("r{}", k + 1) || !ids.insert(r.id.as_str()) {
            return bad("project resolution id");
        }
        if !STRATEGIES.contains(&r.strategy.as_str()) {
            return bad("project resolution strategy");
        }
        if r.resolution_set.as_deref().is_some_and(|h| !hex64(h)) {
            return bad("project resolution set hash");
        }
        let file = commit
            .files
            .values()
            .find(|f| f.document == r.document)
            .ok_or(Error::Invalid("project resolution document"))?;
        // A record produces the state the commit names for its document; one
        // record per document and strategy.
        if file.state != r.merged || !produced.insert((r.document.0, r.strategy.as_str())) {
            return bad("project resolution record");
        }
        let shape = match r.strategy.as_str() {
            RENAME_FOLLOW => {
                r.path.as_ref().is_some_and(|p| {
                    p.left != p.right
                        && (p.merged == p.left || p.merged == p.right)
                        && commit
                            .files
                            .get(&p.merged)
                            .is_some_and(|f| f.document == r.document)
                }) && r.relocation.is_none()
                    && r.source.is_none()
            }
            // A missing base is the same document added on both sides (XD-F7).
            SAME_FILE => {
                r.path.is_none()
                    && r.relocation.is_none()
                    && r.source.is_none()
                    && r.follows.is_none()
                    && r.left.is_some()
                    && r.right.is_some()
                    && r.left != r.right
                    && r.base != r.left
                    && r.base != r.right
            }
            _ => {
                r.relocation.as_deref().is_some_and(hex64)
                    && r.follows.is_some()
                    && r.source.as_ref().is_some_and(|s| {
                        s.document != r.document
                            && match &s.merged {
                                Some(m) => commit
                                    .files
                                    .values()
                                    .any(|f| f.document == s.document && f.state == *m),
                                None => !commit.files.values().any(|f| f.document == s.document),
                            }
                    })
                    && r.path.is_none()
            }
        };
        if !shape {
            return bad("project resolution record shape");
        }
    }
    relocation::validate_records(commit)
}

/// The provenance a v4 merge's records owe its two parents: each recorded left and
/// right state (and path, and source state) is the one that parent holds for the
/// record's document. The merge-base half of the check needs ancestry; the local
/// importer runs it, a service that stores no graph checks this half.
pub fn check_parents(commit: &Commit, left: &Commit, right: &Commit) -> Result<(), Error> {
    let state = |c: &Commit, d: DocumentId| {
        c.files
            .values()
            .find(|f| f.document == d)
            .map(|f| f.state.clone())
    };
    let path = |c: &Commit, d: DocumentId| {
        c.files
            .iter()
            .find(|(_, f)| f.document == d)
            .map(|(p, _)| p.clone())
    };
    for r in &commit.project_resolutions {
        let mut ok = state(left, r.document) == r.left && state(right, r.document) == r.right;
        if let Some(s) = &r.source {
            ok &= state(left, s.document) == s.left && state(right, s.document) == s.right;
        }
        if let Some(p) = &r.path {
            ok &= path(left, r.document).as_deref() == Some(p.left.as_str())
                && path(right, r.document).as_deref() == Some(p.right.as_str());
        }
        if !ok {
            return Err(Error::Invalid(
                "project resolution does not match its parents",
            ));
        }
    }
    Ok(())
}

/// The commit-level resolution-set hash a review of a v4 merge binds: SHA-256 of
/// the domain and the canonical JSON of each record's `{document, strategy,
/// resolution_set}` in record order. Records without automatic node decisions
/// contribute their identity only.
pub fn resolution_set_hash(commit: &Commit) -> String {
    let entries: Vec<Value> = commit
        .project_resolutions
        .iter()
        .map(|r| {
            serde_json::json!({
                "document": r.document.0.to_string(),
                "strategy": r.strategy,
                "resolution_set": r.resolution_set,
            })
        })
        .collect();
    let mut ctx = Sha256::new();
    ctx.update(RESOLUTION_SET_DOMAIN);
    ctx.update(crate::hashing::canonical_json(&Value::Array(entries)));
    super::hex(ctx.finalize().as_ref())
}

/// Whether a protected branch needs a review that binds [`resolution_set_hash`]
/// before it may take this commit.
pub fn needs_review(commit: &Commit) -> bool {
    commit.project_resolutions.iter().any(|r| r.needs_review)
}

/// Whether a conflict class can ever be settled automatically (design 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Auto {
    /// Automatic whenever detected.
    Always,
    /// Automatic only under the stated conditions (they did not hold if reported).
    Conditional,
    Never,
}

/// The closed conflict taxonomy of design section 7. A class not listed here does
/// not exist; every listed class says once whether it can be automatic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Class {
    #[serde(rename = "XD-F1")]
    SameDocumentEdited,
    #[serde(rename = "XD-F2")]
    DeleteEdit,
    #[serde(rename = "XD-F3")]
    RenameRename,
    #[serde(rename = "XD-F4")]
    PathClaimedTwice,
    #[serde(rename = "XD-F5")]
    FileDirectory,
    #[serde(rename = "XD-F6")]
    PortabilityCollision,
    #[serde(rename = "XD-F7")]
    AddAdd,
    #[serde(rename = "XD-F9")]
    RenameDelete,
    #[serde(rename = "XD-R1")]
    MoveEdit,
    #[serde(rename = "XD-R2")]
    MoveDelete,
    #[serde(rename = "XD-R3")]
    MoveMove,
    #[serde(rename = "XD-R5")]
    DestinationDeleted,
    #[serde(rename = "XD-R7")]
    DuplicateRelocation,
    #[serde(rename = "XD-R10")]
    AudienceBoundary,
    #[serde(rename = "XD-S2")]
    SplitSplit,
    #[serde(rename = "XD-S3")]
    JoinDropsProperties,
    #[serde(rename = "XD-C1")]
    NodeInTwoDocuments,
}

impl Class {
    pub fn code(self) -> &'static str {
        match self {
            Self::SameDocumentEdited => "XD-F1",
            Self::DeleteEdit => "XD-F2",
            Self::RenameRename => "XD-F3",
            Self::PathClaimedTwice => "XD-F4",
            Self::FileDirectory => "XD-F5",
            Self::PortabilityCollision => "XD-F6",
            Self::AddAdd => "XD-F7",
            Self::RenameDelete => "XD-F9",
            Self::MoveEdit => "XD-R1",
            Self::MoveDelete => "XD-R2",
            Self::MoveMove => "XD-R3",
            Self::DestinationDeleted => "XD-R5",
            Self::DuplicateRelocation => "XD-R7",
            Self::AudienceBoundary => "XD-R10",
            Self::SplitSplit => "XD-S2",
            Self::JoinDropsProperties => "XD-S3",
            Self::NodeInTwoDocuments => "XD-C1",
        }
    }

    /// The fixed answer of design 7.5. A reported conflict of a conditional class
    /// is one whose conditions failed.
    pub fn auto(self) -> Auto {
        match self {
            Self::SameDocumentEdited | Self::AddAdd | Self::MoveEdit => Auto::Conditional,
            _ => Auto::Never,
        }
    }
}

/// One project-level conflict. Its id is `class:` and 12 hex digits of a hash of
/// the class and participants, so it is stable across runs and orientations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XdConflict {
    pub id: String,
    pub class: Class,
    pub auto: Auto,
    /// Paths (or `path#node`) the conflict is about, sorted.
    pub participants: Vec<String>,
    /// The documents a `take` choice replaces, by UUID.
    pub documents: Vec<DocumentId>,
    pub detail: String,
}

impl XdConflict {
    pub fn new(
        class: Class,
        mut participants: Vec<String>,
        documents: Vec<DocumentId>,
        detail: impl Into<String>,
    ) -> Self {
        participants.sort();
        participants.dedup();
        let mut documents = documents;
        documents.sort_by_key(|d| d.0);
        documents.dedup();
        let mut ctx = Sha256::new();
        ctx.update(class.code().as_bytes());
        for p in &participants {
            ctx.update(b"\0");
            ctx.update(p.as_bytes());
        }
        for d in &documents {
            ctx.update(b"\0");
            ctx.update(d.0.as_bytes());
        }
        let id = format!(
            "{}:{}",
            class.code(),
            &super::hex(ctx.finalize().as_ref())[..12]
        );
        Self {
            id,
            class,
            auto: class.auto(),
            participants,
            documents,
            detail: detail.into(),
        }
    }
}

/// A person's choice for one conflict (resolution file v2, design 8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    pub conflict: String,
    /// `left`, `right` or `delete`: every document of the conflict takes that
    /// parent's file entry (or is removed).
    pub take: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionFile {
    pub version: u8,
    #[serde(default)]
    pub choices: Vec<Choice>,
}

impl ResolutionFile {
    pub fn validate(&self) -> Result<(), Error> {
        let mut seen = BTreeSet::new();
        if self.version != 2
            || self.choices.len() > 4096
            || !self.choices.iter().all(|c| {
                matches!(c.take.as_str(), "left" | "right" | "delete") && seen.insert(&c.conflict)
            })
        {
            return Err(Error::Invalid("resolution file v2"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_never_automatic_list_is_closed_and_ids_are_stable() {
        let never = [
            Class::DeleteEdit,
            Class::RenameRename,
            Class::PathClaimedTwice,
            Class::FileDirectory,
            Class::PortabilityCollision,
            Class::RenameDelete,
            Class::MoveDelete,
            Class::MoveMove,
            Class::DestinationDeleted,
            Class::DuplicateRelocation,
            Class::AudienceBoundary,
            Class::SplitSplit,
            Class::JoinDropsProperties,
            Class::NodeInTwoDocuments,
        ];
        assert!(never.iter().all(|c| c.auto() == Auto::Never));
        let doc = DocumentId(uuid::Uuid::from_u128(1));
        let a = XdConflict::new(
            Class::RenameRename,
            vec!["b".into(), "a".into()],
            vec![doc],
            "x",
        );
        let b = XdConflict::new(
            Class::RenameRename,
            vec!["a".into(), "b".into()],
            vec![doc],
            "y",
        );
        assert_eq!(a.id, b.id);
        assert!(a.id.starts_with("XD-F3:") && a.id.len() == 6 + 12);
        assert_ne!(
            a.id,
            XdConflict::new(Class::DeleteEdit, vec!["a".into()], vec![doc], "").id
        );
        assert!(serde_json::to_string(&a)
            .unwrap()
            .contains("\"class\":\"XD-F3\""));
    }

    #[test]
    fn resolution_files_take_only_known_choices_once() {
        let ok: ResolutionFile = serde_json::from_str(
            r#"{"version":2,"choices":[{"conflict":"XD-F3:aaaaaaaaaaaa","take":"left"}]}"#,
        )
        .unwrap();
        assert!(ok.validate().is_ok());
        let mut twice = ok.clone();
        twice.choices.push(twice.choices[0].clone());
        assert!(twice.validate().is_err());
        let mut odd = ok.clone();
        odd.choices[0].take = "both".into();
        assert!(odd.validate().is_err());
        assert!(serde_json::from_str::<ResolutionFile>(r#"{"version":2,"x":1}"#).is_err());
    }
}
