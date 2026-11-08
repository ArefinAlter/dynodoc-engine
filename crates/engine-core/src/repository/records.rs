//! The provenance records a signed commit carries (recovery source, same-file merge
//! record). Pure data, so the WebAssembly build encodes the same commits; planning and
//! merging stay in `recovery` and `convergence`.
use crate::shared_checkpoint::Address;
use engine_shared::DocumentId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    CherryPick,
    Revert,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub kind: Kind,
    pub commit: Address,
    /// None only for a root commit. A merge requires an explicit chosen parent.
    pub mainline: Option<Address>,
}

/// Same-document conflicting files examined per comparison; the rest are counted.
pub const MAX_REPORTED_FILES: usize = 64;

/// Strategy id signed into a v3 commit: the node/field three-way merge of
/// `convergence::converge`, clean in both orientations. A different algorithm needs a
/// different id; importers accept only ids they know.
pub const STRATEGY: &str = "dynodoc.same-file.node-field.v1";

/// Signed provenance of one automatically merged path: the three input state
/// roots under one stable document identity and the stored merged state root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    pub path: String,
    pub document: DocumentId,
    /// State at the unique best common ancestor.
    pub base: Address,
    /// State in the first parent.
    pub left: Address,
    /// State in the second parent.
    pub right: Address,
    pub merged: Address,
    pub strategy: String,
}
