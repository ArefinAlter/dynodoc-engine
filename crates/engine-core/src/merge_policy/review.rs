//! Review gating (design 6.2 and 6.4): which automatic decisions a review must see,
//! and the hash that binds a review decision to exactly that set.
//!
//! ```text
//! resolution_set_hash = SHA-256("dynodoc.resolution-set\0v1\0" ||
//!         canonical JSON of sorted [{document, strategy, node, field,
//!                                    base, left, right, merged, loser}])
//! ```
//!
//! Values enter as the SHA-256 digests of their canonical JSON (the evidence never
//! copies content), and the sides are named after the commit's parents (`left` is
//! the first), so the hash is the same whichever orientation decided the merge.

use super::evidence::{DecisionOutcome, MergeEvidence};
use engine_shared::DocumentId;
use serde::Serialize;

pub const DOMAIN: &[u8] = b"dynodoc.resolution-set\0v1\0";

/// One automatic decision as a reviewer is shown it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Entry {
    /// The document UUID, hyphenated lowercase.
    pub document: Option<String>,
    pub strategy: String,
    pub node: Option<String>,
    pub field: String,
    pub base: String,
    pub left: String,
    pub right: String,
    pub merged: String,
    pub loser: Vec<String>,
    /// Not hashed: whether the gate asked for review of this decision.
    #[serde(skip)]
    pub needs_review: bool,
}

/// The automatic decisions of one converged document. `team` names the input that
/// played the team side (`left` or `right`), as `ConvergenceEvidence` does.
pub fn entries(evidence: &MergeEvidence, team: &str, document: Option<DocumentId>) -> Vec<Entry> {
    evidence
        .decisions
        .iter()
        .filter(|d| {
            matches!(
                d.outcome,
                DecisionOutcome::Merged | DecisionOutcome::Preferred
            )
        })
        .filter_map(|d| {
            let (left, right) = if team == "left" {
                (&d.team, &d.draft)
            } else {
                (&d.draft, &d.team)
            };
            Some(Entry {
                document: document.map(|d| d.0.to_string()),
                strategy: d.strategy.clone()?,
                node: d.node.as_ref().map(|n| n.0.clone()),
                field: d.field.clone(),
                base: d.base.sha256.clone(),
                left: left.sha256.clone(),
                right: right.sha256.clone(),
                merged: d.merged.as_ref()?.sha256.clone(),
                loser: d.lost.iter().map(|l| l.sha256.clone()).collect(),
                needs_review: d.needs_review,
            })
        })
        .collect()
}

/// The hash of a set of entries, independent of their order.
pub fn hash(entries: &[Entry]) -> [u8; 32] {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort();
    #[allow(clippy::expect_used, reason = "entries are plain JSON data")]
    let value = serde_json::to_value(&sorted).expect("entries are plain JSON data");
    crate::hashing::sha256(&[DOMAIN, &crate::hashing::canonical_json(&value)])
}

pub fn hash_hex(entries: &[Entry]) -> String {
    super::hex(&hash(entries))
}

/// Whether any decision asks for review before a protected branch may take it.
pub fn needs_review(entries: &[Entry]) -> bool {
    entries.iter().any(|e| e.needs_review)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(field: &str) -> Entry {
        Entry {
            document: Some(uuid::Uuid::from_u128(7).to_string()),
            strategy: "dynodoc.text.diff3-grapheme.v1".into(),
            node: Some("01J00000000000000000000000".into()),
            field: field.into(),
            base: "aa".repeat(32),
            left: "bb".repeat(32),
            right: "cc".repeat(32),
            merged: "dd".repeat(32),
            loser: vec![],
            needs_review: true,
        }
    }

    #[test]
    fn the_hash_is_order_independent_and_binds_every_field() {
        let (a, b) = (entry("content"), entry("label"));
        assert_eq!(hash(&[a.clone(), b.clone()]), hash(&[b.clone(), a.clone()]));
        let mut changed = a.clone();
        changed.merged = "ee".repeat(32);
        assert_ne!(hash(&[a.clone(), b.clone()]), hash(&[changed, b.clone()]));
        let mut lost = a.clone();
        lost.loser.push("ff".repeat(32));
        assert_ne!(hash(std::slice::from_ref(&a)), hash(&[lost]));
        // needs_review is a gate fact, not part of what was decided.
        let mut quiet = a.clone();
        quiet.needs_review = false;
        assert_eq!(hash(&[a]), hash(&[quiet]));
        assert_eq!(hash_hex(&[]), super::super::hex(&hash(&[])),);
    }
}
