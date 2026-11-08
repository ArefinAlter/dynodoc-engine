//! Loser preservation (design 7): an automatic outcome that does not use one side's
//! value never drops it. Each such value becomes a pending suggestion (or, with
//! `defaults.loser: comment`, a comment) on the same node in the merged state, so a
//! reviewer can restore it with the existing suggestion workflow.
//!
//! The record depends only on content (node, field, strategy and the value), never
//! on which side lost, so both orientations of a merge write the same entry (law
//! L1) and writing it twice is one entry. Its author is the system actor
//! `merge-resolver` (NC-Q6); the originating authors are not known to a state merge,
//! so `detail.origin` names the value by digest.
//!
//! With `defaults.loser: none` no automatic outcome may lose anything: the engine
//! turns such an outcome into a conflict (`loser-not-preserved`).

use super::{evidence::Digest, policy::Loser};
use crate::materializer::{CommentState, DocumentState, SuggestionState};
use engine_shared::{EventPayload, NodeId};
use serde::Serialize;
use serde_json::{json, Value};

/// The system actor named as the author of loser suggestions.
pub const AUTHOR: &str = "merge-resolver";
const DOMAIN: &[u8] = b"dynodoc.merge-loser\0v1\0";

/// A value an automatic decision did not use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LostValue {
    pub node: Option<NodeId>,
    pub field: String,
    pub rule: String,
    pub strategy: String,
    #[serde(skip)]
    pub value: Value,
    pub digest: Digest,
}

impl LostValue {
    pub fn new(
        node: Option<NodeId>,
        field: &str,
        rule: &str,
        strategy: &str,
        value: Value,
    ) -> Self {
        Self {
            digest: Digest::of(&value),
            node,
            field: field.into(),
            rule: rule.into(),
            strategy: strategy.into(),
            value,
        }
    }

    /// The suggestion id: `merge-` and 26 hex digits of a content hash.
    pub fn suggestion_id(&self) -> String {
        let key = json!({
            "node": self.node,
            "field": self.field,
            "strategy": self.strategy,
            "value": self.value,
        });
        let digest = crate::hashing::sha256(&[DOMAIN, &crate::hashing::canonical_json(&key)]);
        format!("merge-{}", &super::hex(&digest)[..26])
    }

    fn detail(&self) -> Value {
        json!({
            "kind": "merge-loser",
            "author": AUTHOR,
            "rule": self.rule,
            "strategy": self.strategy,
            "change": {
                "type": "FieldEdited",
                "node_id": self.node,
                "field": self.field,
                "value": self.value,
            },
            "origin": {"value_sha256": self.digest.sha256},
        })
    }

    fn comment(&self) -> String {
        format!(
            "Merge kept another value for `{}` (rule {}, strategy {}). The value not kept: {}",
            self.field, self.rule, self.strategy, self.value
        )
    }
}

/// Write each loser into `state`; returns the operations that do the same to the
/// team state of an event plan. Idempotent: an entry already present is skipped.
pub fn apply(state: &mut DocumentState, losers: &[LostValue], mode: Loser) -> Vec<EventPayload> {
    let mut ops = Vec::new();
    for lost in losers {
        match mode {
            Loser::None => {}
            Loser::Suggestion => {
                let id = lost.suggestion_id();
                if state.suggestions.contains_key(&id) {
                    continue;
                }
                state.suggestions.insert(
                    id.clone(),
                    SuggestionState {
                        target_node_id: lost.node.clone(),
                        detail: lost.detail(),
                        accepted: false,
                        rejected_reason: None,
                    },
                );
                ops.push(EventPayload::SuggestionProposed {
                    suggestion_id: id,
                    target_node_id: lost.node.clone(),
                    detail: lost.detail(),
                });
            }
            Loser::Comment => {
                let comment = CommentState {
                    node_id: lost.node.clone(),
                    body: lost.comment(),
                };
                if state.comments.contains(&comment) {
                    continue;
                }
                ops.push(EventPayload::CommentAdded {
                    node_id: comment.node_id.clone(),
                    body: comment.body.clone(),
                });
                state.comments.push(comment);
            }
        }
    }
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_loser_is_written_once_and_names_its_value() {
        let lost = LostValue::new(
            Some(NodeId("01J00000000000000000000000".into())),
            "cell_2",
            "sheet-values",
            "dynodoc.sheet.cell.v1",
            json!("42"),
        );
        let mut state = DocumentState::default();
        let ops = apply(&mut state, &[lost.clone(), lost.clone()], Loser::Suggestion);
        assert_eq!(ops.len(), 1);
        let s = &state.suggestions[&lost.suggestion_id()];
        assert_eq!(s.detail["change"]["value"], json!("42"));
        assert_eq!(s.detail["author"], AUTHOR);
        assert!(!s.accepted);
        assert!(apply(&mut state, std::slice::from_ref(&lost), Loser::Suggestion).is_empty());
        let mut comments = DocumentState::default();
        apply(&mut comments, &[lost], Loser::Comment);
        assert!(comments.comments[0].body.contains("\"42\""));
    }
}
