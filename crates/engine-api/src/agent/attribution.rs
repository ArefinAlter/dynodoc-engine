//! Attribution layer C (decision 038, docs/AI-AGENT-CONNECTORS.md 6.3 and 6.4): when a person
//! merges an AI agent's change request, the merge appends one `ChangeAttributed` event after the
//! content events, in the same transaction, naming who wrote each of them.
//!
//! What it records, from rows the server wrote itself (never from the agent's words):
//!
//! - the agent identity, the person it acted for, the key's client kind, the merger, the
//!   approvals that counted and whether the rules were bypassed;
//! - for every merged event, the agent session and turn whose `propose` last touched the
//!   block (the receipts of migrations 0044 and 0056), or the person whose edit in the draft
//!   kept under half of the agent's text (the merge's containment, decision 029 section 3);
//! - each named session's turn count and chain head at the merge, so the session record and
//!   the document chain vouch for each other.
//!
//! The content events keep the merger as `actor_id`, as before: every reader that treats the
//! actor as the person whose authority appended the event stays right. The seal is the
//! authorship record, and because it is an event, `content_hash` and the chain cover it.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use engine_core::log;
use engine_shared::{
    AttributedPart, Attribution, DocumentId, Event, EventPayload, IdentityId, SealedSession,
};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::error::ApiError;

/// The facts of one merge that the seal records.
pub(crate) struct Merge<'a> {
    pub document: DocumentId,
    pub draft: Uuid,
    pub merger: Uuid,
    /// The request row of [`crate::reviews::REQUEST_JSON`]; only agent requests are sealed.
    pub request: &'a Value,
    /// The content events this merge appended, in order.
    pub events: &'a [Event],
    /// `{node, by, retained}` of the merge's containment check.
    pub person_edits: &'a [Value],
    /// The review state (`approved_by`).
    pub review: &'a Value,
    pub overridden: bool,
}

/// Append the seal of `merge`, or nothing for a person's request or an empty merge.
pub(crate) async fn seal(
    tx: &mut Transaction<'_, Postgres>,
    merge: Merge<'_>,
) -> Result<Option<Event>, ApiError> {
    let agent = &merge.request["agent"];
    let (Some(identity), Some(principal)) =
        (agent["id"].as_str(), agent["principal"]["id"].as_str())
    else {
        return Ok(None);
    };
    let (Some(first), Some(last)) = (merge.events.first(), merge.events.last()) else {
        return Ok(None);
    };
    // The turn whose propose last touched each block (receipts in call order).
    let receipts: Vec<(Option<Uuid>, Option<i32>, Vec<String>)> = sqlx::query_as(
        "select session_id,turn,nodes from agent_proposal_receipt where draft_id=$1 and kind='propose' order by at,id",
    )
    .bind(merge.draft)
    .fetch_all(&mut **tx)
    .await?;
    let mut turn_of: HashMap<String, (Option<Uuid>, Option<i32>)> = HashMap::new();
    for (session, turn, nodes) in receipts {
        for node in nodes {
            turn_of.insert(node, (session, turn));
        }
    }
    // node -> (the person took the block over, who edited it)
    let edited: HashMap<&str, (bool, &str)> = merge
        .person_edits
        .iter()
        .filter_map(|p| {
            let kept = p["retained"].as_u64()?;
            Some((
                p["node"].as_str()?,
                (
                    kept < u64::from(crate::reviews::AGENT_DRAFT_KEPT),
                    p["by"].as_str()?,
                ),
            ))
        })
        .collect();
    type Key = (Option<Uuid>, Option<i32>, Option<String>, Option<String>);
    let mut groups: BTreeMap<Key, Vec<i64>> = BTreeMap::new();
    for event in merge.events {
        let node = event.target_node_id.as_ref().map(|n| n.0.as_str());
        let by = node.and_then(|n| edited.get(n));
        let key = match by {
            Some((true, person)) => (None, None, Some((*person).to_owned()), None),
            _ => {
                let (session, turn) = node
                    .and_then(|n| turn_of.get(n))
                    .copied()
                    .unwrap_or((None, None));
                (session, turn, None, by.map(|(_, who)| (*who).to_owned()))
            }
        };
        groups.entry(key).or_default().push(event.seq);
    }
    let named: BTreeSet<Uuid> = groups.keys().filter_map(|k| k.0).collect();
    let mut sessions = Vec::with_capacity(named.len());
    for id in named {
        let row: Option<(i32, Vec<u8>)> =
            sqlx::query_as("select turns,head from agent_session where id=$1")
                .bind(id)
                .fetch_optional(&mut **tx)
                .await?;
        if let Some((turns, head)) = row {
            sessions.push(SealedSession {
                id: id.to_string(),
                turns,
                head: hex::encode(head),
            });
        }
    }
    let seal = Attribution {
        draft_id: merge.draft.to_string(),
        agent: identity.to_owned(),
        principal: principal.to_owned(),
        client_kind: agent["client_kind"]
            .as_str()
            .unwrap_or("generic")
            .to_owned(),
        merger: merge.merger.to_string(),
        first_seq: first.seq,
        last_seq: last.seq,
        parts: groups
            .into_iter()
            .map(
                |((session, turn, person, edited_by), seqs)| AttributedPart {
                    seqs,
                    session: session.map(|s| s.to_string()),
                    turn,
                    person,
                    edited_by,
                },
            )
            .collect(),
        sessions,
        approvals: merge.review["approved_by"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        rules_overridden: merge.overridden,
    };
    let event = log::append_in_tx(
        tx,
        merge.document,
        &EventPayload::ChangeAttributed(Box::new(seal)),
        IdentityId(merge.merger),
    )
    .await?;
    Ok(Some(event))
}
