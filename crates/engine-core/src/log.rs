//! The append-only, hash-chained event log — the system of record (docs/14).
//!
//! All other state (the materialized `node`/`document` tree, snapshots) is a fold
//! over this log. Three properties make it trustworthy:
//!
//! 1. **Immutable.** The `event` table's triggers (0002_events.sql) forbid
//!    UPDATE/DELETE, and this module exposes no path that revises an event.
//! 2. **Tamper-evident.** Each event carries `content_hash` (over its semantic
//!    content) and `chain_hash = SHA-256(content_hash ‖ prev_chain_hash)`, genesis
//!    folding 32 zero bytes. [`verify_chain`] recomputes both for every event and
//!    detects any payload edit, reorder, or gap (docs/04 §E.2).
//! 3. **Linearizable per document.** [`append`] serializes a document's appends by
//!    taking a row lock on its `document` row, so `seq` is a gap-free 1-based
//!    sequence and the chain is consistent. Appends to *different* documents run in
//!    parallel.
//!
//! ## Hash construction (must stay stable — it is the audit contract)
//!
//! `content_hash` is SHA-256 over four length-framed fields, in order: the event
//! type string, the target node id (empty if none), the canonical-JSON payload, and
//! the actor's 16 UUID bytes. Length-framing (`u64` big-endian length before each
//! field) makes the concatenation unambiguous. The payload is canonicalized
//! (recursively sorted keys, no whitespace) so the digest is reproducible across
//! the JSONB round-trip.
//!
//! V1 does **not** hash `document_id`, `seq`, the event `id`, or `created_at`.
//! Verification separately checks the requested document, sequence continuity and
//! predecessor hashes; these checks do not cryptographically bind those excluded
//! fields. In particular, a privileged writer can copy a complete chain to another
//! document and it still passes chain verification. Changing an event ID also changes
//! a `CommentAdded` thread's identity without changing its v1 commitment. Database
//! `now()` timestamps may be identical for all events in a transaction and are not
//! independently witnessed creation times.
//!
//! Append-only storage and an externally retained head remain separate safeguards.
//! An event-v2 contract would need version-aware hashing/readers; these exclusions
//! must not be repaired by changing historical v1 hash bytes. Portable signed commits
//! and receipts are distinct formats; see the evolution plan, part 6.

use engine_shared::{DocumentId, Event, EventPayload, IdentityId};
use futures::TryStreamExt;
use sqlx::PgPool;
use uuid::Uuid;

use crate::snapshot::{self, SnapshotEngine, SnapshotReason, DEFAULT_MAX_EVENTS_IN_TAIL};

pub(crate) use crate::hashing::canonical_json;
pub use crate::hashing::ZERO_HASH;
use crate::hashing::{self, chain_hash, content_hash};

/// Errors from event-log operations.
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// A database or transaction error.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// The payload could not be serialized to JSON.
    #[error("payload serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    /// No `document` row exists for the given id (nothing to append to).
    #[error("document {0} does not exist")]
    DocumentNotFound(Uuid),
    /// [`verify_chain`] found the stored chain inconsistent at this `seq`.
    #[error("chain broken at seq {seq}: {detail}")]
    ChainBroken { seq: i64, detail: String },
    /// The event committed but the required post-commit snapshot step failed.
    #[error("post-commit snapshot failed: {0}")]
    PostCommitSnapshot(String),
}

/// Append one semantic event to a document's log and return the inserted row.
///
/// Opens a transaction, locks the document row to serialize concurrent appends,
/// computes the hashes, and inserts with `seq = prev_seq + 1` (genesis `seq = 1`).
/// After the commit it runs the post-commit snapshot step (immediate for `Deployed`,
/// otherwise a best-effort background `ensure_recent`).
pub async fn append(
    pool: &PgPool,
    document_id: DocumentId,
    payload: &EventPayload,
    actor_id: IdentityId,
) -> Result<Event, EventError> {
    let mut tx = pool.begin().await?;
    let inserted = append_in_tx(&mut tx, document_id, payload, actor_id).await?;
    tx.commit().await?;

    post_commit_snapshot(pool, document_id, std::slice::from_ref(payload)).await?;
    Ok(inserted)
}

/// Append one event inside a caller-owned transaction, returning the inserted row
/// *without* committing or taking any snapshot.
///
/// This is the linearization primitive: it locks the document row, reads the prior
/// chain head, and inserts at `seq = prev_seq + 1`. Calling it twice on the same
/// transaction appends two events atomically (the governance `accept` path appends
/// the now-canonical wrapped event and the `SuggestionAccepted` event together —
/// docs/16 "two-event semantics"); the second call sees the first's row, so the
/// chain stays gap-free. The caller is responsible for `commit()` and for running
/// [`post_commit_snapshot`] afterward.
pub async fn append_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    document_id: DocumentId,
    payload: &EventPayload,
    actor_id: IdentityId,
) -> Result<Event, EventError> {
    // Generate the event id outside the lock-sensitive work (a ULID embeds its own
    // creation time, so it is correct here and keeps the lock window short).
    let event_id = ulid::Ulid::generate().to_string();

    let event_type = payload.event_type();
    let target_node_id = payload.target_node_id().map(|n| n.0.clone());
    let payload_value = serde_json::to_value(payload)?;
    let canonical = canonical_json(&payload_value);

    let content_hash = content_hash(
        event_type.as_str(),
        target_node_id.as_deref(),
        &canonical,
        &actor_id.0,
    );

    // Serialize all appends for this document. Locking the document row (rather than
    // the latest event row) is what actually makes appends linearizable: a lock on
    // the latest *existing* event does not stop a concurrent txn from selecting that
    // same row and computing a duplicate next `seq`. NO KEY UPDATE conflicts with
    // other writers and permission/lifecycle locks, but permits checkpoint KEY
    // SHARE guards. Appends never change document.id; checkpoints pin immutable
    // event sequences and must not require stopping later appends.
    let exists: Option<(Uuid,)> =
        sqlx::query_as("select id from document where id = $1 for no key update")
            .bind(document_id.0)
            .fetch_optional(&mut **tx)
            .await?;
    if exists.is_none() {
        return Err(EventError::DocumentNotFound(document_id.0));
    }

    let prev: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "select seq, chain_hash from event where document_id = $1 order by seq desc limit 1",
    )
    .bind(document_id.0)
    .fetch_optional(&mut **tx)
    .await?;

    let (prev_seq, prev_chain_hash) = match prev {
        Some((seq, hash)) => (seq, hash),
        None => (0, ZERO_HASH.to_vec()),
    };
    let next_seq = prev_seq + 1;
    let chain_hash = chain_hash(&content_hash, &prev_chain_hash);

    let inserted: Event = sqlx::query_as(
        "insert into event
           (id, document_id, seq, type, actor_id, target_node_id, payload,
            content_hash, prev_chain_hash, chain_hash)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         returning *",
    )
    .bind(&event_id)
    .bind(document_id.0)
    .bind(next_seq)
    .bind(event_type.as_str())
    .bind(actor_id.0)
    .bind(target_node_id)
    .bind(&payload_value)
    .bind(&content_hash[..])
    .bind(&prev_chain_hash[..])
    .bind(&chain_hash[..])
    .fetch_one(&mut **tx)
    .await?;

    Ok(inserted)
}

/// Run the post-commit snapshot step for a batch of just-committed events: take an
/// immediate snapshot if any event requires one (`Deployed`), otherwise spawn a
/// best-effort background `ensure_recent`. Call this once, after `commit()`.
pub async fn post_commit_snapshot(
    pool: &PgPool,
    document_id: DocumentId,
    payloads: &[EventPayload],
) -> Result<(), EventError> {
    if payloads.iter().any(snapshot::requires_immediate_snapshot) {
        SnapshotEngine::new(pool.clone())
            .take(document_id, SnapshotReason::Deployed)
            .await
            .map_err(|err| EventError::PostCommitSnapshot(err.to_string()))?;
    } else {
        snapshot::spawn_ensure_recent(pool.clone(), document_id, DEFAULT_MAX_EVENTS_IN_TAIL);
    }
    Ok(())
}

/// Replay a document's log in `seq` order, recompute every hash, and confirm it
/// matches what is stored. Linear in history bytes; streams events without
/// collecting the whole log in application memory. Returns
/// [`EventError::ChainBroken`] naming the exact `seq` on the first inconsistency —
/// Snapshot equivalence is checked separately by `snapshot_verification::verify_document`.
pub async fn verify_chain(pool: &PgPool, document_id: DocumentId) -> Result<(), EventError> {
    verify_from(pool, document_id, 0, &ZERO_HASH).await
}

/// Verify only the events after a trusted `(trusted_seq, trusted_chain_hash)`
/// position, which must match the stored row; `0` with [`ZERO_HASH`] verifies the
/// whole chain. Earlier events are not re-checked. The position must come from
/// outside this database: one read from it adds speed, not security.
pub async fn verify_from(
    pool: &PgPool,
    document_id: DocumentId,
    trusted_seq: i64,
    trusted_chain_hash: &[u8],
) -> Result<(), EventError> {
    if trusted_seq < 0 || (trusted_seq == 0 && trusted_chain_hash != ZERO_HASH) {
        return Err(EventError::ChainBroken {
            seq: trusted_seq,
            detail: "invalid trusted position (genesis must use 32 zero bytes)".into(),
        });
    }
    // Genesis audits every stored row, including malformed negative sequences;
    // the schema does not enforce positive seq values. A trusted non-genesis
    // position intentionally skips earlier rows.
    let from_seq = if trusted_seq == 0 {
        i64::MIN
    } else {
        trusted_seq
    };
    // One statement, so the trusted row and the suffix come from one consistent view.
    let mut events = sqlx::query_as::<_, Event>(
        "select * from event where document_id = $1 and seq >= $2 order by seq asc",
    )
    .bind(document_id.0)
    .bind(from_seq)
    .fetch(pool);

    if trusted_seq > 0 {
        match events.try_next().await? {
            Some(ev) if ev.seq == trusted_seq && ev.chain_hash[..] == trusted_chain_hash[..] => {}
            Some(ev) if ev.seq == trusted_seq => {
                return Err(EventError::ChainBroken {
                    seq: trusted_seq,
                    detail: "stored chain_hash differs from the trusted position".into(),
                })
            }
            _ => {
                return Err(EventError::ChainBroken {
                    seq: trusted_seq,
                    detail: "trusted position not found".into(),
                })
            }
        }
    }

    let mut prev_chain_hash = trusted_chain_hash.to_vec();
    let mut expected_seq = trusted_seq;
    let mut seals = Seals::default();
    while let Some(ev) = events.try_next().await? {
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or_else(|| EventError::ChainBroken {
                seq: ev.seq,
                detail: "event sequence exceeds the supported range".into(),
            })?;
        verify_event(&ev, document_id, expected_seq, &prev_chain_hash)?;
        seals.observe(&ev)?;

        prev_chain_hash = ev.chain_hash.clone();
    }

    Ok(())
}

/// Verify one row against its pinned document, expected sequence and predecessor.
pub(crate) fn verify_event(
    event: &Event,
    document: DocumentId,
    expected_seq: i64,
    previous: &[u8],
) -> Result<(), EventError> {
    if event.document_id != document {
        return Err(EventError::ChainBroken {
            seq: event.seq,
            detail: "document binding mismatch".into(),
        });
    }
    if event.seq != expected_seq {
        return Err(EventError::ChainBroken {
            seq: event.seq,
            detail: format!(
                "expected seq {expected_seq}, found {} (gap or reorder)",
                event.seq
            ),
        });
    }
    hashing::verify_event(event, expected_seq, previous)
        .map(|_| ())
        .map_err(|broken| EventError::ChainBroken {
            seq: broken.seq,
            detail: broken.detail.into(),
        })
}

/// The sealed-authorship rules (decision 038) over one ordered pass of a chain: each
/// `ChangeAttributed` parses, names exactly the events between the previous seal and itself,
/// and its own bytes are already covered by [`verify_event`]. A pass that starts at a trusted
/// position does not know earlier seals, so it checks only that a range starts after seq 0.
#[derive(Debug, Default)]
pub(crate) struct Seals {
    last: i64,
    /// Seals seen in this pass.
    pub(crate) count: usize,
}

impl Seals {
    pub(crate) fn observe(&mut self, event: &Event) -> Result<(), EventError> {
        if event.event_type != engine_shared::EventType::ChangeAttributed.as_str() {
            return Ok(());
        }
        let broken = |detail: String| EventError::ChainBroken {
            seq: event.seq,
            detail: format!("sealed authorship: {detail}"),
        };
        let Ok(EventPayload::ChangeAttributed(seal)) =
            serde_json::from_value::<EventPayload>(event.payload.clone())
        else {
            return Err(broken("the payload is malformed".into()));
        };
        seal.check(event.seq, self.last).map_err(broken)?;
        self.last = event.seq;
        self.count += 1;
        Ok(())
    }
}

/// Read events with `from_seq <= seq <= to_seq`, in `seq` order.
pub async fn read_range(
    pool: &PgPool,
    document_id: DocumentId,
    from_seq: i64,
    to_seq: i64,
) -> Result<Vec<Event>, EventError> {
    let events = sqlx::query_as(
        "select * from event
         where document_id = $1 and seq between $2 and $3
         order by seq asc",
    )
    .bind(document_id.0)
    .bind(from_seq)
    .bind(to_seq)
    .fetch_all(pool)
    .await?;
    Ok(events)
}

/// Bounded history page, including at most one lookahead row for a 1,000-row API
/// page. SQL applies the limit before rows enter application memory.
pub async fn read_range_page(
    pool: &PgPool,
    document_id: DocumentId,
    from_seq: i64,
    to_seq: i64,
    limit: i64,
) -> Result<Vec<Event>, EventError> {
    Ok(sqlx::query_as("select * from event where document_id=$1 and seq between $2 and $3 order by seq asc limit $4")
        .bind(document_id.0).bind(from_seq).bind(to_seq).bind(limit.clamp(1, 1001))
        .fetch_all(pool).await?)
}

/// Read every event after a snapshot's `through_seq`, in `seq` order — the tail the
/// materializer folds onto a snapshot. Pass `0` to read the whole log.
pub async fn read_since_snapshot(
    pool: &PgPool,
    document_id: DocumentId,
    snapshot_seq: i64,
) -> Result<Vec<Event>, EventError> {
    let events =
        sqlx::query_as("select * from event where document_id = $1 and seq > $2 order by seq asc")
            .bind(document_id.0)
            .bind(snapshot_seq)
            .fetch_all(pool)
            .await?;
    Ok(events)
}

#[cfg(test)]
mod tests {
    //! In-memory property tests for the verification *math*, no database required.
    //! These exercise the same `content_hash`/`chain_hash` functions that the
    //! DB-backed [`verify_chain`] uses; the DB integration lives in
    //! `tests/event_log_test.rs`.

    use super::*;
    use proptest::prelude::*;
    use serde_json::Value;

    /// A standalone copy of the verify loop over synthetic rows, so the
    /// tamper/reorder properties can be checked without Postgres.
    #[derive(Clone)]
    struct Row {
        seq: i64,
        event_type: String,
        target: Option<String>,
        payload: Value,
        content_hash: Vec<u8>,
        prev_chain_hash: Vec<u8>,
        chain_hash: Vec<u8>,
    }

    /// Build a well-formed chain of `n` FieldEdited-shaped events for one actor.
    fn build_chain(actor: Uuid, payloads: &[Value]) -> Vec<Row> {
        let mut rows = Vec::new();
        let mut prev = ZERO_HASH.to_vec();
        for (i, payload) in payloads.iter().enumerate() {
            let canonical = canonical_json(payload);
            let ch = content_hash("FieldEdited", Some("node-1"), &canonical, &actor);
            let chain = chain_hash(&ch, &prev);
            rows.push(Row {
                seq: i as i64 + 1,
                event_type: "FieldEdited".into(),
                target: Some("node-1".into()),
                payload: payload.clone(),
                content_hash: ch.to_vec(),
                prev_chain_hash: prev.clone(),
                chain_hash: chain.to_vec(),
            });
            prev = chain.to_vec();
        }
        rows
    }

    /// The same checks `verify_chain` runs, over in-memory rows. Returns the first
    /// bad `seq`, or `None` if the chain is intact.
    fn verify_rows(rows: &[Row], actor: Uuid) -> Option<i64> {
        let mut prev = ZERO_HASH.to_vec();
        for (i, r) in rows.iter().enumerate() {
            let expected_seq = i as i64 + 1;
            if r.seq != expected_seq {
                return Some(r.seq);
            }
            let canonical = canonical_json(&r.payload);
            let ch = content_hash(&r.event_type, r.target.as_deref(), &canonical, &actor);
            if ch[..] != r.content_hash[..] {
                return Some(r.seq);
            }
            if r.prev_chain_hash[..] != prev[..] {
                return Some(r.seq);
            }
            let chain = chain_hash(&ch, &prev);
            if chain[..] != r.chain_hash[..] {
                return Some(r.seq);
            }
            prev = r.chain_hash.clone();
        }
        None
    }

    fn payloads_strategy() -> impl Strategy<Value = Vec<Value>> {
        // Realistic PoC shape: small objects of string fields. Avoids JSONB numeric
        // normalization concerns and keeps the canonical form stable.
        prop::collection::vec(
            prop::collection::hash_map("[a-z_]{1,8}", "[ -~]{0,24}", 1..4).prop_map(|m| {
                Value::Object(m.into_iter().map(|(k, v)| (k, Value::String(v))).collect())
            }),
            1..12,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// A freshly built chain always verifies.
        #[test]
        fn intact_chain_verifies(payloads in payloads_strategy()) {
            let actor = Uuid::from_u128(7);
            let rows = build_chain(actor, &payloads);
            prop_assert_eq!(verify_rows(&rows, actor), None);
        }

        /// Tampering with any byte of any event's payload is detected at that seq.
        #[test]
        fn payload_tamper_is_detected(
            payloads in payloads_strategy(),
            idx in 0usize..12,
        ) {
            let actor = Uuid::from_u128(7);
            let mut rows = build_chain(actor, &payloads);
            let target = idx % rows.len();
            // Mutate the stored payload without recomputing its hash.
            rows[target].payload = serde_json::json!({ "tampered": "yes" });
            prop_assert_eq!(verify_rows(&rows, actor), Some(rows[target].seq));
        }

        /// Swapping two adjacent events breaks the chain linkage.
        #[test]
        fn reorder_is_detected(payloads in payloads_strategy().prop_filter(
            "need at least two events", |p| p.len() >= 2)) {
            let actor = Uuid::from_u128(7);
            let mut rows = build_chain(actor, &payloads);
            rows.swap(0, 1);
            // verify_rows checks seq contiguity first; the swap makes seq[0] == 2.
            prop_assert!(verify_rows(&rows, actor).is_some());
        }
    }

    #[test]
    fn canonical_json_sorts_keys_and_is_stable() {
        let a = serde_json::json!({ "b": 1, "a": { "d": 2, "c": 3 } });
        let b = serde_json::json!({ "a": { "c": 3, "d": 2 }, "b": 1 });
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(canonical_json(&a), br#"{"a":{"c":3,"d":2},"b":1}"#.to_vec());
    }

    #[test]
    fn genesis_chain_hash_folds_zero_prev() {
        let actor = Uuid::from_u128(1);
        let canonical = canonical_json(&serde_json::json!({ "x": "y" }));
        let ch = content_hash("FieldEdited", Some("n1"), &canonical, &actor);
        let chain = chain_hash(&ch, &ZERO_HASH);
        // Deterministic: recomputing gives the same digest.
        assert_eq!(chain, chain_hash(&ch, &ZERO_HASH));
        assert_ne!(chain, ch);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("fixture hex"))
            .collect()
    }

    /// One valid log with every event type. The fixture's hashes come from an
    /// independent implementation of the documented formula; replay must reproduce
    /// the pinned state and node Merkle root.
    #[test]
    fn v1_golden_log_hashes_and_replay_are_stable() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/v1-log.json")).unwrap();
        let document = DocumentId(fixture["document_id"].as_str().unwrap().parse().unwrap());
        let actor = IdentityId(fixture["actor_id"].as_str().unwrap().parse().unwrap());

        let mut events = Vec::new();
        let mut types = std::collections::BTreeSet::new();
        let mut previous = ZERO_HASH.to_vec();
        for row in fixture["events"].as_array().unwrap() {
            let payload: EventPayload = serde_json::from_value(row["payload"].clone()).unwrap();
            let event = Event {
                id: engine_shared::EventId(row["id"].as_str().unwrap().into()),
                document_id: document,
                seq: row["seq"].as_i64().unwrap(),
                event_type: row["type"].as_str().unwrap().into(),
                actor_id: actor,
                target_node_id: row["target_node_id"]
                    .as_str()
                    .map(|id| engine_shared::NodeId(id.into())),
                payload: row["payload"].clone(),
                content_hash: hex(row["content_hash"].as_str().unwrap()),
                prev_chain_hash: hex(row["prev_chain_hash"].as_str().unwrap()),
                chain_hash: hex(row["chain_hash"].as_str().unwrap()),
                created_at: chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
            };
            // The type and target columns are derived from the payload at append time.
            assert_eq!(event.event_type, payload.event_type().as_str());
            assert_eq!(event.target_node_id.as_ref(), payload.target_node_id());
            verify_event(&event, document, event.seq, &previous).unwrap();
            previous = event.chain_hash.clone();
            types.insert(event.event_type.clone());
            events.push(event);
        }
        assert_eq!(types.len(), 15, "the fixture covers every v1 event type");

        let state = crate::materializer::Materializer::fold(&events).unwrap();
        let pinned: crate::materializer::DocumentState =
            serde_json::from_value(fixture["final_state"].clone()).unwrap();
        assert_eq!(state, pinned);
        assert_eq!(
            snapshot::merkle_root(&state).unwrap().to_vec(),
            hex(fixture["merkle_root"].as_str().unwrap())
        );
    }
}
