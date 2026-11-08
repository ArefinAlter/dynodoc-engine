//! Ledger mode (decisions 025 and 028): the server keeps the signed edit messages, the
//! commit graph and a per-commit block-hash manifest, never a baseline of unchanged content.
//!
//! The first commit of a ledger document records each block's hash without its content; later
//! commits carry the full new state of each changed block with its new hash. The manifest of
//! any revision is the `block_hash` field of its live blocks, so it needs no table of its own;
//! its Merkle root (see [`root`]) travels with checkpoints and changes, and a pane that holds a
//! different root fetches [`manifest`] to find the differing blocks. Blocks or images a pane
//! lacks travel between members through the relay at the end of this module: stored only until
//! delivered, size-capped, deleted when the requester downloads them.
use crate::{
    access,
    auth::{sha256, AuthContext},
    error::ApiError,
    provenance::{connector_tx, Connector},
    reviews, AppState,
};
use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use engine_core::materializer::DocumentState;
use engine_shared::EventPayload;
use engine_shared::NodeId;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/documents/{id}/storage",
            get(storage_get).post(storage_set),
        )
        .route(
            "/projects/{id}/storage",
            get(project_storage_get).post(project_storage_set),
        )
        .route("/connector/documents/{id}/storage", get(connector_storage))
        .route("/connector/documents/{id}/manifest", get(manifest))
        .route("/connector/documents/{id}/relay", post(relay_ask))
        .route("/connector/documents/{id}/relay/wanted", get(relay_wanted))
        .route(
            "/connector/documents/{id}/relay/{request}",
            get(relay_take)
                .post(relay_serve)
                .layer(axum::extract::DefaultBodyLimit::max(RELAY_BODY_MAX)),
        )
}

fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}

/// A document's storage choice. No `document_storage` row means repository mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Storage {
    pub(crate) ledger: bool,
    pub(crate) hash_only_media: bool,
    /// Encrypted projects (decision 035): block hashes are keyed with a key the server never
    /// holds, and changed blocks carry their content sealed (`{block_hash, sealed}`).
    pub(crate) keyed: bool,
    /// The epoch whose document key the block hashes were keyed under (0 when not keyed):
    /// a pane needs it to derive the ledger block key from its delegation (decision 041).
    pub(crate) key_epoch: i32,
}
impl Storage {
    pub(crate) fn json(self) -> Value {
        let mut v = json!({
            "mode": if self.ledger { "ledger" } else { "repository" },
            "media": if self.hash_only_media { "hash_only" } else { "stored" }
        });
        // Only encrypted projects' ledger documents say so; plaintext answers are unchanged.
        if self.keyed {
            v["block_hashes"] = json!("keyed");
            v["block_key_epoch"] = json!(self.key_epoch);
        }
        v
    }
}
pub(crate) async fn storage(db: &mut PgConnection, id: Uuid) -> Result<Storage, ApiError> {
    let row: Option<(String, String, String, Option<i32>)> = sqlx::query_as(
        "select mode,media_policy,block_hash_key,block_key_epoch from document_storage where document_id=$1",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row.map_or(
        Storage {
            ledger: false,
            hash_only_media: false,
            keyed: false,
            key_epoch: 0,
        },
        |(mode, media, key, epoch)| Storage {
            ledger: mode == "ledger",
            hash_only_media: media == "hash_only",
            keyed: key == "keyed",
            key_epoch: epoch.unwrap_or(0),
        },
    ))
}

/// A storage choice as the routes take it: `repository` or `ledger`, and `stored` or `hash_only`
/// images (hash only exists in ledger mode).
fn choice(mode: &str, media: Option<&str>) -> Result<Storage, ApiError> {
    let media = media.unwrap_or("stored");
    if !["repository", "ledger"].contains(&mode)
        || !["stored", "hash_only"].contains(&media)
        || (mode == "repository" && media != "stored")
    {
        return Err(bad(
            "Choose repository or ledger mode; images by hash only exist in ledger mode",
        ));
    }
    Ok(Storage {
        ledger: mode == "ledger",
        hash_only_media: media == "hash_only",
        keyed: false,
        key_epoch: 0,
    })
}
impl Storage {
    fn mode(self) -> &'static str {
        if self.ledger {
            "ledger"
        } else {
            "repository"
        }
    }
    fn media(self) -> &'static str {
        if self.hash_only_media {
            "hash_only"
        } else {
            "stored"
        }
    }
}

/// A document that enters a project before its first commit, with no storage setting of its
/// own, takes the project's default (decision 028). A document's own setting always wins.
pub(crate) async fn adopt_project_default(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    actor: Uuid,
) -> Result<(), ApiError> {
    let default: Option<(String, String)> = sqlx::query_as("select p.default_storage_mode,p.default_media_policy from project_settings p where p.space_id=document_project($1) and p.default_storage_mode<>'repository' and not exists(select 1 from document_storage s where s.document_id=$1)")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some((mode, media)) = default else {
        return Ok(());
    };
    if committed(tx, id).await? {
        return Ok(());
    }
    let wanted = choice(&mode, Some(&media))?;
    sqlx::query(
        "insert into document_storage(document_id,mode,media_policy,set_by) values($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(&mode)
    .bind(&media)
    .bind(actor)
    .execute(&mut **tx)
    .await?;
    key_if_encrypted(tx, id).await?;
    crate::product::audit(
        tx,
        actor,
        "document.storage_mode_set",
        id,
        json!({"storage":wanted.json(),"previous":choice("repository", None)?.json(),"source":"project_default"}),
    )
    .await
}

/// In an encrypted project a ledger document's block hashes are keyed under the current
/// epoch's document key (decision 035); before the first epoch there is no key to use.
async fn key_if_encrypted(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
) -> Result<(), ApiError> {
    let project: Option<(String, i32)> = sqlx::query_as("select p.encryption_mode,p.current_epoch from project_settings p where p.space_id=document_project($1)")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    match project {
        Some((mode, 0)) if mode != "none" => Err(bad(
            "Open the encrypted project's first epoch before choosing ledger mode",
        )),
        Some((mode, epoch)) if mode != "none" => {
            sqlx::query("update document_storage set block_hash_key='keyed',block_key_epoch=$2 where document_id=$1 and mode='ledger' and block_hash_key='plain'")
                .bind(id)
                .bind(epoch)
                .execute(&mut **tx)
                .await?;
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Drops the copies a merged ledger change request keeps of its events: its edits and the body
/// of its uploaded bundle (migration 61 checks the request and does the deletion).
pub(crate) async fn compact(
    db: &mut PgConnection,
    document: Uuid,
    draft: Uuid,
) -> Result<(), ApiError> {
    sqlx::query("insert into ledger_compaction(draft_id,document_id) values($1,$2)")
        .bind(draft)
        .bind(document)
        .execute(db)
        .await?;
    Ok(())
}

/// Deletes the block states members' panes sent for agents ([`relay_serve`], kind `state`) once
/// `draft`, an agent's change request, is merged, declined or withdrawn (decision 040, owner
/// decision). Call in the closing transaction, after the request's row is closed; it does
/// nothing for a person's request or one still open (a partly merged request stays open).
/// shortcut: a state is not linked to the request that used it, so all of a document's states
/// stay while any agent request of it is open; link them per request if that keeps them too long.
pub(crate) async fn release_agent_states(
    db: &mut PgConnection,
    document: Uuid,
    draft: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        "delete from ledger_block_state where document_id=$1
           and exists (select 1 from workspace_draft d join agent_identity a on a.identity_id=d.created_by
                        where d.id=$2 and d.document_id=$1 and (d.merged_at is not null or d.review_outcome is not null))
           and not exists (select 1 from workspace_draft d join agent_identity a on a.identity_id=d.created_by
                            where d.document_id=$1 and d.merged_at is null and d.review_outcome is null)",
    )
    .bind(document)
    .bind(draft)
    .execute(db)
    .await?;
    Ok(())
}

/// The block hash of a block's fields, as the SDK's `fieldsHash` computes it: SHA-256 of the
/// fields without `block_hash`, as JSON with sorted keys and no spaces.
pub(crate) fn fields_hash(fields: &Value) -> String {
    let mut rest = fields.as_object().cloned().unwrap_or_default();
    rest.remove("block_hash");
    hex(&sha256(Value::Object(rest).to_string().as_bytes()))
}
/// The server holds this block's full state: its fields hash to its block hash.
fn verified(fields: &Value) -> bool {
    fields.get("block_hash").and_then(Value::as_str) == Some(fields_hash(fields).as_str())
}

/// An agent's proposal on a ledger document, made to carry full block states (decision 028).
/// The server has no baseline, so an agent changes only blocks it creates or whose full state
/// the server holds; every block it creates or changes gets its new block hash, computed from
/// the state the proposal leaves. In a document, a block whose text the agent rewrites drops its
/// host form (Word or Google Docs), which no longer matches the text; the panes rebuild it from
/// the text, as for any block changed in another editor.
///
/// `held` names the blocks of `before` whose state came from a member's pane (decision 040,
/// [`fill`]): the server's own state of each is only its hash, so the proposal re-sends every
/// field of such a block, edits as plain values, and the merged events then hold it whole.
pub(crate) fn agent_ops(
    before: &DocumentState,
    document: bool,
    ops: &[EventPayload],
    held: &BTreeSet<NodeId>,
) -> Result<Vec<EventPayload>, ApiError> {
    let mut touched: Vec<NodeId> = Vec::new();
    let mut created = BTreeSet::new();
    let mut rewritten = BTreeSet::new();
    let mut native = BTreeSet::new();
    for op in ops {
        let id = match op {
            EventPayload::NodeCreated { node_id, .. } => {
                created.insert(node_id.clone());
                node_id
            }
            EventPayload::FieldEdited { node_id, field, .. } if field != "block_hash" => {
                if field == "content" {
                    rewritten.insert(node_id.clone());
                }
                if field == "native" {
                    native.insert(node_id.clone());
                }
                node_id
            }
            EventPayload::RichTextPatched { node_id, .. } => {
                rewritten.insert(node_id.clone());
                node_id
            }
            _ => continue,
        };
        if !touched.contains(id) {
            touched.push(id.clone());
        }
    }
    if touched.iter().any(|id| {
        !created.contains(id)
            && !before
                .nodes
                .get(id)
                .is_some_and(|n| verified(&n.current_fields))
    }) {
        return Err(bad("This block's content is only in members' files (ledger mode), so an agent cannot change it. Ask a member to commit it from their editor, then propose again."));
    }
    let mut out = ops.to_vec();
    if document {
        for id in rewritten.difference(&native) {
            let had = before
                .nodes
                .get(id)
                .is_some_and(|n| !n.current_fields["native"].is_null());
            if had && !created.contains(id) {
                out.push(EventPayload::FieldEdited {
                    node_id: id.clone(),
                    field: "native".into(),
                    value: Value::Null,
                });
            }
        }
    }
    let mut after = before.clone();
    for op in &out {
        engine_core::materializer::apply_payload(&mut after, op)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    }
    for id in touched
        .iter()
        .filter(|id| held.contains(*id) && !created.contains(*id))
    {
        let Some(n) = after.nodes.get(id).filter(|n| !n.deleted) else {
            continue;
        };
        out.retain(|op| {
            !matches!(op, EventPayload::FieldEdited { node_id, .. }
                | EventPayload::RichTextPatched { node_id, .. } if node_id == id)
        });
        if let Some(fields) = n.current_fields.as_object() {
            for (field, value) in fields.iter().filter(|(f, _)| *f != "block_hash") {
                out.push(EventPayload::FieldEdited {
                    node_id: id.clone(),
                    field: field.clone(),
                    value: value.clone(),
                });
            }
        }
    }
    for id in touched {
        if let Some(n) = after.nodes.get(&id).filter(|n| !n.deleted) {
            let hash = fields_hash(&n.current_fields);
            out.push(EventPayload::FieldEdited {
                node_id: id,
                field: "block_hash".into(),
                value: json!(hash),
            });
        }
    }
    Ok(out)
}

/// The block hashes of the blocks `ops` change whose state the server does not hold (a block
/// bound by the first commit and never changed since, and no member's pane has sent it).
pub(crate) fn unheld(before: &DocumentState, ops: &[EventPayload]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for op in ops {
        let id = match op {
            EventPayload::FieldEdited { node_id, field, .. } if field != "block_hash" => node_id,
            EventPayload::RichTextPatched { node_id, .. } => node_id,
            _ => continue,
        };
        if let Some(hash) = before
            .nodes
            .get(id)
            .filter(|n| !verified(&n.current_fields))
            .and_then(|n| n.current_fields.get("block_hash").and_then(Value::as_str))
            .filter(|h| hex64(h))
        {
            out.insert(hash.to_owned());
        }
    }
    out.into_iter().collect()
}

/// The states members' panes sent for blocks of `state` that the server holds only as hashes
/// (decision 040): each was checked against its block hash when it arrived.
pub(crate) async fn held(
    db: &mut PgConnection,
    document: Uuid,
    state: &DocumentState,
) -> Result<Vec<(NodeId, Value)>, ApiError> {
    let want: Vec<(NodeId, String)> = state
        .nodes
        .values()
        .filter(|n| !n.deleted && !verified(&n.current_fields))
        .filter_map(|n| {
            let hash = n.current_fields.get("block_hash").and_then(Value::as_str)?;
            hex64(hash).then(|| (n.id.clone(), hash.to_owned()))
        })
        .collect();
    if want.is_empty() {
        return Ok(Vec::new());
    }
    let hashes: Vec<Vec<u8>> = want.iter().filter_map(|w| hex::decode(&w.1).ok()).collect();
    let rows: Vec<(String, Value)> = sqlx::query_as(
        "select encode(block_hash,'hex'),fields from ledger_block_state where document_id=$1 and block_hash=any($2)",
    )
    .bind(document)
    .bind(&hashes)
    .fetch_all(db)
    .await?;
    let found: BTreeMap<String, Value> = rows.into_iter().collect();
    Ok(want
        .into_iter()
        .filter_map(|(id, hash)| {
            let mut fields = found.get(&hash)?.clone();
            fields["block_hash"] = json!(hash);
            Some((id, fields))
        })
        .collect())
}
/// `state` with the [`held`] states filled in; returns the blocks filled.
pub(crate) fn fill(state: &mut DocumentState, held: Vec<(NodeId, Value)>) -> BTreeSet<NodeId> {
    let mut filled = BTreeSet::new();
    for (id, fields) in held {
        if let Some(n) = state.nodes.get_mut(&id) {
            n.current_fields = fields;
            filled.insert(id);
        }
    }
    filled
}
/// Ask members' panes for the states of `hashes` on behalf of agent identity `agent`: relay
/// requests of kind `state`, answered by any member's pane and kept by [`relay_serve`] only if
/// they hash right. Best effort and outside the refused proposal's transaction, which rolls
/// back; a failure only means nobody is asked this time.
pub(crate) async fn ask_states(
    pool: &sqlx::PgPool,
    document: Uuid,
    agent: Uuid,
    hashes: &[String],
) {
    let subjects: Vec<Vec<u8>> = hashes
        .iter()
        .take(200)
        .filter_map(|h| hex::decode(h).ok())
        .collect();
    if let Err(error) = sqlx::query("insert into ledger_relay(document_id,requested_by,kind,subject) select $1,$2,'state',s from unnest($3::bytea[]) s on conflict(document_id,requested_by,kind,subject) do update set expires_at=now()+interval '1 hour' where ledger_relay.served_at is null")
        .bind(document)
        .bind(agent)
        .bind(&subjects)
        .execute(pool)
        .await
    {
        tracing::warn!(%document, %error, "block states for an agent could not be requested");
    }
}
/// A pane's answer to a `state` request: the block's fields, kept only if they hash to the
/// block hash asked for (a member's pane is not trusted with the content of the ledger).
fn state_answer(hash: &str, bytes: &[u8]) -> Option<Value> {
    let mut fields: Value = serde_json::from_slice(bytes).ok()?;
    let object = fields.as_object_mut()?;
    object.remove("block_hash");
    if object.contains_key("sealed") || fields_hash(&fields) != hash {
        return None;
    }
    Some(fields)
}

/// Rebases a partly merged ledger change request onto the revision its merge left (decision
/// 040): its edits, copies of events for what was merged, are replaced by the difference that
/// is still to merge, so its state is unchanged and it keeps nothing the events hold.
pub(crate) async fn rebase_request(
    db: &mut PgConnection,
    document: Uuid,
    draft: Uuid,
    team: &DocumentState,
    local: &DocumentState,
) -> Result<(), ApiError> {
    let rest = engine_core::workspace_merge::diff(team, local)?;
    let author: Uuid = sqlx::query_scalar("select created_by from workspace_draft where id=$1")
        .bind(draft)
        .fetch_one(&mut *db)
        .await?;
    sqlx::query("insert into ledger_request_rebase(draft_id,document_id) values($1,$2)")
        .bind(draft)
        .bind(document)
        .execute(&mut *db)
        .await?;
    for op in rest {
        sqlx::query("insert into draft_edit(draft_id,payload,actor_id) values($1,$2,$3)")
            .bind(draft)
            .bind(json!(op))
            .bind(author)
            .execute(&mut *db)
            .await?;
    }
    Ok(())
}

/// Refuses a write that does not come from an editor commit. A ledger document changes only
/// through connector bundles, whose blocks carry their manifest hashes; other writers (the web
/// editor, drafts, agents) would either store content the members did not commit or leave the
/// manifest without hashes.
pub(crate) async fn refuse_direct(db: &mut PgConnection, id: Uuid) -> Result<(), ApiError> {
    if storage(db, id).await?.ledger {
        return Err(bad(
            "This document is in ledger mode: its content lives in members' files and changes only through commits from the editor panes.",
        ));
    }
    Ok(())
}

/// A document is committed once it holds anything beyond its root or has a change request;
/// its storage mode is fixed from then on.
async fn committed(db: &mut PgConnection, id: Uuid) -> Result<bool, ApiError> {
    Ok(sqlx::query_scalar("select exists(select 1 from event where document_id=$1 and not (type='NodeCreated' and payload->>'node_type'='form')) or exists(select 1 from workspace_draft where document_id=$1)")
        .bind(id)
        .fetch_one(db)
        .await?)
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// The ledger rules for the operations of one commit on `base`, with `team` the current head.
/// While neither has blocks (the first commit) every operation creates a block whose fields are
/// exactly `{block_hash}`: the server records the manifest and never the content. Later, a new
/// block carries its content, and every created or edited block carries its new `block_hash` in
/// the same commit.
pub(crate) fn check_ops(
    base: &DocumentState,
    team: &DocumentState,
    ops: &[EventPayload],
    keyed: bool,
) -> Result<(), ApiError> {
    if keyed {
        sealed_blocks(ops)?;
    }
    let blocks = |s: &DocumentState| {
        s.nodes
            .values()
            .any(|n| !n.deleted && n.parent_id.is_some())
    };
    let first = !blocks(base) && !blocks(team);
    let mut hashed = BTreeSet::new();
    let mut changed = BTreeSet::new();
    for op in ops {
        match op {
            EventPayload::NodeCreated {
                node_id, fields, ..
            } => {
                let hash = fields.get("block_hash").and_then(Value::as_str);
                let only_hash = fields.as_object().is_some_and(|f| f.len() == 1);
                if !hash.is_some_and(hex64) {
                    return Err(bad("In ledger mode every block carries its block hash."));
                }
                if first && !only_hash {
                    return Err(bad("In ledger mode the first commit records block hashes only, never the content."));
                }
                if !first && only_hash {
                    return Err(bad(
                        "A block added after the first commit carries its content.",
                    ));
                }
                hashed.insert(node_id);
            }
            _ if first => {
                return Err(bad(
                    "In ledger mode the first commit only records the blocks.",
                ));
            }
            EventPayload::FieldEdited {
                node_id,
                field,
                value,
            } if field == "block_hash" => {
                if !value.as_str().is_some_and(hex64) {
                    return Err(bad("Use a lowercase SHA-256 hex block hash"));
                }
                hashed.insert(node_id);
            }
            EventPayload::FieldEdited { node_id, .. }
            | EventPayload::RichTextPatched { node_id, .. } => {
                changed.insert(node_id);
            }
            _ => {}
        }
    }
    if changed.iter().any(|n| !hashed.contains(n)) {
        return Err(bad(
            "In ledger mode each changed block carries its new block hash.",
        ));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// One manifest entry per live block, in node-id order: id, parent, position, block hash
/// (empty when a block has none, as in repository mode).
pub(crate) fn entries(state: &DocumentState) -> Vec<[String; 4]> {
    state
        .nodes
        .values()
        .filter(|n| !n.deleted)
        .filter_map(|n| {
            let parent = n.parent_id.as_ref()?;
            let hash = n.current_fields.get("block_hash").and_then(Value::as_str);
            Some([
                n.id.0.clone(),
                parent.0.clone(),
                n.pos.clone(),
                hash.unwrap_or_default().to_owned(),
            ])
        })
        .collect()
}

/// Merkle root of a revision's manifest. Leaf: SHA-256 of `id \n parent \n pos \n hash`
/// (lowercase hex). Each level hashes the concatenated hex of neighbouring pairs; an odd last
/// node moves up unchanged. No blocks: SHA-256 of the empty string. The SDK's `manifestRoot`
/// computes the same value; both test the same vector.
pub(crate) fn root(entries: &[[String; 4]]) -> String {
    levels(entries)
        .pop()
        .and_then(|mut top| top.pop())
        .unwrap_or_else(|| hex(&sha256(b"")))
}
/// Every level of the manifest's Merkle tree, leaves first and the root last (none for an
/// empty manifest). Node `j` of level `k` covers the leaves `j * 2^k` to `(j + 1) * 2^k`, so a
/// pane compares one level and fetches only the leaf ranges under the nodes that differ.
pub(crate) fn levels(entries: &[[String; 4]]) -> Vec<Vec<String>> {
    let mut level: Vec<String> = entries
        .iter()
        .map(|e| hex(&sha256(e.join("\n").as_bytes())))
        .collect();
    if level.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    while level.len() > 1 {
        let next = level
            .chunks(2)
            .map(|pair| {
                if pair.len() == 2 {
                    hex(&sha256(pair.concat().as_bytes()))
                } else {
                    pair[0].clone()
                }
            })
            .collect();
        out.push(std::mem::replace(&mut level, next));
    }
    out.push(level);
    out
}

/// What the server keeps for one document, in bytes as stored (after column compression):
/// the edit messages (events), the current materialized blocks, snapshots, change requests
/// (their bases and edits), connector uploads, shared state objects, images and relay
/// payloads in flight. The file size is the client's to report beside it (decision 025,
/// acceptance 5).
pub(crate) async fn report(db: &mut PgConnection, id: Uuid) -> Result<Value, ApiError> {
    let row: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "select
            (select count(*) from event where document_id=$1),
            (select coalesce(sum(pg_column_size(payload)),0) from event where document_id=$1)::bigint,
            (select coalesce(sum(pg_column_size(current_fields)),0) from node where document_id=$1)::bigint,
            (select coalesce(sum(pg_column_size(state)),0) from snapshot where document_id=$1)::bigint,
            ((select coalesce(sum(coalesce(pg_column_size(base_state),0)+coalesce(pg_column_size(merge_base_state),0)),0) from workspace_draft where document_id=$1)
              +(select coalesce(sum(pg_column_size(e.payload)),0) from draft_edit e join workspace_draft d on d.id=e.draft_id where d.document_id=$1))::bigint,
            (select coalesce(sum(pg_column_size(body)),0) from provenance_bundle where document_id=$1)::bigint,
            (select coalesce(sum(octet_length(bytes)),0) from checkpoint_object where document_id=$1)::bigint,
            (select coalesce(sum(size),0) from connector_media where document_id=$1)::bigint,
            (select coalesce(sum(octet_length(payload)),0) from ledger_relay where document_id=$1)::bigint,
            (select coalesce(sum(pg_column_size(fields)),0) from ledger_block_state where document_id=$1)::bigint",
    )
    .bind(id)
    .fetch_one(db)
    .await?;
    let (events, edits, nodes, snapshots, requests, bundles, objects, media, relay, states) = row;
    Ok(json!({
        "events": events,
        "bytes": {
            "edit_messages": edits,
            "current_blocks": nodes,
            "snapshots": snapshots,
            "change_requests": requests,
            "uploads": bundles,
            "shared_objects": objects,
            "media": media,
            "relay": relay,
            "agent_block_states": states
        },
        "total_bytes": edits + nodes + snapshots + requests + bundles + objects + media + relay + states
    }))
}

#[utoipa::path(get,path="/documents/{id}/storage",params(("id"=Uuid,Path)),security(("paseto"=[])),responses((status=200,description="Storage mode, media policy, whether it is fixed, and the bytes the server keeps",body=Value)))]
async fn storage_get(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    a: AuthContext,
) -> Result<Json<Value>, ApiError> {
    let mut db = s.pool.acquire().await?;
    access::require_member(&mut db, id, a.identity_id).await?;
    let current = storage(&mut db, id).await?;
    Ok(Json(json!({
        "storage": current.json(),
        "fixed": committed(&mut db, id).await?,
        "report": report(&mut db, id).await?
    })))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct StorageInput {
    /// `repository` or `ledger`.
    mode: String,
    /// `stored` or `hash_only` (ledger mode only). Omitted: `stored`.
    media: Option<String>,
}
#[utoipa::path(post,path="/documents/{id}/storage",params(("id"=Uuid,Path)),request_body=StorageInput,security(("paseto"=[])),responses((status=200,description="Saved and audited",body=Value),(status=403,description="Owners and managers choose the storage mode"),(status=409,description="The mode is fixed once the document has a commit")))]
async fn storage_set(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    a: AuthContext,
    Json(p): Json<StorageInput>,
) -> Result<Json<Value>, ApiError> {
    let wanted = choice(&p.mode, p.media.as_deref())?;
    let mut tx = s.pool.begin().await?;
    sqlx::query("select id from document where id=$1 for update")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    crate::projects::lock_document_project(&mut tx, id).await?;
    if !access::governance_role(&mut tx, id, a.identity_id)
        .await?
        .can_manage()
    {
        return Err(ApiError::Forbidden);
    }
    let current = storage(&mut tx, id).await?;
    if current.ledger != wanted.ledger && committed(&mut tx, id).await? {
        return Err(ApiError::Conflict {
            reason: if current.ledger {
                "This document's content lives in its members' files, so the server cannot become its repository by itself. Import one member's file as a new repository-mode document."
            } else {
                "The storage mode is chosen before the first commit. Create a new ledger-mode document and bind the members' files to it."
            }
            .into(),
        });
    }
    sqlx::query("insert into document_storage(document_id,mode,media_policy,set_by) values($1,$2,$3,$4) on conflict(document_id) do update set mode=excluded.mode,media_policy=excluded.media_policy,set_by=excluded.set_by,set_at=now()")
        .bind(id)
        .bind(wanted.mode())
        .bind(wanted.media())
        .bind(a.identity_id)
        .execute(&mut *tx)
        .await?;
    key_if_encrypted(&mut tx, id).await?;
    crate::product::audit(
        &mut tx,
        a.identity_id,
        "document.storage_mode_set",
        id,
        json!({"storage":wanted.json(),"previous":current.json()}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"storage":wanted.json()})))
}

#[utoipa::path(get,path="/projects/{id}/storage",params(("id"=Uuid,Path)),security(("paseto"=[])),responses((status=200,description="The storage mode new files of this project take",body=Value)))]
async fn project_storage_get(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    a: AuthContext,
) -> Result<Json<Value>, ApiError> {
    let mut db = s.pool.acquire().await?;
    let role = crate::projects::require(&mut db, id, a.identity_id).await?;
    let (mode, media): (String, String) = sqlx::query_as(
        "select default_storage_mode,default_media_policy from project_settings where space_id=$1",
    )
    .bind(id)
    .fetch_optional(&mut *db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let can_manage = ["owner", "manager"].contains(&role.as_str());
    Ok(Json(json!({
        "storage": choice(&mode, Some(&media))?.json(),
        "can_manage": can_manage
    })))
}

#[utoipa::path(post,path="/projects/{id}/storage",params(("id"=Uuid,Path)),request_body=StorageInput,security(("paseto"=[])),responses((status=200,description="Saved and audited; files that join the project before their first commit take it",body=Value),(status=403,description="Project owners and managers choose the default")))]
async fn project_storage_set(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    a: AuthContext,
    Json(p): Json<StorageInput>,
) -> Result<Json<Value>, ApiError> {
    let wanted = choice(&p.mode, p.media.as_deref())?;
    let mut tx = s.pool.begin().await?;
    let role = crate::projects::lock(&mut tx, id, a.identity_id).await?;
    if !["owner", "manager"].contains(&role.as_str()) {
        return Err(ApiError::Forbidden);
    }
    let (mode, media): (String, String) = sqlx::query_as("update project_settings n set default_storage_mode=$2,default_media_policy=$3 from project_settings o where n.space_id=$1 and o.space_id=$1 returning o.default_storage_mode,o.default_media_policy")
        .bind(id)
        .bind(wanted.mode())
        .bind(wanted.media())
        .fetch_one(&mut *tx)
        .await?;
    crate::product::audit(
        &mut tx,
        a.identity_id,
        "project.storage_default_set",
        id,
        json!({"storage":wanted.json(),"previous":choice(&mode, Some(&media))?.json()}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"storage":wanted.json()})))
}

#[utoipa::path(get,path="/connector/documents/{id}/storage",params(("id"=Uuid,Path)),security(("connector_key"=[])),responses((status=200,description="Storage mode and the bytes the server keeps for this file",body=Value)))]
async fn connector_storage(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: Connector,
) -> Result<Json<Value>, ApiError> {
    let mut tx = connector_tx(&s, &c, id).await?;
    let current = storage(&mut tx, id).await?;
    Ok(Json(
        json!({"storage":current.json(),"report":report(&mut tx, id).await?}),
    ))
}

#[derive(Deserialize)]
struct ManifestQuery {
    seq: Option<i64>,
    level: Option<usize>,
    from: Option<usize>,
    to: Option<usize>,
}
/// Nodes of one level, or entries of one range, a manifest answer carries at most.
const MANIFEST_PAGE: usize = 4096;
#[utoipa::path(get,path="/connector/documents/{id}/manifest",params(("id"=Uuid,Path),("seq"=Option<i64>,Query,description="Revision; omitted means the head"),("level"=Option<usize>,Query,description="Only the hashes of this level of the Merkle tree (0 is the leaves), at most 4,096"),("from"=Option<usize>,Query,description="Only the entries from this index"),("to"=Option<usize>,Query,description="Only the entries before this index, at most 4,096 after from")),security(("connector_key"=[])),responses((status=200,description="The block-hash manifest of a revision and its Merkle root",body=Value)))]
async fn manifest(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: Connector,
    Query(q): Query<ManifestQuery>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = connector_tx(&s, &c, id).await?;
    let head: i64 =
        sqlx::query_scalar("select coalesce(max(seq),0) from event where document_id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let seq = q.seq.unwrap_or(head);
    if seq < 0 || seq > head {
        return Err(bad("The revision is outside this document's history"));
    }
    let entries = entries(&reviews::state_through(&mut tx, id, seq).await?);
    let count = entries.len();
    // A subtree answer (decision 040): one level of hashes, or one range of entries.
    if let Some(level) = q.level {
        let mut all = levels(&entries);
        let top = all
            .last()
            .and_then(|l| l.first())
            .cloned()
            .unwrap_or_else(|| root(&entries));
        if level >= all.len() || all[level].len() > MANIFEST_PAGE {
            return Err(bad(
                "Ask for a level of the manifest with at most 4,096 nodes",
            ));
        }
        let hashes = all.swap_remove(level);
        return Ok(Json(
            json!({"seq":seq,"root":top,"count":count,"level":level,"hashes":hashes}),
        ));
    }
    if q.from.is_some() || q.to.is_some() {
        let from = q.from.unwrap_or(0);
        let to = q.to.unwrap_or(count).min(count);
        if from > to || to - from > MANIFEST_PAGE {
            return Err(bad(
                "Ask for at most 4,096 manifest entries, from before to",
            ));
        }
        return Ok(Json(
            json!({"seq":seq,"root":root(&entries),"count":count,"from":from,"blocks":&entries[from..to]}),
        ));
    }
    Ok(Json(
        json!({"seq":seq,"root":root(&entries),"count":count,"blocks":entries}),
    ))
}

/// Requests a member may have open at once in one document.
const RELAY_OPEN_MAX: i64 = 500;
/// A block state (its fields as JSON) passed between members.
const RELAY_BLOCK_MAX: usize = 2 * 1024 * 1024;
/// An image, as the largest image a block may reference.
const RELAY_MEDIA_MAX: usize = 15 * 1024 * 1024;
/// Undelivered payloads one document may hold at once.
const RELAY_QUOTA: i64 = 64 * 1024 * 1024;
/// Base64 of the largest image plus the JSON around it.
const RELAY_BODY_MAX: usize = RELAY_MEDIA_MAX / 3 * 4 + 8 * 1024;

/// The relay is for ledger documents; expired rows go on every call, so nothing outlives its
/// hour without a background job.
async fn relay_tx(
    s: &AppState,
    c: &Connector,
    id: Uuid,
) -> Result<(sqlx::Transaction<'static, sqlx::Postgres>, bool), ApiError> {
    if c.document != id {
        return Err(ApiError::Forbidden);
    }
    // Before the call's transaction, so the purge holds even when the call then fails, and
    // no call holds two pool connections at once.
    sqlx::query("delete from ledger_relay where document_id=$1 and expires_at<=now()")
        .bind(id)
        .execute(&s.pool)
        .await?;
    let mut tx = connector_tx(s, c, id).await?;
    let kept = storage(&mut tx, id).await?;
    if !kept.ledger {
        return Err(bad("The member relay serves ledger-mode documents only"));
    }
    Ok((tx, kept.keyed))
}

/// Keyed ledger documents (encrypted projects, decision 035): a block's fields are only its
/// keyed hash and, after the first commit, its content as a `DYNOSEAL` node-fields envelope
/// (base64url). The server checks the envelope's header and never sees the content.
fn sealed_blocks(ops: &[EventPayload]) -> Result<(), ApiError> {
    use engine_core::e2ee::{commit::decode, seal};
    let envelope = |v: &Value| {
        v.as_str()
            .and_then(|t| decode(t).ok())
            .and_then(|b| seal::Header::parse(&b).ok())
            .is_some_and(|(h, _)| h.kind == seal::Kind::NodeFields)
    };
    let refuse = || {
        bad("In an encrypted project a ledger block carries only its keyed hash and its sealed content")
    };
    for op in ops {
        match op {
            EventPayload::NodeCreated { fields, .. } => {
                let f = fields.as_object().ok_or_else(refuse)?;
                if f.keys().any(|k| k != "block_hash" && k != "sealed")
                    || f.get("sealed").is_some_and(|v| !envelope(v))
                {
                    return Err(refuse());
                }
            }
            EventPayload::FieldEdited { field, value, .. } => {
                if field != "block_hash" && !(field == "sealed" && envelope(value)) {
                    return Err(refuse());
                }
            }
            EventPayload::RichTextPatched { .. } => return Err(refuse()),
            _ => {}
        }
    }
    Ok(())
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct AskInput {
    /// `block` (a block state by its manifest hash) or `media` (an image by SHA-256).
    kind: String,
    hashes: Vec<String>,
    /// The requester's X25519 public key (base64url), for end-to-end encrypted answers later.
    recipient_key: Option<String>,
}
#[utoipa::path(post,path="/connector/documents/{id}/relay",params(("id"=Uuid,Path)),request_body=AskInput,security(("connector_key"=[])),responses((status=200,description="Open requests for these hashes; an online member answers them",body=Value),(status=400,description="Not a ledger document, bad hashes or too many open requests")))]
async fn relay_ask(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: Connector,
    Json(p): Json<AskInput>,
) -> Result<Json<Value>, ApiError> {
    if !["block", "media"].contains(&p.kind.as_str()) || p.hashes.is_empty() || p.hashes.len() > 200
    {
        return Err(bad("Ask for 1 to 200 blocks or images at once"));
    }
    if p.recipient_key.as_deref().is_some_and(|k| {
        k.len() != 43
            || !k
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }) {
        return Err(bad("Use a base64url X25519 public key"));
    }
    let subjects = p
        .hashes
        .iter()
        .map(|h| {
            if hex64(h) {
                hex::decode(h).map_err(|_| bad("Use lowercase SHA-256 hex digests"))
            } else {
                Err(bad("Use lowercase SHA-256 hex digests"))
            }
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    let me = c.auth.identity_id;
    let (mut tx, keyed) = relay_tx(&s, &c, id).await?;
    if keyed && p.recipient_key.is_none() {
        return Err(bad("In an encrypted project, ask with your one-time X25519 key so the answer is sealed to you"));
    }
    let open: i64 = sqlx::query_scalar(
        "select count(*) from ledger_relay where document_id=$1 and requested_by=$2",
    )
    .bind(id)
    .bind(me)
    .fetch_one(&mut *tx)
    .await?;
    if open + subjects.len() as i64 > RELAY_OPEN_MAX {
        return Err(bad(
            "Too many open requests to teammates; wait for answers or for them to expire",
        ));
    }
    sqlx::query("insert into ledger_relay(document_id,requested_by,kind,subject,recipient_key) select $1,$2,$3,s,$5 from unnest($4::bytea[]) s on conflict(document_id,requested_by,kind,subject) do update set expires_at=now()+interval '1 hour',recipient_key=excluded.recipient_key where ledger_relay.served_at is null")
        .bind(id)
        .bind(me)
        .bind(&p.kind)
        .bind(&subjects)
        .bind(&p.recipient_key)
        .execute(&mut *tx)
        .await?;
    let items: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('id',id,'kind',kind,'hash',encode(subject,'hex'),'served',served_at is not null) from ledger_relay where document_id=$1 and requested_by=$2 and kind=$3 and subject=any($4) order by encode(subject,'hex')")
        .bind(id)
        .bind(me)
        .bind(&p.kind)
        .bind(&subjects)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"requests":items})))
}

#[utoipa::path(get,path="/connector/documents/{id}/relay/wanted",params(("id"=Uuid,Path)),security(("connector_key"=[])),responses((status=200,description="Other members' open requests this pane may answer from its copy; the requester is not named",body=Value)))]
async fn relay_wanted(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: Connector,
) -> Result<Json<Value>, ApiError> {
    let (mut tx, _) = relay_tx(&s, &c, id).await?;
    let items: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('id',id,'kind',kind,'hash',encode(subject,'hex'),'recipient_key',recipient_key) from ledger_relay where document_id=$1 and requested_by<>$2 and served_at is null order by created_at limit 200")
        .bind(id)
        .bind(c.auth.identity_id)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"wanted":items})))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct ServeInput {
    /// `plain` (the requester checks the hash) or `x25519-aes256gcm-v1` (reserved).
    encoding: String,
    /// The payload, base64. Never read by the server.
    data: String,
}
#[utoipa::path(post,path="/connector/documents/{id}/relay/{request}",params(("id"=Uuid,Path),("request"=Uuid,Path)),request_body=ServeInput,security(("connector_key"=[])),responses((status=200,description="Held until the requester downloads it, at most an hour",body=Value),(status=400,description="Too large, or the document's relay space is full"),(status=403,description="Your own request"),(status=404,description="Answered, expired or not in this document")))]
async fn relay_serve(
    State(s): State<AppState>,
    Path((id, request)): Path<(Uuid, Uuid)>,
    c: Connector,
    Json(p): Json<ServeInput>,
) -> Result<Json<Value>, ApiError> {
    if !["plain", "x25519-aes256gcm-v1"].contains(&p.encoding.as_str()) {
        return Err(bad("Use the plain or x25519-aes256gcm-v1 encoding"));
    }
    if p.data.len() > RELAY_BODY_MAX {
        return Err(bad("This answer is larger than the relay carries"));
    }
    let bytes = STANDARD
        .decode(p.data.as_bytes())
        .map_err(|_| bad("Send the payload as base64"))?;
    if bytes.is_empty() {
        return Err(bad("Send the payload as base64"));
    }
    let (mut tx, keyed) = relay_tx(&s, &c, id).await?;
    // HPKE: a 32-byte encapsulated key and a 16-byte tag at least.
    if keyed && (p.encoding != engine_core::e2ee::relay::ENCODING || bytes.len() < 48) {
        return Err(bad(
            "In an encrypted project, answer sealed to the requester's key (x25519-aes256gcm-v1)",
        ));
    }
    // One answer at a time per document, so concurrent answers cannot both pass the quota.
    sqlx::query("select pg_advisory_xact_lock(hashtextextended('ledger_relay:' || $1::text, 0))")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let (kind, requester, subject): (String, Uuid, String) = sqlx::query_as("select kind,requested_by,encode(subject,'hex') from ledger_relay where id=$1 and document_id=$2 and served_at is null for update")
        .bind(request)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    if requester == c.auth.identity_id {
        return Err(ApiError::Forbidden);
    }
    if kind == "state" {
        // A block an agent asked for (decision 040): kept, content-addressed, only if it hashes
        // to the block hash asked for; never in an encrypted project (its hashes are keyed).
        if keyed || p.encoding != "plain" || bytes.len() > RELAY_BLOCK_MAX {
            return Err(bad("Send a block state as plain JSON, up to 2 MiB"));
        }
        let fields = state_answer(&subject, &bytes)
            .ok_or_else(|| bad("This block state does not hash to the block asked for"))?;
        sqlx::query("insert into ledger_block_state(document_id,block_hash,fields) values($1,decode($2,'hex'),$3) on conflict do nothing")
            .bind(id)
            .bind(&subject)
            .bind(&fields)
            .execute(&mut *tx)
            .await?;
        sqlx::query("delete from ledger_relay where document_id=$1 and kind='state' and subject=decode($2,'hex')")
            .bind(id)
            .bind(&subject)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(Json(json!({"served":true,"kept":true})));
    }
    let cap = if kind == "block" {
        RELAY_BLOCK_MAX
    } else {
        RELAY_MEDIA_MAX
    };
    if bytes.len() > cap {
        return Err(bad("This answer is larger than the relay carries"));
    }
    let held: i64 = sqlx::query_scalar(
        "select coalesce(sum(octet_length(payload)),0)::bigint from ledger_relay where document_id=$1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if held + bytes.len() as i64 > RELAY_QUOTA {
        return Err(bad(
            "The relay for this document is full; try again once teammates have downloaded their answers",
        ));
    }
    sqlx::query("update ledger_relay set payload=$2,encoding=$3,served_by=$4,served_at=now(),expires_at=now()+interval '1 hour' where id=$1")
        .bind(request)
        .bind(&bytes)
        .bind(&p.encoding)
        .bind(c.auth.identity_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"served":true})))
}

#[utoipa::path(get,path="/connector/documents/{id}/relay/{request}",params(("id"=Uuid,Path),("request"=Uuid,Path)),security(("connector_key"=[])),responses((status=200,description="The answer, deleted from the server by this download; or waiting",body=Value),(status=404,description="Not your request, expired or already downloaded")))]
async fn relay_take(
    State(s): State<AppState>,
    Path((id, request)): Path<(Uuid, Uuid)>,
    c: Connector,
) -> Result<Json<Value>, ApiError> {
    let (mut tx, _) = relay_tx(&s, &c, id).await?;
    let row: (String, String, Option<Vec<u8>>, Option<String>) = sqlx::query_as("select kind,encode(subject,'hex'),payload,encoding from ledger_relay where id=$1 and document_id=$2 and requested_by=$3 for update")
        .bind(request)
        .bind(id)
        .bind(c.auth.identity_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let (kind, hash, payload, encoding) = row;
    let Some(payload) = payload else {
        return Ok(Json(json!({"waiting":true,"kind":kind,"hash":hash})));
    };
    sqlx::query("delete from ledger_relay where id=$1")
        .bind(request)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"kind":kind,"hash":hash,"encoding":encoding,"data":STANDARD.encode(payload)}),
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        storage_get,
        storage_set,
        project_storage_get,
        project_storage_set,
        connector_storage,
        manifest,
        relay_ask,
        relay_wanted,
        relay_serve,
        relay_take
    ),
    components(schemas(StorageInput, AskInput, ServeInput))
)]
pub struct LedgerApi;

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::materializer::MaterializedNode;
    use engine_shared::NodeId;

    fn node(id: &str, parent: Option<&str>, pos: &str, fields: Value) -> MaterializedNode {
        MaterializedNode {
            id: NodeId(id.into()),
            parent_id: parent.map(|p| NodeId(p.into())),
            node_type: if parent.is_some() { "item" } else { "form" }.into(),
            pos: pos.into(),
            current_fields: fields,
            var_name: None,
            deleted: false,
        }
    }
    fn state(nodes: Vec<MaterializedNode>) -> DocumentState {
        DocumentState {
            nodes: nodes.into_iter().map(|n| (n.id.clone(), n)).collect(),
            ..Default::default()
        }
    }
    const H: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn the_merkle_root_matches_the_sdk_vector() {
        assert_eq!(
            root(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let s = state(vec![
            node("R", None, "0", json!({"label":"Doc"})),
            node("A", Some("R"), "B", json!({"block_hash":H})),
            node("B", Some("R"), "C", json!({"block_hash":H,"content":"x"})),
            node("C", Some("R"), "D", json!({})),
        ]);
        let e = entries(&s);
        assert_eq!(e.len(), 3, "the root is not a block");
        assert_eq!(e[2][3], "", "a block without a hash has an empty leaf hash");
        // Same value as `manifestRoot` in the SDK's ledger.test.ts.
        assert_eq!(root(&e), SDK_VECTOR);
    }
    const SDK_VECTOR: &str = "4236928185ec94dd918289c53ca4da78558ebe9cc3cee86b8bbe83d3c768b006";

    #[test]
    fn the_first_ledger_commit_records_hashes_only_and_later_blocks_carry_hashes() {
        let empty = state(vec![node("R", None, "0", json!({}))]);
        let create = |fields: Value| EventPayload::NodeCreated {
            node_id: NodeId("A".into()),
            node_type: engine_shared::NodeType::Item,
            parent_id: Some(NodeId("R".into())),
            pos: "B".into(),
            fields,
            var_name: None,
        };
        assert!(check_ops(&empty, &empty, &[create(json!({"block_hash":H}))], false).is_ok());
        assert!(check_ops(
            &empty,
            &empty,
            &[create(json!({"block_hash":H,"content":"x"}))],
            false
        )
        .is_err());
        assert!(check_ops(&empty, &empty, &[create(json!({"content":"x"}))], false).is_err());
        let started = state(vec![
            node("R", None, "0", json!({})),
            node("A", Some("R"), "B", json!({"block_hash":H})),
        ]);
        assert!(check_ops(
            &started,
            &started,
            &[create(json!({"block_hash":H}))],
            false
        )
        .is_err());
        assert!(check_ops(
            &started,
            &started,
            &[create(json!({"block_hash":H,"content":"x"}))],
            false
        )
        .is_ok());
        let edit = |field: &str, value: Value| EventPayload::FieldEdited {
            node_id: NodeId("A".into()),
            field: field.into(),
            value,
        };
        assert!(check_ops(&started, &started, &[edit("content", json!("y"))], false).is_err());
        assert!(check_ops(
            &started,
            &started,
            &[edit("content", json!("y")), edit("block_hash", json!(H))],
            false
        )
        .is_ok());
        assert!(check_ops(
            &started,
            &started,
            &[
                edit("content", json!("y")),
                edit("block_hash", json!("ABC"))
            ],
            false
        )
        .is_err());
        assert!(check_ops(&empty, &empty, &[edit("block_hash", json!(H))], false).is_err());
        // A stale base cannot record a second set of hash-only blocks after the first commit.
        assert!(check_ops(&empty, &started, &[create(json!({"block_hash":H}))], false).is_err());
    }

    #[test]
    fn a_keyed_ledger_block_carries_only_its_hash_and_sealed_content() {
        use engine_core::e2ee::{commit, keys, seal};
        let started = state(vec![
            node("R", None, "0", json!({})),
            node("A", Some("R"), "B", json!({"block_hash":H})),
        ]);
        let root = keys::Key::from_bytes([4; 32]);
        let ctx = seal::Context {
            project: Uuid::nil(),
            document: Some(Uuid::from_u128(1)),
            node: "B",
            kind: seal::Kind::NodeFields,
            epoch: 1,
            revision: 1,
        };
        let sealed = commit::encode(
            &seal::seal(
                &keys::doc_key(&root, Uuid::nil(), Uuid::from_u128(1)).unwrap(),
                keys::key_id(1, &root),
                &keys::cid_key(&root).unwrap(),
                &ctx,
                &[],
                &json!({"content":"secret"}),
            )
            .unwrap(),
        );
        let create = |fields: Value| EventPayload::NodeCreated {
            node_id: NodeId("B".into()),
            node_type: engine_shared::NodeType::Item,
            parent_id: Some(NodeId("R".into())),
            pos: "C".into(),
            fields,
            var_name: None,
        };
        assert!(check_ops(
            &started,
            &started,
            &[create(json!({"block_hash":H,"sealed":sealed}))],
            true
        )
        .is_ok());
        // Plaintext content, or an envelope that is not a sealed node-fields object, is refused.
        assert!(check_ops(
            &started,
            &started,
            &[create(json!({"block_hash":H,"content":"secret"}))],
            true
        )
        .is_err());
        assert!(check_ops(
            &started,
            &started,
            &[create(json!({"block_hash":H,"sealed":"bm90IHNlYWxlZA"}))],
            true
        )
        .is_err());
        let edit = |field: &str, value: Value| EventPayload::FieldEdited {
            node_id: NodeId("A".into()),
            field: field.into(),
            value,
        };
        assert!(check_ops(
            &started,
            &started,
            &[edit("sealed", json!(sealed)), edit("block_hash", json!(H))],
            true
        )
        .is_ok());
        assert!(check_ops(
            &started,
            &started,
            &[edit("content", json!("x")), edit("block_hash", json!(H))],
            true
        )
        .is_err());
        // The same plaintext edit is fine for a plain ledger document.
        assert!(check_ops(
            &started,
            &started,
            &[edit("content", json!("x")), edit("block_hash", json!(H))],
            false
        )
        .is_ok());
    }

    #[test]
    fn the_block_hash_matches_the_sdk_vector() {
        let fields = json!({
            "label": "x",
            "content": {"type":"paragraph","content":[{"type":"text","text":"Ünïcode \"q\" \\ \n\t\u{1} 中文 €"}]},
            "x": 10.5, "n": 3, "ok": true, "none": null,
            "block_hash": "f".repeat(64)
        });
        // Same value as `fieldsHash` in the SDK's ledger.test.ts.
        assert_eq!(
            fields_hash(&fields),
            "0b07132c03e800ec6b19998f80b141eccede945bbd757da3d5dcb77ced9ecc80"
        );
    }

    #[test]
    fn agents_change_only_blocks_whose_full_state_the_server_holds() {
        let full = |text: &str| {
            let mut f = json!({"content":{"type":"paragraph","content":[{"type":"text","text":text}]},"label":text,"native":{"host":"word","xml":"<w:p/>"}});
            f["block_hash"] = json!(fields_hash(&f));
            f
        };
        let s = state(vec![
            node("R", None, "0", json!({})),
            node("A", Some("R"), "B", full("Kept by the server")),
            node("B", Some("R"), "C", json!({"block_hash":H})),
        ]);
        let edit = |id: &str, field: &str, value: Value| EventPayload::FieldEdited {
            node_id: NodeId(id.into()),
            field: field.into(),
            value,
        };
        // A hash-only block: the server cannot build its full state.
        let none = BTreeSet::new();
        assert!(agent_ops(&s, true, &[edit("B", "label", json!("x"))], &none).is_err());
        // A block the server holds: its new hash covers the new text, without the stale host form.
        let ops = agent_ops(
            &s,
            true,
            &[
                edit("A", "content", json!({"type":"paragraph"})),
                edit("A", "label", json!("")),
            ],
            &none,
        )
        .unwrap();
        let mut after = s.clone();
        for op in &ops {
            engine_core::materializer::apply_payload(&mut after, op).unwrap();
        }
        let a = &after.nodes[&NodeId("A".into())].current_fields;
        assert!(
            a["native"].is_null(),
            "the host form no longer matches the text"
        );
        assert!(verified(a));
        // A new block, and moves and deletes, need no baseline.
        let created = agent_ops(
            &s,
            false,
            &[
                EventPayload::NodeCreated {
                    node_id: NodeId("N".into()),
                    node_type: engine_shared::NodeType::Item,
                    parent_id: Some(NodeId("R".into())),
                    pos: "D".into(),
                    fields: json!({"cell_0":"1"}),
                    var_name: None,
                },
                EventPayload::NodeDeleted {
                    node_id: NodeId("B".into()),
                },
            ],
            &none,
        )
        .unwrap();
        let mut after = s.clone();
        for op in &created {
            engine_core::materializer::apply_payload(&mut after, op).unwrap();
        }
        assert!(verified(&after.nodes[&NodeId("N".into())].current_fields));
        assert_eq!(created.len(), 3, "one hash, for the new block only");
    }

    #[test]
    fn a_block_state_from_a_pane_is_kept_only_if_it_hashes_to_the_block() {
        let fields = json!({"content":"Synthetic paragraph","label":"Synthetic"});
        let hash = fields_hash(&fields);
        let sent = |v: &Value| serde_json::to_vec(v).unwrap();
        assert_eq!(state_answer(&hash, &sent(&fields)), Some(fields.clone()));
        // The block hash a pane may include is not part of the state.
        let with_hash =
            json!({"content":"Synthetic paragraph","label":"Synthetic","block_hash":hash});
        assert_eq!(state_answer(&hash, &sent(&with_hash)), Some(fields.clone()));
        // Other content under the same hash, sealed content, or not an object: refused.
        assert!(state_answer(
            &hash,
            &sent(&json!({"content":"Other","label":"Synthetic"}))
        )
        .is_none());
        assert!(state_answer(&hash, &sent(&json!({"sealed":"x"}))).is_none());
        assert!(state_answer(&hash, b"[1,2]").is_none());
        assert!(state_answer(&hash, b"not json").is_none());
    }

    #[test]
    fn an_agent_change_to_a_held_block_resends_its_whole_state() {
        let held_fields =
            json!({"content":"Synthetic text","label":"Synthetic text","native":{"host":"word"}});
        let hash = fields_hash(&held_fields);
        let mut s = state(vec![
            node("R", None, "0", json!({"label":"Doc"})),
            node("B", Some("R"), "C", json!({"block_hash":hash})),
        ]);
        let edit = EventPayload::FieldEdited {
            node_id: NodeId("B".into()),
            field: "label".into(),
            value: json!("New label"),
        };
        assert_eq!(unheld(&s, std::slice::from_ref(&edit)), vec![hash.clone()]);
        let mut f = held_fields.clone();
        f["block_hash"] = json!(hash);
        let filled = fill(&mut s, vec![(NodeId("B".into()), f)]);
        assert!(unheld(&s, std::slice::from_ref(&edit)).is_empty());
        let ops = agent_ops(&s, false, &[edit], &filled).unwrap();
        // The server's own state is the hash alone: replaying the ops on it gives the block whole.
        let mut server = state(vec![
            node("R", None, "0", json!({"label":"Doc"})),
            node("B", Some("R"), "C", json!({"block_hash":hash})),
        ]);
        for op in &ops {
            engine_core::materializer::apply_payload(&mut server, op).unwrap();
        }
        let b = &server.nodes[&NodeId("B".into())].current_fields;
        assert_eq!(b["label"], "New label");
        assert_eq!(b["content"], "Synthetic text");
        assert!(verified(b));
    }
}
