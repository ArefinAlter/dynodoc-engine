//! V2 typed checkpoints. Stable IDs index immutable values; large strings use
//! content trees. All budgets apply across the complete graph, including reused
//! references. See docs/TYPED-CHECKPOINTS.md for the wire contract and limits.

use std::{
    collections::BTreeMap,
    pin::Pin,
    task::{Context, Poll},
};

use engine_shared::{DocumentId, NodeId};
use ring::digest::{Context as HashContext, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::AsyncWrite;

use super::{
    content, Address, Entry, Error, Limits, ObjectStore, Reader, StateRoots, WriteStats, Writer,
};
use crate::materializer::{CommentState, DocumentState, MaterializedNode, SuggestionState};

pub(super) const MAGIC: &[u8] = b"DYNOTYP\0\x02";
const DOMAIN: &[u8] = b"dynodoc.typed-checkpoint\0v2\0";
pub(super) const MAGIC_V3: &[u8] = b"DYNOTYP\0\x03";
const DOMAIN_V3: &[u8] = b"dynodoc.typed-checkpoint\0v3\0";
pub const MAX_KEY_BYTES: usize = 1024;
pub const MAX_METADATA_BYTES: usize = 4096;
const MAX_TYPED_BYTES: usize = 32 * 1024;
pub const MAX_DEPTH: usize = 64;

/// Semantic budgets bound reconstruction, independently of encoded object size.
/// This is a finite materialization bound, not constant-space DocumentState.
#[derive(Clone, Copy, Debug)]
pub struct SemanticLimits {
    pub values: usize,
    pub string_bytes: usize,
    pub depth: usize,
}

impl Default for SemanticLimits {
    fn default() -> Self {
        Self {
            values: 1_000_000,
            string_bytes: 256 * 1024 * 1024,
            depth: MAX_DEPTH,
        }
    }
}

impl SemanticLimits {
    fn value(&mut self, depth: usize) -> Result<(), Error> {
        if depth > self.depth.min(MAX_DEPTH) {
            return Err(Error::Limit("semantic depth"));
        }
        self.values = self
            .values
            .checked_sub(1)
            .ok_or(Error::Limit("semantic values"))?;
        Ok(())
    }
    fn bytes(&mut self, n: usize) -> Result<(), Error> {
        self.string_bytes = self
            .string_bytes
            .checked_sub(n)
            .ok_or(Error::Limit("semantic string bytes"))?;
        Ok(())
    }
    fn metadata(&mut self, value: &str) -> Result<(), Error> {
        if value.len() > MAX_METADATA_BYTES {
            return Err(Error::Limit("metadata bytes"));
        }
        self.bytes(value.len())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Text {
    pub root: Address,
    pub bytes: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Object {
    Scalar(Value),
    Text(Text),
    Array {
        entries: Address,
        count: usize,
    },
    Dictionary {
        entries: Address,
        count: usize,
    },
    Node {
        id: NodeId,
        parent_id: Option<NodeId>,
        node_type: String,
        pos: String,
        var_name: Option<String>,
        deleted: bool,
        fields: Address,
    },
    Comment {
        node_id: Option<NodeId>,
        body: Text,
    },
    Suggestion {
        target_node_id: Option<NodeId>,
        detail: Address,
        accepted: bool,
        rejected_reason: Option<Text>,
    },
    RemovedChoice(NodeId),
    State(StateRoots),
    Asset {
        media_type: String,
        content: Text,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum ObjectV3 {
    Scalar(Value),
    Text(Text),
    Array {
        entries: Address,
        count: usize,
    },
    Dictionary {
        entries: Address,
        count: usize,
    },
    Node {
        parent_id: Option<NodeId>,
        node_type: String,
        pos: String,
        var_name: Option<String>,
        deleted: bool,
        fields: Address,
        restore_block_id: bool,
        restore_label: bool,
    },
    Comment {
        node_id: Option<NodeId>,
        body: Text,
    },
    Suggestion {
        target_node_id: Option<NodeId>,
        detail: Address,
        accepted: bool,
        rejected_reason: Option<Text>,
    },
    RemovedChoice(NodeId),
    State(StateRoots),
    Asset {
        media_type: String,
        content: Text,
    },
}

fn address(bytes: &[u8]) -> Address {
    let mut hash = HashContext::new(&SHA256);
    hash.update(DOMAIN);
    hash.update(bytes);
    Address(super::hex(hash.finish().as_ref()))
}

fn encode(object: &Object) -> Result<(Address, Vec<u8>), Error> {
    let mut bytes = MAGIC.to_vec();
    let value = serde_json::to_value(object)?;
    serde_json::to_writer(&mut bytes, &super::canonical::CanonicalValue(&value))?;
    if bytes.len() > MAX_TYPED_BYTES {
        return Err(Error::Limit("typed object bytes"));
    }
    Ok((address(&bytes), bytes))
}

fn decode(expected: &Address, bytes: &[u8]) -> Result<Object, Error> {
    if bytes.len() > MAX_TYPED_BYTES {
        return Err(Error::Limit("typed object bytes"));
    }
    if !bytes.starts_with(MAGIC) {
        return Err(Error::Invalid("typed header/version"));
    }
    if address(bytes) != *expected {
        return Err(Error::HashMismatch);
    }
    let object: Object = serde_json::from_slice(&bytes[MAGIC.len()..])?;
    // Scalars cannot smuggle nested JSON past semantic traversal or allocate a
    // large output through one reference. Canonicalization rejects duplicate keys.
    if matches!(
        &object,
        Object::Scalar(Value::Array(_) | Value::Object(_) | Value::String(_))
    ) {
        return Err(Error::Invalid("expected primitive scalar"));
    }
    if encode(&object)?.1 != bytes {
        return Err(Error::Invalid("noncanonical typed object"));
    }
    Ok(object)
}

pub(super) fn validate(expected: &Address, bytes: &[u8]) -> Result<(), Error> {
    decode(expected, bytes).map(|_| ())
}

/// Direct child addresses of a verified typed object (see `super::references`).
pub(super) fn references(expected: &Address, bytes: &[u8]) -> Result<Vec<Address>, Error> {
    Ok(match decode(expected, bytes)? {
        Object::Scalar(_) | Object::RemovedChoice(_) => Vec::new(),
        Object::Text(text) => vec![text.root],
        Object::Array { entries, .. } | Object::Dictionary { entries, .. } => vec![entries],
        Object::Node { fields, .. } => vec![fields],
        Object::Comment { body, .. } => vec![body.root],
        Object::Suggestion {
            detail,
            rejected_reason,
            ..
        } => std::iter::once(detail)
            .chain(rejected_reason.map(|reason| reason.root))
            .collect(),
        Object::State(roots) => roots.addresses(),
        Object::Asset { content, .. } => vec![content.root],
    })
}

pub fn address_v3(bytes: &[u8]) -> Address {
    let mut hash = HashContext::new(&SHA256);
    hash.update(DOMAIN_V3);
    hash.update(bytes);
    Address(super::hex(hash.finish().as_ref()))
}

pub(crate) fn encode_v3(object: &ObjectV3) -> Result<(Address, Vec<u8>), Error> {
    let mut bytes = MAGIC_V3.to_vec();
    let value = serde_json::to_value(object)?;
    serde_json::to_writer(&mut bytes, &super::canonical::CanonicalValue(&value))?;
    if bytes.len() > MAX_TYPED_BYTES {
        return Err(Error::Limit("typed object bytes"));
    }
    Ok((address_v3(&bytes), bytes))
}

pub(crate) fn decode_v3(expected: &Address, bytes: &[u8]) -> Result<ObjectV3, Error> {
    if bytes.len() > MAX_TYPED_BYTES {
        return Err(Error::Limit("typed object bytes"));
    }
    if !bytes.starts_with(MAGIC_V3) {
        return Err(Error::Invalid("typed header/version"));
    }
    if address_v3(bytes) != *expected {
        return Err(Error::HashMismatch);
    }
    let object: ObjectV3 = serde_json::from_slice(&bytes[MAGIC_V3.len()..])?;
    if matches!(
        &object,
        ObjectV3::Scalar(Value::Array(_) | Value::Object(_) | Value::String(_))
    ) {
        return Err(Error::Invalid("expected primitive scalar"));
    }
    if encode_v3(&object)?.1 != bytes {
        return Err(Error::Invalid("noncanonical typed object"));
    }
    Ok(object)
}

pub(super) fn validate_v3(expected: &Address, bytes: &[u8]) -> Result<(), Error> {
    decode_v3(expected, bytes).map(|_| ())
}

pub(super) fn references_v3(expected: &Address, bytes: &[u8]) -> Result<Vec<Address>, Error> {
    Ok(match decode_v3(expected, bytes)? {
        ObjectV3::Scalar(_) | ObjectV3::RemovedChoice(_) => Vec::new(),
        ObjectV3::Text(text) => vec![text.root],
        ObjectV3::Array { entries, .. } | ObjectV3::Dictionary { entries, .. } => vec![entries],
        ObjectV3::Node { fields, .. } => vec![fields],
        ObjectV3::Comment { body, .. } => vec![body.root],
        ObjectV3::Suggestion {
            detail,
            rejected_reason,
            ..
        } => std::iter::once(detail)
            .chain(rejected_reason.map(|reason| reason.root))
            .collect(),
        ObjectV3::State(roots) => roots.addresses(),
        ObjectV3::Asset { content, .. } => vec![content.root],
    })
}

struct Encoder<'a, S> {
    writer: Writer<'a, S>,
    semantic: SemanticLimits,
}
impl<S: ObjectStore> Encoder<'_, S> {
    async fn object(&mut self, object: Object) -> Result<Address, Error> {
        let (address, bytes) = encode(&object)?;
        self.writer.encoded(address, bytes).await
    }
    async fn text(&mut self, text: &[u8]) -> Result<Text, Error> {
        self.semantic.bytes(text.len())?;
        let root = content::write_with_writer(&mut self.writer, &mut &*text).await?;
        Ok(Text {
            root,
            bytes: text.len(),
        })
    }
    async fn value(&mut self, value: &Value, depth: usize) -> Result<Address, Error> {
        self.semantic.value(depth)?;
        let object = match value {
            Value::String(text) => Object::Text(self.text(text.as_bytes()).await?),
            Value::Array(values) => {
                if values.len() > self.semantic.values {
                    return Err(Error::Limit("semantic values"));
                }
                let mut entries = Vec::new();
                for (i, value) in values.iter().enumerate() {
                    let key = format!("{i:016x}");
                    let address = Box::pin(self.value(value, depth + 1)).await?;
                    entries.push((super::route(&key), Entry { key, address }));
                }
                Object::Array {
                    entries: self.writer.entries(entries).await?,
                    count: values.len(),
                }
            }
            Value::Object(values) => {
                if values.len() > self.semantic.values {
                    return Err(Error::Limit("semantic values"));
                }
                let mut entries = Vec::new();
                // Sorting is bounded by the remaining value budget; preserve_order
                // feature unification must not alter the object address.
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_unstable();
                for key in keys {
                    if key.len() > MAX_KEY_BYTES {
                        return Err(Error::Limit("property key bytes"));
                    }
                    self.semantic.bytes(key.len())?;
                    let address = Box::pin(self.value(&values[key], depth + 1)).await?;
                    entries.push((
                        super::route(key),
                        Entry {
                            key: key.clone(),
                            address,
                        },
                    ));
                }
                Object::Dictionary {
                    entries: self.writer.entries(entries).await?,
                    count: values.len(),
                }
            }
            value => Object::Scalar(value.clone()),
        };
        self.object(object).await
    }

    async fn read_object(&mut self, address: &Address) -> Result<Object, Error> {
        if self.writer.budget.max_objects == 0 {
            return Err(Error::Limit("objects"));
        }
        let bytes = if let Some((_, b)) = self.writer.pending.iter().find(|(a, _)| a == address) {
            self.writer.budget.consume(b.len())?;
            b.clone()
        } else {
            let b = self.writer.store.get(self.writer.document, address).await?;
            self.writer.budget.consume(b.len())?;
            b
        };
        decode(address, &bytes)
    }
}

fn charge_value(semantic: &mut SemanticLimits, value: &Value, depth: usize) -> Result<(), Error> {
    semantic.value(depth)?;
    match value {
        Value::String(text) => {
            semantic.bytes(text.len())?;
        }
        Value::Array(values) => {
            if values.len() > semantic.values {
                return Err(Error::Limit("semantic values"));
            }
            for value in values {
                charge_value(semantic, value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            if values.len() > semantic.values {
                return Err(Error::Limit("semantic values"));
            }
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for key in keys {
                if key.len() > MAX_KEY_BYTES {
                    return Err(Error::Limit("property key bytes"));
                }
                semantic.bytes(key.len())?;
                charge_value(semantic, &values[key], depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn node_metadata(limits: &mut SemanticLimits, node: &MaterializedNode) -> Result<(), Error> {
    for text in [&node.id.0, &node.node_type, &node.pos]
        .into_iter()
        .chain(node.parent_id.as_ref().map(|v| &v.0))
        .chain(node.var_name.as_ref())
    {
        limits.metadata(text)?;
    }
    Ok(())
}

fn charge_node_fields_v3(
    semantic: &mut SemanticLimits,
    id: &NodeId,
    current_fields: &Value,
) -> Result<(), Error> {
    match current_fields {
        Value::Object(map) => {
            let restore_block_id =
                matches!(map.get("blockId"), Some(Value::String(b)) if b == &id.0);
            let restore_label = matches!(
                (map.get("content"), map.get("label")),
                (Some(content), Some(Value::String(l)))
                    if !content.is_null() && l == &crate::richtext::plain_text(content)
            );

            if !restore_block_id && !restore_label {
                charge_value(semantic, current_fields, 0)?;
            } else {
                let mut keys: Vec<_> = map
                    .keys()
                    .filter(|&k| {
                        !(restore_block_id && k == "blockId" || restore_label && k == "label")
                    })
                    .collect();
                keys.sort_unstable();

                if keys.len() > semantic.values {
                    return Err(Error::Limit("semantic values"));
                }
                for key in keys {
                    if key.len() > MAX_KEY_BYTES {
                        return Err(Error::Limit("property key bytes"));
                    }
                    semantic.bytes(key.len())?;
                    charge_value(semantic, &map[key], 1)?;
                }
            }
        }
        _ => {
            charge_value(semantic, current_fields, 0)?;
        }
    }
    Ok(())
}

/// Write a typed state graph; the caller owns authorization and atomic publication.
pub async fn write_state<S: ObjectStore>(
    store: &mut S,
    document: DocumentId,
    state: &DocumentState,
    limits: Limits,
    semantic: SemanticLimits,
) -> Result<(Address, WriteStats), Error> {
    let mut encoder = Encoder {
        writer: Writer {
            store,
            document,
            budget: limits,
            stats: WriteStats::default(),
            pending: Vec::new(),
            pending_bytes: 0,
        },
        semantic,
    };
    let mut entries = Vec::new();
    for (id, node) in &state.nodes {
        encoder.semantic.value(0)?;
        if id != &node.id {
            return Err(Error::Invalid("node map key differs from logical id"));
        }
        node_metadata(&mut encoder.semantic, node)?;
        let fields = encoder.value(&node.current_fields, 0).await?;
        let address = encoder
            .object(Object::Node {
                id: id.clone(),
                parent_id: node.parent_id.clone(),
                node_type: node.node_type.clone(),
                pos: node.pos.clone(),
                var_name: node.var_name.clone(),
                deleted: node.deleted,
                fields,
            })
            .await?;
        entries.push((
            super::route(&id.0),
            Entry {
                key: id.0.clone(),
                address,
            },
        ));
    }
    let nodes = encoder.writer.entries(entries).await?;
    let mut entries = Vec::new();
    for (i, comment) in state.comments.iter().enumerate() {
        encoder.semantic.value(0)?;
        if let Some(id) = &comment.node_id {
            encoder.semantic.metadata(&id.0)?;
        }
        let body = encoder.text(comment.body.as_bytes()).await?;
        let address = encoder
            .object(Object::Comment {
                node_id: comment.node_id.clone(),
                body,
            })
            .await?;
        let key = format!("{i:016x}");
        entries.push((super::route(&key), Entry { key, address }));
    }
    let comments = encoder.writer.entries(entries).await?;
    let mut entries = Vec::new();
    for (key, suggestion) in &state.suggestions {
        encoder.semantic.value(0)?;
        encoder.semantic.metadata(key)?;
        if let Some(id) = &suggestion.target_node_id {
            encoder.semantic.metadata(&id.0)?;
        }
        let detail = encoder.value(&suggestion.detail, 0).await?;
        let rejected_reason = match &suggestion.rejected_reason {
            Some(reason) => Some(encoder.text(reason.as_bytes()).await?),
            None => None,
        };
        let address = encoder
            .object(Object::Suggestion {
                target_node_id: suggestion.target_node_id.clone(),
                detail,
                accepted: suggestion.accepted,
                rejected_reason,
            })
            .await?;
        entries.push((
            super::route(key),
            Entry {
                key: key.clone(),
                address,
            },
        ));
    }
    let suggestions = encoder.writer.entries(entries).await?;
    let mut entries = Vec::new();
    if state.removed_choices.len() > encoder.semantic.values {
        return Err(Error::Limit("semantic values"));
    }
    let mut removed: Vec<_> = state.removed_choices.iter().collect();
    removed.sort();
    for id in removed {
        encoder.semantic.value(0)?;
        encoder.semantic.metadata(&id.0)?;
        let address = encoder.object(Object::RemovedChoice(id.clone())).await?;
        entries.push((
            super::route(&id.0),
            Entry {
                key: id.0.clone(),
                address,
            },
        ));
    }
    let removed_choices = encoder.writer.entries(entries).await?;
    let root = encoder
        .object(Object::State(StateRoots {
            nodes,
            comments,
            suggestions,
            removed_choices,
        }))
        .await?;
    encoder.writer.flush().await?;
    Ok((root, encoder.writer.stats))
}

fn is_integrity_error(err: &Error) -> bool {
    matches!(
        err,
        Error::HashMismatch
            | Error::Missing(_)
            | Error::Limit(_)
            | Error::Db(_)
            | Error::Io(_)
            | Error::History(_)
            | Error::Json(_)
            | Error::Invalid("typed header/version")
            | Error::Invalid("declared content length")
            | Error::Invalid("text UTF-8")
            | Error::Invalid("noncanonical typed object")
            | Error::Invalid("radix depth")
            | Error::Invalid("map key route or duplicate")
            | Error::Invalid("map entries or key bytes")
            | Error::Invalid("unnecessary map branch")
            | Error::Invalid("empty branch child")
    )
}

/// Incrementally update an already verified base state with a validated target state.
/// Reuses unchanged node and field objects without re-encoding, falling back to full
/// write_state on unsupported delta shapes or state-metadata inconsistencies.
/// Integrity errors (corruption, hash mismatches, missing objects, limit exhaustion) fail closed.
pub async fn update_state<S: ObjectStore>(
    store: &mut S,
    document: DocumentId,
    base_root: &Address,
    base_state: &DocumentState,
    target_state: &DocumentState,
    limits: Limits,
    semantic: SemanticLimits,
) -> Result<(Address, WriteStats), Error> {
    for (id, node) in &target_state.nodes {
        if id != &node.id {
            return Err(Error::Invalid("node map key differs from logical id"));
        }
    }

    match try_update_state(
        store,
        document,
        base_root,
        base_state,
        target_state,
        limits,
        semantic,
    )
    .await
    {
        Ok(res) => Ok(res),
        Err(err) if is_integrity_error(&err) => Err(err),
        Err(Error::Invalid("node map key differs from logical id")) => {
            Err(Error::Invalid("node map key differs from logical id"))
        }
        Err(_) => write_state(store, document, target_state, limits, semantic).await,
    }
}

async fn try_update_state<S: ObjectStore>(
    store: &mut S,
    document: DocumentId,
    base_root: &Address,
    base_state: &DocumentState,
    target_state: &DocumentState,
    limits: Limits,
    semantic: SemanticLimits,
) -> Result<(Address, WriteStats), Error> {
    let mut encoder = Encoder {
        writer: Writer {
            store,
            document,
            budget: limits,
            stats: WriteStats::default(),
            pending: Vec::new(),
            pending_bytes: 0,
        },
        semantic,
    };

    let base_obj = encoder.read_object(base_root).await?;
    let Object::State(base_roots) = base_obj else {
        return Err(Error::Invalid("expected typed state"));
    };

    // No-op check: enforce semantic budgets across all reachable items, write 0 objects
    if target_state == base_state {
        for (id, node) in &target_state.nodes {
            encoder.semantic.value(0)?;
            if id != &node.id {
                return Err(Error::Invalid("node map key differs from logical id"));
            }
            node_metadata(&mut encoder.semantic, node)?;
            charge_value(&mut encoder.semantic, &node.current_fields, 0)?;
        }
        for comment in &target_state.comments {
            encoder.semantic.value(0)?;
            if let Some(id) = &comment.node_id {
                encoder.semantic.metadata(&id.0)?;
            }
            encoder.semantic.bytes(comment.body.len())?;
        }
        for (key, suggestion) in &target_state.suggestions {
            encoder.semantic.value(0)?;
            encoder.semantic.metadata(key)?;
            if let Some(id) = &suggestion.target_node_id {
                encoder.semantic.metadata(&id.0)?;
            }
            charge_value(&mut encoder.semantic, &suggestion.detail, 0)?;
            if let Some(reason) = &suggestion.rejected_reason {
                encoder.semantic.bytes(reason.len())?;
            }
        }
        if target_state.removed_choices.len() > encoder.semantic.values {
            return Err(Error::Limit("semantic values"));
        }
        let mut removed: Vec<_> = target_state.removed_choices.iter().collect();
        removed.sort();
        for id in removed {
            encoder.semantic.value(0)?;
            encoder.semantic.metadata(&id.0)?;
        }
        return Ok((base_root.clone(), encoder.writer.stats));
    }

    // 1. Process nodes
    let mut node_edits: Vec<(String, Option<Address>)> = Vec::new();

    // Deleted nodes
    for id in base_state.nodes.keys() {
        if !target_state.nodes.contains_key(id) {
            node_edits.push((id.0.clone(), None));
        }
    }

    // Unchanged, modified, or added nodes
    for (id, node) in &target_state.nodes {
        encoder.semantic.value(0)?;
        if id != &node.id {
            return Err(Error::Invalid("node map key differs from logical id"));
        }
        node_metadata(&mut encoder.semantic, node)?;

        if let Some(base_node) = base_state.nodes.get(id) {
            if base_node == node {
                charge_value(&mut encoder.semantic, &node.current_fields, 0)?;
            } else {
                let fields = if base_node.current_fields == node.current_fields {
                    charge_value(&mut encoder.semantic, &node.current_fields, 0)?;
                    let old_node_addr = encoder
                        .writer
                        .lookup(&base_roots.nodes, &id.0)
                        .await?
                        .ok_or(Error::Invalid("base node missing from radix map"))?;
                    match encoder.read_object(&old_node_addr).await? {
                        Object::Node { fields, .. } => fields,
                        _ => return Err(Error::Invalid("expected typed node")),
                    }
                } else {
                    encoder.value(&node.current_fields, 0).await?
                };

                let addr = encoder
                    .object(Object::Node {
                        id: id.clone(),
                        parent_id: node.parent_id.clone(),
                        node_type: node.node_type.clone(),
                        pos: node.pos.clone(),
                        var_name: node.var_name.clone(),
                        deleted: node.deleted,
                        fields,
                    })
                    .await?;
                node_edits.push((id.0.clone(), Some(addr)));
            }
        } else {
            let fields = encoder.value(&node.current_fields, 0).await?;
            let addr = encoder
                .object(Object::Node {
                    id: id.clone(),
                    parent_id: node.parent_id.clone(),
                    node_type: node.node_type.clone(),
                    pos: node.pos.clone(),
                    var_name: node.var_name.clone(),
                    deleted: node.deleted,
                    fields,
                })
                .await?;
            node_edits.push((id.0.clone(), Some(addr)));
        }
    }

    let nodes = if node_edits.is_empty() {
        base_roots.nodes.clone()
    } else {
        encoder
            .writer
            .update_map(&base_roots.nodes, node_edits)
            .await?
    };

    // 2. Process comments
    let comments = if target_state.comments == base_state.comments {
        for comment in &target_state.comments {
            encoder.semantic.value(0)?;
            if let Some(id) = &comment.node_id {
                encoder.semantic.metadata(&id.0)?;
            }
            encoder.semantic.bytes(comment.body.len())?;
        }
        base_roots.comments.clone()
    } else {
        let mut comment_edits = Vec::new();
        let max_len = target_state.comments.len().max(base_state.comments.len());
        for i in 0..max_len {
            let key = format!("{i:016x}");
            match (target_state.comments.get(i), base_state.comments.get(i)) {
                (Some(target_c), Some(base_c)) => {
                    encoder.semantic.value(0)?;
                    if let Some(id) = &target_c.node_id {
                        encoder.semantic.metadata(&id.0)?;
                    }
                    if target_c == base_c {
                        encoder.semantic.bytes(target_c.body.len())?;
                    } else {
                        let body = encoder.text(target_c.body.as_bytes()).await?;
                        let addr = encoder
                            .object(Object::Comment {
                                node_id: target_c.node_id.clone(),
                                body,
                            })
                            .await?;
                        comment_edits.push((key, Some(addr)));
                    }
                }
                (Some(target_c), None) => {
                    encoder.semantic.value(0)?;
                    if let Some(id) = &target_c.node_id {
                        encoder.semantic.metadata(&id.0)?;
                    }
                    let body = encoder.text(target_c.body.as_bytes()).await?;
                    let addr = encoder
                        .object(Object::Comment {
                            node_id: target_c.node_id.clone(),
                            body,
                        })
                        .await?;
                    comment_edits.push((key, Some(addr)));
                }
                (None, Some(_)) => {
                    comment_edits.push((key, None));
                }
                (None, None) => unreachable!(),
            }
        }
        encoder
            .writer
            .update_map(&base_roots.comments, comment_edits)
            .await?
    };

    // 3. Process suggestions
    let suggestions = if target_state.suggestions == base_state.suggestions {
        for (key, suggestion) in &target_state.suggestions {
            encoder.semantic.value(0)?;
            encoder.semantic.metadata(key)?;
            if let Some(id) = &suggestion.target_node_id {
                encoder.semantic.metadata(&id.0)?;
            }
            charge_value(&mut encoder.semantic, &suggestion.detail, 0)?;
            if let Some(reason) = &suggestion.rejected_reason {
                encoder.semantic.bytes(reason.len())?;
            }
        }
        base_roots.suggestions.clone()
    } else {
        let mut sugg_edits = Vec::new();
        for key in base_state.suggestions.keys() {
            if !target_state.suggestions.contains_key(key) {
                sugg_edits.push((key.clone(), None));
            }
        }
        for (key, target_s) in &target_state.suggestions {
            encoder.semantic.value(0)?;
            encoder.semantic.metadata(key)?;
            if let Some(id) = &target_s.target_node_id {
                encoder.semantic.metadata(&id.0)?;
            }

            if let Some(base_s) = base_state.suggestions.get(key) {
                if base_s == target_s {
                    charge_value(&mut encoder.semantic, &target_s.detail, 0)?;
                    if let Some(reason) = &target_s.rejected_reason {
                        encoder.semantic.bytes(reason.len())?;
                    }
                } else {
                    let detail = if base_s.detail == target_s.detail {
                        charge_value(&mut encoder.semantic, &target_s.detail, 0)?;
                        let old_sugg_addr = encoder
                            .writer
                            .lookup(&base_roots.suggestions, key)
                            .await?
                            .ok_or(Error::Invalid("base suggestion missing from map"))?;
                        match encoder.read_object(&old_sugg_addr).await? {
                            Object::Suggestion { detail, .. } => detail,
                            _ => return Err(Error::Invalid("expected typed suggestion")),
                        }
                    } else {
                        encoder.value(&target_s.detail, 0).await?
                    };

                    let rejected_reason = match &target_s.rejected_reason {
                        Some(reason) => Some(encoder.text(reason.as_bytes()).await?),
                        None => None,
                    };
                    let addr = encoder
                        .object(Object::Suggestion {
                            target_node_id: target_s.target_node_id.clone(),
                            detail,
                            accepted: target_s.accepted,
                            rejected_reason,
                        })
                        .await?;
                    sugg_edits.push((key.clone(), Some(addr)));
                }
            } else {
                let detail = encoder.value(&target_s.detail, 0).await?;
                let rejected_reason = match &target_s.rejected_reason {
                    Some(reason) => Some(encoder.text(reason.as_bytes()).await?),
                    None => None,
                };
                let addr = encoder
                    .object(Object::Suggestion {
                        target_node_id: target_s.target_node_id.clone(),
                        detail,
                        accepted: target_s.accepted,
                        rejected_reason,
                    })
                    .await?;
                sugg_edits.push((key.clone(), Some(addr)));
            }
        }
        encoder
            .writer
            .update_map(&base_roots.suggestions, sugg_edits)
            .await?
    };

    // 4. Process removed_choices
    let removed_choices = if target_state.removed_choices == base_state.removed_choices {
        if target_state.removed_choices.len() > encoder.semantic.values {
            return Err(Error::Limit("semantic values"));
        }
        let mut removed: Vec<_> = target_state.removed_choices.iter().collect();
        removed.sort();
        for id in removed {
            encoder.semantic.value(0)?;
            encoder.semantic.metadata(&id.0)?;
        }
        base_roots.removed_choices.clone()
    } else {
        if target_state.removed_choices.len() > encoder.semantic.values {
            return Err(Error::Limit("semantic values"));
        }
        let mut rc_edits = Vec::new();
        for id in &base_state.removed_choices {
            if !target_state.removed_choices.contains(id) {
                rc_edits.push((id.0.clone(), None));
            }
        }
        let mut removed: Vec<_> = target_state.removed_choices.iter().collect();
        removed.sort();
        for id in removed {
            encoder.semantic.value(0)?;
            encoder.semantic.metadata(&id.0)?;
            if !base_state.removed_choices.contains(id) {
                let addr = encoder.object(Object::RemovedChoice(id.clone())).await?;
                rc_edits.push((id.0.clone(), Some(addr)));
            }
        }
        encoder
            .writer
            .update_map(&base_roots.removed_choices, rc_edits)
            .await?
    };

    if nodes == base_roots.nodes
        && comments == base_roots.comments
        && suggestions == base_roots.suggestions
        && removed_choices == base_roots.removed_choices
    {
        encoder.writer.flush().await?;
        return Ok((base_root.clone(), encoder.writer.stats));
    }

    let root = encoder
        .object(Object::State(StateRoots {
            nodes,
            comments,
            suggestions,
            removed_choices,
        }))
        .await?;
    encoder.writer.flush().await?;
    Ok((root, encoder.writer.stats))
}

struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
}
impl AsyncWrite for BoundedBytes {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "content exceeds declared length",
            )));
        }
        self.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Decoder<'a, S> {
    reader: Reader<'a, S>,
    semantic: SemanticLimits,
}
impl<S: ObjectStore> Decoder<'_, S> {
    async fn object(&mut self, root: &Address) -> Result<Object, Error> {
        if self.reader.budget.max_objects == 0 {
            return Err(Error::Limit("objects"));
        }
        let bytes = self.reader.store.get(self.reader.document, root).await?;
        self.reader.budget.consume(bytes.len())?;
        decode(root, &bytes)
    }
    async fn bytes(&mut self, text: Text) -> Result<Vec<u8>, Error> {
        self.semantic.bytes(text.bytes)?;
        let mut sink = BoundedBytes {
            bytes: Vec::new(),
            limit: text.bytes,
        };
        let length = content::read_with_budget(
            self.reader.store,
            self.reader.document,
            &text.root,
            &mut sink,
            &mut self.reader.budget,
        )
        .await?;
        if length != text.bytes as u64 {
            return Err(Error::Invalid("declared content length"));
        }
        Ok(sink.bytes)
    }
    async fn text(&mut self, text: Text) -> Result<String, Error> {
        String::from_utf8(self.bytes(text).await?).map_err(|_| Error::Invalid("text UTF-8"))
    }
    async fn entries(
        &mut self,
        root: &Address,
        count: usize,
        key_limit: usize,
    ) -> Result<BTreeMap<String, Address>, Error> {
        if count > self.semantic.values {
            return Err(Error::Limit("semantic values"));
        }
        let entries = self.reader.entries_limited(root, count, key_limit).await?;
        if entries.len() != count {
            return Err(Error::Invalid("container count"));
        }
        Ok(entries)
    }
    async fn value(&mut self, root: &Address, depth: usize) -> Result<Value, Error> {
        self.semantic.value(depth)?;
        match self.object(root).await? {
            Object::Scalar(value) => Ok(value),
            Object::Text(text) => Ok(Value::String(self.text(text).await?)),
            Object::Array { entries, count } => {
                let entries = self.entries(&entries, count, 16).await?;
                let mut values = Vec::new();
                for (i, (key, root)) in entries.into_iter().enumerate() {
                    if key != format!("{i:016x}") {
                        return Err(Error::Invalid("array ordinal"));
                    }
                    values.push(Box::pin(self.value(&root, depth + 1)).await?);
                }
                Ok(Value::Array(values))
            }
            Object::Dictionary { entries, count } => {
                let entries = self.entries(&entries, count, MAX_KEY_BYTES).await?;
                let mut values = serde_json::Map::new();
                for (key, root) in entries {
                    self.semantic.bytes(key.len())?;
                    values.insert(key, Box::pin(self.value(&root, depth + 1)).await?);
                }
                Ok(Value::Object(values))
            }
            _ => Err(Error::Invalid("expected typed value")),
        }
    }
    async fn records(&mut self, root: &Address) -> Result<BTreeMap<String, Address>, Error> {
        self.reader
            .entries_limited(root, self.semantic.values, MAX_METADATA_BYTES)
            .await
    }
}

/// Verify the entire typed graph and reconstruct state under semantic and I/O
/// budgets. Missing/corrupt/wrongly typed content fails closed, including tombstones.
pub async fn read_state<S: ObjectStore>(
    store: &mut S,
    document: DocumentId,
    root: &Address,
    limits: Limits,
    semantic: SemanticLimits,
) -> Result<DocumentState, Error> {
    let mut decoder = Decoder {
        reader: Reader {
            store,
            document,
            budget: limits,
        },
        semantic,
    };
    let Object::State(roots) = decoder.object(root).await? else {
        return Err(Error::Invalid("expected typed state"));
    };
    let mut state = DocumentState::default();
    for (key, root) in decoder.records(&roots.nodes).await? {
        decoder.semantic.value(0)?;
        let Object::Node {
            id,
            parent_id,
            node_type,
            pos,
            var_name,
            deleted,
            fields,
        } = decoder.object(&root).await?
        else {
            return Err(Error::Invalid("expected typed node"));
        };
        if id.0 != key {
            return Err(Error::Invalid("node key/id"));
        }
        let mut node = MaterializedNode {
            id,
            parent_id,
            node_type,
            pos,
            var_name,
            deleted,
            current_fields: Value::Null,
        };
        node_metadata(&mut decoder.semantic, &node)?;
        node.current_fields = decoder.value(&fields, 0).await?;
        state.nodes.insert(node.id.clone(), node);
    }
    for (key, root) in decoder.records(&roots.comments).await? {
        decoder.semantic.value(0)?;
        if key != format!("{:016x}", state.comments.len()) {
            return Err(Error::Invalid("comment ordinal"));
        }
        let Object::Comment { node_id, body } = decoder.object(&root).await? else {
            return Err(Error::Invalid("expected typed comment"));
        };
        if let Some(id) = &node_id {
            decoder.semantic.metadata(&id.0)?;
        }
        state.comments.push(CommentState {
            node_id,
            body: decoder.text(body).await?,
        });
    }
    for (key, root) in decoder.records(&roots.suggestions).await? {
        decoder.semantic.value(0)?;
        decoder.semantic.metadata(&key)?;
        let Object::Suggestion {
            target_node_id,
            detail,
            accepted,
            rejected_reason,
        } = decoder.object(&root).await?
        else {
            return Err(Error::Invalid("expected typed suggestion"));
        };
        if let Some(id) = &target_node_id {
            decoder.semantic.metadata(&id.0)?;
        }
        let rejected_reason = match rejected_reason {
            Some(reason) => Some(decoder.text(reason).await?),
            None => None,
        };
        let detail = decoder.value(&detail, 0).await?;
        state.suggestions.insert(
            key,
            SuggestionState {
                target_node_id,
                detail,
                accepted,
                rejected_reason,
            },
        );
    }
    for (key, root) in decoder.records(&roots.removed_choices).await? {
        decoder.semantic.value(0)?;
        decoder.semantic.metadata(&key)?;
        match decoder.object(&root).await? {
            Object::RemovedChoice(id) if id.0 == key => {
                state.removed_choices.insert(id);
            }
            _ => return Err(Error::Invalid("removed choice key/id")),
        }
    }
    Ok(state)
}

struct DecoderV3<'a, S> {
    reader: Reader<'a, S>,
    semantic: SemanticLimits,
}

impl<S: ObjectStore> DecoderV3<'_, S> {
    async fn object(&mut self, root: &Address) -> Result<ObjectV3, Error> {
        if self.reader.budget.max_objects == 0 {
            return Err(Error::Limit("objects"));
        }
        let bytes = self.reader.store.get(self.reader.document, root).await?;
        self.reader.budget.consume(bytes.len())?;
        decode_v3(root, &bytes)
    }

    async fn bytes(&mut self, text: Text) -> Result<Vec<u8>, Error> {
        self.semantic.bytes(text.bytes)?;
        let mut sink = BoundedBytes {
            bytes: Vec::new(),
            limit: text.bytes,
        };
        let length = content::read_with_budget(
            self.reader.store,
            self.reader.document,
            &text.root,
            &mut sink,
            &mut self.reader.budget,
        )
        .await?;
        if length != text.bytes as u64 {
            return Err(Error::Invalid("declared content length"));
        }
        Ok(sink.bytes)
    }

    async fn text(&mut self, text: Text) -> Result<String, Error> {
        String::from_utf8(self.bytes(text).await?).map_err(|_| Error::Invalid("text UTF-8"))
    }

    async fn entries(
        &mut self,
        root: &Address,
        count: usize,
        key_limit: usize,
    ) -> Result<BTreeMap<String, Address>, Error> {
        if count > self.semantic.values {
            return Err(Error::Limit("semantic values"));
        }
        let entries = self.reader.entries_limited(root, count, key_limit).await?;
        if entries.len() != count {
            return Err(Error::Invalid("container count"));
        }
        Ok(entries)
    }

    async fn value(&mut self, root: &Address, depth: usize) -> Result<Value, Error> {
        self.semantic.value(depth)?;
        match self.object(root).await? {
            ObjectV3::Scalar(value) => Ok(value),
            ObjectV3::Text(text) => Ok(Value::String(self.text(text).await?)),
            ObjectV3::Array { entries, count } => {
                let entries = self.entries(&entries, count, 16).await?;
                let mut values = Vec::new();
                for (i, (key, root)) in entries.into_iter().enumerate() {
                    if key != format!("{i:016x}") {
                        return Err(Error::Invalid("array ordinal"));
                    }
                    values.push(Box::pin(self.value(&root, depth + 1)).await?);
                }
                Ok(Value::Array(values))
            }
            ObjectV3::Dictionary { entries, count } => {
                let entries = self.entries(&entries, count, MAX_KEY_BYTES).await?;
                let mut values = serde_json::Map::new();
                for (key, root) in entries {
                    self.semantic.bytes(key.len())?;
                    values.insert(key, Box::pin(self.value(&root, depth + 1)).await?);
                }
                Ok(Value::Object(values))
            }
            _ => Err(Error::Invalid("expected typed value")),
        }
    }

    async fn records(&mut self, root: &Address) -> Result<BTreeMap<String, Address>, Error> {
        self.reader
            .entries_limited(root, self.semantic.values, MAX_METADATA_BYTES)
            .await
    }
}

/// Verify the entire v3 typed graph and reconstruct state under semantic and I/O
/// budgets. Missing/corrupt/wrongly typed content fails closed, including tombstones.
pub async fn read_state_v3<S: ObjectStore>(
    store: &mut S,
    document: DocumentId,
    root: &Address,
    limits: Limits,
    semantic: SemanticLimits,
) -> Result<DocumentState, Error> {
    let mut decoder = DecoderV3 {
        reader: Reader {
            store,
            document,
            budget: limits,
        },
        semantic,
    };
    let ObjectV3::State(roots) = decoder.object(root).await? else {
        return Err(Error::Invalid("expected typed state"));
    };
    let mut state = DocumentState::default();
    for (key, root) in decoder.records(&roots.nodes).await? {
        decoder.semantic.value(0)?;
        let ObjectV3::Node {
            parent_id,
            node_type,
            pos,
            var_name,
            deleted,
            fields,
            restore_block_id,
            restore_label,
        } = decoder.object(&root).await?
        else {
            return Err(Error::Invalid("expected typed node"));
        };
        let id = NodeId(key.clone());
        let mut node = MaterializedNode {
            id: id.clone(),
            parent_id,
            node_type,
            pos,
            var_name,
            deleted,
            current_fields: Value::Null,
        };
        node_metadata(&mut decoder.semantic, &node)?;
        let mut fields_val = decoder.value(&fields, 0).await?;

        if restore_block_id || restore_label {
            let Value::Object(ref mut map) = fields_val else {
                return Err(Error::Invalid("expected object fields for restore flag"));
            };
            if restore_block_id {
                if map.contains_key("blockId") {
                    return Err(Error::Invalid("restore_block_id with existing blockId"));
                }
                decoder.semantic.metadata("blockId")?;
                decoder.semantic.metadata(&key)?;
                map.insert("blockId".into(), Value::String(key.clone()));
            }
            if restore_label {
                if map.contains_key("label") {
                    return Err(Error::Invalid("restore_label with existing label"));
                }
                let Some(content) = map.get("content") else {
                    return Err(Error::Invalid("restore_label requires content field"));
                };
                if content.is_null() {
                    return Err(Error::Invalid("restore_label requires content field"));
                }
                let label = crate::richtext::plain_text(content);
                decoder.semantic.metadata("label")?;
                decoder.semantic.metadata(&label)?;
                map.insert("label".into(), Value::String(label));
            }
        }

        if let Value::Object(ref map) = fields_val {
            if !restore_block_id {
                if let Some(Value::String(b_id)) = map.get("blockId") {
                    if b_id == &key {
                        return Err(Error::Invalid(
                            "non-minimal blockId; must be omitted when equal to node id",
                        ));
                    }
                }
            }
            if !restore_label {
                if let Some(content) = map.get("content") {
                    if !content.is_null() {
                        if let Some(Value::String(lbl)) = map.get("label") {
                            if lbl == &crate::richtext::plain_text(content) {
                                return Err(Error::Invalid(
                                    "non-minimal label; must be omitted when equal to plain_text(content)",
                                ));
                            }
                        }
                    }
                }
            }
        }

        node.current_fields = fields_val;
        state.nodes.insert(node.id.clone(), node);
    }
    for (key, root) in decoder.records(&roots.comments).await? {
        decoder.semantic.value(0)?;
        if key != format!("{:016x}", state.comments.len()) {
            return Err(Error::Invalid("comment ordinal"));
        }
        let ObjectV3::Comment { node_id, body } = decoder.object(&root).await? else {
            return Err(Error::Invalid("expected typed comment"));
        };
        if let Some(id) = &node_id {
            decoder.semantic.metadata(&id.0)?;
        }
        state.comments.push(CommentState {
            node_id,
            body: decoder.text(body).await?,
        });
    }
    for (key, root) in decoder.records(&roots.suggestions).await? {
        decoder.semantic.value(0)?;
        decoder.semantic.metadata(&key)?;
        let ObjectV3::Suggestion {
            target_node_id,
            detail,
            accepted,
            rejected_reason,
        } = decoder.object(&root).await?
        else {
            return Err(Error::Invalid("expected typed suggestion"));
        };
        if let Some(id) = &target_node_id {
            decoder.semantic.metadata(&id.0)?;
        }
        let rejected_reason = match rejected_reason {
            Some(reason) => Some(decoder.text(reason).await?),
            None => None,
        };
        let detail = decoder.value(&detail, 0).await?;
        state.suggestions.insert(
            key,
            SuggestionState {
                target_node_id,
                detail,
                accepted,
                rejected_reason,
            },
        );
    }
    for (key, root) in decoder.records(&roots.removed_choices).await? {
        decoder.semantic.value(0)?;
        decoder.semantic.metadata(&key)?;
        match decoder.object(&root).await? {
            ObjectV3::RemovedChoice(id) if id.0 == key => {
                state.removed_choices.insert(id);
            }
            _ => return Err(Error::Invalid("removed choice key/id")),
        }
    }
    Ok(state)
}

struct EncoderV3<'a, S> {
    writer: Writer<'a, S>,
    semantic: SemanticLimits,
}

impl<S: ObjectStore> EncoderV3<'_, S> {
    async fn object(&mut self, object: ObjectV3) -> Result<Address, Error> {
        let (address, bytes) = encode_v3(&object)?;
        self.writer.encoded(address, bytes).await
    }

    async fn text(&mut self, text: &[u8]) -> Result<Text, Error> {
        self.semantic.bytes(text.len())?;
        let root = content::write_with_writer(&mut self.writer, &mut &*text).await?;
        Ok(Text {
            root,
            bytes: text.len(),
        })
    }

    async fn value(&mut self, value: &Value, depth: usize) -> Result<Address, Error> {
        self.semantic.value(depth)?;
        let object = match value {
            Value::String(text) => ObjectV3::Text(self.text(text.as_bytes()).await?),
            Value::Array(values) => {
                if values.len() > self.semantic.values {
                    return Err(Error::Limit("semantic values"));
                }
                let mut entries = Vec::new();
                for (i, value) in values.iter().enumerate() {
                    let key = format!("{i:016x}");
                    let address = Box::pin(self.value(value, depth + 1)).await?;
                    entries.push((super::route(&key), Entry { key, address }));
                }
                ObjectV3::Array {
                    entries: self.writer.entries(entries).await?,
                    count: values.len(),
                }
            }
            Value::Object(values) => {
                if values.len() > self.semantic.values {
                    return Err(Error::Limit("semantic values"));
                }
                let mut entries = Vec::new();
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_unstable();
                for key in keys {
                    if key.len() > MAX_KEY_BYTES {
                        return Err(Error::Limit("property key bytes"));
                    }
                    self.semantic.bytes(key.len())?;
                    let address = Box::pin(self.value(&values[key], depth + 1)).await?;
                    entries.push((
                        super::route(key),
                        Entry {
                            key: key.clone(),
                            address,
                        },
                    ));
                }
                ObjectV3::Dictionary {
                    entries: self.writer.entries(entries).await?,
                    count: values.len(),
                }
            }
            value => ObjectV3::Scalar(value.clone()),
        };
        self.object(object).await
    }

    async fn read_object(&mut self, address: &Address) -> Result<ObjectV3, Error> {
        if self.writer.budget.max_objects == 0 {
            return Err(Error::Limit("objects"));
        }
        let bytes = if let Some((_, b)) = self.writer.pending.iter().find(|(a, _)| a == address) {
            self.writer.budget.consume(b.len())?;
            b.clone()
        } else {
            let b = self.writer.store.get(self.writer.document, address).await?;
            self.writer.budget.consume(b.len())?;
            b
        };
        decode_v3(address, &bytes)
    }

    async fn encode_node_fields(
        &mut self,
        id: &NodeId,
        current_fields: &Value,
    ) -> Result<(Address, bool, bool), Error> {
        match current_fields {
            Value::Object(map) => {
                let restore_block_id =
                    matches!(map.get("blockId"), Some(Value::String(b)) if b == &id.0);
                let restore_label = matches!(
                    (map.get("content"), map.get("label")),
                    (Some(content), Some(Value::String(l)))
                        if !content.is_null() && l == &crate::richtext::plain_text(content)
                );

                let fields = if !restore_block_id && !restore_label {
                    self.value(current_fields, 0).await?
                } else {
                    let mut keys: Vec<_> = map
                        .keys()
                        .filter(|&k| {
                            !(restore_block_id && k == "blockId" || restore_label && k == "label")
                        })
                        .collect();
                    keys.sort_unstable();

                    if keys.len() > self.semantic.values {
                        return Err(Error::Limit("semantic values"));
                    }
                    let mut entries = Vec::new();
                    for key in keys {
                        if key.len() > MAX_KEY_BYTES {
                            return Err(Error::Limit("property key bytes"));
                        }
                        self.semantic.bytes(key.len())?;
                        let address = Box::pin(self.value(&map[key], 1)).await?;
                        entries.push((
                            super::route(key),
                            Entry {
                                key: key.clone(),
                                address,
                            },
                        ));
                    }
                    let entries_root = self.writer.entries(entries).await?;
                    self.object(ObjectV3::Dictionary {
                        entries: entries_root,
                        count: map.len() - (restore_block_id as usize) - (restore_label as usize),
                    })
                    .await?
                };
                Ok((fields, restore_block_id, restore_label))
            }
            _ => {
                let fields = self.value(current_fields, 0).await?;
                Ok((fields, false, false))
            }
        }
    }
}

/// Write a compact v3 typed state graph; caller owns authorization and atomic publication.
pub async fn write_state_v3<S: ObjectStore>(
    store: &mut S,
    document: DocumentId,
    state: &DocumentState,
    limits: Limits,
    semantic: SemanticLimits,
) -> Result<(Address, WriteStats), Error> {
    let mut encoder = EncoderV3 {
        writer: Writer {
            store,
            document,
            budget: limits,
            stats: WriteStats::default(),
            pending: Vec::new(),
            pending_bytes: 0,
        },
        semantic,
    };

    let mut node_entries = Vec::new();
    for (id, node) in &state.nodes {
        encoder.semantic.value(0)?;
        if id != &node.id {
            return Err(Error::Invalid("node map key differs from logical id"));
        }
        node_metadata(&mut encoder.semantic, node)?;

        let (fields, restore_block_id, restore_label) =
            encoder.encode_node_fields(id, &node.current_fields).await?;

        let address = encoder
            .object(ObjectV3::Node {
                parent_id: node.parent_id.clone(),
                node_type: node.node_type.clone(),
                pos: node.pos.clone(),
                var_name: node.var_name.clone(),
                deleted: node.deleted,
                fields,
                restore_block_id,
                restore_label,
            })
            .await?;
        node_entries.push((
            super::route(&id.0),
            Entry {
                key: id.0.clone(),
                address,
            },
        ));
    }
    let nodes = encoder.writer.entries(node_entries).await?;

    let mut comment_entries = Vec::new();
    for (i, comment) in state.comments.iter().enumerate() {
        encoder.semantic.value(0)?;
        if let Some(id) = &comment.node_id {
            encoder.semantic.metadata(&id.0)?;
        }
        let body = encoder.text(comment.body.as_bytes()).await?;
        let address = encoder
            .object(ObjectV3::Comment {
                node_id: comment.node_id.clone(),
                body,
            })
            .await?;
        let key = format!("{i:016x}");
        comment_entries.push((super::route(&key), Entry { key, address }));
    }
    let comments = encoder.writer.entries(comment_entries).await?;

    let mut sugg_entries = Vec::new();
    for (key, suggestion) in &state.suggestions {
        encoder.semantic.value(0)?;
        if key.len() > MAX_KEY_BYTES {
            return Err(Error::Limit("suggestion key bytes"));
        }
        encoder.semantic.metadata(key)?;
        if let Some(id) = &suggestion.target_node_id {
            encoder.semantic.metadata(&id.0)?;
        }
        let detail = encoder.value(&suggestion.detail, 0).await?;
        let rejected_reason = match &suggestion.rejected_reason {
            Some(reason) => Some(encoder.text(reason.as_bytes()).await?),
            None => None,
        };
        let address = encoder
            .object(ObjectV3::Suggestion {
                target_node_id: suggestion.target_node_id.clone(),
                detail,
                accepted: suggestion.accepted,
                rejected_reason,
            })
            .await?;
        sugg_entries.push((
            super::route(key),
            Entry {
                key: key.clone(),
                address,
            },
        ));
    }
    let suggestions = encoder.writer.entries(sugg_entries).await?;

    if state.removed_choices.len() > encoder.semantic.values {
        return Err(Error::Limit("semantic values"));
    }
    let mut rc_entries = Vec::new();
    let mut removed: Vec<_> = state.removed_choices.iter().collect();
    removed.sort();
    for id in removed {
        encoder.semantic.value(0)?;
        encoder.semantic.metadata(&id.0)?;
        let address = encoder.object(ObjectV3::RemovedChoice(id.clone())).await?;
        rc_entries.push((
            super::route(&id.0),
            Entry {
                key: id.0.clone(),
                address,
            },
        ));
    }
    let removed_choices = encoder.writer.entries(rc_entries).await?;

    let root = encoder
        .object(ObjectV3::State(StateRoots {
            nodes,
            comments,
            suggestions,
            removed_choices,
        }))
        .await?;
    encoder.writer.flush().await?;
    Ok((root, encoder.writer.stats))
}

pub const UNSUPPORTED_V3_DELTA: &str = "unsupported v3 delta";

/// Incrementally update an already verified base state with a validated target state under compact v3 format.
/// Reuses unchanged node, field, and annotation objects without re-encoding.
/// Falling back to full write_state_v3 is allowed only for explicitly recognized unsupported delta shapes.
/// Integrity errors (corruption, hash mismatches, missing objects, limit exhaustion) fail closed.
pub async fn update_state_v3<S: ObjectStore>(
    store: &mut S,
    document: DocumentId,
    base_root: &Address,
    base_state: &DocumentState,
    target_state: &DocumentState,
    limits: Limits,
    semantic: SemanticLimits,
) -> Result<(Address, WriteStats), Error> {
    for (id, node) in &target_state.nodes {
        if id != &node.id {
            return Err(Error::Invalid("node map key differs from logical id"));
        }
    }

    match try_update_state_v3(
        store,
        document,
        base_root,
        base_state,
        target_state,
        limits,
        semantic,
    )
    .await
    {
        Ok(res) => Ok(res),
        Err(Error::Invalid(UNSUPPORTED_V3_DELTA)) => {
            write_state_v3(store, document, target_state, limits, semantic).await
        }
        Err(err) => Err(err),
    }
}

async fn try_update_state_v3<S: ObjectStore>(
    store: &mut S,
    document: DocumentId,
    base_root: &Address,
    base_state: &DocumentState,
    target_state: &DocumentState,
    limits: Limits,
    semantic: SemanticLimits,
) -> Result<(Address, WriteStats), Error> {
    let mut encoder = EncoderV3 {
        writer: Writer {
            store,
            document,
            budget: limits,
            stats: WriteStats::default(),
            pending: Vec::new(),
            pending_bytes: 0,
        },
        semantic,
    };

    let base_obj = encoder.read_object(base_root).await?;
    let ObjectV3::State(base_roots) = base_obj else {
        return Err(Error::Invalid("expected typed v3 state"));
    };

    // No-op check: enforce semantic budgets across all reachable items, write 0 objects
    if target_state == base_state {
        for (id, node) in &target_state.nodes {
            encoder.semantic.value(0)?;
            if id != &node.id {
                return Err(Error::Invalid("node map key differs from logical id"));
            }
            node_metadata(&mut encoder.semantic, node)?;
            charge_node_fields_v3(&mut encoder.semantic, id, &node.current_fields)?;
        }
        for comment in &target_state.comments {
            encoder.semantic.value(0)?;
            if let Some(id) = &comment.node_id {
                encoder.semantic.metadata(&id.0)?;
            }
            encoder.semantic.bytes(comment.body.len())?;
        }
        for (key, suggestion) in &target_state.suggestions {
            encoder.semantic.value(0)?;
            if key.len() > MAX_KEY_BYTES {
                return Err(Error::Limit("suggestion key bytes"));
            }
            encoder.semantic.metadata(key)?;
            if let Some(id) = &suggestion.target_node_id {
                encoder.semantic.metadata(&id.0)?;
            }
            charge_value(&mut encoder.semantic, &suggestion.detail, 0)?;
            if let Some(reason) = &suggestion.rejected_reason {
                encoder.semantic.bytes(reason.len())?;
            }
        }
        if target_state.removed_choices.len() > encoder.semantic.values {
            return Err(Error::Limit("semantic values"));
        }
        let mut removed: Vec<_> = target_state.removed_choices.iter().collect();
        removed.sort();
        for id in removed {
            encoder.semantic.value(0)?;
            encoder.semantic.metadata(&id.0)?;
        }
        return Ok((base_root.clone(), encoder.writer.stats));
    }

    // 1. Process nodes
    let mut node_edits: Vec<(String, Option<Address>)> = Vec::new();

    // Deleted nodes
    for id in base_state.nodes.keys() {
        if !target_state.nodes.contains_key(id) {
            node_edits.push((id.0.clone(), None));
        }
    }

    // Unchanged, modified, or added nodes
    for (id, node) in &target_state.nodes {
        encoder.semantic.value(0)?;
        if id != &node.id {
            return Err(Error::Invalid("node map key differs from logical id"));
        }
        node_metadata(&mut encoder.semantic, node)?;

        if let Some(base_node) = base_state.nodes.get(id) {
            if base_node == node {
                charge_node_fields_v3(&mut encoder.semantic, id, &node.current_fields)?;
            } else {
                let (fields, restore_block_id, restore_label) =
                    if base_node.current_fields == node.current_fields {
                        charge_node_fields_v3(&mut encoder.semantic, id, &node.current_fields)?;
                        let old_node_addr = encoder
                            .writer
                            .lookup(&base_roots.nodes, &id.0)
                            .await?
                            .ok_or(Error::Invalid("base node missing from radix map"))?;
                        match encoder.read_object(&old_node_addr).await? {
                            ObjectV3::Node {
                                fields,
                                restore_block_id,
                                restore_label,
                                ..
                            } => (fields, restore_block_id, restore_label),
                            _ => return Err(Error::Invalid("expected typed v3 node")),
                        }
                    } else {
                        encoder.encode_node_fields(id, &node.current_fields).await?
                    };

                let addr = encoder
                    .object(ObjectV3::Node {
                        parent_id: node.parent_id.clone(),
                        node_type: node.node_type.clone(),
                        pos: node.pos.clone(),
                        var_name: node.var_name.clone(),
                        deleted: node.deleted,
                        fields,
                        restore_block_id,
                        restore_label,
                    })
                    .await?;
                node_edits.push((id.0.clone(), Some(addr)));
            }
        } else {
            let (fields, restore_block_id, restore_label) =
                encoder.encode_node_fields(id, &node.current_fields).await?;
            let addr = encoder
                .object(ObjectV3::Node {
                    parent_id: node.parent_id.clone(),
                    node_type: node.node_type.clone(),
                    pos: node.pos.clone(),
                    var_name: node.var_name.clone(),
                    deleted: node.deleted,
                    fields,
                    restore_block_id,
                    restore_label,
                })
                .await?;
            node_edits.push((id.0.clone(), Some(addr)));
        }
    }

    let nodes = if node_edits.is_empty() {
        base_roots.nodes.clone()
    } else {
        encoder
            .writer
            .update_map(&base_roots.nodes, node_edits)
            .await?
    };

    // 2. Process comments
    let comments = if target_state.comments == base_state.comments {
        for comment in &target_state.comments {
            encoder.semantic.value(0)?;
            if let Some(id) = &comment.node_id {
                encoder.semantic.metadata(&id.0)?;
            }
            encoder.semantic.bytes(comment.body.len())?;
        }
        base_roots.comments.clone()
    } else {
        let mut comment_edits = Vec::new();
        let max_len = target_state.comments.len().max(base_state.comments.len());
        for i in 0..max_len {
            let key = format!("{i:016x}");
            match (target_state.comments.get(i), base_state.comments.get(i)) {
                (Some(target_c), Some(base_c)) => {
                    encoder.semantic.value(0)?;
                    if let Some(id) = &target_c.node_id {
                        encoder.semantic.metadata(&id.0)?;
                    }
                    if target_c == base_c {
                        encoder.semantic.bytes(target_c.body.len())?;
                    } else {
                        let body = encoder.text(target_c.body.as_bytes()).await?;
                        let addr = encoder
                            .object(ObjectV3::Comment {
                                node_id: target_c.node_id.clone(),
                                body,
                            })
                            .await?;
                        comment_edits.push((key, Some(addr)));
                    }
                }
                (Some(target_c), None) => {
                    encoder.semantic.value(0)?;
                    if let Some(id) = &target_c.node_id {
                        encoder.semantic.metadata(&id.0)?;
                    }
                    let body = encoder.text(target_c.body.as_bytes()).await?;
                    let addr = encoder
                        .object(ObjectV3::Comment {
                            node_id: target_c.node_id.clone(),
                            body,
                        })
                        .await?;
                    comment_edits.push((key, Some(addr)));
                }
                (None, Some(_)) => {
                    comment_edits.push((key, None));
                }
                (None, None) => unreachable!(),
            }
        }
        encoder
            .writer
            .update_map(&base_roots.comments, comment_edits)
            .await?
    };

    // 3. Process suggestions
    let suggestions = if target_state.suggestions == base_state.suggestions {
        for (key, suggestion) in &target_state.suggestions {
            encoder.semantic.value(0)?;
            if key.len() > MAX_KEY_BYTES {
                return Err(Error::Limit("suggestion key bytes"));
            }
            encoder.semantic.metadata(key)?;
            if let Some(id) = &suggestion.target_node_id {
                encoder.semantic.metadata(&id.0)?;
            }
            charge_value(&mut encoder.semantic, &suggestion.detail, 0)?;
            if let Some(reason) = &suggestion.rejected_reason {
                encoder.semantic.bytes(reason.len())?;
            }
        }
        base_roots.suggestions.clone()
    } else {
        let mut sugg_edits = Vec::new();
        for key in base_state.suggestions.keys() {
            if !target_state.suggestions.contains_key(key) {
                sugg_edits.push((key.clone(), None));
            }
        }
        for (key, target_s) in &target_state.suggestions {
            encoder.semantic.value(0)?;
            if key.len() > MAX_KEY_BYTES {
                return Err(Error::Limit("suggestion key bytes"));
            }
            encoder.semantic.metadata(key)?;
            if let Some(id) = &target_s.target_node_id {
                encoder.semantic.metadata(&id.0)?;
            }

            if let Some(base_s) = base_state.suggestions.get(key) {
                if base_s == target_s {
                    charge_value(&mut encoder.semantic, &target_s.detail, 0)?;
                    if let Some(reason) = &target_s.rejected_reason {
                        encoder.semantic.bytes(reason.len())?;
                    }
                } else {
                    let detail = if base_s.detail == target_s.detail {
                        charge_value(&mut encoder.semantic, &target_s.detail, 0)?;
                        let old_sugg_addr = encoder
                            .writer
                            .lookup(&base_roots.suggestions, key)
                            .await?
                            .ok_or(Error::Invalid("base suggestion missing from map"))?;
                        match encoder.read_object(&old_sugg_addr).await? {
                            ObjectV3::Suggestion { detail, .. } => detail,
                            _ => return Err(Error::Invalid("expected typed v3 suggestion")),
                        }
                    } else {
                        encoder.value(&target_s.detail, 0).await?
                    };

                    let rejected_reason = match &target_s.rejected_reason {
                        Some(reason) => Some(encoder.text(reason.as_bytes()).await?),
                        None => None,
                    };
                    let addr = encoder
                        .object(ObjectV3::Suggestion {
                            target_node_id: target_s.target_node_id.clone(),
                            detail,
                            accepted: target_s.accepted,
                            rejected_reason,
                        })
                        .await?;
                    sugg_edits.push((key.clone(), Some(addr)));
                }
            } else {
                let detail = encoder.value(&target_s.detail, 0).await?;
                let rejected_reason = match &target_s.rejected_reason {
                    Some(reason) => Some(encoder.text(reason.as_bytes()).await?),
                    None => None,
                };
                let addr = encoder
                    .object(ObjectV3::Suggestion {
                        target_node_id: target_s.target_node_id.clone(),
                        detail,
                        accepted: target_s.accepted,
                        rejected_reason,
                    })
                    .await?;
                sugg_edits.push((key.clone(), Some(addr)));
            }
        }
        encoder
            .writer
            .update_map(&base_roots.suggestions, sugg_edits)
            .await?
    };

    // 4. Process removed_choices
    let removed_choices = if target_state.removed_choices == base_state.removed_choices {
        if target_state.removed_choices.len() > encoder.semantic.values {
            return Err(Error::Limit("semantic values"));
        }
        let mut removed: Vec<_> = target_state.removed_choices.iter().collect();
        removed.sort();
        for id in removed {
            encoder.semantic.value(0)?;
            encoder.semantic.metadata(&id.0)?;
        }
        base_roots.removed_choices.clone()
    } else {
        if target_state.removed_choices.len() > encoder.semantic.values {
            return Err(Error::Limit("semantic values"));
        }
        let mut rc_edits = Vec::new();
        for id in &base_state.removed_choices {
            if !target_state.removed_choices.contains(id) {
                rc_edits.push((id.0.clone(), None));
            }
        }
        let mut removed: Vec<_> = target_state.removed_choices.iter().collect();
        removed.sort();
        for id in removed {
            encoder.semantic.value(0)?;
            encoder.semantic.metadata(&id.0)?;
            if !base_state.removed_choices.contains(id) {
                let addr = encoder.object(ObjectV3::RemovedChoice(id.clone())).await?;
                rc_edits.push((id.0.clone(), Some(addr)));
            }
        }
        encoder
            .writer
            .update_map(&base_roots.removed_choices, rc_edits)
            .await?
    };

    if nodes == base_roots.nodes
        && comments == base_roots.comments
        && suggestions == base_roots.suggestions
        && removed_choices == base_roots.removed_choices
    {
        encoder.writer.flush().await?;
        return Ok((base_root.clone(), encoder.writer.stats));
    }

    let root = encoder
        .object(ObjectV3::State(StateRoots {
            nodes,
            comments,
            suggestions,
            removed_choices,
        }))
        .await?;
    encoder.writer.flush().await?;
    Ok((root, encoder.writer.stats))
}

/// Store an opaque asset manifest over preexisting content, verifying the full
/// byte tree without buffering it. Native adapters must explicitly reference this
/// manifest; it is not silently added to DocumentState or a checkpoint.
pub async fn write_asset<S: ObjectStore>(
    store: &mut S,
    document: DocumentId,
    root: &Address,
    media_type: &str,
    limits: Limits,
) -> Result<Address, Error> {
    if media_type.is_empty() || media_type.len() > 255 || !media_type.is_ascii() {
        return Err(Error::Invalid("asset media type"));
    }
    let mut budget = limits;
    let bytes =
        content::read_with_budget(store, document, root, &mut tokio::io::sink(), &mut budget)
            .await?;
    let bytes = usize::try_from(bytes).map_err(|_| Error::Limit("asset length"))?;
    let (address, encoded) = encode(&Object::Asset {
        media_type: media_type.into(),
        content: Text {
            root: root.clone(),
            bytes,
        },
    })?;
    budget.consume(encoded.len())?;
    store.put(document, &address, &encoded).await?;
    Ok(address)
}

/// Verify and stream an explicitly referenced native asset to a staged sink.
pub async fn read_asset<S: ObjectStore, W: AsyncWrite + Unpin + Send>(
    store: &mut S,
    document: DocumentId,
    root: &Address,
    output: &mut W,
    mut limits: Limits,
) -> Result<(String, u64), Error> {
    if limits.max_objects == 0 {
        return Err(Error::Limit("objects"));
    }
    let bytes = store.get(document, root).await?;
    limits.consume(bytes.len())?;
    let Object::Asset {
        media_type,
        content,
    } = decode(root, &bytes)?
    else {
        return Err(Error::Invalid("expected asset"));
    };
    if media_type.is_empty() || media_type.len() > 255 || !media_type.is_ascii() {
        return Err(Error::Invalid("asset media type"));
    }
    let length =
        content::read_with_budget(store, document, &content.root, output, &mut limits).await?;
    if length != content.bytes as u64 {
        return Err(Error::Invalid("asset length"));
    }
    Ok((media_type, length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_checkpoint::{MemoryStore, MAX_OBJECT_BYTES};
    use serde_json::json;

    fn doc() -> DocumentId {
        DocumentId(uuid::Uuid::new_v4())
    }
    async fn write(
        store: &mut MemoryStore,
        document: DocumentId,
        state: &DocumentState,
    ) -> (Address, WriteStats) {
        write_state(
            store,
            document,
            state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap()
    }
    async fn read(
        store: &mut MemoryStore,
        document: DocumentId,
        root: &Address,
    ) -> Result<DocumentState, Error> {
        read_state(
            store,
            document,
            root,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
    }
    fn fixture() -> DocumentState {
        let mut state = super::super::tests::fixture(75);
        state.nodes.values_mut().next().unwrap().current_fields = json!({
            "text": "বাংলা 🦀".repeat(150_000), "array": [null, true, -0.0, 1.25, 18446744073709551615u64],
            "nested": {"runs": [{"text":"Hello", "bold":true}]}
        });
        state.comments[0].body = "Comment".repeat(160_000);
        state
            .suggestions
            .values_mut()
            .next()
            .unwrap()
            .rejected_reason = Some("Reason".repeat(180_000));
        state
    }

    #[tokio::test]
    async fn large_typed_state_roundtrips_reuses_and_preserves_v1() {
        let mut store = MemoryStore::default();
        let document = doc();
        let state = fixture();
        assert!(matches!(
            super::super::write_state(&mut store, document, &state, Limits::default()).await,
            Err(Error::Limit(_))
        ));
        let (root, first) = write(&mut store, document, &state).await;
        assert_eq!(read(&mut store, document, &root).await.unwrap(), state);
        let (same, again) = write(&mut store, document, &state).await;
        assert_eq!(same, root);
        assert_eq!(again.new_objects, 0);
        assert_eq!(again.new_bytes, 0);
        let mut edited = state.clone();
        edited.nodes.values_mut().nth(20).unwrap().current_fields["text"] = json!("Changed");
        let (changed, delta) = write(&mut store, document, &edited).await;
        assert_ne!(changed, root);
        assert!(delta.new_bytes < first.new_bytes / 5);
        assert_eq!(read(&mut store, document, &changed).await.unwrap(), edited);
        assert_eq!(read(&mut store, document, &root).await.unwrap(), state);
        assert!(matches!(
            read(&mut store, doc(), &root).await,
            Err(Error::Missing(_))
        ));
        assert!(
            super::super::read_state(&mut store, document, &root, Limits::default())
                .await
                .is_err()
        );
        let small = super::super::tests::fixture(2);
        let (v1, _) = super::super::write_state(&mut store, document, &small, Limits::default())
            .await
            .unwrap();
        assert_eq!(
            super::super::read_state(&mut store, document, &v1, Limits::default())
                .await
                .unwrap(),
            small
        );
        assert!(read(&mut store, document, &v1).await.is_err());
    }

    #[tokio::test]
    async fn reference_walk_reaches_exactly_the_written_typed_graph() {
        let mut store = MemoryStore::default();
        let document = doc();
        let (root, _) = write(&mut store, document, &fixture()).await;
        // Includes v2 values, v1 map nodes and multi-level content trees.
        assert!(store.object_count() > 100);
        let reached = super::super::tests::reachable(&mut store, document, &root).await;
        assert_eq!(reached.len(), store.object_count());
        let body = "asset body ".repeat(20_000);
        let (content, _) = content::write(
            &mut store,
            document,
            &mut body.as_bytes(),
            Limits::default(),
        )
        .await
        .unwrap();
        let asset = write_asset(
            &mut store,
            document,
            &content,
            "text/plain",
            Limits::default(),
        )
        .await
        .unwrap();
        let reached = super::super::tests::reachable(&mut store, document, &asset).await;
        assert!(reached.len() >= 3);
        assert!(!reached.contains(&root));
    }

    #[tokio::test]
    async fn global_budgets_cover_repeated_values_strings_and_nested_graphs() {
        let mut store = MemoryStore::default();
        let document = doc();
        let mut state = super::super::tests::fixture(1);
        state.nodes.values_mut().next().unwrap().current_fields =
            json!(vec!["x".repeat(MAX_OBJECT_BYTES); 3]);
        let (root, stats) = write(&mut store, document, &state).await;
        for limits in [
            Limits {
                max_bytes: stats.encoded_bytes - 1,
                max_objects: usize::MAX,
            },
            Limits {
                max_bytes: usize::MAX,
                max_objects: stats.visited_objects - 1,
            },
        ] {
            assert!(matches!(
                write_state(
                    &mut store,
                    document,
                    &state,
                    limits,
                    SemanticLimits::default()
                )
                .await,
                Err(Error::Limit(_))
            ));
            assert!(matches!(
                read_state(
                    &mut store,
                    document,
                    &root,
                    limits,
                    SemanticLimits::default()
                )
                .await,
                Err(Error::Limit(_))
            ));
        }
        for semantic in [
            SemanticLimits {
                values: 3,
                ..Default::default()
            },
            SemanticLimits {
                string_bytes: MAX_OBJECT_BYTES * 2,
                ..Default::default()
            },
            SemanticLimits {
                depth: 0,
                ..Default::default()
            },
        ] {
            assert!(matches!(
                write_state(&mut store, document, &state, Limits::default(), semantic).await,
                Err(Error::Limit(_))
            ));
            assert!(matches!(
                read_state(&mut store, document, &root, Limits::default(), semantic).await,
                Err(Error::Limit(_))
            ));
        }
        let exact = Limits {
            max_bytes: stats.encoded_bytes,
            max_objects: stats.visited_objects,
        };
        assert_eq!(
            read_state(
                &mut store,
                document,
                &root,
                exact,
                SemanticLimits::default()
            )
            .await
            .unwrap(),
            state
        );
        let mut nested = Value::Null;
        for _ in 0..MAX_DEPTH + 1 {
            nested = json!([nested]);
        }
        state.nodes.values_mut().next().unwrap().current_fields = nested;
        assert!(matches!(
            write_state(
                &mut store,
                document,
                &state,
                Limits::default(),
                SemanticLimits::default()
            )
            .await,
            Err(Error::Limit("semantic depth"))
        ));
    }

    #[tokio::test]
    async fn missing_corrupt_and_mistyped_values_fail_closed() {
        let mut store = MemoryStore::default();
        let document = doc();
        let state = super::super::tests::fixture(2);
        let (root, _) = write(&mut store, document, &state).await;
        let key = store
            .objects
            .iter()
            .find(|(_, bytes)| bytes.starts_with(content::MAGIC) && bytes[9] == 1)
            .unwrap()
            .0
            .clone();
        let original = store.objects.remove(&key).unwrap();
        assert!(matches!(
            read(&mut store, document, &root).await,
            Err(Error::Missing(_))
        ));
        let mut broken = original.clone();
        broken[10] ^= 1;
        store.objects.insert(key.clone(), broken);
        assert!(matches!(
            read(&mut store, document, &root).await,
            Err(Error::HashMismatch)
        ));
        store.objects.insert(key, original);
        assert_eq!(read(&mut store, document, &root).await.unwrap(), state);
        let (address, bytes) = encode(&Object::Scalar(json!(7))).unwrap();
        store.put(document, &address, &bytes).await.unwrap();
        assert!(matches!(
            read(&mut store, document, &address).await,
            Err(Error::Invalid("expected typed state"))
        ));
    }

    #[tokio::test]
    async fn forged_lengths_counts_utf8_and_metadata_are_rejected() {
        let document = doc();
        let mut store = MemoryStore::default();
        let (root, _) = content::write(&mut store, document, &mut &b"abc"[..], Limits::default())
            .await
            .unwrap();
        let mut decoder = Decoder {
            reader: Reader {
                store: &mut store,
                document,
                budget: Limits::default(),
            },
            semantic: SemanticLimits::default(),
        };
        assert!(decoder
            .text(Text {
                root: root.clone(),
                bytes: 2
            })
            .await
            .is_err());
        assert!(decoder.text(Text { root, bytes: 4 }).await.is_err());
        let (root, _) = content::write(&mut store, document, &mut &b"\xff"[..], Limits::default())
            .await
            .unwrap();
        let mut decoder = Decoder {
            reader: Reader {
                store: &mut store,
                document,
                budget: Limits::default(),
            },
            semantic: SemanticLimits::default(),
        };
        assert!(matches!(
            decoder.text(Text { root, bytes: 1 }).await,
            Err(Error::Invalid("text UTF-8"))
        ));
        let (map, bytes) = super::super::encode(super::super::Object::MapLeaf(vec![])).unwrap();
        store.put(document, &map, &bytes).await.unwrap();
        let (root, bytes) = encode(&Object::Array {
            entries: map,
            count: usize::MAX,
        })
        .unwrap();
        store.put(document, &root, &bytes).await.unwrap();
        let mut decoder = Decoder {
            reader: Reader {
                store: &mut store,
                document,
                budget: Limits::default(),
            },
            semantic: SemanticLimits::default(),
        };
        assert!(matches!(
            decoder.value(&root, 0).await,
            Err(Error::Limit("semantic values"))
        ));
        let mut state = super::super::tests::fixture(1);
        state.nodes.values_mut().next().unwrap().pos = "x".repeat(MAX_METADATA_BYTES + 1);
        assert!(write_state(
            &mut store,
            document,
            &state,
            Limits::default(),
            SemanticLimits::default()
        )
        .await
        .is_err());
        state.nodes.values_mut().next().unwrap().pos = "ok".into();
        state.nodes.values_mut().next().unwrap().current_fields =
            json!({"x".repeat(MAX_KEY_BYTES + 1): null});
        assert!(write_state(
            &mut store,
            document,
            &state,
            Limits::default(),
            SemanticLimits::default()
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn asset_manifest_verifies_scoped_bytes_without_interpreting_them() {
        let mut store = MemoryStore::default();
        let document = doc();
        let data = vec![0xff; 2 * MAX_OBJECT_BYTES];
        let (content, _) = content::write(
            &mut store,
            document,
            &mut data.as_slice(),
            Limits::default(),
        )
        .await
        .unwrap();
        let root = write_asset(
            &mut store,
            document,
            &content,
            "image/png",
            Limits::default(),
        )
        .await
        .unwrap();
        let mut output = Vec::new();
        let (media_type, length) =
            read_asset(&mut store, document, &root, &mut output, Limits::default())
                .await
                .unwrap();
        assert_eq!(media_type, "image/png");
        assert_eq!(length, data.len() as u64);
        assert_eq!(output, data);
        assert!(read(&mut store, document, &root).await.is_err());
        assert!(
            write_asset(&mut store, doc(), &content, "image/png", Limits::default())
                .await
                .is_err()
        );
        assert!(
            write_asset(&mut store, document, &root, "image/png", Limits::default())
                .await
                .is_err()
        );
    }

    #[test]
    fn typed_canonical_vectors_and_noncanonical_rejection() {
        // SHA-256(domain || magic || canonical JSON), independently computed with Python hashlib.
        let (root, bytes) = encode(&Object::Scalar(Value::Null)).unwrap();
        assert_eq!(&bytes[MAGIC.len()..], br#"{"kind":"scalar","value":null}"#);
        assert_eq!(
            root.as_str(),
            "614afa1a326802d2432a51bb917cbff36c01c440f925efdd479eebec01ce6af0"
        );
        assert!(decode(&root, &bytes).is_ok());
        for tail in [
            br#"{"kind":"scalar","value":null,"extra":true}"#.as_slice(),
            br#"{"kind":"scalar","value":[],"value":null}"#,
            br#"{"kind":"scalar","value":{}}"#,
            br#"{ "kind":"scalar","value":null}"#,
        ] {
            let mut bad = MAGIC.to_vec();
            bad.extend_from_slice(tail);
            assert!(decode(&address(&bad), &bad).is_err());
        }
    }

    fn make_test_state(n_nodes: usize) -> DocumentState {
        let mut state = DocumentState::default();
        for i in 0..n_nodes {
            let id = NodeId(format!("node_{i:04}"));
            state.nodes.insert(
                id.clone(),
                MaterializedNode {
                    id: id.clone(),
                    parent_id: if i > 0 {
                        Some(NodeId(format!("node_{:04}", i / 2)))
                    } else {
                        None
                    },
                    node_type: "block".into(),
                    pos: format!("{i:04}"),
                    current_fields: json!({"text": format!("Content for node {i}"), "index": i}),
                    var_name: Some(format!("var_{i}")),
                    deleted: false,
                },
            );
        }
        state.comments.push(CommentState {
            node_id: Some(NodeId("node_0000".into())),
            body: "First comment".into(),
        });
        state.suggestions.insert(
            "sugg_0".into(),
            SuggestionState {
                target_node_id: Some(NodeId("node_0000".into())),
                detail: json!({"replace": "new text"}),
                accepted: false,
                rejected_reason: None,
            },
        );
        state
            .removed_choices
            .insert(NodeId("choice_deleted".into()));
        state
    }

    #[tokio::test]
    async fn update_state_noop_reproduces_root_with_zero_writes() {
        let mut store = MemoryStore::default();
        let document = doc();
        let state = make_test_state(40);
        let (base_root, initial_stats) = write(&mut store, document, &state).await;
        assert!(initial_stats.new_objects > 0);

        let (noop_root, update_stats) = update_state(
            &mut store,
            document,
            &base_root,
            &state,
            &state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        assert_eq!(noop_root, base_root);
        assert_eq!(update_stats.new_objects, 0);
        assert_eq!(update_stats.new_bytes, 0);
    }

    #[tokio::test]
    async fn update_state_exact_oracle_equality_across_edits() {
        let mut store = MemoryStore::default();
        let document = doc();
        let base_state = make_test_state(40);
        let (base_root, _) = write(&mut store, document, &base_state).await;

        let mut target_state = base_state.clone();
        // 1. Add node
        let new_id = NodeId("node_9999".into());
        target_state.nodes.insert(
            new_id.clone(),
            MaterializedNode {
                id: new_id.clone(),
                parent_id: None,
                node_type: "item".into(),
                pos: "9999".into(),
                current_fields: json!({"title": "new item"}),
                var_name: None,
                deleted: false,
            },
        );
        // 2. Delete node
        target_state.nodes.remove(&NodeId("node_0005".into()));
        // 3. Modify node metadata only
        if let Some(n) = target_state.nodes.get_mut(&NodeId("node_0010".into())) {
            n.pos = "updated_pos".into();
            n.deleted = true;
        }
        // 4. Modify node fields
        if let Some(n) = target_state.nodes.get_mut(&NodeId("node_0020".into())) {
            n.current_fields = json!({"text": "brand new text", "changed": true});
        }
        // 5. Add, modify, delete comments
        target_state.comments.push(CommentState {
            node_id: None,
            body: "Appended comment".into(),
        });
        target_state.comments[0].body = "Updated comment 0".into();
        // 6. Suggestions edit
        target_state.suggestions.insert(
            "sugg_1".into(),
            SuggestionState {
                target_node_id: None,
                detail: json!({"extra": 123}),
                accepted: true,
                rejected_reason: Some("already done".into()),
            },
        );
        target_state.suggestions.remove("sugg_0");
        // 7. Removed choices edit
        target_state
            .removed_choices
            .insert(NodeId("choice_new".into()));
        target_state
            .removed_choices
            .remove(&NodeId("choice_deleted".into()));

        // Call update_state
        let (update_root, stats) = update_state(
            &mut store,
            document,
            &base_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        // Call write_state oracle on fresh store
        let mut oracle_store = MemoryStore::default();
        let (oracle_root, oracle_stats) = write(&mut oracle_store, document, &target_state).await;

        assert_eq!(update_root, oracle_root);
        assert!(stats.new_objects > 0);
        assert!(stats.new_objects < oracle_stats.new_objects);

        // Verify reconstruction
        let reconstructed = read_state(
            &mut store,
            document,
            &update_root,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(reconstructed, target_state);
    }

    #[tokio::test]
    async fn update_state_reused_fields_avoid_reencoding() {
        let mut store = MemoryStore::default();
        let document = doc();
        let mut base_state = DocumentState::default();
        let id = NodeId("node_0001".into());
        let large_fields = json!({
            "large_text": "a".repeat(10_000),
            "numbers": (0..100).collect::<Vec<_>>(),
        });
        base_state.nodes.insert(
            id.clone(),
            MaterializedNode {
                id: id.clone(),
                parent_id: None,
                node_type: "block".into(),
                pos: "1".into(),
                current_fields: large_fields.clone(),
                var_name: None,
                deleted: false,
            },
        );
        let (base_root, _) = write(&mut store, document, &base_state).await;

        let mut target_state = base_state.clone();
        target_state.nodes.get_mut(&id).unwrap().pos = "2".into();

        let (new_root, update_stats) = update_state(
            &mut store,
            document,
            &base_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let (oracle_root, _) = write(&mut MemoryStore::default(), document, &target_state).await;
        assert_eq!(new_root, oracle_root);
        eprintln!("REUSED STATS: {:?}", update_stats);

        // 1 Node + 1 map leaf + 1 State root = 3 objects
        assert_eq!(update_stats.new_objects, 3);
        assert!(update_stats.new_bytes < 1000);
    }

    #[tokio::test]
    async fn update_state_unicode_handling() {
        let mut store = MemoryStore::default();
        let document = doc();
        let mut base_state = DocumentState::default();
        let id = NodeId("নথি_১".into());
        base_state.nodes.insert(
            id.clone(),
            MaterializedNode {
                id: id.clone(),
                parent_id: None,
                node_type: "অনচ্ছেদ".into(),
                pos: "১".into(),
                current_fields: json!({"বাংলা": "টেক্সট", "emoji": "🎉🚀🦀"}),
                var_name: Some("চলক".into()),
                deleted: false,
            },
        );
        base_state.comments.push(CommentState {
            node_id: Some(id.clone()),
            body: "মন্তব্য".into(),
        });
        base_state.suggestions.insert(
            "পরামর্শ".into(),
            SuggestionState {
                target_node_id: Some(id.clone()),
                detail: json!({"সংশোধন": "নতুন লেখা"}),
                accepted: false,
                rejected_reason: Some("প্রত্যাখ্যাত".into()),
            },
        );
        base_state.removed_choices.insert(NodeId("পছন্দ".into()));
        let (base_root, _) = write(&mut store, document, &base_state).await;

        let mut target_state = base_state.clone();
        target_state.nodes.get_mut(&id).unwrap().pos = "২".into();
        target_state.comments.push(CommentState {
            node_id: None,
            body: "আরেকটি মন্তব্য".into(),
        });

        let (new_root, _) = update_state(
            &mut store,
            document,
            &base_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let (oracle_root, _) = write(&mut MemoryStore::default(), document, &target_state).await;
        assert_eq!(new_root, oracle_root);

        let read_back = read_state(
            &mut store,
            document,
            &new_root,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(read_back, target_state);
    }

    #[tokio::test]
    async fn update_state_mismatched_node_ids_rejected() {
        let mut store = MemoryStore::default();
        let document = doc();
        let base_state = make_test_state(5);
        let (base_root, _) = write(&mut store, document, &base_state).await;

        let mut bad_target = base_state.clone();
        let mut bad_node = bad_target.nodes.values().next().unwrap().clone();
        bad_node.id = NodeId("different_id".into());
        bad_target.nodes.insert(NodeId("key_id".into()), bad_node);

        let err = update_state(
            &mut store,
            document,
            &base_root,
            &base_state,
            &bad_target,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap_err();

        match err {
            Error::Invalid("node map key differs from logical id") => {}
            other => panic!("expected mismatched node id error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_state_corrupt_base_fails_closed() {
        let mut store = MemoryStore::default();
        let document = doc();
        let base_state = make_test_state(5);
        let (base_root, _) = write(&mut store, document, &base_state).await;

        let mut target_state = base_state.clone();
        target_state.nodes.values_mut().next().unwrap().pos = "99".into();

        // 1. Missing base root
        let missing_root =
            Address("0000000000000000000000000000000000000000000000000000000000000000".into());
        let err = update_state(
            &mut store,
            document,
            &missing_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Missing(_)));

        // 2. Corrupt base root bytes
        let corrupt_root =
            Address("1111111111111111111111111111111111111111111111111111111111111111".into());
        store
            .objects
            .insert((document.0, corrupt_root.clone()), b"corrupted".to_vec());
        let err = update_state(
            &mut store,
            document,
            &corrupt_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Invalid("typed header/version") | Error::HashMismatch
        ));

        // 3. Corrupt a child object of base_root in store
        let Object::State(roots) =
            decode(&base_root, &store.objects[&(document.0, base_root.clone())]).unwrap()
        else {
            panic!()
        };
        store.objects.insert(
            (document.0, roots.nodes.clone()),
            b"corrupted child".to_vec(),
        );
        let err = update_state(
            &mut store,
            document,
            &base_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Invalid(_) | Error::HashMismatch));
    }

    #[tokio::test]
    async fn update_state_semantic_limits_enforced_on_reused_content() {
        let mut store = MemoryStore::default();
        let document = doc();
        let base_state = make_test_state(20);
        let (base_root, _) = write(&mut store, document, &base_state).await;

        let tight_semantic = SemanticLimits {
            values: 5,
            string_bytes: 1024 * 1024,
            depth: 64,
        };
        let err = update_state(
            &mut store,
            document,
            &base_root,
            &base_state,
            &base_state,
            Limits::default(),
            tight_semantic,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Limit("semantic values")));
    }

    #[tokio::test]
    async fn update_state_io_limits_charge_only_new_objects() {
        let mut store = MemoryStore::default();
        let document = doc();
        let base_state = make_test_state(100);
        let (base_root, _) = write(&mut store, document, &base_state).await;

        let mut target_state = base_state.clone();
        target_state.nodes.values_mut().next().unwrap().pos = "updated".into();

        let tight_io = Limits {
            max_objects: 15,
            max_bytes: 1024 * 1024,
        };

        let res = update_state(
            &mut store,
            document,
            &base_root,
            &base_state,
            &target_state,
            tight_io,
            SemanticLimits::default(),
        )
        .await;
        assert!(res.is_ok());

        let mut store2 = MemoryStore::default();
        let err = write_state(
            &mut store2,
            document,
            &target_state,
            tight_io,
            SemanticLimits::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Limit("objects")));
    }

    #[tokio::test]
    async fn update_state_unsupported_delta_fallback() {
        let mut store = MemoryStore::default();
        let document = doc();
        let (scalar_addr, encoded) = encode(&Object::Scalar(Value::Bool(true))).unwrap();
        store.put(document, &scalar_addr, &encoded).await.unwrap();

        let base_state = DocumentState::default();
        let target_state = make_test_state(5);

        let (new_root, stats) = update_state(
            &mut store,
            document,
            &scalar_addr,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let (oracle_root, _) = write(&mut MemoryStore::default(), document, &target_state).await;
        assert_eq!(new_root, oracle_root);
        assert!(stats.new_objects > 0);
    }

    #[tokio::test]
    async fn update_state_randomized_edits_fuzz() {
        struct SimpleRng(u64);
        impl SimpleRng {
            fn next_u32(&mut self) -> u32 {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                (self.0 >> 32) as u32
            }
            fn gen_range(&mut self, low: usize, high: usize) -> usize {
                low + (self.next_u32() as usize % (high - low))
            }
        }

        let mut rng = SimpleRng(20261030);
        let mut store = MemoryStore::default();
        let document = doc();

        let mut current_state = make_test_state(30);
        let (mut current_root, _) = write(&mut store, document, &current_state).await;

        for step in 0..20 {
            let mut target_state = current_state.clone();
            let action = rng.gen_range(0, 6);
            match action {
                0 => {
                    let id = NodeId(format!("fuzzy_node_{}_{}", step, rng.next_u32()));
                    target_state.nodes.insert(
                        id.clone(),
                        MaterializedNode {
                            id: id.clone(),
                            parent_id: None,
                            node_type: "fuzzy".into(),
                            pos: format!("pos_{step}"),
                            current_fields: json!({"step": step, "rand": rng.next_u32()}),
                            var_name: None,
                            deleted: false,
                        },
                    );
                }
                1 => {
                    if !target_state.nodes.is_empty() {
                        let idx = rng.gen_range(0, target_state.nodes.len());
                        let key = target_state.nodes.keys().nth(idx).unwrap().clone();
                        target_state.nodes.remove(&key);
                    }
                }
                2 => {
                    if !target_state.nodes.is_empty() {
                        let idx = rng.gen_range(0, target_state.nodes.len());
                        let key = target_state.nodes.keys().nth(idx).unwrap().clone();
                        let n = target_state.nodes.get_mut(&key).unwrap();
                        n.pos = format!("moved_{step}");
                        n.deleted = rng.next_u32().is_multiple_of(2);
                    }
                }
                3 => {
                    if !target_state.nodes.is_empty() {
                        let idx = rng.gen_range(0, target_state.nodes.len());
                        let key = target_state.nodes.keys().nth(idx).unwrap().clone();
                        let n = target_state.nodes.get_mut(&key).unwrap();
                        n.current_fields = json!({"updated_at_step": step});
                    }
                }
                4 => {
                    if rng.next_u32().is_multiple_of(2) {
                        target_state.comments.push(CommentState {
                            node_id: None,
                            body: format!("Comment at {step}"),
                        });
                    } else if !target_state.comments.is_empty() {
                        target_state.comments.pop();
                    }
                }
                _ => {
                    let key = format!("sugg_{step}");
                    target_state.suggestions.insert(
                        key,
                        SuggestionState {
                            target_node_id: None,
                            detail: json!({"step": step}),
                            accepted: false,
                            rejected_reason: None,
                        },
                    );
                    target_state
                        .removed_choices
                        .insert(NodeId(format!("rc_{step}")));
                }
            }

            let (new_root, _) = update_state(
                &mut store,
                document,
                &current_root,
                &current_state,
                &target_state,
                Limits::default(),
                SemanticLimits::default(),
            )
            .await
            .unwrap();

            let (oracle_root, _) =
                write(&mut MemoryStore::default(), document, &target_state).await;
            assert_eq!(
                new_root, oracle_root,
                "Fuzz step {step} root mismatch with oracle"
            );

            current_state = target_state;
            current_root = new_root;
        }
    }

    #[test]
    fn typed_v3_canonical_vectors_and_noncanonical_rejection() {
        let (root, bytes) = encode_v3(&ObjectV3::Scalar(Value::Null)).unwrap();
        assert_eq!(
            &bytes[MAGIC_V3.len()..],
            br#"{"kind":"scalar","value":null}"#
        );
        assert_eq!(
            root.as_str(),
            "24a4c5329aad519af2cf28e2500cf9eb75c5f372f4ebd366e382e236fd6713d1"
        );
        assert!(decode_v3(&root, &bytes).is_ok());

        // Validate stored and references dispatch for v3
        assert!(super::super::validate_stored(&root, &bytes).is_ok());
        assert_eq!(
            super::super::references(&root, &bytes).unwrap(),
            Vec::<Address>::new()
        );

        // Noncanonical rejections
        for tail in [
            br#"{"kind":"scalar","value":null,"extra":true}"#.as_slice(),
            br#"{"kind":"scalar","value":[],"value":null}"#,
            br#"{"kind":"scalar","value":{}}"#,
            br#"{ "kind":"scalar","value":null}"#,
        ] {
            let mut bad = MAGIC_V3.to_vec();
            bad.extend_from_slice(tail);
            assert!(decode_v3(&address_v3(&bad), &bad).is_err());
        }
    }

    #[tokio::test]
    async fn v3_roundtrip_reconstruction_and_isolation() {
        let mut store = MemoryStore::default();
        let document = doc();

        let mut state = DocumentState::default();
        // Node 1: standard blockId and standard label (both reconstructed)
        state.nodes.insert(
            NodeId("node_1".into()),
            MaterializedNode {
                id: NodeId("node_1".into()),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a0".into(),
                var_name: None,
                deleted: false,
                current_fields: json!({
                    "blockId": "node_1",
                    "content": {
                        "type": "doc",
                        "content": [{"text": "Hello world"}]
                    },
                    "label": "Hello world"
                }),
            },
        );

        // Node 2: custom blockId and custom label (both preserved when flags false)
        state.nodes.insert(
            NodeId("node_2".into()),
            MaterializedNode {
                id: NodeId("node_2".into()),
                parent_id: Some(NodeId("node_1".into())),
                node_type: "heading".into(),
                pos: "a1".into(),
                var_name: Some("h1".into()),
                deleted: false,
                current_fields: json!({
                    "blockId": "custom_block_id",
                    "content": {
                        "type": "doc",
                        "content": [{"text": "Hello world"}]
                    },
                    "label": "Custom Heading Label"
                }),
            },
        );

        // Node 3: tombstone with no blockId/label
        state.nodes.insert(
            NodeId("node_3".into()),
            MaterializedNode {
                id: NodeId("node_3".into()),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a2".into(),
                var_name: None,
                deleted: true,
                current_fields: Value::Null,
            },
        );

        state.comments.push(CommentState {
            node_id: Some(NodeId("node_1".into())),
            body: "Great paragraph".into(),
        });

        state.suggestions.insert(
            "sugg_1".into(),
            SuggestionState {
                target_node_id: Some(NodeId("node_1".into())),
                detail: json!({"text": "suggestion"}),
                accepted: false,
                rejected_reason: Some("Not needed".into()),
            },
        );

        state.removed_choices.insert(NodeId("choice_1".into()));

        // Write v3
        let (root_v3, _) = write_state_v3(
            &mut store,
            document,
            &state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        // Read v3
        let reconstructed = read_state_v3(
            &mut store,
            document,
            &root_v3,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        assert_eq!(reconstructed, state);

        // Verify isolation: v2 reader rejects v3 root
        let v2_read = read_state(
            &mut store,
            document,
            &root_v3,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await;
        assert!(matches!(
            v2_read,
            Err(Error::Invalid("typed header/version"))
        ));

        // Write v2 and check v3 reader rejects v2 root
        let (root_v2, _) = write(&mut store, document, &state).await;
        let v3_read = read_state_v3(
            &mut store,
            document,
            &root_v2,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await;
        assert!(matches!(
            v3_read,
            Err(Error::Invalid("typed header/version"))
        ));
    }

    #[tokio::test]
    async fn v3_writer_comprehensive_cases_and_merkle_equality() {
        let mut store = MemoryStore::default();
        let document = doc();

        let mut state = DocumentState::default();

        // Node 1: standard blockId and standard label (omitted & reconstructed)
        state.nodes.insert(
            NodeId("n1".into()),
            MaterializedNode {
                id: NodeId("n1".into()),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a0".into(),
                var_name: None,
                deleted: false,
                current_fields: json!({
                    "blockId": "n1",
                    "content": {
                        "type": "doc",
                        "content": [{"text": "Hello world"}]
                    },
                    "label": "Hello world"
                }),
            },
        );

        // Node 2: null blockId, label absent
        state.nodes.insert(
            NodeId("n2".into()),
            MaterializedNode {
                id: NodeId("n2".into()),
                parent_id: Some(NodeId("n1".into())),
                node_type: "paragraph".into(),
                pos: "a1".into(),
                var_name: None,
                deleted: false,
                current_fields: json!({
                    "blockId": null,
                    "content": {
                        "type": "doc",
                        "content": [{"text": "No label"}]
                    }
                }),
            },
        );

        // Node 3: missing blockId, stale legacy label where label != plain_text(content)
        state.nodes.insert(
            NodeId("n3".into()),
            MaterializedNode {
                id: NodeId("n3".into()),
                parent_id: None,
                node_type: "heading".into(),
                pos: "a2".into(),
                var_name: Some("title".into()),
                deleted: false,
                current_fields: json!({
                    "content": {
                        "type": "doc",
                        "content": [{"text": "New Heading Text"}]
                    },
                    "label": "Stale Legacy Heading"
                }),
            },
        );

        // Node 4: different blockId, no label
        state.nodes.insert(
            NodeId("n4".into()),
            MaterializedNode {
                id: NodeId("n4".into()),
                parent_id: None,
                node_type: "code_block".into(),
                pos: "a3".into(),
                var_name: None,
                deleted: false,
                current_fields: json!({
                    "blockId": "different_block_id_xyz",
                    "language": "rust"
                }),
            },
        );

        // Node 5: Unicode and format-only content
        state.nodes.insert(
            NodeId("n5".into()),
            MaterializedNode {
                id: NodeId("n5".into()),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a4".into(),
                var_name: None,
                deleted: false,
                current_fields: json!({
                    "blockId": "n5",
                    "content": {
                        "type": "doc",
                        "content": [{"text": "🦀 বাংলা 🚀"}]
                    },
                    "label": "🦀 বাংলা 🚀"
                }),
            },
        );

        // Node 6: empty values
        state.nodes.insert(
            NodeId("n6".into()),
            MaterializedNode {
                id: NodeId("n6".into()),
                parent_id: None,
                node_type: "empty_node".into(),
                pos: "a5".into(),
                var_name: None,
                deleted: false,
                current_fields: json!({}),
            },
        );

        // Node 7 & 8: duplicate bodies under distinct IDs
        state.nodes.insert(
            NodeId("n7".into()),
            MaterializedNode {
                id: NodeId("n7".into()),
                parent_id: None,
                node_type: "item".into(),
                pos: "a6".into(),
                var_name: None,
                deleted: false,
                current_fields: json!({"count": 42, "status": "active"}),
            },
        );
        state.nodes.insert(
            NodeId("n8".into()),
            MaterializedNode {
                id: NodeId("n8".into()),
                parent_id: None,
                node_type: "item".into(),
                pos: "a7".into(),
                var_name: None,
                deleted: false,
                current_fields: json!({"count": 42, "status": "active"}),
            },
        );

        // Node 9: tombstone
        state.nodes.insert(
            NodeId("n9".into()),
            MaterializedNode {
                id: NodeId("n9".into()),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: "a8".into(),
                var_name: None,
                deleted: true,
                current_fields: Value::Null,
            },
        );

        state.comments.push(CommentState {
            node_id: Some(NodeId("n1".into())),
            body: "A comment".into(),
        });
        state.suggestions.insert(
            "s1".into(),
            SuggestionState {
                target_node_id: Some(NodeId("n1".into())),
                detail: json!({"edit": "test"}),
                accepted: true,
                rejected_reason: None,
            },
        );
        state.removed_choices.insert(NodeId("rc1".into()));

        // Write with v2
        let (root_v2, _) = write(&mut store, document, &state).await;

        // Write with v3
        let (root_v3, _stats_v3) = write_state_v3(
            &mut store,
            document,
            &state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        // The v3 STORAGE root intentionally differs; never claim equality with v2 addresses
        assert_ne!(root_v3, root_v2);

        // Read both and verify decoded DocumentState equality
        let decoded_v3 = read_state_v3(
            &mut store,
            document,
            &root_v3,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let decoded_v2 = read_state(
            &mut store,
            document,
            &root_v2,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        assert_eq!(decoded_v3, state);
        assert_eq!(decoded_v2, state);
        assert_eq!(decoded_v2, decoded_v3);

        // Compare legacy node Merkle root with v2
        let merkle_v3 = crate::snapshot::merkle_root(&decoded_v3).unwrap();
        let merkle_v2 = crate::snapshot::merkle_root(&decoded_v2).unwrap();
        assert_eq!(merkle_v3, merkle_v2);

        // Test deterministic round trips
        let (root_v3_again, stats_again) = write_state_v3(
            &mut store,
            document,
            &state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(root_v3_again, root_v3);
        assert_eq!(stats_again.new_objects, 0);
    }

    #[tokio::test]
    async fn v3_reconstruction_and_minimal_flag_rejections() {
        let mut store = MemoryStore::default();
        let document = doc();

        // 1. restore_block_id: true with existing blockId in fields
        {
            let mut encoder = EncoderV3 {
                writer: Writer {
                    store: &mut store,
                    document,
                    budget: Limits::default(),
                    stats: WriteStats::default(),
                    pending: Vec::new(),
                    pending_bytes: 0,
                },
                semantic: SemanticLimits::default(),
            };
            let fields = encoder
                .value(&json!({"blockId": "node_1"}), 0)
                .await
                .unwrap();
            let node_addr = encoder
                .object(ObjectV3::Node {
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: "a0".into(),
                    var_name: None,
                    deleted: false,
                    fields,
                    restore_block_id: true,
                    restore_label: false,
                })
                .await
                .unwrap();
            let nodes = encoder
                .writer
                .entries(vec![(
                    super::super::route("node_1"),
                    Entry {
                        key: "node_1".into(),
                        address: node_addr,
                    },
                )])
                .await
                .unwrap();
            let empty_map = encoder.writer.entries(vec![]).await.unwrap();
            let root = encoder
                .object(ObjectV3::State(StateRoots {
                    nodes,
                    comments: empty_map.clone(),
                    suggestions: empty_map.clone(),
                    removed_choices: empty_map,
                }))
                .await
                .unwrap();
            encoder.writer.flush().await.unwrap();

            let res = read_state_v3(
                &mut store,
                document,
                &root,
                Limits::default(),
                SemanticLimits::default(),
            )
            .await;
            assert!(matches!(
                res,
                Err(Error::Invalid("restore_block_id with existing blockId"))
            ));
        }

        // 2. restore_block_id: false with redundant blockId == id
        {
            let mut encoder = EncoderV3 {
                writer: Writer {
                    store: &mut store,
                    document,
                    budget: Limits::default(),
                    stats: WriteStats::default(),
                    pending: Vec::new(),
                    pending_bytes: 0,
                },
                semantic: SemanticLimits::default(),
            };
            let fields = encoder
                .value(&json!({"blockId": "node_1"}), 0)
                .await
                .unwrap();
            let node_addr = encoder
                .object(ObjectV3::Node {
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: "a0".into(),
                    var_name: None,
                    deleted: false,
                    fields,
                    restore_block_id: false,
                    restore_label: false,
                })
                .await
                .unwrap();
            let nodes = encoder
                .writer
                .entries(vec![(
                    super::super::route("node_1"),
                    Entry {
                        key: "node_1".into(),
                        address: node_addr,
                    },
                )])
                .await
                .unwrap();
            let empty_map = encoder.writer.entries(vec![]).await.unwrap();
            let root = encoder
                .object(ObjectV3::State(StateRoots {
                    nodes,
                    comments: empty_map.clone(),
                    suggestions: empty_map.clone(),
                    removed_choices: empty_map,
                }))
                .await
                .unwrap();
            encoder.writer.flush().await.unwrap();

            let res = read_state_v3(
                &mut store,
                document,
                &root,
                Limits::default(),
                SemanticLimits::default(),
            )
            .await;
            assert!(matches!(
                res,
                Err(Error::Invalid(
                    "non-minimal blockId; must be omitted when equal to node id"
                ))
            ));
        }

        // 3. restore_label: true with existing label in fields
        {
            let mut encoder = EncoderV3 {
                writer: Writer {
                    store: &mut store,
                    document,
                    budget: Limits::default(),
                    stats: WriteStats::default(),
                    pending: Vec::new(),
                    pending_bytes: 0,
                },
                semantic: SemanticLimits::default(),
            };
            let fields = encoder
                .value(&json!({"label": "foo", "content": {"text": "foo"}}), 0)
                .await
                .unwrap();
            let node_addr = encoder
                .object(ObjectV3::Node {
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: "a0".into(),
                    var_name: None,
                    deleted: false,
                    fields,
                    restore_block_id: false,
                    restore_label: true,
                })
                .await
                .unwrap();
            let nodes = encoder
                .writer
                .entries(vec![(
                    super::super::route("node_1"),
                    Entry {
                        key: "node_1".into(),
                        address: node_addr,
                    },
                )])
                .await
                .unwrap();
            let empty_map = encoder.writer.entries(vec![]).await.unwrap();
            let root = encoder
                .object(ObjectV3::State(StateRoots {
                    nodes,
                    comments: empty_map.clone(),
                    suggestions: empty_map.clone(),
                    removed_choices: empty_map,
                }))
                .await
                .unwrap();
            encoder.writer.flush().await.unwrap();

            let res = read_state_v3(
                &mut store,
                document,
                &root,
                Limits::default(),
                SemanticLimits::default(),
            )
            .await;
            assert!(matches!(
                res,
                Err(Error::Invalid("restore_label with existing label"))
            ));
        }

        // 4. restore_label: true with missing content
        {
            let mut encoder = EncoderV3 {
                writer: Writer {
                    store: &mut store,
                    document,
                    budget: Limits::default(),
                    stats: WriteStats::default(),
                    pending: Vec::new(),
                    pending_bytes: 0,
                },
                semantic: SemanticLimits::default(),
            };
            let fields = encoder.value(&json!({}), 0).await.unwrap();
            let node_addr = encoder
                .object(ObjectV3::Node {
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: "a0".into(),
                    var_name: None,
                    deleted: false,
                    fields,
                    restore_block_id: false,
                    restore_label: true,
                })
                .await
                .unwrap();
            let nodes = encoder
                .writer
                .entries(vec![(
                    super::super::route("node_1"),
                    Entry {
                        key: "node_1".into(),
                        address: node_addr,
                    },
                )])
                .await
                .unwrap();
            let empty_map = encoder.writer.entries(vec![]).await.unwrap();
            let root = encoder
                .object(ObjectV3::State(StateRoots {
                    nodes,
                    comments: empty_map.clone(),
                    suggestions: empty_map.clone(),
                    removed_choices: empty_map,
                }))
                .await
                .unwrap();
            encoder.writer.flush().await.unwrap();

            let res = read_state_v3(
                &mut store,
                document,
                &root,
                Limits::default(),
                SemanticLimits::default(),
            )
            .await;
            assert!(matches!(
                res,
                Err(Error::Invalid("restore_label requires content field"))
            ));
        }

        // 5. restore_label: false with redundant label == plain_text(content)
        {
            let mut encoder = EncoderV3 {
                writer: Writer {
                    store: &mut store,
                    document,
                    budget: Limits::default(),
                    stats: WriteStats::default(),
                    pending: Vec::new(),
                    pending_bytes: 0,
                },
                semantic: SemanticLimits::default(),
            };
            let fields = encoder
                .value(&json!({"label": "foo", "content": {"text": "foo"}}), 0)
                .await
                .unwrap();
            let node_addr = encoder
                .object(ObjectV3::Node {
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: "a0".into(),
                    var_name: None,
                    deleted: false,
                    fields,
                    restore_block_id: false,
                    restore_label: false,
                })
                .await
                .unwrap();
            let nodes = encoder
                .writer
                .entries(vec![(
                    super::super::route("node_1"),
                    Entry {
                        key: "node_1".into(),
                        address: node_addr,
                    },
                )])
                .await
                .unwrap();
            let empty_map = encoder.writer.entries(vec![]).await.unwrap();
            let root = encoder
                .object(ObjectV3::State(StateRoots {
                    nodes,
                    comments: empty_map.clone(),
                    suggestions: empty_map.clone(),
                    removed_choices: empty_map,
                }))
                .await
                .unwrap();
            encoder.writer.flush().await.unwrap();

            let res = read_state_v3(
                &mut store,
                document,
                &root,
                Limits::default(),
                SemanticLimits::default(),
            )
            .await;
            assert!(matches!(
                res,
                Err(Error::Invalid(
                    "non-minimal label; must be omitted when equal to plain_text(content)"
                ))
            ));
        }

        // 6. Node with id field in JSON rejected by noncanonical check / deny_unknown_fields
        {
            let raw_node = json!({
                "kind": "node",
                "value": {
                    "id": "node_1",
                    "deleted": false,
                    "fields": "0000000000000000000000000000000000000000000000000000000000000000",
                    "node_type": "paragraph",
                    "parent_id": null,
                    "pos": "a0",
                    "restore_block_id": false,
                    "restore_label": false,
                    "var_name": null
                }
            });
            let mut bytes = MAGIC_V3.to_vec();
            serde_json::to_writer(
                &mut bytes,
                &super::super::canonical::CanonicalValue(&raw_node),
            )
            .unwrap();
            let addr = address_v3(&bytes);
            assert!(decode_v3(&addr, &bytes).is_err());
        }
    }

    #[tokio::test]
    async fn update_state_v3_noop_reproduces_root_with_zero_writes() {
        let mut store = MemoryStore::default();
        let document = doc();
        let state = make_test_state(40);
        let (base_root, initial_stats) = write_state_v3(
            &mut store,
            document,
            &state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();
        assert!(initial_stats.new_objects > 0);

        let (noop_root, update_stats) = update_state_v3(
            &mut store,
            document,
            &base_root,
            &state,
            &state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        assert_eq!(noop_root, base_root);
        assert_eq!(update_stats.new_objects, 0);
        assert_eq!(update_stats.new_bytes, 0);
    }

    #[tokio::test]
    async fn update_state_v3_exact_oracle_equality_across_edits() {
        let mut store = MemoryStore::default();
        let document = doc();
        let base_state = make_test_state(40);
        let (base_root, _) = write_state_v3(
            &mut store,
            document,
            &base_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let mut target_state = base_state.clone();
        // 1. Add node (with blockId matching node id, testing restore_block_id)
        let new_id = NodeId("node_9999".into());
        target_state.nodes.insert(
            new_id.clone(),
            MaterializedNode {
                id: new_id.clone(),
                parent_id: None,
                node_type: "item".into(),
                pos: "9999".into(),
                current_fields: json!({"title": "new item", "blockId": "node_9999"}),
                var_name: None,
                deleted: false,
            },
        );
        // 2. Delete node
        target_state.nodes.remove(&NodeId("node_0005".into()));
        // 3. Modify node metadata only
        if let Some(n) = target_state.nodes.get_mut(&NodeId("node_0010".into())) {
            n.pos = "updated_pos".into();
            n.deleted = true;
        }
        // 4. Modify node fields with label == plain_text(content)
        if let Some(n) = target_state.nodes.get_mut(&NodeId("node_0020".into())) {
            n.current_fields = json!({
                "content": {"text": "hello world"},
                "label": "hello world",
                "changed": true
            });
        }
        // 5. Add, modify, delete comments
        target_state.comments.push(CommentState {
            node_id: None,
            body: "Appended comment".into(),
        });
        target_state.comments[0].body = "Updated comment 0".into();
        // 6. Suggestions edit
        target_state.suggestions.insert(
            "sugg_1".into(),
            SuggestionState {
                target_node_id: None,
                detail: json!({"extra": 123}),
                accepted: true,
                rejected_reason: Some("already done".into()),
            },
        );
        target_state.suggestions.remove("sugg_0");
        // 7. Removed choices edit
        target_state
            .removed_choices
            .insert(NodeId("choice_new".into()));
        target_state
            .removed_choices
            .remove(&NodeId("choice_deleted".into()));

        // Call update_state_v3
        let (update_root, stats) = update_state_v3(
            &mut store,
            document,
            &base_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        // Call write_state_v3 oracle on fresh store
        let mut oracle_store = MemoryStore::default();
        let (oracle_root, oracle_stats) = write_state_v3(
            &mut oracle_store,
            document,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        assert_eq!(update_root, oracle_root);
        assert!(stats.new_objects > 0);
        assert!(stats.new_objects < oracle_stats.new_objects);

        // Verify reconstruction
        let reconstructed = read_state_v3(
            &mut store,
            document,
            &update_root,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(reconstructed, target_state);
    }

    #[tokio::test]
    async fn update_state_v3_reused_fields_avoid_reencoding() {
        let mut store = MemoryStore::default();
        let document = doc();
        let mut base_state = DocumentState::default();
        let id = NodeId("node_0001".into());
        let large_fields = json!({
            "large_text": "a".repeat(10_000),
            "numbers": (0..100).collect::<Vec<_>>(),
            "blockId": "node_0001",
        });
        base_state.nodes.insert(
            id.clone(),
            MaterializedNode {
                id: id.clone(),
                parent_id: None,
                node_type: "block".into(),
                pos: "1".into(),
                current_fields: large_fields.clone(),
                var_name: None,
                deleted: false,
            },
        );
        let (base_root, _) = write_state_v3(
            &mut store,
            document,
            &base_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let mut target_state = base_state.clone();
        target_state.nodes.get_mut(&id).unwrap().pos = "2".into();

        let (new_root, update_stats) = update_state_v3(
            &mut store,
            document,
            &base_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let (oracle_root, _) = write_state_v3(
            &mut MemoryStore::default(),
            document,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(new_root, oracle_root);

        // 1 Node + 1 map leaf + 1 State root = 3 objects
        assert_eq!(update_stats.new_objects, 3);
        assert!(update_stats.new_bytes < 1000);
    }

    #[tokio::test]
    async fn update_state_v3_omission_flag_transitions_and_unicode() {
        let mut store = MemoryStore::default();
        let document = doc();
        let mut base_state = DocumentState::default();
        let id1 = NodeId("নথি_১".into());
        base_state.nodes.insert(
            id1.clone(),
            MaterializedNode {
                id: id1.clone(),
                parent_id: None,
                node_type: "অনচ্ছেদ".into(),
                pos: "১".into(),
                // Initial: blockId matches id1 (omitted), label != plain_text(content) (retained)
                current_fields: json!({
                    "blockId": "নথি_১",
                    "content": {"text": "বাংলা"},
                    "label": "কাস্টম লেবেল",
                    "emoji": "🎉🚀🦀"
                }),
                var_name: Some("চলক".into()),
                deleted: false,
            },
        );

        let (base_root, _) = write_state_v3(
            &mut store,
            document,
            &base_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let mut target_state = base_state.clone();
        // Transition: blockId changes so it NO LONGER matches id1 (omission flag flips to false)
        // and label changes to match plain_text(content) (omission flag flips to true)
        target_state.nodes.get_mut(&id1).unwrap().current_fields = json!({
            "blockId": "অন্য_আইডি",
            "content": {"text": "বাংলা"},
            "label": "বাংলা",
            "emoji": "🎉🚀🦀"
        });

        let (update_root, _) = update_state_v3(
            &mut store,
            document,
            &base_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let (oracle_root, _) = write_state_v3(
            &mut MemoryStore::default(),
            document,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        assert_eq!(update_root, oracle_root);

        let read_back = read_state_v3(
            &mut store,
            document,
            &update_root,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(read_back, target_state);
    }

    #[tokio::test]
    async fn update_state_v3_mismatched_node_ids_rejected() {
        let mut store = MemoryStore::default();
        let document = doc();
        let base_state = make_test_state(5);
        let (base_root, _) = write_state_v3(
            &mut store,
            document,
            &base_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let mut bad_target = base_state.clone();
        let mut bad_node = bad_target.nodes.values().next().unwrap().clone();
        bad_node.id = NodeId("different_id".into());
        bad_target.nodes.insert(NodeId("key_id".into()), bad_node);

        let err = update_state_v3(
            &mut store,
            document,
            &base_root,
            &base_state,
            &bad_target,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap_err();

        match err {
            Error::Invalid("node map key differs from logical id") => {}
            other => panic!("expected mismatched node id error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_state_v3_corrupt_base_fails_closed() {
        let mut store = MemoryStore::default();
        let document = doc();
        let base_state = make_test_state(5);
        let (_base_root, _) = write_state_v3(
            &mut store,
            document,
            &base_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let mut target_state = base_state.clone();
        target_state.nodes.values_mut().next().unwrap().pos = "99".into();

        // 1. Missing base root
        let missing_root =
            Address("0000000000000000000000000000000000000000000000000000000000000000".into());
        let err = update_state_v3(
            &mut store,
            document,
            &missing_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Missing(_)));

        // 2. Corrupt base root bytes
        let corrupt_root =
            Address("1111111111111111111111111111111111111111111111111111111111111111".into());
        store
            .objects
            .insert((document.0, corrupt_root.clone()), b"corrupted".to_vec());
        let err = update_state_v3(
            &mut store,
            document,
            &corrupt_root,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Invalid("typed header/version") | Error::HashMismatch
        ));

        // 3. Base root points to wrong object type (ObjectV3::Scalar instead of ObjectV3::State)
        let (scalar_addr, encoded) = encode_v3(&ObjectV3::Scalar(Value::Bool(true))).unwrap();
        store.put(document, &scalar_addr, &encoded).await.unwrap();
        let err = update_state_v3(
            &mut store,
            document,
            &scalar_addr,
            &base_state,
            &target_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Invalid("expected typed v3 state")));
    }

    #[tokio::test]
    async fn update_state_v3_semantic_limits_enforced_on_reused_content() {
        let mut store = MemoryStore::default();
        let document = doc();
        let base_state = make_test_state(20);
        let (base_root, _) = write_state_v3(
            &mut store,
            document,
            &base_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let tight_semantic = SemanticLimits {
            values: 5,
            string_bytes: 1024 * 1024,
            depth: 64,
        };
        let err = update_state_v3(
            &mut store,
            document,
            &base_root,
            &base_state,
            &base_state,
            Limits::default(),
            tight_semantic,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Limit("semantic values")));
    }

    #[tokio::test]
    async fn update_state_v3_io_limits_charge_only_new_objects() {
        let mut store = MemoryStore::default();
        let document = doc();
        let base_state = make_test_state(100);
        let (base_root, _) = write_state_v3(
            &mut store,
            document,
            &base_state,
            Limits::default(),
            SemanticLimits::default(),
        )
        .await
        .unwrap();

        let mut target_state = base_state.clone();
        target_state.nodes.values_mut().next().unwrap().pos = "updated".into();

        let tight_io = Limits {
            max_objects: 15,
            max_bytes: 1024 * 1024,
        };
        let res = update_state_v3(
            &mut store,
            document,
            &base_root,
            &base_state,
            &target_state,
            tight_io,
            SemanticLimits::default(),
        )
        .await;
        assert!(res.is_ok());

        // write_state_v3 from scratch would fail on tight_io.max_objects
        let mut store2 = MemoryStore::default();
        let err = write_state_v3(
            &mut store2,
            document,
            &target_state,
            tight_io,
            SemanticLimits::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Limit("objects")));
    }
}
