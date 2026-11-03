//! Opt-in, document-scoped shared checkpoints. See docs/SHARED-CHECKPOINTS.md.
//!
//! This codec preserves all `DocumentState` fields. It does not change event
//! hashes, select a large-asset backend, or provide a portable commit protocol.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;

use engine_shared::{DocumentId, NodeId};
use ring::digest::{digest, Context, SHA256};
use serde::{Deserialize, Serialize};

use crate::materializer::{CommentState, DocumentState, MaterializedNode, SuggestionState};

pub(crate) mod canonical;
pub mod content;
pub mod postgres;
pub mod typed;
use canonical::ObjectRef;

pub const MAX_OBJECT_BYTES: usize = 1024 * 1024;
/// Maximum values fetched together. PostgreSQL retains at most this many encoded
/// objects between batches (16 MiB with the per-object column/codec limit).
pub const READ_BATCH_OBJECTS: usize = 16;
/// Bounded encoded write buffer. A single maximum-size object fits by itself.
pub const WRITE_BATCH_OBJECTS: usize = 64;
pub const WRITE_BATCH_BYTES: usize = MAX_OBJECT_BYTES;
const LEAF_ENTRIES: usize = 32;
const DOMAIN: &[u8] = b"dynodoc.shared-checkpoint\0v1\0";

/// Canonical, lowercase hexadecimal SHA-256 address. Construction validates it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Address(String);

impl TryFrom<String> for Address {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid("invalid object address"));
        }
        Ok(Self(value))
    }
}

impl From<Address> for String {
    fn from(value: Address) -> String {
        value.0
    }
}

impl Address {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("shared checkpoint limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid shared checkpoint: {0}")]
    Invalid(&'static str),
    #[error("missing checkpoint object {0}")]
    Missing(String),
    #[error("checkpoint object hash mismatch")]
    HashMismatch,
    #[error("checkpoint codec: {0}")]
    Json(#[from] serde_json::Error),
    #[error("checkpoint content I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("checkpoint database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("checkpoint history: {0}")]
    History(#[from] crate::snapshot::SnapshotError),
}

/// Per-operation budgets, including reused objects. No request is unbounded.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_objects: usize,
    pub max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_objects: 1_000_000,
            max_bytes: 512 * 1024 * 1024,
        }
    }
}

impl Limits {
    pub(crate) fn consume(&mut self, bytes: usize) -> Result<(), Error> {
        self.max_objects = self
            .max_objects
            .checked_sub(1)
            .ok_or(Error::Limit("objects"))?;
        self.max_bytes = self
            .max_bytes
            .checked_sub(bytes)
            .ok_or(Error::Limit("bytes"))?;
        Ok(())
    }
}

/// Internal storage interface, not an authorization interface. Every operation
/// must be scoped to a document already authorized by the caller. `put` must
/// validate bytes/address and return true only when inserting a new object.
pub trait ObjectStore: Send {
    /// Results follow input order; repeated addresses report a new insertion at
    /// most once. Callers own rollback/atomic publication. Backends validate bytes.
    fn put_batch(
        &mut self,
        document: DocumentId,
        objects: &[(Address, Vec<u8>)],
    ) -> impl Future<Output = Result<Vec<bool>, Error>> + Send {
        async move {
            let mut inserted = Vec::with_capacity(objects.len());
            for (address, bytes) in objects {
                inserted.push(self.put(document, address, bytes).await?);
            }
            Ok(inserted)
        }
    }

    /// Optional bounded read-ahead. Every value still passes ordinary `get`,
    /// hash/type validation and budget accounting. A backend may ignore this hint.
    fn prefetch(
        &mut self,
        _document: DocumentId,
        _addresses: &[Address],
    ) -> impl Future<Output = Result<(), Error>> + Send {
        async { Ok(()) }
    }

    fn put(
        &mut self,
        document: DocumentId,
        address: &Address,
        bytes: &[u8],
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    fn get(
        &mut self,
        document: DocumentId,
        address: &Address,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;
}

/// Small local/test backend. Durability belongs to the PostgreSQL backend;
/// a durable on-disk local repository is a later increment.
#[derive(Default)]
pub struct MemoryStore {
    objects: BTreeMap<(uuid::Uuid, Address), Vec<u8>>,
}

impl MemoryStore {
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn stored_bytes(&self) -> usize {
        self.objects.values().map(Vec::len).sum()
    }
}

impl ObjectStore for MemoryStore {
    async fn put(
        &mut self,
        document: DocumentId,
        address: &Address,
        bytes: &[u8],
    ) -> Result<bool, Error> {
        validate_stored(address, bytes)?;
        let key = (document.0, address.clone());
        if let Some(existing) = self.objects.get(&key) {
            if existing != bytes {
                return Err(Error::HashMismatch);
            }
            return Ok(false);
        }
        self.objects.insert(key, bytes.to_vec());
        Ok(true)
    }

    async fn get(&mut self, document: DocumentId, address: &Address) -> Result<Vec<u8>, Error> {
        self.objects
            .get(&(document.0, address.clone()))
            .cloned()
            .ok_or_else(|| Error::Missing(address.0.clone()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    key: String,
    address: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateRoots {
    nodes: Address,
    comments: Address,
    suggestions: Address,
    removed_choices: Address,
}

impl StateRoots {
    fn addresses(self) -> Vec<Address> {
        vec![
            self.nodes,
            self.comments,
            self.suggestions,
            self.removed_choices,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Object {
    Node(MaterializedNode),
    Comment(CommentState),
    Suggestion(SuggestionState),
    RemovedChoice(NodeId),
    MapLeaf(Vec<Entry>),
    MapBranch(BTreeMap<String, Address>),
    State(StateRoots),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    object: Object,
}

fn address(bytes: &[u8]) -> Address {
    let mut hash = Context::new(&SHA256);
    hash.update(DOMAIN);
    hash.update(bytes);
    Address(hex(hash.finish().as_ref()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn route(key: &str) -> String {
    hex(digest(&SHA256, key.as_bytes()).as_ref())
}

#[cfg(test)]
fn encode(object: Object) -> Result<(Address, Vec<u8>), Error> {
    canonical::encode((&object).into(), MAX_OBJECT_BYTES)
}

fn decode(expected: &Address, bytes: &[u8]) -> Result<Object, Error> {
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(Error::Limit("object bytes"));
    }
    if &address(bytes) != expected {
        return Err(Error::HashMismatch);
    }
    let envelope: Envelope = serde_json::from_slice(bytes)?;
    if envelope.version != 1 {
        return Err(Error::Invalid("unsupported object version"));
    }
    // Also rejects duplicate/unknown fields and noncanonical numeric/string forms.
    canonical::matches((&envelope.object).into(), bytes)?;
    match &envelope.object {
        Object::MapLeaf(entries)
            if entries.len() > LEAF_ENTRIES || entries.windows(2).any(|w| w[0].key >= w[1].key) =>
        {
            return Err(Error::Invalid("map leaf order or size"));
        }
        Object::MapBranch(children)
            if children.is_empty()
                || children.len() > 16
                || children
                    .keys()
                    .any(|k| k.len() != 1 || !b"0123456789abcdef".contains(&k.as_bytes()[0])) =>
        {
            return Err(Error::Invalid("map branch slots"));
        }
        _ => {}
    }
    Ok(envelope.object)
}

// New content objects occupy the same document-scoped store, but have a separate
// version/hash domain. V1 state readers still require only v1 checkpoint objects.
/// Verify one encoded object and its address. This does not verify a complete
/// reachable graph and never grants access to an object or its document.
pub fn validate_stored(expected: &Address, bytes: &[u8]) -> Result<(), Error> {
    if bytes.starts_with(content::MAGIC) {
        content::validate(expected, bytes)
    } else if bytes.starts_with(typed::MAGIC) {
        typed::validate(expected, bytes)
    } else {
        decode(expected, bytes).map(|_| ())
    }
}

/// Direct child references of one stored object, after the same address and
/// canonical-form checks as [`validate_stored`]. Retention planning uses this to
/// walk a graph without reconstructing `DocumentState`; it grants no access and
/// does not verify that the referenced objects exist.
pub fn references(expected: &Address, bytes: &[u8]) -> Result<Vec<Address>, Error> {
    if bytes.starts_with(content::MAGIC) {
        content::references(expected, bytes)
    } else if bytes.starts_with(typed::MAGIC) {
        typed::references(expected, bytes)
    } else {
        Ok(match decode(expected, bytes)? {
            Object::MapLeaf(entries) => entries.into_iter().map(|entry| entry.address).collect(),
            Object::MapBranch(children) => children.into_values().collect(),
            Object::State(roots) => roots.addresses(),
            Object::Node(_)
            | Object::Comment(_)
            | Object::Suggestion(_)
            | Object::RemovedChoice(_) => Vec::new(),
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct WriteStats {
    pub visited_objects: usize,
    pub encoded_bytes: usize,
    pub new_objects: usize,
    pub new_bytes: usize,
}

struct Writer<'a, S> {
    store: &'a mut S,
    document: DocumentId,
    budget: Limits,
    stats: WriteStats,
    pending: Vec<(Address, Vec<u8>)>,
    pending_bytes: usize,
}

impl<S: ObjectStore + Send> Writer<'_, S> {
    async fn object(&mut self, object: Object) -> Result<Address, Error> {
        self.value((&object).into()).await
    }

    async fn value(&mut self, object: ObjectRef<'_>) -> Result<Address, Error> {
        if self.budget.max_objects == 0 {
            return Err(Error::Limit("objects"));
        }
        let (address, bytes) = canonical::encode(object, self.budget.max_bytes)?;
        self.encoded(address, bytes).await
    }

    async fn encoded(&mut self, address: Address, bytes: Vec<u8>) -> Result<Address, Error> {
        self.budget.consume(bytes.len())?;
        self.stats.visited_objects += 1;
        self.stats.encoded_bytes += bytes.len();
        if self.pending.len() == WRITE_BATCH_OBJECTS
            || self.pending_bytes + bytes.len() > WRITE_BATCH_BYTES
        {
            self.flush().await?;
        }
        self.pending_bytes += bytes.len();
        self.pending.push((address.clone(), bytes));
        Ok(address)
    }

    async fn flush(&mut self) -> Result<(), Error> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let inserted = self.store.put_batch(self.document, &self.pending).await?;
        if inserted.len() != self.pending.len() {
            return Err(Error::Invalid("batch result length"));
        }
        for ((_, bytes), new) in self.pending.drain(..).zip(inserted) {
            if new {
                self.stats.new_objects += 1;
                self.stats.new_bytes += bytes.len();
            }
        }
        self.pending_bytes = 0;
        Ok(())
    }

    // Entries are keyed by (hash route, original key), so splitting borrows slices
    // instead of copying all entries at every depth.
    async fn map(&mut self, entries: &[(String, Entry)], depth: usize) -> Result<Address, Error> {
        if entries.len() <= LEAF_ENTRIES {
            let mut leaf: Vec<_> = entries.iter().map(|(_, e)| e.clone()).collect();
            leaf.sort_by(|a, b| a.key.cmp(&b.key));
            return self.object(Object::MapLeaf(leaf)).await;
        }
        if depth == 64 {
            return Err(Error::Limit("radix depth"));
        }
        let mut children = BTreeMap::new();
        let mut start = 0;
        while start < entries.len() {
            let nibble = &entries[start].0[depth..depth + 1];
            let length = entries[start..].partition_point(|(r, _)| &r[depth..depth + 1] == nibble);
            let child = Box::pin(self.map(&entries[start..start + length], depth + 1)).await?;
            children.insert(nibble.to_owned(), child);
            start += length;
        }
        self.object(Object::MapBranch(children)).await
    }

    async fn entries(&mut self, mut entries: Vec<(String, Entry)>) -> Result<Address, Error> {
        entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.key.cmp(&b.1.key)));
        self.map(&entries, 0).await
    }

    async fn read_object(&mut self, address: &Address) -> Result<Object, Error> {
        if self.budget.max_objects == 0 {
            return Err(Error::Limit("objects"));
        }
        let bytes = self.store.get(self.document, address).await?;
        self.budget.consume(bytes.len())?;
        decode(address, &bytes)
    }

    async fn update_node(
        &mut self,
        current: Option<&Address>,
        depth: usize,
        prefix: &str,
        edits: &[PreparedEdit],
    ) -> Result<NodeOutcome, Error> {
        if depth > 64 {
            return Err(Error::Limit("radix depth"));
        }

        if let Some(curr_addr) = current {
            let obj = self.read_object(curr_addr).await?;
            match obj {
                Object::MapLeaf(mut leaf) => {
                    let original_leaf = leaf.clone();
                    for edit in edits {
                        match &edit.address {
                            Some(new_addr) => {
                                match leaf.binary_search_by(|e| e.key.as_str().cmp(&edit.key)) {
                                    Ok(idx) => {
                                        leaf[idx].address = new_addr.clone();
                                    }
                                    Err(idx) => {
                                        leaf.insert(
                                            idx,
                                            Entry {
                                                key: edit.key.clone(),
                                                address: new_addr.clone(),
                                            },
                                        );
                                    }
                                }
                            }
                            None => {
                                if let Ok(idx) =
                                    leaf.binary_search_by(|e| e.key.as_str().cmp(&edit.key))
                                {
                                    leaf.remove(idx);
                                }
                            }
                        }
                    }

                    if leaf.len() <= LEAF_ENTRIES {
                        if leaf.is_empty() {
                            if depth == 0 {
                                if original_leaf.is_empty() {
                                    return Ok(NodeOutcome {
                                        address: Some(curr_addr.clone()),
                                        count: SubtreeCount::Exact(Vec::new()),
                                    });
                                }
                                let addr = self.object(Object::MapLeaf(Vec::new())).await?;
                                return Ok(NodeOutcome {
                                    address: Some(addr),
                                    count: SubtreeCount::Exact(Vec::new()),
                                });
                            }
                            return Ok(NodeOutcome {
                                address: None,
                                count: SubtreeCount::Exact(Vec::new()),
                            });
                        }
                        if leaf == original_leaf {
                            return Ok(NodeOutcome {
                                address: Some(curr_addr.clone()),
                                count: SubtreeCount::Exact(leaf),
                            });
                        }
                        let addr = self.object(Object::MapLeaf(leaf.clone())).await?;
                        return Ok(NodeOutcome {
                            address: Some(addr),
                            count: SubtreeCount::Exact(leaf),
                        });
                    }

                    // leaf.len() > LEAF_ENTRIES: leaf must split
                    let mut routed: Vec<(String, Entry)> =
                        leaf.into_iter().map(|e| (route(&e.key), e)).collect();
                    routed.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.key.cmp(&b.1.key)));
                    let addr = self.map(&routed, depth).await?;
                    Ok(NodeOutcome {
                        address: Some(addr),
                        count: SubtreeCount::Many,
                    })
                }
                Object::MapBranch(mut children) => {
                    let original_children = children.clone();
                    let mut start = 0;
                    let mut child_outcomes: BTreeMap<String, NodeOutcome> = BTreeMap::new();
                    while start < edits.len() {
                        let nibble = &edits[start].route[depth..depth + 1];
                        let length = edits[start..]
                            .partition_point(|e| &e.route[depth..depth + 1] == nibble);
                        let slice = &edits[start..start + length];
                        start += length;

                        let child_curr = children.get(nibble);
                        let outcome = Box::pin(self.update_node(
                            child_curr,
                            depth + 1,
                            &format!("{prefix}{nibble}"),
                            slice,
                        ))
                        .await?;
                        child_outcomes.insert(nibble.to_owned(), outcome);
                    }

                    for (nibble, outcome) in &child_outcomes {
                        match &outcome.address {
                            Some(addr) => {
                                children.insert(nibble.clone(), addr.clone());
                            }
                            None => {
                                children.remove(nibble);
                            }
                        }
                    }

                    // Check for collapse
                    if children.is_empty() {
                        if depth == 0 {
                            let addr = self.object(Object::MapLeaf(Vec::new())).await?;
                            return Ok(NodeOutcome {
                                address: Some(addr),
                                count: SubtreeCount::Exact(Vec::new()),
                            });
                        }
                        return Ok(NodeOutcome {
                            address: None,
                            count: SubtreeCount::Exact(Vec::new()),
                        });
                    }

                    let mut can_collapse = true;
                    let mut total_entries = Vec::new();

                    for (nibble, child_addr) in &children {
                        if let Some(outcome) = child_outcomes.get(nibble) {
                            match &outcome.count {
                                SubtreeCount::Exact(entries) => {
                                    total_entries.extend(entries.iter().cloned());
                                    if total_entries.len() > LEAF_ENTRIES {
                                        can_collapse = false;
                                        break;
                                    }
                                }
                                SubtreeCount::Many => {
                                    can_collapse = false;
                                    break;
                                }
                            }
                        } else {
                            let child_obj = self.read_object(child_addr).await?;
                            match child_obj {
                                Object::MapLeaf(entries) => {
                                    total_entries.extend(entries);
                                    if total_entries.len() > LEAF_ENTRIES {
                                        can_collapse = false;
                                        break;
                                    }
                                }
                                Object::MapBranch(_) => {
                                    can_collapse = false;
                                    break;
                                }
                                _ => return Err(Error::Invalid("expected map child")),
                            }
                        }
                    }

                    if can_collapse && total_entries.len() <= LEAF_ENTRIES {
                        total_entries.sort_by(|a, b| a.key.cmp(&b.key));
                        let addr = self.object(Object::MapLeaf(total_entries.clone())).await?;
                        return Ok(NodeOutcome {
                            address: Some(addr),
                            count: SubtreeCount::Exact(total_entries),
                        });
                    }

                    if children == original_children {
                        return Ok(NodeOutcome {
                            address: Some(curr_addr.clone()),
                            count: SubtreeCount::Many,
                        });
                    }

                    let addr = self.object(Object::MapBranch(children)).await?;
                    Ok(NodeOutcome {
                        address: Some(addr),
                        count: SubtreeCount::Many,
                    })
                }
                _ => Err(Error::Invalid("expected bounded map")),
            }
        } else {
            // New subtree from edits
            let insertions: Vec<Entry> = edits
                .iter()
                .filter_map(|e| {
                    e.address.as_ref().map(|addr| Entry {
                        key: e.key.clone(),
                        address: addr.clone(),
                    })
                })
                .collect();

            if insertions.is_empty() {
                return Ok(NodeOutcome {
                    address: None,
                    count: SubtreeCount::Exact(Vec::new()),
                });
            }

            if insertions.len() <= LEAF_ENTRIES {
                let mut leaf = insertions;
                leaf.sort_by(|a, b| a.key.cmp(&b.key));
                let addr = self.object(Object::MapLeaf(leaf.clone())).await?;
                return Ok(NodeOutcome {
                    address: Some(addr),
                    count: SubtreeCount::Exact(leaf),
                });
            }

            let mut routed: Vec<(String, Entry)> =
                insertions.into_iter().map(|e| (route(&e.key), e)).collect();
            routed.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.key.cmp(&b.1.key)));
            let addr = self.map(&routed, depth).await?;
            Ok(NodeOutcome {
                address: Some(addr),
                count: SubtreeCount::Many,
            })
        }
    }

    pub async fn update_map(
        &mut self,
        base_root: &Address,
        edits: impl IntoIterator<Item = (String, Option<Address>)>,
    ) -> Result<Address, Error> {
        let mut prepared: Vec<PreparedEdit> = edits
            .into_iter()
            .map(|(key, address)| {
                let r = route(&key);
                PreparedEdit {
                    route: r,
                    key,
                    address,
                }
            })
            .collect();
        prepared.sort_by(|a, b| a.route.cmp(&b.route).then(a.key.cmp(&b.key)));
        let mut deduped: Vec<PreparedEdit> = Vec::with_capacity(prepared.len());
        for edit in prepared {
            if let Some(last) = deduped.last_mut() {
                if last.key == edit.key {
                    *last = edit;
                    continue;
                }
            }
            deduped.push(edit);
        }
        if deduped.is_empty() {
            let obj = self.read_object(base_root).await?;
            match obj {
                Object::MapLeaf(_) | Object::MapBranch(_) => return Ok(base_root.clone()),
                _ => return Err(Error::Invalid("expected bounded map root")),
            }
        }
        let outcome = self.update_node(Some(base_root), 0, "", &deduped).await?;
        let root = outcome
            .address
            .unwrap_or_else(|| unreachable!("depth 0 must always return Some address"));
        Ok(root)
    }
}

enum SubtreeCount {
    Exact(Vec<Entry>),
    Many,
}

struct NodeOutcome {
    address: Option<Address>,
    count: SubtreeCount,
}

struct PreparedEdit {
    route: String,
    key: String,
    address: Option<Address>,
}

/// Write a canonical radix map from entries, producing the full writer's canonical layout.
pub async fn write_map<S: ObjectStore + Send>(
    store: &mut S,
    document: DocumentId,
    entries: impl IntoIterator<Item = (String, Address)>,
    limits: Limits,
) -> Result<(Address, WriteStats), Error> {
    let mut writer = Writer {
        store,
        document,
        budget: limits,
        stats: WriteStats::default(),
        pending: Vec::new(),
        pending_bytes: 0,
    };
    let routed: Vec<(String, Entry)> = entries
        .into_iter()
        .map(|(key, address)| (route(&key), Entry { key, address }))
        .collect();
    let root = writer.entries(routed).await?;
    writer.flush().await?;
    Ok((root, writer.stats))
}

/// Incrementally update an existing verified map root with insert, replace, and delete operations.
/// Reuses unchanged child subtrees while strictly reproducing the canonical layout.
pub async fn update_map<S: ObjectStore + Send>(
    store: &mut S,
    document: DocumentId,
    base_root: &Address,
    edits: impl IntoIterator<Item = (String, Option<Address>)>,
    limits: Limits,
) -> Result<(Address, WriteStats), Error> {
    let mut writer = Writer {
        store,
        document,
        budget: limits,
        stats: WriteStats::default(),
        pending: Vec::new(),
        pending_bytes: 0,
    };
    let root = writer.update_map(base_root, edits).await?;
    writer.flush().await?;
    Ok((root, writer.stats))
}

/// Read all entries from a canonical radix map root into an in-memory map.
pub async fn read_map<S: ObjectStore + Send>(
    store: &mut S,
    document: DocumentId,
    root: &Address,
    limits: Limits,
) -> Result<BTreeMap<String, Address>, Error> {
    let mut reader = Reader {
        store,
        document,
        budget: limits,
    };
    reader.entries(root).await
}

/// Write a deterministic shared state graph. The store's caller controls atomic
/// publication; use `postgres::take` for transactionally published checkpoints.
pub async fn write_state<S: ObjectStore + Send>(
    store: &mut S,
    document: DocumentId,
    state: &DocumentState,
    limits: Limits,
) -> Result<(Address, WriteStats), Error> {
    let mut writer = Writer {
        store,
        document,
        budget: limits,
        stats: WriteStats::default(),
        pending: Vec::new(),
        pending_bytes: 0,
    };
    let mut entries = Vec::new();
    for (id, node) in &state.nodes {
        if id != &node.id {
            return Err(Error::Invalid("node map key differs from logical id"));
        }
        let address = writer.value(ObjectRef::Node(node)).await?;
        entries.push((
            route(&id.0),
            Entry {
                key: id.0.clone(),
                address,
            },
        ));
    }
    let nodes = writer.entries(entries).await?;
    let mut entries = Vec::new();
    for (index, comment) in state.comments.iter().enumerate() {
        let key = format!("{index:016x}");
        let address = writer.value(ObjectRef::Comment(comment)).await?;
        entries.push((route(&key), Entry { key, address }));
    }
    let comments = writer.entries(entries).await?;
    let mut entries = Vec::new();
    for (key, suggestion) in &state.suggestions {
        let address = writer.value(ObjectRef::Suggestion(suggestion)).await?;
        entries.push((
            route(key),
            Entry {
                key: key.clone(),
                address,
            },
        ));
    }
    let suggestions = writer.entries(entries).await?;
    let mut entries = Vec::new();
    // Deterministic insertion order also prevents same-revision publishers from
    // locking shared object rows in opposite orders (HashSet order is randomized).
    let mut removed: Vec<_> = state.removed_choices.iter().collect();
    removed.sort();
    for id in removed {
        let address = writer.value(ObjectRef::RemovedChoice(id)).await?;
        entries.push((
            route(&id.0),
            Entry {
                key: id.0.clone(),
                address,
            },
        ));
    }
    let removed_choices = writer.entries(entries).await?;
    let root = writer
        .object(Object::State(StateRoots {
            nodes,
            comments,
            suggestions,
            removed_choices,
        }))
        .await?;
    writer.flush().await?;
    Ok((root, writer.stats))
}

struct Reader<'a, S> {
    store: &'a mut S,
    document: DocumentId,
    budget: Limits,
}

impl<S: ObjectStore + Send> Reader<'_, S> {
    async fn object(&mut self, address: &Address) -> Result<Object, Error> {
        // Check object budget before the backend read; bytes are capped by codec
        // and the PostgreSQL column constraint. Backends must bound their fetch.
        if self.budget.max_objects == 0 {
            return Err(Error::Limit("objects"));
        }
        let bytes = self.store.get(self.document, address).await?;
        self.budget.consume(bytes.len())?;
        decode(address, &bytes)
    }

    async fn entries(&mut self, root: &Address) -> Result<BTreeMap<String, Address>, Error> {
        self.entries_limited(root, usize::MAX, usize::MAX).await
    }

    async fn entries_limited(
        &mut self,
        root: &Address,
        max_entries: usize,
        max_key_bytes: usize,
    ) -> Result<BTreeMap<String, Address>, Error> {
        let mut entries = BTreeMap::new();
        // Breadth-first batches avoid retaining decoded ancestors or losing a
        // sibling prefetch when recursion replaces the cache. Only references
        // and (parent, subtree count) accounting survive between batches.
        let mut queue = VecDeque::from([(root.clone(), String::new(), None)]);
        let mut counts: Vec<(Option<usize>, usize, bool)> = Vec::new();
        while !queue.is_empty() {
            if queue.len() > self.budget.max_objects {
                return Err(Error::Limit("objects"));
            }
            let batch: Vec<_> = queue.drain(..queue.len().min(READ_BATCH_OBJECTS)).collect();
            let addresses: Vec<_> = batch
                .iter()
                .map(|(address, _, _)| address.clone())
                .collect();
            self.store.prefetch(self.document, &addresses).await?;
            let batch_len = batch.len();
            for (offset, (address, prefix, parent)) in batch.into_iter().enumerate() {
                match self.object(&address).await? {
                    Object::MapLeaf(leaf) => {
                        counts.push((parent, leaf.len(), false));
                        for entry in leaf {
                            if entries.len() == max_entries || entry.key.len() > max_key_bytes {
                                return Err(Error::Limit("map entries or key bytes"));
                            }
                            if !route(&entry.key).starts_with(&prefix)
                                || entries.insert(entry.key, entry.address).is_some()
                            {
                                return Err(Error::Invalid("map key route or duplicate"));
                            }
                        }
                    }
                    Object::MapBranch(children) if prefix.len() < 64 => {
                        // Bound queued references before allocating more. Object
                        // visits (including repeated refs) consume the same budget.
                        if queue.len() + children.len() + batch_len - offset - 1
                            > self.budget.max_objects
                        {
                            return Err(Error::Limit("objects"));
                        }
                        let index = counts.len();
                        counts.push((parent, 0, true));
                        for (slot, child) in children {
                            queue.push_back((child, format!("{prefix}{slot}"), Some(index)));
                        }
                    }
                    _ => return Err(Error::Invalid("expected bounded map")),
                }
            }
        }
        for index in (0..counts.len()).rev() {
            let (parent, count, branch) = counts[index];
            if branch && count <= LEAF_ENTRIES {
                return Err(Error::Invalid("unnecessary map branch"));
            }
            if let Some(parent) = parent {
                if count == 0 {
                    return Err(Error::Invalid("empty branch child"));
                }
                counts[parent].1 += count;
            }
        }
        Ok(entries)
    }

    async fn values(
        &mut self,
        root: &Address,
        mut apply: impl FnMut(String, Object) -> Result<(), Error> + Send,
    ) -> Result<(), Error> {
        let mut entries = self.entries(root).await?.into_iter();
        loop {
            let batch: Vec<_> = entries.by_ref().take(READ_BATCH_OBJECTS).collect();
            if batch.is_empty() {
                return Ok(());
            }
            if self.budget.max_objects < batch.len() {
                return Err(Error::Limit("objects"));
            }
            let addresses: Vec<_> = batch.iter().map(|(_, address)| address.clone()).collect();
            self.store.prefetch(self.document, &addresses).await?;
            for (key, address) in batch {
                apply(key, self.object(&address).await?)?;
            }
        }
    }
}

/// Verify every reachable object's bytes, type and map structure and reconstruct
/// the complete state. Missing/corrupt content never falls back to legacy data.
pub async fn read_state<S: ObjectStore + Send>(
    store: &mut S,
    document: DocumentId,
    root: &Address,
    limits: Limits,
) -> Result<DocumentState, Error> {
    let mut reader = Reader {
        store,
        document,
        budget: limits,
    };
    let Object::State(roots) = reader.object(root).await? else {
        return Err(Error::Invalid("expected state root"));
    };
    let mut state = DocumentState::default();
    reader
        .values(&roots.nodes, |key, object| {
            match object {
                Object::Node(node) if node.id.0 == key => {
                    state.nodes.insert(node.id.clone(), node);
                }
                _ => return Err(Error::Invalid("node type or logical id")),
            }
            Ok(())
        })
        .await?;
    reader
        .values(&roots.comments, |key, object| {
            match object {
                Object::Comment(comment) if key == format!("{:016x}", state.comments.len()) => {
                    state.comments.push(comment)
                }
                _ => return Err(Error::Invalid("comment type or ordinal")),
            }
            Ok(())
        })
        .await?;
    reader
        .values(&roots.suggestions, |key, object| {
            match object {
                Object::Suggestion(suggestion) => {
                    state.suggestions.insert(key, suggestion);
                }
                _ => return Err(Error::Invalid("suggestion type")),
            }
            Ok(())
        })
        .await?;
    reader
        .values(&roots.removed_choices, |key, object| {
            match object {
                Object::RemovedChoice(id) if id.0 == key => {
                    state.removed_choices.insert(id);
                }
                _ => return Err(Error::Invalid("removed choice type or id")),
            }
            Ok(())
        })
        .await?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    pub(super) fn fixture(count: usize) -> DocumentState {
        let mut state = DocumentState::default();
        for i in 0..count {
            let id = NodeId(format!("{i:026}"));
            state.nodes.insert(
                id.clone(),
                MaterializedNode {
                    id,
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: format!("p{i:08}"),
                    current_fields: json!({"text": "বাংলা 🦀", "number": 1.25, "zero": -0.0}),
                    var_name: None,
                    deleted: i % 3 == 0,
                },
            );
        }
        state.comments = vec![
            CommentState {
                node_id: None,
                body: "First".into(),
            },
            CommentState {
                node_id: None,
                body: "Second".into(),
            },
        ];
        state.suggestions.insert(
            "suggestion".into(),
            SuggestionState {
                target_node_id: None,
                detail: json!({"a": 1}),
                accepted: false,
                rejected_reason: Some("No".into()),
            },
        );
        state
            .removed_choices
            .extend([NodeId("removed-a".into()), NodeId("removed-b".into())]);
        state
    }

    #[test]
    fn canonical_hash_vectors_and_version_rejection() {
        // Independently calculated using Python hashlib; freeze the byte contract.
        let (hash, bytes) = encode(Object::MapLeaf(vec![])).unwrap();
        assert_eq!(
            bytes,
            br#"{"object":{"kind":"map_leaf","value":[]},"version":1}"#
        );
        assert_eq!(
            hash.as_str(),
            "efaaafd1e1dec0e21809e614a073b33740339414045d8070c7820386f73e981b"
        );
        let (hash, bytes) = encode(Object::Comment(CommentState {
            node_id: None,
            body: "বাংলা 🦀\n".into(),
        }))
        .unwrap();
        assert_eq!(
            hash.as_str(),
            "d083d9ebaa357c47fd8875b5eaaaebaac345fcb14621fde6c42ea5d7b96eb5bd"
        );
        assert!(matches!(decode(&hash, &bytes), Ok(Object::Comment(_))));
        let future = br#"{"object":{"kind":"map_leaf","value":[]},"version":2}"#;
        assert!(matches!(
            decode(&address(future), future),
            Err(Error::Invalid("unsupported object version"))
        ));
        let noncanonical = b"{ \"object\":{\"kind\":\"map_leaf\",\"value\":[]},\"version\":1}";
        assert!(decode(&address(noncanonical), noncanonical).is_err());
        for bad in ["A".repeat(64), "f".repeat(63), "g".repeat(64)] {
            assert!(Address::try_from(bad).is_err());
        }
    }

    #[tokio::test]
    async fn full_state_round_trip_reuses_objects_and_is_document_scoped() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = MemoryStore::default();
        let mut state = fixture(1500);
        let (root, first) = write_state(&mut store, doc, &state, Limits::default())
            .await
            .unwrap();
        assert_eq!(
            read_state(&mut store, doc, &root, Limits::default())
                .await
                .unwrap(),
            state
        );
        let (again, retry) = write_state(&mut store, doc, &state, Limits::default())
            .await
            .unwrap();
        assert_eq!(root, again);
        assert_eq!(retry.new_bytes, 0);
        assert_eq!(retry.new_objects, 0);
        // One content edit changes one value and its radix path, not other values.
        state.nodes.values_mut().nth(700).unwrap().current_fields["text"] = json!("Edited");
        let (edited, delta) = write_state(&mut store, doc, &state, Limits::default())
            .await
            .unwrap();
        assert_ne!(root, edited);
        assert!(delta.new_objects <= 6, "{delta:?}");
        assert!(delta.new_bytes < first.new_bytes / 20, "{delta:?}");
        assert_eq!(
            read_state(&mut store, doc, &edited, Limits::default())
                .await
                .unwrap(),
            state
        );
        // Insertion also changes only a bounded path; no fixed-size array suffix rewrite.
        let mut node = state.nodes.values().next().unwrap().clone();
        node.id = NodeId("an-inserted-id".into());
        state.nodes.insert(node.id.clone(), node);
        let (_, insert) = write_state(&mut store, doc, &state, Limits::default())
            .await
            .unwrap();
        assert!(insert.new_objects <= 20, "{insert:?}");
        let other = DocumentId(uuid::Uuid::new_v4());
        assert!(matches!(
            read_state(&mut store, other, &root, Limits::default()).await,
            Err(Error::Missing(_))
        ));
        let (_, other_stats) = write_state(&mut store, other, &fixture(1500), Limits::default())
            .await
            .unwrap();
        assert_eq!(first.new_bytes, other_stats.new_bytes);
    }

    /// Breadth-first walk of verified direct references from `root`.
    pub(super) async fn reachable(
        store: &mut MemoryStore,
        document: DocumentId,
        root: &Address,
    ) -> std::collections::BTreeSet<Address> {
        let mut seen = std::collections::BTreeSet::new();
        let mut queue = vec![root.clone()];
        while let Some(address) = queue.pop() {
            if seen.insert(address.clone()) {
                let bytes = store.get(document, &address).await.unwrap();
                queue.extend(references(&address, &bytes).unwrap());
            }
        }
        seen
    }

    #[tokio::test]
    async fn reference_walk_reaches_exactly_the_written_v1_graph() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = MemoryStore::default();
        let (root, _) = write_state(&mut store, doc, &fixture(300), Limits::default())
            .await
            .unwrap();
        assert!(store.object_count() > 300);
        assert_eq!(
            reachable(&mut store, doc, &root).await.len(),
            store.object_count()
        );
        let bytes = store.get(doc, &root).await.unwrap();
        // Another object's bytes under this address are a hash mismatch, not a reference list.
        let other = Address::try_from("ab".repeat(32)).unwrap();
        assert!(matches!(
            references(&other, &bytes),
            Err(Error::HashMismatch)
        ));
    }

    #[tokio::test]
    async fn every_state_component_changes_the_commitment() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = MemoryStore::default();
        let state = fixture(4);
        let (original, _) = write_state(&mut store, doc, &state, Limits::default())
            .await
            .unwrap();
        for change in 0..5 {
            let mut altered = state.clone();
            match change {
                0 => altered.comments.reverse(),
                1 => altered.suggestions.get_mut("suggestion").unwrap().accepted = true,
                2 => altered.removed_choices.clear(),
                3 => altered.nodes.values_mut().next().unwrap().deleted = false,
                _ => altered.nodes.values_mut().next().unwrap().pos = "moved".into(),
            }
            let (root, _) = write_state(&mut store, doc, &altered, Limits::default())
                .await
                .unwrap();
            assert_ne!(original, root);
            assert_eq!(
                read_state(&mut store, doc, &root, Limits::default())
                    .await
                    .unwrap(),
                altered
            );
        }
    }

    #[tokio::test]
    async fn missing_corrupt_and_wrongly_typed_references_fail_closed() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = MemoryStore::default();
        let state = fixture(3);
        let (root, _) = write_state(&mut store, doc, &state, Limits::default())
            .await
            .unwrap();
        let node_key = store
            .objects
            .iter()
            .find(|(_, bytes)| matches!(decode(&address(bytes), bytes), Ok(Object::Node(_))))
            .unwrap()
            .0
            .clone();
        store.objects.remove(&node_key).unwrap();
        assert!(matches!(
            read_state(&mut store, doc, &root, Limits::default()).await,
            Err(Error::Missing(_))
        ));
        store.objects.insert(node_key, b"corrupt".to_vec());
        assert!(matches!(
            read_state(&mut store, doc, &root, Limits::default()).await,
            Err(Error::HashMismatch)
        ));
        let (leaf, leaf_bytes) = encode(Object::MapLeaf(vec![])).unwrap();
        store.put(doc, &leaf, &leaf_bytes).await.unwrap();
        let (bad_root, bytes) = encode(Object::State(StateRoots {
            nodes: root.clone(),
            comments: leaf.clone(),
            suggestions: leaf.clone(),
            removed_choices: leaf,
        }))
        .unwrap();
        store.put(doc, &bad_root, &bytes).await.unwrap();
        assert!(matches!(
            read_state(&mut store, doc, &bad_root, Limits::default()).await,
            Err(Error::Invalid("expected bounded map"))
        ));
        assert!(store.put(doc, &root, &bytes).await.is_err());
        assert!(!bytes.is_empty());
    }

    #[tokio::test]
    async fn budgets_and_oversized_objects_are_rejected() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = MemoryStore::default();
        let mut state = fixture(1);
        let (root, _) = write_state(&mut store, doc, &state, Limits::default())
            .await
            .unwrap();
        for limit in [
            Limits {
                max_objects: 1,
                max_bytes: usize::MAX,
            },
            Limits {
                max_objects: usize::MAX,
                max_bytes: 1,
            },
        ] {
            assert!(matches!(
                write_state(&mut store, doc, &state, limit).await,
                Err(Error::Limit(_))
            ));
            assert!(matches!(
                read_state(&mut store, doc, &root, limit).await,
                Err(Error::Limit(_))
            ));
        }
        state.nodes.values_mut().next().unwrap().current_fields =
            json!({"text": "x".repeat(MAX_OBJECT_BYTES)});
        assert!(matches!(
            write_state(&mut store, doc, &state, Limits::default()).await,
            Err(Error::Limit("object bytes"))
        ));
    }

    #[tokio::test]
    async fn malformed_map_routes_and_comment_ordinals_are_rejected() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = MemoryStore::default();
        let (empty, bytes) = encode(Object::MapLeaf(vec![])).unwrap();
        store.put(doc, &empty, &bytes).await.unwrap();
        let (comment, bytes) = encode(Object::Comment(CommentState {
            node_id: None,
            body: "A".into(),
        }))
        .unwrap();
        store.put(doc, &comment, &bytes).await.unwrap();
        let key = "0000000000000001".to_owned(); // ordinal zero is missing
        let entry = Entry {
            key: key.clone(),
            address: comment,
        };
        let (leaf, bytes) = encode(Object::MapLeaf(vec![entry.clone()])).unwrap();
        store.put(doc, &leaf, &bytes).await.unwrap();
        let roots = |comments| {
            Object::State(StateRoots {
                nodes: empty.clone(),
                comments,
                suggestions: empty.clone(),
                removed_choices: empty.clone(),
            })
        };
        let (root, bytes) = encode(roots(leaf.clone())).unwrap();
        store.put(doc, &root, &bytes).await.unwrap();
        assert!(matches!(
            read_state(&mut store, doc, &root, Limits::default()).await,
            Err(Error::Invalid("comment type or ordinal"))
        ));
        let wrong_slot = if route(&key).starts_with('0') {
            "1"
        } else {
            "0"
        };
        let (branch, bytes) = encode(Object::MapBranch(BTreeMap::from([(
            wrong_slot.to_owned(),
            leaf,
        )])))
        .unwrap();
        store.put(doc, &branch, &bytes).await.unwrap();
        let (root, bytes) = encode(roots(branch)).unwrap();
        store.put(doc, &root, &bytes).await.unwrap();
        assert!(matches!(
            read_state(&mut store, doc, &root, Limits::default()).await,
            Err(Error::Invalid("map key route or duplicate"))
        ));
        let (duplicate, bytes) = encode(Object::MapLeaf(vec![entry.clone(), entry])).unwrap();
        assert!(matches!(
            store.put(doc, &duplicate, &bytes).await,
            Err(Error::Invalid("map leaf order or size"))
        ));
    }

    #[derive(Default)]
    struct TrackingStore {
        inner: MemoryStore,
        gets: std::sync::atomic::AtomicUsize,
        puts: std::sync::atomic::AtomicUsize,
    }

    impl ObjectStore for TrackingStore {
        async fn put(
            &mut self,
            document: DocumentId,
            address: &Address,
            bytes: &[u8],
        ) -> Result<bool, Error> {
            self.puts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.put(document, address, bytes).await
        }

        async fn get(&mut self, document: DocumentId, address: &Address) -> Result<Vec<u8>, Error> {
            self.gets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.get(document, address).await
        }
    }

    struct SimpleRng(u64);
    impl SimpleRng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
        }
        fn range(&mut self, max: usize) -> usize {
            (self.next_u64() as usize) % max
        }
    }

    #[tokio::test]
    async fn randomized_incremental_updates_match_full_writer_exactly() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = MemoryStore::default();
        let mut rng = SimpleRng(42);

        let mut oracle: BTreeMap<String, Address> = BTreeMap::new();
        let (mut current_root, _) = write_map(&mut store, doc, oracle.clone(), Limits::default())
            .await
            .unwrap();

        for round in 0..100 {
            let mut edits = Vec::new();
            let num_edits = 1 + rng.range(10);
            for _ in 0..num_edits {
                let action = rng.range(3);
                match action {
                    0 | 1 => {
                        // Insert or update
                        let key = format!("key_{:04x}", rng.range(200));
                        let val = Address(format!("{:064x}", rng.next_u64()));
                        oracle.insert(key.clone(), val.clone());
                        edits.push((key, Some(val)));
                    }
                    _ => {
                        // Delete
                        let key = if !oracle.is_empty() && (rng.range(10) < 7) {
                            let keys: Vec<_> = oracle.keys().cloned().collect();
                            keys[rng.range(keys.len())].clone()
                        } else {
                            format!("nonexistent_{:04x}", rng.range(50))
                        };
                        oracle.remove(&key);
                        edits.push((key, None));
                    }
                }
            }

            let (updated_root, _) =
                update_map(&mut store, doc, &current_root, edits, Limits::default())
                    .await
                    .unwrap();

            let (expected_root, _) = write_map(&mut store, doc, oracle.clone(), Limits::default())
                .await
                .unwrap();

            assert_eq!(
                updated_root, expected_root,
                "round {round} mismatch between incremental and full writer"
            );

            let read_back = read_map(&mut store, doc, &updated_root, Limits::default())
                .await
                .unwrap();
            assert_eq!(read_back, oracle, "round {round} oracle mismatch");

            current_root = updated_root;
        }
    }

    #[tokio::test]
    async fn untouched_subtrees_are_reused_without_redundant_gets_or_puts() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = TrackingStore::default();

        let mut initial_map = BTreeMap::new();
        for i in 0..300 {
            initial_map.insert(format!("node_{i:04}"), Address(format!("{i:064x}")));
        }

        let (root, _) = write_map(&mut store, doc, initial_map.clone(), Limits::default())
            .await
            .unwrap();

        // Reset tracking counters
        store.gets.store(0, std::sync::atomic::Ordering::Relaxed);
        store.puts.store(0, std::sync::atomic::Ordering::Relaxed);

        // Edit a single key
        let new_addr = Address("f".repeat(64));
        let edits = vec![("node_0050".to_string(), Some(new_addr.clone()))];
        let (new_root, stats) = update_map(&mut store, doc, &root, edits, Limits::default())
            .await
            .unwrap();

        let gets = store.gets.load(std::sync::atomic::Ordering::Relaxed);
        let puts = store.puts.load(std::sync::atomic::Ordering::Relaxed);

        // 300 entries span around 10-15 leaves and multiple branch levels.
        // Updating 1 key touches only the nodes along its root-to-leaf path.
        assert!(gets < 5, "expected O(depth) gets, got {gets}");
        assert!(puts < 5, "expected O(depth) puts, got {puts}");
        assert!(stats.visited_objects < 5);

        // Verify result matches full writer
        initial_map.insert("node_0050".to_string(), new_addr);
        let (expected_root, _) = write_map(&mut store, doc, initial_map, Limits::default())
            .await
            .unwrap();
        assert_eq!(new_root, expected_root);
    }

    #[tokio::test]
    async fn no_op_updates_produce_exact_same_root_without_creating_objects() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = MemoryStore::default();

        let mut initial = BTreeMap::new();
        for i in 0..50 {
            initial.insert(format!("item_{i}"), Address(format!("{i:064x}")));
        }
        let (root, _) = write_map(&mut store, doc, initial.clone(), Limits::default())
            .await
            .unwrap();

        // No-ops: update existing item with identical address, and delete nonexistent key
        let no_ops = vec![
            ("item_5".to_string(), Some(Address(format!("{:064x}", 5)))),
            ("nonexistent".to_string(), None),
        ];

        let (same_root, stats) = update_map(&mut store, doc, &root, no_ops, Limits::default())
            .await
            .unwrap();

        assert_eq!(same_root, root);
        assert_eq!(stats.new_objects, 0);
    }

    #[tokio::test]
    async fn leaf_split_and_branch_collapse_transitions() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = MemoryStore::default();

        // 1. Build exactly 32 entries -> must be a MapLeaf
        let mut map_32 = BTreeMap::new();
        for i in 0..32 {
            map_32.insert(format!("k_{i:02}"), Address(format!("{i:064x}")));
        }
        let (root_32, _) = write_map(&mut store, doc, map_32.clone(), Limits::default())
            .await
            .unwrap();
        let obj = decode(&root_32, &store.get(doc, &root_32).await.unwrap()).unwrap();
        assert!(
            matches!(obj, Object::MapLeaf(_)),
            "32 entries must be a MapLeaf"
        );

        // 2. Insert 1 more entry -> 33 entries -> must split into MapBranch
        let (root_33, _) = update_map(
            &mut store,
            doc,
            &root_32,
            vec![("k_32".to_string(), Some(Address(format!("{:064x}", 32))))],
            Limits::default(),
        )
        .await
        .unwrap();
        let obj = decode(&root_33, &store.get(doc, &root_33).await.unwrap()).unwrap();
        assert!(
            matches!(obj, Object::MapBranch(_)),
            "33 entries must split into a MapBranch"
        );

        // 3. Delete 1 entry -> 32 entries -> must collapse back into MapLeaf
        let (root_collapsed, _) = update_map(
            &mut store,
            doc,
            &root_33,
            vec![("k_32".to_string(), None)],
            Limits::default(),
        )
        .await
        .unwrap();
        let obj = decode(
            &root_collapsed,
            &store.get(doc, &root_collapsed).await.unwrap(),
        )
        .unwrap();
        assert!(
            matches!(obj, Object::MapLeaf(_)),
            "32 entries must collapse into a MapLeaf"
        );
        assert_eq!(
            root_collapsed, root_32,
            "collapsed root must match original 32-entry leaf"
        );

        // 4. Delete all remaining entries -> empty map
        let all_deletes: Vec<_> = (0..32).map(|i| (format!("k_{i:02}"), None)).collect();
        let (root_empty, _) = update_map(
            &mut store,
            doc,
            &root_collapsed,
            all_deletes,
            Limits::default(),
        )
        .await
        .unwrap();
        let (expected_empty, _) = write_map(&mut store, doc, BTreeMap::new(), Limits::default())
            .await
            .unwrap();
        assert_eq!(root_empty, expected_empty);
    }

    #[tokio::test]
    async fn invalid_roots_and_budget_limits_fail_closed() {
        let doc = DocumentId(uuid::Uuid::new_v4());
        let mut store = MemoryStore::default();

        // Nonexistent root
        let missing = Address("e".repeat(64));
        assert!(update_map(
            &mut store,
            doc,
            &missing,
            vec![("k".into(), Some(Address("1".repeat(64))))],
            Limits::default(),
        )
        .await
        .is_err());

        // Corrupt object
        store
            .objects
            .insert((doc.0, missing.clone()), b"corrupt".to_vec());
        assert!(matches!(
            update_map(
                &mut store,
                doc,
                &missing,
                vec![("k".into(), Some(Address("1".repeat(64))))],
                Limits::default(),
            )
            .await,
            Err(Error::HashMismatch)
        ));

        // Wrong object type (e.g. State root instead of map root)
        let (leaf, leaf_bytes) = encode(Object::MapLeaf(vec![])).unwrap();
        store.put(doc, &leaf, &leaf_bytes).await.unwrap();
        let (state_root, state_bytes) = encode(Object::State(StateRoots {
            nodes: leaf.clone(),
            comments: leaf.clone(),
            suggestions: leaf.clone(),
            removed_choices: leaf.clone(),
        }))
        .unwrap();
        store.put(doc, &state_root, &state_bytes).await.unwrap();

        assert!(matches!(
            update_map(
                &mut store,
                doc,
                &state_root,
                vec![("k".into(), Some(leaf.clone()))],
                Limits::default(),
            )
            .await,
            Err(Error::Invalid("expected bounded map"))
        ));

        // Budget exceeded
        let (valid_root, _) = write_map(&mut store, doc, BTreeMap::new(), Limits::default())
            .await
            .unwrap();
        assert!(matches!(
            update_map(
                &mut store,
                doc,
                &valid_root,
                vec![("k".into(), Some(leaf))],
                Limits {
                    max_objects: 0,
                    max_bytes: usize::MAX,
                },
            )
            .await,
            Err(Error::Limit("objects"))
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn arbitrary_text_and_unordered_removals_round_trip(text in ".{0,250}", count in 0usize..90) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let doc = DocumentId(uuid::Uuid::new_v4());
                let mut store = MemoryStore::default();
                let mut state = fixture(count);
                state.comments[0].body = text;
                let (root, _) = write_state(&mut store, doc, &state, Limits::default()).await.unwrap();
                assert_eq!(read_state(&mut store, doc, &root, Limits::default()).await.unwrap(), state);
                state.removed_choices = state.removed_choices.iter().cloned().collect();
                let (again, _) = write_state(&mut store, doc, &state, Limits::default()).await.unwrap();
                assert_eq!(root, again);
            });
        }
    }
}
