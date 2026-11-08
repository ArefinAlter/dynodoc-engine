//! Structural checkpoint codec for sealed documents (protocol 4.2). The design calls it
//! typed v3; `DYNOTYP\0\x03` was taken by the compact codec of schema 54, so it ships as
//! typed **v4** (`DYNOTYP\0\x04`, domain `dynodoc.typed-checkpoint\0v4\0`), decision 035.
//!
//! Clear records carry the tree (id, parent, type, `pos`, revision, deletion) and point at
//! `DYNOSEAL` objects for every content value. The service runs [`validate`] and
//! [`references`] (graph, hashes, structure) and never interprets a sealed leaf; members
//! run [`read`] with epoch keys.
//!
//! shortcut: the node map is a sorted index of at most 256 entries per object, not the v1
//! hash-routed radix map, so an edit rewrites a leaf and the path above it but inserts
//! shift leaf boundaries; switch to the radix map when sealed documents pass ~10,000 nodes.
#[cfg(feature = "persistence")]
use super::{keys::Key, seal::Context};
use super::{
    seal::{self, Kind},
    sha256, Error,
};
use crate::materializer::{CommentState, DocumentState, MaterializedNode, SuggestionState};
use crate::shared_checkpoint::Address;
use engine_shared::NodeId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
#[cfg(feature = "persistence")]
use uuid::Uuid;

pub const MAGIC: &[u8] = b"DYNOTYP\0\x04";
pub const DOMAIN: &[u8] = b"dynodoc.typed-checkpoint\0v4\0";
pub const INDEX_FANOUT: usize = 256;
const MAX_DEPTH: usize = 8;
/// The sealed-fields key that carries a node's `var_name` (`$` keys are reserved).
pub const VAR_NAME_KEY: &str = "$var_name";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRecord {
    pub id: String,
    pub parent_id: Option<String>,
    pub node_type: String,
    pub pos: String,
    pub rev: u64,
    pub deleted: bool,
    /// Always null: the name is inside the sealed fields.
    pub var_name: Option<String>,
    /// A `DYNOSEAL` kind 1 object.
    pub fields: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommentRecord {
    pub node_id: Option<String>,
    pub ordinal: u64,
    pub body: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuggestionRecord {
    pub id: String,
    pub detail: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<(String, Address)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<(String, Address)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRecord {
    pub nodes: Address,
    pub comments: Address,
    pub suggestions: Address,
    pub removed_choices: Vec<String>,
    pub sealed: bool,
    pub epoch_floor: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Object {
    Node(NodeRecord),
    Comment(CommentRecord),
    Suggestion(SuggestionRecord),
    Index(Index),
    State(StateRecord),
}

pub fn address(bytes: &[u8]) -> Result<Address, Error> {
    seal::to_address(sha256(&[DOMAIN, bytes]))
}

pub fn encode(object: &Object) -> Result<(Address, Vec<u8>), Error> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend(super::canonical(object)?);
    if bytes.len() > seal::MAX_OBJECT_BYTES {
        return Err(Error::Limit("structural object bytes"));
    }
    Ok((address(&bytes)?, bytes))
}

/// Decode and check one structural object: magic, address, canonical form, structure.
pub fn decode(expected: &Address, bytes: &[u8]) -> Result<Object, Error> {
    if !bytes.starts_with(MAGIC) || bytes.len() > seal::MAX_OBJECT_BYTES {
        return Err(Error::Malformed("structural object header"));
    }
    if address(bytes)? != *expected {
        return Err(Error::Malformed("structural object address"));
    }
    let object: Object = serde_json::from_slice(&bytes[MAGIC.len()..])
        .map_err(|_| Error::Malformed("structural object"))?;
    if encode(&object)?.1 != bytes {
        return Err(Error::Malformed("structural object is not canonical"));
    }
    match &object {
        Object::Node(n) if n.var_name.is_some() || n.id.is_empty() => {
            return Err(Error::Malformed("sealed node record"));
        }
        // An empty map is one index with neither list; otherwise exactly one list, sorted.
        Object::Index(i)
            if (!i.entries.is_empty() && !i.children.is_empty())
                || i.entries.len().max(i.children.len()) > INDEX_FANOUT
                || i.entries.windows(2).any(|w| w[0].0 >= w[1].0)
                || i.children.windows(2).any(|w| w[0].0 >= w[1].0) =>
        {
            return Err(Error::Malformed("index entries"));
        }
        Object::State(s) if !s.sealed || s.epoch_floor == 0 => {
            return Err(Error::Malformed("sealed state record"));
        }
        _ => {}
    }
    Ok(object)
}

/// The service-side check of a structural object.
pub fn validate(expected: &Address, bytes: &[u8]) -> Result<(), Error> {
    decode(expected, bytes).map(|_| ())
}

/// Child addresses, for reachability, retention and erasure planning.
pub fn references(expected: &Address, bytes: &[u8]) -> Result<Vec<Address>, Error> {
    Ok(match decode(expected, bytes)? {
        Object::Node(n) => vec![n.fields],
        Object::Comment(c) => vec![c.body],
        Object::Suggestion(s) => vec![s.detail],
        Object::Index(i) => i
            .entries
            .into_iter()
            .chain(i.children)
            .map(|(_, a)| a)
            .collect(),
        Object::State(s) => vec![s.nodes, s.comments, s.suggestions],
    })
}

/// The keys of one epoch for one document.
#[cfg(feature = "persistence")]
pub struct EpochKeys {
    pub key_id: [u8; 8],
    pub doc: Key,
    pub cid: Key,
}

/// Where a node's sealed fields live, carried between writes so unchanged nodes keep their
/// object (and its epoch) instead of being re-sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRef {
    pub rev: u64,
    pub fields: Address,
    pub epoch: u32,
}

pub struct Written {
    pub root: Address,
    pub objects: Vec<(Address, Vec<u8>)>,
    pub nodes: BTreeMap<String, NodeRef>,
}

/// One content value a write must seal, at its position (the write supplies the project,
/// document and epoch). [`write()`] seals these with ring; a browser seals them with Web Crypto
/// and hands the bytes to [`assemble`] (decision 041).
#[derive(Debug, Clone, PartialEq)]
pub struct Leaf {
    pub kind: Kind,
    pub node: String,
    pub revision: u64,
    pub value: Value,
}

/// A sealed leaf a reader must open: its address, its position, and the epoch its header names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    pub address: Address,
    pub kind: Kind,
    pub node: String,
    pub revision: u64,
    pub epoch: u32,
}

fn sealed_fields(node: &MaterializedNode) -> Value {
    let mut fields = node.current_fields.clone();
    if let (Some(name), Value::Object(map)) = (&node.var_name, &mut fields) {
        map.insert(VAR_NAME_KEY.into(), Value::String(name.clone()));
    }
    fields
}

fn index(
    entries: Vec<(String, Address)>,
    objects: &mut Vec<(Address, Vec<u8>)>,
) -> Result<Address, Error> {
    let mut level: Vec<(String, Address)> = Vec::new();
    for chunk in entries.chunks(INDEX_FANOUT) {
        let (address, bytes) = encode(&Object::Index(Index {
            entries: chunk.to_vec(),
            children: Vec::new(),
        }))?;
        level.push((chunk[0].0.clone(), address.clone()));
        objects.push((address, bytes));
    }
    if level.is_empty() {
        let (address, bytes) = encode(&Object::Index(Index {
            entries: Vec::new(),
            children: Vec::new(),
        }))?;
        objects.push((address.clone(), bytes));
        return Ok(address);
    }
    while level.len() > 1 {
        let mut next = Vec::new();
        for chunk in level.chunks(INDEX_FANOUT) {
            let (address, bytes) = encode(&Object::Index(Index {
                entries: Vec::new(),
                children: chunk.to_vec(),
            }))?;
            next.push((chunk[0].0.clone(), address.clone()));
            objects.push((address, bytes));
        }
        level = next;
    }
    Ok(level.remove(0).1)
}

/// The state and node references of the previous write of the same document.
pub type Previous<'a> = Option<(&'a DocumentState, &'a BTreeMap<String, NodeRef>)>;

/// The leaves a write of `state` must seal, in order: every node whose fields or name differ
/// from `previous` (at `rev + 1`, or 1 when new), then every comment, then every suggestion.
pub fn leaves(state: &DocumentState, previous: Previous<'_>) -> Result<Vec<Leaf>, Error> {
    let mut out = Vec::new();
    for (id, node) in &state.nodes {
        let before = previous.and_then(|(s, r)| Some((s.nodes.get(id)?, r.get(&id.0)?)));
        match before {
            Some((old, _))
                if old.current_fields == node.current_fields && old.var_name == node.var_name => {}
            _ => out.push(Leaf {
                kind: Kind::NodeFields,
                node: id.0.clone(),
                revision: before.map_or(1, |(_, r)| r.rev + 1),
                value: sealed_fields(node),
            }),
        }
    }
    for (ordinal, comment) in state.comments.iter().enumerate() {
        out.push(Leaf {
            kind: Kind::Comment,
            node: format!("comment:{ordinal}"),
            revision: 0,
            value: Value::String(comment.body.clone()),
        });
    }
    for (id, suggestion) in &state.suggestions {
        out.push(Leaf {
            kind: Kind::Suggestion,
            node: id.clone(),
            revision: 0,
            value: serde_json::to_value(suggestion).map_err(|_| Error::Malformed("suggestion"))?,
        });
    }
    Ok(out)
}

/// Build the structural graph of `state` over its sealed leaves: `sealed[i]` is the `DYNOSEAL`
/// object of the i-th entry of [`leaves`] for the same `state` and `previous`, sealed under
/// `epoch`. Only headers are checked here (kind, epoch, no child references); whether a leaf
/// opens is the readers' check. Nodes without a leaf keep their `previous` object.
pub fn assemble(
    state: &DocumentState,
    epoch: u32,
    previous: Previous<'_>,
    sealed: Vec<Vec<u8>>,
) -> Result<Written, Error> {
    if epoch == 0 {
        return Err(Error::Malformed("epoch"));
    }
    let expected = leaves(state, previous)?;
    if expected.len() != sealed.len() {
        return Err(Error::Malformed("one sealed object per leaf"));
    }
    let mut objects = Vec::new();
    let mut fresh: BTreeMap<(Kind, String), (u64, Address)> = BTreeMap::new();
    for (leaf, bytes) in expected.into_iter().zip(sealed) {
        let (header, _) = seal::Header::parse(&bytes)?;
        if header.kind != leaf.kind || header.epoch != epoch || !header.refs.is_empty() {
            return Err(Error::Malformed("sealed leaf header"));
        }
        let address = seal::address(&bytes)?;
        fresh.insert((leaf.kind, leaf.node), (leaf.revision, address.clone()));
        objects.push((address, bytes));
    }
    let leaf = |kind: Kind, node: &str| -> Result<Address, Error> {
        fresh
            .get(&(kind, node.to_owned()))
            .map(|(_, a)| a.clone())
            .ok_or(Error::Malformed("sealed leaf missing"))
    };
    let mut refs = BTreeMap::new();
    let mut nodes = Vec::new();
    for (id, node) in &state.nodes {
        let key = id.0.clone();
        let reference = match fresh.get(&(Kind::NodeFields, key.clone())) {
            Some((rev, fields)) => NodeRef {
                rev: *rev,
                fields: fields.clone(),
                epoch,
            },
            None => previous
                .and_then(|(_, r)| r.get(&key))
                .cloned()
                .ok_or(Error::Malformed("sealed leaf missing"))?,
        };
        let record = NodeRecord {
            id: key.clone(),
            parent_id: node.parent_id.as_ref().map(|p| p.0.clone()),
            node_type: node.node_type.clone(),
            pos: node.pos.clone(),
            rev: reference.rev,
            deleted: node.deleted,
            var_name: None,
            fields: reference.fields.clone(),
        };
        let (address, bytes) = encode(&Object::Node(record))?;
        objects.push((address.clone(), bytes));
        nodes.push((key.clone(), address));
        refs.insert(key, reference);
    }
    let mut comments = Vec::new();
    for (ordinal, comment) in state.comments.iter().enumerate() {
        let (address, bytes) = encode(&Object::Comment(CommentRecord {
            node_id: comment.node_id.as_ref().map(|n| n.0.clone()),
            ordinal: ordinal as u64,
            body: leaf(Kind::Comment, &format!("comment:{ordinal}"))?,
        }))?;
        objects.push((address.clone(), bytes));
        comments.push((format!("{ordinal:020}"), address));
    }
    let mut suggestions = Vec::new();
    for id in state.suggestions.keys() {
        let (address, bytes) = encode(&Object::Suggestion(SuggestionRecord {
            id: id.clone(),
            detail: leaf(Kind::Suggestion, id)?,
        }))?;
        objects.push((address.clone(), bytes));
        suggestions.push((id.clone(), address));
    }
    let epoch_floor = refs
        .values()
        .map(|r| r.epoch)
        .chain([epoch])
        .min()
        .unwrap_or(epoch);
    let record = StateRecord {
        nodes: index(nodes, &mut objects)?,
        comments: index(comments, &mut objects)?,
        suggestions: index(suggestions, &mut objects)?,
        removed_choices: state.removed_choices.iter().map(|n| n.0.clone()).collect(),
        sealed: true,
        epoch_floor,
    };
    let (root, bytes) = encode(&Object::State(record))?;
    objects.push((root.clone(), bytes));
    let mut seen = std::collections::BTreeSet::new();
    objects.retain(|(a, _)| seen.insert(a.clone()));
    Ok(Written {
        root,
        objects,
        nodes: refs,
    })
}

/// Seal a document state under one epoch. Nodes whose fields and name equal `previous`
/// keep their sealed object and revision; changed nodes get `rev + 1` and a new object.
#[cfg(feature = "persistence")]
pub fn write(
    state: &DocumentState,
    project: Uuid,
    document: Uuid,
    epoch: u32,
    keys: &EpochKeys,
    previous: Previous<'_>,
) -> Result<Written, Error> {
    let sealed = leaves(state, previous)?
        .iter()
        .map(|leaf| {
            let ctx = Context {
                project,
                document: Some(document),
                node: &leaf.node,
                kind: leaf.kind,
                epoch,
                revision: leaf.revision,
            };
            seal::seal(&keys.doc, keys.key_id, &keys.cid, &ctx, &[], &leaf.value)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assemble(state, epoch, previous, sealed)
}

fn get<'a>(objects: &'a BTreeMap<Address, Vec<u8>>, address: &Address) -> Result<&'a [u8], Error> {
    objects
        .get(address)
        .map(Vec::as_slice)
        .ok_or(Error::Refused("object missing"))
}

fn entries(
    objects: &BTreeMap<Address, Vec<u8>>,
    root: &Address,
    depth: usize,
    out: &mut Vec<(String, Address)>,
) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::Limit("index depth"));
    }
    match decode(root, get(objects, root)?)? {
        Object::Index(i) => {
            out.extend(i.entries);
            for (_, child) in i.children {
                entries(objects, &child, depth + 1, out)?;
            }
            Ok(())
        }
        _ => Err(Error::Malformed("index object expected")),
    }
}

fn opening(
    objects: &BTreeMap<Address, Vec<u8>>,
    address: &Address,
    kind: Kind,
    node: &str,
    revision: u64,
) -> Result<Opening, Error> {
    let header = seal::validate(address, get(objects, address)?)?;
    Ok(Opening {
        address: address.clone(),
        kind,
        node: node.to_owned(),
        revision,
        epoch: header.epoch,
    })
}

/// The clear records of a sealed state with the leaf each one points at.
struct Outline {
    nodes: Vec<(NodeRecord, Opening)>,
    comments: Vec<(CommentRecord, Opening)>,
    suggestions: Vec<(SuggestionRecord, Opening)>,
    removed_choices: Vec<String>,
}

fn outline(root: &Address, objects: &BTreeMap<Address, Vec<u8>>) -> Result<Outline, Error> {
    let Object::State(state) = decode(root, get(objects, root)?)? else {
        return Err(Error::Malformed("state object expected"));
    };
    let mut out = Outline {
        nodes: Vec::new(),
        comments: Vec::new(),
        suggestions: Vec::new(),
        removed_choices: state.removed_choices,
    };
    let mut list = Vec::new();
    entries(objects, &state.nodes, 0, &mut list)?;
    for (key, address) in list {
        let Object::Node(n) = decode(&address, get(objects, &address)?)? else {
            return Err(Error::Malformed("node record expected"));
        };
        if n.id != key {
            return Err(Error::Malformed("node index key"));
        }
        let o = opening(objects, &n.fields, Kind::NodeFields, &n.id, n.rev)?;
        out.nodes.push((n, o));
    }
    let mut list = Vec::new();
    entries(objects, &state.comments, 0, &mut list)?;
    for (_, address) in list {
        let Object::Comment(c) = decode(&address, get(objects, &address)?)? else {
            return Err(Error::Malformed("comment record expected"));
        };
        let node = format!("comment:{}", c.ordinal);
        let o = opening(objects, &c.body, Kind::Comment, &node, 0)?;
        out.comments.push((c, o));
    }
    let mut list = Vec::new();
    entries(objects, &state.suggestions, 0, &mut list)?;
    for (id, address) in list {
        let Object::Suggestion(s) = decode(&address, get(objects, &address)?)? else {
            return Err(Error::Malformed("suggestion record expected"));
        };
        if s.id != id {
            return Err(Error::Malformed("suggestion index key"));
        }
        let o = opening(objects, &s.detail, Kind::Suggestion, &s.id, 0)?;
        out.suggestions.push((s, o));
    }
    Ok(out)
}

/// Every sealed leaf a reader must open to rebuild the state at `root`, at the position the
/// reader derives from the clear records (never from fields the service sends separately).
pub fn openings(
    root: &Address,
    objects: &BTreeMap<Address, Vec<u8>>,
) -> Result<Vec<Opening>, Error> {
    let o = outline(root, objects)?;
    Ok(o.nodes
        .into_iter()
        .map(|(_, x)| x)
        .chain(o.comments.into_iter().map(|(_, x)| x))
        .chain(o.suggestions.into_iter().map(|(_, x)| x))
        .collect())
}

/// Rebuild a document state from its structural graph; `open` opens one leaf (with ring in
/// [`read`], from Web Crypto results in the WebAssembly engine).
pub fn read_with(
    root: &Address,
    objects: &BTreeMap<Address, Vec<u8>>,
    mut open: impl FnMut(&Opening) -> Result<Value, Error>,
) -> Result<(DocumentState, BTreeMap<String, NodeRef>), Error> {
    let outline = outline(root, objects)?;
    let mut out = DocumentState::default();
    let mut refs = BTreeMap::new();
    for (n, o) in outline.nodes {
        let mut fields = open(&o)?;
        let var_name = fields
            .as_object_mut()
            .and_then(|m| m.remove(VAR_NAME_KEY))
            .and_then(|v| v.as_str().map(str::to_owned));
        refs.insert(
            n.id.clone(),
            NodeRef {
                rev: n.rev,
                fields: n.fields.clone(),
                epoch: o.epoch,
            },
        );
        out.nodes.insert(
            NodeId(n.id.clone()),
            MaterializedNode {
                id: NodeId(n.id),
                parent_id: n.parent_id.map(NodeId),
                node_type: n.node_type,
                pos: n.pos,
                current_fields: fields,
                var_name,
                deleted: n.deleted,
            },
        );
    }
    for (c, o) in outline.comments {
        let body = open(&o)?;
        out.comments.push(CommentState {
            node_id: c.node_id.map(NodeId),
            body: body
                .as_str()
                .ok_or(Error::Malformed("comment body"))?
                .to_owned(),
        });
    }
    for (s, o) in outline.suggestions {
        let suggestion: SuggestionState =
            serde_json::from_value(open(&o)?).map_err(|_| Error::Malformed("suggestion"))?;
        out.suggestions.insert(s.id, suggestion);
    }
    out.removed_choices = outline.removed_choices.into_iter().map(NodeId).collect();
    Ok((out, refs))
}

/// Rebuild a document state from its structural graph, opening every sealed leaf at the
/// position the reader derives from the clear records.
#[cfg(feature = "persistence")]
pub fn read(
    root: &Address,
    objects: &BTreeMap<Address, Vec<u8>>,
    project: Uuid,
    document: Uuid,
    keys: &BTreeMap<u32, EpochKeys>,
) -> Result<(DocumentState, BTreeMap<String, NodeRef>), Error> {
    read_with(root, objects, |o| {
        let k = keys.get(&o.epoch).ok_or(Error::Refused(
            "not readable on this device: no key for this epoch",
        ))?;
        let ctx = Context {
            project,
            document: Some(document),
            node: &o.node,
            kind: o.kind,
            epoch: o.epoch,
            revision: o.revision,
        };
        seal::open(&k.doc, k.key_id, &k.cid, &ctx, get(objects, &o.address)?)
    })
}

/// The service's keyless check of a sealed document state: fetch every object reachable from
/// `root` through `store` (so a recording store sees the reachable set), validate each one's
/// address and header or structure, and refuse more than `max_objects`. Never decrypts.
pub async fn traverse<S: crate::shared_checkpoint::ObjectStore>(
    store: &mut S,
    document: engine_shared::DocumentId,
    root: &Address,
    max_objects: usize,
) -> Result<usize, crate::shared_checkpoint::Error> {
    use crate::shared_checkpoint::{references, Error as StoreError};
    let bytes = store.get(document, root).await?;
    if !matches!(decode(root, &bytes), Ok(Object::State(_))) {
        return Err(StoreError::Invalid("sealed state root"));
    }
    let mut seen = std::collections::BTreeSet::from([root.clone()]);
    let mut queue = references(root, &bytes)?;
    while let Some(address) = queue.pop() {
        if !seen.insert(address.clone()) {
            continue;
        }
        if seen.len() > max_objects {
            return Err(StoreError::Limit("sealed state objects"));
        }
        let bytes = store.get(document, &address).await?;
        if !bytes.starts_with(MAGIC) && !bytes.starts_with(seal::MAGIC) {
            return Err(StoreError::Invalid(
                "a sealed state holds only sealed or structural objects",
            ));
        }
        queue.extend(references(&address, &bytes)?);
    }
    Ok(seen.len())
}
