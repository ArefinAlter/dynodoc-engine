//! The WebAssembly exports with Rust errors: JSON text in, JSON text out.
use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use engine_core::{
    e2ee, hashing,
    materializer::{apply_payload, DocumentState, Materializer},
    ops::validate_op,
    repository::{device::Challenge, Commit},
    richtext,
    shared_checkpoint::{self, typed, Address, Limits, MemoryStore},
    workspace_merge,
};
use engine_shared::{DocumentId, Event, EventPayload};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

/// The engine version and the parity vector set it reproduces.
pub const VERSION: &str = concat!("dynodoc-engine ", env!("CARGO_PKG_VERSION"), "; parity v1");

/// Why a call failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is not the JSON this call takes.
    #[error("invalid input: {0}")]
    Input(#[from] serde_json::Error),
    /// The engine rejected the input.
    #[error("{0}")]
    Engine(String),
}

fn parse<T: DeserializeOwned>(json: &str) -> Result<T, Error> {
    Ok(serde_json::from_str(json)?)
}
fn text(value: &impl serde::Serialize) -> Result<String, Error> {
    Ok(serde_json::to_string(value)?)
}
fn engine(e: impl std::fmt::Display) -> Error {
    Error::Engine(e.to_string())
}

/// Canonical JSON text of a JSON text.
pub fn canonical_json(json: &str) -> Result<String, Error> {
    let bytes = hashing::canonical_json(&parse::<Value>(json)?);
    String::from_utf8(bytes).map_err(engine)
}

/// Lowercase hex SHA-256 of the canonical JSON of a JSON text.
pub fn canonical_hash(json: &str) -> Result<String, Error> {
    let bytes = hashing::canonical_json(&parse::<Value>(json)?);
    Ok(hashing::hex(&hashing::sha256(&[&bytes])))
}

/// Verify consecutive event rows of one document after `(after_seq, after_chain_hash)`.
pub fn verify_chain(events: &str, after_seq: i64, after_chain_hash: &str) -> Result<String, Error> {
    let events: Vec<Event> = parse(events)?;
    let mut previous = unhex32(after_chain_hash)?;
    if after_seq < 0 || (after_seq == 0 && previous != hashing::ZERO_HASH) {
        return Err(engine("a chain starts at seq 0 with the zero hash"));
    }
    let mut seq = after_seq;
    for event in &events {
        if event.document_id != events[0].document_id {
            return Err(engine(format!(
                "chain broken at seq {}: document binding mismatch",
                event.seq
            )));
        }
        seq += 1;
        previous = hashing::verify_event(event, seq, &previous).map_err(engine)?;
    }
    text(&json!({"through_seq": seq, "chain_hash": hashing::hex(&previous)}))
}

fn unhex32(value: &str) -> Result<[u8; 32], Error> {
    let bytes = value.as_bytes();
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    if bytes.len() != 64 {
        return Err(engine("use a lowercase hex SHA-256 chain hash"));
    }
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        match (digit(pair[0]), digit(pair[1])) {
            (Some(hi), Some(lo)) => out[i] = hi << 4 | lo,
            _ => return Err(engine("use a lowercase hex SHA-256 chain hash")),
        }
    }
    Ok(out)
}

/// Fold event rows from an empty document.
pub fn fold(events: &str) -> Result<String, Error> {
    let events: Vec<Event> = parse(events)?;
    text(&Materializer::fold(&events).map_err(engine)?)
}

/// Validate and apply operations in order.
pub fn apply_ops(state: &str, ops: &str) -> Result<String, Error> {
    let mut state: DocumentState = parse(state)?;
    for op in parse::<Vec<EventPayload>>(ops)? {
        validate_op(&state, &op).map_err(engine)?;
        apply_payload(&mut state, &op).map_err(engine)?;
    }
    text(&state)
}

/// Lowercase hex Merkle root of a state.
pub fn state_hash(state: &str) -> Result<String, Error> {
    let state: DocumentState = parse(state)?;
    Ok(hashing::hex(&hashing::merkle_root(&state)?))
}

/// Three-way merge of states.
pub fn merge(base: &str, team: &str, draft: &str, resolutions: &str) -> Result<String, Error> {
    let resolutions: BTreeMap<String, String> = parse(resolutions)?;
    text(&workspace_merge::merge(
        &parse(base)?,
        &parse(team)?,
        &parse(draft)?,
        &resolutions,
    ))
}

/// Operations from one state to another.
pub fn diff(from: &str, to: &str) -> Result<String, Error> {
    text(&workspace_merge::diff(&parse(from)?, &parse(to)?).map_err(engine)?)
}

/// Three-way merge of one rich-text value, `null` on overlap.
pub fn merge_text(base: &str, team: &str, draft: &str) -> Result<String, Error> {
    text(&richtext::merge(
        &parse(base)?,
        &parse(team)?,
        &parse(draft)?,
    ))
}

/// The server's staging read budget (`project_staging`): a state it would refuse to
/// read is not written here either.
const STATE_LIMITS: Limits = Limits {
    max_objects: 65_536,
    max_bytes: 64 * 1024 * 1024,
};

/// Polls a future once. The in-memory store answers at once, so the typed writer never
/// waits; a future that did would be a bug, reported rather than spun on.
fn ready<T>(future: impl std::future::Future<Output = T>) -> Result<T, Error> {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => Ok(value),
        std::task::Poll::Pending => Err(Error::Engine("the object store did not answer".into())),
    }
}

/// The v2 typed object graph of a document state (what a project commit's file entry
/// names): `{"state": root, "objects": [{"address", "bytes"}]}`, bytes in base64 as the
/// staging upload route takes them.
pub fn write_state(document: &str, state: &str) -> Result<String, Error> {
    let document = DocumentId(serde_json::from_value(Value::String(document.into()))?);
    let state: DocumentState = parse(state)?;
    let mut store = MemoryStore::default();
    let (root, _) = ready(typed::write_state(
        &mut store,
        document,
        &state,
        STATE_LIMITS,
        Default::default(),
    ))?
    .map_err(engine)?;
    let objects: Vec<Value> = store
        .objects()
        .map(|(address, bytes)| json!({"address": address, "bytes": STANDARD.encode(bytes)}))
        .collect();
    text(&json!({"state": root, "objects": objects}))
}

/// A project commit's address and the bytes its author signs (hex), after the engine's
/// validation: `{"address", "signing_message"}`. `author_key` must be the signer's key.
pub fn commit_address(commit: &str) -> Result<String, Error> {
    let commit: Commit = parse(commit)?;
    let address = commit.address().map_err(engine)?;
    let message = commit.signing_message().map_err(engine)?;
    text(&json!({"address": address, "signing_message": hashing::hex(&message)}))
}

/// The bytes a device key signs to enrol (hex), for a challenge from `POST /devices/challenge`.
pub fn enrollment_message(challenge: &str) -> Result<String, Error> {
    let challenge: Challenge = parse(challenge)?;
    Ok(hashing::hex(&challenge.message().map_err(engine)?))
}

// ---- sealed documents of encrypted projects (decision 041) -------------------------------
// The engine builds and walks the structural graph; the host seals and opens every leaf with
// Web Crypto (the SDK's `e2ee.seal`/`e2ee.open`), so no key ever enters WebAssembly memory.

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedPrevious {
    state: DocumentState,
    nodes: BTreeMap<String, e2ee::state::NodeRef>,
}

fn previous(json: &str) -> Result<Option<SealedPrevious>, Error> {
    parse(json)
}

fn bytes_of(b64: &str) -> Result<Vec<u8>, Error> {
    STANDARD
        .decode(b64)
        .map_err(|_| engine("object bytes must be base64"))
}

fn object_map(json: &str) -> Result<BTreeMap<Address, Vec<u8>>, Error> {
    parse::<BTreeMap<Address, String>>(json)?
        .into_iter()
        .map(|(a, b)| Ok((a, bytes_of(&b)?)))
        .collect()
}

/// The leaves a sealed write must seal, in order: `[{"kind","node","revision","value"}]`.
/// `previous` is `null` or `{"state","nodes"}` from the last read or write of the file.
pub fn sealed_leaves(state: &str, previous_json: &str) -> Result<String, Error> {
    let state: DocumentState = parse(state)?;
    let prev = previous(previous_json)?;
    let leaves =
        e2ee::state::leaves(&state, prev.as_ref().map(|p| (&p.state, &p.nodes))).map_err(engine)?;
    let out: Vec<Value> = leaves
        .into_iter()
        .map(|l| json!({"kind": l.kind.name(), "node": l.node, "revision": l.revision, "value": l.value}))
        .collect();
    text(&out)
}

/// The structural graph over the sealed leaves (`sealed`: base64 objects in the order of
/// [`sealed_leaves`]): `{"state": root, "objects": [{"address","bytes"}], "nodes"}`.
pub fn sealed_assemble(
    state: &str,
    epoch: u32,
    previous_json: &str,
    sealed: &str,
) -> Result<String, Error> {
    let state: DocumentState = parse(state)?;
    let prev = previous(previous_json)?;
    let sealed = parse::<Vec<String>>(sealed)?
        .iter()
        .map(|b| bytes_of(b))
        .collect::<Result<Vec<_>, _>>()?;
    let written = e2ee::state::assemble(
        &state,
        epoch,
        prev.as_ref().map(|p| (&p.state, &p.nodes)),
        sealed,
    )
    .map_err(engine)?;
    let objects: Vec<Value> = written
        .objects
        .iter()
        .map(|(address, bytes)| json!({"address": address, "bytes": STANDARD.encode(bytes)}))
        .collect();
    text(&json!({"state": written.root, "objects": objects, "nodes": written.nodes}))
}

/// The sealed leaves to open for the state at `root` (`objects`: address to base64):
/// `[{"address","kind","node","revision","epoch"}]`.
pub fn sealed_openings(root: &str, objects: &str) -> Result<String, Error> {
    let root: Address = parse(&json!(root).to_string())?;
    let objects = object_map(objects)?;
    let out: Vec<Value> = e2ee::state::openings(&root, &objects)
        .map_err(engine)?
        .into_iter()
        .map(|o| json!({"address": o.address, "kind": o.kind.name(), "node": o.node, "revision": o.revision, "epoch": o.epoch}))
        .collect();
    text(&out)
}

/// The state at `root` from the opened leaves (`opened`: address to content):
/// `{"state","nodes"}`.
pub fn sealed_read(root: &str, objects: &str, opened: &str) -> Result<String, Error> {
    let root: Address = parse(&json!(root).to_string())?;
    let objects = object_map(objects)?;
    let opened: BTreeMap<Address, Value> = parse(opened)?;
    let (state, nodes) = e2ee::state::read_with(&root, &objects, |o| {
        opened
            .get(&o.address)
            .cloned()
            .ok_or(e2ee::Error::Refused("a leaf was not opened"))
    })
    .map_err(engine)?;
    text(&json!({"state": state, "nodes": nodes}))
}

/// Child addresses of one stored object of any format, after its address check (to fetch a
/// graph object by object).
pub fn object_references(address: &str, bytes: &str) -> Result<String, Error> {
    let address: Address = parse(&json!(address).to_string())?;
    text(&shared_checkpoint::references(&address, &bytes_of(bytes)?).map_err(engine)?)
}

fn replay_presigned(project: &str, entries: &str) -> Result<e2ee::records::Log, Error> {
    let project: uuid::Uuid = parse(&json!(project).to_string())?;
    let entries: Vec<e2ee::records::SignedEntry> = parse(entries)?;
    let mut log = e2ee::records::Log::new(project);
    for entry in &entries {
        log.append_presigned(entry).map_err(engine)?;
    }
    Ok(log)
}

/// The membership log's authorization rules (the service's own) over entries whose
/// signatures the host has already checked: the verified membership, or the first refusal.
pub fn replay_log(project: &str, entries: &str) -> Result<String, Error> {
    let log = replay_presigned(project, entries)?;
    let pairs = |m: &BTreeMap<String, (uuid::Uuid, String)>| -> Value {
        m.iter()
            .map(|(k, (id, other))| (k.clone(), json!([id, other])))
            .collect::<serde_json::Map<_, _>>()
            .into()
    };
    text(&json!({
        "length": log.length,
        "head": log.head.map(|h| hashing::hex(&h)),
        "members": log.members,
        "signing_keys": log.signing_keys,
        "encryption_keys": pairs(&log.encryption_keys),
        "recovery": pairs(&log.recovery),
        "escrow": log.escrow,
        "epochs": log.epochs,
        "sealed": log.sealed,
        "recipients": log.recipients(),
    }))
}

/// The epoch-record chain rules against the replayed log (signatures checked by the host).
pub fn verify_epochs(project: &str, entries: &str, records: &str) -> Result<String, Error> {
    let log = replay_presigned(project, entries)?;
    let records: Vec<e2ee::records::EpochRecord> = parse(records)?;
    e2ee::records::verify_epochs_presigned(&log, &records).map_err(engine)?;
    let hashes = records
        .iter()
        .map(|r| r.hash().map(|h| hashing::hex(&h)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(engine)?;
    text(&hashes)
}
