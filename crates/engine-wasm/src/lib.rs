//! The engine's pure core for WebAssembly hosts (decision 036): the same Rust that the
//! server runs, compiled to `wasm32-unknown-unknown`, so a browser, an editor pane or the
//! desktop client computes canonical JSON, event chain hashes, the folded state, its Merkle
//! root and three-way merges bit for bit as the server does.
//!
//! Every export takes and returns JSON text, holds no state between calls and touches no
//! clock, random source, network or storage: the host owns input and output. Errors are
//! thrown as JavaScript `Error`s with the engine's message. The [`engine`] module holds the
//! same functions with Rust errors, for native tests and the parity vectors.
use wasm_bindgen::prelude::*;

pub mod engine;

fn js(result: Result<String, engine::Error>) -> Result<String, JsError> {
    result.map_err(|e| JsError::new(&e.to_string()))
}

/// Version of the engine and of the parity vectors it reproduces.
#[wasm_bindgen(js_name = engineVersion)]
pub fn engine_version() -> String {
    engine::VERSION.into()
}

/// Canonical JSON text (sorted keys, compact, serde_json numbers) of a JSON text.
#[wasm_bindgen(js_name = canonicalJson)]
pub fn canonical_json(json: &str) -> Result<String, JsError> {
    js(engine::canonical_json(json))
}

/// Lowercase hex SHA-256 of the canonical JSON of a JSON text.
#[wasm_bindgen(js_name = canonicalHash)]
pub fn canonical_hash(json: &str) -> Result<String, JsError> {
    js(engine::canonical_hash(json))
}

/// Verify event rows (as `GET /documents/{id}/events` returns them, in order) after a
/// trusted position; returns `{"through_seq", "chain_hash"}` of the last row.
#[wasm_bindgen(js_name = verifyChain)]
pub fn verify_chain(
    events: &str,
    after_seq: i64,
    after_chain_hash: &str,
) -> Result<String, JsError> {
    js(engine::verify_chain(events, after_seq, after_chain_hash))
}

/// Fold event rows from an empty document into its state.
#[wasm_bindgen]
pub fn fold(events: &str) -> Result<String, JsError> {
    js(engine::fold(events))
}

/// Validate and apply operations to a state, in order; returns the new state.
#[wasm_bindgen(js_name = applyOps)]
pub fn apply_ops(state: &str, ops: &str) -> Result<String, JsError> {
    js(engine::apply_ops(state, ops))
}

/// Lowercase hex Merkle root of a state (the snapshot root).
#[wasm_bindgen(js_name = stateHash)]
pub fn state_hash(state: &str) -> Result<String, JsError> {
    js(engine::state_hash(state))
}

/// Three-way merge of states with explicit resolutions; returns
/// `{"state", "conflicts", "ops"}`, where `ops` replays the merge onto `team`.
#[wasm_bindgen]
pub fn merge(base: &str, team: &str, draft: &str, resolutions: &str) -> Result<String, JsError> {
    js(engine::merge(base, team, draft, resolutions))
}

/// Operations that turn one state into another.
#[wasm_bindgen]
pub fn diff(from: &str, to: &str) -> Result<String, JsError> {
    js(engine::diff(from, to))
}

/// Three-way merge of one rich-text value (a block's `content`): the merged value, or
/// `null` when the edits overlap.
#[wasm_bindgen(js_name = mergeText)]
pub fn merge_text(base: &str, team: &str, draft: &str) -> Result<String, JsError> {
    js(engine::merge_text(base, team, draft))
}

/// The v2 typed objects and root of a document state, for a project commit.
#[wasm_bindgen(js_name = writeState)]
pub fn write_state(document: &str, state: &str) -> Result<String, JsError> {
    js(engine::write_state(document, state))
}

/// A project commit's address and the hex bytes its author signs.
#[wasm_bindgen(js_name = commitAddress)]
pub fn commit_address(commit: &str) -> Result<String, JsError> {
    js(engine::commit_address(commit))
}

/// The hex bytes a device key signs to enrol for an enrollment challenge.
#[wasm_bindgen(js_name = enrollmentMessage)]
pub fn enrollment_message(challenge: &str) -> Result<String, JsError> {
    js(engine::enrollment_message(challenge))
}

/// Sealed documents (decision 041): the leaves a write must seal with Web Crypto.
#[wasm_bindgen(js_name = sealedLeaves)]
pub fn sealed_leaves(state: &str, previous: &str) -> Result<String, JsError> {
    js(engine::sealed_leaves(state, previous))
}

/// The structural graph over the leaves the host sealed, in the order of `sealedLeaves`.
#[wasm_bindgen(js_name = sealedAssemble)]
pub fn sealed_assemble(
    state: &str,
    epoch: u32,
    previous: &str,
    sealed: &str,
) -> Result<String, JsError> {
    js(engine::sealed_assemble(state, epoch, previous, sealed))
}

/// The sealed leaves a reader opens with Web Crypto for the state at `root`.
#[wasm_bindgen(js_name = sealedOpenings)]
pub fn sealed_openings(root: &str, objects: &str) -> Result<String, JsError> {
    js(engine::sealed_openings(root, objects))
}

/// The state at `root` from the leaves the host opened.
#[wasm_bindgen(js_name = sealedRead)]
pub fn sealed_read(root: &str, objects: &str, opened: &str) -> Result<String, JsError> {
    js(engine::sealed_read(root, objects, opened))
}

/// Child addresses of one stored object (any format), after its address check.
#[wasm_bindgen(js_name = objectReferences)]
pub fn object_references(address: &str, bytes: &str) -> Result<String, JsError> {
    js(engine::object_references(address, bytes))
}

/// Encrypted projects (decision 041): the membership log's rules over entries whose Ed25519
/// signatures the host has already checked with Web Crypto.
#[wasm_bindgen(js_name = replayLog)]
pub fn replay_log(project: &str, entries: &str) -> Result<String, JsError> {
    js(engine::replay_log(project, entries))
}

/// The epoch-record chain rules (signatures checked by the host); returns each record's hash.
#[wasm_bindgen(js_name = verifyEpochs)]
pub fn verify_epochs(project: &str, entries: &str, records: &str) -> Result<String, JsError> {
    js(engine::verify_epochs(project, entries, records))
}
