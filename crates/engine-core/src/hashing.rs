//! Pure hashing shared by the server and the WebAssembly engine (decision 036): canonical
//! JSON, SHA-256, the v1 event content and chain hashes, and the snapshot Merkle root.
//!
//! Nothing here reads a clock, a random source, the platform's word size or a hash map's
//! iteration order, so the same inputs give the same bytes on every target. The golden
//! vectors in `tests/fixtures/wasm-parity-v1.json` hold that true for native and
//! WebAssembly builds. The formulas are the audit contract documented in [`crate::log`];
//! they moved here unchanged so the pure build does not need the database modules.
use engine_shared::Event;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::materializer::{DocumentState, MaterializedNode};

/// The genesis `prev_chain_hash`: 32 zero bytes, so the column stays NOT NULL.
pub const ZERO_HASH: [u8; 32] = [0u8; 32];

/// SHA-256 of the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Canonical JSON: object keys sorted recursively (by UTF-8 bytes, which is code point
/// order), no insignificant whitespace, scalars in serde_json's compact form. The same
/// logical value always serializes to the same bytes, so a hash is reproducible after the
/// value round-trips through PostgreSQL JSONB.
///
/// Numbers keep serde_json's spelling: an integer literal that fits `i64` or `u64` stays an
/// integer, every other number is an `f64` printed in shortest round-trip form (`1.0`,
/// `1e-7`, `1e21`). Clients that are not Rust must reproduce that rule (the SDK's
/// `stableJson`); JSONB normalizes numbers, so a payload with non-canonical numeric
/// literals could in principle differ across the round-trip.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

#[allow(clippy::expect_used, reason = "scalar JSON is infallible")]
fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).expect("string JSON is infallible");
                out.push(b':');
                write_canonical(&map[*key], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        // Scalars (null, bool, number, string) have a single compact serde form.
        scalar => serde_json::to_writer(out, scalar).expect("scalar JSON is infallible"),
    }
}

/// SHA-256 over the event's semantic content, length-framed: the event type, the target
/// node id (empty if none), the canonical payload and the actor's 16 UUID bytes, each
/// preceded by its `u64` big-endian length.
pub fn content_hash(
    event_type: &str,
    target_node_id: Option<&str>,
    canonical_payload: &[u8],
    actor_id: &Uuid,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in [
        event_type.as_bytes(),
        target_node_id.unwrap_or("").as_bytes(),
        canonical_payload,
        actor_id.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// `chain_hash = SHA-256(content_hash ‖ prev_chain_hash)`. Both inputs are fixed-width
/// 32-byte digests, so plain concatenation is unambiguous.
pub fn chain_hash(content_hash: &[u8], prev_chain_hash: &[u8]) -> [u8; 32] {
    sha256(&[content_hash, prev_chain_hash])
}

/// Why an event does not continue a chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("chain broken at seq {seq}: {detail}")]
pub struct ChainBroken {
    pub seq: i64,
    pub detail: &'static str,
}

/// Check one stored event against its predecessor's chain hash and return its chain hash:
/// sequence continuity, the recomputed content hash, the stored predecessor link and the
/// recomputed chain hash. The document binding is the caller's check.
pub fn verify_event(
    event: &Event,
    expected_seq: i64,
    previous: &[u8],
) -> Result<[u8; 32], ChainBroken> {
    let broken = |detail| ChainBroken {
        seq: event.seq,
        detail,
    };
    if event.seq != expected_seq {
        return Err(broken("sequence gap or reorder"));
    }
    let content = content_hash(
        &event.event_type,
        event.target_node_id.as_ref().map(|n| n.0.as_str()),
        &canonical_json(&event.payload),
        &event.actor_id.0,
    );
    if content[..] != event.content_hash[..] {
        return Err(broken(
            "content_hash mismatch (type, target, payload, or actor altered)",
        ));
    }
    if event.prev_chain_hash[..] != previous[..] {
        return Err(broken(
            "prev_chain_hash does not match the prior event's chain_hash",
        ));
    }
    let chain = chain_hash(&content, previous);
    if chain[..] != event.chain_hash[..] {
        return Err(broken("chain_hash mismatch"));
    }
    Ok(chain)
}

/// Merkle root over a materialized state's nodes in id order: leaves are
/// `SHA-256(0x00 ‖ canonical node JSON)`, inner nodes `SHA-256(0x01 ‖ left ‖ right)`, an
/// odd level padded with [`ZERO_HASH`]; an empty state is [`ZERO_HASH`]. Snapshots store it.
pub fn merkle_root(state: &DocumentState) -> Result<[u8; 32], serde_json::Error> {
    if state.nodes.is_empty() {
        return Ok(ZERO_HASH);
    }
    let mut layer: Vec<[u8; 32]> = state
        .nodes
        .values()
        .map(hash_node)
        .collect::<Result<Vec<_>, _>>()?;
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(ZERO_HASH);
        }
        layer = layer
            .chunks(2)
            .map(|pair| sha256(&[&[0x01], &pair[0], &pair[1]]))
            .collect();
    }
    Ok(layer[0])
}

fn hash_node(node: &MaterializedNode) -> Result<[u8; 32], serde_json::Error> {
    let canonical = canonical_json(&serde_json::to_value(node)?);
    Ok(sha256(&[&[0x00], &canonical]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sort_by_code_point_not_utf16() {
        // U+FF5E sorts after U+1F600 in UTF-16 code units but before it by code point.
        let value = json!({"\u{1F600}": 1, "\u{FF5E}": 2, "a": 3});
        assert_eq!(
            String::from_utf8(canonical_json(&value)).unwrap(),
            "{\"a\":3,\"\u{FF5E}\":2,\"\u{1F600}\":1}"
        );
    }

    #[test]
    fn sha256_matches_the_standard_vector() {
        assert_eq!(
            hex(&sha256(&[b"a", b"bc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
