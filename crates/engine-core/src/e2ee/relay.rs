//! Ledger mode (decision 028) in encrypted projects, decision 035:
//!
//! - **Relay answers sealed to the requester.** Encoding `x25519-aes256gcm-v1` is HPKE base
//!   mode with the grant suite, to the requester's per-request X25519 key, with `info` binding
//!   the document, the kind and the requested hash. The service stores and forwards opaque
//!   bytes; the requester still checks the content against the hash it asked for.
//! - **Keyed block hashes.** A manifest block hash is HMAC-SHA-256 under the document's
//!   ledger block key (derived from its document key, which the service never holds), so a
//!   short paragraph cannot be confirmed by guessing and hashing it.
use super::{grant, hex, keys::Key, sha256, Error};
use serde_json::Value;
use uuid::Uuid;

pub const ENCODING: &str = "x25519-aes256gcm-v1";
pub const INFO_LABEL: &[u8] = b"dynodoc.ledger-relay\0v1\0";
pub const BLOCK_HASH_LABEL: &[u8] = b"dynodoc.ledger-block\0v1\0";

/// `block` = 1, `media` = 2 (the relay's two request kinds).
pub fn kind_byte(kind: &str) -> Result<u8, Error> {
    match kind {
        "block" => Ok(1),
        "media" => Ok(2),
        _ => Err(Error::Unsupported("relay kind")),
    }
}

pub fn info(document: Uuid, kind: &str, subject: &[u8; 32]) -> Result<Vec<u8>, Error> {
    Ok([
        INFO_LABEL,
        document.as_bytes(),
        &[kind_byte(kind)?],
        subject,
    ]
    .concat())
}

/// Seal an answer for the requester's key; returns `enc || ciphertext`.
pub fn seal_answer(
    recipient_key: &[u8; 32],
    document: Uuid,
    kind: &str,
    subject: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    grant::hpke_seal(
        recipient_key,
        &info(document, kind, subject)?,
        &[],
        payload,
        None,
    )
}

/// [`seal_answer`] with a fixed ephemeral seed, for published test vectors only.
pub fn seal_answer_with_ikm(
    recipient_key: &[u8; 32],
    document: Uuid,
    kind: &str,
    subject: &[u8; 32],
    payload: &[u8],
    ikm: [u8; 32],
) -> Result<Vec<u8>, Error> {
    grant::hpke_seal(
        recipient_key,
        &info(document, kind, subject)?,
        &[],
        payload,
        Some(ikm),
    )
}

pub fn open_answer(
    requester: &grant::DeviceKey,
    document: Uuid,
    kind: &str,
    subject: &[u8; 32],
    sealed: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    grant::hpke_open(requester, &info(document, kind, subject)?, &[], sealed)
}

/// The fields a block hash covers: everything but `block_hash`, as stable JSON (sorted keys,
/// no spaces), the encoding of `ledger::fields_hash` and the SDK's `fieldsHash`.
fn stable(fields: &Value) -> Vec<u8> {
    let mut rest = fields.as_object().cloned().unwrap_or_default();
    rest.remove("block_hash");
    crate::log::canonical_json(&Value::Object(rest))
}

/// A manifest block hash: unkeyed SHA-256 (plaintext projects, decision 028) or keyed
/// HMAC-SHA-256 under the ledger block key (encrypted projects, decision 035).
pub fn block_hash(key: Option<&Key>, fields: &Value) -> String {
    match key {
        None => hex(&sha256(&[&stable(fields)])),
        Some(key) => {
            let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key.as_bytes());
            let mut ctx = ring::hmac::Context::with_key(&k);
            ctx.update(BLOCK_HASH_LABEL);
            ctx.update(&stable(fields));
            hex(ctx.sign().as_ref())
        }
    }
}
