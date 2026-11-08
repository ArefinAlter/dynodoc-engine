//! The key hierarchy of cryptographic design section 4: epoch roots and the keys derived
//! from them. Derived keys live in memory only and are recomputed on use.
use super::{sha256, Error};
use ring::hkdf;
use uuid::Uuid;
use zeroize::Zeroize;

pub const META_LABEL: &[u8] = b"dynodoc.k.meta.v1";
pub const CID_LABEL: &[u8] = b"dynodoc.k.cid.v1";
pub const DOC_LABEL: &[u8] = b"dynodoc.k.doc.v1";
pub const KEY_ID_LABEL: &[u8] = b"dynodoc.key-id.v1\0";
pub const CID_DOMAIN: &[u8] = b"dynodoc.cid.v1\0";
/// Ledger manifest block hashes in encrypted projects (decision 035): one key per document,
/// derived from its document key, so a pane holding only that document key can compute it.
pub const LEDGER_BLOCK_LABEL: &[u8] = b"dynodoc.k.ledger-block.v1";

/// A 32-byte secret: an epoch root, an explicit document root or a derived key. Wiped on
/// drop, never printed, never serialized.
pub struct Key([u8; 32]);

impl Key {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::Malformed("key length"))
    }
    /// A fresh epoch root or document root from the operating-system generator.
    pub fn random() -> Result<Self, Error> {
        super::random::<32>().map(Self)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// An explicit copy, for the few places that hand a key to a second owner.
    pub fn duplicate(&self) -> Self {
        Self(self.0)
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA-256 (RFC 5869) extract and expand. An empty salt is the RFC's zero salt.
pub(crate) fn hkdf(ikm: &[u8], salt: &[u8], info: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    hkdf::Salt::new(hkdf::HKDF_SHA256, salt)
        .extract(ikm)
        .expand(info, Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| Error::Limit("hkdf output"))
}

/// HKDF-Expand only, with `prk` used as the pseudorandom key (recovery derivation 11.2).
pub(crate) fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, prk)
        .expand(&[info], Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| Error::Limit("hkdf output"))
}

fn derive(root: &Key, info: &[&[u8]]) -> Result<Key, Error> {
    let mut out = [0u8; 32];
    hkdf(root.as_bytes(), &[], info, &mut out)?;
    Ok(Key(out))
}

/// `K_meta_e`: project-level text (titles, file names, messages, issue text).
pub fn meta_key(root: &Key) -> Result<Key, Error> {
    derive(root, &[META_LABEL])
}
/// `K_cid_e`: the HMAC key of keyed content identifiers.
pub fn cid_key(root: &Key) -> Result<Key, Error> {
    derive(root, &[CID_LABEL])
}
/// `K_doc_{e,d}`: one document in one epoch; delegable alone (goal G7).
pub fn doc_key(root: &Key, project: Uuid, document: Uuid) -> Result<Key, Error> {
    derive(root, &[DOC_LABEL, project.as_bytes(), document.as_bytes()])
}
/// The key of a ledger document's manifest block hashes (decision 035).
pub fn ledger_block_key(doc_key: &Key) -> Result<Key, Error> {
    derive(doc_key, &[LEDGER_BLOCK_LABEL])
}

/// The 8-byte key identifier hint of an epoch root.
pub fn key_id(epoch: u32, root: &Key) -> [u8; 8] {
    let hash = sha256(&[KEY_ID_LABEL, &epoch.to_be_bytes(), root.as_bytes()]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

/// Keyed content identifier: HMAC-SHA-256(K_cid, label || kind || canonical plaintext).
pub fn cid(cid_key: &Key, kind: u8, canonical_plaintext: &[u8]) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, cid_key.as_bytes());
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(CID_DOMAIN);
    ctx.update(&[kind]);
    ctx.update(canonical_plaintext);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}
