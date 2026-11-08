//! The `DYNOSEAL` container (cryptographic design section 8): a clear binary header, then
//! AES-256-GCM ciphertext under a single-use key derived from the epoch key and a random
//! salt, with a key commitment checked before decryption. The service validates the header,
//! size, child references and address ([`validate`]) and never decrypts.
//!
//! Without `persistence` (the WebAssembly engine) only the keyless half builds: [`Header`],
//! [`address`], [`validate`], [`references`] and [`aad`]; browsers seal and open with Web Crypto.
#[cfg(feature = "persistence")]
use super::keys;
use super::{lp, sha256, Error};
use crate::shared_checkpoint::Address;
#[cfg(feature = "persistence")]
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
#[cfg(feature = "persistence")]
use serde_json::{json, Value};
#[cfg(feature = "persistence")]
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const MAGIC: &[u8; 8] = b"DYNOSEAL";
pub const FORMAT_VERSION: u8 = 1;
/// Suite 0x01: AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256, Ed25519, HPKE X25519 (design 3.1).
pub const SUITE: u8 = 1;
pub const HEADER_LEN: usize = 74;
pub const TAG_LEN: usize = 16;
/// The existing `MAX_OBJECT_BYTES` of the object store.
pub const MAX_OBJECT_BYTES: usize = 1024 * 1024;
pub const MAX_REFS: usize = 4096;
pub const AAD_LABEL: &[u8] = b"dynodoc.seal.v1";
pub const KEY_BLOCK_INFO: &[u8] = b"dynodoc.seal.v1/aead+nonce+commit\0";
pub const ADDRESS_DOMAIN: &[u8] = b"dynodoc.sealed-object\0v1\0";
/// Padding buckets of design 8.6; a larger frame is not padded (it is already a chunk).
pub const BUCKETS: [usize; 10] = [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];
/// Flag bit 0 (compressed) is reserved for bundles and not produced in Phase 1 (design 8.8).
const KNOWN_FLAGS: u8 = 0;

/// Object kinds of design 8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Kind {
    NodeFields = 1,
    TextChunk = 2,
    Comment = 3,
    Suggestion = 4,
    Meta = 5,
    AssetChunk = 6,
    Bundle = 7,
    Event = 8,
    StateIndex = 9,
}

impl Kind {
    pub fn from_byte(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            1 => Self::NodeFields,
            2 => Self::TextChunk,
            3 => Self::Comment,
            4 => Self::Suggestion,
            5 => Self::Meta,
            6 => Self::AssetChunk,
            7 => Self::Bundle,
            8 => Self::Event,
            9 => Self::StateIndex,
            _ => return Err(Error::Unsupported("sealed object kind")),
        })
    }
    /// The kind's name, as the SDK writes it (`node_fields`, `comment`, ...).
    pub fn name(self) -> &'static str {
        match self {
            Self::NodeFields => "node_fields",
            Self::TextChunk => "text_chunk",
            Self::Comment => "comment",
            Self::Suggestion => "suggestion",
            Self::Meta => "meta",
            Self::AssetChunk => "asset_chunk",
            Self::Bundle => "bundle",
            Self::Event => "event",
            Self::StateIndex => "state_index",
        }
    }
    /// The plaintext body key: node fields are `fields`, everything else `value`.
    #[cfg(feature = "persistence")]
    fn body_key(self) -> &'static str {
        if self == Self::NodeFields {
            "fields"
        } else {
            "value"
        }
    }
}

/// Where an object sits. A reader builds this from its own knowledge (design 8.9 step 4),
/// never from fields the service supplied separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context<'a> {
    pub project: Uuid,
    /// `None` for project-level kinds (16 zero bytes in the AAD).
    pub document: Option<Uuid>,
    /// Node id, or the client event ULID for kind 8; empty when not node-bound.
    pub node: &'a str,
    pub kind: Kind,
    pub epoch: u32,
    /// Node revision, the author's base sequence for kind 8, or 0.
    pub revision: u64,
}

/// The clear header. `key_id` selects among held epoch keys; it is not authenticated alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub suite: u8,
    pub kind: Kind,
    pub flags: u8,
    pub epoch: u32,
    pub key_id: [u8; 8],
    pub salt: [u8; 32],
    pub key_commitment: [u8; 16],
    pub refs: Vec<[u8; 32]>,
}

impl Header {
    /// Strict parse of a whole object. Returns the header and the ciphertext offset.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), Error> {
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(Error::Limit("sealed object bytes"));
        }
        if bytes.len() < HEADER_LEN + TAG_LEN || &bytes[..8] != MAGIC {
            return Err(Error::Malformed("sealed object header"));
        }
        if bytes[8] != FORMAT_VERSION {
            return Err(Error::Unsupported("sealed object version"));
        }
        if bytes[9] != SUITE {
            return Err(Error::Unsupported("suite"));
        }
        let kind = Kind::from_byte(bytes[10])?;
        let flags = bytes[11];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Error::Unsupported("sealed object flags"));
        }
        let epoch = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if epoch == 0 {
            return Err(Error::Malformed("epoch"));
        }
        let ref_count = u16::from_be_bytes([bytes[72], bytes[73]]) as usize;
        if ref_count > MAX_REFS {
            return Err(Error::Limit("child references"));
        }
        let body = HEADER_LEN + 32 * ref_count;
        if bytes.len() < body + TAG_LEN {
            return Err(Error::Malformed("sealed object length"));
        }
        let mut refs = Vec::with_capacity(ref_count);
        for chunk in bytes[HEADER_LEN..body].chunks_exact(32) {
            let mut r = [0u8; 32];
            r.copy_from_slice(chunk);
            if refs.last().is_some_and(|last: &[u8; 32]| *last >= r) {
                return Err(Error::Malformed(
                    "child references must be strictly ascending",
                ));
            }
            refs.push(r);
        }
        let ciphertext = bytes.len() - body - TAG_LEN;
        if ciphertext < 4 || !padded_len_ok(ciphertext) {
            return Err(Error::Malformed("padded length"));
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&bytes[16..24]);
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[24..56]);
        let mut key_commitment = [0u8; 16];
        key_commitment.copy_from_slice(&bytes[56..72]);
        Ok((
            Self {
                suite: SUITE,
                kind,
                flags,
                epoch,
                key_id,
                salt,
                key_commitment,
                refs,
            },
            body,
        ))
    }
}

fn padded_len_ok(len: usize) -> bool {
    BUCKETS.contains(&len) || len > *BUCKETS.last().unwrap_or(&65536)
}

#[cfg(feature = "persistence")]
fn padded_len(framed: usize) -> usize {
    BUCKETS
        .iter()
        .copied()
        .find(|b| *b >= framed)
        .unwrap_or(framed)
}

/// `SHA-256("dynodoc.sealed-object\0v1\0" || bytes)`, the object's store address.
pub fn address(bytes: &[u8]) -> Result<Address, Error> {
    to_address(sha256(&[ADDRESS_DOMAIN, bytes]))
}

pub(crate) fn to_address(bytes: [u8; 32]) -> Result<Address, Error> {
    Address::try_from(super::hex(&bytes)).map_err(|_| Error::Malformed("address"))
}

/// The service-side check: header syntax, bounds, sorted unique refs and the address.
/// Grants no access and never decrypts.
pub fn validate(expected: &Address, bytes: &[u8]) -> Result<Header, Error> {
    let (header, _) = Header::parse(bytes)?;
    if address(bytes)? != *expected {
        return Err(Error::Malformed("sealed object address"));
    }
    Ok(header)
}

/// Child addresses in the clear header, for retention, transfer and erasure planning.
pub fn references(expected: &Address, bytes: &[u8]) -> Result<Vec<Address>, Error> {
    validate(expected, bytes)?
        .refs
        .into_iter()
        .map(to_address)
        .collect()
}

/// The associated data of design 8.3 (175 bytes for a 26-character node id).
pub fn aad(ctx: &Context<'_>, refs: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(160 + ctx.node.len());
    lp(&mut out, AAD_LABEL);
    lp(&mut out, ctx.project.as_bytes());
    lp(&mut out, ctx.document.unwrap_or(Uuid::nil()).as_bytes());
    lp(&mut out, ctx.node.as_bytes());
    lp(&mut out, &[ctx.kind as u8]);
    out.extend_from_slice(&ctx.epoch.to_be_bytes());
    out.extend_from_slice(&ctx.revision.to_be_bytes());
    lp(&mut out, &[SUITE]);
    let concatenated: Vec<u8> = refs.concat();
    lp(&mut out, &sha256(&[&concatenated]));
    out
}

/// The 76-byte per-object key block: AEAD key, nonce, commitment key.
#[cfg(feature = "persistence")]
pub struct KeyBlock {
    pub key: keys::Key,
    pub nonce: [u8; 12],
    pub commit_key: keys::Key,
}

#[cfg(feature = "persistence")]
pub fn key_block(key: &keys::Key, salt: &[u8; 32]) -> Result<KeyBlock, Error> {
    let mut okm = [0u8; 76];
    keys::hkdf(key.as_bytes(), salt, &[KEY_BLOCK_INFO, &[SUITE]], &mut okm)?;
    let block = KeyBlock {
        key: keys::Key::from_slice(&okm[..32])?,
        nonce: okm[32..44]
            .try_into()
            .map_err(|_| Error::Malformed("nonce"))?,
        commit_key: keys::Key::from_slice(&okm[44..76])?,
    };
    zeroize::Zeroize::zeroize(&mut okm);
    Ok(block)
}

#[cfg(feature = "persistence")]
pub fn commitment(commit_key: &keys::Key, aad: &[u8]) -> [u8; 16] {
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, commit_key.as_bytes()),
        aad,
    );
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag.as_ref()[..16]);
    out
}

/// The canonical plaintext body `{"cid":..,"fields"|"value":..,"v":1}` with the keyed
/// identifier of the content inside, so the service never sees it (design 9.2).
#[cfg(feature = "persistence")]
pub fn body(cid_key: &keys::Key, kind: Kind, content: &Value) -> Vec<u8> {
    let canonical = crate::log::canonical_json(content);
    let cid = keys::cid(cid_key, kind as u8, &canonical);
    let mut body = serde_json::Map::new();
    body.insert("cid".into(), json!(super::hex(&cid)));
    body.insert(kind.body_key().into(), content.clone());
    body.insert("v".into(), json!(1));
    crate::log::canonical_json(&Value::Object(body))
}

/// Seal `content` for `ctx` under `key` (K_doc, K_meta or an explicit document root) with a
/// fresh random salt. `refs` are child addresses; they stay in the clear, sorted.
#[cfg(feature = "persistence")]
pub fn seal(
    key: &keys::Key,
    key_id: [u8; 8],
    cid_key: &keys::Key,
    ctx: &Context<'_>,
    refs: &[Address],
    content: &Value,
) -> Result<Vec<u8>, Error> {
    seal_with_salt(
        key,
        key_id,
        cid_key,
        ctx,
        refs,
        content,
        super::random::<32>()?,
    )
}

/// [`seal`] with a caller-chosen salt, for published test vectors only: a repeated salt
/// under one key repeats the AES-GCM key and nonce.
#[cfg(feature = "persistence")]
pub fn seal_with_salt(
    key: &keys::Key,
    key_id: [u8; 8],
    cid_key: &keys::Key,
    ctx: &Context<'_>,
    refs: &[Address],
    content: &Value,
    salt: [u8; 32],
) -> Result<Vec<u8>, Error> {
    if ctx.epoch == 0 {
        return Err(Error::Malformed("epoch"));
    }
    let mut raw: Vec<[u8; 32]> = refs
        .iter()
        .map(|a| super::unhex::<32>(a.as_str(), "address"))
        .collect::<Result<_, _>>()?;
    raw.sort();
    raw.dedup();
    if raw.len() > MAX_REFS {
        return Err(Error::Limit("child references"));
    }
    let body = body(cid_key, ctx.kind, content);
    let framed = 4 + body.len();
    let mut plaintext = Vec::with_capacity(padded_len(framed));
    plaintext.extend_from_slice(&(body.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(&body);
    plaintext.resize(padded_len(framed), 0);
    let aad = aad(ctx, &raw);
    let block = key_block(key, &salt)?;
    let mut out = Vec::with_capacity(HEADER_LEN + 32 * raw.len() + plaintext.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[FORMAT_VERSION, SUITE, ctx.kind as u8, 0]);
    out.extend_from_slice(&ctx.epoch.to_be_bytes());
    out.extend_from_slice(&key_id);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&commitment(&block.commit_key, &aad));
    out.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    for r in &raw {
        out.extend_from_slice(r);
    }
    let cipher = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, block.key.as_bytes()).map_err(|_| Error::Malformed("key"))?,
    );
    let tag = cipher
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(block.nonce),
            Aad::from(&aad),
            &mut plaintext,
        )
        .map_err(|_| Error::Authentication)?;
    out.extend_from_slice(&plaintext);
    out.extend_from_slice(tag.as_ref());
    if out.len() > MAX_OBJECT_BYTES {
        return Err(Error::Limit("sealed object bytes"));
    }
    Ok(out)
}

/// Open an object at `ctx` with the epoch key whose identifier is `key_id`: commitment first, then AES-256-GCM, then the frame, padding,
/// body shape and the keyed identifier. Returns the content (`fields` or `value`).
#[cfg(feature = "persistence")]
pub fn open(
    key: &keys::Key,
    key_id: [u8; 8],
    cid_key: &keys::Key,
    ctx: &Context<'_>,
    bytes: &[u8],
) -> Result<Value, Error> {
    let (header, body_at) = Header::parse(bytes)?;
    // The hint is outside the AAD; checking it against the chosen key makes every header
    // byte fail closed (design 14).
    if !bool::from(header.key_id.ct_eq(&key_id)) {
        return Err(Error::Refused(
            "object key id differs from the held epoch key",
        ));
    }
    if header.kind != ctx.kind {
        return Err(Error::Refused("object kind differs from its position"));
    }
    if header.epoch != ctx.epoch {
        return Err(Error::Refused("object epoch differs from its position"));
    }
    let aad = aad(ctx, &header.refs);
    let block = key_block(key, &header.salt)?;
    if !bool::from(commitment(&block.commit_key, &aad).ct_eq(&header.key_commitment)) {
        return Err(Error::Commitment);
    }
    let cipher = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, block.key.as_bytes()).map_err(|_| Error::Malformed("key"))?,
    );
    let mut buffer = bytes[body_at..].to_vec();
    let plaintext = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(block.nonce),
            Aad::from(&aad),
            &mut buffer,
        )
        .map_err(|_| Error::Authentication)?;
    let length =
        u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
    if 4 + length > plaintext.len()
        || padded_len(4 + length) != plaintext.len()
        || plaintext[4 + length..].iter().any(|b| *b != 0)
    {
        return Err(Error::Malformed("plaintext frame or padding"));
    }
    let body = &plaintext[4..4 + length];
    let value: Value =
        serde_json::from_slice(body).map_err(|_| Error::Malformed("plaintext body"))?;
    let map = value
        .as_object()
        .ok_or(Error::Malformed("plaintext body"))?;
    let content = map
        .get(ctx.kind.body_key())
        .ok_or(Error::Malformed("plaintext body"))?;
    if map.len() != 3
        || map.get("v") != Some(&json!(1))
        || self::body(cid_key, ctx.kind, content) != body
    {
        return Err(Error::Malformed("plaintext body or keyed identifier"));
    }
    Ok(content.clone())
}
