//! Encrypted projects (Phase 1 of docs/END-TO-END-ENCRYPTION.md): the client-side
//! cryptography and the records the service stores and verifies without keys.
//! Constructions, labels and formats: docs/E2EE-CRYPTOGRAPHIC-DESIGN.md; tables, routes and
//! the feature matrix: docs/E2EE-PROTOCOL-AND-MIGRATION.md; settled points: decision 035.
//!
//! **Status.** Pre-release and not independently reviewed (assurance gates G1 and G2 of
//! docs/E2EE-THREAT-MODEL-AND-ASSURANCE.md have not run). User-facing copy says "encrypted
//! projects (pre-release, not independently reviewed)", never "end-to-end encrypted".
//!
//! ```text
//!   epoch root PER_e (random per epoch, delivered by HPKE grants to device keys)
//!     -> K_meta_e, K_cid_e, K_doc_{e,d}  (HKDF, one-way)
//!     -> per object: HKDF(K, salt) -> AES-256-GCM key | nonce | commitment key  (DYNOSEAL)
//! ```
//!
//! What the service may do with this module: parse and validate sealed headers, addresses,
//! child references, signed records and chains ([`seal::validate`], [`records`]). It never
//! holds an epoch root, a document key or a private key.
//!
//! Without the `persistence` feature (the WebAssembly engine, decision 036) only the keyless
//! parts build: sealed headers and addresses, the structural codec of sealed documents and the
//! sealed commit fields. Browsers do the cryptography with Web Crypto around them (decision 041).

pub mod commit;
#[cfg(feature = "persistence")]
pub mod escrow;
pub mod features;
#[cfg(feature = "persistence")]
pub mod grant;
#[cfg(feature = "persistence")]
pub mod keys;
pub mod records;
#[cfg(feature = "persistence")]
pub mod recovery;
#[cfg(feature = "persistence")]
pub mod relay;
pub mod seal;
pub mod state;

/// Every refusal of this module. Messages never contain key bytes or plaintext.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("unsupported {0}")]
    Unsupported(&'static str),
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
    /// The key commitment does not match: tampered bytes or a different key. Never retried
    /// under another key (cryptographic design 8.5).
    #[error("key commitment mismatch")]
    Commitment,
    /// A wrong key, a wrong context and any change to the bytes look the same.
    #[error("cannot open: wrong key or context, or the bytes were changed")]
    Authentication,
    #[error("signature does not verify")]
    Signature,
    /// A record is well formed but not allowed at its position (chain, role, epoch).
    #[error("refused: {0}")]
    Refused(&'static str),
    #[error("system random generator failed")]
    Random,
}

/// Length-prefixed field (u64 big-endian length, then the bytes), as `log.rs::feed`.
pub(crate) fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut ctx = sha2::Sha256::new();
    for part in parts {
        ctx.update(part);
    }
    ctx.finalize().into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hexadecimal of exactly `N` bytes.
pub(crate) fn unhex<const N: usize>(value: &str, what: &'static str) -> Result<[u8; N], Error> {
    let bytes = value.as_bytes();
    if bytes.len() != N * 2
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(Error::Malformed(what));
    }
    let mut out = [0u8; N];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(out)
}

/// Canonical JSON (sorted keys, no spaces), the encoding of every signed record.
pub(crate) fn canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let value = serde_json::to_value(value).map_err(|_| Error::Malformed("record"))?;
    Ok(crate::hashing::canonical_json(&value))
}

#[cfg(feature = "persistence")]
pub(crate) fn random<const N: usize>() -> Result<[u8; N], Error> {
    use ring::rand::SecureRandom;
    let mut out = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| Error::Random)?;
    Ok(out)
}

/// Ed25519 verification of `message` under a lowercase-hex public key.
#[cfg(feature = "persistence")]
pub(crate) fn verify(public_key: &str, message: &[u8], signature: &str) -> Result<(), Error> {
    let key = unhex::<32>(public_key, "signing key")?;
    let signature = unhex::<64>(signature, "signature")?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(message, &signature)
        .map_err(|_| Error::Signature)
}

#[cfg(feature = "persistence")]
pub(crate) fn sign(key: &ring::signature::Ed25519KeyPair, message: &[u8]) -> String {
    hex(key.sign(message).as_ref())
}

#[cfg(feature = "persistence")]
pub(crate) fn public_hex(key: &ring::signature::Ed25519KeyPair) -> String {
    use ring::signature::KeyPair;
    hex(key.public_key().as_ref())
}
