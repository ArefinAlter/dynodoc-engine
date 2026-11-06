//! Versioned normalized state export format (`dynodoc.state-export`, v1).
//!
//! Exports a single historical file from a signed commit as a self-contained
//! normalized DocumentState JSON envelope. It is not a DOCX/XLSX/PPTX binary,
//! but a verified canonical document model at an exact commit.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;

use ring::signature::Ed25519KeyPair;
use serde::de::{DeserializeSeed, Deserializer, Visitor};
use serde::{Deserialize, Serialize};

use super::{attestation, hex, unhex, Error};
use crate::materializer::DocumentState;
use crate::repository::SignedCommit;
use crate::shared_checkpoint::{
    self, validate_stored, Address, Error as CheckpointError, Limits, ObjectStore,
};
use engine_shared::DocumentId;

/// Format identifier for normalized historical state exports.
pub const STATE_EXPORT_FORMAT: &str = "dynodoc.state-export";

/// Current format version for state exports.
pub const STATE_EXPORT_VERSION: u32 = 1;

/// Maximum size in bytes allowed for a state export JSON output (64 MiB).
pub const MAX_STATE_EXPORT_BYTES: usize = 64 * 1024 * 1024;

/// Summary report returned upon successful state export verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedStateExportReport {
    pub project: uuid::Uuid,
    pub commit: Address,
    pub path: String,
    pub document: DocumentId,
    pub root: Address,
}

/// Versioned normalized state export envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateExportEnvelope {
    pub format: String,
    pub version: u32,
    pub path: String,
    pub commit: SignedCommit,
    pub state: DocumentState,
}

/// A writer wrapper that counts bytes written and enforces an exact upper bound.
pub struct BoundedWriter<W: Write> {
    inner: W,
    written: usize,
    limit: usize,
}

impl<W: Write> BoundedWriter<W> {
    pub fn new(inner: W, limit: usize) -> Self {
        Self {
            inner,
            written: 0,
            limit,
        }
    }

    pub fn bytes_written(&self) -> usize {
        self.written
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written + buf.len() > self.limit {
            return Err(std::io::Error::other(format!(
                "exported state exceeds maximum size limit ({} bytes)",
                self.limit
            )));
        }
        let n = self.inner.write(buf)?;
        self.written += n;
        Ok(n)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if self.written + buf.len() > self.limit {
            return Err(std::io::Error::other(format!(
                "exported state exceeds maximum size limit ({} bytes)",
                self.limit
            )));
        }
        self.inner.write_all(buf)?;
        self.written += buf.len();
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl StateExportEnvelope {
    pub fn new(path: String, commit: SignedCommit, state: DocumentState) -> Self {
        Self {
            format: STATE_EXPORT_FORMAT.to_string(),
            version: STATE_EXPORT_VERSION,
            path,
            commit,
            state,
        }
    }

    /// Write this envelope as pretty JSON to a writer with default 64 MiB limit.
    /// Uses streaming serialization through a counting bounded writer so escaped
    /// text cannot allocate an unbounded memory buffer before size rejection.
    pub fn write_to_writer<W: Write>(&self, writer: W) -> anyhow::Result<usize> {
        self.write_to_writer_limited(writer, MAX_STATE_EXPORT_BYTES)
    }

    /// Write this envelope as pretty JSON to a writer with an explicit byte limit.
    pub fn write_to_writer_limited<W: Write>(
        &self,
        writer: W,
        limit: usize,
    ) -> anyhow::Result<usize> {
        let mut bounded = BoundedWriter::new(writer, limit);
        serde_json::to_writer_pretty(&mut bounded, self)
            .map_err(|e| anyhow::anyhow!("serializing state export envelope: {e}"))?;
        bounded.flush()?;
        Ok(bounded.bytes_written())
    }

    /// Write this envelope to a new file created exclusively (refuses overwrite),
    /// setting private owner-only permissions (0600 on Unix, private ACL on Windows) from creation.
    ///
    /// If writing, serialization, or flushing fails, any incomplete output file is cleaned up.
    pub fn write_to_path<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<usize> {
        self.write_to_path_limited(path, MAX_STATE_EXPORT_BYTES)
    }

    /// Write this envelope to a new file with an explicit byte limit.
    pub fn write_to_path_limited<P: AsRef<Path>>(
        &self,
        path: P,
        limit: usize,
    ) -> anyhow::Result<usize> {
        let p = path.as_ref();
        anyhow::ensure!(
            !p.exists(),
            "output file {} already exists; refusing overwrite",
            p.display()
        );

        let mut file = super::private_fs::create_private_file(p)
            .map_err(|e| anyhow::anyhow!("creating output file at {}: {e}", p.display()))?;

        let guard = super::private_fs::AutoRemoveFile::new(p.to_path_buf());

        let bytes = self.write_to_writer_limited(&mut file, limit)?;
        file.sync_all()?;
        drop(file);
        guard.commit();

        Ok(bytes)
    }
}

/// A bounded discard store that validates each object's address matches its canonical
/// hash without storing or retaining an object graph in memory.
pub struct DiscardHashStore {
    limits: Limits,
    objects_visited: usize,
    bytes_visited: usize,
}

impl DiscardHashStore {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            objects_visited: 0,
            bytes_visited: 0,
        }
    }

    pub fn objects_visited(&self) -> usize {
        self.objects_visited
    }

    pub fn bytes_visited(&self) -> usize {
        self.bytes_visited
    }
}

impl ObjectStore for DiscardHashStore {
    async fn put(
        &mut self,
        _document: DocumentId,
        address: &Address,
        bytes: &[u8],
    ) -> Result<bool, CheckpointError> {
        self.objects_visited += 1;
        self.bytes_visited += bytes.len();
        if self.objects_visited > self.limits.max_objects
            || self.bytes_visited > self.limits.max_bytes
        {
            return Err(CheckpointError::Limit("discard hash store budget exceeded"));
        }
        validate_stored(address, bytes)?;
        Ok(true)
    }

    async fn get(
        &mut self,
        _document: DocumentId,
        address: &Address,
    ) -> Result<Vec<u8>, CheckpointError> {
        Err(CheckpointError::Missing(address.as_str().into()))
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("JSON value with unique keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _: &'de str) -> Result<(), E> {
        Ok(())
    }

    fn visit_i128<E>(self, _: i128) -> Result<(), E> {
        Ok(())
    }

    fn visit_u128<E>(self, _: u128) -> Result<(), E> {
        Ok(())
    }

    fn visit_char<E>(self, _: char) -> Result<(), E> {
        Ok(())
    }

    fn visit_bytes<E>(self, _: &[u8]) -> Result<(), E> {
        Ok(())
    }

    fn visit_borrowed_bytes<E>(self, _: &'de [u8]) -> Result<(), E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(()) = seq.next_element_seed(StrictJsonSeed)? {}
        Ok(())
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key `{key}`")));
            }
            map.next_value_seed(StrictJsonSeed)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct StrictJsonSeed;

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

fn validate_no_duplicate_keys(bytes: &[u8]) -> anyhow::Result<()> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    StrictJsonSeed
        .deserialize(&mut de)
        .map_err(|e| anyhow::anyhow!("duplicate JSON key or malformed syntax: {e}"))?;
    Ok(())
}

/// Offline verification of an exported state against an expected project, signed commit, and path.
///
/// Validates:
/// - Input size bounds (<= 64 MiB by default)
/// - Format and version matching (`dynodoc.state-export`, v1)
/// - Exact JSON syntax with NO duplicate keys anywhere in the hierarchy
/// - No trailing non-whitespace data
/// - Commit cryptographic signature (Ed25519) and project UUID
/// - Exact path presence in the signed commit's manifest
/// - Node map keys matching logical node IDs
/// - Full re-encoding of DocumentState using typed-v2 rules matching the signed file root
///
/// Returns a `VerifiedStateExportReport` on success.
pub async fn verify_state_export<R: std::io::Read>(
    reader: R,
    expected_project: uuid::Uuid,
    expected_commit: &Address,
    expected_path: &str,
) -> anyhow::Result<VerifiedStateExportReport> {
    verify_state_export_limited(
        reader,
        expected_project,
        expected_commit,
        expected_path,
        MAX_STATE_EXPORT_BYTES,
    )
    .await
}

/// Offline verification of an exported state file at a filesystem path.
pub async fn verify_state_export_file<P: AsRef<Path>>(
    path: P,
    expected_project: uuid::Uuid,
    expected_commit: &Address,
    expected_path: &str,
) -> anyhow::Result<VerifiedStateExportReport> {
    let file = std::fs::File::open(path.as_ref()).map_err(|e| {
        anyhow::anyhow!(
            "opening state export file at {}: {e}",
            path.as_ref().display()
        )
    })?;
    verify_state_export(file, expected_project, expected_commit, expected_path).await
}

/// Offline verification of an exported state with an explicit byte limit.
pub async fn verify_state_export_limited<R: std::io::Read>(
    reader: R,
    expected_project: uuid::Uuid,
    expected_commit: &Address,
    expected_path: &str,
    limit: usize,
) -> anyhow::Result<VerifiedStateExportReport> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow::anyhow!("reading state export input: {e}"))?;

    anyhow::ensure!(
        bytes.len() <= limit,
        "state export exceeds maximum size limit ({limit} bytes)"
    );
    anyhow::ensure!(!bytes.is_empty(), "state export input is empty");

    // 1. Strict duplicate key check across all objects in JSON
    validate_no_duplicate_keys(&bytes)?;

    // 2. Deserialize envelope and ensure NO trailing data
    let mut de = serde_json::Deserializer::from_slice(&bytes);
    let envelope = StateExportEnvelope::deserialize(&mut de)
        .map_err(|e| anyhow::anyhow!("deserializing state export envelope: {e}"))?;
    de.end()
        .map_err(|e| anyhow::anyhow!("trailing characters in state export input: {e}"))?;
    // `DocumentState` and its parts ignore unknown fields; reject them so nothing in
    // the file rides along unverified.
    let input: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("parsing state export input: {e}"))?;
    anyhow::ensure!(
        serde_json::to_value(&envelope)? == input,
        "state export contains fields outside the verified envelope"
    );

    // 3. Format and version validation
    anyhow::ensure!(
        envelope.format == STATE_EXPORT_FORMAT,
        "unsupported state export format `{}`; expected `{}`",
        envelope.format,
        STATE_EXPORT_FORMAT
    );
    anyhow::ensure!(
        envelope.version == STATE_EXPORT_VERSION,
        "unsupported state export version {}; expected version {}",
        envelope.version,
        STATE_EXPORT_VERSION
    );

    // 4. Expected path validation
    anyhow::ensure!(
        envelope.path == expected_path,
        "envelope path `{}` does not match expected path `{}`",
        envelope.path,
        expected_path
    );

    // 5. Commit project and signature validation
    anyhow::ensure!(
        envelope.commit.commit.project == expected_project,
        "commit project `{}` does not match expected project `{}`",
        envelope.commit.commit.project,
        expected_project
    );

    let actual_commit_address = envelope
        .commit
        .verify()
        .map_err(|e| anyhow::anyhow!("verifying commit signature: {e}"))?;
    anyhow::ensure!(
        &actual_commit_address == expected_commit,
        "commit address `{}` does not match expected commit `{}`",
        actual_commit_address.as_str(),
        expected_commit.as_str()
    );

    // 6. Locate path in signed manifest
    let file_entry = envelope
        .commit
        .commit
        .files
        .get(expected_path)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "path `{}` not found in signed commit files manifest",
                expected_path
            )
        })?;

    // 7. Verify map-key to logical node ID agreement
    for (key, node) in &envelope.state.nodes {
        anyhow::ensure!(
            key == &node.id,
            "node map key `{}` differs from logical node id `{}`",
            key.0,
            node.id.0
        );
    }

    // 8. Re-encode full supplied DocumentState using typed-v2 rules
    let mut store = DiscardHashStore::new(Limits::default());
    let (computed_root, _) = shared_checkpoint::typed::write_state(
        &mut store,
        file_entry.document,
        &envelope.state,
        Limits::default(),
        shared_checkpoint::typed::SemanticLimits::default(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("re-encoding state under typed-v2 rules: {e}"))?;

    anyhow::ensure!(
        computed_root == file_entry.state,
        "computed state root `{}` does not match signed manifest state root `{}`",
        computed_root.as_str(),
        file_entry.state.as_str()
    );

    Ok(VerifiedStateExportReport {
        project: expected_project,
        commit: actual_commit_address,
        path: expected_path.to_string(),
        document: file_entry.document,
        root: computed_root,
    })
}

/// The companion `.dynoattest` file extension.
pub const ATTESTATION_EXTENSION: &str = "dynoattest";

/// Domain separation for state export attestation payload address hashing.
pub const STATE_EXPORT_ATTESTATION_DOMAIN: &[u8] = b"dynodoc.state-export-attestation\0v1\0";

/// Domain separation for state export attestation Ed25519 signatures.
pub const STATE_EXPORT_ATTESTATION_SIGN_DOMAIN: &[u8] =
    b"dynodoc.state-export-attestation-signature\0v1\0";

/// Format version for state export provenance attestations.
pub const ATTESTATION_VERSION: u8 = 1;

/// Maximum size in bytes allowed for an attestation JSON envelope (4 KiB).
pub const MAX_ATTESTATION_BYTES: usize = 4096;

/// Compute lowercase hex-encoded SHA-256 digest of raw state bytes.
pub fn compute_state_digest(state_bytes: &[u8]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(state_bytes);
    hex(ctx.finish().as_ref())
}

/// Helper to derive companion `.dynoattest` path for a given state export file path.
pub fn companion_attestation_path<P: AsRef<Path>>(state_path: P) -> std::path::PathBuf {
    let p = state_path.as_ref();
    let mut s = p.as_os_str().to_os_string();
    s.push(format!(".{ATTESTATION_EXTENSION}"));
    std::path::PathBuf::from(s)
}

/// Unsigned claim binding the exported state to a project repository commit and authority epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateExportPayload {
    /// Format version (1).
    pub version: u8,
    /// Stable project UUID.
    pub project: uuid::Uuid,
    /// Authority epoch under which this attestation was issued.
    pub authority_epoch: u32,
    /// Hex-encoded 32-byte Ed25519 public key of the signer.
    #[serde(alias = "signer_public_key")]
    pub signer_key: String,
    /// Verified commit address containing the state.
    #[serde(alias = "commit_address")]
    pub commit: Address,
    /// Hex-encoded 32-byte SHA-256 digest of the exported state bytes.
    #[serde(alias = "state_hash", alias = "digest")]
    pub state_digest: String,
    /// Declared issuance time in milliseconds since Unix epoch.
    pub issued_at_ms: i64,
}

impl StateExportPayload {
    /// Compute the canonical address for this attestation payload under domain separation.
    pub fn address(&self) -> Result<Address, Error> {
        if self.version != ATTESTATION_VERSION {
            return Err(Error::Invalid("attestation version"));
        }
        if self.project.is_nil() {
            return Err(Error::Invalid("attestation project"));
        }
        if self.authority_epoch < 1
            || self.authority_epoch > crate::repository::authority_epoch::MAX_EPOCH
        {
            return Err(Error::Invalid("attestation authority epoch"));
        }
        unhex(&self.signer_key, 32)?;
        unhex(&self.state_digest, 32)?;
        if self.issued_at_ms < 0 {
            return Err(Error::Invalid("attestation timestamp"));
        }
        attestation::hash(STATE_EXPORT_ATTESTATION_DOMAIN, self)
    }
}

/// Cryptographic provenance attestation emitted in a companion `.dynoattest` JSON block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateExportAttestation {
    /// Format version (1).
    pub version: u8,
    /// Stable project UUID.
    pub project: uuid::Uuid,
    /// Authority epoch under which this attestation was issued.
    pub authority_epoch: u32,
    /// Hex-encoded 32-byte Ed25519 public key of the signer.
    #[serde(alias = "signer_public_key")]
    pub signer_key: String,
    /// Verified commit address containing the state.
    #[serde(alias = "commit_address")]
    pub commit: Address,
    /// Hex-encoded 32-byte SHA-256 digest of the exported state bytes.
    #[serde(alias = "state_hash", alias = "digest")]
    pub state_digest: String,
    /// Declared issuance time in milliseconds since Unix epoch.
    pub issued_at_ms: i64,
    /// Hex-encoded 64-byte Ed25519 signature over domain and payload address.
    pub signature: String,
}

impl StateExportAttestation {
    /// Extract the unsigned payload of this attestation.
    pub fn payload(&self) -> StateExportPayload {
        StateExportPayload {
            version: self.version,
            project: self.project,
            authority_epoch: self.authority_epoch,
            signer_key: self.signer_key.clone(),
            commit: self.commit.clone(),
            state_digest: self.state_digest.clone(),
            issued_at_ms: self.issued_at_ms,
        }
    }

    /// Compute the address of this attestation's payload.
    pub fn address(&self) -> Result<Address, Error> {
        self.payload().address()
    }

    /// Sign a payload with an Ed25519 keypair.
    pub fn sign(mut payload: StateExportPayload, key: &Ed25519KeyPair) -> Result<Self, Error> {
        use ring::signature::KeyPair;
        payload.signer_key = hex(key.public_key().as_ref());
        let addr = payload.address()?;
        let msg = attestation::message(STATE_EXPORT_ATTESTATION_SIGN_DOMAIN, &addr)?;
        let signature = hex(key.sign(&msg).as_ref());
        Ok(Self {
            version: payload.version,
            project: payload.project,
            authority_epoch: payload.authority_epoch,
            signer_key: payload.signer_key,
            commit: payload.commit,
            state_digest: payload.state_digest,
            issued_at_ms: payload.issued_at_ms,
            signature,
        })
    }

    /// Generate and sign a new provenance attestation for raw exported state bytes.
    pub fn generate(
        project: uuid::Uuid,
        authority_epoch: u32,
        commit: Address,
        state_bytes: &[u8],
        key: &Ed25519KeyPair,
        issued_at_ms: i64,
    ) -> Result<Self, Error> {
        use ring::signature::KeyPair;
        let state_digest = compute_state_digest(state_bytes);
        let payload = StateExportPayload {
            version: ATTESTATION_VERSION,
            project,
            authority_epoch,
            signer_key: hex(key.public_key().as_ref()),
            commit,
            state_digest,
            issued_at_ms,
        };
        Self::sign(payload, key)
    }

    /// Write this attestation to a companion file with owner-only private permissions (0600 on Unix, private ACL on Windows).
    pub fn write_companion_file<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let p = path.as_ref();
        anyhow::ensure!(
            !p.exists(),
            "attestation file {} already exists; refusing overwrite",
            p.display()
        );
        let mut file = super::private_fs::create_private_file(p)
            .map_err(|e| anyhow::anyhow!("creating attestation file at {}: {e}", p.display()))?;
        let guard = super::private_fs::AutoRemoveFile::new(p.to_path_buf());
        let json_bytes = serde_json::to_vec_pretty(self)?;
        anyhow::ensure!(
            json_bytes.len() <= MAX_ATTESTATION_BYTES,
            "attestation exceeds maximum size limit ({} bytes)",
            MAX_ATTESTATION_BYTES
        );
        file.write_all(&json_bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        guard.commit();
        Ok(())
    }

    /// Read an attestation from a companion file path, enforcing the maximum size limit.
    pub fn read_companion_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let p = path.as_ref();
        let file = std::fs::File::open(p)
            .map_err(|e| anyhow::anyhow!("opening attestation file at {}: {e}", p.display()))?;
        let mut bytes = Vec::new();
        file.take(MAX_ATTESTATION_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= MAX_ATTESTATION_BYTES,
            "attestation file exceeds maximum size limit ({} bytes)",
            MAX_ATTESTATION_BYTES
        );
        let attestation: Self = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parsing attestation JSON: {e}"))?;
        Ok(attestation)
    }
}

/// Error conditions during provenance attestation verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("invalid attestation: {0}")]
    Invalid(&'static str),

    #[error("state digest mismatch: expected {expected}, actual {actual}")]
    DigestMismatch { expected: String, actual: String },

    #[error("project UUID mismatch: expected {expected}, actual {actual}")]
    ProjectMismatch {
        expected: uuid::Uuid,
        actual: uuid::Uuid,
    },

    #[error("commit address mismatch: expected {expected:?}, actual {actual:?}")]
    CommitMismatch { expected: Address, actual: Address },

    #[error("signer key {signer_key} is not in the trusted keys for this project")]
    UntrustedKey { signer_key: String },

    #[error("no trust anchor: pass at least one trusted key, or ask for signature-only verification explicitly")]
    NoTrustAnchor,

    #[error("inconsistent verification policy: {0}")]
    InconsistentPolicy(&'static str),

    #[error("authority epoch {epoch} is outside the window of signer key {signer_key} (from {from_epoch}, until {until_epoch:?})")]
    KeyEpochOutsideWindow {
        signer_key: String,
        epoch: u32,
        from_epoch: u32,
        until_epoch: Option<u32>,
    },

    #[error("cryptographic signature verification failed: {0}")]
    SignatureFailed(&'static str),

    #[error("authority epoch {epoch} is expired (minimum valid epoch is {min_valid_epoch})")]
    ExpiredEpoch { epoch: u32, min_valid_epoch: u32 },

    #[error("authority epoch {epoch} exceeds maximum active epoch {max_valid_epoch}")]
    FutureEpoch { epoch: u32, max_valid_epoch: u32 },
}

/// What a successful attestation check establishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationTrust {
    /// The signer key is a trust anchor the caller configured, and the attestation's
    /// epoch lies in that key's window.
    Authority,
    /// Only that the key embedded in the attestation signed these bytes. Nothing here
    /// says who holds that key.
    SignatureOnly,
}

/// Epochs, inclusive, in which a configured trust anchor may sign. `until_epoch: None`
/// means the key is still active; a retired or revoked key has an end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEpochs {
    pub from_epoch: u32,
    pub until_epoch: Option<u32>,
}

/// Verification policy configuring trust anchors for provenance attestations. Without
/// `signature_only`, at least one trusted key is required: an empty set trusts nobody.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationVerificationPolicy {
    pub expected_project: Option<uuid::Uuid>,
    pub expected_commit: Option<Address>,
    pub trusted_keys: BTreeMap<String, KeyEpochs>,
    pub min_epoch: Option<u32>,
    pub max_epoch: Option<u32>,
    pub signature_only: bool,
}

impl AttestationVerificationPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust a key in every epoch.
    pub fn with_trusted_key(self, key: impl Into<String>) -> Self {
        self.with_trusted_key_epochs(key, 0, None)
    }

    /// Trust a key only for attestations issued in `from_epoch..=until_epoch`.
    pub fn with_trusted_key_epochs(
        mut self,
        key: impl Into<String>,
        from_epoch: u32,
        until_epoch: Option<u32>,
    ) -> Self {
        self.trusted_keys.insert(
            key.into(),
            KeyEpochs {
                from_epoch,
                until_epoch,
            },
        );
        self
    }

    pub fn with_trusted_keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for k in keys {
            self = self.with_trusted_key(k);
        }
        self
    }

    /// Accept any signer and label the result untrusted. Cannot be combined with trusted keys.
    pub fn with_signature_only(mut self) -> Self {
        self.signature_only = true;
        self
    }

    pub fn with_project(mut self, project: uuid::Uuid) -> Self {
        self.expected_project = Some(project);
        self
    }

    pub fn with_commit(mut self, commit: Address) -> Self {
        self.expected_commit = Some(commit);
        self
    }

    pub fn with_min_epoch(mut self, min: u32) -> Self {
        self.min_epoch = Some(min);
        self
    }

    pub fn with_max_epoch(mut self, max: u32) -> Self {
        self.max_epoch = Some(max);
        self
    }

    pub fn with_active_epoch(mut self, active_epoch: u32, max_age: u32) -> Self {
        self.min_epoch = Some(active_epoch.saturating_sub(max_age));
        self.max_epoch = Some(active_epoch);
        self
    }

    fn validate(&self) -> Result<(), AttestationError> {
        if let (Some(min), Some(max)) = (self.min_epoch, self.max_epoch) {
            if min > max {
                return Err(AttestationError::InconsistentPolicy(
                    "minimum epoch is above the maximum epoch",
                ));
            }
        }
        if self.signature_only {
            if !self.trusted_keys.is_empty() {
                return Err(AttestationError::InconsistentPolicy(
                    "signature-only verification cannot also list trusted keys",
                ));
            }
        } else if self.trusted_keys.is_empty() {
            return Err(AttestationError::NoTrustAnchor);
        }
        for window in self.trusted_keys.values() {
            if window
                .until_epoch
                .is_some_and(|until| until < window.from_epoch)
            {
                return Err(AttestationError::InconsistentPolicy(
                    "a trusted key's window ends before it starts",
                ));
            }
        }
        Ok(())
    }
}

/// Verify a state export provenance attestation against state bytes and verification policy.
pub fn verify_state_attestation(
    attestation: &StateExportAttestation,
    state_bytes: &[u8],
    policy: &AttestationVerificationPolicy,
) -> Result<AttestationTrust, AttestationError> {
    policy.validate()?;
    // 1. Verify state digest
    let actual_digest = compute_state_digest(state_bytes);
    if attestation.state_digest != actual_digest {
        return Err(AttestationError::DigestMismatch {
            expected: attestation.state_digest.clone(),
            actual: actual_digest,
        });
    }

    // 2. Verify project UUID if specified in policy
    if let Some(expected_project) = policy.expected_project {
        if attestation.project != expected_project {
            return Err(AttestationError::ProjectMismatch {
                expected: expected_project,
                actual: attestation.project,
            });
        }
    }

    // 3. Verify commit address if specified in policy
    if let Some(ref expected_commit) = policy.expected_commit {
        if &attestation.commit != expected_commit {
            return Err(AttestationError::CommitMismatch {
                expected: expected_commit.clone(),
                actual: attestation.commit.clone(),
            });
        }
    }

    // 4. Verify authority epoch bounds
    if let Some(min_epoch) = policy.min_epoch {
        if attestation.authority_epoch < min_epoch {
            return Err(AttestationError::ExpiredEpoch {
                epoch: attestation.authority_epoch,
                min_valid_epoch: min_epoch,
            });
        }
    }
    if let Some(max_epoch) = policy.max_epoch {
        if attestation.authority_epoch > max_epoch {
            return Err(AttestationError::FutureEpoch {
                epoch: attestation.authority_epoch,
                max_valid_epoch: max_epoch,
            });
        }
    }

    // 5. The signer must be a configured trust anchor, in an epoch its record allows,
    // unless the caller explicitly asked for a signature-only (untrusted) check.
    let trust = if policy.signature_only {
        AttestationTrust::SignatureOnly
    } else {
        let window = policy
            .trusted_keys
            .get(&attestation.signer_key)
            .ok_or_else(|| AttestationError::UntrustedKey {
                signer_key: attestation.signer_key.clone(),
            })?;
        let epoch = attestation.authority_epoch;
        if epoch < window.from_epoch || window.until_epoch.is_some_and(|until| epoch > until) {
            return Err(AttestationError::KeyEpochOutsideWindow {
                signer_key: attestation.signer_key.clone(),
                epoch,
                from_epoch: window.from_epoch,
                until_epoch: window.until_epoch,
            });
        }
        AttestationTrust::Authority
    };

    // 6. Verify cryptographic signature
    let addr = attestation
        .address()
        .map_err(|_| AttestationError::Invalid("attestation payload"))?;
    let msg = attestation::message(STATE_EXPORT_ATTESTATION_SIGN_DOMAIN, &addr)
        .map_err(|_| AttestationError::Invalid("signature message"))?;
    attestation::verify(&attestation.signer_key, &attestation.signature, &msg).map_err(|_| {
        AttestationError::SignatureFailed("Ed25519 signature is invalid for the signer key")
    })?;

    Ok(trust)
}

fn read_state_bounded(path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("opening state file at {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_STATE_EXPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_STATE_EXPORT_BYTES,
        "state file exceeds maximum size limit ({} bytes)",
        MAX_STATE_EXPORT_BYTES
    );
    Ok(bytes)
}

fn verify_attestation_bytes(
    state_path: &Path,
    attestation_path: Option<&Path>,
    state_bytes: &[u8],
    policy: &AttestationVerificationPolicy,
) -> anyhow::Result<(StateExportAttestation, AttestationTrust)> {
    let attestation = StateExportAttestation::read_companion_file(
        attestation_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| companion_attestation_path(state_path)),
    )?;
    let trust = verify_state_attestation(&attestation, state_bytes, policy)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((attestation, trust))
}

/// Offline verification of an exported state file and companion attestation file only.
pub fn verify_state_export_attestation_file<P: AsRef<Path>, Q: AsRef<Path>>(
    state_path: P,
    attestation_path: Option<Q>,
    policy: &AttestationVerificationPolicy,
) -> anyhow::Result<(StateExportAttestation, AttestationTrust)> {
    let state_path = state_path.as_ref();
    let state_bytes = read_state_bounded(state_path)?;
    verify_attestation_bytes(
        state_path,
        attestation_path.as_ref().map(|p| p.as_ref()),
        &state_bytes,
        policy,
    )
}

/// The ordinary state-export verification (signed manifest, path, full typed state root)
/// and then the attestation, both over one bounded read, so they describe the same bytes.
/// The attestation must name the same project and commit the export was checked against.
pub async fn verify_state_export_and_attestation_file<P: AsRef<Path>, Q: AsRef<Path>>(
    state_path: P,
    attestation_path: Option<Q>,
    expected_project: uuid::Uuid,
    expected_commit: &Address,
    expected_path: &str,
    policy: &AttestationVerificationPolicy,
) -> anyhow::Result<(
    VerifiedStateExportReport,
    StateExportAttestation,
    AttestationTrust,
)> {
    let state_path = state_path.as_ref();
    let state_bytes = read_state_bounded(state_path)?;
    let report = verify_state_export(
        std::io::Cursor::new(&state_bytes),
        expected_project,
        expected_commit,
        expected_path,
    )
    .await?;
    let policy = policy
        .clone()
        .with_project(expected_project)
        .with_commit(expected_commit.clone());
    let (attestation, trust) = verify_attestation_bytes(
        state_path,
        attestation_path.as_ref().map(|p| p.as_ref()),
        &state_bytes,
        &policy,
    )?;
    Ok((report, attestation, trust))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materializer::{CommentState, MaterializedNode, SuggestionState};
    use crate::repository::Commit;
    use engine_shared::NodeId;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("dynodoc-test-export-{}", uuid::Uuid::new_v4()));
            super::super::private_fs::create_private_dir(&path).expect("create test private dir");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_commit() -> SignedCommit {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let commit = Commit {
            version: 1,
            project: uuid::Uuid::new_v4(),
            parents: vec![],
            files: BTreeMap::new(),
            author_key: String::new(),
            authored_at_ms: 1000,
            message: "test commit".into(),
            recovery: None,
            same_file_resolutions: vec![],
        };
        SignedCommit::sign(commit, &key).expect("signing commit")
    }

    fn sample_envelope(state: DocumentState) -> StateExportEnvelope {
        StateExportEnvelope::new("docs/spec.docx".into(), test_commit(), state)
    }

    #[test]
    fn test_state_export_exact_under_over_limit_enforcement() {
        let node = MaterializedNode {
            id: NodeId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
            parent_id: None,
            node_type: "paragraph".into(),
            pos: "a0".into(),
            var_name: None,
            deleted: false,
            current_fields: json!({"text": "Hello world"}),
        };
        let state = DocumentState {
            nodes: BTreeMap::from([(node.id.clone(), node)]),
            ..Default::default()
        };
        let envelope = sample_envelope(state);

        let mut buf = Vec::new();
        let actual_len = envelope.write_to_writer(&mut buf).expect("write to writer");
        assert_eq!(actual_len, buf.len());

        // Exact limit should succeed
        let mut buf_exact = Vec::new();
        let n_exact = envelope
            .write_to_writer_limited(&mut buf_exact, actual_len)
            .expect("exact limit should succeed");
        assert_eq!(n_exact, actual_len);
        assert_eq!(buf_exact, buf);

        // One byte under limit should fail
        let mut buf_under = Vec::new();
        let err_under = envelope
            .write_to_writer_limited(&mut buf_under, actual_len - 1)
            .expect_err("under limit should fail");
        assert!(
            err_under.to_string().contains("exceeds maximum size limit"),
            "expected size limit error, got: {err_under}"
        );

        // One byte over limit should succeed
        let mut buf_over = Vec::new();
        let n_over = envelope
            .write_to_writer_limited(&mut buf_over, actual_len + 1)
            .expect("over limit should succeed");
        assert_eq!(n_over, actual_len);
        assert_eq!(buf_over, buf);
    }

    #[test]
    fn test_state_export_escape_heavy_strings_charge_encoded_bytes() {
        // String full of JSON control/escape characters: quote, backslash, newline, carriage return, tab
        let escape_string = "\"\\\n\r\t".repeat(200);
        let raw_len = escape_string.len(); // 1000 bytes
        assert_eq!(raw_len, 1000);

        let node = MaterializedNode {
            id: NodeId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
            parent_id: None,
            node_type: "paragraph".into(),
            pos: "a0".into(),
            var_name: None,
            deleted: false,
            current_fields: json!({"text": escape_string}),
        };
        let state = DocumentState {
            nodes: BTreeMap::from([(node.id.clone(), node)]),
            ..Default::default()
        };
        let envelope = sample_envelope(state);

        let mut buf = Vec::new();
        let actual_len = envelope.write_to_writer(&mut buf).expect("write to writer");

        // The serialized envelope contains the escaped text (at least 2000 bytes for the string alone)
        assert!(actual_len > 2000);

        // Setting a limit equal to actual_len - 100 must fail because BoundedWriter charges the actual serialized JSON bytes as they are written.
        let mut limited_buf = Vec::new();
        let err = envelope
            .write_to_writer_limited(&mut limited_buf, actual_len - 100)
            .expect_err("should fail when actual escaped bytes exceed limit");
        assert!(
            err.to_string().contains("exceeds maximum size limit"),
            "expected size limit error, got: {err}"
        );
    }

    #[test]
    fn test_state_export_preserves_annotations_tombstones_and_deleted_nodes() {
        let active_node = MaterializedNode {
            id: NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA1".into()),
            parent_id: None,
            node_type: "paragraph".into(),
            pos: "a0".into(),
            var_name: Some("first_paragraph".into()),
            deleted: false,
            current_fields: json!({
                "text": "Active text",
                "tombstoned_field": null,
                "nested": {
                    "count": 42,
                    "deleted_flag": null
                }
            }),
        };

        let deleted_node = MaterializedNode {
            id: NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA2".into()),
            parent_id: Some(active_node.id.clone()),
            node_type: "run".into(),
            pos: "a1".into(),
            var_name: None,
            deleted: true,
            current_fields: json!({"deleted_text": "tombstone"}),
        };

        let comments = vec![
            CommentState {
                node_id: Some(active_node.id.clone()),
                body: "Needs citation".into(),
            },
            CommentState {
                node_id: None,
                body: "Overall doc note".into(),
            },
        ];

        let mut suggestions = BTreeMap::new();
        suggestions.insert(
            "sug-1".into(),
            SuggestionState {
                target_node_id: Some(active_node.id.clone()),
                detail: json!({"replacement": "Improved text"}),
                accepted: false,
                rejected_reason: Some("Grammar rule mismatch".into()),
            },
        );

        let removed_choices = BTreeSet::from([deleted_node.id.clone()]);

        let state = DocumentState {
            nodes: BTreeMap::from([
                (active_node.id.clone(), active_node),
                (deleted_node.id.clone(), deleted_node),
            ]),
            comments,
            suggestions,
            removed_choices,
        };

        let envelope = sample_envelope(state);

        let mut serialized = Vec::new();
        envelope
            .write_to_writer(&mut serialized)
            .expect("write_to_writer");

        let roundtrip: StateExportEnvelope =
            serde_json::from_slice(&serialized).expect("deserialize envelope");

        assert_eq!(roundtrip, envelope);
        assert_eq!(roundtrip.format, STATE_EXPORT_FORMAT);
        assert_eq!(roundtrip.version, STATE_EXPORT_VERSION);
        assert_eq!(roundtrip.state.nodes.len(), 2);
        assert!(roundtrip.state.nodes[&NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA2".into())].deleted);
        assert_eq!(
            roundtrip.state.nodes[&NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA1".into())].current_fields
                ["tombstoned_field"],
            serde_json::Value::Null
        );
        assert_eq!(roundtrip.state.comments.len(), 2);
        assert_eq!(roundtrip.state.suggestions.len(), 1);
        assert_eq!(roundtrip.state.removed_choices.len(), 1);
    }

    #[test]
    fn test_state_export_write_to_path_refuses_overwrite_and_cleans_up_on_failure() {
        let dir = TempDir::new();
        let envelope = sample_envelope(DocumentState::default());

        // 1. Refuse overwrite if target already exists
        let existing_path = dir.path().join("existing.json");
        std::fs::write(&existing_path, b"existing content").expect("write existing");

        let err = envelope
            .write_to_path(&existing_path)
            .expect_err("should refuse overwrite");
        assert!(
            err.to_string()
                .contains("already exists; refusing overwrite"),
            "expected overwrite error, got: {err}"
        );
        // Ensure content unchanged
        assert_eq!(
            std::fs::read(&existing_path).expect("read existing"),
            b"existing content"
        );

        // 2. Clean up incomplete file on size limit failure
        let fail_path = dir.path().join("fail_limited.json");
        let err_limited = envelope
            .write_to_path_limited(&fail_path, 10)
            .expect_err("small limit should fail");
        assert!(
            err_limited
                .to_string()
                .contains("exceeds maximum size limit"),
            "expected limit error, got: {err_limited}"
        );
        assert!(
            !fail_path.exists(),
            "failed export must clean up partial file at {}",
            fail_path.display()
        );

        // 3. Successful write creates private file
        let ok_path = dir.path().join("ok_export.json");
        let written = envelope
            .write_to_path(&ok_path)
            .expect("successful write_to_path");
        assert!(ok_path.exists());
        assert_eq!(std::fs::metadata(&ok_path).unwrap().len() as usize, written);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&ok_path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "exported file permissions must be owner-only 0600"
            );
        }

        let roundtrip: StateExportEnvelope =
            serde_json::from_reader(std::fs::File::open(&ok_path).unwrap()).unwrap();
        assert_eq!(roundtrip, envelope);
    }

    async fn make_signed_export(
        project: uuid::Uuid,
        doc: DocumentId,
        path: &str,
        state: DocumentState,
    ) -> (StateExportEnvelope, Address, Address) {
        let mut store = DiscardHashStore::new(Limits::default());
        let (root, _) = shared_checkpoint::typed::write_state(
            &mut store,
            doc,
            &state,
            Limits::default(),
            shared_checkpoint::typed::SemanticLimits::default(),
        )
        .await
        .unwrap();

        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let commit = Commit {
            version: 1,
            project,
            parents: vec![],
            files: BTreeMap::from([(
                path.to_string(),
                crate::repository::FileEntry {
                    document: doc,
                    state: root.clone(),
                },
            )]),
            author_key: String::new(),
            authored_at_ms: 1000,
            message: "valid test export commit".into(),
            recovery: None,
            same_file_resolutions: vec![],
        };
        let signed = SignedCommit::sign(commit, &key).unwrap();
        let commit_addr = signed.verify().unwrap();
        let envelope = StateExportEnvelope::new(path.to_string(), signed, state);
        (envelope, commit_addr, root)
    }

    fn sample_full_state() -> DocumentState {
        let node1 = MaterializedNode {
            id: NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA1".into()),
            parent_id: None,
            node_type: "paragraph".into(),
            pos: "a0".into(),
            var_name: Some("p1".into()),
            deleted: false,
            current_fields: json!({"text": "Hello world", "optional": null}),
        };
        let node2 = MaterializedNode {
            id: NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA2".into()),
            parent_id: Some(node1.id.clone()),
            node_type: "run".into(),
            pos: "a1".into(),
            var_name: None,
            deleted: false,
            current_fields: json!({"bold": true}),
        };
        let comments = vec![CommentState {
            node_id: Some(node1.id.clone()),
            body: "A comment".into(),
        }];
        let mut suggestions = BTreeMap::new();
        suggestions.insert(
            "sug-1".into(),
            SuggestionState {
                target_node_id: Some(node1.id.clone()),
                detail: json!({"change": "edit"}),
                accepted: false,
                rejected_reason: None,
            },
        );
        let removed_choices = BTreeSet::new();

        DocumentState {
            nodes: BTreeMap::from([(node1.id.clone(), node1), (node2.id.clone(), node2)]),
            comments,
            suggestions,
            removed_choices,
        }
    }

    #[tokio::test]
    async fn test_verify_state_export_success_pretty_and_compact() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/overview.docx";
        let state = sample_full_state();

        let (envelope, commit_addr, state_root) =
            make_signed_export(project, doc, path, state).await;

        // 1. Pretty JSON export verification
        let mut pretty = Vec::new();
        envelope.write_to_writer(&mut pretty).unwrap();

        let report = verify_state_export(&pretty[..], project, &commit_addr, path)
            .await
            .expect("verify pretty export");
        assert_eq!(report.project, project);
        assert_eq!(report.commit, commit_addr);
        assert_eq!(report.path, path);
        assert_eq!(report.document, doc);
        assert_eq!(report.root, state_root);

        // 2. Compact JSON export verification
        let compact = serde_json::to_vec(&envelope).unwrap();
        let compact_report = verify_state_export(&compact[..], project, &commit_addr, path)
            .await
            .expect("verify compact export");
        assert_eq!(compact_report, report);
    }

    #[tokio::test]
    async fn test_verify_state_export_tampered_state_field() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/report.docx";
        let state = sample_full_state();

        let (mut envelope, commit_addr, _) = make_signed_export(project, doc, path, state).await;

        // Tamper state: change text in node1
        let node1 = envelope
            .state
            .nodes
            .get_mut(&NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA1".into()))
            .unwrap();
        node1.current_fields = json!({"text": "Tampered text", "optional": null});

        let mut buf = Vec::new();
        envelope.write_to_writer(&mut buf).unwrap();

        let err = verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect_err("tampered text must fail");
        assert!(
            err.to_string().contains("computed state root")
                && err
                    .to_string()
                    .contains("does not match signed manifest state root"),
            "expected root mismatch error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_verify_state_export_tampered_comments_suggestions_choices() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/report.docx";

        // A. Tamper comment
        let (mut env_comment, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;
        env_comment.state.comments[0].body = "Tampered comment".into();
        let mut buf = Vec::new();
        env_comment.write_to_writer(&mut buf).unwrap();
        let err = verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect_err("tampered comment must fail");
        assert!(err
            .to_string()
            .contains("does not match signed manifest state root"));

        // B. Tamper suggestions
        let (mut env_sug, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;
        env_sug.state.suggestions.clear();
        let mut buf = Vec::new();
        env_sug.write_to_writer(&mut buf).unwrap();
        let err = verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect_err("cleared suggestion must fail");
        assert!(err
            .to_string()
            .contains("does not match signed manifest state root"));

        // C. Tamper removed_choices
        let (mut env_rc, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;
        env_rc
            .state
            .removed_choices
            .insert(NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA1".into()));
        let mut buf = Vec::new();
        env_rc.write_to_writer(&mut buf).unwrap();
        let err = verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect_err("tampered removed_choices must fail");
        assert!(err
            .to_string()
            .contains("does not match signed manifest state root"));

        // D. Tamper deleted flag
        let (mut env_del, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;
        env_del
            .state
            .nodes
            .get_mut(&NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA1".into()))
            .unwrap()
            .deleted = true;
        let mut buf = Vec::new();
        env_del.write_to_writer(&mut buf).unwrap();
        let err = verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect_err("tampered deleted flag must fail");
        assert!(err
            .to_string()
            .contains("does not match signed manifest state root"));
    }

    #[tokio::test]
    async fn test_verify_state_export_null_vs_missing_field_difference() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/report.docx";

        let (mut envelope, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;

        // Change `{"text": "Hello world", "optional": null}` to missing optional: `{"text": "Hello world"}`
        let node1 = envelope
            .state
            .nodes
            .get_mut(&NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA1".into()))
            .unwrap();
        node1.current_fields = json!({"text": "Hello world"});

        let mut buf = Vec::new();
        envelope.write_to_writer(&mut buf).unwrap();

        let err = verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect_err("null vs missing difference must change root");
        assert!(err
            .to_string()
            .contains("does not match signed manifest state root"));
    }

    #[tokio::test]
    async fn test_verify_state_export_tampered_commit_signature() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/report.docx";

        let (mut envelope, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;

        // Tamper signature string
        let mut sig_chars: Vec<char> = envelope.commit.signature.chars().collect();
        sig_chars[0] = if sig_chars[0] == '0' { '1' } else { '0' };
        envelope.commit.signature = sig_chars.into_iter().collect();

        let mut buf = Vec::new();
        envelope.write_to_writer(&mut buf).unwrap();

        let err = verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect_err("bad signature must fail");
        assert!(err.to_string().contains("verifying commit signature"));
    }

    #[tokio::test]
    async fn test_verify_state_export_wrong_project_or_commit_or_path() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/report.docx";

        let (envelope, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;

        let mut buf = Vec::new();
        envelope.write_to_writer(&mut buf).unwrap();

        // 1. Wrong project
        let wrong_proj = uuid::Uuid::new_v4();
        let err = verify_state_export(&buf[..], wrong_proj, &commit_addr, path)
            .await
            .expect_err("wrong project must fail");
        assert!(err.to_string().contains("does not match expected project"));

        // 2. Wrong commit
        let wrong_commit = Address::try_from("00".repeat(32)).unwrap();
        let err = verify_state_export(&buf[..], project, &wrong_commit, path)
            .await
            .expect_err("wrong commit must fail");
        assert!(err.to_string().contains("does not match expected commit"));

        // 3. Wrong expected path
        let err = verify_state_export(&buf[..], project, &commit_addr, "docs/other.docx")
            .await
            .expect_err("mismatched path must fail");
        assert!(err.to_string().contains("does not match expected path"));
    }

    #[tokio::test]
    async fn test_verify_state_export_map_key_node_id_mismatch() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/report.docx";

        let (mut envelope, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;

        // Disagree: map key is different from node.id
        let wrong_key = NodeId("01DIFFERENTKEY0000000000000".into());
        let node = envelope
            .state
            .nodes
            .remove(&NodeId("01ARZ3NDEKTSV4RRFFQ69G5FA2".into()))
            .unwrap();
        envelope.state.nodes.insert(wrong_key, node);

        let mut buf = Vec::new();
        envelope.write_to_writer(&mut buf).unwrap();

        let err = verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect_err("map key mismatch must fail");
        assert!(err.to_string().contains("differs from logical node id"));
    }

    #[tokio::test]
    async fn test_verify_state_export_duplicate_keys_rejected() {
        let project = uuid::Uuid::new_v4();
        let commit_addr = Address::try_from("aa".repeat(32)).unwrap();

        // Top-level duplicate key
        let dup_json = r#"{
            "format": "dynodoc.state-export",
            "format": "dynodoc.state-export",
            "version": 1,
            "path": "test.docx",
            "commit": null,
            "state": null
        }"#;

        let err = verify_state_export(dup_json.as_bytes(), project, &commit_addr, "test.docx")
            .await
            .expect_err("duplicate top-level key must fail");
        assert!(err.to_string().contains("duplicate key `format`"));

        // Nested duplicate key in object
        let nested_dup_json = r#"{
            "format": "dynodoc.state-export",
            "version": 1,
            "path": "test.docx",
            "commit": {
                "version": 1,
                "project": "00000000-0000-0000-0000-000000000000",
                "parents": [],
                "files": {},
                "author_key": "abc",
                "author_key": "abc",
                "authored_at_ms": 1,
                "message": ""
            },
            "state": { "nodes": {} }
        }"#;

        let err2 = verify_state_export(
            nested_dup_json.as_bytes(),
            project,
            &commit_addr,
            "test.docx",
        )
        .await
        .expect_err("nested duplicate key must fail");
        assert!(err2.to_string().contains("duplicate key `author_key`"));
    }

    #[tokio::test]
    async fn test_verify_state_export_trailing_data_rejected() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/report.docx";

        let (envelope, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;

        let mut buf = Vec::new();
        envelope.write_to_writer(&mut buf).unwrap();
        // Append trailing data
        buf.extend_from_slice(b" {\"extra\": 123}");

        let err = verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect_err("trailing characters must fail");
        assert!(err.to_string().contains("trailing characters"));
    }

    #[tokio::test]
    async fn test_verify_state_export_unknown_nested_fields_rejected() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/report.docx";
        let (envelope, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;
        let mut buf = Vec::new();
        envelope.write_to_writer(&mut buf).unwrap();
        verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect("untouched export verifies");

        // An extra field inside the state, which serde would otherwise ignore.
        let mut value: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        value["state"]["unverified_note"] = json!("injected");
        let tampered = serde_json::to_vec_pretty(&value).unwrap();
        let err = verify_state_export(&tampered[..], project, &commit_addr, path)
            .await
            .expect_err("unknown nested field must fail");
        assert!(
            err.to_string().contains("outside the verified envelope"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn test_verify_state_export_oversized_input_rejected() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/report.docx";

        let (envelope, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;

        let mut buf = Vec::new();
        envelope.write_to_writer(&mut buf).unwrap();

        let err = verify_state_export_limited(&buf[..], project, &commit_addr, path, 100)
            .await
            .expect_err("tiny limit must reject input");
        assert!(err.to_string().contains("exceeds maximum size limit"));
    }

    #[tokio::test]
    async fn test_verify_state_export_unsupported_version_or_format() {
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/report.docx";

        // 1. Wrong format
        let (mut env_fmt, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;
        env_fmt.format = "unknown-format".into();
        let mut buf = Vec::new();
        env_fmt.write_to_writer(&mut buf).unwrap();
        let err = verify_state_export(&buf[..], project, &commit_addr, path)
            .await
            .expect_err("unknown format must fail");
        assert!(err.to_string().contains("unsupported state export format"));

        // 2. Wrong version
        let (mut env_ver, commit_addr, _) =
            make_signed_export(project, doc, path, sample_full_state()).await;
        env_ver.version = 99;
        let mut buf2 = Vec::new();
        env_ver.write_to_writer(&mut buf2).unwrap();
        let err2 = verify_state_export(&buf2[..], project, &commit_addr, path)
            .await
            .expect_err("unknown version must fail");
        assert!(err2
            .to_string()
            .contains("unsupported state export version"));
    }

    #[tokio::test]
    async fn test_verify_state_export_file_helper() {
        let dir = TempDir::new();
        let project = uuid::Uuid::new_v4();
        let doc = DocumentId(uuid::Uuid::new_v4());
        let path = "docs/file_helper.docx";

        let (envelope, commit_addr, state_root) =
            make_signed_export(project, doc, path, sample_full_state()).await;

        let file_path = dir.path().join("export.json");
        envelope.write_to_path(&file_path).unwrap();

        let report = verify_state_export_file(&file_path, project, &commit_addr, path)
            .await
            .expect("file verification should succeed");
        assert_eq!(report.project, project);
        assert_eq!(report.commit, commit_addr);
        assert_eq!(report.path, path);
        assert_eq!(report.document, doc);
        assert_eq!(report.root, state_root);
    }

    #[test]
    fn test_valid_attestation_verification() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let pub_key = super::super::hex(key.public_key().as_ref());
        let project = uuid::Uuid::new_v4();
        let commit = Address::try_from(
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        )
        .unwrap();
        let state_bytes =
            b"{\"format\":\"dynodoc.state-export\",\"version\":1,\"data\":\"sample\"}";

        let attestation = StateExportAttestation::generate(
            project,
            2,
            commit.clone(),
            state_bytes,
            &key,
            1_700_000_000_000,
        )
        .expect("generation should succeed");

        assert_eq!(attestation.version, ATTESTATION_VERSION);
        assert_eq!(attestation.project, project);
        assert_eq!(attestation.authority_epoch, 2);
        assert_eq!(attestation.signer_key, pub_key);
        assert_eq!(attestation.commit, commit);
        assert_eq!(attestation.state_digest, compute_state_digest(state_bytes));

        let policy = AttestationVerificationPolicy::new()
            .with_project(project)
            .with_commit(commit)
            .with_trusted_key(&pub_key)
            .with_active_epoch(3, 1); // min_epoch: 2, max_epoch: 3

        verify_state_attestation(&attestation, state_bytes, &policy)
            .expect("valid attestation must verify cleanly");
    }

    #[test]
    fn test_tampered_state_rejection() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let pub_key = super::super::hex(key.public_key().as_ref());
        let project = uuid::Uuid::new_v4();
        let commit = Address::try_from(
            "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        )
        .unwrap();
        let original_state = b"{\"format\":\"dynodoc.state-export\",\"version\":1}";
        let tampered_state = b"{\"format\":\"dynodoc.state-export\",\"version\":2}";

        let attestation = StateExportAttestation::generate(
            project,
            1,
            commit.clone(),
            original_state,
            &key,
            1_700_000_000_000,
        )
        .expect("generation should succeed");

        let policy = AttestationVerificationPolicy::new()
            .with_project(project)
            .with_commit(commit)
            .with_trusted_key(&pub_key);

        let err = verify_state_attestation(&attestation, tampered_state, &policy)
            .expect_err("tampered state must fail verification");

        match err {
            AttestationError::DigestMismatch { expected, actual } => {
                assert_eq!(expected, compute_state_digest(original_state));
                assert_eq!(actual, compute_state_digest(tampered_state));
            }
            other => panic!("expected DigestMismatch error, got {other:?}"),
        }
    }

    #[test]
    fn test_wrong_key_rejection() {
        let key1 = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let key2 = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
        let pub_key2 = super::super::hex(key2.public_key().as_ref());

        let project = uuid::Uuid::new_v4();
        let commit = Address::try_from(
            "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        )
        .unwrap();
        let state_bytes = b"{\"content\":\"verified\"}";

        let attestation = StateExportAttestation::generate(
            project,
            1,
            commit.clone(),
            state_bytes,
            &key1,
            1_700_000_000_000,
        )
        .expect("generation should succeed");

        // 1. Untrusted signer key in policy
        let policy_untrusted = AttestationVerificationPolicy::new()
            .with_project(project)
            .with_commit(commit.clone())
            .with_trusted_key(&pub_key2);

        let err = verify_state_attestation(&attestation, state_bytes, &policy_untrusted)
            .expect_err("untrusted key must be rejected");

        assert!(matches!(err, AttestationError::UntrustedKey { .. }));

        // 2. Cryptographic signature corruption
        let mut corrupted_attestation = attestation.clone();
        corrupted_attestation.signature = "00".repeat(64);

        let policy_with_key1 = AttestationVerificationPolicy::new()
            .with_project(project)
            .with_commit(commit)
            .with_trusted_key(super::super::hex(key1.public_key().as_ref()));

        let err_sig =
            verify_state_attestation(&corrupted_attestation, state_bytes, &policy_with_key1)
                .expect_err("corrupted signature must fail");

        assert!(matches!(err_sig, AttestationError::SignatureFailed(_)));
    }

    #[test]
    fn test_expired_epoch_handling() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let pub_key = super::super::hex(key.public_key().as_ref());
        let project = uuid::Uuid::new_v4();
        let commit = Address::try_from(
            "4444444444444444444444444444444444444444444444444444444444444444".to_string(),
        )
        .unwrap();
        let state_bytes = b"{\"nodes\":[]}";

        // Attestation signed at epoch 1
        let attestation_epoch1 = StateExportAttestation::generate(
            project,
            1,
            commit.clone(),
            state_bytes,
            &key,
            1_700_000_000_000,
        )
        .expect("generation should succeed");

        // Policy requires active epoch 3 with max age 1 -> allowed range [2, 3]
        let policy_window = AttestationVerificationPolicy::new()
            .with_project(project)
            .with_commit(commit.clone())
            .with_trusted_key(&pub_key)
            .with_active_epoch(3, 1);

        let err_expired =
            verify_state_attestation(&attestation_epoch1, state_bytes, &policy_window)
                .expect_err("epoch 1 must be rejected as expired when min_epoch is 2");

        match err_expired {
            AttestationError::ExpiredEpoch {
                epoch,
                min_valid_epoch,
            } => {
                assert_eq!(epoch, 1);
                assert_eq!(min_valid_epoch, 2);
            }
            other => panic!("expected ExpiredEpoch, got {other:?}"),
        }

        // Future epoch check: attestation at epoch 5 when policy max_epoch is 4
        let attestation_future = StateExportAttestation::generate(
            project,
            5,
            commit.clone(),
            state_bytes,
            &key,
            1_700_000_000_000,
        )
        .expect("generation should succeed");

        let policy_max = AttestationVerificationPolicy::new()
            .with_project(project)
            .with_commit(commit)
            .with_trusted_key(&pub_key)
            .with_max_epoch(4);

        let err_future = verify_state_attestation(&attestation_future, state_bytes, &policy_max)
            .expect_err("future epoch must be rejected");

        match err_future {
            AttestationError::FutureEpoch {
                epoch,
                max_valid_epoch,
            } => {
                assert_eq!(epoch, 5);
                assert_eq!(max_valid_epoch, 4);
            }
            other => panic!("expected FutureEpoch, got {other:?}"),
        }
    }

    #[test]
    fn test_companion_file_roundtrip_and_permissions() {
        let dir = TempDir::new();
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let pub_key = super::super::hex(key.public_key().as_ref());
        let project = uuid::Uuid::new_v4();
        let commit = Address::try_from(
            "5555555555555555555555555555555555555555555555555555555555555555".to_string(),
        )
        .unwrap();
        let state_bytes = b"{\"state\":{\"nodes\":{}}}";

        let state_file_path = dir.path().join("exported_doc.json");
        std::fs::write(&state_file_path, state_bytes).unwrap();

        let companion_path = companion_attestation_path(&state_file_path);
        assert_eq!(
            companion_path,
            dir.path().join("exported_doc.json.dynoattest")
        );

        let attestation = StateExportAttestation::generate(
            project,
            1,
            commit.clone(),
            state_bytes,
            &key,
            1_700_000_000_000,
        )
        .unwrap();

        attestation.write_companion_file(&companion_path).unwrap();
        assert!(companion_path.is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&companion_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        // Refuse overwrite
        let err_overwrite = attestation
            .write_companion_file(&companion_path)
            .unwrap_err();
        assert!(err_overwrite
            .to_string()
            .contains("already exists; refusing overwrite"));

        // Read and verify
        let policy = AttestationVerificationPolicy::new()
            .with_project(project)
            .with_commit(commit)
            .with_trusted_key(&pub_key);

        let (verified, trust) =
            verify_state_export_attestation_file(&state_file_path, None::<&Path>, &policy)
                .expect("file verification helper should succeed");

        assert_eq!(verified, attestation);
        assert_eq!(trust, AttestationTrust::Authority);
    }

    struct Signed {
        key: Ed25519KeyPair,
        pub_key: String,
        project: uuid::Uuid,
        commit: Address,
        bytes: &'static [u8],
        attestation: StateExportAttestation,
    }

    fn signed_at_epoch(seed: u8, epoch: u32) -> Signed {
        let key = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let pub_key = super::super::hex(key.public_key().as_ref());
        let project = uuid::Uuid::new_v4();
        let commit = Address::try_from("22".repeat(32)).unwrap();
        let bytes: &'static [u8] = b"{\"format\":\"dynodoc.state-export\",\"version\":1}";
        let attestation =
            StateExportAttestation::generate(project, epoch, commit.clone(), bytes, &key, 1)
                .unwrap();
        Signed {
            key,
            pub_key,
            project,
            commit,
            bytes,
            attestation,
        }
    }

    #[test]
    fn no_trust_anchor_is_refused_and_signature_only_is_labelled_untrusted() {
        let s = signed_at_epoch(7, 2);
        let base = AttestationVerificationPolicy::new()
            .with_project(s.project)
            .with_commit(s.commit.clone());

        // An empty trust set trusts nobody; it must not accept a self-signed attestation.
        assert_eq!(
            verify_state_attestation(&s.attestation, s.bytes, &base),
            Err(AttestationError::NoTrustAnchor)
        );
        // The weaker check has to be asked for, and says what it does not establish.
        let signature_only = base.clone().with_signature_only();
        assert_eq!(
            verify_state_attestation(&s.attestation, s.bytes, &signature_only),
            Ok(AttestationTrust::SignatureOnly)
        );
        // An attestation signed by another key still fails its own signature.
        let mut forged = s.attestation.clone();
        forged.signer_key = signed_at_epoch(8, 2).pub_key;
        assert!(matches!(
            verify_state_attestation(&forged, s.bytes, &signature_only),
            Err(AttestationError::SignatureFailed(_))
        ));
        // Trust anchors and signature-only are contradictory.
        assert!(matches!(
            verify_state_attestation(
                &s.attestation,
                s.bytes,
                &signature_only.with_trusted_key(&s.pub_key)
            ),
            Err(AttestationError::InconsistentPolicy(_))
        ));
        // A trusted key does give an authority verdict.
        assert_eq!(
            verify_state_attestation(&s.attestation, s.bytes, &base.with_trusted_key(&s.pub_key)),
            Ok(AttestationTrust::Authority)
        );
    }

    #[test]
    fn a_trusted_key_is_only_trusted_in_its_own_epochs() {
        let s = signed_at_epoch(7, 5);
        let policy = |from: u32, until: Option<u32>| {
            AttestationVerificationPolicy::new()
                .with_project(s.project)
                .with_commit(s.commit.clone())
                .with_trusted_key_epochs(&s.pub_key, from, until)
        };
        assert_eq!(
            verify_state_attestation(&s.attestation, s.bytes, &policy(5, Some(5))),
            Ok(AttestationTrust::Authority)
        );
        // Not yet active, retired (or revoked), and a window that ends before it starts.
        for (from, until) in [(6, None), (0, Some(4))] {
            assert!(
                matches!(
                    verify_state_attestation(&s.attestation, s.bytes, &policy(from, until)),
                    Err(AttestationError::KeyEpochOutsideWindow { epoch: 5, .. })
                ),
                "window {from}..{until:?}"
            );
        }
        assert!(matches!(
            verify_state_attestation(&s.attestation, s.bytes, &policy(7, Some(6))),
            Err(AttestationError::InconsistentPolicy(_))
        ));
        // Global limits that contradict each other are refused rather than ignored.
        let conflicting = policy(0, None).with_min_epoch(9).with_max_epoch(3);
        assert!(matches!(
            verify_state_attestation(&s.attestation, s.bytes, &conflicting),
            Err(AttestationError::InconsistentPolicy(_))
        ));
        // Another key is not made trusted by a window that was meant for this one.
        let other = AttestationVerificationPolicy::new()
            .with_project(s.project)
            .with_trusted_key_epochs(signed_at_epoch(9, 5).pub_key, 0, None);
        assert!(matches!(
            verify_state_attestation(&s.attestation, s.bytes, &other),
            Err(AttestationError::UntrustedKey { .. })
        ));
        let _ = &s.key;
    }

    #[test]
    fn the_wrong_project_or_commit_never_verifies_even_for_a_trusted_key() {
        let s = signed_at_epoch(7, 2);
        let trusted = AttestationVerificationPolicy::new().with_trusted_key(&s.pub_key);
        assert!(matches!(
            verify_state_attestation(
                &s.attestation,
                s.bytes,
                &trusted.clone().with_project(uuid::Uuid::new_v4())
            ),
            Err(AttestationError::ProjectMismatch { .. })
        ));
        assert!(matches!(
            verify_state_attestation(
                &s.attestation,
                s.bytes,
                &trusted.with_commit(Address::try_from("33".repeat(32)).unwrap())
            ),
            Err(AttestationError::CommitMismatch { .. })
        ));
    }
}
