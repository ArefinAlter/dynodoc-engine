//! Versioned normalized state export format (`dynodoc.state-export`, v1).
//!
//! Exports a single historical file from a signed commit as a self-contained
//! normalized DocumentState JSON envelope. It is not a DOCX/XLSX/PPTX binary,
//! but a verified canonical document model at an exact commit.

use std::io::{Read, Write};
use std::path::Path;

use serde::de::{DeserializeSeed, Deserializer, Visitor};
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materializer::{CommentState, MaterializedNode, SuggestionState};
    use crate::repository::Commit;
    use engine_shared::NodeId;
    use ring::signature::Ed25519KeyPair;
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
}
