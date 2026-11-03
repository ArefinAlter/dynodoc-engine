//! Versioned normalized state export format (`dynodoc.state-export`, v1).
//!
//! Exports a single historical file from a signed commit as a self-contained
//! normalized DocumentState JSON envelope. It is not a DOCX/XLSX/PPTX binary,
//! but a verified canonical document model at an exact commit.

use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::materializer::DocumentState;
use crate::repository::SignedCommit;

/// Format identifier for normalized historical state exports.
pub const STATE_EXPORT_FORMAT: &str = "dynodoc.state-export";

/// Current format version for state exports.
pub const STATE_EXPORT_VERSION: u32 = 1;

/// Maximum size in bytes allowed for a state export JSON output (64 MiB).
pub const MAX_STATE_EXPORT_BYTES: usize = 64 * 1024 * 1024;

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
}
