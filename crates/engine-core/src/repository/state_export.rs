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

    /// Write this envelope as pretty JSON to a writer.
    pub fn write_to_writer<W: Write>(&self, mut writer: W) -> anyhow::Result<()> {
        let json_bytes = serde_json::to_vec_pretty(self)?;
        anyhow::ensure!(
            json_bytes.len() <= MAX_STATE_EXPORT_BYTES,
            "exported state exceeds maximum size limit ({} bytes)",
            MAX_STATE_EXPORT_BYTES
        );
        writer.write_all(&json_bytes)?;
        writer.flush()?;
        Ok(())
    }

    /// Write this envelope to a new file created exclusively (refuses overwrite),
    /// setting private owner-only permissions (0600 on Unix, private ACL on Windows) from creation.
    ///
    /// If writing or serialization fails, any incomplete output file is cleaned up.
    pub fn write_to_path<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let p = path.as_ref();
        anyhow::ensure!(
            !p.exists(),
            "output file {} already exists; refusing overwrite",
            p.display()
        );

        let mut file = super::private_fs::create_private_file(p)
            .map_err(|e| anyhow::anyhow!("creating output file at {}: {e}", p.display()))?;

        let guard = super::private_fs::AutoRemoveFile::new(p.to_path_buf());

        self.write_to_writer(&mut file)?;
        file.sync_all()?;
        drop(file);
        guard.commit();

        Ok(())
    }
}
